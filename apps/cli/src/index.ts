#!/usr/bin/env node
/**
 * CesSpace ARC — Operator CLI (`arc`)
 *
 * Implements §24 Local Admin Channel (operator side), §25 token display,
 * §29 `arc policy test`, and §34 Task 3.
 *
 * Two independent capability planes:
 * - Admin commands require an explicitly configured local admin endpoint AND an
 *   operator private key supplied through an inherited file descriptor only.
 * - `arc policy test` is fully offline: it executes zero ARC tools, creates zero
 *   approval records, writes zero audit records, and never contacts admin IPC.
 *
 * The CLI never reads a private key from argv, from an environment VALUE, from a
 * config file, or from a default path. Only the integer FD number may appear in
 * argv or the environment.
 */

import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  RC03_MUTATION_TOOLS,
  WorkspaceRegistry,
  DeclarativePolicyEngine,
  type PolicySourceFormat,
} from '@cesspace-arc/policy';
import {
  ADMIN_MAX_REASON_BYTES,
  ADMIN_REQUEST_ID_REGEX,
  ArcError,
  type AdminResponse,
} from '@cesspace-arc/protocol';

import { AdminClientError, AdminIpcClient, readPrivateKeyFromFd } from './admin-client.js';

export const CLI_NAME = 'arc';
export const CLI_VERSION = '0.4.0-rc04';

export const EXIT_OK = 0;
export const EXIT_FAILURE = 1;
export const EXIT_USAGE = 2;

/** Injected dependencies, so the CLI is testable without real process I/O. */
export interface CliDependencies {
  stdout?: (text: string) => void;
  stderr?: (text: string) => void;
  env?: Record<string, string | undefined>;
  readFile?: (filePath: string) => string;
  readPrivateKeyFromFd?: (fd: number) => unknown;
  createAdminClient?: (options: { endpoint: string; privateKey: unknown }) => {
    request(method: string, params: Record<string, string>): Promise<AdminResponse>;
  };
}

interface CliIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  env: Record<string, string | undefined>;
  readFile: (filePath: string) => string;
  readPrivateKeyFromFd: (fd: number) => unknown;
  createAdminClient: (options: { endpoint: string; privateKey: unknown }) => {
    request(method: string, params: Record<string, string>): Promise<AdminResponse>;
  };
}

/** Usage failure: reported on stderr and mapped to a nonzero exit code. */
class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

const HELP_TEXT = `${CLI_NAME} — CesSpace ARC operator CLI

Usage:
  ${CLI_NAME} approvals list
  ${CLI_NAME} approvals inspect <requestId>
  ${CLI_NAME} approve <requestId>
  ${CLI_NAME} reject <requestId> [--reason <text>]
  ${CLI_NAME} enrollment create --client-id <id> --client-type <type> --spki-pin <64hex> [--label <text>]
  ${CLI_NAME} enrollment cancel <enrollmentId>
  ${CLI_NAME} policy test <file> [options]
  ${CLI_NAME} --help
  ${CLI_NAME} --version

Admin channel options (approvals, approve, reject, enrollment):
  --admin-socket <path>   Local admin IPC endpoint
                          (env: CESSPACE_ARC_ADMIN_SOCKET)
  --admin-key-fd <n>      Inherited file descriptor holding the operator
                          Ed25519 private key, base64 DER PKCS#8
                          (env: CESSPACE_ARC_ADMIN_PRIVATE_KEY_FD)

  The private key is read only from the inherited descriptor. It is never
  accepted through argv, the environment, a config file, or a default path.

policy test options:
  --format <json|yaml>        Policy format (inferred from .json/.yaml/.yml)
  --workspace <id>=<path>     Register a local test workspace (repeatable)
  --tool <name>               Evaluate this tool
  --path <relpath>            Workspace-relative target path
  --executable <basename>     Executable basename
  --git-branch <branch>       Git branch
  --git-action <action>       Git action

  Without --tool, the policy is only validated, normalized, and hashed.
`;

/**
 * Strict base-10 integer parsing for the FD selector.
 * Rejects signs, decimals, whitespace, and empty strings.
 */
function parseFdNumber(value: unknown): number {
  if (typeof value !== 'string' || !/^[0-9]{1,7}$/.test(value)) {
    throw new UsageError('--admin-key-fd must be a non-negative integer.');
  }
  return Number.parseInt(value, 10);
}

interface ParsedAdminArgs {
  endpoint?: string;
  keyFd?: number;
}

/** Reads an option value, failing closed when the value is absent. */
function takeValue(argv: string[], index: number, option: string): string {
  const value = argv[index + 1];
  if (value === undefined || value.startsWith('--')) {
    throw new UsageError(`${option} requires a value.`);
  }
  return value;
}

/**
 * Extracts admin channel configuration from argv and the (non-secret)
 * environment. Only the FD NUMBER may come from either source.
 */
function resolveAdminConfig(
  argv: string[],
  env: Record<string, string | undefined>,
): ParsedAdminArgs {
  const config: ParsedAdminArgs = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--admin-socket') {
      config.endpoint = takeValue(argv, i, '--admin-socket');
      i++;
    } else if (argv[i] === '--admin-key-fd') {
      config.keyFd = parseFdNumber(takeValue(argv, i, '--admin-key-fd'));
      i++;
    }
  }
  if (config.endpoint === undefined && env.CESSPACE_ARC_ADMIN_SOCKET !== undefined) {
    config.endpoint = env.CESSPACE_ARC_ADMIN_SOCKET;
  }
  if (config.keyFd === undefined && env.CESSPACE_ARC_ADMIN_PRIVATE_KEY_FD !== undefined) {
    config.keyFd = parseFdNumber(env.CESSPACE_ARC_ADMIN_PRIVATE_KEY_FD);
  }
  return config;
}

/** Strips recognised global options, returning positional arguments. */
function stripAdminOptions(argv: string[]): string[] {
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--admin-socket' || argv[i] === '--admin-key-fd') {
      i++;
      continue;
    }
    rest.push(argv[i]);
  }
  return rest;
}

async function callAdmin(
  io: CliIo,
  config: ParsedAdminArgs,
  method: string,
  params: Record<string, string>,
): Promise<AdminResponse> {
  if (config.endpoint === undefined) {
    throw new UsageError(
      'Admin channel endpoint is not configured. Supply --admin-socket <path> or CESSPACE_ARC_ADMIN_SOCKET.',
    );
  }
  if (config.keyFd === undefined) {
    throw new UsageError(
      'Admin key is not configured. Supply --admin-key-fd <n> or CESSPACE_ARC_ADMIN_PRIVATE_KEY_FD.',
    );
  }

  // The private key is imported from the inherited descriptor only.
  const privateKey = io.readPrivateKeyFromFd(config.keyFd);
  const client = io.createAdminClient({ endpoint: config.endpoint, privateKey });
  return client.request(method, params);
}

/** Renders a bounded admin failure on stderr. Never includes key material. */
function reportAdminFailure(
  io: CliIo,
  response: AdminResponse,
  context: 'approval' | 'enrollment' = 'approval',
): number {
  const code = response.error?.code ?? 'INTERNAL_ERROR';
  if (code === 'AUTHENTICATION_FAILED') {
    io.stderr('Admin authentication failed. The operator key was not accepted.\n');
  } else if (code === 'INVALID_ADMIN_REQUEST') {
    io.stderr('Admin request was rejected as invalid.\n');
  } else if (code === 'NOT_FOUND_OR_NOT_PENDING') {
    io.stderr(
      context === 'enrollment'
        ? 'No pending enrollment matches that enrollment ID.\n'
        : 'No pending approval matches that request ID.\n',
    );
  } else if (code === 'APPROVAL_EXPIRED') {
    io.stderr('The approval request has expired.\n');
  } else if (code === 'APPROVAL_REJECTED') {
    io.stderr('The approval request could not be acted on.\n');
  } else if (code === 'RESOURCE_EXHAUSTED') {
    io.stderr(
      context === 'enrollment'
        ? 'Pending enrollment limits were reached.\n'
        : 'Approval resource limits were reached.\n',
    );
  } else {
    io.stderr('Admin operation failed.\n');
  }
  return EXIT_FAILURE;
}

// ---------------------------------------------------------------------------
// RC-05 Task 2: enrollment administration
//
// Wire-format bounds mirrored locally so the CLI can fail before opening a
// connection. The server re-validates authoritatively; these are convenience
// checks only. Authoritative definitions live in the frozen RC-05 contract.
// ---------------------------------------------------------------------------

/** Canonical SPKI pin: SHA-256 of DER SPKI, 64 lowercase hex characters. */
const ENROLLMENT_SPKI_PIN_REGEX = /^[0-9a-f]{64}$/;
/** Server-generated enrollment identifier: 32 lowercase hex characters. */
const ENROLLMENT_ID_REGEX = /^[0-9a-f]{32}$/;
/** Maximum display label size in UTF-8 bytes. */
const ENROLLMENT_MAX_LABEL_BYTES = 64;
/** Maximum clientId / clientType size in UTF-8 bytes. */
const ENROLLMENT_MAX_IDENTIFIER_BYTES = 128;

interface EnrollmentCreateOptions {
  clientId: string;
  clientType: string;
  spkiPin: string;
  displayLabel?: string;
}

/** Validates a required bounded identifier supplied on the command line. */
function validateEnrollmentIdentifier(value: string | undefined, option: string): string {
  if (value === undefined || value.trim().length === 0) {
    throw new UsageError(`${option} is required.`);
  }
  if (value.includes('\u0000')) {
    throw new UsageError(`${option} must not contain NUL.`);
  }
  if (Buffer.byteLength(value, 'utf8') > ENROLLMENT_MAX_IDENTIFIER_BYTES) {
    throw new UsageError(
      `${option} must not exceed ${ENROLLMENT_MAX_IDENTIFIER_BYTES} UTF-8 bytes.`,
    );
  }
  return value;
}

/** Parses `enrollment create` arguments. Rejects unknown options. */
function parseEnrollmentCreateArgs(args: readonly string[]): EnrollmentCreateOptions {
  let clientId: string | undefined;
  let clientType: string | undefined;
  let spkiPin: string | undefined;
  let displayLabel: string | undefined;

  const argv = [...args];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--client-id') {
      clientId = takeValue(argv, i, arg);
      i++;
    } else if (arg === '--client-type') {
      clientType = takeValue(argv, i, arg);
      i++;
    } else if (arg === '--spki-pin') {
      spkiPin = takeValue(argv, i, arg);
      i++;
    } else if (arg === '--label') {
      displayLabel = takeValue(argv, i, arg);
      i++;
    } else {
      throw new UsageError(`Unknown option for enrollment create: ${arg}`);
    }
  }

  const validatedClientId = validateEnrollmentIdentifier(clientId, '--client-id');
  const validatedClientType = validateEnrollmentIdentifier(clientType, '--client-type');

  if (spkiPin === undefined) {
    throw new UsageError('--spki-pin is required.');
  }
  if (!ENROLLMENT_SPKI_PIN_REGEX.test(spkiPin)) {
    throw new UsageError('--spki-pin must be exactly 64 lowercase hexadecimal characters.');
  }

  if (displayLabel !== undefined) {
    if (displayLabel.includes('\u0000')) {
      throw new UsageError('--label must not contain NUL.');
    }
    if (Buffer.byteLength(displayLabel, 'utf8') > ENROLLMENT_MAX_LABEL_BYTES) {
      throw new UsageError(`--label must not exceed ${ENROLLMENT_MAX_LABEL_BYTES} UTF-8 bytes.`);
    }
  }

  return {
    clientId: validatedClientId,
    clientType: validatedClientType,
    spkiPin,
    ...(displayLabel === undefined ? {} : { displayLabel }),
  };
}

/**
 * Renders a successful enrollment creation.
 *
 * The one-time enrollment secret is displayed exactly once, on stdout, to the
 * authenticated operator. It is never written to any file, never included in a
 * log line, and never repeated by any later command.
 */
function renderEnrollmentCreate(io: CliIo, result: unknown): number {
  if (result === null || typeof result !== 'object') {
    io.stderr('Enrollment creation returned no result.\n');
    return EXIT_FAILURE;
  }
  const enrollment = (result as { enrollment?: unknown }).enrollment;
  const secret = (result as { secret?: unknown }).secret;
  if (
    enrollment === null ||
    typeof enrollment !== 'object' ||
    typeof secret !== 'string' ||
    !/^[0-9a-f]{64}$/.test(secret)
  ) {
    io.stderr('Enrollment creation returned an unusable result.\n');
    return EXIT_FAILURE;
  }

  const view = enrollment as Record<string, unknown>;
  io.stdout(`Enrollment ID : ${String(view.enrollmentId)}\n`);
  io.stdout(`Client        : ${String(view.clientId)} (${String(view.clientType)})\n`);
  io.stdout(`SPKI pin      : ${String(view.spkiPin)}\n`);
  if (typeof view.displayLabel === 'string' && view.displayLabel.length > 0) {
    io.stdout(`Label         : ${view.displayLabel}\n`);
  }
  io.stdout(`Expires in    : ${formatSeconds(view.remainingSeconds)}s\n`);
  io.stdout(`\n`);
  io.stdout(`One-time enrollment secret (shown once, store it securely):\n`);
  io.stdout(`${secret}\n`);
  return EXIT_OK;
}

/** Renders a successful enrollment cancellation. */
function renderEnrollmentCancel(io: CliIo, result: unknown): number {
  if (result === null || typeof result !== 'object') {
    io.stderr('Enrollment cancellation returned no result.\n');
    return EXIT_FAILURE;
  }
  const view = result as Record<string, unknown>;
  io.stdout(`Enrollment ID : ${String(view.enrollmentId)}\n`);
  io.stdout(`State         : ${String(view.state)}\n`);
  return EXIT_OK;
}

// ---------------------------------------------------------------------------
// Admin command rendering
// ---------------------------------------------------------------------------

function formatSeconds(value: unknown): string {
  return typeof value === 'number' && Number.isFinite(value) ? String(value) : 'unknown';
}

/** Renders the safe review summary. Never raw material, never a token. */
function renderReviewSummary(io: CliIo, summary: unknown, indent = '  '): void {
  if (summary === null || typeof summary !== 'object') {
    return;
  }
  const s = summary as Record<string, unknown>;
  const line = (label: string, value: unknown): void => {
    io.stdout(`${indent}${label}: ${String(value)}\n`);
  };

  if (Array.isArray(s.targetPaths) && s.targetPaths.length > 0) {
    io.stdout(`${indent}Target paths:\n`);
    for (const target of s.targetPaths) {
      io.stdout(`${indent}  - ${String(target)}\n`);
    }
  }
  for (const key of ['contentBytes', 'contentHash', 'patchBytes', 'patchHash']) {
    if (s[key] !== undefined) line(key, s[key]);
  }
  for (const key of ['expectedHash', 'expectedSourceHash', 'overwrite', 'dryRun', 'fuzz']) {
    if (s[key] !== undefined) line(key, s[key]);
  }
  if (s.executable !== undefined) line('executable', s.executable);
  if (s.argumentCount !== undefined) line('argumentCount', s.argumentCount);
}

/** `arc approvals list` — bounded metadata only, never review material. */
function renderList(io: CliIo, result: unknown): number {
  const approvals = (result as { approvals?: unknown })?.approvals;
  if (!Array.isArray(approvals)) {
    io.stderr('Admin response was malformed.\n');
    return EXIT_FAILURE;
  }
  if (approvals.length === 0) {
    io.stdout('No pending approval requests.\n');
    return EXIT_OK;
  }
  io.stdout(`Pending approval requests: ${approvals.length}\n\n`);
  for (const entry of approvals) {
    const approval = entry as Record<string, unknown>;
    const actor = `${String(approval.clientId)} (${String(approval.clientType)})`;
    const session = approval.sessionId === undefined ? '-' : String(approval.sessionId);
    const device = approval.deviceId === undefined ? '-' : String(approval.deviceId);
    io.stdout(`  Request:   ${String(approval.requestId)}\n`);
    io.stdout(`  Tool:      ${String(approval.toolName)}\n`);
    io.stdout(`  State:     ${String(approval.state)}\n`);
    io.stdout(`  Caller:    ${actor}\n`);
    io.stdout(`  Session:   ${session}\n`);
    io.stdout(`  Device:    ${device}\n`);
    io.stdout(`  Workspace: ${String(approval.workspaceId)}\n`);
    io.stdout(`  Created:   ${String(approval.createdAt)}\n`);
    io.stdout(`  Expires:   ${String(approval.expiresAt)}\n`);
    io.stdout(`  Remaining: ${formatSeconds(approval.remainingSeconds)}s\n`);
    io.stdout(`  Review:    ${String(approval.reviewMaterialBytes)} bytes\n`);
    renderReviewSummary(io, approval.reviewSummary);
    io.stdout('\n');
  }
  io.stdout('Run `arc approvals inspect <requestId>` to review a request.\n');
  return EXIT_OK;
}

/** `arc approvals inspect <requestId>` — trusted operator review display. */
function renderInspect(io: CliIo, result: unknown): number {
  const detail = (result ?? {}) as Record<string, unknown>;
  io.stdout(`Request:   ${String(detail.requestId)}\n`);
  io.stdout(`Tool:      ${String(detail.toolName)}\n`);
  io.stdout(`State:     ${String(detail.state)}\n`);
  io.stdout(`Caller:    ${String(detail.clientId)} (${String(detail.clientType)})\n`);
  if (detail.sessionId !== undefined) {
    io.stdout(`Session:   ${String(detail.sessionId)}\n`);
  }
  if (detail.deviceId !== undefined) {
    io.stdout(`Device:    ${String(detail.deviceId)}\n`);
  }
  io.stdout(`Workspace: ${String(detail.workspaceId)}\n`);
  io.stdout(`Created:   ${String(detail.createdAt)}\n`);
  io.stdout(`Expires:   ${String(detail.expiresAt)}\n`);
  io.stdout(`Remaining: ${formatSeconds(detail.remainingSeconds)}s\n`);
  renderReviewSummary(io, detail.reviewSummary, '');
  io.stdout('\nReview Material:\n');
  io.stdout(`${typeof detail.reviewMaterial === 'string' ? detail.reviewMaterial : ''}\n`);
  return EXIT_OK;
}

/** `arc approve <requestId>` — the only place a raw token is displayed. */
function renderApprove(io: CliIo, result: unknown): number {
  const grant = (result ?? {}) as Record<string, unknown>;
  io.stdout(`Request ${String(grant.requestId)} APPROVED\n\n`);
  io.stdout('One-Time Approval Token:\n');
  io.stdout(`  ${String(grant.token)}\n\n`);
  io.stdout(
    `Expires at: ${String(grant.expiresAt)} (Remaining: ${formatSeconds(grant.remainingSeconds)}s)\n`,
  );
  io.stdout('Provide this token to the agent. Single-use only.\n');
  return EXIT_OK;
}

function renderReject(io: CliIo, result: unknown): number {
  const rejection = (result ?? {}) as Record<string, unknown>;
  io.stdout(`Request ${String(rejection.requestId)} ${String(rejection.state)}\n`);
  return EXIT_OK;
}

// ---------------------------------------------------------------------------
// `arc policy test` — offline only
// ---------------------------------------------------------------------------

interface PolicyTestOptions {
  file?: string;
  format?: PolicySourceFormat;
  workspaces: Array<{ id: string; path: string }>;
  tool?: string;
  targetPath?: string;
  executable?: string;
  gitBranch?: string;
  gitAction?: string;
}

/** Determines the policy format from --format or a safe file extension only. */
function resolvePolicyFormat(options: PolicyTestOptions, file: string): PolicySourceFormat {
  if (options.format !== undefined) {
    return options.format;
  }
  const extension = path.extname(file).toLowerCase();
  if (extension === '.json') return 'json';
  if (extension === '.yaml' || extension === '.yml') return 'yaml';
  throw new UsageError(
    'Policy format could not be determined from the file extension. Supply --format json or --format yaml.',
  );
}

function parsePolicyTestArgs(rest: string[]): PolicyTestOptions {
  const options: PolicyTestOptions = { workspaces: [] };
  const positional: string[] = [];

  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (arg === '--format') {
      const value = takeValue(rest, i, '--format');
      if (value !== 'json' && value !== 'yaml') {
        throw new UsageError('--format must be either json or yaml.');
      }
      options.format = value;
      i++;
    } else if (arg === '--workspace') {
      const value = takeValue(rest, i, '--workspace');
      const separator = value.indexOf('=');
      if (separator <= 0 || separator === value.length - 1) {
        throw new UsageError('--workspace must be supplied as <id>=<path>.');
      }
      options.workspaces.push({
        id: value.slice(0, separator),
        path: value.slice(separator + 1),
      });
      i++;
    } else if (arg === '--tool') {
      options.tool = takeValue(rest, i, '--tool');
      i++;
    } else if (arg === '--path') {
      options.targetPath = takeValue(rest, i, '--path');
      i++;
    } else if (arg === '--executable') {
      options.executable = takeValue(rest, i, '--executable');
      i++;
    } else if (arg === '--git-branch') {
      options.gitBranch = takeValue(rest, i, '--git-branch');
      i++;
    } else if (arg === '--git-action') {
      options.gitAction = takeValue(rest, i, '--git-action');
      i++;
    } else if (arg.startsWith('--')) {
      throw new UsageError(`Unknown option for policy test: ${arg}`);
    } else {
      positional.push(arg);
    }
  }

  if (positional.length === 0) {
    throw new UsageError('policy test requires a policy file path.');
  }
  if (positional.length > 1) {
    throw new UsageError('policy test accepts exactly one policy file path.');
  }
  options.file = positional[0];
  return options;
}

/**
 * Runs `arc policy test`: parse, validate, normalize, hash, and optionally
 * evaluate. Executes zero ARC tools and creates zero approval records.
 */
function runPolicyTest(io: CliIo, options: PolicyTestOptions): number {
  const file = options.file as string;

  let format: PolicySourceFormat;
  try {
    format = resolvePolicyFormat(options, file);
  } catch (err) {
    io.stderr(`${(err as Error).message}\n`);
    return EXIT_USAGE;
  }

  let sourceText: string;
  try {
    sourceText = io.readFile(file);
  } catch {
    io.stderr('Policy file could not be read.\n');
    return EXIT_FAILURE;
  }

  // The registry starts EMPTY unless the operator explicitly registers local
  // test workspaces. process.cwd() is never implicitly authorized.
  const registry = new WorkspaceRegistry();
  for (const workspace of options.workspaces) {
    try {
      registry.registerWorkspace(workspace.id, workspace.path);
    } catch {
      // Never echo the supplied path back in the error.
      io.stderr('A --workspace path could not be registered.\n');
      return EXIT_FAILURE;
    }
  }

  let engine: DeclarativePolicyEngine;
  try {
    engine = DeclarativePolicyEngine.fromExternalText(registry, sourceText, format);
  } catch (err: unknown) {
    // Only the generic, already-redacted ArcError surface is shown.
    if (err instanceof ArcError) {
      io.stderr(`${err.code}: ${err.message}\n`);
    } else {
      io.stderr('POLICY_PARSE_ERROR: Policy document could not be parsed.\n');
    }
    return EXIT_FAILURE;
  }

  io.stdout(`policyHash: ${engine.getPolicyHash()}\n`);
  io.stdout(`source:     ${engine.getSourceMode()}\n`);

  if (options.tool === undefined) {
    io.stdout(
      '\nPolicy validated and normalized. No --tool supplied, so no evaluation was performed.\n',
    );
    return EXIT_OK;
  }

  const target: Record<string, string> = { toolName: options.tool };
  if (options.targetPath !== undefined) target.path = options.targetPath;
  if (options.executable !== undefined) target.executableBasename = options.executable;
  if (options.gitBranch !== undefined) target.gitBranch = options.gitBranch;
  if (options.gitAction !== undefined) target.gitAction = options.gitAction;

  const decision = engine.evaluate(target as never);
  io.stdout(`\noutcome:        ${decision.effect}\n`);
  io.stdout(`matchingRuleId: ${decision.matchingRuleId}\n`);
  io.stdout(`reason:         ${decision.reason}\n`);

  // The mutation floor is the only reason a non-DENY ALLOW-rule outcome is
  // elevated; surface it explicitly rather than silently.
  const floorApplied =
    decision.effect === 'REQUIRE_APPROVAL' &&
    (RC03_MUTATION_TOOLS as readonly string[]).includes(options.tool) &&
    decision.reason.includes('mutation approval floor');
  if (floorApplied) {
    io.stdout(
      '\nNotice: the RC-03 mutation approval floor applied. The matched rule allows this tool,\n' +
        'but file mutation tools are always elevated to REQUIRE_APPROVAL.\n',
    );
  }

  io.stdout('\nNo tools were executed. No approval records or audit records were created.\n');
  return EXIT_OK;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Runs the CLI against an argument vector (excluding node and the script path).
 * Returns the process exit code. Never throws for operator-facing failures.
 */
export async function runCli(
  argv: readonly string[],
  dependencies: CliDependencies = {},
): Promise<number> {
  const io: CliIo = {
    stdout: dependencies.stdout ?? ((text) => process.stdout.write(text)),
    stderr: dependencies.stderr ?? ((text) => process.stderr.write(text)),
    env: dependencies.env ?? process.env,
    readFile: dependencies.readFile ?? ((filePath) => fs.readFileSync(filePath, 'utf8')),
    readPrivateKeyFromFd: dependencies.readPrivateKeyFromFd ?? ((fd) => readPrivateKeyFromFd(fd)),
    createAdminClient:
      dependencies.createAdminClient ??
      ((options) =>
        new AdminIpcClient({
          endpoint: options.endpoint,
          privateKey: options.privateKey as never,
        })),
  };

  const args = [...argv];

  if (args.length === 0 || args[0] === '--help' || args[0] === '-h' || args[0] === 'help') {
    io.stdout(HELP_TEXT);
    return EXIT_OK;
  }
  if (args[0] === '--version' || args[0] === '-v' || args[0] === 'version') {
    io.stdout(`${CLI_NAME} ${CLI_VERSION}\n`);
    return EXIT_OK;
  }

  try {
    const command = args[0];

    if (
      command === 'approvals' ||
      command === 'approve' ||
      command === 'reject' ||
      command === 'enrollment'
    ) {
      const config = resolveAdminConfig(args, io.env);
      const rest = stripAdminOptions(args);
      const head = rest[0];

      if (head === 'enrollment') {
        const sub = rest[1];
        if (sub === 'create') {
          const options = parseEnrollmentCreateArgs(rest.slice(2));
          const params: Record<string, string> = {
            clientId: options.clientId,
            clientType: options.clientType,
            spkiPin: options.spkiPin,
          };
          if (options.displayLabel !== undefined) params.displayLabel = options.displayLabel;
          const response = await callAdmin(io, config, 'enrollment.create', params);
          if (!response.ok) return reportAdminFailure(io, response, 'enrollment');
          return renderEnrollmentCreate(io, response.result);
        }
        if (sub === 'cancel') {
          if (rest.length !== 3) {
            throw new UsageError('enrollment cancel requires exactly one <enrollmentId>.');
          }
          const enrollmentId = rest[2];
          if (!ENROLLMENT_ID_REGEX.test(enrollmentId)) {
            throw new UsageError(
              'enrollmentId must be exactly 32 lowercase hexadecimal characters.',
            );
          }
          const response = await callAdmin(io, config, 'enrollment.cancel', { enrollmentId });
          if (!response.ok) return reportAdminFailure(io, response, 'enrollment');
          return renderEnrollmentCancel(io, response.result);
        }
        throw new UsageError(`Unknown enrollment subcommand: ${String(sub)}`);
      }

      if (head === 'approvals') {
        const sub = rest[1];
        if (sub === 'list') {
          if (rest.length !== 2) {
            throw new UsageError('approvals list takes no further arguments.');
          }
          const response = await callAdmin(io, config, 'approvals.list', {});
          if (!response.ok) return reportAdminFailure(io, response);
          return renderList(io, response.result);
        }
        if (sub === 'inspect') {
          if (rest.length !== 3) {
            throw new UsageError('approvals inspect requires exactly one <requestId>.');
          }
          const requestId = rest[2];
          if (!ADMIN_REQUEST_ID_REGEX.test(requestId)) {
            throw new UsageError('requestId must be exactly 32 lowercase hexadecimal characters.');
          }
          const response = await callAdmin(io, config, 'approvals.inspect', { requestId });
          if (!response.ok) return reportAdminFailure(io, response);
          return renderInspect(io, response.result);
        }
        throw new UsageError(`Unknown approvals subcommand: ${String(sub)}`);
      }

      if (head === 'approve') {
        if (rest.length !== 2) {
          throw new UsageError('approve requires exactly one <requestId>.');
        }
        const requestId = rest[1];
        if (!ADMIN_REQUEST_ID_REGEX.test(requestId)) {
          throw new UsageError('requestId must be exactly 32 lowercase hexadecimal characters.');
        }
        const response = await callAdmin(io, config, 'approval.approve', { requestId });
        if (!response.ok) return reportAdminFailure(io, response);
        return renderApprove(io, response.result);
      }

      if (head === 'reject') {
        let reason: string | undefined;
        const positional: string[] = [];
        for (let i = 1; i < rest.length; i++) {
          if (rest[i] === '--reason') {
            reason = takeValue(rest, i, '--reason');
            i++;
          } else if (rest[i].startsWith('--')) {
            throw new UsageError(`Unknown option for reject: ${rest[i]}`);
          } else {
            positional.push(rest[i]);
          }
        }
        if (positional.length !== 1) {
          throw new UsageError('reject requires exactly one <requestId>.');
        }
        const requestId = positional[0];
        if (!ADMIN_REQUEST_ID_REGEX.test(requestId)) {
          throw new UsageError('requestId must be exactly 32 lowercase hexadecimal characters.');
        }
        if (reason !== undefined) {
          if (reason.includes('\u0000')) {
            throw new UsageError('--reason must not contain NUL.');
          }
          if (Buffer.byteLength(reason, 'utf8') > ADMIN_MAX_REASON_BYTES) {
            throw new UsageError(`--reason must not exceed ${ADMIN_MAX_REASON_BYTES} UTF-8 bytes.`);
          }
        }
        const params: Record<string, string> = { requestId };
        if (reason !== undefined) params.reason = reason;
        const response = await callAdmin(io, config, 'approval.reject', params);
        if (!response.ok) return reportAdminFailure(io, response);
        return renderReject(io, response.result);
      }
    }

    if (command === 'policy') {
      if (args[1] !== 'test') {
        throw new UsageError(`Unknown policy subcommand: ${String(args[1])}`);
      }
      const options = parsePolicyTestArgs(args.slice(2));
      return runPolicyTest(io, options);
    }

    throw new UsageError(`Unknown command: ${command}`);
  } catch (err: unknown) {
    if (err instanceof UsageError) {
      io.stderr(`${err.message}\n`);
      return EXIT_USAGE;
    }
    if (err instanceof AdminClientError) {
      io.stderr(`${err.message}\n`);
      return EXIT_FAILURE;
    }
    // Never surface an unexpected internal error verbatim.
    io.stderr('Command failed.\n');
    return EXIT_FAILURE;
  }
}

/** Runs the CLI as an executable, using real process dependencies. */
async function main(): Promise<void> {
  const exitCode = await runCli(process.argv.slice(2));
  process.exitCode = exitCode;
}

// Auto-run only when executed directly as a script.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  void main();
}

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

import { runAuditCommand } from './audit.js';

import {
  RC03_MUTATION_TOOLS,
  WorkspaceRegistry,
  DeclarativePolicyEngine,
  type PolicySourceFormat,
} from '@cesspace-arc/policy';
import {
  ADMIN_DEVICE_ID_REGEX,
  ADMIN_MAX_DISPLAY_LABEL_BYTES,
  ADMIN_MAX_REASON_BYTES,
  ADMIN_REQUEST_ID_REGEX,
  ADMIN_SESSION_ID_REGEX,
  ADMIN_SPKI_PIN_REGEX,
  ArcError,
  type AdminResponse,
} from '@cesspace-arc/protocol';

import { AdminClientError, AdminIpcClient, readPrivateKeyFromFd } from './admin-client.js';

export const CLI_NAME = 'arc';
export const CLI_VERSION = '0.7.0-rc07';

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
  ${CLI_NAME} devices list
  ${CLI_NAME} devices inspect <deviceId>
  ${CLI_NAME} devices revoke <deviceId>
  ${CLI_NAME} devices rename <deviceId> --label <text>
  ${CLI_NAME} devices pin-add <deviceId> --spki-pin <64hex>
  ${CLI_NAME} devices pin-remove <deviceId> --spki-pin <64hex>
  ${CLI_NAME} sessions list
  ${CLI_NAME} sessions revoke <sessionId>
  ${CLI_NAME} policy test <file> [options]
  ${CLI_NAME} audit status|verify|inspect|export [options]
  ${CLI_NAME} --help
  ${CLI_NAME} --version

Admin channel options (approvals, approve, reject, enrollment, devices, sessions):
  --admin-socket <path>   Local admin IPC endpoint
                          (env: CESSPACE_ARC_ADMIN_SOCKET)
  --admin-key-fd <n>      Inherited file descriptor holding the operator
                          Ed25519 private key, base64 DER PKCS#8
                          (env: CESSPACE_ARC_ADMIN_PRIVATE_KEY_FD)

  The private key is read only from the inherited descriptor. It is never
  accepted through argv, the environment, a config file, or a default path.

Device and session administration options:
  --label <text>          New display label for \`devices rename\` (<= 64 UTF-8 bytes)
  --spki-pin <64hex>      Public SPKI pin for \`devices pin-add\` / \`devices pin-remove\`

  These commands are reachable ONLY over the local authenticated admin channel.
  There is no remote, HTTP, or MCP equivalent, and no command here prints a
  session token, a token digest, an enrollment secret, or private key material.

policy test options:
  --format <json|yaml>        Policy format (inferred from .json/.yaml/.yml)
  --workspace <id>=<path>     Register a local test workspace (repeatable)
  --tool <name>               Evaluate this tool
  --path <relpath>            Workspace-relative target path
  --executable <basename>     Executable basename
  --git-branch <branch>       Git branch
  --git-action <action>       Git action

  Without --tool, the policy is only validated, normalized, and hashed.

audit options (local operator only):
  --dir <path>            Audit store directory (default: ~/.cesspace-arc/audit)
  --checkpoint-key <path> PUBLIC Ed25519 checkpoint key (status, verify, export)
  --anchor-key <path>     PUBLIC Ed25519 anchor receipt key (anchor mode only)
  --workspace <path>      Authoritative agent workspace root (repeatable)
  --no-workspaces         Authoritatively assert this host has NO workspaces
  --from <seq>            First sequence, inclusive (inspect, export)
  --to <seq>              Last sequence, inclusive (inspect, export)
  --limit <n>             Maximum records to display (inspect, max 100)
  --output <dir>          New evidence bundle directory (export)

  \`arc audit\` reads filesystem evidence directly. It opens no admin channel,
  accepts no --admin-socket or --admin-key-fd, requires no running server, and
  uses PUBLIC verification keys only. No private signing key is ever read.
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
function takeValue(argv: readonly string[], index: number, option: string): string {
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

/**
 * Bounded admin failure contexts.
 *
 * The context selects only the human-readable sentence; the code set is shared,
 * so no command can introduce a new operator-visible failure vocabulary.
 */
type AdminFailureContext = 'approval' | 'enrollment' | 'device' | 'session';

/** The per-context sentences for codes whose wording depends on the subject. */
const NOT_FOUND_MESSAGES: Record<AdminFailureContext, string> = {
  approval: 'No pending approval matches that request ID.\n',
  enrollment: 'No pending enrollment matches that enrollment ID.\n',
  device: 'No enrolled device matches that device ID.\n',
  session: 'No live session matches that session ID.\n',
};

const EXHAUSTED_MESSAGES: Record<AdminFailureContext, string> = {
  approval: 'Approval resource limits were reached.\n',
  enrollment: 'Pending enrollment limits were reached.\n',
  device: 'The device would exceed the two active SPKI pin limit.\n',
  session: 'Session resource limits were reached.\n',
};

/**
 * Renders a bounded admin failure on stderr. Never includes key material, and
 * never distinguishes one internal cause from another.
 */
function reportAdminFailure(
  io: CliIo,
  response: AdminResponse,
  context: AdminFailureContext = 'approval',
): number {
  const code = response.error?.code ?? 'INTERNAL_ERROR';
  if (code === 'AUTHENTICATION_FAILED') {
    io.stderr('Admin authentication failed. The operator key was not accepted.\n');
  } else if (code === 'INVALID_ADMIN_REQUEST') {
    io.stderr('Admin request was rejected as invalid.\n');
  } else if (code === 'NOT_FOUND_OR_NOT_PENDING') {
    io.stderr(NOT_FOUND_MESSAGES[context]);
  } else if (code === 'APPROVAL_EXPIRED') {
    io.stderr('The approval request has expired.\n');
  } else if (code === 'APPROVAL_REJECTED') {
    io.stderr('The approval request could not be acted on.\n');
  } else if (code === 'RESOURCE_EXHAUSTED') {
    io.stderr(EXHAUSTED_MESSAGES[context]);
  } else if (code === 'ADMINISTRATION_UNAVAILABLE') {
    // Deliberately undifferentiated: the operator learns that device and
    // session administration is not currently answerable by an authoritative
    // composition, and nothing about why or what the durable state is.
    io.stderr('Device and session administration is unavailable on this server.\n');
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
/**
 * Persisted client identity bounds, matching the authoritative domain rules in
 * @cesspace-arc/auth: clientId <= 128 characters, clientType <= 64 characters.
 * Character counts, not bytes, because that is what the trust-store schema
 * enforces. The server re-validates authoritatively.
 */
const ENROLLMENT_MAX_CLIENT_ID_CHARS = 128;
const ENROLLMENT_MAX_CLIENT_TYPE_CHARS = 64;

interface EnrollmentCreateOptions {
  clientId: string;
  clientType: string;
  spkiPin: string;
  displayLabel?: string;
}

/** Validates a required bounded identifier supplied on the command line. */
function validateEnrollmentIdentifier(
  value: string | undefined,
  option: string,
  maxChars: number,
): string {
  if (value === undefined || value.trim().length === 0) {
    throw new UsageError(`${option} is required.`);
  }
  if (value.includes('\u0000')) {
    throw new UsageError(`${option} must not contain NUL.`);
  }
  if (value.length > maxChars) {
    throw new UsageError(`${option} must not exceed ${maxChars} characters.`);
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

  const validatedClientId = validateEnrollmentIdentifier(
    clientId,
    '--client-id',
    ENROLLMENT_MAX_CLIENT_ID_CHARS,
  );
  const validatedClientType = validateEnrollmentIdentifier(
    clientType,
    '--client-type',
    ENROLLMENT_MAX_CLIENT_TYPE_CHARS,
  );

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
// RC-05 Task 9: local device and session administration
//
// Reachable ONLY over the local authenticated admin channel: there is no remote
// equivalent, no HTTP or WebSocket admin API, and no MCP admin tool, and these
// commands are useless without both an explicitly configured admin endpoint and
// the operator private key in an inherited descriptor.
//
// Every argument is validated here BEFORE a connection is opened, as a
// convenience only. The server re-validates the same bounds authoritatively, so
// a client that skipped these checks could not reach a weaker code path.
//
// No command in this section prints a session token, a token digest, an
// enrollment secret, private key material, or TLS private material.
// ---------------------------------------------------------------------------

/** Validates a `<deviceId>` positional. */
function parseDeviceId(value: unknown): string {
  if (typeof value !== 'string' || !ADMIN_DEVICE_ID_REGEX.test(value)) {
    throw new UsageError('deviceId must be exactly 32 lowercase hexadecimal characters.');
  }
  return value;
}

/** Validates a `<sessionId>` positional. */
function parseSessionId(value: unknown): string {
  if (typeof value !== 'string' || !ADMIN_SESSION_ID_REGEX.test(value)) {
    throw new UsageError('sessionId must be exactly 64 lowercase hexadecimal characters.');
  }
  return value;
}

/** Validates an `--spki-pin` value: the canonical 64-lowercase-hex SPKI pin. */
function parseSpkiPin(value: unknown): string {
  if (typeof value !== 'string' || !ADMIN_SPKI_PIN_REGEX.test(value)) {
    throw new UsageError('--spki-pin must be exactly 64 lowercase hexadecimal characters.');
  }
  return value;
}

/** Validates an `--label` value against the Task-1 trust-store display bound. */
function parseDisplayLabel(value: unknown): string {
  if (typeof value !== 'string') {
    throw new UsageError('--label requires a value.');
  }
  if (value.includes('\u0000')) {
    throw new UsageError('--label must not contain NUL.');
  }
  if (Buffer.byteLength(value, 'utf8') > ADMIN_MAX_DISPLAY_LABEL_BYTES) {
    throw new UsageError(`--label must not exceed ${ADMIN_MAX_DISPLAY_LABEL_BYTES} UTF-8 bytes.`);
  }
  return value;
}

interface ParsedDeviceArgs {
  positional: string[];
  label?: string;
  spkiPin?: string;
}

/**
 * Splits a `devices` subcommand's arguments into positionals and the options
 * that subcommand accepts.
 *
 * `accepted` is per-subcommand, so an option that belongs to another subcommand
 * is rejected as unknown rather than silently ignored, and surplus positionals
 * are rejected by the caller.
 */
function parseDeviceArgs(args: readonly string[], accepted: readonly string[]): ParsedDeviceArgs {
  const positional: string[] = [];
  let label: string | undefined;
  let spkiPin: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--label' && accepted.includes('label')) {
      label = parseDisplayLabel(takeValue(args, i, '--label'));
      i++;
    } else if (arg === '--spki-pin' && accepted.includes('spkiPin')) {
      spkiPin = parseSpkiPin(takeValue(args, i, '--spki-pin'));
      i++;
    } else if (arg.startsWith('--')) {
      throw new UsageError(`Unknown option for this command: ${arg}`);
    } else {
      positional.push(arg);
    }
  }
  const parsed: ParsedDeviceArgs = { positional };
  if (label !== undefined) parsed.label = label;
  if (spkiPin !== undefined) parsed.spkiPin = spkiPin;
  return parsed;
}

/** `arc devices list` — bounded metadata only. Never discloses SPKI pins. */
function renderDevicesList(io: CliIo, result: unknown): number {
  const devices = (result as { devices?: unknown })?.devices;
  if (!Array.isArray(devices)) {
    io.stderr('Admin response was malformed.\n');
    return EXIT_FAILURE;
  }
  if (devices.length === 0) {
    io.stdout('No enrolled devices.\n');
    return EXIT_OK;
  }
  io.stdout(`Enrolled devices: ${devices.length}\n\n`);
  for (const entry of devices) {
    const device = entry as Record<string, unknown>;
    const label =
      typeof device.displayLabel === 'string' && device.displayLabel.length > 0
        ? device.displayLabel
        : '-';
    io.stdout(`  Device:   ${String(device.deviceId)}\n`);
    io.stdout(`  Client:   ${String(device.clientId)} (${String(device.clientType)})\n`);
    io.stdout(`  Label:    ${label}\n`);
    io.stdout(`  Enrolled: ${String(device.enrolledAt)}\n`);
    io.stdout(`  State:    ${device.revoked === true ? 'REVOKED' : 'ACTIVE'}\n`);
    io.stdout(`  Pins:     ${String(device.activePinCount)}\n\n`);
  }
  io.stdout('Run `arc devices inspect <deviceId>` to see active SPKI pins.\n');
  return EXIT_OK;
}

/** `arc devices inspect <deviceId>` — includes the active public SPKI pins. */
function renderDeviceInspect(io: CliIo, result: unknown): number {
  if (result === null || typeof result !== 'object') {
    io.stderr('Device inspection returned no result.\n');
    return EXIT_FAILURE;
  }
  const device = result as Record<string, unknown>;
  const label =
    typeof device.displayLabel === 'string' && device.displayLabel.length > 0
      ? device.displayLabel
      : '-';
  io.stdout(`Device:   ${String(device.deviceId)}\n`);
  io.stdout(`Client:   ${String(device.clientId)} (${String(device.clientType)})\n`);
  io.stdout(`Label:    ${label}\n`);
  io.stdout(`Enrolled: ${String(device.enrolledAt)}\n`);
  io.stdout(`State:    ${device.revoked === true ? 'REVOKED' : 'ACTIVE'}\n`);
  io.stdout(`\nActive SPKI pins:\n`);
  const pins = device.pins;
  if (!Array.isArray(pins) || pins.length === 0) {
    io.stdout('  (none)\n');
    return EXIT_OK;
  }
  for (const pin of pins) {
    io.stdout(`  ${String(pin)}\n`);
  }
  io.stdout('\nAt most two pins are active. Removing the final pin is refused.\n');
  return EXIT_OK;
}

/** `arc devices revoke <deviceId>` — durable, and immediate for sessions. */
function renderDeviceRevoke(io: CliIo, result: unknown): number {
  const device = (result ?? {}) as Record<string, unknown>;
  io.stdout(`Device ${String(device.deviceId)} ${String(device.revoked)}\n`);
  io.stdout(`Sessions revoked:   ${String(device.sessionsRevoked)}\n`);
  io.stdout(`Transports closed:  ${String(device.transportsClosed)}\n`);
  io.stdout('The device can no longer authenticate, and its live sessions are gone.\n');
  return EXIT_OK;
}

/** `arc devices rename <deviceId> --label <text>` — display metadata only. */
function renderDeviceRename(io: CliIo, result: unknown): number {
  const device = (result ?? {}) as Record<string, unknown>;
  io.stdout(`Device ${String(device.deviceId)} renamed.\n`);
  io.stdout(`Label: ${String(device.displayLabel)}\n`);
  io.stdout('Identity, pins, and authorization are unchanged.\n');
  return EXIT_OK;
}

/** `arc devices pin-add` / `arc devices pin-remove` — the overlap window. */
function renderDevicePinMutation(io: CliIo, result: unknown, action: 'added' | 'removed'): number {
  const device = (result ?? {}) as Record<string, unknown>;
  io.stdout(`Device ${String(device.deviceId)}: pin ${action}.\n`);
  io.stdout(`Active pins: ${String(device.activePinCount)}\n`);
  return EXIT_OK;
}

/** `arc sessions list` — live sessions only. Never a token or a token digest. */
function renderSessionsList(io: CliIo, result: unknown): number {
  const sessions = (result as { sessions?: unknown })?.sessions;
  if (!Array.isArray(sessions)) {
    io.stderr('Admin response was malformed.\n');
    return EXIT_FAILURE;
  }
  if (sessions.length === 0) {
    io.stdout('No live sessions.\n');
    return EXIT_OK;
  }
  io.stdout(`Live sessions: ${sessions.length}\n\n`);
  for (const entry of sessions) {
    const session = entry as Record<string, unknown>;
    io.stdout(`  Session:  ${String(session.sessionId)}\n`);
    io.stdout(`  Device:   ${String(session.deviceId)}\n`);
    io.stdout(`  Client:   ${String(session.clientId)} (${String(session.clientType)})\n`);
    io.stdout(`  Issued:   ${String(session.issuedAt)}\n`);
    io.stdout(`  State:    ${String(session.state)}\n\n`);
  }
  io.stdout('Run `arc sessions revoke <sessionId>` to end one session.\n');
  return EXIT_OK;
}

/** `arc sessions revoke <sessionId>` — exactly one session. */
function renderSessionRevoke(io: CliIo, result: unknown): number {
  const session = (result ?? {}) as Record<string, unknown>;
  io.stdout(`Session ${String(session.sessionId)} ${String(session.state)}\n`);
  io.stdout(`Transport closed: ${session.transportClosed === true ? 'yes' : 'no'}\n`);
  io.stdout('The session credential is invalid immediately.\n');
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
      command === 'enrollment' ||
      command === 'devices' ||
      command === 'sessions'
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

      if (head === 'devices') {
        const sub = rest[1];
        if (sub === 'list') {
          if (rest.length !== 2) {
            throw new UsageError('devices list takes no further arguments.');
          }
          const response = await callAdmin(io, config, 'devices.list', {});
          if (!response.ok) return reportAdminFailure(io, response, 'device');
          return renderDevicesList(io, response.result);
        }
        if (sub === 'inspect') {
          if (rest.length !== 3) {
            throw new UsageError('devices inspect requires exactly one <deviceId>.');
          }
          const deviceId = parseDeviceId(rest[2]);
          const response = await callAdmin(io, config, 'devices.inspect', { deviceId });
          if (!response.ok) return reportAdminFailure(io, response, 'device');
          return renderDeviceInspect(io, response.result);
        }
        if (sub === 'revoke') {
          if (rest.length !== 3) {
            throw new UsageError('devices revoke requires exactly one <deviceId>.');
          }
          const deviceId = parseDeviceId(rest[2]);
          const response = await callAdmin(io, config, 'device.revoke', { deviceId });
          if (!response.ok) return reportAdminFailure(io, response, 'device');
          return renderDeviceRevoke(io, response.result);
        }
        if (sub === 'rename') {
          const parsed = parseDeviceArgs(rest.slice(2), ['label']);
          if (parsed.positional.length !== 1) {
            throw new UsageError('devices rename requires exactly one <deviceId>.');
          }
          if (parsed.label === undefined) {
            throw new UsageError('devices rename requires --label <text>.');
          }
          const deviceId = parseDeviceId(parsed.positional[0]);
          const response = await callAdmin(io, config, 'device.rename', {
            deviceId,
            displayLabel: parsed.label,
          });
          if (!response.ok) return reportAdminFailure(io, response, 'device');
          return renderDeviceRename(io, response.result);
        }
        if (sub === 'pin-add' || sub === 'pin-remove') {
          const parsed = parseDeviceArgs(rest.slice(2), ['spkiPin']);
          if (parsed.positional.length !== 1) {
            throw new UsageError(`devices ${sub} requires exactly one <deviceId>.`);
          }
          if (parsed.spkiPin === undefined) {
            throw new UsageError(`devices ${sub} requires --spki-pin <64hex>.`);
          }
          const deviceId = parseDeviceId(parsed.positional[0]);
          const method = sub === 'pin-add' ? 'device.pin.add' : 'device.pin.remove';
          const response = await callAdmin(io, config, method, {
            deviceId,
            spkiPin: parsed.spkiPin,
          });
          if (!response.ok) return reportAdminFailure(io, response, 'device');
          return renderDevicePinMutation(
            io,
            response.result,
            sub === 'pin-add' ? 'added' : 'removed',
          );
        }
        throw new UsageError(`Unknown devices subcommand: ${String(sub)}`);
      }

      if (head === 'sessions') {
        const sub = rest[1];
        if (sub === 'list') {
          if (rest.length !== 2) {
            throw new UsageError('sessions list takes no further arguments.');
          }
          const response = await callAdmin(io, config, 'sessions.list', {});
          if (!response.ok) return reportAdminFailure(io, response, 'session');
          return renderSessionsList(io, response.result);
        }
        if (sub === 'revoke') {
          if (rest.length !== 3) {
            throw new UsageError('sessions revoke requires exactly one <sessionId>.');
          }
          const sessionId = parseSessionId(rest[2]);
          const response = await callAdmin(io, config, 'session.revoke', { sessionId });
          if (!response.ok) return reportAdminFailure(io, response, 'session');
          return renderSessionRevoke(io, response.result);
        }
        throw new UsageError(`Unknown sessions subcommand: ${String(sub)}`);
      }
    }

    if (command === 'policy') {
      if (args[1] !== 'test') {
        throw new UsageError(`Unknown policy subcommand: ${String(args[1])}`);
      }
      const options = parsePolicyTestArgs(args.slice(2));
      return runPolicyTest(io, options);
    }

    // The audit group is local-only by construction: it is dispatched HERE,
    // outside the admin gate above, so `resolveAdminConfig`, `stripAdminOptions`
    // and `callAdmin` are never reached and no admin option is even parsed. The
    // commands read filesystem evidence directly and require no running server.
    if (command === 'audit') {
      return await runAuditCommand(io, args.slice(1));
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

/**
 * CesSpace ARC — RC-06 Task 7: `arc audit` — the local operator evidence commands.
 *
 * ## Local operator only
 *
 * Every command here reads the filesystem evidence directly. None of them:
 *
 * - opens the admin IPC channel, or accepts `--admin-socket` / `--admin-key-fd`;
 * - constructs an `AdminIpcClient`;
 * - talks to a running MCP server, trusts one, or requires one to be running;
 * - exposes any remote, gateway, HTTP or WebSocket audit surface.
 *
 * They work with the server stopped, and they are deliberately wired outside the
 * admin command gate in `index.ts` so that no admin option is even parsed on
 * this path. Audit administration never leaves the local operator shell.
 *
 * ## No private keys
 *
 * The commands take PUBLIC verification keys only. There is no flag, environment
 * variable or default path for a checkpoint signing key, and none is ever read —
 * `verify`, `inspect` and `export` are read-only observations.
 *
 * @packageDocumentation
 */

import { DEFAULT_AUDIT_DIR } from '@cesspace-arc/audit';
import {
  exportEvidenceBundle,
  inspectRetainedRecords,
  readOfflineAuditStatus,
  verifyOfflineStore,
} from '@cesspace-arc/audit';

/** Exit codes. Kept identical to the CLI's own frozen constants. */
export const AUDIT_EXIT_OK = 0;
export const AUDIT_EXIT_FAILURE = 1;
export const AUDIT_EXIT_USAGE = 2;

/** The output pair the audit commands are given, satisfied by the CLI's `CliIo`. */
export interface AuditCommandIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
}

/**
 * Coded failures that describe malformed OPERATOR INPUT rather than bad
 * evidence. They exit as usage errors, matching the CLI's convention that a
 * command line the operator got wrong is a usage problem, not a store problem.
 */
const USAGE_CODES: ReadonlySet<string> = new Set([
  'INVALID_SEQUENCE_RANGE',
  'INSPECT_LIMIT_EXCEEDED',
  'INVALID_EXPORT_PATH',
]);

/** A usage failure: reported on stderr and mapped to the usage exit code. */
class AuditUsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuditUsageError';
  }
}

/** Parsed audit options, shared by every subcommand. */
interface ParsedAuditOptions {
  dir: string;
  checkpointKeyPath?: string;
  anchorKeyPath?: string;
  /**
   * The authoritative workspace roots, or `undefined` when the operator has not
   * said anything about them.
   *
   * The distinction is the whole point: "no --workspace was given" is NOT the
   * same statement as "there are no workspaces". Only an explicit
   * `--no-workspaces` (or at least one `--workspace`) makes the set
   * authoritative, and anything else leaves it unknown so the export can fail
   * closed rather than manufacture an empty list nobody asserted.
   */
  workspacePaths?: string[];
  from?: number;
  to?: number;
  limit?: number;
  output?: string;
}

/** Reads an option value, failing closed when the value is absent. */
function takeValue(argv: readonly string[], index: number, option: string): string {
  const value = argv[index + 1];
  if (value === undefined || value.startsWith('--')) {
    throw new AuditUsageError(`${option} requires a value.`);
  }
  return value;
}

/**
 * Strict positive-integer parsing.
 *
 * Rejects signs, decimals, whitespace, empty strings and anything beyond the
 * safe-integer range, so `--from 1e9` or `--from -1` are usage errors rather
 * than a silently coerced sequence number.
 */
function parsePositiveInteger(value: unknown, option: string): number {
  if (typeof value !== 'string' || !/^[0-9]{1,16}$/.test(value)) {
    throw new AuditUsageError(`${option} must be a positive integer.`);
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new AuditUsageError(`${option} must be a positive integer.`);
  }
  return parsed;
}

/**
 * Parses the options shared by every audit subcommand.
 *
 * `accepted` is a per-subcommand allowlist, matching the CLI's existing
 * device-command convention: an option that is not meaningful for the
 * subcommand in front of the operator is an error, never silently ignored.
 */
function parseAuditOptions(
  argv: readonly string[],
  accepted: readonly string[],
): ParsedAuditOptions {
  const parsed: ParsedAuditOptions = { dir: DEFAULT_AUDIT_DIR };
  let declaredNoWorkspaces = false;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--dir' && accepted.includes('dir')) {
      parsed.dir = takeValue(argv, i, '--dir');
      i += 1;
    } else if (arg === '--checkpoint-key' && accepted.includes('checkpoint-key')) {
      parsed.checkpointKeyPath = takeValue(argv, i, '--checkpoint-key');
      i += 1;
    } else if (arg === '--anchor-key' && accepted.includes('anchor-key')) {
      parsed.anchorKeyPath = takeValue(argv, i, '--anchor-key');
      i += 1;
    } else if (arg === '--workspace' && accepted.includes('workspace')) {
      parsed.workspacePaths = [...(parsed.workspacePaths ?? []), takeValue(argv, i, '--workspace')];
      i += 1;
    } else if (arg === '--no-workspaces' && accepted.includes('workspace')) {
      // A value-less flag: it must NOT consume the following token, or the next
      // option's own value would be swallowed as a positional.
      declaredNoWorkspaces = true;
    } else if (arg === '--output' && accepted.includes('output')) {
      parsed.output = takeValue(argv, i, '--output');
      i += 1;
    } else if (arg === '--from' && accepted.includes('from')) {
      parsed.from = parsePositiveInteger(takeValue(argv, i, '--from'), '--from');
      i += 1;
    } else if (arg === '--to' && accepted.includes('to')) {
      parsed.to = parsePositiveInteger(takeValue(argv, i, '--to'), '--to');
      i += 1;
    } else if (arg === '--limit' && accepted.includes('limit')) {
      parsed.limit = parsePositiveInteger(takeValue(argv, i, '--limit'), '--limit');
      i += 1;
    } else {
      throw new AuditUsageError(`Unknown option for this audit command: ${arg}`);
    }
  }

  if (declaredNoWorkspaces) {
    if (parsed.workspacePaths !== undefined) {
      throw new AuditUsageError('--no-workspaces cannot be combined with --workspace.');
    }
    // An explicit, authoritative assertion that this host has no agent
    // workspaces. Only this makes an empty set a statement rather than a default.
    parsed.workspacePaths = [];
  }

  return parsed;
}

/** The public verification keys, in the shape the audit package expects. */
function verificationKeys(parsed: ParsedAuditOptions): { checkpointPublicKeyPath: string } {
  if (parsed.checkpointKeyPath === undefined) {
    throw new AuditUsageError(
      '--checkpoint-key <path> is required: verification needs the PUBLIC checkpoint key.',
    );
  }
  return { checkpointPublicKeyPath: parsed.checkpointKeyPath };
}

function line(io: AuditCommandIo, label: string, value: string): void {
  io.stdout(`${`${label}:`.padEnd(24)}${value}\n`);
}

/* -------------------------------------------------------------------------- *
 * Subcommands
 * -------------------------------------------------------------------------- */

async function runStatus(io: AuditCommandIo, argv: readonly string[]): Promise<number> {
  const parsed = parseAuditOptions(argv, ['dir', 'checkpoint-key', 'anchor-key', 'workspace']);
  const status = await readOfflineAuditStatus({
    directory: parsed.dir,
    workspacePaths: parsed.workspacePaths ?? [],
    ...verificationKeys(parsed),
    ...(parsed.anchorKeyPath === undefined
      ? {}
      : { anchorReceiptPublicKeyPath: parsed.anchorKeyPath }),
  });

  io.stdout('Audit store status\n\n');
  line(io, 'Storage path', status.storagePath);
  line(io, 'Store ID', status.storeId);
  line(io, 'Anchor mode', status.anchorMode);
  line(
    io,
    'Active segment',
    `${status.activeSegment.filename}${status.activeSegment.present ? '' : ' (absent)'}`,
  );
  line(io, 'Retained segments', String(status.totalRetainedSegments));
  line(io, 'Current sequence', String(status.currentSequence));
  line(
    io,
    'Last checkpoint',
    status.lastCheckpointSequence === null ? 'none' : String(status.lastCheckpointSequence),
  );
  line(io, 'Unanchored', String(status.unanchoredCheckpointCount));
  line(io, 'Recoveries', String(status.indeterminateRecoveries));
  line(io, 'Integrity', status.integrity);
  return AUDIT_EXIT_OK;
}

async function runVerify(io: AuditCommandIo, argv: readonly string[]): Promise<number> {
  const parsed = parseAuditOptions(argv, ['dir', 'checkpoint-key', 'anchor-key', 'workspace']);
  const result = await verifyOfflineStore({
    directory: parsed.dir,
    workspacePaths: parsed.workspacePaths ?? [],
    ...verificationKeys(parsed),
    ...(parsed.anchorKeyPath === undefined
      ? {}
      : { anchorReceiptPublicKeyPath: parsed.anchorKeyPath }),
  });

  io.stdout('Audit verification: VERIFIED\n\n');
  line(io, 'Store ID', result.storeId);
  line(io, 'Records', String(result.primary.recordCount));
  line(io, 'Terminal sequence', String(result.primary.terminalSequence));
  line(io, 'Retained segments', String(result.primary.logicalArchiveCount));
  line(io, 'Checkpoints', String(result.checkpoints.checkpointCount));
  line(io, 'Primary (Tier 1)', result.tiers.primary);
  line(io, 'Checkpoints (Tier 2)', result.tiers.checkpoint);
  if (result.anchor.configured) {
    line(io, 'Receipts', String(result.anchor.receiptCount));
    line(io, 'Anchoring (Tier 3)', result.tiers.anchor);
  } else {
    line(
      io,
      'Anchoring (Tier 3)',
      'NOT CONFIGURED — external anchoring is not enabled for this store',
    );
  }
  return AUDIT_EXIT_OK;
}

async function runInspect(io: AuditCommandIo, argv: readonly string[]): Promise<number> {
  const parsed = parseAuditOptions(argv, ['dir', 'workspace', 'from', 'to', 'limit']);
  const records = await inspectRetainedRecords({
    directory: parsed.dir,
    workspacePaths: parsed.workspacePaths ?? [],
    ...(parsed.from === undefined ? {} : { from: parsed.from }),
    ...(parsed.to === undefined ? {} : { to: parsed.to }),
    ...(parsed.limit === undefined ? {} : { limit: parsed.limit }),
  });

  if (records.length === 0) {
    io.stdout('No retained records matched the requested range.\n');
    return AUDIT_EXIT_OK;
  }

  io.stdout(`Retained records: ${records.length}\n\n`);
  for (const record of records) {
    // The persisted record is already the centrally redacted representation.
    // It is displayed as stored; no second redaction pass rewrites the evidence.
    io.stdout(`${JSON.stringify(record)}\n`);
  }
  return AUDIT_EXIT_OK;
}

async function runExport(io: AuditCommandIo, argv: readonly string[]): Promise<number> {
  const parsed = parseAuditOptions(argv, [
    'dir',
    'checkpoint-key',
    'anchor-key',
    'workspace',
    'from',
    'to',
    'output',
  ]);
  if (parsed.output === undefined) {
    throw new AuditUsageError('--output <dir> is required.');
  }

  const result = await exportEvidenceBundle({
    directory: parsed.dir,
    outputDirectory: parsed.output,
    // Deliberately NOT defaulted to []: an absent set means "unknown", and the
    // export refuses on that. Only an explicit operator statement reaches here
    // as an authoritative list.
    workspacePaths: parsed.workspacePaths,
    ...verificationKeys(parsed),
    ...(parsed.anchorKeyPath === undefined
      ? {}
      : { anchorReceiptPublicKeyPath: parsed.anchorKeyPath }),
    ...(parsed.from === undefined ? {} : { from: parsed.from }),
    ...(parsed.to === undefined ? {} : { to: parsed.to }),
  });

  io.stdout('Evidence bundle written\n\n');
  line(io, 'Output', result.outputDirectory);
  line(io, 'Store ID', result.manifest.storeId);
  line(
    io,
    'Sequence range',
    `${result.manifest.sequenceRange.start}..${result.manifest.sequenceRange.end}`,
  );
  line(io, 'Files', String(result.fileCount));
  line(io, 'Bytes', String(result.totalBytes));
  line(io, 'Checkpoints', String(result.manifest.checkpointHashes.length));
  line(io, 'Anchor receipts', String(result.manifest.anchorReceiptIds.length));
  return AUDIT_EXIT_OK;
}

/* -------------------------------------------------------------------------- *
 * Entry point
 * -------------------------------------------------------------------------- */

const AUDIT_HELP = `Usage:
  arc audit status [options]
  arc audit verify [options]
  arc audit inspect [--from <seq>] [--to <seq>] [--limit <n>] [options]
  arc audit export --output <dir> [--from <seq>] [--to <seq>] [options]

audit options:
  --dir <path>            Audit store directory (default: ~/.cesspace-arc/audit)
  --checkpoint-key <path> PUBLIC Ed25519 checkpoint key (status, verify, export)
  --anchor-key <path>     PUBLIC Ed25519 anchor receipt key (anchor mode only)
  --workspace <path>      Authoritative agent workspace root (repeatable)
  --no-workspaces         Authoritatively assert this host has NO workspaces
  --from <seq>            First sequence, inclusive (inspect, export)
  --to <seq>              Last sequence, inclusive (inspect, export)
  --limit <n>             Maximum records to display (inspect, max 100)
  --output <dir>          New evidence bundle directory (export)

  \`export\` refuses to run unless the workspace roots are authoritatively
  known: supply --workspace (repeatable) or --no-workspaces. An unstated set is
  treated as unknown, never as empty.

  These commands are LOCAL ONLY. They read filesystem evidence directly and
  never open the admin channel: --admin-socket and --admin-key-fd are not
  accepted here, and no running server is required. Only PUBLIC verification
  keys are used; a private signing key is never read.
`;

/**
 * Runs one `arc audit` invocation.
 *
 * Returns an exit code rather than throwing, matching the CLI's other local
 * command (`arc policy test`): usage failures map to the usage code, and every
 * other failure is reported as a bounded `CODE: message` pair — never a raw
 * internal error, and never any key material.
 */
export async function runAuditCommand(
  io: AuditCommandIo,
  argv: readonly string[],
): Promise<number> {
  const sub = argv[0];

  try {
    if (sub === '--help' || sub === '-h' || sub === 'help' || sub === undefined) {
      io.stdout(AUDIT_HELP);
      return AUDIT_EXIT_OK;
    }
    if (sub === 'status') return await runStatus(io, argv.slice(1));
    if (sub === 'verify') return await runVerify(io, argv.slice(1));
    if (sub === 'inspect') return await runInspect(io, argv.slice(1));
    if (sub === 'export') return await runExport(io, argv.slice(1));
    throw new AuditUsageError(`Unknown audit subcommand: ${String(sub)}`);
  } catch (err: unknown) {
    if (err instanceof AuditUsageError) {
      io.stderr(`${err.message}\n`);
      return AUDIT_EXIT_USAGE;
    }
    const coded = err as { code?: string; message?: string };
    if (typeof coded.code === 'string' && typeof coded.message === 'string') {
      // Some coded errors already carry their code in the message; never print
      // it twice.
      const detail = coded.message.startsWith(coded.code)
        ? coded.message
        : `${coded.code}: ${coded.message}`;
      io.stderr(`${detail}\n`);
      return USAGE_CODES.has(coded.code) ? AUDIT_EXIT_USAGE : AUDIT_EXIT_FAILURE;
    }
    io.stderr('Audit command failed.\n');
    return AUDIT_EXIT_FAILURE;
  }
}

/** The audit group's help text, for the top-level CLI help. */
export function auditHelpText(): string {
  return AUDIT_HELP;
}

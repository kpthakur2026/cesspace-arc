/**
 * ARC 1.0 Task 2 — strict Core configuration and transactional state lifecycle.
 *
 * Product identity and persistent schema identity are deliberately independent.
 * Schema-1 RC-08 state migrates explicitly into stable schema-2 Core state.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DeviceTrustStore } from '@cesspace-arc/auth';
import {
  redactString,
  verifyOfflineStore,
  type OfflineVerificationResult,
} from '@cesspace-arc/audit';
import { parseDocument } from 'yaml';
import { isPreCommitFaultEnabled } from './internal-test-seam.js';

export const CORE_PRODUCT_VERSION = '1.0.0';
export const CORE_HEALTH_STAGE = 'ARC-1.0';
export const LEGACY_CORE_PRODUCT_VERSION = '0.8.0-rc08';
export const CORE_CONFIG_SCHEMA_VERSION = 2;
export const CORE_STATE_SCHEMA_VERSION = 2;
export const CORE_MIGRATION_VERSION = 1;
export const SUPPORTED_SOURCE_STATE_SCHEMA_VERSIONS = Object.freeze([1, 2] as const);
export const CORE_CONFIG_FILENAME = 'core-config.json';
export const CORE_STATE_METADATA_FILENAME = 'state-metadata.json';
export const CORE_LIVE_STATE_DIRECTORY = 'state';
export const CORE_MIGRATION_DIRECTORY = '.arc10-migration';
export const CORE_MIGRATION_JOURNAL_FILENAME = 'journal.json';
export const CORE_MIGRATION_LOCK_FILENAME = 'migration.lock';
export const CORE_ENVIRONMENT_ALLOWLIST = Object.freeze(['CESSPACE_ARC_LOG_LEVEL'] as const);

const MAX_CONFIG_BYTES = 256 * 1024;
const MAX_SECRET_BYTES = 64 * 1024;
const MAX_PATH_BYTES = 4096;
const MAX_WORKSPACES = 32;
const MAX_STATE_FILES = 10_000;
const MAX_STATE_FILE_BYTES = 64 * 1024 * 1024;
const MAX_STATE_TOTAL_BYTES = 1024 * 1024 * 1024;
const MAX_JOURNAL_BYTES = 32 * 1024;
const HASH_REGEX = /^[0-9a-f]{40,64}$/;
const SHA256_REGEX = /^[0-9a-f]{64}$/;
const ID_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/;

export type CoreLogLevel = 'error' | 'warn' | 'info';

export interface CoreWorkspaceConfig {
  readonly id: string;
  readonly root: string;
}

export type CoreTransportConfig =
  | { readonly kind: 'stdio' }
  | {
      readonly kind: 'remote';
      readonly bindHost: string;
      readonly port: number;
      readonly publicHostname: string;
      readonly serverCertificatePath: string;
      readonly privateKeyPath: string;
      readonly clientCaPaths: readonly string[];
    };

export interface CoreConfigV2 {
  readonly schemaVersion: 2;
  readonly productVersion: '1.0.0';
  readonly profile: 'core';
  readonly transport: CoreTransportConfig;
  readonly workspaces: readonly CoreWorkspaceConfig[];
  readonly defaultWorkspaceId: string;
  readonly policy: { readonly path: string };
  readonly audit: {
    readonly directory: string;
    readonly signingKeyPath: string;
    readonly publicKeyPath: string;
  };
  readonly admin?: {
    readonly socketPath: string;
    readonly operatorPublicKeyPath: string;
  };
  readonly state: {
    readonly trustStorePath: string;
    readonly processDirectory: string;
  };
  readonly observability: { readonly logLevel: CoreLogLevel };
}

interface CoreConfigV1 extends Omit<CoreConfigV2, 'schemaVersion' | 'productVersion' | 'profile'> {
  readonly schemaVersion: 1;
  readonly productVersion: '0.8.0-rc08';
}

export interface CoreStateMetadata {
  readonly format: 'cesspace-arc-core-state';
  readonly stateSchemaVersion: 1 | 2;
  readonly configSchemaVersion: 1 | 2;
  readonly productVersion: '0.8.0-rc08' | '1.0.0';
  readonly sourceCommit: string;
  readonly sourceTree: string;
  readonly profile: 'core';
  readonly migrationVersion?: 1;
}

export interface ResolvedCoreConfig {
  readonly config: CoreConfigV2;
  readonly stateDirectory: string;
  readonly policyPath: string;
  readonly auditDirectory: string;
  readonly auditSigningKeyPath: string;
  readonly auditPublicKeyPath: string;
  readonly trustStorePath: string;
  readonly processDirectory: string;
  readonly adminSocketPath?: string;
  readonly operatorPublicKeyPath?: string;
}

export interface CorePreflightResult {
  readonly resolved: ResolvedCoreConfig;
  readonly devices: number;
  readonly audit: OfflineVerificationResult;
  readonly state: CoreStateMetadata;
}

export type MigrationLifecycleState =
  'STAGED' | 'COMMITTING' | 'COMMITTED' | 'RECOVERED' | 'ROLLED_BACK';

export interface MigrationEvidence {
  readonly format: 'cesspace-arc-migration-v1';
  readonly migrationVersion: 1;
  readonly lifecycle: MigrationLifecycleState;
  readonly sourceSchemaVersion: 1;
  readonly targetSchemaVersion: 2;
  readonly sourceConfigSchemaVersion: 1;
  readonly targetConfigSchemaVersion: 2;
  readonly sourceDigest: string;
  readonly backupDigest: string;
  readonly stagedDigest: string;
  readonly committedDigest?: string;
  readonly restoredDigest?: string;
  readonly reversible: boolean;
  readonly steps: readonly string[];
  readonly audit: {
    readonly storeId: string;
    readonly terminalSequence: number;
    readonly terminalRecordHash: string;
    readonly checkpointCount: number;
    readonly lastCheckpointHash: string | null;
  };
}

export interface MigrationResult {
  readonly result: 'MIGRATED' | 'ALREADY_CURRENT';
  readonly evidence: MigrationEvidence | null;
  readonly stateDigest: string;
}

export interface RecoveryResult {
  readonly result: 'NO_RECOVERY_NEEDED' | 'ORIGINAL_RESTORED' | 'COMMIT_COMPLETED';
  readonly stateDigest: string;
}

export interface RollbackResult {
  readonly result: 'ROLLED_BACK';
  readonly stateDigest: string;
  readonly evidence: MigrationEvidence;
}

export class CoreLifecycleError extends Error {
  public readonly code: string;

  public constructor(code: string, message: string) {
    super(redactString(message).slice(0, 512));
    this.name = 'CoreLifecycleError';
    this.code = code;
  }
}

function fail(code: string, message: string): never {
  throw new CoreLifecycleError(code, message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function closedRecord(
  value: unknown,
  allowed: readonly string[],
  label: string,
): Record<string, unknown> {
  if (!isRecord(value)) fail('CONFIG_INVALID', `${label} must be an object.`);
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(value)) {
    if (!allowedSet.has(key)) fail('UNKNOWN_CONFIG_FIELD', `Unknown ${label} field '${key}'.`);
  }
  return value;
}

function boundedString(value: unknown, label: string, maxBytes = MAX_PATH_BYTES): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    Buffer.byteLength(value, 'utf8') > maxBytes ||
    /[\0\r\n]/u.test(value)
  ) {
    fail('CONFIG_INVALID', `${label} must be a bounded non-empty string.`);
  }
  return value;
}

function relativeSelector(value: unknown, label: string): string {
  const selected = boundedString(value, label);
  if (
    path.isAbsolute(selected) ||
    selected.includes('\\') ||
    selected.split('/').some((part) => part === '' || part === '.' || part === '..') ||
    path.posix.normalize(selected) !== selected
  ) {
    fail('CONFIG_PATH_INVALID', `${label} must be a normalized state-relative path.`);
  }
  return selected;
}

function absoluteWorkspace(value: unknown): string {
  const selected = boundedString(value, 'workspace root');
  if (!path.isAbsolute(selected)) fail('CONFIG_PATH_INVALID', 'Workspace root must be absolute.');
  return path.normalize(selected);
}

function parseStrictJson(text: string, label: string): unknown {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    fail('CONFIG_PARSE_FAILED', `${label} is not valid JSON.`);
  }
  const document = parseDocument(text, { schema: 'json', strict: true, uniqueKeys: true });
  if (document.errors.length > 0) {
    fail('CONFIG_PARSE_FAILED', `${label} contains duplicate or invalid JSON keys.`);
  }
  return parsed;
}

function parseTransport(value: unknown): CoreTransportConfig {
  const record = closedRecord(
    value,
    [
      'kind',
      'bindHost',
      'port',
      'publicHostname',
      'serverCertificatePath',
      'privateKeyPath',
      'clientCaPaths',
    ],
    'transport',
  );
  if (record.kind === 'stdio') {
    if (Object.keys(record).length !== 1)
      fail('CONFIG_INCOMPATIBLE', 'stdio transport cannot carry remote selectors.');
    return { kind: 'stdio' };
  }
  if (record.kind !== 'remote') fail('CONFIG_INVALID', 'Transport kind is unsupported.');
  if (!Number.isInteger(record.port) || Number(record.port) < 1 || Number(record.port) > 65535)
    fail('CONFIG_INVALID', 'Remote port must be an integer from 1 through 65535.');
  if (
    !Array.isArray(record.clientCaPaths) ||
    record.clientCaPaths.length < 1 ||
    record.clientCaPaths.length > 4
  )
    fail('CONFIG_INVALID', 'Remote client CA selectors must contain one through four paths.');
  const clientCaPaths = record.clientCaPaths.map((item) =>
    relativeSelector(item, 'client CA path'),
  );
  if (new Set(clientCaPaths).size !== clientCaPaths.length)
    fail('CONFIG_INVALID', 'Remote client CA selectors must be unique.');
  return {
    kind: 'remote',
    bindHost: boundedString(record.bindHost, 'remote bind host', 253),
    port: Number(record.port),
    publicHostname: boundedString(record.publicHostname, 'remote public hostname', 253),
    serverCertificatePath: relativeSelector(
      record.serverCertificatePath,
      'server certificate path',
    ),
    privateKeyPath: relativeSelector(record.privateKeyPath, 'server private-key path'),
    clientCaPaths,
  };
}

function parseCoreConfig(raw: unknown, expectedVersion: 1 | 2): CoreConfigV1 | CoreConfigV2 {
  const record = closedRecord(
    raw,
    [
      'schemaVersion',
      'productVersion',
      'profile',
      'transport',
      'workspaces',
      'defaultWorkspaceId',
      'policy',
      'audit',
      'admin',
      'state',
      'observability',
    ],
    'configuration',
  );
  if (record.schemaVersion !== expectedVersion)
    fail('CONFIG_SCHEMA_UNSUPPORTED', 'Configuration schema version is unsupported.');
  const expectedProductVersion =
    expectedVersion === 1 ? LEGACY_CORE_PRODUCT_VERSION : CORE_PRODUCT_VERSION;
  if (record.productVersion !== expectedProductVersion)
    fail('CONFIG_PRODUCT_MISMATCH', 'Configuration product version is unsupported.');
  if (expectedVersion === 2 && record.profile !== 'core')
    fail('CONFIG_INVALID', 'Configuration profile must be core.');
  if (expectedVersion === 1 && record.profile !== undefined)
    fail('UNKNOWN_CONFIG_FIELD', "Unknown configuration field 'profile'.");

  if (
    !Array.isArray(record.workspaces) ||
    record.workspaces.length < 1 ||
    record.workspaces.length > MAX_WORKSPACES
  )
    fail('CONFIG_INVALID', `Configuration must contain one through ${MAX_WORKSPACES} workspaces.`);
  const workspaces = record.workspaces.map((item) => {
    const workspace = closedRecord(item, ['id', 'root'], 'workspace');
    const id = boundedString(workspace.id, 'workspace id', 64);
    if (!ID_REGEX.test(id)) fail('CONFIG_INVALID', 'Workspace id is malformed.');
    return { id, root: absoluteWorkspace(workspace.root) };
  });
  if (new Set(workspaces.map((item) => item.id)).size !== workspaces.length)
    fail('CONFIG_INVALID', 'Workspace identifiers must be unique.');
  if (new Set(workspaces.map((item) => item.root)).size !== workspaces.length)
    fail('CONFIG_INVALID', 'Workspace roots must be unique.');
  const defaultWorkspaceId = boundedString(record.defaultWorkspaceId, 'default workspace id', 64);
  if (!workspaces.some((item) => item.id === defaultWorkspaceId))
    fail('CONFIG_INCOMPATIBLE', 'Default workspace must name a registered workspace.');

  const policy = closedRecord(record.policy, ['path'], 'policy');
  const audit = closedRecord(
    record.audit,
    ['directory', 'signingKeyPath', 'publicKeyPath'],
    'audit',
  );
  const state = closedRecord(record.state, ['trustStorePath', 'processDirectory'], 'state');
  const observability = closedRecord(record.observability, ['logLevel'], 'observability');
  if (!['error', 'warn', 'info'].includes(String(observability.logLevel)))
    fail('CONFIG_INVALID', 'Observability log level is unsupported.');

  let admin: CoreConfigV2['admin'];
  if (record.admin !== undefined) {
    const parsedAdmin = closedRecord(
      record.admin,
      ['socketPath', 'operatorPublicKeyPath'],
      'admin',
    );
    admin = {
      socketPath: relativeSelector(parsedAdmin.socketPath, 'admin socket path'),
      operatorPublicKeyPath: relativeSelector(
        parsedAdmin.operatorPublicKeyPath,
        'operator public-key path',
      ),
    };
  }

  const common = {
    productVersion: expectedProductVersion,
    transport: parseTransport(record.transport),
    workspaces,
    defaultWorkspaceId,
    policy: { path: relativeSelector(policy.path, 'policy path') },
    audit: {
      directory: relativeSelector(audit.directory, 'audit directory'),
      signingKeyPath: relativeSelector(audit.signingKeyPath, 'audit signing-key path'),
      publicKeyPath: relativeSelector(audit.publicKeyPath, 'audit public-key path'),
    },
    ...(admin === undefined ? {} : { admin }),
    state: {
      trustStorePath: relativeSelector(state.trustStorePath, 'trust-store path'),
      processDirectory: relativeSelector(state.processDirectory, 'process-state directory'),
    },
    observability: { logLevel: observability.logLevel as CoreLogLevel },
  };
  return expectedVersion === 1
    ? ({ schemaVersion: 1, ...common } as CoreConfigV1)
    : ({ schemaVersion: 2, profile: 'core', ...common } as CoreConfigV2);
}

function readBoundedRegularFile(filePath: string, maxBytes: number, label: string): Buffer {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(filePath);
  } catch {
    fail('FILE_INVALID', `${label} is unavailable.`);
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > maxBytes)
    fail('FILE_INVALID', `${label} is not an authorized bounded regular file.`);
  return fs.readFileSync(filePath);
}

function assertPublicFile(filePath: string, label: string): void {
  readBoundedRegularFile(filePath, MAX_CONFIG_BYTES, label);
}

function assertPublicConfigAuthority(filePath: string): void {
  const stat = fs.lstatSync(filePath);
  if ((stat.mode & 0o022) !== 0)
    fail('CONFIG_PERMISSIONS_INSECURE', 'Configuration must not be group/world writable.');
}

export function validateSecretFile(filePath: string, label = 'secret file'): void {
  let fd: number | null = null;
  try {
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const stat = fs.fstatSync(fd);
    const mode = stat.mode & 0o777;
    const expectedUid = typeof process.getuid === 'function' ? process.getuid() : stat.uid;
    if (
      !stat.isFile() ||
      stat.nlink !== 1 ||
      stat.uid !== expectedUid ||
      ![0o400, 0o600].includes(mode) ||
      stat.size < 1 ||
      stat.size > MAX_SECRET_BYTES
    ) {
      fail('SECRET_FILE_INSECURE', `${label} failed owner, mode, type, or size validation.`);
    }
  } catch (error) {
    if (error instanceof CoreLifecycleError) throw error;
    fail('SECRET_FILE_INSECURE', `${label} could not be opened securely.`);
  } finally {
    if (fd !== null) fs.closeSync(fd);
  }
}

function applyEnvironment(
  config: CoreConfigV2,
  environment: Readonly<Record<string, string | undefined>>,
): CoreConfigV2 {
  const raw = environment.CESSPACE_ARC_LOG_LEVEL;
  if (raw === undefined) return config;
  if (!['error', 'warn', 'info'].includes(raw))
    fail('ENV_OVERRIDE_INVALID', 'CESSPACE_ARC_LOG_LEVEL is invalid.');
  return { ...config, observability: { logLevel: raw as CoreLogLevel } };
}

function resolveInside(stateDirectory: string, selector: string): string {
  const resolved = path.resolve(stateDirectory, ...selector.split('/'));
  const prefix = `${path.resolve(stateDirectory)}${path.sep}`;
  if (!resolved.startsWith(prefix))
    fail('CONFIG_PATH_INVALID', 'State path escapes its authority.');
  let cursor = path.resolve(stateDirectory);
  for (const part of selector.split('/').slice(0, -1)) {
    cursor = path.join(cursor, part);
    if (fs.existsSync(cursor) && fs.lstatSync(cursor).isSymbolicLink())
      fail('CONFIG_PATH_INVALID', 'State path contains a symbolic-link component.');
  }
  return resolved;
}

export function loadCoreConfig(
  configPath: string,
  options: { environment?: Readonly<Record<string, string | undefined>> } = {},
): CoreConfigV2 {
  const bytes = readBoundedRegularFile(configPath, MAX_CONFIG_BYTES, 'Core configuration');
  assertPublicConfigAuthority(configPath);
  const parsed = parseCoreConfig(parseStrictJson(bytes.toString('utf8'), 'Core configuration'), 2);
  return applyEnvironment(parsed as CoreConfigV2, options.environment ?? {});
}

export function readCoreStateMetadata(stateDirectory: string): CoreStateMetadata {
  const bytes = readBoundedRegularFile(
    path.join(stateDirectory, CORE_STATE_METADATA_FILENAME),
    MAX_CONFIG_BYTES,
    'Core state metadata',
  );
  const record = closedRecord(
    parseStrictJson(bytes.toString('utf8'), 'Core state metadata'),
    [
      'format',
      'stateSchemaVersion',
      'configSchemaVersion',
      'productVersion',
      'sourceCommit',
      'sourceTree',
      'profile',
      'migrationVersion',
    ],
    'state metadata',
  );
  if (record.format !== 'cesspace-arc-core-state' || record.profile !== 'core')
    fail('STATE_METADATA_INVALID', 'Core state metadata identity is invalid.');
  if (
    ![1, 2].includes(record.stateSchemaVersion as number) ||
    ![1, 2].includes(record.configSchemaVersion as number)
  )
    fail('UNSUPPORTED_STATE_VERSION', 'Core state schema is newer or unsupported.');
  const expectedProductVersion =
    record.stateSchemaVersion === 1 ? LEGACY_CORE_PRODUCT_VERSION : CORE_PRODUCT_VERSION;
  if (record.productVersion !== expectedProductVersion)
    fail('STATE_METADATA_INVALID', 'Core state product identity is invalid.');
  if (!HASH_REGEX.test(String(record.sourceCommit)) || !HASH_REGEX.test(String(record.sourceTree)))
    fail('STATE_METADATA_INVALID', 'Core state source identity is invalid.');
  if (record.stateSchemaVersion === 2 && record.migrationVersion !== CORE_MIGRATION_VERSION)
    fail('STATE_METADATA_INVALID', 'Current Core state migration identity is invalid.');
  if (record.stateSchemaVersion === 1 && record.migrationVersion !== undefined)
    fail('STATE_METADATA_INVALID', 'Legacy Core state contains unexpected migration identity.');
  return record as unknown as CoreStateMetadata;
}

export function assertStateCompatibility(stateDirectory: string): CoreStateMetadata {
  return readCoreStateMetadata(stateDirectory);
}

function resolveConfig(config: CoreConfigV2, stateDirectory: string): ResolvedCoreConfig {
  return {
    config,
    stateDirectory,
    policyPath: resolveInside(stateDirectory, config.policy.path),
    auditDirectory: resolveInside(stateDirectory, config.audit.directory),
    auditSigningKeyPath: resolveInside(stateDirectory, config.audit.signingKeyPath),
    auditPublicKeyPath: resolveInside(stateDirectory, config.audit.publicKeyPath),
    trustStorePath: resolveInside(stateDirectory, config.state.trustStorePath),
    processDirectory: resolveInside(stateDirectory, config.state.processDirectory),
    ...(config.admin === undefined
      ? {}
      : {
          adminSocketPath: resolveInside(stateDirectory, config.admin.socketPath),
          operatorPublicKeyPath: resolveInside(stateDirectory, config.admin.operatorPublicKeyPath),
        }),
  };
}

export async function preflightCoreState(
  stateDirectory: string,
  options: { environment?: Readonly<Record<string, string | undefined>> } = {},
): Promise<CorePreflightResult> {
  const canonicalState = fs.realpathSync(stateDirectory);
  const state = assertStateCompatibility(canonicalState);
  if (
    state.stateSchemaVersion !== CORE_STATE_SCHEMA_VERSION ||
    state.configSchemaVersion !== CORE_CONFIG_SCHEMA_VERSION
  )
    fail('MIGRATION_REQUIRED', 'Core state requires a supported migration before startup.');
  const config = loadCoreConfig(path.join(canonicalState, CORE_CONFIG_FILENAME), options);
  const resolved = resolveConfig(config, canonicalState);
  assertPublicFile(resolved.policyPath, 'policy file');
  assertPublicFile(resolved.auditPublicKeyPath, 'audit public-key file');
  if (resolved.operatorPublicKeyPath !== undefined)
    assertPublicFile(resolved.operatorPublicKeyPath, 'operator public-key file');
  validateSecretFile(resolved.auditSigningKeyPath, 'audit signing-key file');
  if (config.transport.kind === 'remote') {
    assertPublicFile(
      resolveInside(canonicalState, config.transport.serverCertificatePath),
      'TLS server certificate file',
    );
    for (const clientCaPath of config.transport.clientCaPaths)
      assertPublicFile(resolveInside(canonicalState, clientCaPath), 'TLS client CA file');
    validateSecretFile(
      resolveInside(canonicalState, config.transport.privateKeyPath),
      'TLS private-key file',
    );
  }
  const trustStore = DeviceTrustStore.loadFromFile(resolved.trustStorePath);
  const audit = await verifyOfflineStore({
    directory: resolved.auditDirectory,
    checkpointPublicKeyPath: resolved.auditPublicKeyPath,
    workspacePaths: config.workspaces.map((workspace) => workspace.root),
  });
  return { resolved, devices: trustStore.getDeviceCount(), audit, state };
}

export function toArcServerConfig(preflight: CorePreflightResult): {
  transport: 'stdio' | 'remote';
  authorizedRoots: Array<{ id: string; path: string }>;
  defaultWorkspaceId: string;
  audit: { directory: string; signingKeyPath: string; publicKeyPath: string };
} {
  return {
    transport: preflight.resolved.config.transport.kind,
    authorizedRoots: preflight.resolved.config.workspaces.map((workspace) => ({
      id: workspace.id,
      path: workspace.root,
    })),
    defaultWorkspaceId: preflight.resolved.config.defaultWorkspaceId,
    audit: {
      directory: preflight.resolved.auditDirectory,
      signingKeyPath: preflight.resolved.auditSigningKeyPath,
      publicKeyPath: preflight.resolved.auditPublicKeyPath,
    },
  };
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  return `{${Object.keys(value as Record<string, unknown>)
    .sort()
    .map(
      (key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`,
    )
    .join(',')}}`;
}

function writeJsonAtomic(filePath: string, value: unknown, mode = 0o600): void {
  const bytes = Buffer.from(`${canonicalJson(value)}\n`);
  if (
    bytes.length > MAX_JOURNAL_BYTES &&
    path.basename(filePath) === CORE_MIGRATION_JOURNAL_FILENAME
  )
    fail('MIGRATION_EVIDENCE_TOO_LARGE', 'Migration evidence exceeded its bound.');
  const temporary = `${filePath}.tmp-${process.pid}-${crypto.randomBytes(6).toString('hex')}`;
  const fd = fs.openSync(
    temporary,
    fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY,
    mode,
  );
  try {
    fs.writeFileSync(fd, bytes);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(temporary, filePath);
  const parent = fs.openSync(
    path.dirname(filePath),
    fs.constants.O_RDONLY | fs.constants.O_DIRECTORY,
  );
  try {
    fs.fsyncSync(parent);
  } finally {
    fs.closeSync(parent);
  }
}

interface TreeEntry {
  readonly path: string;
  readonly mode: number;
  readonly bytes: Buffer;
}

function collectTree(root: string): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let total = 0;
  const walk = (directory: string, relative: string, depth: number): void => {
    if (depth > 32) fail('STATE_BOUNDS_EXCEEDED', 'State directory depth exceeds its bound.');
    const names = fs.readdirSync(directory).sort();
    for (const name of names) {
      const childRelative = relative ? `${relative}/${name}` : name;
      if (Buffer.byteLength(childRelative, 'utf8') > MAX_PATH_BYTES)
        fail('STATE_BOUNDS_EXCEEDED', 'State path exceeds its bound.');
      const fullPath = path.join(directory, name);
      const stat = fs.lstatSync(fullPath);
      if (stat.isSymbolicLink()) fail('STATE_SYMLINK_REFUSED', 'State contains a symbolic link.');
      if (stat.isDirectory()) {
        walk(fullPath, childRelative, depth + 1);
        continue;
      }
      if (!stat.isFile() || stat.nlink !== 1)
        fail('STATE_ENTRY_REFUSED', 'State contains a non-regular or linked entry.');
      if (stat.size > MAX_STATE_FILE_BYTES)
        fail('STATE_BOUNDS_EXCEEDED', 'State file exceeds its bound.');
      const bytes = fs.readFileSync(fullPath);
      total += bytes.length;
      if (entries.length + 1 > MAX_STATE_FILES || total > MAX_STATE_TOTAL_BYTES)
        fail('STATE_BOUNDS_EXCEEDED', 'State tree exceeds its bounded inventory.');
      entries.push({ path: childRelative, mode: stat.mode & 0o777, bytes });
    }
  };
  walk(root, '', 0);
  return entries;
}

export function digestCoreState(root: string): string {
  const hash = crypto.createHash('sha256');
  for (const entry of collectTree(root)) {
    hash.update(entry.path);
    hash.update('\0');
    hash.update(entry.mode.toString(8));
    hash.update('\0');
    hash.update(crypto.createHash('sha256').update(entry.bytes).digest('hex'));
    hash.update('\n');
  }
  return hash.digest('hex');
}

function copyStateTree(source: string, destination: string): void {
  if (fs.existsSync(destination))
    fail('MIGRATION_DESTINATION_EXISTS', 'Migration destination already exists.');
  fs.mkdirSync(destination, { mode: 0o700 });
  try {
    for (const entry of collectTree(source)) {
      const target = path.join(destination, ...entry.path.split('/'));
      fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
      fs.writeFileSync(target, entry.bytes, {
        mode: entry.mode,
        flag: 'wx',
      });
      fs.chmodSync(target, entry.mode);
    }
  } catch (error) {
    fs.rmSync(destination, { recursive: true, force: true });
    throw error;
  }
}

function migrationPaths(root: string): {
  root: string;
  live: string;
  work: string;
  lock: string;
  journal: string;
  backup: string;
  staged: string;
  retired: string;
  rollbackStaged: string;
  rollbackCurrent: string;
} {
  const canonicalRoot = fs.realpathSync(root);
  const live = path.join(canonicalRoot, CORE_LIVE_STATE_DIRECTORY);
  const liveStat = fs.lstatSync(live);
  if (!liveStat.isDirectory() || liveStat.isSymbolicLink())
    fail('MIGRATION_PATH_INVALID', 'Authoritative state must be a real directory.');
  const work = path.join(canonicalRoot, CORE_MIGRATION_DIRECTORY);
  if (fs.existsSync(work)) {
    const workStat = fs.lstatSync(work);
    if (!workStat.isDirectory() || workStat.isSymbolicLink())
      fail('MIGRATION_PATH_INVALID', 'Migration work area must be a real directory.');
  }
  return {
    root: canonicalRoot,
    live,
    work,
    lock: path.join(work, CORE_MIGRATION_LOCK_FILENAME),
    journal: path.join(work, CORE_MIGRATION_JOURNAL_FILENAME),
    backup: path.join(work, 'backup'),
    staged: path.join(work, 'staged'),
    retired: path.join(work, 'retired'),
    rollbackStaged: path.join(work, 'rollback-staged'),
    rollbackCurrent: path.join(work, 'rollback-current'),
  };
}

function linuxProcessStartTime(pid: number): string | null {
  if (process.platform !== 'linux' || !Number.isSafeInteger(pid) || pid < 1) return null;
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
    const close = stat.lastIndexOf(')');
    if (close < 0) return null;
    return (
      stat
        .slice(close + 2)
        .trim()
        .split(/\s+/u)[19] ?? null
    );
  } catch {
    return null;
  }
}

function reclaimStaleMigrationLock(lockPath: string): boolean {
  if (process.platform !== 'linux') return false;
  let lock: unknown;
  try {
    lock = parseStrictJson(
      readBoundedRegularFile(lockPath, 1024, 'Migration lock').toString('utf8'),
      'Migration lock',
    );
  } catch {
    return false;
  }
  if (!isRecord(lock) || lock.format !== 'cesspace-arc-migration-lock-v1') return false;
  const pid = Number(lock.pid);
  const startTime = typeof lock.startTime === 'string' ? lock.startTime : null;
  if (!Number.isSafeInteger(pid) || pid < 1 || startTime === null) return false;
  if (linuxProcessStartTime(pid) === startTime) return false;
  const stalePath = `${lockPath}.stale-${process.pid}-${crypto.randomBytes(6).toString('hex')}`;
  try {
    fs.renameSync(lockPath, stalePath);
    fs.rmSync(stalePath, { force: true });
    return true;
  } catch {
    return false;
  }
}

function acquireMigrationLock(paths: ReturnType<typeof migrationPaths>): () => void {
  if (!fs.existsSync(paths.work)) fs.mkdirSync(paths.work, { mode: 0o700 });
  const workStat = fs.lstatSync(paths.work);
  if (!workStat.isDirectory() || workStat.isSymbolicLink() || (workStat.mode & 0o077) !== 0)
    fail('MIGRATION_PATH_INVALID', 'Migration work area permissions or type are unsafe.');
  let fd: number;
  for (;;) {
    try {
      fd = fs.openSync(
        paths.lock,
        fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY,
        0o600,
      );
      break;
    } catch (error) {
      if (
        (error as NodeJS.ErrnoException).code !== 'EEXIST' ||
        !reclaimStaleMigrationLock(paths.lock)
      )
        fail('MIGRATION_LOCKED', 'Another migration owns the state root.');
    }
  }
  const startTime = linuxProcessStartTime(process.pid);
  if (startTime === null) {
    fs.closeSync(fd);
    fs.rmSync(paths.lock, { force: true });
    fail('MIGRATION_LOCK_UNAVAILABLE', 'Process identity is unavailable for migration locking.');
  }
  fs.writeFileSync(
    fd,
    `${JSON.stringify({
      format: 'cesspace-arc-migration-lock-v1',
      pid: process.pid,
      startTime,
    })}\n`,
  );
  fs.fsyncSync(fd);
  return () => {
    try {
      fs.closeSync(fd);
    } finally {
      fs.rmSync(paths.lock, { force: true });
    }
  };
}

function auditProjection(result: OfflineVerificationResult): MigrationEvidence['audit'] {
  return {
    storeId: result.storeId,
    terminalSequence: result.primary.terminalSequence,
    terminalRecordHash: result.primary.terminalRecordHash,
    checkpointCount: result.checkpoints.checkpointCount,
    lastCheckpointHash: result.checkpoints.lastCheckpointHash,
  };
}

async function verifyAuditInState(
  stateDirectory: string,
  config: CoreConfigV1 | CoreConfigV2,
): Promise<OfflineVerificationResult> {
  return verifyOfflineStore({
    directory: resolveInside(stateDirectory, config.audit.directory),
    checkpointPublicKeyPath: resolveInside(stateDirectory, config.audit.publicKeyPath),
    workspacePaths: config.workspaces.map((workspace) => workspace.root),
  });
}

function loadConfigAtVersion(stateDirectory: string, version: 1 | 2): CoreConfigV1 | CoreConfigV2 {
  const configPath = path.join(stateDirectory, CORE_CONFIG_FILENAME);
  const bytes = readBoundedRegularFile(configPath, MAX_CONFIG_BYTES, 'Core configuration');
  assertPublicConfigAuthority(configPath);
  return parseCoreConfig(parseStrictJson(bytes.toString('utf8'), 'Core configuration'), version);
}

function transformStagedState(staged: string, source: CoreStateMetadata): void {
  const legacy = loadConfigAtVersion(staged, 1) as CoreConfigV1;
  const current: CoreConfigV2 = {
    ...legacy,
    schemaVersion: 2,
    productVersion: CORE_PRODUCT_VERSION,
    profile: 'core',
  };
  writeJsonAtomic(path.join(staged, CORE_CONFIG_FILENAME), current);
  const metadata: CoreStateMetadata = {
    ...source,
    stateSchemaVersion: 2,
    configSchemaVersion: 2,
    productVersion: CORE_PRODUCT_VERSION,
    migrationVersion: 1,
  };
  writeJsonAtomic(path.join(staged, CORE_STATE_METADATA_FILENAME), metadata);
}

async function migrateCoreStateInternal(root: string): Promise<MigrationResult> {
  const paths = migrationPaths(root);
  const current = readCoreStateMetadata(paths.live);
  if (current.stateSchemaVersion === 2) {
    const preflight = await preflightCoreState(paths.live);
    return {
      result: 'ALREADY_CURRENT',
      evidence: null,
      stateDigest: digestCoreState(preflight.resolved.stateDirectory),
    };
  }
  if (current.stateSchemaVersion !== 1 || current.configSchemaVersion !== 1)
    fail('UNSUPPORTED_STATE_VERSION', 'Source state schema is not migratable.');
  const release = acquireMigrationLock(paths);
  try {
    const legacy = loadConfigAtVersion(paths.live, 1) as CoreConfigV1;
    assertPublicFile(resolveInside(paths.live, legacy.policy.path), 'policy file');
    validateSecretFile(
      resolveInside(paths.live, legacy.audit.signingKeyPath),
      'audit signing-key file',
    );
    DeviceTrustStore.loadFromFile(resolveInside(paths.live, legacy.state.trustStorePath));
    const auditBefore = await verifyAuditInState(paths.live, legacy);
    const sourceDigest = digestCoreState(paths.live);

    if (!fs.existsSync(paths.backup)) copyStateTree(paths.live, paths.backup);
    const backupDigest = digestCoreState(paths.backup);
    if (backupDigest !== sourceDigest)
      fail('BACKUP_VERIFICATION_FAILED', 'Migration backup does not match source state.');

    fs.rmSync(paths.staged, { recursive: true, force: true });
    copyStateTree(paths.backup, paths.staged);
    transformStagedState(paths.staged, current);
    const stagedConfig = loadConfigAtVersion(paths.staged, 2) as CoreConfigV2;
    DeviceTrustStore.loadFromFile(resolveInside(paths.staged, stagedConfig.state.trustStorePath));
    const auditStaged = await verifyAuditInState(paths.staged, stagedConfig);
    if (canonicalJson(auditProjection(auditStaged)) !== canonicalJson(auditProjection(auditBefore)))
      fail('AUDIT_CONTINUITY_LOST', 'Audit continuity changed during migration staging.');
    const stagedDigest = digestCoreState(paths.staged);
    const evidence: MigrationEvidence = {
      format: 'cesspace-arc-migration-v1',
      migrationVersion: 1,
      lifecycle: 'STAGED',
      sourceSchemaVersion: 1,
      targetSchemaVersion: 2,
      sourceConfigSchemaVersion: 1,
      targetConfigSchemaVersion: 2,
      sourceDigest,
      backupDigest,
      stagedDigest,
      reversible: true,
      steps: [
        'SOURCE_VALIDATED',
        'AUDIT_VERIFIED',
        'BACKUP_VERIFIED',
        'TARGET_STAGED',
        'TARGET_VALIDATED',
      ],
      audit: auditProjection(auditBefore),
    };
    writeJsonAtomic(paths.journal, evidence);
    if (isPreCommitFaultEnabled())
      fail('MIGRATION_FAULT_INJECTED', 'Migration stopped at the deterministic pre-commit seam.');

    const committing = { ...evidence, lifecycle: 'COMMITTING' as const };
    writeJsonAtomic(paths.journal, committing);
    fs.rmSync(paths.retired, { recursive: true, force: true });
    fs.renameSync(paths.live, paths.retired);
    try {
      fs.renameSync(paths.staged, paths.live);
    } catch (error) {
      fs.renameSync(paths.retired, paths.live);
      throw error;
    }
    const preflight = await preflightCoreState(paths.live);
    const committedDigest = digestCoreState(paths.live);
    const committed: MigrationEvidence = {
      ...evidence,
      lifecycle: 'COMMITTED',
      committedDigest,
      steps: [...evidence.steps, 'ATOMIC_COMMIT', 'TARGET_REOPENED'],
      audit: auditProjection(preflight.audit),
    };
    writeJsonAtomic(paths.journal, committed);
    fs.rmSync(paths.retired, { recursive: true, force: true });
    return { result: 'MIGRATED', evidence: committed, stateDigest: committedDigest };
  } finally {
    release();
  }
}

export async function migrateCoreState(root: string): Promise<MigrationResult> {
  return migrateCoreStateInternal(root);
}

function readJournal(journalPath: string): MigrationEvidence {
  const bytes = readBoundedRegularFile(journalPath, MAX_JOURNAL_BYTES, 'Migration journal');
  const value = closedRecord(
    parseStrictJson(bytes.toString('utf8'), 'Migration journal'),
    [
      'format',
      'migrationVersion',
      'lifecycle',
      'sourceSchemaVersion',
      'targetSchemaVersion',
      'sourceConfigSchemaVersion',
      'targetConfigSchemaVersion',
      'sourceDigest',
      'backupDigest',
      'stagedDigest',
      'committedDigest',
      'restoredDigest',
      'reversible',
      'steps',
      'audit',
    ],
    'migration journal',
  );
  if (
    value.format !== 'cesspace-arc-migration-v1' ||
    value.migrationVersion !== 1 ||
    !['STAGED', 'COMMITTING', 'COMMITTED', 'ROLLED_BACK'].includes(String(value.lifecycle)) ||
    value.sourceSchemaVersion !== 1 ||
    value.targetSchemaVersion !== 2 ||
    value.sourceConfigSchemaVersion !== 1 ||
    value.targetConfigSchemaVersion !== 2 ||
    !SHA256_REGEX.test(String(value.sourceDigest)) ||
    !SHA256_REGEX.test(String(value.backupDigest)) ||
    !SHA256_REGEX.test(String(value.stagedDigest)) ||
    (value.committedDigest !== undefined && !SHA256_REGEX.test(String(value.committedDigest))) ||
    (value.restoredDigest !== undefined && !SHA256_REGEX.test(String(value.restoredDigest))) ||
    typeof value.reversible !== 'boolean' ||
    !Array.isArray(value.steps) ||
    value.steps.length > 16 ||
    !value.steps.every((step) => typeof step === 'string' && ID_REGEX.test(step)) ||
    !isRecord(value.audit) ||
    typeof value.audit.storeId !== 'string' ||
    !Number.isSafeInteger(value.audit.terminalSequence) ||
    Number(value.audit.terminalSequence) < 0 ||
    !SHA256_REGEX.test(String(value.audit.terminalRecordHash)) ||
    !Number.isSafeInteger(value.audit.checkpointCount) ||
    Number(value.audit.checkpointCount) < 0 ||
    (value.audit.lastCheckpointHash !== null &&
      !SHA256_REGEX.test(String(value.audit.lastCheckpointHash)))
  )
    fail('MIGRATION_JOURNAL_INVALID', 'Migration journal identity is invalid.');
  return value as unknown as MigrationEvidence;
}

export async function recoverCoreMigration(root: string): Promise<RecoveryResult> {
  const paths = migrationPaths(root);
  if (!fs.existsSync(paths.journal)) {
    return { result: 'NO_RECOVERY_NEEDED', stateDigest: digestCoreState(paths.live) };
  }
  const release = acquireMigrationLock(paths);
  try {
    const journal = readJournal(paths.journal);
    if (journal.lifecycle === 'STAGED') {
      const liveDigest = digestCoreState(paths.live);
      if (liveDigest !== journal.sourceDigest)
        fail(
          'MIGRATION_RECOVERY_REFUSED',
          'Live state no longer matches interrupted migration source.',
        );
      fs.rmSync(paths.staged, { recursive: true, force: true });
      fs.rmSync(paths.journal, { force: true });
      return { result: 'ORIGINAL_RESTORED', stateDigest: liveDigest };
    }
    if (journal.lifecycle === 'COMMITTING') {
      if (fs.existsSync(paths.live)) {
        const liveDigest = digestCoreState(paths.live);
        if (liveDigest === journal.sourceDigest && fs.existsSync(paths.staged)) {
          fs.rmSync(paths.retired, { recursive: true, force: true });
          fs.renameSync(paths.live, paths.retired);
          try {
            fs.renameSync(paths.staged, paths.live);
          } catch (error) {
            fs.renameSync(paths.retired, paths.live);
            throw error;
          }
        } else if (liveDigest !== journal.stagedDigest) {
          fail(
            'MIGRATION_RECOVERY_REFUSED',
            'Authoritative state does not match migration evidence.',
          );
        }
      } else if (fs.existsSync(paths.staged)) {
        fs.renameSync(paths.staged, paths.live);
      } else {
        fail('MIGRATION_RECOVERY_REFUSED', 'No authoritative state exists for commit recovery.');
      }
      const preflight = await preflightCoreState(paths.live);
      const stateDigest = digestCoreState(paths.live);
      if (stateDigest !== journal.stagedDigest)
        fail('MIGRATION_RECOVERY_REFUSED', 'Recovered target does not match staged evidence.');
      const completed: MigrationEvidence = {
        ...journal,
        lifecycle: 'COMMITTED',
        committedDigest: stateDigest,
        steps: [...journal.steps, 'RECOVERY_COMMIT', 'TARGET_REOPENED'],
        audit: auditProjection(preflight.audit),
      };
      writeJsonAtomic(paths.journal, completed);
      fs.rmSync(paths.retired, { recursive: true, force: true });
      return { result: 'COMMIT_COMPLETED', stateDigest };
    }
    return { result: 'NO_RECOVERY_NEEDED', stateDigest: digestCoreState(paths.live) };
  } finally {
    release();
  }
}

export async function rollbackCoreState(root: string): Promise<RollbackResult> {
  const paths = migrationPaths(root);
  const release = acquireMigrationLock(paths);
  try {
    const journal = readJournal(paths.journal);
    if (journal.lifecycle !== 'COMMITTED' || journal.reversible !== true)
      fail('ROLLBACK_INCOMPATIBLE', 'Migration is not eligible for compatible rollback.');
    if (!fs.existsSync(paths.backup) || digestCoreState(paths.backup) !== journal.backupDigest)
      fail('ROLLBACK_BACKUP_INVALID', 'Verified migration backup is unavailable or changed.');
    const backupMetadata = readCoreStateMetadata(paths.backup);
    if (backupMetadata.stateSchemaVersion !== 1 || backupMetadata.configSchemaVersion !== 1)
      fail('ROLLBACK_INCOMPATIBLE', 'Backup schema is outside the supported rollback boundary.');
    const backupConfig = loadConfigAtVersion(paths.backup, 1) as CoreConfigV1;
    const backupAudit = await verifyAuditInState(paths.backup, backupConfig);
    if (canonicalJson(auditProjection(backupAudit)) !== canonicalJson(journal.audit))
      fail('AUDIT_CONTINUITY_LOST', 'Backup audit evidence does not match migration evidence.');

    fs.rmSync(paths.rollbackStaged, { recursive: true, force: true });
    copyStateTree(paths.backup, paths.rollbackStaged);
    fs.rmSync(paths.rollbackCurrent, { recursive: true, force: true });
    fs.renameSync(paths.live, paths.rollbackCurrent);
    fs.renameSync(paths.rollbackStaged, paths.live);
    const restoredDigest = digestCoreState(paths.live);
    if (restoredDigest !== journal.sourceDigest) {
      fs.renameSync(paths.live, paths.rollbackStaged);
      fs.renameSync(paths.rollbackCurrent, paths.live);
      fail(
        'ROLLBACK_VERIFICATION_FAILED',
        'Restored state did not match the verified source digest.',
      );
    }
    fs.rmSync(paths.rollbackCurrent, { recursive: true, force: true });
    const rolledBack: MigrationEvidence = {
      ...journal,
      lifecycle: 'ROLLED_BACK',
      restoredDigest,
      steps: [...journal.steps, 'COMPATIBLE_ROLLBACK'],
    };
    writeJsonAtomic(paths.journal, rolledBack);
    return { result: 'ROLLED_BACK', stateDigest: restoredDigest, evidence: rolledBack };
  } finally {
    release();
  }
}

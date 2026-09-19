import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { ArcError } from '@cesspace-arc/protocol';
import {
  EnrolledDeviceRecord,
  EnrollDeviceInput,
  generateDeviceId,
  isValidDeviceId,
  isValidSpkiPin,
  validateClientId,
  validateClientType,
  validateDisplayLabel,
  MAX_ACTIVE_PINS_PER_DEVICE,
  MAX_CLIENT_ID_CHARS,
  MAX_CLIENT_TYPE_CHARS,
  MAX_ENROLLED_DEVICES,
  MAX_TRUST_STORE_BYTES,
} from './device-identity.js';

/**
 * Top-level structure for devices.json trust store.
 * Strict closed schema: version must be 1, devices must be an array of EnrolledDeviceRecord.
 */
export interface DeviceTrustStoreData {
  readonly version: 1;
  readonly devices: readonly EnrolledDeviceRecord[];
}

/**
 * Validate trust store data against strict closed-schema rules.
 * Unknown fields, malformed records, duplicate IDs, duplicate pins, or invalid bounds fail closed.
 */
export function validateTrustStoreData(raw: unknown): DeviceTrustStoreData {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw ArcError.invalidRequestSchema('Trust store data must be a JSON object.');
  }

  const record = raw as Record<string, unknown>;
  const allowedTopKeys = new Set(['version', 'devices']);
  for (const key of Object.keys(record)) {
    if (!allowedTopKeys.has(key)) {
      throw ArcError.invalidRequestSchema(
        `Unknown field '${key}' in trust store root. Strict closed schema enforced.`,
      );
    }
  }

  if (record.version !== 1) {
    throw ArcError.invalidRequestSchema(
      `Unsupported trust store version '${String(record.version)}'. Expected version 1.`,
    );
  }

  if (!Array.isArray(record.devices)) {
    throw ArcError.invalidRequestSchema('Trust store devices field must be an array.');
  }

  if (record.devices.length > MAX_ENROLLED_DEVICES) {
    throw ArcError.resourceExhausted(
      `Trust store exceeds maximum enrolled devices limit of ${MAX_ENROLLED_DEVICES} (got ${record.devices.length}).`,
    );
  }

  const seenDeviceIds = new Set<string>();
  const seenPins = new Set<string>();
  const validatedDevices: EnrolledDeviceRecord[] = [];

  const allowedDeviceKeys = new Set([
    'deviceId',
    'clientId',
    'clientType',
    'pins',
    'enrolledAt',
    'displayLabel',
    'revoked',
  ]);

  for (let i = 0; i < record.devices.length; i++) {
    const dev = record.devices[i];
    if (typeof dev !== 'object' || dev === null || Array.isArray(dev)) {
      throw ArcError.invalidRequestSchema(`Device record at index ${i} must be an object.`);
    }

    const devObj = dev as Record<string, unknown>;
    for (const key of Object.keys(devObj)) {
      if (!allowedDeviceKeys.has(key)) {
        throw ArcError.invalidRequestSchema(
          `Unknown field '${key}' in device record at index ${i}. Strict closed schema enforced.`,
        );
      }
    }

    // deviceId
    if (!isValidDeviceId(devObj.deviceId)) {
      throw ArcError.invalidRequestSchema(
        `Invalid deviceId at index ${i}: must be exactly 32 lowercase hexadecimal characters.`,
      );
    }
    if (seenDeviceIds.has(devObj.deviceId)) {
      throw ArcError.invalidRequestSchema(
        `Duplicate deviceId '${devObj.deviceId}' in trust store at index ${i}.`,
      );
    }
    seenDeviceIds.add(devObj.deviceId);

    // clientId / clientType share the authoritative admission rule, so a value
    // accepted for a pending enrollment can always be persisted here.
    let clientId: string;
    let clientType: string;
    try {
      clientId = validateClientId(devObj.clientId);
    } catch {
      throw ArcError.invalidRequestSchema(
        `Invalid clientId at index ${i}: must be a non-empty string up to ${MAX_CLIENT_ID_CHARS} characters.`,
      );
    }
    try {
      clientType = validateClientType(devObj.clientType);
    } catch {
      throw ArcError.invalidRequestSchema(
        `Invalid clientType at index ${i}: must be a non-empty string up to ${MAX_CLIENT_TYPE_CHARS} characters.`,
      );
    }

    // pins
    if (!Array.isArray(devObj.pins)) {
      throw ArcError.invalidRequestSchema(`pins at index ${i} must be an array.`);
    }
    if (devObj.pins.length === 0) {
      throw ArcError.invalidRequestSchema(
        `Empty pin set for device '${devObj.deviceId}' at index ${i}. Device must have at least 1 pin.`,
      );
    }
    if (devObj.pins.length > MAX_ACTIVE_PINS_PER_DEVICE) {
      throw ArcError.resourceExhausted(
        `Device '${devObj.deviceId}' exceeds maximum active pins of ${MAX_ACTIVE_PINS_PER_DEVICE} (got ${devObj.pins.length}).`,
      );
    }

    const devicePins = new Set<string>();
    for (let pIdx = 0; pIdx < devObj.pins.length; pIdx++) {
      const pin = devObj.pins[pIdx];
      if (!isValidSpkiPin(pin)) {
        throw ArcError.invalidRequestSchema(
          `Invalid SPKI pin at index ${i}, pin index ${pIdx}: must be 64 lowercase hexadecimal characters.`,
        );
      }
      if (devicePins.has(pin)) {
        throw ArcError.invalidRequestSchema(
          `Duplicate pin '${pin}' within device '${devObj.deviceId}'.`,
        );
      }
      devicePins.add(pin);

      if (seenPins.has(pin)) {
        throw ArcError.invalidRequestSchema(
          `Pin collision: SPKI pin '${pin}' belongs to more than one enrolled device.`,
        );
      }
      seenPins.add(pin);
    }

    // enrolledAt
    if (typeof devObj.enrolledAt !== 'string' || devObj.enrolledAt.trim().length === 0) {
      throw ArcError.invalidRequestSchema(
        `Invalid enrolledAt at index ${i}: must be a non-empty ISO 8601 string.`,
      );
    }

    // displayLabel
    const displayLabel = validateDisplayLabel(devObj.displayLabel ?? '');

    // revoked
    if (typeof devObj.revoked !== 'boolean') {
      throw ArcError.invalidRequestSchema(
        `Invalid revoked state at index ${i}: must be a boolean.`,
      );
    }

    validatedDevices.push({
      deviceId: devObj.deviceId,
      clientId,
      clientType,
      pins: Object.freeze([...devObj.pins]),
      enrolledAt: devObj.enrolledAt,
      displayLabel,
      revoked: devObj.revoked,
    });
  }

  return {
    version: 1,
    devices: Object.freeze(validatedDevices),
  };
}

/**
 * Minimal stat interface for trust store file verification.
 */
export interface MinimalTrustStoreFileStat {
  isSymbolicLink(): boolean;
  isFile(): boolean;
  readonly size: number;
  readonly mode: number;
  readonly uid: number;
}

/**
 * Minimal stat interface for trust store parent directory verification.
 */
export interface MinimalTrustStoreDirStat {
  isSymbolicLink(): boolean;
  isDirectory(): boolean;
  readonly mode: number;
  readonly uid: number;
}

/**
 * Narrow internal filesystem adapter interface for trust store operations.
 * Defaults to node:fs in production; injectable for deterministic tests.
 */
export interface TrustStoreFsAdapter {
  lstatSync(path: string): fs.Stats | MinimalTrustStoreFileStat | MinimalTrustStoreDirStat;
  openSync(path: string, flags: number | string, mode?: number): number;
  writeSync(
    fd: number,
    buffer: NodeJS.ArrayBufferView,
    offset?: number,
    length?: number,
    position?: number | null,
  ): number;
  fsyncSync(fd: number): void;
  closeSync(fd: number): void;
  renameSync(oldPath: string, newPath: string): void;
  unlinkSync(path: string): void;
  existsSync(path: string): boolean;
  readFileSync(path: string, encoding: 'utf8'): string;
  getuid?(): number;
}

/**
 * Default production filesystem adapter bound directly to node:fs operations.
 */
export const defaultFsAdapter: TrustStoreFsAdapter = {
  lstatSync: (p) => fs.lstatSync(p),
  openSync: (p, flags, mode) =>
    mode !== undefined ? fs.openSync(p, flags, mode) : fs.openSync(p, flags),
  writeSync: (fd, buffer, offset, length, position) =>
    fs.writeSync(fd, buffer, offset, length, position),
  fsyncSync: (fd) => fs.fsyncSync(fd),
  closeSync: (fd) => fs.closeSync(fd),
  renameSync: (oldP, newP) => fs.renameSync(oldP, newP),
  unlinkSync: (p) => fs.unlinkSync(p),
  existsSync: (p) => fs.existsSync(p),
  readFileSync: (p, enc) => fs.readFileSync(p, enc),
  getuid: () => (typeof process.getuid === 'function' ? process.getuid() : 0),
};

/**
 * Validate that a trust-store path does not contain path traversal, NUL bytes, or empty strings (§16.1).
 * Traversal sequences (..) are strictly rejected before normalization.
 */
export function assertValidTrustStorePath(filePath: string): void {
  if (typeof filePath !== 'string' || filePath.trim().length === 0) {
    throw ArcError.invalidRequestSchema('Trust store filePath must be a non-empty string.');
  }

  // Reject NUL bytes or control characters
  if (filePath.includes('\0')) {
    throw ArcError.invalidPathChars('Trust store path contains invalid characters or null bytes.');
  }

  // Reject path traversal sequences (..) in any path component
  const normalized = filePath.replace(/\\/g, '/');
  const segments = normalized.split('/');
  if (segments.includes('..')) {
    throw ArcError.accessDenied(
      'Path traversal sequence (..) is strictly forbidden in trust store path.',
    );
  }
}

/**
 * Validate trust store file stat against frozen §16.1 requirements:
 * 1. Not a symlink.
 * 2. Regular file (S_ISREG).
 * 3. Bounded file size <= 256 KiB.
 * 4. Mode 0600 (group/world access forbidden).
 * 5. Owner matches expected process UID.
 */
export function validateTrustStoreFileStat(
  stat: MinimalTrustStoreFileStat,
  expectedUid: number,
  resolvedPath = 'Trust store file',
): void {
  if (stat.isSymbolicLink()) {
    throw ArcError.unsafeSymlink(
      `Trust store file is a symbolic link: ${resolvedPath}. Symlinks are strictly forbidden.`,
    );
  }

  if (!stat.isFile()) {
    throw ArcError.notAFile(`Trust store path is not a regular file: ${resolvedPath}`);
  }

  if (stat.size > MAX_TRUST_STORE_BYTES) {
    throw ArcError.resourceExhausted(
      `Trust store file exceeds maximum size ceiling of ${MAX_TRUST_STORE_BYTES} bytes (got ${stat.size} bytes).`,
    );
  }

  if (process.platform !== 'win32') {
    if ((stat.mode & 0o077) !== 0) {
      throw ArcError.accessDenied(
        `Trust store permissions 0${(stat.mode & 0o777).toString(8)} are insecure. Must be mode 0600 (group/world access forbidden).`,
      );
    }

    if (stat.uid !== expectedUid) {
      throw ArcError.accessDenied(
        `Trust store file owner UID (${stat.uid}) does not match process UID (${expectedUid}).`,
      );
    }
  }
}

/**
 * Validate parent directory stat against frozen §16.1 requirements:
 * 1. Not a symlink.
 * 2. Must be a directory.
 * 3. Group and world writable bits forbidden (mode & 0022 === 0).
 * 4. Owner is process UID or root (0).
 */
export function validateTrustStoreParentDirectoryStat(
  parentStat: MinimalTrustStoreDirStat,
  expectedUid: number,
  parentDir = 'Trust store parent directory',
): void {
  if (parentStat.isSymbolicLink()) {
    throw ArcError.unsafeSymlink(`Trust store parent directory is a symbolic link: ${parentDir}.`);
  }

  if (!parentStat.isDirectory()) {
    throw ArcError.notADirectory(`Trust store parent path is not a directory: ${parentDir}.`);
  }

  if (process.platform !== 'win32') {
    if ((parentStat.mode & 0o022) !== 0) {
      throw ArcError.accessDenied(
        `Trust store parent directory permissions 0${(parentStat.mode & 0o777).toString(8)} are group or world writable.`,
      );
    }

    if (parentStat.uid !== expectedUid && parentStat.uid !== 0) {
      throw ArcError.accessDenied(
        `Trust store parent directory owner UID (${parentStat.uid}) is neither process UID (${expectedUid}) nor root (0).`,
      );
    }
  }
}

/**
 * Perform filesystem integrity checks on the trust store path (§16.1):
 * 1. Rejects path traversal (..) and invalid characters.
 * 2. Regular file only (reject symlinks via lstat/O_NOFOLLOW).
 * 3. Ownership must match current process UID.
 * 4. File mode must be strictly 0600 (mode & 0077 === 0).
 * 5. Parent directory must be owned by process UID or root, and not group/world writable.
 * 6. Size must not exceed 256 KiB.
 */
export function verifyTrustStoreFileIntegrity(filePath: string): void {
  verifyTrustStoreFileIntegrityWithAdapter(filePath, defaultFsAdapter);
}

/**
 * @internal Internal implementation of verifyTrustStoreFileIntegrity with filesystem adapter.
 */
export function verifyTrustStoreFileIntegrityWithAdapter(
  filePath: string,
  fsAdapter: TrustStoreFsAdapter = defaultFsAdapter,
): void {
  assertValidTrustStorePath(filePath);

  const resolved = path.resolve(filePath);

  let stat: fs.Stats | MinimalTrustStoreFileStat;
  try {
    stat = fsAdapter.lstatSync(resolved) as MinimalTrustStoreFileStat;
  } catch (err: unknown) {
    const error = err as NodeJS.ErrnoException;
    if (error.code === 'ENOENT') {
      throw ArcError.fileNotFound(`Trust store file not found: ${resolved}`);
    }
    throw ArcError.internalError(`Failed to stat trust store file: ${error.message}`);
  }

  const currentUid = fsAdapter.getuid
    ? fsAdapter.getuid()
    : typeof process.getuid === 'function'
      ? process.getuid()
      : 0;

  validateTrustStoreFileStat(stat, currentUid, resolved);

  // Parent directory checks
  const parentDir = path.dirname(resolved);
  let parentStat: fs.Stats | MinimalTrustStoreDirStat;
  try {
    parentStat = fsAdapter.lstatSync(parentDir) as MinimalTrustStoreDirStat;
  } catch {
    throw ArcError.parentNotFound(`Trust store parent directory not found: ${parentDir}`);
  }

  validateTrustStoreParentDirectoryStat(parentStat, currentUid, parentDir);
}

/**
 * Atomically persist trust store data to disk following the §16.1 protocol:
 * 1. Reject traversal sequences or malformed paths.
 * 2. Validate data against schema and size ceiling.
 * 3. Enforce parent directory ownership (process UID or root) and non-writable permissions BEFORE writing.
 * 4. Validate existing destination target file integrity if present BEFORE creating temporary file (§16.1).
 * 5. Write to a temporary file in the same directory mode 0600, guaranteeing complete bytes written.
 * 6. fsync temporary file.
 * 7. Rename over destination path.
 * 8. fsync parent directory where supported, propagating actual I/O or operational errors fail-closed.
 * 9. Clean up temporary files on pre-commit failures and preserve prior valid state.
 */
export function atomicPersistTrustStore(filePath: string, data: DeviceTrustStoreData): void {
  atomicPersistTrustStoreWithAdapter(filePath, data, defaultFsAdapter);
}

/**
 * @internal Internal implementation of atomicPersistTrustStore with filesystem adapter.
 */
export function atomicPersistTrustStoreWithAdapter(
  filePath: string,
  data: DeviceTrustStoreData,
  fsAdapter: TrustStoreFsAdapter = defaultFsAdapter,
): void {
  assertValidTrustStorePath(filePath);

  const validated = validateTrustStoreData(data);
  const serialized = JSON.stringify(validated, null, 2);
  const serializedBytes = Buffer.byteLength(serialized, 'utf8');

  if (serializedBytes > MAX_TRUST_STORE_BYTES) {
    throw ArcError.resourceExhausted(
      `Serialized trust store exceeds ${MAX_TRUST_STORE_BYTES} byte ceiling (${serializedBytes} bytes).`,
    );
  }

  const resolved = path.resolve(filePath);
  const parentDir = path.dirname(resolved);

  const currentUid = fsAdapter.getuid
    ? fsAdapter.getuid()
    : typeof process.getuid === 'function'
      ? process.getuid()
      : 0;

  // 1. Validate parent directory integrity before writing any temporary trust state (§16.1)
  let parentStat: fs.Stats | MinimalTrustStoreDirStat;
  try {
    parentStat = fsAdapter.lstatSync(parentDir) as MinimalTrustStoreDirStat;
  } catch {
    throw ArcError.parentNotFound(`Cannot persist: parent directory not found: ${parentDir}`);
  }
  validateTrustStoreParentDirectoryStat(parentStat, currentUid, parentDir);

  // 2. Validate existing destination target file if present BEFORE creating temporary file (§16.1)
  try {
    const targetStat = fsAdapter.lstatSync(resolved) as MinimalTrustStoreFileStat;
    validateTrustStoreFileStat(targetStat, currentUid, resolved);
  } catch (err: unknown) {
    if (err instanceof ArcError) {
      throw err;
    }
    const error = err as NodeJS.ErrnoException;
    if (error.code !== 'ENOENT') {
      throw ArcError.internalError(`Failed to stat destination trust store file: ${error.message}`);
    }
  }

  const tmpFilename = `.devices.json.tmp.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString('hex')}`;
  const tmpPath = path.join(parentDir, tmpFilename);

  let fd: number | null = null;
  try {
    // Open temporary file with exclusive creation and mode 0600
    fd = fsAdapter.openSync(
      tmpPath,
      fs.constants.O_CREAT | fs.constants.O_WRONLY | fs.constants.O_EXCL,
      0o600,
    );

    // Complete synchronous write loop verifying all bytes are written
    const buffer = Buffer.from(serialized, 'utf8');
    let bytesWritten = 0;
    while (bytesWritten < buffer.length) {
      const chunkWritten = fsAdapter.writeSync(
        fd,
        buffer,
        bytesWritten,
        buffer.length - bytesWritten,
        null,
      );
      if (typeof chunkWritten !== 'number' || chunkWritten <= 0) {
        throw ArcError.internalError(
          `Failed to write complete trust store buffer: zero progress (wrote ${bytesWritten}/${buffer.length} bytes).`,
        );
      }
      bytesWritten += chunkWritten;
    }

    // fsync to flush temporary file data to disk
    fsAdapter.fsyncSync(fd);

    fsAdapter.closeSync(fd);
    fd = null;

    // Atomically rename over destination path
    fsAdapter.renameSync(tmpPath, resolved);

    // fsync parent directory where supported
    if (process.platform !== 'win32') {
      let dirFd: number | null = null;
      let dirOpened = false;
      try {
        const dirOpenFlags = (fs.constants.O_RDONLY ?? 0) | (fs.constants.O_DIRECTORY ?? 0);
        try {
          dirFd = fsAdapter.openSync(parentDir, dirOpenFlags);
          dirOpened = true;
        } catch (openErr: unknown) {
          const errCode = (openErr as NodeJS.ErrnoException).code;
          // openSync must NOT tolerate EINVAL. Only ENOTSUP and EOPNOTSUPP are tolerated if the
          // filesystem/OS does not support opening directory descriptors.
          if (errCode === 'ENOTSUP' || errCode === 'EOPNOTSUPP') {
            dirOpened = false;
          } else {
            throw ArcError.internalError(
              `Failed to open trust store parent directory for sync '${parentDir}': ${(openErr as Error)?.message || String(openErr)}`,
            );
          }
        }

        if (dirOpened && dirFd !== null) {
          try {
            fsAdapter.fsyncSync(dirFd);
          } catch (fsyncErr: unknown) {
            const errCode = (fsyncErr as NodeJS.ErrnoException).code;
            // On certain POSIX/Linux platforms and filesystems (e.g. NFS, FAT, VFAT, or specific
            // kernel configurations), fsync(2) on an opened directory file descriptor returns
            // EINVAL (or ENOTSUP/EOPNOTSUPP) to signal that directory synchronization is
            // unsupported. All operational errors (EIO, EBADF, EPERM, EISDIR, etc.) fail closed.
            const fsyncUnsupportedCodes = new Set(['ENOTSUP', 'EOPNOTSUPP', 'EINVAL']);
            if (errCode && fsyncUnsupportedCodes.has(errCode)) {
              // Tolerated as OS/filesystem signal that directory fsync is unsupported
            } else {
              throw ArcError.internalError(
                `Failed to fsync trust store parent directory '${parentDir}': ${(fsyncErr as Error)?.message || String(fsyncErr)}`,
              );
            }
          }
        }
      } finally {
        if (dirFd !== null) {
          try {
            fsAdapter.closeSync(dirFd);
          } catch {
            // ignore close error during cleanup
          }
        }
      }
    }
  } catch (err: unknown) {
    if (fd !== null) {
      try {
        fsAdapter.closeSync(fd);
      } catch {
        // ignore close error during cleanup
      }
    }
    try {
      if (fsAdapter.existsSync(tmpPath)) {
        fsAdapter.unlinkSync(tmpPath);
      }
    } catch {
      // ignore cleanup failure
    }
    throw err;
  }
}

/**
 * @internal Standalone internal adapter-aware loader for deterministic tests.
 * Excluded from the public package index.
 */
export function loadTrustStoreWithAdapter(
  filePath: string,
  fsAdapter: TrustStoreFsAdapter = defaultFsAdapter,
): DeviceTrustStore {
  verifyTrustStoreFileIntegrityWithAdapter(filePath, fsAdapter);

  const resolved = path.resolve(filePath);
  const content = fsAdapter.readFileSync(resolved, 'utf8');

  if (Buffer.byteLength(content, 'utf8') > MAX_TRUST_STORE_BYTES) {
    throw ArcError.resourceExhausted(
      `Trust store file exceeds maximum size ceiling of ${MAX_TRUST_STORE_BYTES} bytes.`,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    throw ArcError.invalidRequestSchema(
      'Failed to parse trust store file: content is not valid JSON.',
    );
  }

  const validated = validateTrustStoreData(parsed);
  return new DeviceTrustStore(validated);
}

/**
 * @internal Standalone internal adapter-aware persister for deterministic tests.
 * Excluded from the public package index.
 */
export function saveTrustStoreWithAdapter(
  store: DeviceTrustStore,
  filePath: string,
  fsAdapter: TrustStoreFsAdapter = defaultFsAdapter,
): void {
  atomicPersistTrustStoreWithAdapter(filePath, store.toData(), fsAdapter);
}

/**
 * In-memory manager for enrolled device trust and pinning invariants (§7, §8, §16).
 */
export class DeviceTrustStore {
  private readonly devices: Map<string, EnrolledDeviceRecord> = new Map();

  constructor(initialData?: DeviceTrustStoreData) {
    if (initialData) {
      const validated = validateTrustStoreData(initialData);
      for (const dev of validated.devices) {
        this.devices.set(dev.deviceId, dev);
      }
    }
  }

  /**
   * Create an empty in-memory trust store.
   */
  public static createEmpty(): DeviceTrustStore {
    return new DeviceTrustStore({ version: 1, devices: [] });
  }

  /**
   * Load trust store from a file on disk after verifying filesystem integrity and schema.
   * Production entry point using real filesystem. Corrupt, missing, unreadable, or invalid
   * store throws and never silently defaults to empty.
   */
  public static loadFromFile(filePath: string): DeviceTrustStore {
    return loadTrustStoreWithAdapter(filePath, defaultFsAdapter);
  }

  /**
   * Persist current in-memory store atomically to disk.
   * Production entry point using real filesystem.
   */
  public saveToFile(filePath: string): void {
    saveTrustStoreWithAdapter(this, filePath, defaultFsAdapter);
  }

  /**
   * Export the current store state as a immutable DeviceTrustStoreData object.
   */
  public toData(): DeviceTrustStoreData {
    return {
      version: 1,
      devices: Object.freeze(this.getDevices()),
    };
  }

  /**
   * Return a snapshot list of all enrolled device records.
   */
  public getDevices(): readonly EnrolledDeviceRecord[] {
    return Object.freeze(Array.from(this.devices.values()));
  }

  /**
   * Return the count of enrolled devices.
   */
  public getDeviceCount(): number {
    return this.devices.size;
  }

  /**
   * Find a device by its ARC-assigned deviceId.
   */
  public findDeviceById(deviceId: string): EnrolledDeviceRecord | undefined {
    return this.devices.get(deviceId);
  }

  /**
   * Find an enrolled device by an active SPKI pin.
   * A pin maps to at most one enrolled device globally.
   */
  public findDeviceByPin(pin: string): EnrolledDeviceRecord | undefined {
    for (const dev of this.devices.values()) {
      if (dev.pins.includes(pin)) {
        return dev;
      }
    }
    return undefined;
  }

  /**
   * Query if a device is marked revoked.
   */
  public isDeviceRevoked(deviceId: string): boolean {
    const dev = this.devices.get(deviceId);
    return dev !== undefined && dev.revoked;
  }

  /**
   * Enroll a device in the trust store (§8):
   * - If the pin already exists with the same clientId: reuses existing deviceId.
   * - If the pin already exists with a different clientId: rejected.
   * - If the pin is new: assigns a fresh ARC deviceId, checking 256-device limit.
   * - Display label validated <= 64 UTF-8 bytes.
   */
  public enrollDevice(input: EnrollDeviceInput): {
    device: EnrolledDeviceRecord;
    reconnected: boolean;
  } {
    if (typeof input !== 'object' || input === null) {
      throw ArcError.invalidRequestSchema('EnrollDeviceInput must be an object.');
    }

    const { clientId, clientType, pin } = input;
    // Same authoritative rules as the persisted schema: enrollment must never
    // produce a device the trust store would refuse to serialize.
    validateClientId(clientId);
    validateClientType(clientType);
    if (!isValidSpkiPin(pin)) {
      throw ArcError.invalidRequestSchema(
        'Invalid SPKI pin: must be exactly 64 lowercase hexadecimal characters.',
      );
    }

    const displayLabel = validateDisplayLabel(input.displayLabel ?? '');

    // Check duplicate enrollment
    const existing = this.findDeviceByPin(pin);
    if (existing) {
      if (existing.clientId === clientId) {
        // Same pin, same clientId: reuse existing device record (§8)
        return { device: existing, reconnected: true };
      }
      // Same pin, different clientId: reject
      throw ArcError.invalidRequestSchema(
        `SPKI pin '${pin}' is already enrolled under a different clientId ('${existing.clientId}').`,
      );
    }

    // New device: check capacity ceiling
    if (this.devices.size >= MAX_ENROLLED_DEVICES) {
      throw ArcError.resourceExhausted(
        `Cannot enroll device: trust store has reached the maximum of ${MAX_ENROLLED_DEVICES} devices.`,
      );
    }

    // Preflight serialized size
    const newRecord: EnrolledDeviceRecord = {
      deviceId: generateDeviceId(),
      clientId,
      clientType,
      pins: Object.freeze([pin]),
      enrolledAt: new Date().toISOString(),
      displayLabel,
      revoked: false,
    };

    // Verify addition does not exceed 256 KiB
    const candidateData: DeviceTrustStoreData = {
      version: 1,
      devices: [...this.devices.values(), newRecord],
    };
    const testJson = JSON.stringify(candidateData);
    if (Buffer.byteLength(testJson, 'utf8') > MAX_TRUST_STORE_BYTES) {
      throw ArcError.resourceExhausted(
        `Cannot enroll device: resulting trust store exceeds ${MAX_TRUST_STORE_BYTES} byte ceiling.`,
      );
    }

    this.devices.set(newRecord.deviceId, newRecord);
    return { device: newRecord, reconnected: false };
  }

  /**
   * Add a pin to an existing device (rotation overlap window, §7 P-7).
   * Device can have at most 2 active pins. Adding a 3rd active pin fails closed.
   */
  public addPinToDevice(deviceId: string, newPin: string): void {
    const dev = this.devices.get(deviceId);
    if (!dev) {
      throw ArcError.deviceNotEnrolled(`Device '${deviceId}' is not enrolled in trust store.`);
    }

    if (!isValidSpkiPin(newPin)) {
      throw ArcError.invalidRequestSchema(
        'Invalid SPKI pin: must be exactly 64 lowercase hexadecimal characters.',
      );
    }

    // If device already has this pin, no-op
    if (dev.pins.includes(newPin)) {
      return;
    }

    // Pin must not belong to another device
    const otherDev = this.findDeviceByPin(newPin);
    if (otherDev && otherDev.deviceId !== deviceId) {
      throw ArcError.invalidRequestSchema(
        `Pin collision: SPKI pin '${newPin}' is already assigned to device '${otherDev.deviceId}'.`,
      );
    }

    // Cannot exceed 2 active pins
    if (dev.pins.length >= MAX_ACTIVE_PINS_PER_DEVICE) {
      throw ArcError.resourceExhausted(
        `Device '${deviceId}' already has maximum active pins of ${MAX_ACTIVE_PINS_PER_DEVICE}. Existing pins retained.`,
      );
    }

    const updatedPins = Object.freeze([...dev.pins, newPin]);
    const updated: EnrolledDeviceRecord = {
      ...dev,
      pins: updatedPins,
    };

    this.devices.set(deviceId, updated);
  }

  /**
   * Remove a pin from an existing device (closing rotation overlap window, §7 P-7).
   * A device cannot have an empty pin set; removing the sole active pin is rejected.
   */
  public removePinFromDevice(deviceId: string, pinToRemove: string): void {
    const dev = this.devices.get(deviceId);
    if (!dev) {
      throw ArcError.deviceNotEnrolled(`Device '${deviceId}' is not enrolled in trust store.`);
    }

    if (!isValidSpkiPin(pinToRemove)) {
      throw ArcError.invalidRequestSchema('Invalid SPKI pin format.');
    }

    if (!dev.pins.includes(pinToRemove)) {
      throw ArcError.invalidRequestSchema(
        `Pin '${pinToRemove}' is not assigned to device '${deviceId}'.`,
      );
    }

    if (dev.pins.length <= 1) {
      throw ArcError.invalidRequestSchema(
        `Cannot remove pin '${pinToRemove}': device '${deviceId}' must retain at least 1 active pin.`,
      );
    }

    const updatedPins = Object.freeze(dev.pins.filter((p) => p !== pinToRemove));
    const updated: EnrolledDeviceRecord = {
      ...dev,
      pins: updatedPins,
    };

    this.devices.set(deviceId, updated);
  }

  /**
   * Revoke an enrolled device.
   * Marks the device record as revoked; revocation is immediate and survives restart when persisted.
   */
  public revokeDevice(deviceId: string): void {
    const dev = this.devices.get(deviceId);
    if (!dev) {
      throw ArcError.deviceNotEnrolled(`Device '${deviceId}' is not enrolled in trust store.`);
    }

    const updated: EnrolledDeviceRecord = {
      ...dev,
      revoked: true,
    };

    this.devices.set(deviceId, updated);
  }
}

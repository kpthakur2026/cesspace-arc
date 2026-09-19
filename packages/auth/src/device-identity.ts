import crypto from 'node:crypto';
import { ArcError } from '@cesspace-arc/protocol';

/**
 * Constants governing device identity, SPKI pinning, and resource bounds.
 * Authoritative contract: docs/architecture/rc05-scope-acceptance.md §7, §8, §16.
 */
export const DEVICE_ID_LENGTH = 32;
export const DEVICE_ID_REGEX = /^[0-9a-f]{32}$/;

export const SPKI_PIN_LENGTH = 64;
export const SPKI_PIN_REGEX = /^[0-9a-f]{64}$/;

export const MAX_ACTIVE_PINS_PER_DEVICE = 2;
export const MAX_ENROLLED_DEVICES = 256;
export const MAX_DISPLAY_LABEL_BYTES = 64;
export const MAX_TRUST_STORE_BYTES = 256 * 1024; // 262,144 bytes (256 KiB)

/**
 * Metadata record for an enrolled device in the ARC trust store.
 * Persists strictly the fields permitted by §8:
 * deviceId, clientId, clientType, pin set, enrollment timestamp, display label, revocation state.
 */
export interface EnrolledDeviceRecord {
  readonly deviceId: string;
  readonly clientId: string;
  readonly clientType: string;
  readonly pins: readonly string[];
  readonly enrolledAt: string;
  readonly displayLabel: string;
  readonly revoked: boolean;
}

/**
 * Input for enrolling a device in the trust store.
 */
export interface EnrollDeviceInput {
  readonly clientId: string;
  readonly clientType: string;
  readonly pin: string;
  readonly displayLabel?: string;
}

/**
 * Generate an ARC-controlled deviceId consisting of 16 cryptographically
 * random bytes rendered as exactly 32 lowercase hexadecimal characters (§8).
 * A caller cannot supply or influence deviceId.
 */
export function generateDeviceId(): string {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * Validate that a string conforms to the canonical deviceId format:
 * exactly 32 lowercase hexadecimal characters.
 */
export function isValidDeviceId(id: unknown): id is string {
  return typeof id === 'string' && DEVICE_ID_REGEX.test(id);
}

/**
 * Validate that a string conforms to the canonical SPKI pin format:
 * exactly 64 lowercase hexadecimal characters (§7 P-5).
 * Non-hex, uppercase, wrong-length, or malformed pins return false.
 */
export function isValidSpkiPin(pin: unknown): pin is string {
  return typeof pin === 'string' && SPKI_PIN_REGEX.test(pin);
}

/**
 * Validate that a display label does not exceed 64 UTF-8 bytes (§8, RC05-NEG-22).
 * Fails closed with ArcError.invalidRequestSchema if invalid or too large.
 */
export function validateDisplayLabel(label: unknown): string {
  if (typeof label !== 'string') {
    throw ArcError.invalidRequestSchema('displayLabel must be a string.');
  }
  const byteLength = Buffer.byteLength(label, 'utf8');
  if (byteLength > MAX_DISPLAY_LABEL_BYTES) {
    throw ArcError.invalidRequestSchema(
      `displayLabel exceeds maximum allowed ${MAX_DISPLAY_LABEL_BYTES} UTF-8 bytes (got ${byteLength} bytes).`,
    );
  }
  return label;
}

/**
 * Derive the canonical SPKI pin from a certificate or public key.
 * Pinned object: SHA-256(DER SubjectPublicKeyInfo) rendered as 64 lowercase hex characters (§7 P-4, P-5).
 */
export function deriveSpkiPin(
  input: string | Buffer | crypto.KeyObject | crypto.X509Certificate,
): string {
  let derSpki: Buffer;

  if (input instanceof crypto.X509Certificate) {
    derSpki = input.publicKey.export({ type: 'spki', format: 'der' });
  } else if (input instanceof crypto.KeyObject) {
    if (input.type === 'public') {
      derSpki = input.export({ type: 'spki', format: 'der' });
    } else if (input.type === 'private') {
      derSpki = crypto.createPublicKey(input).export({ type: 'spki', format: 'der' });
    } else {
      throw ArcError.invalidRequestSchema('SecretKey cannot be used to derive SPKI pin.');
    }
  } else if (typeof input === 'string') {
    if (input.includes('BEGIN CERTIFICATE')) {
      const cert = new crypto.X509Certificate(input);
      derSpki = cert.publicKey.export({ type: 'spki', format: 'der' });
    } else if (input.includes('BEGIN PUBLIC KEY')) {
      const pubKey = crypto.createPublicKey(input);
      derSpki = pubKey.export({ type: 'spki', format: 'der' });
    } else {
      try {
        const cert = new crypto.X509Certificate(Buffer.from(input, 'utf8'));
        derSpki = cert.publicKey.export({ type: 'spki', format: 'der' });
      } catch {
        try {
          const pubKey = crypto.createPublicKey(input);
          derSpki = pubKey.export({ type: 'spki', format: 'der' });
        } catch {
          throw ArcError.invalidRequestSchema(
            'Failed to derive SPKI pin: unrecognized certificate or public key format.',
          );
        }
      }
    }
  } else if (Buffer.isBuffer(input)) {
    try {
      const cert = new crypto.X509Certificate(input);
      derSpki = cert.publicKey.export({ type: 'spki', format: 'der' });
    } catch {
      try {
        const pubKey = crypto.createPublicKey({ key: input, format: 'der', type: 'spki' });
        derSpki = pubKey.export({ type: 'spki', format: 'der' });
      } catch {
        // If already raw DER SubjectPublicKeyInfo buffer
        derSpki = input;
      }
    }
  } else {
    throw ArcError.invalidRequestSchema('Invalid input type for deriveSpkiPin.');
  }

  return crypto.createHash('sha256').update(derSpki).digest('hex').toLowerCase();
}

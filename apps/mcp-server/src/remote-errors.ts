/**
 * CesSpace ARC — RC-05 Task 3 Remote Gateway Errors
 *
 * Machine-readable, bounded failures for the TLS/mTLS admission layer.
 *
 * Every reason is a fixed enum. Messages never contain certificate bytes,
 * private-key bytes, file contents, PEM text, or key material — only the
 * category of the failure, so a startup error can be logged safely.
 */

/** Bounded, non-secret remote gateway failure categories. */
export type RemoteFailureReason =
  // Configuration
  | 'REMOTE_CONFIG_MISSING'
  | 'BIND_HOST_INVALID'
  | 'PORT_INVALID'
  | 'PUBLIC_HOSTNAME_INVALID'
  | 'WILDCARD_BIND_NOT_OPTED_IN'
  | 'HANDSHAKE_TIMEOUT_INVALID'
  // Server certificate and key
  | 'SERVER_CERTIFICATE_INVALID'
  | 'SERVER_CERTIFICATE_UNREADABLE'
  | 'SERVER_CERTIFICATE_MALFORMED'
  | 'SERVER_CERTIFICATE_NOT_YET_VALID'
  | 'SERVER_CERTIFICATE_EXPIRED'
  | 'SERVER_CERTIFICATE_SAN_MISMATCH'
  | 'SERVER_KEY_AND_CERTIFICATE_MISMATCH'
  | 'PRIVATE_KEY_SOURCE_INVALID'
  | 'PRIVATE_KEY_UNREADABLE'
  | 'PRIVATE_KEY_INSECURE'
  | 'PRIVATE_KEY_MALFORMED'
  // Client trust roots
  | 'CLIENT_CA_EMPTY'
  | 'CLIENT_CA_TOO_MANY'
  | 'CLIENT_CA_PATH_INVALID'
  | 'CLIENT_CA_UNREADABLE'
  | 'CLIENT_CA_INSECURE'
  | 'CLIENT_CA_TOO_LARGE'
  | 'CLIENT_CA_MALFORMED'
  | 'CLIENT_CA_MULTIPLE_ROOTS'
  // Trust store
  | 'TRUST_STORE_PATH_INVALID'
  | 'TRUST_STORE_INVALID'
  // Lifecycle
  | 'LISTENER_BIND_FAILED'
  | 'GATEWAY_ALREADY_STARTED'
  | 'GATEWAY_NOT_STARTED';

/**
 * Remote gateway startup or runtime failure.
 *
 * `reason` is the only machine-readable surface. `message` is a bounded,
 * generic sentence safe to log.
 */
export class RemoteConfigError extends Error {
  constructor(
    message: string,
    public readonly reason: RemoteFailureReason,
    options?: { cause?: unknown },
  ) {
    super(message);
    this.name = 'RemoteConfigError';
    if (options?.cause !== undefined) {
      // Retained for operator diagnostics. It is never serialized to a client
      // and never contains key or certificate material.
      this.cause = options.cause;
    }
  }
}

/**
 * Standard error categories for CesSpace ARC.
 */
export type ArcErrorCategory =
  | 'PROTOCOL'
  | 'AUTHENTICATION'
  | 'AUTHORIZATION'
  | 'FILESYSTEM'
  | 'EXECUTION'
  | 'RESOURCE'
  | 'INTERNAL';

/**
 * Standard machine-readable error codes.
 */
export type ArcErrorCode =
  // Protocol & Schema Errors
  | 'INVALID_REQUEST_SCHEMA'
  | 'UNSUPPORTED_METHOD'
  | 'PARSE_ERROR'

  // Authentication Errors
  | 'UNAUTHENTICATED'
  | 'INVALID_SESSION_TOKEN'
  | 'DEVICE_NOT_ENROLLED'

  // Authorization & Policy Errors
  | 'POLICY_DENIED'
  | 'APPROVAL_REQUIRED'
  | 'APPROVAL_EXPIRED'
  | 'APPROVAL_REJECTED'
  | 'PROTECTED_BRANCH_DENIED'
  | 'FORBIDDEN_COMMAND'

  // Filesystem & Boundary Errors
  | 'PATH_ESCAPES_ROOT'
  | 'ACCESS_DENIED'
  | 'FILE_NOT_FOUND'
  | 'PARENT_NOT_FOUND'
  | 'ALREADY_EXISTS'
  | 'CONFLICT_PRECONDITION_FAILED'
  | 'NOT_A_DIRECTORY'
  | 'IS_A_DIRECTORY'
  | 'NOT_A_FILE'
  | 'HARDLINK_DETECTED'
  | 'UNSAFE_SYMLINK'
  | 'CROSS_DEVICE_MOVE_UNSUPPORTED'
  | 'INVALID_PATH_CHARS'
  | 'NO_WORKSPACE_CONFIGURED'

  // Execution & Resource Errors
  | 'EXECUTION_TIMEOUT'
  | 'COMMAND_FAILED'
  | 'PROCESS_NOT_FOUND'
  | 'PAYLOAD_TOO_LARGE'
  | 'RATE_LIMIT_EXCEEDED'
  | 'RESOURCE_EXHAUSTED'

  // Internal Errors
  | 'INTERNAL_ERROR'
  | 'ROLLBACK_FAILED';

/**
 * Canonical structured error payload emitted across the control plane.
 */
export interface ArcErrorPayload {
  code: ArcErrorCode;
  category: ArcErrorCategory;
  message: string;
  details?: Record<string, string | number | boolean>;
  remediationHint?: string;
  retryable: boolean;
}

/**
 * Canonical structured error class for CesSpace ARC.
 */
export class ArcError extends Error implements ArcErrorPayload {
  public readonly code: ArcErrorCode;
  public readonly category: ArcErrorCategory;
  public readonly details?: Record<string, string | number | boolean>;
  public readonly remediationHint?: string;
  public readonly retryable: boolean;

  constructor(payload: ArcErrorPayload) {
    super(payload.message);
    this.name = 'ArcError';
    this.code = payload.code;
    this.category = payload.category;
    this.details = payload.details;
    this.remediationHint = payload.remediationHint;
    this.retryable = payload.retryable;
    Object.setPrototypeOf(this, new.target.prototype);
  }

  public toJSON(): ArcErrorPayload {
    return {
      code: this.code,
      category: this.category,
      message: this.message,
      details: this.details,
      remediationHint: this.remediationHint,
      retryable: this.retryable,
    };
  }

  public static pathEscapesRoot(
    message = 'Security violation: Path resolves outside the authorized workspace boundary.',
  ): ArcError {
    return new ArcError({
      code: 'PATH_ESCAPES_ROOT',
      category: 'FILESYSTEM',
      message,
      retryable: false,
      remediationHint: 'Ensure path is contained strictly within the authorized workspace root.',
    });
  }

  public static accessDenied(
    message = 'Access denied: Path matches sensitive or blacklisted pattern.',
  ): ArcError {
    return new ArcError({
      code: 'ACCESS_DENIED',
      category: 'FILESYSTEM',
      message,
      retryable: false,
      remediationHint: 'Credential and sensitive configuration files cannot be accessed.',
    });
  }

  public static fileNotFound(message = 'File not found in workspace.'): ArcError {
    return new ArcError({
      code: 'FILE_NOT_FOUND',
      category: 'FILESYSTEM',
      message,
      retryable: false,
      remediationHint: 'Check that the requested relative path exists.',
    });
  }

  public static notADirectory(message = 'Target path is not a directory.'): ArcError {
    return new ArcError({
      code: 'NOT_A_DIRECTORY',
      category: 'FILESYSTEM',
      message,
      retryable: false,
    });
  }

  public static isADirectory(message = 'Target path is a directory, not a file.'): ArcError {
    return new ArcError({
      code: 'IS_A_DIRECTORY',
      category: 'FILESYSTEM',
      message,
      retryable: false,
    });
  }

  public static invalidPathChars(
    message = 'Path contains invalid characters or null bytes.',
  ): ArcError {
    return new ArcError({
      code: 'INVALID_PATH_CHARS',
      category: 'FILESYSTEM',
      message,
      retryable: false,
      remediationHint: 'Remove null bytes or control characters from path.',
    });
  }

  public static noWorkspaceConfigured(
    message = 'No authorized workspace configured for operation.',
  ): ArcError {
    return new ArcError({
      code: 'NO_WORKSPACE_CONFIGURED',
      category: 'FILESYSTEM',
      message,
      retryable: false,
      remediationHint:
        'Register and specify an authorized workspace before invoking workspace tools.',
    });
  }

  public static payloadTooLarge(
    message = 'Requested read or result payload exceeds maximum allowed size.',
  ): ArcError {
    return new ArcError({
      code: 'PAYLOAD_TOO_LARGE',
      category: 'RESOURCE',
      message,
      retryable: false,
      remediationHint: 'Use offset and length parameters to paginate file reads.',
    });
  }

  public static invalidRequestSchema(message: string, remediationHint?: string): ArcError {
    return new ArcError({
      code: 'INVALID_REQUEST_SCHEMA',
      category: 'PROTOCOL',
      message,
      retryable: false,
      remediationHint,
    });
  }

  public static policyDenied(message = 'Operation denied by policy.'): ArcError {
    return new ArcError({
      code: 'POLICY_DENIED',
      category: 'AUTHORIZATION',
      message,
      retryable: false,
      remediationHint: 'Review active policy rules or request approval.',
    });
  }

  public static internalError(message = 'Internal error occurred.'): ArcError {
    return new ArcError({
      code: 'INTERNAL_ERROR',
      category: 'INTERNAL',
      message,
      retryable: false,
    });
  }

  public static processNotFound(message = 'Process not found.'): ArcError {
    return new ArcError({
      code: 'PROCESS_NOT_FOUND',
      category: 'RESOURCE',
      message,
      retryable: false,
      remediationHint: 'Verify the processId returned from run_command.',
    });
  }

  public static executionTimeout(
    message = 'Command execution exceeded configured timeout.',
  ): ArcError {
    return new ArcError({
      code: 'EXECUTION_TIMEOUT',
      category: 'EXECUTION',
      message,
      retryable: true,
      remediationHint: 'Increase timeoutMs if the command legitimately requires more time.',
    });
  }

  public static resourceExhausted(message = 'Resource limit exceeded.'): ArcError {
    return new ArcError({
      code: 'RESOURCE_EXHAUSTED',
      category: 'RESOURCE',
      message,
      retryable: true,
      remediationHint: 'Wait for active processes to complete before launching new ones.',
    });
  }

  public static forbiddenCommand(
    message = 'Command or executable is forbidden by policy.',
  ): ArcError {
    return new ArcError({
      code: 'FORBIDDEN_COMMAND',
      category: 'AUTHORIZATION',
      message,
      retryable: false,
      remediationHint: 'Ensure the executable is in the approved development tool allowlist.',
    });
  }

  public static conflictPreconditionFailed(
    message = 'Precondition failed: file content or attributes do not match expected precondition.',
    details?: Record<string, string | number | boolean>,
  ): ArcError {
    return new ArcError({
      code: 'CONFLICT_PRECONDITION_FAILED',
      category: 'FILESYSTEM',
      message,
      details,
      retryable: false,
      remediationHint: 'Verify the expected hash matches the current file contents.',
    });
  }

  public static alreadyExists(
    message = 'Destination or target file already exists.',
    details?: Record<string, string | number | boolean>,
  ): ArcError {
    return new ArcError({
      code: 'ALREADY_EXISTS',
      category: 'FILESYSTEM',
      message,
      details,
      retryable: false,
      remediationHint: 'Ensure destination does not exist prior to creation or move.',
    });
  }

  public static parentNotFound(
    message = 'Immediate parent directory does not exist.',
    details?: Record<string, string | number | boolean>,
  ): ArcError {
    return new ArcError({
      code: 'PARENT_NOT_FOUND',
      category: 'FILESYSTEM',
      message,
      details,
      retryable: false,
      remediationHint: 'Create the parent directory before creating files within it.',
    });
  }

  public static notAFile(
    message = 'Target path is not a regular file.',
    details?: Record<string, string | number | boolean>,
  ): ArcError {
    return new ArcError({
      code: 'NOT_A_FILE',
      category: 'FILESYSTEM',
      message,
      details,
      retryable: false,
    });
  }

  public static hardlinkDetected(
    message = 'Security violation: Target file has hardlink count greater than 1.',
    details?: Record<string, string | number | boolean>,
  ): ArcError {
    return new ArcError({
      code: 'HARDLINK_DETECTED',
      category: 'FILESYSTEM',
      message,
      details,
      retryable: false,
      remediationHint: 'Files with multiple hardlinks cannot be mutated safely.',
    });
  }

  public static unsafeSymlink(
    message = 'Security violation: Target or intermediate component is a symbolic link.',
    details?: Record<string, string | number | boolean>,
  ): ArcError {
    return new ArcError({
      code: 'UNSAFE_SYMLINK',
      category: 'FILESYSTEM',
      message,
      details,
      retryable: false,
      remediationHint: 'Symbolic links cannot be created, modified, or traversed for mutation.',
    });
  }

  public static crossDeviceMoveUnsupported(
    message = 'Cross-device file move is not supported.',
    details?: Record<string, string | number | boolean>,
  ): ArcError {
    return new ArcError({
      code: 'CROSS_DEVICE_MOVE_UNSUPPORTED',
      category: 'FILESYSTEM',
      message,
      details,
      retryable: false,
      remediationHint: 'Move operations must be contained within the same filesystem.',
    });
  }

  public static rollbackFailed(
    message = 'Operation rollback failed.',
    details?: Record<string, string | number | boolean>,
  ): ArcError {
    return new ArcError({
      code: 'ROLLBACK_FAILED',
      category: 'INTERNAL',
      message,
      details,
      retryable: false,
      remediationHint: 'Administrative recovery may be required for indicated paths.',
    });
  }
}

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
  | 'PATCH_PARSE_ERROR'
  | 'POLICY_PARSE_ERROR'

  // Authentication Errors
  | 'UNAUTHENTICATED'
  | 'INVALID_SESSION_TOKEN'
  | 'DEVICE_NOT_ENROLLED'

  // Authorization & Policy Errors
  | 'POLICY_DENIED'
  | 'APPROVAL_REQUIRED'
  | 'APPROVAL_EXPIRED'
  | 'APPROVAL_REJECTED'
  | 'POLICY_LOAD_ERROR'
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
  | 'PATCH_PREFLIGHT_FAILED'
  | 'PATCH_UNSUPPORTED_OPERATION'

  // Execution & Resource Errors
  | 'EXECUTION_TIMEOUT'
  | 'COMMAND_FAILED'
  | 'PROCESS_NOT_FOUND'
  | 'PAYLOAD_TOO_LARGE'
  | 'RATE_LIMIT_EXCEEDED'
  | 'RESOURCE_EXHAUSTED'
  | 'CONCURRENCY_EXCEEDED'
  | 'COMPOSITE_TIMEOUT'

  // Internal Errors
  | 'INTERNAL_ERROR'
  | 'ROLLBACK_FAILED'

  // Repository & Worktree Errors (RC-07 Target)
  | 'GIT_REPOSITORY_NOT_FOUND'
  | 'PATH_OUTSIDE_WORKSPACE'
  | 'SYMLINK_ESCAPE_DETECTED'
  | 'WORKSPACE_UNREGISTERED'
  | 'INVALID_GIT_ARGUMENT';

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

  public static approvalRequired(
    message = 'Operation requires explicit human approval.',
    details?: Record<string, string | number | boolean>,
  ): ArcError {
    return new ArcError({
      code: 'APPROVAL_REQUIRED',
      category: 'AUTHORIZATION',
      message,
      details,
      retryable: false,
      remediationHint:
        'Obtain explicit approval through the trusted operator workflow before retrying this protected operation.',
    });
  }

  public static approvalExpired(
    message = 'Approval request has expired.',
    details?: Record<string, string | number | boolean>,
  ): ArcError {
    return new ArcError({
      code: 'APPROVAL_EXPIRED',
      category: 'AUTHORIZATION',
      message,
      details,
      retryable: false,
      remediationHint: 'Request a new human approval for this operation.',
    });
  }

  public static approvalRejected(
    message = 'Approval validation failed.',
    details?: Record<string, string | number | boolean>,
  ): ArcError {
    return new ArcError({
      code: 'APPROVAL_REJECTED',
      category: 'AUTHORIZATION',
      message,
      details,
      retryable: false,
      remediationHint: 'Ensure approval token and request bindings match exactly.',
    });
  }

  public static policyParseError(
    message = 'Declarative policy document could not be parsed: invalid structure.',
    details?: Record<string, string | number | boolean>,
  ): ArcError {
    return new ArcError({
      code: 'POLICY_PARSE_ERROR',
      category: 'PROTOCOL',
      message,
      details,
      retryable: false,
      remediationHint:
        'Ensure policy adheres to the RC-04 declarative schema and resource constraints.',
    });
  }

  public static policyLoadError(
    message = 'Declarative policy could not be loaded into the policy engine.',
    details?: Record<string, string | number | boolean>,
  ): ArcError {
    return new ArcError({
      code: 'POLICY_LOAD_ERROR',
      category: 'AUTHORIZATION',
      message,
      details,
      retryable: false,
      remediationHint: 'Check that all referenced workspaces exist and policy syntax is valid.',
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

  public static concurrencyExceeded(
    message = 'Concurrent execution limit exceeded for this workspace.',
    details?: Record<string, string | number | boolean>,
  ): ArcError {
    return new ArcError({
      code: 'CONCURRENCY_EXCEEDED',
      category: 'RESOURCE',
      message,
      retryable: true,
      remediationHint:
        'Wait for active workspace test processes to finish before running additional tests.',
      ...(details ? { details } : {}),
    });
  }

  public static compositeTimeout(
    message = 'Composite execution exceeded aggregate timeout.',
    details?: Record<string, string | number | boolean>,
  ): ArcError {
    return new ArcError({
      code: 'COMPOSITE_TIMEOUT',
      category: 'RESOURCE',
      message,
      details,
      retryable: false,
      remediationHint: 'Reduce verification suite scope or investigate long-running step.',
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

  public static patchParseError(
    message = 'Patch could not be parsed: invalid unified diff structure.',
    details?: Record<string, string | number | boolean>,
  ): ArcError {
    return new ArcError({
      code: 'PATCH_PARSE_ERROR',
      category: 'PROTOCOL',
      message,
      details,
      retryable: false,
      remediationHint:
        'Ensure the patch is a valid, well-formed unified diff conforming to the RC-03 contract.',
    });
  }

  public static patchPreflightFailed(
    message = 'Patch preflight validation failed.',
    details?: Record<string, string | number | boolean>,
  ): ArcError {
    return new ArcError({
      code: 'PATCH_PREFLIGHT_FAILED',
      category: 'FILESYSTEM',
      message,
      details,
      retryable: false,
      remediationHint:
        'Ensure the target file exists, is regular UTF-8 text, and exact hunk context lines match.',
    });
  }

  public static patchUnsupportedOperation(
    message = 'Unsupported patch operation.',
    details?: Record<string, string | number | boolean>,
  ): ArcError {
    return new ArcError({
      code: 'PATCH_UNSUPPORTED_OPERATION',
      category: 'FILESYSTEM',
      message,
      details,
      retryable: false,
      remediationHint:
        'apply_patch only supports modifying existing regular text files. File creation, deletion, renaming, binary patches, and mode changes are forbidden.',
    });
  }

  public static deviceNotEnrolled(
    message = 'Device not enrolled in trust store.',
    details?: Record<string, string | number | boolean>,
  ): ArcError {
    return new ArcError({
      code: 'DEVICE_NOT_ENROLLED',
      category: 'AUTHENTICATION',
      message,
      details,
      retryable: false,
    });
  }

  /**
   * Generic pre-session authentication failure (rc05 §25.1).
   *
   * The SINGLE client-facing answer for every pre-session device/session
   * admission failure: no enrolled device, a revoked device, a zero-device
   * gateway, or a tokenless request with no session context. It deliberately
   * carries no details, because the reason is an internal diagnostic
   * (`DEVICE_NOT_ENROLLED` is never remote-facing).
   */
  public static unauthenticated(message = 'Authentication failed'): ArcError {
    return new ArcError({
      code: 'UNAUTHENTICATED',
      category: 'AUTHENTICATION',
      message,
      retryable: false,
    });
  }

  /**
   * Generic post-session failure (rc05 §25.1).
   *
   * The SINGLE client-facing answer once a server-issued session is involved:
   * missing credential, malformed credential, wrong digest, expiry, revocation,
   * identity/binding mismatch, or a device that has since been revoked. It never
   * confirms whether the session existed, expired, or was revoked.
   */
  public static invalidSessionToken(message = 'Invalid or expired session token'): ArcError {
    return new ArcError({
      code: 'INVALID_SESSION_TOKEN',
      category: 'AUTHENTICATION',
      message,
      retryable: false,
    });
  }

  public static gitRepositoryNotFound(
    message = 'Directory is not a valid Git repository.',
  ): ArcError {
    return new ArcError({
      code: 'GIT_REPOSITORY_NOT_FOUND',
      category: 'FILESYSTEM',
      message,
      retryable: false,
      remediationHint: 'Ensure the target directory is an initialized Git repository.',
    });
  }

  public static pathOutsideWorkspace(
    message = 'Target path resolves outside authorized workspace boundary.',
  ): ArcError {
    return new ArcError({
      code: 'PATH_OUTSIDE_WORKSPACE',
      category: 'FILESYSTEM',
      message,
      retryable: false,
      remediationHint: 'Ensure target path is strictly contained within authorized workspace root.',
    });
  }

  public static symlinkEscapeDetected(
    message = 'Symlink resolves outside authorized workspace boundary.',
  ): ArcError {
    return new ArcError({
      code: 'SYMLINK_ESCAPE_DETECTED',
      category: 'FILESYSTEM',
      message,
      retryable: false,
      remediationHint: 'Symlinks escaping the workspace boundary are strictly forbidden.',
    });
  }

  public static workspaceUnregistered(
    message = 'Specified workspace is not registered in authorized workspaces.',
  ): ArcError {
    return new ArcError({
      code: 'WORKSPACE_UNREGISTERED',
      category: 'AUTHORIZATION',
      message,
      retryable: false,
      remediationHint: 'Provide an authorized registered workspaceId or workspaceRoot.',
    });
  }

  public static invalidGitArgument(
    message = 'Invalid Git argument provided.',
    remediationHint?: string,
  ): ArcError {
    return new ArcError({
      code: 'INVALID_GIT_ARGUMENT',
      category: 'PROTOCOL',
      message,
      retryable: false,
      remediationHint:
        remediationHint ??
        'Provide a valid Git revision or argument without leading dashes or shell metacharacters.',
    });
  }
}

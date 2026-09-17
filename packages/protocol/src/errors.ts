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
  | 'NOT_A_DIRECTORY'
  | 'IS_A_DIRECTORY'
  | 'INVALID_PATH_CHARS'
  | 'NO_WORKSPACE_CONFIGURED'

  // Execution & Resource Errors
  | 'EXECUTION_TIMEOUT'
  | 'COMMAND_FAILED'
  | 'PROCESS_NOT_FOUND'
  | 'PAYLOAD_TOO_LARGE'
  | 'RATE_LIMIT_EXCEEDED'

  // Internal Errors
  | 'INTERNAL_ERROR';

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

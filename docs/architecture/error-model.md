# Structured Error Model — CesSpace ARC

> **Document:** Error Handling Specification
> **Status:** RC-00 Approved Baseline — RC-01 Active
> **Classification:** Architecture & Protocol Specification

---

## 1. Objectives & Principles

In an agent-to-machine control plane, error handling serves two critical purposes:

1. **Developer & Agent Usability:** AI agents need structured, machine-readable errors to understand why a request failed, whether it can be retried, and what parameter needs adjustment.
2. **Security & Information Concealment:** Error messages must never leak sensitive host details, usernames, absolute filesystem paths outside the workspace, stack traces, or internal network topology.

### Core Error Principles

- **Fail Closed:** Any unhandled exception or ambiguous state produces a generic, safe error rather than partial execution.
- **Zero Information Leakage:** Path errors report relative paths within the workspace root; host paths outside the jail are completely concealed.
- **Consistent Structure:** Every error emitted over MCP or internal interfaces conforms to the canonical `ArcError` structure.

---

## 2. Canonical Error Schema

```typescript
export interface ArcErrorPayload {
  // Standard machine-readable error code (e.g. "PATH_ESCAPES_ROOT")
  code: ArcErrorCode;

  // High-level category
  category: ArcErrorCategory;

  // Safe, sanitized human-readable message
  message: string;

  // Structured safe contextual attributes (no secrets/paths outside jail)
  details?: Record<string, string | number | boolean>;

  // Actionable remediation suggestion for the agent/user
  remediationHint?: string;

  // Boolean indicating if caller may safely retry without modification
  retryable: boolean;
}

export type ArcErrorCategory =
  | 'PROTOCOL' // Malformed JSON-RPC, schema violation
  | 'AUTHENTICATION' // Missing or invalid session token
  | 'AUTHORIZATION' // Denied by policy or missing approval
  | 'FILESYSTEM' // Path traversal, file not found, permission error
  | 'EXECUTION' // Subprocess timeout, non-zero exit, signal termination
  | 'RESOURCE' // Payload size exceeded, rate limit hit
  | 'INTERNAL'; // Unexpected control plane error
```

---

## 3. Standardized Error Codes & Mapping

| Error Code                | Category         | HTTP/JSON-RPC Code | Description                                            | Information Sanitization                              |
| :------------------------ | :--------------- | :----------------- | :----------------------------------------------------- | :---------------------------------------------------- |
| `INVALID_REQUEST_SCHEMA`  | `PROTOCOL`       | -32600 / 400       | Request parameters do not match MCP schema.            | Omits unparseable buffer contents.                    |
| `UNAUTHENTICATED`         | `AUTHENTICATION` | -32001 / 401       | Session token missing, expired, or invalid.            | Generic authentication required response.             |
| `POLICY_DENIED`           | `AUTHORIZATION`  | -32003 / 403       | Operation denied by active policy rule.                | Returns rule ID and denied action; no host internals. |
| `APPROVAL_REQUIRED`       | `AUTHORIZATION`  | -32002 / 202       | Operation requires human approval before proceeding.   | Returns `approvalRequestId` and expiration time.      |
| `APPROVAL_EXPIRED`        | `AUTHORIZATION`  | -32004 / 410       | Approval token exceeded TTL window.                    | Generic timeout message.                              |
| `PATH_ESCAPES_ROOT`       | `FILESYSTEM`     | -32010 / 403       | Target path attempts traversal outside workspace root. | **Never echoes resolved external path.**              |
| `ACCESS_DENIED`           | `FILESYSTEM`     | -32011 / 403       | File or directory matches sensitive blacklist.         | Identifies path pattern category only.                |
| `FILE_NOT_FOUND`          | `FILESYSTEM`     | -32012 / 404       | Target file does not exist in workspace.               | Mentions relative path only.                          |
| `PAYLOAD_TOO_LARGE`       | `RESOURCE`       | -32020 / 413       | Request or response exceeds maximum allowed size.      | Reports byte limits and actual size.                  |
| `RATE_LIMIT_EXCEEDED`     | `RESOURCE`       | -32021 / 429       | Client exceeded request rate limit.                    | Reports retry-after duration in seconds.              |
| `EXECUTION_TIMEOUT`       | `EXECUTION`      | -32030 / 504       | Command execution exceeded maximum allowed time.       | Reports configured timeout ceiling.                   |
| `COMMAND_FAILED`          | `EXECUTION`      | -32031 / 500       | Process terminated with non-zero exit code.            | Reports exit code and bounded stderr.                 |
| `PROTECTED_BRANCH_DENIED` | `AUTHORIZATION`  | -32040 / 403       | Direct mutation of protected Git branch denied.        | Specifies protected branch name.                      |
| `INTERNAL_ERROR`          | `INTERNAL`       | -32603 / 500       | Unexpected internal failure.                           | **Masks internal stack traces.**                      |

---

## 4. Anti-Leakage Sanitization Rules

To ensure host privacy and security:

1. **Path Scrubbing:** Any path matching the host's system structure (e.g., `/home/username/`, `/var/lib/`, `/tmp/arc-run-XXXX`) is stripped or replaced with relative workspace notation (`./path/to/file`).
2. **Username & Hostname Masking:** Host system usernames and machine hostnames are scrubbed from stderr, stdout, and error strings.
3. **No Raw Stack Traces in MCP Responses:** Internal TypeScript/Node.js stack traces are logged only to secure local audit logs, never returned over JSON-RPC to the calling agent.
4. **Symlink Target Concealment:** If an operation fails because a symlink points to `/etc/shadow`, the error message states:
   > _"Security violation: Path resolves outside the authorized workspace boundary."_
   > It **never** discloses what file outside the boundary was targeted.

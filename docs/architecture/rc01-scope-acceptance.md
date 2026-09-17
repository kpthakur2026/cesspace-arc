# RC-01 Scope & Acceptance Criteria — CesSpace ARC

> **Document:** Stage Specification & Quality Gates
> **Status:** RC-00 Proposed Baseline — Pending Independent Review
> **Target Stage:** `RC-01` — Read-Only MCP Core
> **Estimated Effort:** 6–10 Hours

---

## 1. Stage Objective & Boundaries

The objective of **RC-01** is to build the initial **read-only Model Context Protocol (MCP) server core**, providing safe inspection capabilities into explicitly approved local development workspaces.

### Mandatory Prerequisite: The Minimal Security Kernel

To preserve the permanent invariant that **no operation may execute without policy enforcement and audit evidence**, RC-01 does NOT implement standalone or unmonitored tools. Instead, RC-01 must implement a **Minimal Security Kernel** inside `packages/policy` and `packages/audit` through which all 9 read-only tools must strictly pass:

1. **Default-Deny Admission Gate:** Rejects unauthenticated callers, invalid schemas, or unregistered tools before dispatch.
2. **Explicit Tool Allowlist:** Admits only the 9 designated read-only tools; all other tool names trigger immediate `POLICY_DENIED`.
3. **Authorized-Workspace Registry:** Enforces that all targets resolve to pre-registered canonical workspace roots.
4. **Canonical Workspace Binding:** Binds every operation to the active workspace context tuple.
5. **Unified Policy Decision Path:** Dispatches each operation through `evaluate()` in `packages/policy`.
6. **Minimal Structured Audit Sink:** Emits a canonical `AuditRecord` to a structured in-memory/stream sink for every tool invocation.

In **RC-04**, this exact policy kernel is extended with user-defined YAML rules and approvals; in **RC-06**, the audit sink is extended with persistent storage and anchoring. Zero duplicated authorization systems are created.

### Permitted Implementation Scope for RC-01

- Local stdio-based MCP transport.
- Minimal Security Kernel (`packages/policy`, `packages/audit`).
- The 9 designated read-only tools.
- Canonical path resolver and workspace boundary containment (`packages/filesystem`).
- Symlink traversal protection and descriptor-level checks.
- Structured error handling (`packages/protocol`).
- Unit tests and mandatory security negative control tests.

### Explicitly Out of Scope for RC-01 (Forbidden)

- Terminal command execution (`run_command`).
- File creation or modification (`write_file`, `create_file`, `apply_patch`).
- Network listeners, remote HTTP gateways, or open ports.
- Device enrollment or complex remote token lifecycles (local stdio execution only).
- Public deployment or cloud integrations.

---

## 2. Tools to Implement in RC-01

| Tool Name            | Capability                                | Input Constraints                                                | Security Controls                                      |
| :------------------- | :---------------------------------------- | :--------------------------------------------------------------- | :----------------------------------------------------- |
| **`health`**         | Check server readiness and active stage.  | None (`{}`).                                                     | Non-sensitive static status response.                  |
| **`list_directory`** | List entries within authorized workspace. | `path` (string), `recursive` (bool), `maxDepth` (1..5).          | Canonical path check, hides blacklisted files.         |
| **`read_file`**      | Read file content within workspace.       | `path` (string), `offset` (int), `length` (int <= 1MB).          | Canonical path check, blacklist filter, max 1MB limit. |
| **`search_files`**   | Find files by glob/regex pattern.         | `pattern` (string), `subPath` (optional), `maxResults` (<= 200). | Traversal bounded to approved root.                    |
| **`search_text`**    | Search text in workspace files.           | `query` (string), `isRegex` (bool), `maxMatches` (<= 200).       | ReDoS protection, skips binary & blacklisted files.    |
| **`git_status`**     | Working tree branch and dirty state.      | `workspaceRoot` (optional).                                      | Verified Git root, parameter injection guard.          |
| **`git_diff`**       | Working tree or commit diff.              | `target` (string), `path` (string), `cached` (bool).             | Max diff size limit (512KB), secret masking.           |
| **`git_log`**        | Recent commit history.                    | `maxCount` (<= 100), `revision` (string).                        | Revision argument sanitization.                        |
| **`system_status`**  | Host VM CPU/memory/disk stats.            | None (`{}`).                                                     | Host metrics sanitized; no hostnames/private IPs.      |

---

## 3. Mandatory Security & Negative Control Criteria

RC-01 cannot be approved without automated negative test cases proving the following failure scenarios:

1. **Path Traversal via Relative Slashes:**
   - Input: `read_file` with `path: "../../../../etc/passwd"`.
   - Expected Result: Request rejected with error code `PATH_ESCAPES_ROOT`.
2. **Symlink Escape to External Target:**
   - Input: `read_file` targeting a symlink inside the workspace pointing to `/etc/shadow`.
   - Expected Result: Request rejected with error code `PATH_ESCAPES_ROOT`.
3. **Secret File Blacklist Enforcement:**
   - Input: `read_file` with `path: ".env"` or `path: ".ssh/id_rsa"` within an approved workspace.
   - Expected Result: Request rejected with error code `ACCESS_DENIED`.
4. **Git Argument Injection Prevention:**
   - Input: `git_log` with `revision: "--output=/tmp/pwned"`.
   - Expected Result: Sanitizer rejects dangerous argument with `INVALID_REQUEST_SCHEMA`.
5. **Payload Buffer Exceeded:**
   - Input: `read_file` with `length: 50000000` (50 MB).
   - Expected Result: Request rejected or clamped with `PAYLOAD_TOO_LARGE`.
6. **Unapproved Workspace Root Access:**
   - Input: Any filesystem tool targeting an absolute directory not in the approved root list.
   - Expected Result: Request rejected with `PATH_ESCAPES_ROOT` or `NO_WORKSPACE_CONFIGURED`.
7. **Unregistered Tool Invocation (Kernel Default Deny):**
   - Input: Request calling `run_command` or any mutating tool in RC-01.
   - Expected Result: Rejected at admission by Minimal Security Kernel with `POLICY_DENIED`.
8. **Audit Trail Verification:**
   - Assertion: Every invoked tool (both allowed and denied) must produce a matching `AuditRecord` in the audit sink.

---

## 4. Quality Gates Checklist for RC-01

Before RC-01 is marked complete and submitted for review, the following gates must pass:

- [ ] **Typecheck:** Clean TypeScript compilation with `tsc --noEmit` and `strict: true`.
- [ ] **Lint:** Zero ESLint errors or warnings across all packages.
- [ ] **Formatting:** Prettier verification passes (`pnpm run format:check`).
- [ ] **Unit Tests:** 100% pass rate on core logic.
- [ ] **Negative Security Suite:** All 8 mandatory negative control scenarios pass.
- [ ] **`git diff --check`:** Zero whitespace or merge conflict markers.
- [ ] **Secret Scan:** Clean scan verifying zero credentials committed (Gitleaks + policy check).
- [ ] **Dependency Audit:** `pnpm audit` reports zero known vulnerabilities.
- [ ] **Stage-Gate Stop:** Complete diff and test execution evidence documented; stop for independent review.

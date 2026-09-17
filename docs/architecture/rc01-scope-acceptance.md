# RC-01 Scope & Acceptance Criteria — CesSpace ARC

> **Document:** Stage Specification & Quality Gates
> **Status:** RC-00 Approved Baseline
> **Target Stage:** `RC-01` — Read-Only MCP Core
> **Estimated Effort:** 6–10 Hours

---

## 1. Stage Objective & Boundaries

The objective of **RC-01** is to build the initial **read-only Model Context Protocol (MCP) server core**, providing safe inspection capabilities into explicitly approved local development workspaces.

### Permitted Implementation Scope for RC-01
- Local stdio-based MCP transport.
- The 9 designated read-only tools.
- Canonical path resolver and workspace boundary containment.
- Symlink traversal protection.
- Structured error handling.
- Unit tests and mandatory security negative control tests.

### Explicitly Out of Scope for RC-01 (Forbidden)
- Terminal command execution (`run_command`).
- File creation or modification (`write_file`, `create_file`, `apply_patch`).
- Network listeners, remote HTTP gateways, or open ports.
- Authentication tokens or device enrollment (stdio local execution only).
- Public deployment or cloud integrations.

---

## 2. Tools to Implement in RC-01

| Tool Name | Capability | Input Constraints | Security Controls |
| :--- | :--- | :--- | :--- |
| **`health`** | Check server readiness and active stage. | None (`{}`). | Non-sensitive static status response. |
| **`list_directory`** | List entries within authorized workspace. | `path` (string), `recursive` (bool), `maxDepth` (1..5). | Canonical path check, hides blacklisted files. |
| **`read_file`** | Read file content within workspace. | `path` (string), `offset` (int), `length` (int <= 1MB). | Canonical path check, blacklist filter, max 1MB limit. |
| **`search_files`** | Find files by glob/regex pattern. | `pattern` (string), `subPath` (optional), `maxResults` (<= 200). | Traversal bounded to approved root. |
| **`search_text`** | Search text in workspace files. | `query` (string), `isRegex` (bool), `maxMatches` (<= 200). | ReDoS protection, skips binary & blacklisted files. |
| **`git_status`** | Working tree branch and dirty state. | `workspaceRoot` (optional). | Verified Git root, parameter injection guard. |
| **`git_diff`** | Working tree or commit diff. | `target` (string), `path` (string), `cached` (bool). | Max diff size limit (512KB), secret masking. |
| **`git_log`** | Recent commit history. | `maxCount` (<= 100), `revision` (string). | Revision argument sanitization. |
| **`system_status`**| Host VM CPU/memory/disk stats. | None (`{}`). | Host metrics sanitized; no hostnames/private IPs. |

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
   - Expected Result: Request rejected with `PATH_ESCAPES_ROOT`.

---

## 4. Quality Gates Checklist for RC-01

Before RC-01 is marked complete and submitted for review, the following gates must pass:

- [ ] **Typecheck:** Clean TypeScript compilation with `tsc --noEmit` and `strict: true`.
- [ ] **Lint:** Zero ESLint errors or warnings across all packages.
- [ ] **Formatting:** Prettier / format verification passes.
- [ ] **Unit Tests:** 100% pass rate on core logic.
- [ ] **Negative Security Suite:** All 6 mandatory negative control scenarios pass.
- [ ] **`git diff --check`:** Zero whitespace or merge conflict markers.
- [ ] **Secret Scan:** Clean scan verifying zero credentials committed.
- [ ] **Stage-Gate Stop:** Complete diff and test execution evidence documented; stop for independent review.

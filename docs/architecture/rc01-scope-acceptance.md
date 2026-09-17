# RC-01 Scope & Acceptance Criteria — CesSpace ARC

> **Document:** Stage Specification & Quality Gates
> **Status:** RC-01 Implementation — IN PROGRESS / PENDING INDEPENDENT REVIEW
> **Target Stage:** `RC-01` — Read-Only MCP Core
> **Base:** `main` (RC-00 Approved Baseline)

---

## 1. Stage Objective & Boundaries

The objective of **RC-01** is to build the initial **read-only Model Context Protocol (MCP) server core**, providing safe inspection capabilities into explicitly approved local development workspaces.

### 1.1. Mandatory Prerequisite: The Minimal Security Kernel

To preserve the permanent invariant that **no operation may execute without policy enforcement and audit evidence**, RC-01 does NOT implement standalone or unmonitored tools. All 9 read-only tools strictly pass through the **Minimal Security Kernel** implemented in `packages/policy` and `packages/audit`:

1. **Default-Deny Admission Gate:** Rejects unauthenticated callers, invalid schemas, or unregistered tools before dispatch.
2. **Explicit Tool Allowlist:** Admits only the 9 designated read-only tools; all other tool names (such as `run_command` or `write_file`) trigger immediate `POLICY_DENIED`.
3. **Authorized-Workspace Registry:** Enforces that all targets resolve to pre-registered canonical workspace roots (`WorkspaceRegistry`).
4. **Canonical Workspace Binding:** Binds every operation to the active workspace context tuple (`PolicyEvaluationContext`).
5. **Unified Policy Decision Path:** Dispatches each operation through `evaluate()` in `packages/policy` prior to any execution.
6. **Minimal Structured Audit Sink:** Emits a canonical `AuditRecord` with sequential SHA-256 hash chaining to an in-memory/stream sink for every tool invocation (both ALLOW and DENY).

In **RC-04**, this exact policy kernel is extended with user-defined YAML rules and approvals; in **RC-06**, the audit sink is extended with persistent storage and anchoring. Zero duplicated authorization systems are created.

### 1.2. Permitted Implementation Scope for RC-01

- Local stdio-based MCP transport via `@modelcontextprotocol/sdk`.
- Minimal Security Kernel (`packages/policy`, `packages/audit`).
- The 9 designated read-only tools (`health`, `list_directory`, `read_file`, `search_files`, `search_text`, `git_status`, `git_diff`, `git_log`, `system_status`).
- Canonical path resolver and workspace boundary containment (`packages/filesystem`).
- Symlink traversal protection and blacklist secret filtering.
- Read-only Git inspection using `execFile` with argument arrays and `shell: false` (`packages/git`).
- Structured error handling (`packages/protocol`).
- Unit tests and mandatory security negative control tests (`tests/`).

### 1.3. Explicitly Out of Scope for RC-01 (Strictly Forbidden)

- Terminal command execution (`run_command`).
- File creation or modification (`write_file`, `create_file`, `apply_patch`).
- Network listeners, remote HTTP gateways, or open TCP ports.
- Device enrollment or complex remote token lifecycles (local stdio execution only).
- Public deployment or cloud integrations.
- Mutating Git operations (`git commit`, `git push`, `git checkout -b`, etc.).

---

## 2. Tools Implemented in RC-01

| Tool Name            | Capability                                | Input Constraints                                                | Security Controls                                      |
| :------------------- | :---------------------------------------- | :--------------------------------------------------------------- | :----------------------------------------------------- |
| **`health`**         | Check server readiness and active stage.  | None (`{}`).                                                     | Non-sensitive static status response (`RC-01`).        |
| **`list_directory`** | List entries within authorized workspace. | `path` (string), `recursive` (bool), `maxDepth` (1..5).          | Canonical path check, hides blacklisted files.         |
| **`read_file`**      | Read file content within workspace.       | `path` (string), `offset` (int), `length` (int <= 1MB).          | Canonical path check, blacklist filter, max 1MB limit. |
| **`search_files`**   | Find files by glob/regex pattern.         | `pattern` (string), `subPath` (optional), `maxResults` (<= 200). | Traversal bounded to approved root.                    |
| **`search_text`**    | Search text in workspace files.           | `query` (string), `isRegex` (bool), `maxMatches` (<= 200).       | ReDoS protection, skips binary & blacklisted files.    |
| **`git_status`**     | Working tree branch and dirty state.      | `workspaceRoot` (optional).                                      | Verified Git root, parameter injection guard.          |
| **`git_diff`**       | Working tree or commit diff.              | `target` (string), `path` (string), `cached` (bool).             | Max diff size limit (512KB), secret masking.           |
| **`git_log`**        | Recent commit history.                    | `maxCount` (<= 100), `revision` (string).                        | Revision argument sanitization (rejects `--`).         |
| **`system_status`**  | Host VM CPU/memory/disk stats.            | None (`{}`).                                                     | Host metrics sanitized; no hostnames/private IPs.      |

---

## 3. Security Controls & Guarantees

### 3.1. Filesystem Guarantees

- **Syntactic Normalization:** Rejects null bytes (`\0`) with `INVALID_PATH_CHARS` and raw URL traversal tokens.
- **Canonical Root Resolution:** Uses `fs.realpathSync` to canonicalize both workspace root and candidate targets.
- **Prefix Enclosure Check:** Asserts target resides strictly under `canonicalWorkspaceRoot + path.sep`. Traversal escapes (`../../../../etc/passwd`) and external symlink escapes throw `PATH_ESCAPES_ROOT`.
- **Sensitive Path Blacklist:** Permanently denies access to `.env`, `.env.*`, `.ssh/**`, `.aws/**`, `.gnupg/**`, `.kube/**`, `.git/config`, `.git/hooks/**`, private keys (`id_rsa*`, `id_ed25519*`, `*.pem`, `*.key`), and host system paths (`/etc/**`, `/proc/**`, `/sys/**`) with `ACCESS_DENIED`.

### 3.2. Residual TOCTOU & Hardlink Risk (Honest Disclosure)

- **Userspace Baseline:** RC-01 implements the Tier 1 Userspace Canonicalization baseline via Node.js `fs.realpathSync` and prefix checks.
- **Residual TOCTOU Risk:** Because native Linux `openat2` with `RESOLVE_BENEATH` requires native C/Rust bindings (scheduled for future hardening), a theoretical time-of-check to time-of-use race exists if an attacker can concurrently rename an ancestor directory during path resolution.
- **Hardlink Aliasing Risk:** Hardlinks created inside the workspace pointing to external files share the underlying inode. While inode link counts are inspected (`stat.nlink > 1`), complete mitigation requires sandbox mount-level isolation (Tier 3).

### 3.3. Git Safety & Parameter Injection Prevention

- Subprocess invocation strictly uses `execFile('git', args, { shell: false })`.
- Parameters (`revision`, `target`, `path`) cannot begin with `-` or `--` (preventing argument injection such as `--output=/tmp/pwned`).
- Output limits: `git_diff` buffer capped at 512 KiB; `git_log` capped at 100 commits.
- All mutating commands (`commit`, `push`, `pull`, `checkout`, `reset`, `clean`) are strictly absent.

### 3.4. Audit Behavior

- Emits structured `AuditRecord` for both `ALLOW` and `DENY` invocations.
- Data minimization: file contents are omitted (`[FILE_CONTENT_OMITTED]`), credentials masked (`[REDACTED_SECRET]`, `[REDACTED_BY_NAME]`).
- Sequential SHA-256 hash chaining links consecutive audit events to detect log truncation or modification.

---

## 4. Mandatory Security Negative Control Results

| #   | Test Scenario              | Input / Attack Vector                                          | Expected Outcome                                                  | Status   |
| --- | -------------------------- | -------------------------------------------------------------- | ----------------------------------------------------------------- | -------- |
| 1   | Path Traversal             | `read_file path: "../../../../etc/passwd"`                     | `PATH_ESCAPES_ROOT`                                               | **PASS** |
| 2   | Symlink Escape             | Symlink in workspace pointing to external target               | `PATH_ESCAPES_ROOT`                                               | **PASS** |
| 3   | Secret Blacklist           | `read_file path: ".env"`                                       | `ACCESS_DENIED`                                                   | **PASS** |
| 4   | SSH Key Access             | `read_file path: ".ssh/id_rsa"`                                | `ACCESS_DENIED`                                                   | **PASS** |
| 5   | Unapproved Workspace       | Target path in unapproved absolute directory                   | Rejected (`POLICY_DENIED` / `PATH_ESCAPES_ROOT`)                  | **PASS** |
| 6   | Payload Size Limit         | `read_file length: 52428800` (50 MB)                           | `PAYLOAD_TOO_LARGE`                                               | **PASS** |
| 7   | Mutating Command           | Call `run_command`                                             | `POLICY_DENIED`                                                   | **PASS** |
| 8   | Unregistered Tool          | Call `unknown_backdoor_tool`                                   | `POLICY_DENIED`                                                   | **PASS** |
| 9   | Git Argument Injection     | `git_log revision: "--output=/tmp/pwned"`                      | `INVALID_REQUEST_SCHEMA`                                          | **PASS** |
| 10  | Negative Read Bounds       | `read_file offset: -10, length: -5`                            | `INVALID_REQUEST_SCHEMA`                                          | **PASS** |
| 11  | Directory Max Depth        | `list_directory maxDepth: 10` (> 5)                            | `INVALID_REQUEST_SCHEMA`                                          | **PASS** |
| 12  | Search Blacklist Traversal | `search_files pattern: "*.env*"` / `search_text query: secret` | Zero blacklisted entries returned                                 | **PASS** |
| 13  | Denied Audit Evidence      | Invoke denied `run_command`                                    | Emits `AuditRecord` with `status: DENIED`                         | **PASS** |
| 14  | Allowed Audit Evidence     | Invoke allowed `health`                                        | Emits `AuditRecord` with `status: SUCCESS`                        | **PASS** |
| 15  | Repository Immutability    | Run all 9 tools against fixture repo                           | Zero git commits / zero file changes                              | **PASS** |
| 16  | Malformed Schema           | Missing required parameters / null bytes                       | Fails closed with `INVALID_REQUEST_SCHEMA` / `INVALID_PATH_CHARS` | **PASS** |

---

## 5. Local Running & Testing Instructions

### Run Verification Suite

```bash
# Execute complete RC-01 verification suite (9 quality gates)
bash scripts/verify-rc01.sh
```

### Run Tests Directly

```bash
# Run contract and negative security tests
pnpm run test
```

### Start MCP Server (Local Stdio)

```bash
# Run MCP server using active workspace
node apps/mcp-server/dist/index.js

# Or specify custom workspace via environment variable
CESSPACE_WORKSPACE=/path/to/my/repo node apps/mcp-server/dist/index.js
```

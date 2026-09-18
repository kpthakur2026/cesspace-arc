# RC-03 Scope & Acceptance Criteria — CesSpace ARC

> **Document:** Stage Specification & Quality Gates  
> **Status:** RC-03 Scope Frozen — Implementation Not Started  
> **Target Stage:** `RC-03` — Safe File Modification  
> **Base:** `main` (Verified RC-02 Main Merge at `f9560abdca5b122cf29388561a8c6b240cdc871a`)

---

## 1. Stage Objective & Governance

The objective of **RC-03** is to introduce safe, policy-governed file modification capabilities into CesSpace ARC. Building upon the verified read-only inspection baseline (RC-01) and controlled terminal execution (RC-02), RC-03 introduces five discrete mutation tools:

1. `create_file`: Create a new file within an authorized workspace root (target must not exist).
2. `write_file`: Overwrite an existing file with complete content (requires exact `expectedHash` precondition).
3. `apply_patch`: Apply a bounded unified diff patch to existing files using a preflight-all, commit-with-rollback model.
4. `delete_file`: Delete a single authorized regular file (target must exist and match `expectedHash`; no directory deletion).
5. `move_file`: Move or rename a file within authorized workspace roots (destination must not exist; requires `expectedSourceHash`).

### 1.1. Core Invariants Maintained

Every file mutation operation in RC-03 must pass through the **Minimal Security Kernel** and satisfy the following non-negotiable security invariants:

1. **Strict Default-Deny & Policy Classification:** All five mutation tools are classified under `REQUIRE APPROVAL` in the policy engine.
2. **Approval Boundary Architecture & No Bypass:** RC-03 defines the mutation tools and implements the underlying mutation engine, validation pipelines, and subsystem interfaces (`IFilesystemSubsystem`). In RC-03, there is **NO** approval-token redemption path or elevation mechanism; the complete interactive human approval state machine and approval token lifecycle are owned strictly by **RC-04**. Therefore, direct MCP tool invocations for mutation tools remain **permanently fail-closed / non-executable** in RC-03 with `REQUIRE_APPROVAL` or `POLICY_DENIED`. No fake token, temporary bypass, environment flag, test backdoor, or unconditional `ALLOW` may be introduced. Subsystem unit and integration tests exercise bounded mutation primitives directly through the `IFilesystemSubsystem` driver interface.
3. **Permanent Denial of All Git Internal Metadata Mutation:** RC-03 mutation APIs may modify working-tree files, but **NEVER** Git metadata. Every RC-03 mutation tool permanently denies any operation targeting `.git/**`. This includes at minimum:
   - `.git/HEAD`
   - `.git/index`
   - `.git/config`
   - `.git/hooks/**`
   - `.git/refs/**`
   - `.git/logs/**`
   - `.git/objects/**`
   - `.git/worktrees/**`
   - `.git/modules/**`
     File mutation must never serve as a filesystem-level bypass around Git repository governance or object integrity.
4. **No Shell Execution or External Binary Delegation:** File mutations and patch applications are implemented strictly in native Node.js / POSIX filesystem calls. Invoking host binaries (such as `patch`, `git apply`, `rm`, `mv`, `cp`, `touch`, `sed`, `awk`, or shell subshells) is strictly forbidden.
5. **Jailed Canonical Path Resolution & Length Constraints:** Every target path (source, destination, and patch targets) must undergo canonical normalization, symlink resolution, and prefix-enclosure verification against the authorized workspace root before any file descriptor is opened. Maximum input path length is strictly **1024 characters** (matching the ARC protocol schema). Operating system limits (255 bytes per segment, 4096 bytes host path) act as additional constraints. Any attempt to traverse (`../`), escape via symlink, or access outside the workspace fails closed immediately with `PATH_ESCAPES_ROOT`.
6. **Hardlink Aliasing Defense:** Filesystem operations must verify inode link counts (`stat.nlink > 1`). Mutating a file with multiple hardlinks is rejected immediately with `HARDLINK_DETECTED` to prevent modifying external files aliased into the workspace via hardlinks.
7. **Strict Symlink Immutability:** To prevent symlink confusion, TOCTOU redirection, and arbitrary target overwrites:
   - `create_file`, `write_file`, and `apply_patch` never follow or replace symbolic links. If target or any intermediate path is a symlink, the operation fails with `UNSAFE_SYMLINK` or `PATH_ESCAPES_ROOT`.
   - `move_file` requires the source to be a regular file; symbolic-link sources are denied with `UNSAFE_SYMLINK`.
   - `delete_file` in RC-03 rejects symbolic link targets with `UNSAFE_SYMLINK` (only regular files may be deleted).
8. **Deterministic Mandatory Preconditions (Lost-Update Defense):** Preconditions are mandatory across all mutation operations to prevent silent lost updates:
   - `write_file`: Caller must provide `expectedHash` (64-character SHA-256 hex string). Current on-disk content SHA-256 must match exactly; otherwise fails with `CONFLICT_PRECONDITION_FAILED`.
   - `delete_file`: Caller must provide `expectedHash`. Current on-disk content SHA-256 must match; otherwise fails with `CONFLICT_PRECONDITION_FAILED`.
   - `move_file`: Caller must provide `expectedSourceHash`. Current on-disk source file SHA-256 must match; otherwise fails with `CONFLICT_PRECONDITION_FAILED`.
   - `create_file`: Precondition is target **MUST NOT EXIST**. If target exists, fails with `ALREADY_EXISTS`.
   - `apply_patch`: Preflight captures content hashes of all targets. Immediately prior to each file commit, the implementation verifies the target has not changed since preflight; if changed, commits halt and rollback is invoked.
   - _TOCTOU Acknowledgment:_ Userspace check-then-act sequences have inherent race windows unless commit-time filesystem semantics enforce preconditions. The implementation must use commit-time no-replace and exclusive primitives to minimize race exposure.
9. **No-Replace Primitives for Creation and Movement:**
   - `create_file` must never replace an existing file. It uses an exclusive commit primitive (e.g. `O_CREAT | O_EXCL` via `wx` flag or native link-based commit) so the final commit fails at the kernel level if the destination exists.
   - `move_file` destination must not exist. Ordinary `rename()` replaces existing destinations in POSIX; therefore, `move_file` must employ a commit-time verification or exclusive atomic primitive (such as `fs.link` which fails with `EEXIST` if destination exists, followed by `fs.unlink` of source) ensuring that a destination appearing after an initial check is never overwritten.
   - Cross-filesystem moves (`EXDEV`) are strictly rejected with `CROSS_DEVICE_MOVE_UNSUPPORTED`; silent copy-and-delete fallback is forbidden.
10. **File Permission Preservation & Safe Creation Mode:**
    - `write_file` atomic replacement must preserve the original regular file's mode bits (`stat.mode & 0o777`). The replacement file must have its permissions set to match the original file prior to atomic commit.
    - `create_file` must create new files with conservative default permissions (`0o644` masked by process umask) and directories with `0o755` masked by umask. Source files must never be rendered executable or world-writable inadvertently.
11. **Truthful Multi-File Patch Contract:** Multi-file patch application is **not** a single transactional filesystem commit. It is specified truthfully as **preflight-all, commit-with-rollback**. If a failure occurs during commit and deterministic rollback cannot restore previous state, a distinct severe error (`ROLLBACK_FAILED`) is raised and audited.
12. **Permanent Sensitive Path Blacklist:** The immutable blacklist (`.git/**`, `.env*`, `.ssh/`, `.aws/`, `.gnupg/`, `.kube/`, `id_rsa*`, `id_ed25519*`, `/etc/`, `/proc/`, `/sys/`, `/dev/`, `/root/`) applies unconditionally to all mutation targets.
13. **Resource Bounds & Payload Limits:**
    - Maximum input path length: 1024 characters.
    - Maximum write content payload: 1 MiB (1,048,576 bytes).
    - Maximum patch size: 512 KiB (524,288 bytes).
    - Maximum changed files per patch: 10 files.
    - Requests exceeding limits fail closed immediately with `PAYLOAD_TOO_LARGE` or `INVALID_REQUEST_SCHEMA`.
14. **Audit Evidence & Data Minimization:** Every file mutation emits a structured audit record (`FILE_CREATED`, `FILE_WRITTEN`, `PATCH_APPLIED`, `FILE_DELETED`, `FILE_MOVED`) with cryptographic SHA-256 hash chaining. Raw file content and patch text are **strictly omitted** from audit log events and error messages. Only metadata is recorded: canonical relative paths, byte counts, pre-operation SHA-256 hashes, post-operation SHA-256 hashes, and operation status.

### 1.2. Scope Freeze Declaration

> **RC-03 STATUS: SCOPE FROZEN / IMPLEMENTATION NOT STARTED**  
> Task 0 / Task 0.1 freezes the architecture, API contracts, security invariants, error taxonomy, and acceptance criteria. Zero runtime mutation code in `apps/` or `packages/` is introduced. Implementation begins only after this specification commit is pushed and independently reviewed.

---

## 2. Canonical Mutation Tool Specifications

### 2.1. `create_file`

Creates a new file at the specified workspace-relative path. Target **MUST NOT** exist.

- **Input Schema:**
  ```json
  {
    "path": "string (required, relative path within workspace, max 1024 chars)",
    "content": "string (required, UTF-8 file content, max 1 MiB)"
  }
  ```
- **Output Schema:**
  ```json
  {
    "path": "string (canonical relative path)",
    "bytesWritten": 1024,
    "contentHash": "sha256-hex-digest",
    "created": true
  }
  ```
- **Operational Semantics:**
  1. Validates path length <= 1024 characters; checks for null bytes and URL encoding.
  2. Verifies path does not target `.git/**` or any blacklisted pattern (`ACCESS_DENIED`).
  3. Resolves canonical parent directory; verifies parent is enclosed within workspace root (`PATH_ESCAPES_ROOT`).
  4. If parent directory does not exist, creates missing directories within workspace with `0o755` mode.
  5. Target must not exist. If target exists, fails immediately with `ALREADY_EXISTS`. `create_file` has **no** overwrite parameter.
  6. Writes file content to a sibling temporary file in the same directory (`.arc-tmp-{uuid}`) with `0o644` mode (masked by umask) and calls `fsync`.
  7. Commits via a kernel-level no-replace primitive (e.g. `fs.link(tmp, target)` which fails with `EEXIST` if target exists, followed by unlinking the temporary sibling file). If target appears concurrently, commit fails with `ALREADY_EXISTS`.
  8. Emits `FILE_CREATED` audit event (metadata only, raw content omitted).

### 2.2. `write_file`

Overwrites an existing file with complete content. Target **MUST** already exist and match `expectedHash`.

- **Input Schema:**
  ```json
  {
    "path": "string (required, relative path within workspace, max 1024 chars)",
    "content": "string (required, UTF-8 file content, max 1 MiB)",
    "expectedHash": "string (required, 64-character SHA-256 hex digest of current file)",
    "overwrite": "boolean (required, must be true to confirm overwrite intent)"
  }
  ```
- **Output Schema:**
  ```json
  {
    "path": "string (canonical relative path)",
    "bytesWritten": 2048,
    "contentHash": "sha256-hex-digest-of-new-content",
    "previousHash": "sha256-hex-digest-of-previous-content"
  }
  ```
- **Operational Semantics:**
  1. Validates path length <= 1024 characters; verifies path does not target `.git/**` or blacklist (`ACCESS_DENIED`).
  2. If `overwrite !== true`, rejects with `INVALID_REQUEST_SCHEMA`.
  3. Validates `expectedHash` format (64-character hex string); if missing or invalid, rejects with `INVALID_REQUEST_SCHEMA`.
  4. Resolves canonical path within workspace root. Target must exist; if missing, rejects with `FILE_NOT_FOUND` (`write_file` never creates new files).
  5. Inspects file type using `lstat`. If target is a directory (`IS_A_DIRECTORY`), symlink (`UNSAFE_SYMLINK`), or special file (`NOT_A_FILE`), rejects immediately.
  6. Inspects hardlink count (`stat.nlink > 1`); fails with `HARDLINK_DETECTED` if aliased.
  7. Reads current file content and computes SHA-256. If hash !== `expectedHash`, rejects with `CONFLICT_PRECONDITION_FAILED`.
  8. Captures existing file mode bits (`stat.mode & 0o777`).
  9. Writes new content to sibling temporary file (`.arc-tmp-{uuid}`), applies original file permissions (`fchmod`), and calls `fsync`.
  10. Atomically replaces target via `fs.rename`.
  11. Emits `FILE_WRITTEN` audit event with old and new hashes; raw content is redacted.

### 2.3. `apply_patch`

Applies a bounded unified diff patch to existing workspace files using a **preflight-all, commit-with-rollback** model.

- **Input Schema:**
  ```json
  {
    "patch": "string (required, unified diff formatted string, max 512 KiB)",
    "dryRun": "boolean (optional, default false)",
    "fuzz": "integer (optional, default 0, max 0 — zero-fuzz required)"
  }
  ```
- **Output Schema:**
  ```json
  {
    "success": true,
    "modifiedFiles": ["src/index.ts", "src/utils.ts"],
    "stats": {
      "filesChanged": 2,
      "insertions": 15,
      "deletions": 4
    },
    "dryRun": false
  }
  ```
- **Operational Semantics & Strict Restrictions:**
  1. **Allowed Operations:** Modifies **ONLY existing regular text files**.
  2. **Forbidden Patch Directives:** The unified diff parser strictly rejects patches that attempt to:
     - Create new files (`PATCH_UNSUPPORTED_OPERATION`).
     - Delete existing files (`PATCH_UNSUPPORTED_OPERATION`).
     - Rename or move files (`PATCH_UNSUPPORTED_OPERATION`).
     - Change file permission modes / executable bits (`PATCH_UNSUPPORTED_OPERATION`).
     - Target or traverse symbolic links (`UNSAFE_SYMLINK` / `PATCH_UNSUPPORTED_OPERATION`).
     - Target `.git/**` or blacklisted paths (`ACCESS_DENIED`).
  3. **Input Bounds:** Rejects patch if length > 512 KiB, if targets > 10 files (`PAYLOAD_TOO_LARGE`), or if `fuzz > 0` (`INVALID_REQUEST_SCHEMA`).
  4. **Phase 1: Parse & Preflight (Zero Disk Mutation):**
     - Parses unified diff into structured file hunks in-memory.
     - Resolves canonical path for each target file; verifies each resides in workspace root, is not blacklisted, is a regular file (`stat.isFile()`), not a symlink, and has `stat.nlink === 1`.
     - Reads existing content and records `preflightHash` (SHA-256) and original permissions for every target file.
     - Simulates applying hunks in-memory with zero fuzz.
     - If any hunk fails to match context lines exactly, or if any target is missing, the entire operation fails with `PATCH_PREFLIGHT_FAILED`. Zero disk changes occur.
  5. If `dryRun === true`, returns preflight success and stats without writing to disk.
  6. **Phase 2: Staging Sibling Replacement Files:**
     - For each target file, writes modified buffer to sibling temp file (`.arc-tmp-{uuid}`) in the same directory, applies original permissions (`fchmod`), and `fsync`s.
  7. **Phase 3: Pre-Commit Revalidation & Individual Commit:**
     - Immediately before committing each file, verifies current on-disk SHA-256 still matches `preflightHash`. If any file changed concurrently, halts commit immediately and initiates rollback.
     - Atomically commits files one by one via `fs.rename`.
  8. **Phase 4: Deterministic Rollback on Failure:**
     - If an error occurs during commit of file `N`, the engine attempts to restore files `1` through `N-1` to their preflight content.
     - If rollback fails for any reason, raises `ROLLBACK_FAILED` with detailed metadata indicating which files require administrative recovery.
  9. Emits `PATCH_APPLIED` audit event (metadata only; patch text and file contents omitted).

### 2.4. `delete_file`

Deletes a single authorized regular file within the workspace root. Target **MUST** exist and match `expectedHash`.

- **Input Schema:**
  ```json
  {
    "path": "string (required, relative path within workspace, max 1024 chars)",
    "expectedHash": "string (required, 64-character SHA-256 hex digest)"
  }
  ```
- **Output Schema:**
  ```json
  {
    "path": "string (canonical relative path)",
    "deleted": true,
    "contentHash": "sha256-hex-digest-of-deleted-content"
  }
  ```
- **Operational Semantics:**
  1. Validates path length <= 1024 characters; verifies path does not target `.git/**` or blacklist (`ACCESS_DENIED`).
  2. Validates `expectedHash` format (64-character hex string); if missing or invalid, rejects with `INVALID_REQUEST_SCHEMA`.
  3. Resolves canonical path within workspace root. Target must exist; if missing, rejects with `FILE_NOT_FOUND`.
  4. Inspects target using `lstat`. If target is a directory, rejects with `IS_A_DIRECTORY`. **Recursive directory deletion is strictly forbidden.**
  5. If target is a symbolic link, rejects with `UNSAFE_SYMLINK`.
  6. Inspects hardlink count (`stat.nlink > 1`); fails with `HARDLINK_DETECTED` if aliased.
  7. Reads file content and computes SHA-256. If hash !== `expectedHash`, rejects with `CONFLICT_PRECONDITION_FAILED`.
  8. Unlinks file via `fs.unlinkSync` / `fs.promises.unlink`.
  9. Emits `FILE_DELETED` audit event with `contentHash`.

### 2.5. `move_file`

Moves or renames a file within authorized workspace roots. Destination **MUST NOT** exist; source **MUST** match `expectedSourceHash`.

- **Input Schema:**
  ```json
  {
    "sourcePath": "string (required, relative path within workspace, max 1024 chars)",
    "destinationPath": "string (required, relative path within workspace, max 1024 chars)",
    "expectedSourceHash": "string (required, 64-character SHA-256 hex digest of source)"
  }
  ```
- **Output Schema:**
  ```json
  {
    "sourcePath": "string (canonical relative path)",
    "destinationPath": "string (canonical relative path)",
    "moved": true
  }
  ```
- **Operational Semantics:**
  1. Validates path lengths <= 1024 characters; checks for null bytes and URL encoding.
  2. Verifies neither `sourcePath` nor `destinationPath` targets `.git/**` or blacklist (`ACCESS_DENIED`).
  3. Resolves canonical path for `sourcePath` (must exist; otherwise `FILE_NOT_FOUND`).
  4. Inspects source using `lstat`. Source must be a regular file; if directory (`IS_A_DIRECTORY`) or symlink (`UNSAFE_SYMLINK`), rejects immediately.
  5. Inspects source hardlink count (`stat.nlink > 1`); fails with `HARDLINK_DETECTED`.
  6. Validates `expectedSourceHash` format. Computes current source SHA-256; if mismatched, rejects with `CONFLICT_PRECONDITION_FAILED`.
  7. Resolves destination canonical parent directory; verifies parent is inside workspace root (`PATH_ESCAPES_ROOT`).
  8. If destination already exists, rejects with `ALREADY_EXISTS`. `move_file` has **no** overwrite parameter in RC-03.
  9. **No-Replace & Cross-Device Commit:**
     - Cross-device movement is rejected with `CROSS_DEVICE_MOVE_UNSUPPORTED` (no silent copy-delete fallback).
     - To guarantee no replacement at commit time, uses an exclusive linking primitive (e.g. `fs.link(source, dest)` which fails if destination exists, followed by `fs.unlink(source)`).
  10. Emits `FILE_MOVED` audit event (metadata only).

---

## 3. Security Boundary & Threat Mitigations

| Threat Vector                        | Mitigation Strategy in RC-03                                                                        | Fail-Closed Mechanism                        |
| :----------------------------------- | :-------------------------------------------------------------------------------------------------- | :------------------------------------------- |
| **Git Metadata Tampering**           | Permanent denial of `.git/**` for all mutation operations (`HEAD`, `refs`, `index`, `hooks`, etc.). | `ACCESS_DENIED`                              |
| **Silent Lost Updates**              | Mandatory `expectedHash` on `write_file`/`delete_file` and `expectedSourceHash` on `move_file`.     | `CONFLICT_PRECONDITION_FAILED`               |
| **Accidental Overwrites**            | `create_file` and `move_file` strictly require destination to not exist; no `overwrite` flag.       | `ALREADY_EXISTS`                             |
| **Create/Move Replace Races**        | Commit-time exclusive/no-replace primitives (e.g. `O_EXCL` / `fs.link` semantics).                  | `ALREADY_EXISTS`                             |
| **Cross-Device Move Corruption**     | Cross-filesystem `move_file` fails closed deterministically; no copy+delete fallback.               | `CROSS_DEVICE_MOVE_UNSUPPORTED`              |
| **Multi-File Patch Partial State**   | Preflight-all, commit-with-rollback model; rollback failure explicitly surfaced and audited.        | `PATCH_PREFLIGHT_FAILED` / `ROLLBACK_FAILED` |
| **Patch Scope Smuggling**            | Directives creating, deleting, renaming files, changing modes, or targeting symlinks are denied.    | `PATCH_UNSUPPORTED_OPERATION`                |
| **File Permission Drift**            | `write_file` preserves original regular file mode (`0o777`); `create_file` uses `0o644` with umask. | Explicit mode propagation                    |
| **Symlink Redirection / Traversal**  | Symlink targets permanently denied for create/write/patch/move/delete.                              | `UNSAFE_SYMLINK` / `PATH_ESCAPES_ROOT`       |
| **Hardlink Inode Aliasing**          | `stat.nlink > 1` checked on all candidate targets; rejected before mutation.                        | `HARDLINK_DETECTED`                          |
| **Path Traversal (`../`, `%2e%2e`)** | Canonical realpath resolution, normalization, 1024-char limit, prefix enclosure.                    | `PATH_ESCAPES_ROOT` / `INVALID_PATH_CHARS`   |
| **Directory Destruction**            | `delete_file` restricted strictly to regular files; directory deletion permanently blocked.         | `IS_A_DIRECTORY`                             |
| **Secret Leakage in Audit Trail**    | Raw file contents and diff text strictly omitted from audit logs and errors; only hashes logged.    | Data minimization by design                  |
| **Unauthorized Execution**           | All mutation tools classified `REQUIRE APPROVAL`; direct MCP invocation fails closed.               | `REQUIRE_APPROVAL`                           |

---

## 4. Error Taxonomy for RC-03

The following structured error codes extend `@cesspace-arc/protocol` for RC-03:

| Error Code                      | HTTP-Equivalent          | Description                                                                                      |
| :------------------------------ | :----------------------- | :----------------------------------------------------------------------------------------------- |
| `CONFLICT_PRECONDITION_FAILED`  | 412 Precondition Failed  | Current file SHA-256 does not match caller's `expectedHash` or `expectedSourceHash`.             |
| `ALREADY_EXISTS`                | 409 Conflict             | Target destination file already exists (for `create_file` or `move_file`).                       |
| `FILE_NOT_FOUND`                | 404 Not Found            | Target file to write, delete, or move does not exist.                                            |
| `IS_A_DIRECTORY`                | 400 Bad Request          | Target path is a directory where a regular file was required.                                    |
| `NOT_A_FILE`                    | 400 Bad Request          | Target is a special filesystem node (socket, FIFO, device) rather than a regular file.           |
| `HARDLINK_DETECTED`             | 403 Forbidden            | Target file has link count > 1, preventing external hardlink aliasing mutation.                  |
| `UNSAFE_SYMLINK`                | 403 Forbidden            | Target is or traverses a symbolic link, which is forbidden for mutation in RC-03.                |
| `PATCH_PARSE_ERROR`             | 400 Bad Request          | Patch syntax is invalid or not recognized as standard unified diff.                              |
| `PATCH_PREFLIGHT_FAILED`        | 422 Unprocessable Entity | Patch cannot apply cleanly (hunk context mismatch, missing file, or out-of-bounds path).         |
| `PATCH_UNSUPPORTED_OPERATION`   | 400 Bad Request          | Patch contains forbidden directives (file creation, deletion, rename, mode change, symlink).     |
| `CROSS_DEVICE_MOVE_UNSUPPORTED` | 400 Bad Request          | `move_file` spans distinct filesystems/mountpoints; copy+delete fallback is disallowed.          |
| `ROLLBACK_FAILED`               | 500 Internal Error       | Multi-file patch commit failed and rollback could not restore prior file state.                  |
| `PATH_ESCAPES_ROOT`             | 403 Forbidden            | Target path attempts to escape the authorized workspace root boundary.                           |
| `ACCESS_DENIED`                 | 403 Forbidden            | Target path targets `.git/**` or matches sensitive blacklist patterns.                           |
| `PAYLOAD_TOO_LARGE`             | 413 Payload Too Large    | Content exceeds 1 MiB or patch exceeds 512 KiB / 10 files.                                       |
| `INVALID_REQUEST_SCHEMA`        | 400 Bad Request          | Request arguments fail schema validation (missing required fields, path > 1024 chars, fuzz > 0). |
| `REQUIRE_APPROVAL`              | 403 Forbidden            | MCP invocation requires human approval token (RC-04 boundary).                                   |

---

## 5. Acceptance Verification Plan

When RC-03 implementation begins, acceptance verification must prove both negative and positive controls:

### 5.1. Mandatory Negative Controls

- [ ] Attempting `write_file` on `.git/HEAD` fails with `ACCESS_DENIED`.
- [ ] Attempting `write_file` on `.git/refs/heads/main` fails with `ACCESS_DENIED`.
- [ ] Attempting `create_file` under `.git/` fails with `ACCESS_DENIED`.
- [ ] Attempting `delete_file` under `.git/` fails with `ACCESS_DENIED`.
- [ ] Attempting `move_file` into `.git/` fails with `ACCESS_DENIED`.
- [ ] Attempting `move_file` out of `.git/` fails with `ACCESS_DENIED`.
- [ ] Attempting `apply_patch` targeting `.git/` files fails with `ACCESS_DENIED`.
- [ ] Attempting `write_file` without `expectedHash` fails with `INVALID_REQUEST_SCHEMA`.
- [ ] Attempting `write_file` with mismatched `expectedHash` fails with `CONFLICT_PRECONDITION_FAILED`.
- [ ] Attempting `write_file` with `overwrite: false` or omitted fails with `INVALID_REQUEST_SCHEMA`.
- [ ] Attempting `write_file` on non-existent file fails with `FILE_NOT_FOUND`.
- [ ] Attempting `create_file` on existing path fails with `ALREADY_EXISTS` (never overwrites).
- [ ] Concurrent creation race fails safely with `ALREADY_EXISTS` at commit time.
- [ ] Attempting `delete_file` without `expectedHash` fails with `INVALID_REQUEST_SCHEMA`.
- [ ] Attempting `delete_file` with mismatched `expectedHash` fails with `CONFLICT_PRECONDITION_FAILED`.
- [ ] Attempting `delete_file` on a directory fails with `IS_A_DIRECTORY`.
- [ ] Attempting `delete_file` on a symlink fails with `UNSAFE_SYMLINK`.
- [ ] Attempting `move_file` without `expectedSourceHash` fails with `INVALID_REQUEST_SCHEMA`.
- [ ] Attempting `move_file` with mismatched `expectedSourceHash` fails with `CONFLICT_PRECONDITION_FAILED`.
- [ ] Attempting `move_file` onto an existing destination path fails with `ALREADY_EXISTS`.
- [ ] Attempting `move_file` across distinct filesystem mount points fails with `CROSS_DEVICE_MOVE_UNSUPPORTED`.
- [ ] Attempting mutation on file with `stat.nlink > 1` fails with `HARDLINK_DETECTED`.
- [ ] Attempting `create_file`, `write_file`, or `apply_patch` on symlink target fails with `UNSAFE_SYMLINK`.
- [ ] Attempting `move_file` with symlink source fails with `UNSAFE_SYMLINK`.
- [ ] Attempting mutation on blacklisted paths (`.env`, `.ssh/id_rsa`, `/etc/passwd`) fails with `ACCESS_DENIED`.
- [ ] Attempting path traversal (`../../etc/passwd`, symlink escaping root) fails with `PATH_ESCAPES_ROOT`.
- [ ] Attempting input path exceeding 1024 characters fails with `INVALID_REQUEST_SCHEMA`.
- [ ] Attempting `apply_patch` with invalid unified diff fails with `PATCH_PARSE_ERROR`.
- [ ] Attempting `apply_patch` containing file creation directives fails with `PATCH_UNSUPPORTED_OPERATION`.
- [ ] Attempting `apply_patch` containing file deletion directives fails with `PATCH_UNSUPPORTED_OPERATION`.
- [ ] Attempting `apply_patch` containing file rename directives fails with `PATCH_UNSUPPORTED_OPERATION`.
- [ ] Attempting `apply_patch` containing file mode change directives fails with `PATCH_UNSUPPORTED_OPERATION`.
- [ ] Attempting `apply_patch` targeting a symlink fails with `UNSAFE_SYMLINK` / `PATCH_UNSUPPORTED_OPERATION`.
- [ ] Attempting `apply_patch` where any hunk fails context match fails with `PATCH_PREFLIGHT_FAILED` with zero disk changes.
- [ ] Attempting `apply_patch` where target file changes between preflight and commit halts and triggers rollback.
- [ ] Attempting `apply_patch` exceeding 512 KiB or 10 files fails with `PAYLOAD_TOO_LARGE`.
- [ ] Attempting `apply_patch` with `fuzz > 0` fails with `INVALID_REQUEST_SCHEMA`.
- [ ] Simulated rollback failure reports `ROLLBACK_FAILED` with damaged file metadata.
- [ ] Direct invocation of any of the 5 tools through policy engine fails with `REQUIRE_APPROVAL` (default-deny).
- [ ] Audit logs confirm raw file and patch contents are completely redacted.

### 5.2. Mandatory Positive Controls

- [ ] `create_file` creates a new file and returns correct canonical relative path, byte count, and SHA-256 hash.
- [ ] `create_file` creates required intermediate parent directories within the workspace root with `0o755` mode.
- [ ] `create_file` creates file with conservative mode (`0o644` modified by umask).
- [ ] `write_file` replaces existing file atomically and preserves original regular file mode bits (`stat.mode`).
- [ ] `write_file` with matching `expectedHash` succeeds cleanly and returns previous and new SHA-256 hashes.
- [ ] `apply_patch` with valid single-file diff applies cleanly to existing regular file and returns diff stats.
- [ ] `apply_patch` with valid multi-file diff applies all changes across multiple existing files using preflight-all, commit-with-rollback.
- [ ] `apply_patch` with `dryRun: true` returns success and stats without writing to disk.
- [ ] `delete_file` unlinks target file and returns deleted file SHA-256 hash.
- [ ] `delete_file` with matching `expectedHash` deletes successfully.
- [ ] `move_file` with matching `expectedSourceHash` atomically moves file to new path and verifies old path no longer exists.
- [ ] All mutations emit valid structured audit log events with SHA-256 chaining and zero payload leakage.

---

## 6. Non-Goals & Deferrals

- **Interactive Human Approval State Machine:** Explicitly deferred to RC-04. RC-03 enforces `REQUIRE APPROVAL` in the policy engine and tests subsystem drivers directly.
- **File Watching & Subscriptions:** File change notifications (`workspace/didChangeWatchedFiles`) are deferred to post-RC-04.
- **Multi-Workspace Cross-Linking:** Moving files across different workspace roots is strictly forbidden; `move_file` operates strictly within the active workspace.
- **Recursive Directory Deletion:** Deletion of directory hierarchies (`rm -rf`) is permanently prohibited in CesSpace ARC.

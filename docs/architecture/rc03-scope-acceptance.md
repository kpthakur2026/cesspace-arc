# RC-03 Scope & Acceptance Criteria — CesSpace ARC

> **Document:** Stage Specification & Quality Gates
> **Status:** RC-03 Implementation Complete — MCP / Policy / Audit Integration Done (Task 3)
> **Target Stage:** `RC-03` — Safe File Modification
> **Base:** `main` (Verified RC-02 Main Merge at `f9560abdca5b122cf29388561a8c6b240cdc871a`)

---

## 1. Stage Objective & Governance

The objective of **RC-03** is to introduce safe, policy-governed file modification capabilities into CesSpace ARC. Building upon the verified read-only inspection baseline (RC-01) and controlled terminal execution (RC-02), RC-03 introduces five discrete mutation tools:

1. `create_file`: Create a new file within an authorized workspace root (target must not exist; parent directory must already exist).
2. `write_file`: Overwrite an existing file with complete content (requires exact `expectedHash` precondition).
3. `apply_patch`: Apply a bounded unified diff patch to existing files using a preflight-all, commit-with-rollback model with safe rollback revalidation.
4. `delete_file`: Delete a single authorized regular file (target must exist and match `expectedHash`; no directory deletion).
5. `move_file`: Execute a no-replace move with rollback within authorized workspace roots (destination must not exist; requires `expectedSourceHash`).

### 1.1. Core Invariants Maintained

Every file mutation operation in RC-03 must pass through the **Minimal Security Kernel** and satisfy the following non-negotiable security invariants:

1. **Strict Default-Deny & Policy Classification:** All five mutation tools are classified under `REQUIRE APPROVAL` in the policy engine.
2. **Approval Boundary Architecture & No Bypass:** RC-03 defines the mutation tools and implements the underlying mutation engine, validation pipelines, and subsystem interfaces (`IFilesystemSubsystem`). In RC-03, there is **NO** approval-token redemption path or elevation mechanism; the complete interactive human approval state machine and approval token lifecycle are owned strictly by **RC-04**. Therefore, direct MCP tool invocations for mutation tools remain **permanently fail-closed / non-executable** in RC-03 with `APPROVAL_REQUIRED` (policy outcome: `REQUIRE_APPROVAL`) or `POLICY_DENIED`. No fake token, temporary bypass, environment flag, test backdoor, or unconditional `ALLOW` may be introduced. Subsystem unit and integration tests exercise bounded mutation primitives directly through the `IFilesystemSubsystem` driver interface.
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
5. **Jailed Canonical Path Resolution & Parent Semantics:** Every target path (source, destination, and patch targets) must undergo canonical normalization, symlink resolution, and prefix-enclosure verification against the authorized workspace root before any file descriptor is opened. Maximum input path length is strictly **1024 characters** (matching the ARC protocol schema). Operating system limits (255 bytes per segment, 4096 bytes host path) act as additional constraints. Any attempt to traverse (`../`), escape via symlink, or access outside the workspace fails closed immediately with `PATH_ESCAPES_ROOT`. For `create_file`, the immediate parent directory must already exist within the workspace root; ARC does **not** automatically create intermediate directories, avoiding unmanaged side-effects and hidden directory creation capabilities. If the parent directory is missing, the operation fails with `PARENT_NOT_FOUND`.
6. **Hardlink Aliasing Defense:** Filesystem operations must verify inode link counts (`stat.nlink > 1`). Mutating a file with multiple hardlinks is rejected immediately with `HARDLINK_DETECTED` to prevent modifying external files aliased into the workspace via hardlinks.
7. **Strict Symlink Immutability:** To prevent symlink confusion, TOCTOU redirection, and arbitrary target overwrites:
   - `create_file`, `write_file`, and `apply_patch` never follow or replace symbolic links. If target or any intermediate path is a symlink, the operation fails with `UNSAFE_SYMLINK` or `PATH_ESCAPES_ROOT`.
   - `move_file` requires the source to be a regular file; symbolic-link sources are denied with `UNSAFE_SYMLINK`.
   - `delete_file` in RC-03 rejects symbolic link targets with `UNSAFE_SYMLINK` (only regular files may be deleted).
8. **Deterministic Mandatory Preconditions & TOCTOU Residual Risk:** Preconditions are mandatory across all mutation operations to prevent silent lost updates under cooperating/normal execution:
   - `write_file`: Caller must provide `expectedHash` (64-character SHA-256 hex string). Current on-disk content SHA-256 must match exactly; otherwise fails with `CONFLICT_PRECONDITION_FAILED`.
   - `delete_file`: Caller must provide `expectedHash`. Current on-disk content SHA-256 must match; otherwise fails with `CONFLICT_PRECONDITION_FAILED`.
   - `move_file`: Caller must provide `expectedSourceHash`. Current on-disk source file SHA-256 must match; otherwise fails with `CONFLICT_PRECONDITION_FAILED`.
   - `create_file`: Precondition is target **MUST NOT EXIST**. If target exists, fails with `ALREADY_EXISTS`.
   - `apply_patch`: Preflight captures content hashes of all targets. Immediately prior to each file commit, the implementation verifies the target has not changed since preflight; if changed, commits halt and rollback is invoked.
   - _Pre-Commit Revalidation:_ Immediately before destructive commit, the implementation revalidates content hash, file type, dev/inode identity (where applicable), and symlink/hardlink conditions. If any value changed, fails with `CONFLICT_PRECONDITION_FAILED`.
   - _Truthful TOCTOU Acknowledgment:_ Standard userspace Node.js path APIs cannot completely eliminate a malicious same-user filesystem race between the final revalidation and the kernel mutation operation. Absolute TOCTOU elimination is not claimed. This residual risk remains explicitly documented until a descriptor-relative / kernel-enforced mutation primitive (`openat2` / `RESOLVE_BENEATH`) is implemented in a later hardening stage.
9. **In-Process Mutation Serialization:** To prevent concurrent ARC callers or concurrent requests within the same process from racing each other:
   - ARC enforces strict in-process serialization for conflicting mutations per workspace and per canonical target path.
   - Multi-file `apply_patch` acquires exclusive in-process locks for all candidate target paths before preflight and retains them through commit or rollback.
   - Lock acquisition order is strictly deterministic (lexicographical sorting by canonical path) to guarantee deadlock freedom.
   - Locks are guaranteed released via `finally` blocks on success or error.
   - _Boundary Note:_ Serialization guarantees coordination between ARC invocations; it does not protect against uncoordinated concurrent processes running outside ARC on the host.
10. **Safe Move Contract (No-Replace Move with Rollback):**
    - `move_file` is specified as a **no-replace move with rollback**, not an atomic operation.
    - Destination must not exist. The implementation creates the destination entry using an exclusive linking operation (`fs.link`), verifies that destination refers to the intended source identity/content, and only then unlinks the source.
    - If unlinking the source fails, the implementation attempts rollback by unlinking the newly-created destination. If rollback fails, `ROLLBACK_FAILED` is reported with recovery metadata.
    - If an OS crash or power loss occurs between link and unlink, both filenames may temporarily point to the same inode. Crash-transactional atomicity is not claimed.
    - Cross-filesystem movement (`EXDEV`) fails deterministically with `CROSS_DEVICE_MOVE_UNSUPPORTED`; silent copy+delete fallback is strictly forbidden.
11. **File Permission Preservation & Safe Creation Mode:**
    - `write_file` atomic replacement must preserve the original regular file's mode bits (`stat.mode & 0o777`). The replacement file must have its permissions set to match the original file prior to atomic commit.
    - `create_file` must create new files with conservative default permissions (`0o644` masked by process umask). Source files must never be rendered executable or world-writable inadvertently.
12. **Truthful Multi-File Patch Contract & Rollback Safety:**
    - Multi-file patch application is specified truthfully as **preflight-all, commit-with-rollback**.
    - When rolling back an already-committed patch target, the engine **does not blindly overwrite** the file. It verifies that the file's current content hash matches what ARC committed. If another actor modified the file in the interim, rollback halts for that file, and `ROLLBACK_FAILED` is raised with audit metadata indicating which files require administrative recovery.
13. **Permanent Sensitive Path Blacklist:** The immutable blacklist (`.git/**`, `.env*`, `.ssh/`, `.aws/`, `.gnupg/`, `.kube/`, `id_rsa*`, `id_ed25519*`, `/etc/`, `/proc/`, `/sys/`, `/dev/`, `/root/`) applies unconditionally to all mutation targets.
14. **Resource Bounds & Payload Limits:**
    - Maximum input path length: 1024 characters.
    - Maximum write content payload: 1 MiB (1,048,576 bytes).
    - Maximum patch size: 512 KiB (524,288 bytes).
    - Maximum changed files per patch: 10 files.
    - Requests exceeding limits fail closed immediately with `PAYLOAD_TOO_LARGE` or `INVALID_REQUEST_SCHEMA`.
15. **Audit Evidence & Data Minimization:** Every file mutation emits a structured audit record (`FILE_CREATED`, `FILE_WRITTEN`, `PATCH_APPLIED`, `FILE_DELETED`, `FILE_MOVED`) with cryptographic SHA-256 hash chaining. Raw file content and patch text are **strictly omitted** from audit log events and error messages. Only metadata is recorded: canonical relative paths, byte counts, pre-operation SHA-256 hashes, post-operation SHA-256 hashes, and operation status.

### 1.2. Scope Freeze Declaration

> **RC-03 STATUS: IMPLEMENTATION COMPLETE**
> Tasks 0–0.2 froze the architecture, API contracts, security invariants, error taxonomy, serialization model, and acceptance criteria. Tasks 1–1.2 implemented the core filesystem mutation engine. Task 2–2.2 implemented the bounded apply_patch engine. Task 3 completed MCP discovery, Zod schema admission, policy/approval integration, audit data minimization, and all quality gates. RC-03 is fully integrated. The human approval execution workflow is deferred to RC-04.

---

## 2. Canonical Mutation Tool Specifications

### 2.1. `create_file`

Creates a new file at the specified workspace-relative path. Target **MUST NOT** exist, and parent directory **MUST** already exist.

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
  4. Verifies parent directory exists and is a directory. If parent directory does not exist, fails closed with `PARENT_NOT_FOUND`. Intermediate directories are **never** automatically created in RC-03.
  5. Verifies parent directory is not a symbolic link.
  6. Acquires in-process lock for canonical target path.
  7. Target must not exist. If target exists, fails with `ALREADY_EXISTS`. `create_file` has **no** overwrite parameter.
  8. Writes file content to a sibling temporary file in the same directory (`.arc-tmp-{uuid}`) with `0o644` mode (masked by umask) and calls `fsync`.
  9. Commits via a kernel-level no-replace primitive (e.g. `fs.link(tmp, target)` which fails with `EEXIST` if target exists, followed by unlinking the temporary sibling file). If target appears concurrently, commit fails with `ALREADY_EXISTS`.
  10. Emits `FILE_CREATED` audit event (metadata only, raw content omitted).

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
  4. Acquires in-process lock for canonical target path.
  5. Resolves canonical path within workspace root. Target must exist; if missing, rejects with `FILE_NOT_FOUND` (`write_file` never creates new files).
  6. Inspects file type using `lstat`. If target is a directory (`IS_A_DIRECTORY`), symlink (`UNSAFE_SYMLINK`), or special file (`NOT_A_FILE`), rejects immediately.
  7. Inspects hardlink count (`stat.nlink > 1`); fails with `HARDLINK_DETECTED` if aliased.
  8. Reads current file content and computes SHA-256. If hash !== `expectedHash`, rejects with `CONFLICT_PRECONDITION_FAILED`.
  9. Captures existing file mode bits (`stat.mode & 0o777`).
  10. Writes new content to sibling temporary file (`.arc-tmp-{uuid}`), applies original file permissions (`fchmod`), and calls `fsync`.
  11. Revalidates target preconditions immediately prior to commit (content hash, type, inode identity). If changed, aborts with `CONFLICT_PRECONDITION_FAILED`.
  12. Atomically replaces target via `fs.rename`.
  13. Emits `FILE_WRITTEN` audit event with old and new hashes; raw content is redacted.

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
  4. **Lock Acquisition:** Sorts canonical target paths lexicographically and acquires all in-process locks before preflight.
  5. **Phase 1: Parse & Preflight (Zero Disk Mutation):**
     - Parses unified diff into structured file hunks in-memory.
     - Resolves canonical path for each target file; verifies each resides in workspace root, is not blacklisted, is a regular file (`stat.isFile()`), not a symlink, and has `stat.nlink === 1`.
     - Reads existing content and records `preflightHash` (SHA-256) and original permissions for every target file.
     - Simulates applying hunks in-memory with zero fuzz.
     - If any hunk fails to match context lines exactly, or if any target is missing, the entire operation fails with `PATCH_PREFLIGHT_FAILED`. Zero disk changes occur.
  6. If `dryRun === true`, returns preflight success and stats without writing to disk.
  7. **Phase 2: Staging Sibling Replacement Files:**
     - For each target file, writes modified buffer to sibling temp file (`.arc-tmp-{uuid}`) in the same directory, applies original permissions (`fchmod`), and `fsync`s.
  8. **Phase 3: Pre-Commit Revalidation & Individual Commit:**
     - Immediately before committing each file, verifies current on-disk SHA-256 still matches `preflightHash`. If any file changed concurrently, halts commit immediately and initiates rollback.
     - Commits files one by one via `fs.rename`.
  9. **Phase 4: Safe Rollback on Failure:**
     - If an error occurs during commit of file `N`, the engine attempts to restore files `1` through `N-1` to their preflight content.
     - _Rollback Verification:_ Before restoring file `i`, the engine verifies that the current file content hash matches the committed content hash (ensuring no intermediate changes occurred). If a file was modified after ARC's commit, the engine does **not** overwrite it, logs recovery-required audit metadata, and raises `ROLLBACK_FAILED`.
     - If rollback fails or encounters an unresolvable conflict, raises `ROLLBACK_FAILED` with detailed metadata.
  10. Emits `PATCH_APPLIED` audit event (metadata only; patch text and file contents omitted).

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
  3. Acquires in-process lock for canonical target path.
  4. Resolves canonical path within workspace root. Target must exist; if missing, rejects with `FILE_NOT_FOUND`.
  5. Inspects target using `lstat`. If target is a directory, rejects with `IS_A_DIRECTORY`. **Recursive directory deletion is strictly forbidden.**
  6. If target is a symbolic link, rejects with `UNSAFE_SYMLINK`.
  7. Inspects hardlink count (`stat.nlink > 1`); fails with `HARDLINK_DETECTED` if aliased.
  8. Reads file content and computes SHA-256. If hash !== `expectedHash`, rejects with `CONFLICT_PRECONDITION_FAILED`.
  9. Revalidates preconditions immediately before `fs.unlink`.
  10. Unlinks file via `fs.unlinkSync` / `fs.promises.unlink`.
  11. Emits `FILE_DELETED` audit event with `contentHash`.

### 2.5. `move_file`

Executes a **no-replace move with rollback** within authorized workspace roots. Destination **MUST NOT** exist; source **MUST** match `expectedSourceHash`.

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
- **Operational Semantics (No-Replace Move with Rollback):**
  1. Validates path lengths <= 1024 characters; checks for null bytes and URL encoding.
  2. Verifies neither `sourcePath` nor `destinationPath` targets `.git/**` or blacklist (`ACCESS_DENIED`).
  3. Resolves canonical path for `sourcePath` (must exist; otherwise `FILE_NOT_FOUND`).
  4. Inspects source using `lstat`. Source must be a regular file; if directory (`IS_A_DIRECTORY`) or symlink (`UNSAFE_SYMLINK`), rejects immediately.
  5. Inspects source hardlink count (`stat.nlink > 1`); fails with `HARDLINK_DETECTED`.
  6. Validates `expectedSourceHash` format. Computes current source SHA-256; if mismatched, rejects with `CONFLICT_PRECONDITION_FAILED`.
  7. Resolves destination canonical parent directory; verifies parent exists and is inside workspace root (`PATH_ESCAPES_ROOT`).
  8. If destination already exists, rejects with `ALREADY_EXISTS`. `move_file` has **no** overwrite parameter in RC-03.
  9. **Lock Acquisition:** Acquires in-process locks for `sourcePath` and `destinationPath` in deterministic lexicographical order.
  10. **Pre-Commit Revalidation & Link Creation:**
      - Revalidates source content hash and preconditions immediately before link creation.
      - Cross-device movement is rejected with `CROSS_DEVICE_MOVE_UNSUPPORTED` (no silent copy-delete fallback).
      - Creates destination hardlink using exclusive linking (`fs.link`). If destination appears concurrently, `fs.link` fails with `EEXIST` -> `ALREADY_EXISTS`.
      - Verifies destination refers to intended source identity (`stat` dev and inode match source).
  11. **Source Unlink & Rollback:**
      - Removes source name via `fs.unlink(source)`.
      - If removing source fails, attempts rollback by unlinking the newly-created destination (`fs.unlink(destination)`).
      - If rollback fails, raises `ROLLBACK_FAILED` with recovery metadata.
      - _Crash Note:_ An unexpected system crash between link and unlink may leave both paths referencing the same inode; full multi-step crash atomicity is not claimed.
  12. Emits `FILE_MOVED` audit event (metadata only).

---

## 3. Security Boundary & Threat Mitigations

| Threat Vector                        | Mitigation Strategy in RC-03                                                                         | Fail-Closed Mechanism                        |
| :----------------------------------- | :--------------------------------------------------------------------------------------------------- | :------------------------------------------- |
| **Git Metadata Tampering**           | Permanent denial of `.git/**` for all mutation operations (`HEAD`, `refs`, `index`, `hooks`, etc.).  | `ACCESS_DENIED`                              |
| **Silent Lost Updates**              | Mandatory `expectedHash` on `write_file`/`delete_file` and `expectedSourceHash` on `move_file`.      | `CONFLICT_PRECONDITION_FAILED`               |
| **Accidental Overwrites**            | `create_file` and `move_file` strictly require destination to not exist; no `overwrite` flag.        | `ALREADY_EXISTS`                             |
| **Create/Move Replace Races**        | Commit-time exclusive/no-replace primitives (e.g. `O_EXCL` / `fs.link` semantics).                   | `ALREADY_EXISTS`                             |
| **Unintended Directory Creation**    | `create_file` requires immediate parent directory to already exist; no recursive directory creation. | `PARENT_NOT_FOUND`                           |
| **Internal Mutation Races**          | In-process lexicographical path locking serializes conflicting ARC mutations.                        | Deadlock-free serialization                  |
| **Cross-Device Move Corruption**     | Cross-filesystem `move_file` fails closed deterministically; no copy+delete fallback.                | `CROSS_DEVICE_MOVE_UNSUPPORTED`              |
| **Multi-File Patch Partial State**   | Preflight-all, commit-with-rollback model; safe rollback revalidation; failure audited.              | `PATCH_PREFLIGHT_FAILED` / `ROLLBACK_FAILED` |
| **Patch Scope Smuggling**            | Directives creating, deleting, renaming files, changing modes, or targeting symlinks are denied.     | `PATCH_UNSUPPORTED_OPERATION`                |
| **File Permission Drift**            | `write_file` preserves original regular file mode (`0o777`); `create_file` uses `0o644` with umask.  | Explicit mode propagation                    |
| **Symlink Redirection / Traversal**  | Symlink targets permanently denied for create/write/patch/move/delete.                               | `UNSAFE_SYMLINK` / `PATH_ESCAPES_ROOT`       |
| **Hardlink Inode Aliasing**          | `stat.nlink > 1` checked on all candidate targets; rejected before mutation.                         | `HARDLINK_DETECTED`                          |
| **Path Traversal (`../`, `%2e%2e`)** | Canonical realpath resolution, normalization, 1024-char limit, prefix enclosure.                     | `PATH_ESCAPES_ROOT` / `INVALID_PATH_CHARS`   |
| **Directory Destruction**            | `delete_file` restricted strictly to regular files; directory deletion permanently blocked.          | `IS_A_DIRECTORY`                             |
| **Secret Leakage in Audit Trail**    | Raw file contents and diff text strictly omitted from audit logs and errors; only hashes logged.     | Data minimization by design                  |
| **Unauthorized Execution**           | All mutation tools classified `REQUIRE APPROVAL`; direct MCP invocation fails closed.                | `APPROVAL_REQUIRED`                          |

---

## 4. Error Taxonomy for RC-03

The following structured error codes extend `@cesspace-arc/protocol` for RC-03:

| Error Code                      | HTTP-Equivalent          | Description                                                                                        |
| :------------------------------ | :----------------------- | :------------------------------------------------------------------------------------------------- |
| `CONFLICT_PRECONDITION_FAILED`  | 412 Precondition Failed  | Current file SHA-256 does not match caller's `expectedHash` or `expectedSourceHash`.               |
| `ALREADY_EXISTS`                | 409 Conflict             | Target destination file already exists (for `create_file` or `move_file`).                         |
| `FILE_NOT_FOUND`                | 404 Not Found            | Target file to write, delete, or move does not exist.                                              |
| `PARENT_NOT_FOUND`              | 404 Not Found            | Immediate parent directory for file creation does not exist.                                       |
| `IS_A_DIRECTORY`                | 400 Bad Request          | Target path is a directory where a regular file was required.                                      |
| `NOT_A_FILE`                    | 400 Bad Request          | Target is a special filesystem node (socket, FIFO, device) rather than a regular file.             |
| `HARDLINK_DETECTED`             | 403 Forbidden            | Target file has link count > 1, preventing external hardlink aliasing mutation.                    |
| `UNSAFE_SYMLINK`                | 403 Forbidden            | Target is or traverses a symbolic link, which is forbidden for mutation in RC-03.                  |
| `PATCH_PARSE_ERROR`             | 400 Bad Request          | Patch syntax is invalid or not recognized as standard unified diff.                                |
| `PATCH_PREFLIGHT_FAILED`        | 422 Unprocessable Entity | Patch cannot apply cleanly (hunk context mismatch, missing file, or out-of-bounds path).           |
| `PATCH_UNSUPPORTED_OPERATION`   | 400 Bad Request          | Patch contains forbidden directives (file creation, deletion, rename, mode change, symlink).       |
| `CROSS_DEVICE_MOVE_UNSUPPORTED` | 400 Bad Request          | `move_file` spans distinct filesystems/mountpoints; copy+delete fallback is disallowed.            |
| `ROLLBACK_FAILED`               | 500 Internal Error       | Multi-file patch commit or move failed and rollback could not restore prior file state.            |
| `PATH_ESCAPES_ROOT`             | 403 Forbidden            | Target path attempts to escape the authorized workspace root boundary.                             |
| `ACCESS_DENIED`                 | 403 Forbidden            | Target path targets `.git/**` or matches sensitive blacklist patterns.                             |
| `PAYLOAD_TOO_LARGE`             | 413 Payload Too Large    | Content exceeds 1 MiB or patch exceeds 512 KiB / 10 files.                                         |
| `INVALID_REQUEST_SCHEMA`        | 400 Bad Request          | Request arguments fail schema validation (missing required fields, path > 1024 chars, fuzz > 0).   |
| `APPROVAL_REQUIRED`             | 403 Forbidden            | MCP invocation requires human approval token (policy outcome: `REQUIRE_APPROVAL`, RC-04 boundary). |

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
- [ ] Attempting `create_file` when immediate parent directory does not exist fails with `PARENT_NOT_FOUND`.
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
- [ ] Simulated rollback failure (or unresolvable rollback conflict) reports `ROLLBACK_FAILED` with damaged file metadata.
- [ ] Direct invocation of any of the 5 tools through policy engine fails with `APPROVAL_REQUIRED` (policy outcome `REQUIRE_APPROVAL`, default-deny).
- [ ] Audit logs confirm raw file and patch contents are completely redacted.

### 5.2. Mandatory Positive Controls

- [ ] `create_file` creates a new file and returns correct canonical relative path, byte count, and SHA-256 hash when parent directory exists.
- [ ] `create_file` creates file with conservative mode (`0o644` modified by umask).
- [ ] `write_file` replaces existing file atomically and preserves original regular file mode bits (`stat.mode`).
- [ ] `write_file` with matching `expectedHash` succeeds cleanly and returns previous and new SHA-256 hashes.
- [ ] `apply_patch` with valid single-file diff applies cleanly to existing regular file and returns diff stats.
- [ ] `apply_patch` with valid multi-file diff applies all changes across multiple existing files using preflight-all, commit-with-rollback.
- [ ] `apply_patch` with `dryRun: true` returns success and stats without writing to disk.
- [ ] `delete_file` unlinks target file and returns deleted file SHA-256 hash.
- [ ] `delete_file` with matching `expectedHash` deletes successfully.
- [ ] `move_file` with matching `expectedSourceHash` executes no-replace move with rollback to new path and verifies old path is removed.
- [ ] All mutations emit valid structured audit log events with SHA-256 chaining and zero payload leakage.

---

## 6. Non-Goals & Deferrals

- **Interactive Human Approval State Machine:** Explicitly deferred to RC-04. RC-03 enforces `REQUIRE APPROVAL` in the policy engine and tests subsystem drivers directly.
- **File Watching & Subscriptions:** File change notifications (`workspace/didChangeWatchedFiles`) are deferred to post-RC-04.
- **Multi-Workspace Cross-Linking:** Moving files across different workspace roots is strictly forbidden; `move_file` operates strictly within the active workspace.
- **Recursive Directory Deletion:** Deletion of directory hierarchies (`rm -rf`) is permanently prohibited in CesSpace ARC.

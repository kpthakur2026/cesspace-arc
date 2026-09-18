# RC-03 Scope & Acceptance Criteria — CesSpace ARC

> **Document:** Stage Specification & Quality Gates  
> **Status:** RC-03 Scope Frozen — Implementation Not Started  
> **Target Stage:** `RC-03` — Safe File Modification  
> **Base:** `main` (Verified RC-02 Main Merge at `f9560abdca5b122cf29388561a8c6b240cdc871a`)

---

## 1. Stage Objective & Governance

The objective of **RC-03** is to introduce safe, policy-governed file modification capabilities into CesSpace ARC. Building upon the verified read-only inspection baseline (RC-01) and controlled terminal execution (RC-02), RC-03 introduces five atomic mutation tools:

1. `create_file`: Create a new file within an authorized workspace root.
2. `write_file`: Overwrite or update an existing file with complete content.
3. `apply_patch`: Apply a bounded unified diff patch atomically across workspace files.
4. `delete_file`: Delete a single authorized file (file-only, no recursive directory deletion).
5. `move_file`: Atomically move or rename a file within authorized workspace roots.

### 1.1. Core Invariants Maintained

Every file mutation operation in RC-03 must pass through the **Minimal Security Kernel** and satisfy the following non-negotiable security invariants:

1. **Strict Default-Deny & Policy Classification:** All five mutation tools are classified under `REQUIRE APPROVAL` in the policy engine. Unauthenticated or unapproved invocations via the Model Context Protocol (MCP) fail closed immediately with `REQUIRE_APPROVAL` or `POLICY_DENIED`.
2. **Approval Boundary Architecture:** In RC-03, direct tool invocation through the policy layer without an approved token fails closed. RC-03 implements the underlying mutation engine, validation pipelines, and subsystem interfaces (`IFilesystemSubsystem`). Subsystem unit and integration tests exercise the mutation engine directly via driver interfaces without weakening MCP default-deny policy or inventing a temporary/mock approval bypass. The reusable interactive approval token state machine and elevation UI remain strictly owned by RC-04.
3. **No Shell Execution or External Binary Delegation:** File mutations and patch applications are implemented strictly in native Node.js / POSIX filesystem calls. Invoking host binaries (such as `patch`, `git apply`, `rm`, `mv`, `cp`, `touch`, `sed`, `awk`, or shell subshells) is strictly forbidden.
4. **Jailed Canonical Path Resolution:** Every target path (source, destination, and patch targets) must undergo canonical normalization, symlink resolution, and prefix-enclosure verification against the authorized workspace root before any file descriptor is opened. Any attempt to traverse (`../`), escape via symlink, or access outside the workspace fails closed immediately with `PATH_ESCAPES_ROOT`.
5. **Hardlink Aliasing Defense:** Filesystem operations must verify inode link counts (`stat.nlink > 1`). Mutating a file with multiple hardlinks is rejected immediately (`HARDLINK_DETECTED`) to prevent modifying files outside the workspace root aliased through hardlinks.
6. **Atomic Replacement & Sibling Temp Files:** File writes and creations must write to a sibling temporary file in the same parent directory (`.arc-tmp-{uuid}`), flush to disk (`fsync`), and replace the target via atomic rename (`fs.rename`). On any error, temporary files are immediately cleaned up. Partial, truncated, or torn file writes are strictly impossible.
7. **Concurrency & Lost-Update Protection:** Mutation operations (`write_file`, `delete_file`, `move_file`) support optimistic concurrency control via an optional `expectedHash` (SHA-256 hex string). If provided, the existing file content hash must match `expectedHash` before mutation proceeds. If mismatched, the operation fails closed with `CONFLICT_PRECONDITION_FAILED`. Silent last-write-wins is strictly prevented.
8. **Permanent Sensitive Path Blacklist:** The immutable blacklist (`.env*`, `.ssh/`, `.aws/`, `.gnupg/`, `.kube/`, `.git/config`, `.git/hooks/`, `id_rsa*`, `/etc/`, `/proc/`, `/sys/`, `/dev/`, etc.) applies unconditionally to all mutation targets. No mutation tool may read, create, modify, rename, or delete any blacklisted path.
9. **Resource Bounds & Payload Limits:**
   - Maximum write content payload: 1 MiB (1,048,576 bytes).
   - Maximum patch size: 512 KiB (524,288 bytes).
   - Maximum changed files per patch: 10 files.
   - Maximum path length: 4096 bytes; maximum single path segment: 255 bytes.
   - Requests exceeding bounds fail closed immediately with `PAYLOAD_TOO_LARGE` or `INVALID_REQUEST_SCHEMA`.
10. **Audit Evidence & Data Minimization:** Every file mutation emits a structured audit record (`FILE_CREATED`, `FILE_WRITTEN`, `PATCH_APPLIED`, `FILE_DELETED`, `FILE_MOVED`) with cryptographic SHA-256 hash chaining. To prevent secret leakage, raw file content and raw diff text are **strictly omitted** from audit log events and error messages. Audit logs record only metadata: canonical relative paths, byte counts, pre-operation SHA-256 hashes, and post-operation SHA-256 hashes.

### 1.2. Scope Freeze Declaration

> **RC-03 STATUS: SCOPE FROZEN / IMPLEMENTATION NOT STARTED**  
> Task 0 freezes the architecture, API contracts, security invariants, and acceptance criteria. Zero runtime mutation code in `apps/` or `packages/` is introduced during Task 0. Implementation begins only after this specification commit is pushed and independently reviewed.

---

## 2. Canonical Mutation Tool Specifications

### 2.1. `create_file`

Creates a new file at the specified workspace-relative path.

- **Input Schema:**
  ```json
  {
    "path": "string (required, relative path within workspace)",
    "content": "string (required, UTF-8 file content, max 1 MiB)",
    "overwrite": "boolean (optional, default false)"
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
  1. Resolves canonical path of parent directory; verifies parent is enclosed within workspace root.
  2. If parent directories do not exist within the workspace, creates them with secure permissions (`0755`).
  3. If target file already exists and `overwrite` is `false`, rejects with `ALREADY_EXISTS`.
  4. If target file exists and `overwrite` is `true`, enforces hardlink check (`nlink <= 1`), writes via sibling temporary file, flushes (`fsync`), and atomically replaces target.
  5. Target path cannot be an existing directory.

### 2.2. `write_file`

Overwrites or updates an existing file with complete content.

- **Input Schema:**
  ```json
  {
    "path": "string (required, relative path within workspace)",
    "content": "string (required, UTF-8 file content, max 1 MiB)",
    "expectedHash": "string (optional, 64-character SHA-256 hex digest of current file)",
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
  1. Resolves canonical path; target file must exist (if file does not exist, rejects with `FILE_NOT_FOUND`; clients must use `create_file` for new files).
  2. Target cannot be a directory (`IS_A_DIRECTORY`) or special device node.
  3. Inspects hardlink count (`stat.nlink <= 1`); fails with `HARDLINK_DETECTED` if aliased.
  4. If `expectedHash` is provided, calculates SHA-256 of current on-disk content. If mismatched, fails with `CONFLICT_PRECONDITION_FAILED`.
  5. If `overwrite` is not explicitly `true`, rejects with `INVALID_REQUEST_SCHEMA`.
  6. Writes content to sibling temporary file in the same directory (`.arc-tmp-{uuid}`), flushes (`fsync`), and renames atomically to target path.

### 2.3. `apply_patch`

Applies a unified diff patch atomically across one or more workspace files.

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
- **Operational Semantics:**
  1. Parses unified diff entirely in-memory using deterministic native parser (no external `patch` or `git apply` invocation).
  2. Bounded input: rejects patch if length exceeds 512 KiB or targets more than 10 distinct files.
  3. Strict zero-fuzz policy: `fuzz` parameter cannot exceed 0; hunks must match exact line contexts.
  4. **Multi-File Atomic Preflight Phase:**
     - Resolves canonical path for every referenced file (old and new paths).
     - Verifies all paths reside strictly within workspace root and do not match blacklisted patterns.
     - Verifies hardlink counts (`stat.nlink <= 1`) on all target files.
     - Simulates applying every hunk to in-memory buffers of target files.
     - If ANY hunk fails to match, ANY file is missing, or ANY target path escapes the workspace boundary, the entire preflight fails closed immediately with `PATCH_PREFLIGHT_FAILED`. Zero disk modifications occur.
  5. If `dryRun` is `true`, returns preflight success and statistics without modifying disk.
  6. **Atomic Application Phase:**
     - For each modified file, writes new content to a sibling temporary file (`.arc-tmp-{uuid}`) and `fsync`s.
     - Atomically renames temporary files to target paths.
     - If an unexpected I/O error occurs during rename, rolls back all already-renamed files from in-memory backup buffers.

### 2.4. `delete_file`

Deletes a single authorized file within the workspace root.

- **Input Schema:**
  ```json
  {
    "path": "string (required, relative path within workspace)",
    "expectedHash": "string (optional, 64-character SHA-256 hex digest)"
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
  1. Resolves canonical path within workspace root. Target must exist; if missing, rejects with `FILE_NOT_FOUND`.
  2. Target must be a regular file or symbolic link. If target is a directory, rejects with `IS_A_DIRECTORY`. **Recursive directory deletion is strictly forbidden.**
  3. Verifies path does not match sensitive blacklist.
  4. If `expectedHash` is provided, verifies current file content SHA-256 matches before deletion. If mismatched, rejects with `CONFLICT_PRECONDITION_FAILED`.
  5. Unlinks the file via `fs.unlinkSync` / `fs.promises.unlink`.

### 2.5. `move_file`

Atomically moves or renames a file within authorized workspace roots.

- **Input Schema:**
  ```json
  {
    "sourcePath": "string (required, relative path within workspace)",
    "destinationPath": "string (required, relative path within workspace)",
    "overwrite": "boolean (optional, default false)",
    "expectedSourceHash": "string (optional, 64-character SHA-256 hex digest)"
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
  1. Resolves canonical path for `sourcePath` (must exist) and canonical destination path for `destinationPath`.
  2. Both `sourcePath` and `destinationPath` must resolve strictly within the authorized workspace root and neither may match blacklisted patterns.
  3. Source must be a regular file or contained symbolic link (cannot be a directory).
  4. If `destinationPath` already exists:
     - If destination is a directory, rejects with `IS_A_DIRECTORY`.
     - If `overwrite` is `false`, rejects with `ALREADY_EXISTS`.
     - If `overwrite` is `true`, enforces hardlink check (`nlink <= 1`) on destination.
  5. Destination parent directory must exist or be created within workspace boundary.
  6. If `expectedSourceHash` is provided, verifies source content SHA-256 before move; if mismatched, rejects with `CONFLICT_PRECONDITION_FAILED`.
  7. Performs atomic rename (`fs.rename`).

---

## 3. Security Boundary & Threat Mitigations

| Threat Vector                                  | Mitigation Strategy in RC-03                                                                                   | Fail-Closed Mechanism                      |
| :--------------------------------------------- | :------------------------------------------------------------------------------------------------------------- | :----------------------------------------- |
| **Path Traversal (`../`, `%2e%2e`)**           | Canonical realpath resolution + syntactic normalization + prefix enclosure verification.                       | `PATH_ESCAPES_ROOT` / `INVALID_PATH_CHARS` |
| **Symlink Escape / Poisoning**                 | Resolves realpath before operation; verifies canonical target remains inside workspace root.                   | `PATH_ESCAPES_ROOT`                        |
| **Hardlink Aliasing (`nlink > 1`)**            | Inspects `stat.nlink` on candidate target files. If `nlink > 1`, mutation is rejected.                         | `HARDLINK_DETECTED`                        |
| **Silent Lost Updates**                        | Optimistic concurrency checking via `expectedHash` (SHA-256).                                                  | `CONFLICT_PRECONDITION_FAILED`             |
| **Torn / Partial Writes (Crash / Power Loss)** | Sibling temp file (`.arc-tmp-{uuid}`), `fsync`, atomic POSIX rename.                                           | Target file unchanged on failure           |
| **Directory Destruction**                      | `delete_file` restricted strictly to regular files/symlinks via `fs.unlink`. Directory deletion rejected.      | `IS_A_DIRECTORY`                           |
| **Credential / Secret Modification**           | Permanent immutable deny-list enforced on all mutation targets (`.env*`, `.ssh`, `.aws`, `.git/config`, etc.). | `ACCESS_DENIED`                            |
| **Arbitrary Command Injection**                | Unified diff engine implemented in pure TypeScript/Node.js. No calls to `patch` or `git apply`.                | Zero subprocess execution                  |
| **Resource Exhaustion / Memory Bomb**          | Strict payload caps (1 MiB content, 512 KiB patch, max 10 files per patch, max 0 fuzz).                        | `PAYLOAD_TOO_LARGE`                        |
| **Secret Leakage in Audit Trail**              | Raw file contents and diff patches completely redacted from audit logs. Only hashes and sizes logged.          | Data minimization by design                |

---

## 4. Error Taxonomy for RC-03

The following structured error codes extend `@cesspace-arc/protocol`:

| Error Code                     | HTTP-Equivalent          | Description                                                                         |
| :----------------------------- | :----------------------- | :---------------------------------------------------------------------------------- |
| `CONFLICT_PRECONDITION_FAILED` | 412 Precondition Failed  | Current file SHA-256 does not match caller's `expectedHash`.                        |
| `ALREADY_EXISTS`               | 409 Conflict             | Target file already exists and `overwrite` was not set to true.                     |
| `IS_A_DIRECTORY`               | 400 Bad Request          | Target path is a directory where a regular file was required.                       |
| `NOT_A_FILE`                   | 400 Bad Request          | Target is a special node (socket, FIFO, device) rather than a regular file.         |
| `HARDLINK_DETECTED`            | 403 Forbidden            | Target file has link count > 1, preventing external hardlink mutation.              |
| `PATCH_PARSE_ERROR`            | 400 Bad Request          | Patch syntax is invalid or not recognized as standard unified diff.                 |
| `PATCH_PREFLIGHT_FAILED`       | 422 Unprocessable Entity | Patch cannot apply cleanly (context mismatch, missing file, or out-of-bounds path). |
| `PAYLOAD_TOO_LARGE`            | 413 Payload Too Large    | Content exceeds 1 MiB or patch exceeds 512 KiB / 10 files.                          |
| `PATH_ESCAPES_ROOT`            | 403 Forbidden            | Target path attempts to escape the authorized workspace root.                       |
| `ACCESS_DENIED`                | 403 Forbidden            | Target path matches blacklisted credential or configuration patterns.               |
| `FILE_NOT_FOUND`               | 404 Not Found            | Target file to write, delete, or move does not exist.                               |
| `REQUIRE_APPROVAL`             | 403 Forbidden            | MCP invocation requires human approval token (RC-04 boundary).                      |

---

## 5. Acceptance Verification Plan

When RC-03 implementation begins, acceptance verification must prove both negative and positive controls:

### 5.1. Mandatory Negative Controls

- [ ] Attempting `create_file` on existing path with `overwrite: false` fails with `ALREADY_EXISTS`.
- [ ] Attempting `write_file` with mismatched `expectedHash` fails with `CONFLICT_PRECONDITION_FAILED`.
- [ ] Attempting `write_file` with `overwrite: false` or omitted fails with `INVALID_REQUEST_SCHEMA`.
- [ ] Attempting `write_file` on non-existent file fails with `FILE_NOT_FOUND`.
- [ ] Attempting `delete_file` on directory fails with `IS_A_DIRECTORY`.
- [ ] Attempting `delete_file` with mismatched `expectedHash` fails with `CONFLICT_PRECONDITION_FAILED`.
- [ ] Attempting mutation on file with `stat.nlink > 1` fails with `HARDLINK_DETECTED`.
- [ ] Attempting mutation on blacklisted paths (`.env`, `.ssh/id_rsa`, `.git/config`, `/etc/passwd`) fails with `ACCESS_DENIED`.
- [ ] Attempting path traversal (`../../etc/passwd`, symlink escaping root) fails with `PATH_ESCAPES_ROOT`.
- [ ] Attempting `apply_patch` with invalid unified diff fails with `PATCH_PARSE_ERROR`.
- [ ] Attempting `apply_patch` where any hunk fails fails with `PATCH_PREFLIGHT_FAILED` with zero disk changes.
- [ ] Attempting `apply_patch` exceeding 512 KiB or 10 files fails with `PAYLOAD_TOO_LARGE`.
- [ ] Attempting `apply_patch` with `fuzz > 0` fails with `INVALID_REQUEST_SCHEMA`.
- [ ] Attempting `move_file` onto existing destination with `overwrite: false` fails with `ALREADY_EXISTS`.
- [ ] Direct invocation of any of the 5 tools through policy engine fails with `REQUIRE_APPROVAL` (default-deny).
- [ ] Audit logs confirm raw file and patch contents are completely redacted.

### 5.2. Mandatory Positive Controls

- [ ] `create_file` creates a new file and returns correct canonical relative path, byte count, and SHA-256 hash.
- [ ] `create_file` creates required intermediate parent directories within the workspace root.
- [ ] `create_file` with `overwrite: true` successfully replaces existing file.
- [ ] `write_file` replaces existing file atomically and returns old and new SHA-256 hashes.
- [ ] `write_file` with matching `expectedHash` succeeds cleanly.
- [ ] `apply_patch` with valid single-file diff applies cleanly and returns diff stats.
- [ ] `apply_patch` with valid multi-file diff applies all changes atomically.
- [ ] `apply_patch` with `dryRun: true` returns success and stats without writing to disk.
- [ ] `delete_file` unlinks target file and returns deleted file SHA-256 hash.
- [ ] `delete_file` with matching `expectedHash` deletes successfully.
- [ ] `move_file` atomically moves file to new path and verifies old path no longer exists.
- [ ] `move_file` with `overwrite: true` replaces destination file atomically.
- [ ] All mutations emit valid structured audit log events with SHA-256 chaining.

---

## 6. Non-Goals & Deferrals

- **Interactive Human Approval State Machine:** Explicitly deferred to RC-04. RC-03 enforces `REQUIRE APPROVAL` in the policy engine and tests subsystem drivers directly.
- **File Watching & Subscriptions:** File change notifications (`workspace/didChangeWatchedFiles`) are deferred to post-RC-04.
- **Multi-Workspace Cross-Linking:** Moving files across different workspace roots is strictly forbidden; `move_file` operates strictly within the active workspace.
- **Recursive Directory Deletion:** Deletion of directory hierarchies (`rm -rf`) is permanently prohibited in CesSpace ARC.

# MCP Tool Taxonomy — CesSpace ARC

> **Document:** Tool Specification
> **Status:** RC-00 Approved Baseline
> **Classification:** Architecture & Interface Specification

---

## 1. Overview of Tool Taxonomy

CesSpace ARC provides a standardized set of tools exposed via the Model Context Protocol (MCP). Tools are partitioned into three lifecycle tiers based on their capability and security risk:

1. **Read-Only Inspection Tools (Tier 1 — RC-01 Target):** Safely observe filesystem state, Git status, and system health within authorized workspace roots.
2. **Controlled Mutation & Execution Tools (Tier 2 — RC-02 & RC-03 Targets):** Execute bounded processes and mutate files under strict policy supervision and human approval.
3. **Engineering-Aware Composite Tools (Tier 3 — RC-07 Target):** High-level engineering primitives composing Tier 1 and Tier 2 capabilities to safely verify builds, run tests, and generate stage evidence.

---

## 2. Tier 1: Read-Only Tools (RC-01 Target)

Read-only tools provide visibility into development environments without altering state. They default to the `ALLOW` policy outcome when operating within authorized workspace roots.

### 2.1. `health`
* **Description:** Verifies control plane readiness, active policy status, and subsystem health.
* **Input Schema:** Empty object `{}`.
* **Output Schema:**
  ```json
  {
    "status": "HEALTHY",
    "version": "0.0.0-rc00",
    "stage": "RC-00",
    "policyEngineActive": true,
    "auditActive": true,
    "authorizedWorkspacesCount": 1
  }
  ```
* **Default Policy:** `ALLOW`.

---

### 2.2. `list_directory`
* **Description:** Lists contents of an authorized directory within the workspace jail.
* **Input Schema:**
  ```json
  {
    "path": "string (relative to workspace root or absolute authorized path)",
    "recursive": "boolean (optional, default false)",
    "maxDepth": "integer (optional, min 1, max 5, default 1)",
    "includeHidden": "boolean (optional, default false)"
  }
  ```
* **Output Schema:** Array of file/directory entries (name, relative path, type, size, modified time).
* **Security Controls:** Canonical path check (`realpath`), symlink resolution check, hidden/credential file masking.
* **Default Policy:** `ALLOW` for authorized paths; `DENY` for blacklisted or external paths.

---

### 2.3. `read_file`
* **Description:** Reads file content within the authorized workspace.
* **Input Schema:**
  ```json
  {
    "path": "string (required)",
    "offset": "integer (optional, default 0)",
    "length": "integer (optional, default 65536, max 1048576)"
  }
  ```
* **Output Schema:**
  ```json
  {
    "content": "string (UTF-8 encoded)",
    "bytesRead": 1024,
    "totalSize": 1024,
    "truncated": false
  }
  ```
* **Security Controls:** Max read limit (1 MB default), binary file detection, `.env` / credentials path blacklist.
* **Default Policy:** `ALLOW` within workspace; `DENY` for blacklisted filenames.

---

### 2.4. `search_files`
* **Description:** Finds file paths matching a glob or substring pattern within authorized workspace roots.
* **Input Schema:**
  ```json
  {
    "pattern": "string (required, glob or name pattern)",
    "subPath": "string (optional, subdirectory to restrict search)",
    "maxResults": "integer (optional, default 50, max 200)"
  }
  ```
* **Output Schema:** Array of matched relative file paths.
* **Security Controls:** Symlink containment check during traversal; bounded result set.
* **Default Policy:** `ALLOW`.

---

### 2.5. `search_text`
* **Description:** Searches for text or regular expressions within files inside authorized roots.
* **Input Schema:**
  ```json
  {
    "query": "string (required)",
    "isRegex": "boolean (optional, default false)",
    "filePattern": "string (optional glob)",
    "maxMatches": "integer (optional, default 50, max 200)"
  }
  ```
* **Output Schema:** Array of matches (path, lineNumber, snippet).
* **Security Controls:** ReDoS regex complexity check, skips binary files and blacklisted paths.
* **Default Policy:** `ALLOW`.

---

### 2.6. `git_status`
* **Description:** Inspects Git working tree status (branch, modified, staged, untracked files).
* **Input Schema:**
  ```json
  {
    "workspaceRoot": "string (optional, defaults to active workspace)"
  }
  ```
* **Output Schema:** Current branch, commit hash, staged files, unstaged files, untracked files.
* **Security Controls:** Verifies target directory is an approved Git repository; blocks parameter injection.
* **Default Policy:** `ALLOW`.

---

### 2.7. `git_diff`
* **Description:** Inspects Git diff of working tree or specific commit.
* **Input Schema:**
  ```json
  {
    "target": "string (optional, e.g. HEAD, origin/main, or empty for working tree)",
    "path": "string (optional, filter by relative path)",
    "cached": "boolean (optional, default false)"
  }
  ```
* **Output Schema:** Unified diff string (capped to max buffer size, e.g. 512 KB).
* **Security Controls:** Redacts potential secret patterns in diff output; limits output size.
* **Default Policy:** `ALLOW`.

---

### 2.8. `git_log`
* **Description:** Reads recent commit history.
* **Input Schema:**
  ```json
  {
    "maxCount": "integer (optional, default 10, max 100)",
    "revision": "string (optional, branch/tag/hash)",
    "path": "string (optional, filter by path)"
  }
  ```
* **Output Schema:** Array of commits (hash, author, date, message).
* **Security Controls:** Argument injection sanitization on revision strings.
* **Default Policy:** `ALLOW`.

---

### 2.9. `system_status`
* **Description:** Inspects host VM status (OS, architecture, load, memory, disk space in workspace).
* **Input Schema:** Empty object `{}`.
* **Output Schema:**
  ```json
  {
    "os": "linux",
    "arch": "x64",
    "cpuCount": 8,
    "memoryTotalBytes": 17179869184,
    "memoryFreeBytes": 8589934592,
    "workspaceDiskFreeBytes": 53687091200
  }
  ```
* **Security Controls:** Opaque sanitization; does not leak hostname, MAC address, internal IP, or private user IDs.
* **Default Policy:** `ALLOW`.

---

## 3. Tier 2: Controlled Mutation & Execution Tools (RC-02 & RC-03 Targets)

These tools modify files, run commands, or interact with processes. They are strictly governed by policy and human approval.

| Tool Name | Stage | Primary Function | Default Policy Outcome |
| :--- | :--- | :--- | :--- |
| `run_command` | RC-02 | Execute whitelisted command with argv array and timeout. | `REQUIRE APPROVAL` (or `ALLOW` for pre-approved test runners) |
| `read_command_output` | RC-02 | Read stdout/stderr stream from running or completed command. | `ALLOW` (scoped to caller's task ID) |
| `cancel_command` | RC-02 | Terminate running command task via SIGTERM/SIGKILL. | `ALLOW` (scoped to caller's task ID) |
| `process_list` | RC-02 | List processes spawned by the control plane. | `ALLOW` |
| `apply_patch` | RC-03 | Apply unified diff patch to workspace files atomically. | `REQUIRE APPROVAL` |
| `write_file` | RC-03 | Write complete contents to a file inside authorized root. | `REQUIRE APPROVAL` |
| `create_file` | RC-03 | Create a new file within authorized root. | `REQUIRE APPROVAL` |

---

## 4. Tier 3: Engineering-Aware Tools (RC-07 Target)

Higher-level engineering tools provide safe composite operations:

* **`arc_repo_status`:** Composes `git_status`, branch verification, and dirty tree checks into a high-level summary.
* **`arc_worktree_status`:** Verifies isolated agent worktree configurations.
* **`arc_review_diff`:** Produces a structured review-ready diff with security annotation.
* **`arc_verify`:** Runs standard verification suites (format, lint, typecheck, tests) within policy.
* **`arc_test`:** Runs targeted unit or integration test suites with execution bounds.
* **`arc_ci_status`:** Inspects local CI simulation status.
* **`arc_stage_evidence`:** Gathers git diff, status, and test evidence required for stage completion handoff.

---

## 5. Parameter Constraints & Security Invariants Summary

1. All path arguments (`path`, `subPath`) must undergo canonical resolution before use.
2. All command arguments (`run_command`) must be passed as distinct array tokens (`string[]`), never concatenated strings.
3. Numerical limits (`maxDepth`, `maxResults`, `maxCount`, `length`) are enforced with strict bounds.
4. Tools cannot be renamed or dynamically redefined by client agents.

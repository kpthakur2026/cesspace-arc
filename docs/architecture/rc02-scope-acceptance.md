# RC-02 Scope & Acceptance Criteria — CesSpace ARC

> **Document:** Stage Specification & Quality Gates
> **Status:** RC-02 Under Review — Review Remediations Active
> **Target Stage:** `RC-02` — Controlled Terminal & Process Execution
> **Base:** `main` (Approved RC-01 Merge at `8a4beb9ea559d1f2d3a0f143d82892ff168383b8`)

---

## 1. Stage Objective & Boundaries

The objective of **RC-02** is to build controlled terminal execution and process lifecycle management on top of the approved RC-01 read-only core. RC-02 introduces safe, policy-governed command execution within explicitly authorized workspaces without opening arbitrary interactive shells, network backdoors, or unmonitored execution paths.

### 1.1. Core Invariants Maintained

Every operation in RC-02 continues to pass through the **Security Kernel** and the authoritative execution pipeline:

1. **Default-Deny Security Kernel:** No command executes without prior policy admission.
2. **Explicit Executable Allowlist & Profiles:** Only approved development executables (`node`, `npm`, `pnpm`, `git`, `tsc`, `eslint`, `prettier`, `vitest`, `pytest`) are permitted. In RC-02, non-git executables are strictly restricted to safe informational operations (`--version`, `--help`). Arbitrary code execution (`node <script>`, `node -e`, `npx`, `npm run/start/test/exec`, `pnpm run/exec/dlx`) is strictly forbidden.
3. **Explicitly Denied Executables:** Direct shells (`bash`, `sh`, `zsh`, `fish`, `dash`, `powershell`, `cmd`), privilege escalation (`sudo`, `su`, `doas`, `pkexec`), system mutation (`rm`, `rmdir`, `mkfs`, `fdisk`, `dd`), network clients (`curl`, `wget`, `ssh`, `scp`, `sftp`, `nc`, `socat`), package execution bypasses (`npx`), and cloud/container management tools (`docker`, `kubectl`, `terraform`, `aws`, `gcloud`, `az`) fail closed immediately with `POLICY_DENIED` or `FORBIDDEN_COMMAND`.
4. **Shell-Free Invocation & Process Groups:** Subprocesses are spawned strictly with `shell: false`, deterministic argument arrays, and `detached: true` on POSIX systems to allow process-group termination (`process.kill(-pid, sig)`) of child process hierarchies. No shell parsing or shell string concatenation is permitted.
5. **Jailed Working Directory & Trusted Resolution:** Working directories must resolve strictly within the canonical authorized workspace root. Executables are resolved strictly from fixed trusted system directories (`/usr/bin`, `/bin`, `/usr/local/bin`) or `/proc/self/exe` for the exact active Node runtime (where canonical path, device, and inode match `process.execPath`, establishing kernel TCB identity without generic directory or PATH trust). Resolution from user-controlled paths, `node_modules/.bin`, or arbitrary world/group-writable locations is strictly forbidden.
6. **Isolated Environment:** Process environments are purged of inherited credentials, cloud tokens, and sensitive paths. Extra environment variables are strictly limited to allowlisted safe keys (`CI`, `FORCE_COLOR`, `NO_COLOR`, `DEBUG`, `NODE_ENV`).
7. **Bounded Output Buffering & UTF-8 Safety:** Process output buffers are strictly bounded to 512 KiB per process and 128 KiB per read request. Pagination is multi-byte UTF-8 safe to prevent splitting characters at chunk boundaries.
8. **Deterministic Concurrency Limits & Grace Periods:** Strict concurrency controls enforce max 10 globally running processes, max 4 per session, and max 4 per workspace. Processes undergoing termination (`TERMINATING`) continue to count toward active limits until completely exited.
9. **Authoritative Ownership & Opaque Identifiers:** Processes are addressed strictly by opaque UUIDs (`arc-proc-{UUID}`). Process control strictly verifies three-part caller identity (`clientId`, `sessionId`, and `workspaceId`). Mismatched or missing identity fails closed. Raw OS PIDs are never exposed to clients or accepted as selectors.
10. **Structured Audit Evidence & Data Minimization:** Every invocation and asynchronous process lifecycle event (`PROCESS_SPAWN_SUCCEEDED`, `PROCESS_SPAWN_FAILED`, `PROCESS_EXITED`, `PROCESS_TIMEOUT`, `PROCESS_TERMINATION_REQUESTED`, `PROCESS_SIGTERM_SENT`, `PROCESS_SIGKILL_ESCALATED`, `PROCESS_TERMINATED`) emits structured SHA-256 hash-chained audit evidence. Raw arguments are omitted from audit logs and policy error messages, recording only safe metadata.

### 1.2. Permitted Implementation Scope for RC-02

- 4 new MCP tools: `run_command`, `process_status`, `process_output`, `terminate_process`.
- Execution engine in `packages/terminal` (`ControlledProcessRunner`, `CommandPolicy`, `ExecutableResolver`).
- Process registry in `packages/processes` (`ProcessRegistry`).
- Policy admission rules in `packages/policy` for the 4 new tools.
- Output redaction and data minimization in `packages/audit`.
- Structured error additions in `packages/protocol` (`RESOURCE_EXHAUSTED`, `processNotFound`, `executionTimeout`, `resourceExhausted`, `forbiddenCommand`).
- All 9 RC-01 read-only inspection tools remain active and operational (13 total tools).

### 1.3. Explicitly Out of Scope for RC-02 (Strictly Forbidden)

- File modification tools (`write_file`, `create_file`, `apply_patch`) — scheduled for RC-03.
- Arbitrary package installation or mutating package manager workflows (`npm install`, `npm add`).
- Arbitrary script execution (`node <script>`, `npx <pkg>`, `npm run <script>`).
- Network listeners, remote HTTP gateways, or open TCP ports.
- Device enrollment or remote token lifecycles (local stdio transport only).
- Mutating Git operations (`git commit`, `git push`, `git checkout -b`, etc.).

---

## 2. Tools Implemented in RC-02

| Tool Name               | Capability                               | Input Constraints                                                                          | Security Controls                                                                                                                                      |
| :---------------------- | :--------------------------------------- | :----------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`health`**            | Check server readiness and active stage. | None (`{}`).                                                                               | Returns `RC-02` stage metadata.                                                                                                                        |
| **`system_status`**     | Host VM CPU/memory/disk stats.           | None (`{}`).                                                                               | Sanitized metrics; no hostnames/IPs.                                                                                                                   |
| **`list_directory`**    | List workspace directory entries.        | `path`, `recursive`, `maxDepth` (1..5).                                                    | Canonical path check, hides secrets.                                                                                                                   |
| **`read_file`**         | Read file content within workspace.      | `path`, `offset`, `length` (<= 1MB).                                                       | Canonical path check, max 1MB limit.                                                                                                                   |
| **`search_files`**      | Find files by glob pattern.              | `pattern`, `subPath`, `maxResults` (<= 200).                                               | Traversal bounded to approved root.                                                                                                                    |
| **`search_text`**       | Search text in workspace files.          | `query`, `isRegex`, `maxMatches` (<= 200).                                                 | ReDoS guards, skips blacklisted files.                                                                                                                 |
| **`git_status`**        | Working tree branch and dirty state.     | `workspaceRoot` (optional).                                                                | Verified Git root, parameter injection guard.                                                                                                          |
| **`git_diff`**          | Working tree or commit diff.             | `target`, `path`, `cached`.                                                                | Max 512KB limit, secret masking.                                                                                                                       |
| **`git_log`**           | Recent commit history.                   | `maxCount` (<= 100), `revision`.                                                           | Parameter injection guard (rejects `--`).                                                                                                              |
| **`run_command`**       | Execute an approved dev tool.            | `executable`, `args` (<= 100), `cwd`, `timeoutMs` (100..300000), `env`, `runInBackground`. | Allowlist & profile check, `shell: false`, bounded output (512 KiB), secret scrubbing. General Git execution removed (only `git --version` permitted). |
| **`process_status`**    | Query process execution state.           | `processId` (`arc-proc-*`), `workspaceId`.                                                 | Opaque ID validation, 3-part identity check (`clientId`, `sessionId`, `workspaceId`). Resolves from ProcessRecord before policy evaluation.            |
| **`process_output`**    | Read buffered process output.            | `processId`, `offset`, `stdoutCursor`, `stderrCursor`, `maxBytes` (<= 128 KiB).            | Bounded chunk read, combined stdout/stderr budget, multi-byte UTF-8 safe, secret scrubbing.                                                            |
| **`terminate_process`** | Terminate an ARC-managed process.        | `processId`, `signal` (`SIGTERM` \| `SIGKILL`), `workspaceId`.                             | Process group kill (`-pid`), SIGTERM with SIGKILL escalation, 3-part ownership validation, stale PID race hardening.                                   |

---

## 3. Acceptance Verification Summary

- **Total Test Cases:** 143/143 passing (54 RC-00/RC-01 + 89 RC-02 tests including 48 independent review regressions).
- **RC-02 Negative Controls:** 80 mandatory negative controls verified (denied commands, code execution bypasses, argument injection, shell metacharacters, env allowlist, strict schema, process ownership isolation, cwd containment, path traversal, git command denial, pre-schema parameter redaction, world/group-writable binary denial, untrusted symlink denial, unsafe/untrusted Node candidate denial, incomplete caller identity denial, total response budget enforcement, async spawn event failure handling, stale PID race hardening, background asynchronous spawn failure fail-closed/truthful reporting).
- **RC-02 Positive Controls:** 9 positive controls verified (`run_command` foreground/background, `process_status`, `process_output`, `terminate_process`, allowlisted env keys, exact Node binary resolution, audit logging).
- **Code Quality:** Zero Prettier issues, zero ESLint warnings/errors, clean TypeScript compilation across all 11 workspace packages.
- **Supply Chain Security:** Zero Gitleaks detections, zero forbidden credential files, zero private IPs in source, zero `pnpm audit` vulnerabilities.

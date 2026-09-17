# RC-02 Scope & Acceptance Criteria — CesSpace ARC

> **Document:** Stage Specification & Quality Gates
> **Status:** RC-02 Implementation Complete
> **Target Stage:** `RC-02` — Controlled Terminal & Process Execution
> **Base:** `main` (Approved RC-01 Merge at `8a4beb9ea559d1f2d3a0f143d82892ff168383b8`)

---

## 1. Stage Objective & Boundaries

The objective of **RC-02** is to build controlled terminal execution and process lifecycle management on top of the approved RC-01 read-only core. RC-02 introduces safe, policy-governed command execution within explicitly authorized workspaces without opening arbitrary interactive shells, network backdoors, or unmonitored execution paths.

### 1.1. Core Invariants Maintained

Every operation in RC-02 continues to pass through the **Security Kernel** and the authoritative execution pipeline:

1. **Default-Deny Security Kernel:** No command executes without prior policy admission.
2. **Explicit Executable Allowlist:** Only approved development executables (`node`, `npm`, `pnpm`, `npx`, `git`, `tsc`, `eslint`, `prettier`, `vitest`, `pytest`) are permitted.
3. **Explicitly Denied Executables:** Direct shells (`bash`, `sh`, `zsh`, `fish`, `dash`, `powershell`, `cmd`), privilege escalation (`sudo`, `su`, `doas`, `pkexec`), system mutation (`rm`, `rmdir`, `mkfs`, `fdisk`, `dd`), network clients (`curl`, `wget`, `ssh`, `scp`, `sftp`, `nc`, `socat`), and cloud/container management tools (`docker`, `kubectl`, `terraform`, `aws`, `gcloud`, `az`) fail closed immediately with `POLICY_DENIED` or `FORBIDDEN_COMMAND`.
4. **Shell-Free Invocation:** Subprocesses are spawned strictly with `shell: false` and deterministic argument arrays. No shell parsing or shell string concatenation is permitted.
5. **Jailed Working Directory:** Working directories must resolve strictly within the canonical authorized workspace root (`realpathSync` prefix enclosure check).
6. **Isolated Environment:** Process environments are purged of inherited credentials, cloud tokens, and sensitive paths. Extra environment variables are strictly limited to allowlisted safe keys (`CI`, `FORCE_COLOR`, `NO_COLOR`, `DEBUG`, `NODE_ENV`).
7. **Bounded Output Buffering:** Process output buffers are strictly bounded to 512 KiB per process and 128 KiB per read request.
8. **Deterministic Concurrency Limits:** Strict concurrency controls enforce max 10 globally running processes, max 4 per session, and max 4 per workspace.
9. **Opaque Process Identifiers:** Processes are addressed strictly by opaque UUIDs (`arc-proc-{UUID}`). Raw OS PIDs are never exposed to clients or accepted as selectors.
10. **Structured Audit Evidence:** Every invocation (allowed, denied, failed, or timed out) emits structured SHA-256 hash-chained audit evidence with redacted outputs and environment values.

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
- Network listeners, remote HTTP gateways, or open TCP ports.
- Device enrollment or remote token lifecycles (local stdio transport only).
- Mutating Git operations (`git commit`, `git push`, `git checkout -b`, etc.).

---

## 2. Tools Implemented in RC-02

| Tool Name               | Capability                               | Input Constraints                                                                          | Security Controls                                                            |
| :---------------------- | :--------------------------------------- | :----------------------------------------------------------------------------------------- | :--------------------------------------------------------------------------- |
| **`health`**            | Check server readiness and active stage. | None (`{}`).                                                                               | Returns `RC-02` stage metadata.                                              |
| **`system_status`**     | Host VM CPU/memory/disk stats.           | None (`{}`).                                                                               | Sanitized metrics; no hostnames/IPs.                                         |
| **`list_directory`**    | List workspace directory entries.        | `path`, `recursive`, `maxDepth` (1..5).                                                    | Canonical path check, hides secrets.                                         |
| **`read_file`**         | Read file content within workspace.      | `path`, `offset`, `length` (<= 1MB).                                                       | Canonical path check, max 1MB limit.                                         |
| **`search_files`**      | Find files by glob pattern.              | `pattern`, `subPath`, `maxResults` (<= 200).                                               | Traversal bounded to approved root.                                          |
| **`search_text`**       | Search text in workspace files.          | `query`, `isRegex`, `maxMatches` (<= 200).                                                 | ReDoS guards, skips blacklisted files.                                       |
| **`git_status`**        | Working tree branch and dirty state.     | `workspaceRoot` (optional).                                                                | Verified Git root, parameter injection guard.                                |
| **`git_diff`**          | Working tree or commit diff.             | `target`, `path`, `cached`.                                                                | Max 512KB limit, secret masking.                                             |
| **`git_log`**           | Recent commit history.                   | `maxCount` (<= 100), `revision`.                                                           | Parameter injection guard (rejects `--`).                                    |
| **`run_command`**       | Execute an approved dev tool.            | `executable`, `args` (<= 100), `cwd`, `timeoutMs` (100..300000), `env`, `runInBackground`. | Allowlist check, `shell: false`, bounded output (512 KiB), secret scrubbing. |
| **`process_status`**    | Query process execution state.           | `processId` (`arc-proc-*`).                                                                | Opaque ID validation, session ownership check.                               |
| **`process_output`**    | Read buffered process output.            | `processId`, `offset`, `maxBytes` (<= 128 KiB).                                            | Bounded chunk read, secret scrubbing.                                        |
| **`terminate_process`** | Terminate an ARC-managed process.        | `processId`, `signal` (`SIGTERM` \| `SIGKILL`).                                            | SIGTERM with SIGKILL escalation, session ownership.                          |

---

## 3. Acceptance Verification Summary

- **Total Test Cases:** 95/95 passing (54 RC-00/RC-01 + 41 RC-02 tests).
- **RC-02 Negative Controls:** 33 mandatory negative controls verified (denied commands, argument injection, shell metacharacters, env allowlist, strict schema, process ownership isolation, cwd containment, path traversal).
- **RC-02 Positive Controls:** 8 positive controls verified (`run_command` foreground/background, `process_status`, `process_output`, `terminate_process`, allowlisted env keys, audit logging).
- **Code Quality:** Zero Prettier issues, zero ESLint warnings/errors, clean TypeScript compilation across all 11 workspace packages.
- **Supply Chain Security:** Zero Gitleaks detections, zero forbidden credential files, zero private IPs in source, zero `pnpm audit` vulnerabilities.

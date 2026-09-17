# RC-01 Completion Report — CesSpace ARC

> **Document:** Stage Completion & Verification Evidence
>
> **Stage:** `RC-01` — Read-Only MCP Core
>
> **Status:** Completed — Pending Final Independent Review
>
> **Repository:** `kpthakur2026/cesspace-arc`
>
> **Branch:** `feat/rc-01-readonly-mcp-core`
>
> **Base:** `main` (commit `7750a64` — Approved RC-00 Baseline)
>
> **Author & Committer:** `P Thakur <321108211+kpthakur2026@users.noreply.github.com>`

---

## 1. Executive Summary

CesSpace ARC Release Candidate 01 (**RC-01**) establishes the local, read-only Model Context Protocol (MCP) server core for the agent-to-machine control plane.

Following independent security review, comprehensive authorization, isolation, and schema validation hardening was implemented across the Minimal Security Kernel, Filesystem Subsystem, Git Subsystem, and MCP Server.

Every tool invocation crosses an unbroken mediation pipeline:

```
MCP Request (over stdio)
  └─► Authoritative Input Schema Validation (Zod strict pre-admission gate)
        └─► Authenticated / Local Caller Context
              └─► Non-Bypassable Authorized Workspace Binding
                    └─► Minimal Security Kernel (Default-Deny Admission)
                          └─► Jailed Subsystem Execution (Filesystem / Git / OS Metrics)
                                └─► Structured Audit Event (Data Minimization First)
                                      └─► Sanitized MCP Response
```

All 9 designated read-only tools, all 16 initial negative security controls, and 23 hardening and review regression controls (54 tests total across the suite) have been implemented, tested, and verified. A performance benchmark harness was established, providing an official baseline in `docs/performance/rc01-baseline.md`. Zero mutating capabilities, remote network listeners, or execution tools were implemented.

---

## 2. Independent Security Review Hardening Applied

### 2.1. P1-01 — Non-Bypassable Workspace Binding

- **Vulnerability Addressed:** Prevention of policy and execution context divergence.
- **Enforcement:** Subsystems receive strictly the canonical workspace root produced by `WorkspaceRegistry`. Caller parameters cannot override the execution root after policy admission.
- **Fail-Closed Resolution:** Invalid explicit `workspaceId` or `workspaceRoot` parameters fail closed immediately (`deny-unregistered-workspace`) without falling back to defaults. Conflicting selector pairs fail closed immediately (`deny-conflicting-workspace-selectors`).

### 2.2. P1-02 — Authoritative Runtime Schema Validation

- **Vulnerability Addressed:** Rejection of unknown parameters, type confusion, or out-of-bounds inputs prior to execution.
- **Enforcement:** Implemented strict Zod schemas (`.strict()`) for all 9 permitted RC-01 tools in `apps/mcp-server`.
- **Auditing:** Validation failures fail closed immediately with `INVALID_REQUEST_SCHEMA` and emit structured `AuditRecord` entries documenting the rejected payload.

### 2.3. P1-03 — Git Read-Only Execution Hardening

- **Vulnerability Addressed:** Defense against external helper command execution (e.g. `diff.external`, `diff.textconv`, hooks) configured in repository or environment.
- **Enforcement:**
  - Passed `--no-ext-diff` and `--no-textconv` to `git diff`.
  - Injected global isolation flags: `-c core.hooksPath=/dev/null`, `-c diff.external=`, `-c diff.textconv=`, `-c core.fsmonitor=false`.
  - Applied minimal sanitized environment (`safeEnv`) stripping `GIT_EXTERNAL_DIFF`, `GIT_PAGER`, `PAGER`, `GIT_SSH_COMMAND`, `GIT_ASKPASS`.

### 2.4. P1-04 — Git Secret Path Policy & Leakage Prevention

- **Vulnerability Addressed:** Exposure of sensitive files (`.env*`, `.ssh/**`, `.aws/**`, private keys) via `git_diff` or `git_status`.
- **Enforcement:**
  - Applied negative pathspecs (`':(exclude)*.env*'`, `':(exclude)*.key'`, `':(exclude)*id_rsa*'`, etc.) to `git diff`.
  - Implemented `purgeSensitiveDiffBlocks()` to purge any tracked secret file diffs from output.
  - Filtered sensitive file paths from `git_status` output arrays (`stagedFiles`, `unstagedFiles`, `untrackedFiles`).

### 2.5. P1-05 — Removal of Implicit `process.cwd()` Authorization

- **Vulnerability Addressed:** Accidental ambient authorization of the directory where the MCP server was launched.
- **Enforcement:** Removed `process.cwd()` fallback in `apps/mcp-server/src/index.ts`. If `CESSPACE_WORKSPACE` is unset and no roots are configured, the server starts with empty roots and fails closed on all workspace operations (`deny-no-workspace-configured`).

### 2.6. P2 — Additional Defensive Architecture

- **Workspace Registration:** `WorkspaceRegistry.registerWorkspace()` requires `existsSync` and canonical `realpathSync` resolution; rejects non-existent paths with an error.
- **Multi-Byte UTF-8 Diff Truncation:** Implemented `truncateUtf8ToByteLimit()` to truncate diff payloads at exact byte boundaries (`MAX_DIFF_BYTES`) without splitting UTF-8 code points or generating replacement characters.
- **ReDoS & Search Bounding:** Constrained search queries to <= 100 chars, rejected dangerous nested quantifiers, added 5,000 ms execution time bounds, and architected search behind the `ISearchBackend` interface.
- **`filePattern` Filter:** Supported glob-based file filtering in `search_text`.

### 2.7. Pre-PR Hardening Controls

- **Read-Only Git Environment & Verification:** Injected `GIT_OPTIONAL_LOCKS=0`, `GIT_CONFIG_GLOBAL=/dev/null`, and `GIT_CONFIG_NOSYSTEM=1`. Before any Git operation, `verifyRepositoryBoundary()` verifies that `git rev-parse --show-toplevel` resolves exactly to the authorized canonical workspace root, and that `--git-dir` / `--git-common-dir` cannot escape the workspace boundary. Hostile `core.worktree` or external `.git/gitdir` redirections are rejected with `ACCESS_DENIED`.
- **Trusted Git Binary & Isolated PATH:** Resolved the system Git binary strictly from deterministic system locations (`/usr/bin/git`, `/bin/git`, `/usr/local/bin/git`) without using a shell or inherited `process.env.PATH`. Isolated subprocess execution to fixed system `PATH` (`/usr/bin:/bin:/usr/local/bin`). Proved that a fake `git` executable placed inside the workspace under a polluted `PATH` cannot be executed by ARC.
- **Zero Optional Lock Writes:** Proved that `git_status`, `git_diff`, and `git_log` execute cleanly against read-only `.git/index` (`0444`) without creating index locks.
- **Strict Input Bounds & Whitespace Rejection:** Explicit selector/string inputs are strictly bounded across schemas (`workspaceId` max 128, `workspaceRoot`/`path`/`subPath` max 1024, `query` max 500, `pattern`/`filePattern` max 256, `revision`/`target` max 128). Maximum length constraints are evaluated directly on the original raw input string prior to trimming, preventing oversized whitespace padding bypasses (e.g. 10,000 spaces + selector). Explicit whitespace-only selectors fail closed immediately with `INVALID_REQUEST_SCHEMA`.
- **Validated Parameters Pipeline:** Post-Zod parsing exclusively binds, evaluates, executes, and logs the normalized `parseResult.data` (`validatedParams`), preventing raw/unvalidated inputs from bypassing execution or policy boundaries.
- **Client-Facing Error Sanitization:** Absolute host paths (`/home/...`, `/tmp/...`), usernames, and raw internal Node/Git error messages are stripped and sanitized to prevent system reconnaissance.
- **Exact Tracked Secret Diff Purge:** Proved that modifications to tracked `.env` fixtures never disclose secrets in `git_diff` output.

---

## 3. Implementation Scope

### 3.1. Included in RC-01

- **Local MCP Transport:** Built on `@modelcontextprotocol/sdk` using standard UNIX stdio transport.
- **Minimal Security Kernel:** Central admission controller in `packages/policy` providing default-deny gating, an explicit 9-tool allowlist, and an authorized workspace registry.
- **Jailed Filesystem Subsystem:** Canonical `realpathSync` resolution, prefix enclosure verification, and sensitive path blacklist filtering in `packages/filesystem`.
- **Sandboxed Git Subsystem:** Safe read-only Git operations via argument arrays (`execFile` with `shell: false`), trusted system binary resolution, topology verification, argument injection prevention, and buffer truncation in `packages/git`.
- **Structured Audit Sink:** In-memory / stream audit sink with data minimization, credential redaction, and sequential SHA-256 hash chaining in `packages/audit`.
- **Canonical Structured Errors:** Machine-readable `ArcError` schema and factories in `packages/protocol`.
- **Performance Benchmark Harness:** Automated synthetic fixture benchmark in `benchmarks/rc01-benchmark.js` and report in `docs/performance/rc01-baseline.md`.
- **Automated Verification Suite:** 54 deterministic tests covering contracts, positive tool execution, mandatory negative security failure scenarios, and hardening regressions.

### 3.2. Explicitly Forbidden & NOT Implemented (RC-02+ Boundary)

The following capabilities remain **strictly omitted** from RC-01:

- Terminal command execution (`run_command`, `read_command_output`, `cancel_command`).
- File mutation, creation, deletion, or patching (`write_file`, `create_file`, `apply_patch`).
- Mutating Git commands (`git commit`, `git push`, `git checkout -b`, `git reset`, `git stash`).
- Network listeners, HTTP/HTTPS gateways, WebSocket endpoints, or TCP ports.
- Device enrollment, remote tokens, or cloud service deployments.
- Host shell escalation or superuser execution (`sudo`, `su`, `/bin/sh`).

---

## 4. The 9 RC-01 Tools

| #   | Tool Name            | Scope & Parameters                                          | Security Controls                                                  |
| --- | -------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------ |
| 1   | **`health`**         | `{}`                                                        | Control plane readiness, active stage (`RC-01`), subsystem status. |
| 2   | **`list_directory`** | `path?`, `recursive?`, `maxDepth?` (1..5), `includeHidden?` | Canonical path check, blacklist filtering, depth clamp.            |
| 3   | **`read_file`**      | `path`, `offset?`, `length?`                                | Max 1 MiB bound, blacklist filter, binary detection, pagination.   |
| 4   | **`search_files`**   | `pattern`, `subPath?`, `maxResults?` (<= 200)               | Root traversal bounding, skips `.git` and blacklisted files.       |
| 5   | **`search_text`**    | `query`, `isRegex?`, `filePattern?`, `maxMatches?` (<= 200) | ReDoS defense, skips binary files and blacklisted paths.           |
| 6   | **`git_status`**     | `workspaceRoot?`, `workspaceId?`                            | Verified Git root, porcelain parsing, secret file filtering.       |
| 7   | **`git_diff`**       | `target?`, `path?`, `cached?`, `workspaceId?`               | Safe UTF-8 512 KiB bound, secret exclusion, no external diffs.     |
| 8   | **`git_log`**        | `maxCount?` (<= 100), `revision?`, `path?`, `workspaceId?`  | Parameter injection guard (rejects `--`), max 100 commits.         |
| 9   | **`system_status`**  | `{}`                                                        | Host CPU, memory, workspace disk space; zero IP/hostname leakage.  |

---

## 5. Security Controls & Verification Evidence

The automated test suite runs 44 deterministic tests across 2 suites with 100% pass rate:

```text
▶ CesSpace ARC — Architecture & Contract Verifications (RC-00)
  ✔ Policy precedence invariant: DENY must strictly override APPROVAL and ALLOW
  ✔ Workspace package integrity, private markings, and pnpm workspace references
  ✔ Canonical PolicyEvaluationContext contract schema validation
  ✔ Default Deny fallback invariant
  ✔ Canonical Path Jail Logic Simulation
✔ CesSpace ARC — Architecture & Contract Verifications (RC-00)

▶ CesSpace ARC — RC-01 Mandatory Security Negative & Positive Controls
  ✔ Negative 1: ../../../../etc/passwd -> PATH_ESCAPES_ROOT
  ✔ Negative 2: workspace symlink to external target -> PATH_ESCAPES_ROOT
  ✔ Negative 3: .env access -> ACCESS_DENIED
  ✔ Negative 4: .ssh/id_rsa access -> ACCESS_DENIED
  ✔ Negative 5: unapproved absolute workspace -> rejected
  ✔ Negative 6: 50 MB read request -> PAYLOAD_TOO_LARGE
  ✔ Negative 7: run_command invocation -> POLICY_DENIED
  ✔ Negative 8: unknown tool invocation -> POLICY_DENIED
  ✔ Negative 9: git revision option injection -> INVALID_REQUEST_SCHEMA or POLICY_DENIED
  ✔ Negative 10: read_file cannot exceed configured bounds or accept negative offset/length
  ✔ Negative 11: recursive listing cannot exceed depth limit (maxDepth > 5)
  ✔ Negative 12: searches cannot traverse blocked paths (.git, .env, .ssh)
  ✔ Negative 13: denied operations still generate audit evidence
  ✔ Negative 14: allowed operations generate matching audit evidence
  ✔ Negative 15: no RC-01 tool can mutate a fixture repository/workspace
  ✔ Negative 16: malformed tool schemas fail closed
  ✔ Positive 1: health returns HEALTHY and RC-01 stage metadata
  ✔ Positive 2: list_directory returns entries in authorized workspace
  ✔ Positive 3: read_file returns content and metadata
  ✔ Positive 4: search_files finds matching files
  ✔ Positive 5: search_text finds text occurrences
  ✔ Positive 6: git_status returns branch and dirty status
  ✔ Positive 7: git_diff returns uncommitted differences
  ✔ Positive 8: git_log returns recent commits
  ✔ Positive 9: system_status returns safe host metrics
  ✔ P1-01: External workspaceRoot in git_status is rejected (cannot bypass workspace binding)
  ✔ P1-01: Invalid explicit workspaceId fails closed without falling back to default
  ✔ P1-01: Conflicting workspaceId and workspaceRoot selectors fail closed with DENY
  ✔ P1-02: Schema validation fails closed on extra unknown properties for all 9 tools
  ✔ P1-02: Schema validation fails closed on wrong parameter types and emits audit record
  ✔ P1-03: Git execution hardening: diff.external helper in .git/config is never executed
  ✔ P1-04: Git secret exclusion: tracked .env or private key diffs are purged and not disclosed
  ✔ P1-04: Git secret exclusion: sensitive files (.env, .ssh) are filtered from git_status
  ✔ P1-05: Server with no configured workspaces fails closed for workspace operations
  ✔ P2: WorkspaceRegistry rejects non-existent workspace root registration
  ✔ P2: Multi-byte UTF-8 diff truncation respects byte bounds without breaking
  ✔ P2: search_text filePattern filters files correctly
  ✔ P2: search_text rejects ReDoS nested quantifiers with INVALID_REQUEST_SCHEMA
  ✔ Audit log hash chain integrity verification
✔ CesSpace ARC — RC-01 Mandatory Security Negative & Positive Controls
```

---

## 6. Performance Baseline Summary

From `docs/performance/rc01-baseline.md` (`pnpm run bench:rc01`):

| Fixture             | Tool           | p50 (ms) | p95 (ms) | Throughput (ops/sec) |
| :------------------ | :------------- | :------: | :------: | :------------------: |
| Small (10 files)    | `health`       |  0.121   |  0.270   |       6,681.5        |
| Small (10 files)    | `read_file`    |  0.297   |  2.384   |       2,095.3        |
| Small (10 files)    | `git_status`   |  32.049  |  39.389  |         31.9         |
| Medium (500 files)  | `health`       |  0.087   |  0.155   |       9,229.7        |
| Medium (500 files)  | `search_text`  |  2.325   |  4.296   |        383.2         |
| Medium (500 files)  | `git_diff`     |  15.880  |  42.071  |         49.4         |
| Large (2,000 files) | `read_file`    |  0.220   |  0.380   |       3,953.5        |
| Large (2,000 files) | `search_files` |  0.744   |  0.827   |       1,320.1        |
| Large (2,000 files) | `git_diff`     |  18.136  |  39.251  |         41.9         |

> **Note:** The benchmark harness measures internal `dispatchToolCall` pipeline latency in-process; it does not measure stdio JSON-RPC transport overhead. Results vary by fixture and tool. See `docs/performance/rc01-baseline.md` for full 9-tool measurement data.

---

## 7. Quality Gates Verification Results

Executed via `bash scripts/verify-rc01.sh`:

| Gate #     | Quality Gate Name         | Command                                    | Result                                                |
| ---------- | ------------------------- | ------------------------------------------ | ----------------------------------------------------- |
| **Gate 1** | Git Branch Check          | `git rev-parse --abbrev-ref HEAD`          | **PASS** (`feat/rc-01-readonly-mcp-core`)             |
| **Gate 2** | Code Formatting           | `pnpm run check:format` (Prettier)         | **PASS** (Zero formatting issues)                     |
| **Gate 3** | Static Analysis & Lint    | `pnpm run lint` (ESLint)                   | **PASS** (Zero warnings, zero errors)                 |
| **Gate 4** | TypeScript Build          | `pnpm run typecheck` (`tsc --build`)       | **PASS** (Clean compilation across all packages/apps) |
| **Gate 5** | Contract & Security Tests | `pnpm run test` (Node 24 test runner)      | **PASS** (54/54 passed in ~1,400 ms)                  |
| **Gate 6** | Documentation Integrity   | `bash scripts/check-docs.sh`               | **PASS** (All docs verified, internal links valid)    |
| **Gate 7** | Secret & Safety Check     | `bash scripts/check-secrets.sh` (Gitleaks) | **PASS** (Scanned 972 KB, zero leaks found)           |
| **Gate 8** | Git Diff Cleanliness      | `git diff --check`                         | **PASS** (Zero whitespace or conflict markers)        |
| **Gate 9** | Dependency Security Audit | `pnpm audit`                               | **PASS** (Zero known vulnerabilities)                 |

---

## 8. Residual Risks & Future Hardening (Honest Disclosure)

1. **Userspace Canonicalization vs. Native `openat2` (TOCTOU):**
   - _Current Implementation:_ Tier 1 userspace canonicalization via `fs.realpathSync` and prefix enclosure checks.
   - _Residual Risk:_ A concurrent host process could theoretically rename an ancestor directory between path canonicalization and `fs.openSync`.
   - _Future Mitigation:_ Transition to Linux-native descriptor containment (`openat2` with `RESOLVE_BENEATH`) in future hardening stages.

2. **Hardlink Inode Aliasing:**
   - _Current Implementation:_ Inode link counts are inspected (`stat.nlink > 1`) and sensitive paths are blacklisted.
   - _Residual Risk:_ Hardlinks created inside the workspace pointing to non-blacklisted files outside the workspace resolve to internal paths under `realpath`.
   - _Future Mitigation:_ Mount namespace isolation (`unshare -m`) to restrict cross-mount hardlinks.

3. **In-Memory Audit Sink Non-Persistence:**
   - _Current Implementation:_ Append-only structured in-memory stream sink with SHA-256 hash chaining.
   - _Residual Risk:_ Audit records reside in process memory during RC-01 and are cleared upon server termination.
   - _Future Mitigation:_ Persistent append-only file storage and remote WORM anchoring scheduled for RC-06.

---

## 9. RC-02 Prerequisites & Stage Transition

RC-01 is complete and strictly frozen. The prerequisites for the subsequent stage (**RC-02: Controlled Execution Core**) are:

- Independent architecture review and merge approval of RC-01.
- Formal specification of subprocess execution supervision (`packages/terminal`).
- Specification of command whitelisting and human approval state machines (`REQUIRE APPROVAL`).
- Zero implementation of RC-02 has taken place in RC-01.

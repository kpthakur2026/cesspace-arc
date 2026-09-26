# RC-07 Final Integration & Acceptance Report

**Stage:** RC-07 — Engineering-Aware Tools Architecture: Repository Inspection, Diff Review, Project Verification, Isolated Testing, CI Status, and Stage Evidence Aggregation

**Scope title:** Higher-level engineering-aware tools composing lower-level primitives with strict adherence to security boundaries, deterministic execution, workspace containment, approval lifecycle binding, audit durability, transport parity, process orphan cleanup, and secret scrubbing.

**Base main:** `20de2e72bf85dd9178a35881c951f637de9e8ec7`

**Approved implementation baseline before Task 8:** `f1d7c3ddec2d1dbc8a3274f99d07f74520f05226`

**Task-8 implementation history:**

- Final security hardening, transport parity, process cleanup, secret redaction, all 75 negative controls, all 20 positive flows, verification script, and version bump: the commit containing this report.

**Branch:** `feat/rc-07-engineering-aware-tools`

> PR and merge status is **not** asserted by this document. It is verified externally after independent review.

---

## 1. Eight-Task Implementation Summary

| Task | Deliverable                                                                                                                                                                | Commits                       |
| :--- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---------------------------- |
| 1    | Composite Invocation Framework (`arc_repo_status`, deterministic execution registry, policy engine mediation, workspace jailing, `RC07-NEG-001..012`, `RC07-FLOW-01..02`). | Task 1 commit                 |
| 2    | Repository & Worktree Status (`arc_worktree_status`, multi-worktree inspection, Git subsystem containment, `RC07-NEG-013..021`, `RC07-FLOW-03..05`).                       | Task 2 commit                 |
| 3    | Sandboxed Diff Review & Secret Masking (`arc_review_diff`, hunk trimming, unified diff parsing, regex redaction, `RC07-NEG-022..029`, `RC07-FLOW-06..08`).                 | Task 3 commit                 |
| 4    | Project Verification Suite (`arc_verify`, solution-aware no-write typechecking, format/lint/test suite execution, `RC07-NEG-030..042`, `RC07-FLOW-09..10`).                | Task 4 commit                 |
| 5    | Isolated Test Execution (`arc_test`, deterministic Node tap runner, process tree interruption, `RC07-NEG-043..050`, `RC07-FLOW-11..12`).                                   | Task 5 commit                 |
| 6    | Zero-Network CI Inspection (`arc_ci_status`, canonical `.github/workflows` confinement, symlink traversal prevention, `RC07-NEG-051..053`, `RC07-FLOW-13`).                | Task 6 commit                 |
| 7    | Stage Evidence Aggregation (`arc_stage_evidence`, verified pre-existing ledger boundary, anti-self-referencing check, `RC07-NEG-054..061`, `RC07-FLOW-14..15`).            | `bce4a0d`, `f1d7c3d`          |
| 8    | Security Hardening, Transport Parity, Acceptance & Promotion (`RC07-NEG-062..075`, `RC07-FLOW-16..20`, `scripts/verify-rc07.sh`, version `0.7.0-rc07`, stage `RC-07`).     | Commit containing this report |

---

## 2. Final Architecture Summary

### 2.1 The Cardinal Composition Invariant

No RC-07 tool reaches the operating system, filesystem, Git repository, child process subsystem, network stack, or mutation subsystem through a weaker path than the corresponding RC-01..RC-06 primitive. All high-level engineering tools strictly compose lower-level authorities.

### 2.2 Subprocess Ownership & Controlled Process Runner

- **Zero Direct Child Process:** No RC-07 composite module imports or invokes Node `child_process` directly (`exec`, `execFile`, `spawn`, `fork`).
- **Internal Deterministic Registry:** Project code execution in `arc_verify` and `arc_test` is strictly restricted to server-approved deterministic execution identities:
  1. `verify-format-v1` (`prettier --check .`)
  2. `verify-lint-v1` (`eslint .`)
  3. `verify-typecheck-v1` (`tsc --noEmit`)
  4. `verify-test-v1` (`node --test`)
  5. `arc-test-node-v1` (`node --test --test-reporter=tap`)
- **Process State Persistence & Orphan Cleanup:** On child spawn, process state is recorded in a separate durable directory (`process-state/`). On server startup or recovery, `sweepOrphanProcesses` inspects active processes, cross-verifies process start time via Linux `/proc/[pid]/stat` (field 22) against PID reuse, sends `SIGTERM`, and escalates to `SIGKILL` after 2,000ms if unresponsive.

### 2.3 Filesystem & Workspace Confinement

- **Subsystem Mediation:** All workspace file access traverses `FilesystemSubsystem` with strict `realpath` validation. Symlinks resolving outside authorized workspace roots are rejected with `PATH_OUTSIDE_WORKSPACE`.
- **Workflow Jailing:** `arc_ci_status` validates that `.github/workflows` resolves to a real directory strictly inside the workspace root and prohibits symlinked escape attempts.

### 2.4 Policy & Approval Engine Integration

- **Authoritative Policy Evaluation:** Built-in declarative policy evaluates all operations (`ALLOW`, `REQUIRE_APPROVAL`, `DENY`). External policies can override default rules to `DENY` or `REQUIRE_APPROVAL`.
- **ApprovalStateManager:** Mutating operations or privileged commands require cryptographic approval tokens bound to deterministic `planHash`. Approval tokens cannot be forged, replayed, or substituted.

### 2.5 Single Root Audit Lifecycle

- **Pre-Dispatch Durability:** A durable root `STARTED` record is committed and synced to disk before any subsystem invocation.
- **Terminal Record:** Operations terminate with a single `COMPLETED` record (or `DENIED` if policy refuses execution). There is no root `FAILED` phase, preserving total observable event causality.
- **Stage Evidence Integrity:** `arc_stage_evidence` evaluates only verified pre-existing evidence committed to the ledger _prior_ to its own `STARTED` record, preventing self-referential evidence inflation.

### 2.6 Redaction & Secrecy Hardening

- **Output Scrubbing:** All raw command outputs and composite error messages pass through central regex-based redaction patterns masking GitHub PATs, AWS access keys, OpenAI keys, bearer tokens, private keys, and certificates (`[REDACTED_SECRET]`).
- **Path Sanitization:** Absolute host filesystem paths are redacted to `[REDACTED_PATH]`.

### 2.7 Transport Parity

- **Dual Transports:** All composite tools are fully accessible over both local stdio transport and remote Streamable HTTP over TLS 1.3.
- **Identical Schemas:** The JSON response payload structures, property names, and error codes are identical across transports.
- **Layer C Admission:** Remote invocations pass authenticated Layer C rate limiting, consuming exactly one token and releasing outstanding request slots cleanly.

---

## 3. Negative Controls Verification (RC07-NEG-001..075)

All 75 frozen negative controls defined in `docs/architecture/rc07-scope-acceptance.md §8` are implemented, contiguous, unique, and verified passing:

| Control Range       | Domain                                                                                          | Primary Suite                             | Status |
| :------------------ | :---------------------------------------------------------------------------------------------- | :---------------------------------------- | :----- |
| `RC07-NEG-001..012` | Composite framework foundation, plan authorization, policy denial, registry injection rejection | `tests/rc07-composite-framework.test.js`  | PASS   |
| `RC07-NEG-013..021` | Repository & worktree status, detached HEAD, submodules, unborn branches, uncommitted mutations | `tests/rc07-repo-worktree-status.test.js` | PASS   |
| `RC07-NEG-022..029` | Diff review, hunk trimming, secret masking, binary files, symlink traversal, path confinement   | `tests/rc07-review-diff.test.js`          | PASS   |
| `RC07-NEG-030..042` | Verification suite, deterministic arguments, timeout bounds, output truncation, no-write check  | `tests/rc07-verify.test.js`               | PASS   |
| `RC07-NEG-043..050` | Isolated test runner, TAP parsing, non-zero exits, test timeouts, child cleanup                 | `tests/rc07-test.test.js`                 | PASS   |
| `RC07-NEG-051..053` | CI status inspection, unparseable YAML, symlinked workflow directories, external path escapes   | `tests/rc07-ci-status.test.js`            | PASS   |
| `RC07-NEG-054..061` | Stage evidence inspection, invalid stages, zero evidence, unanchored stores, tampering          | `tests/rc07-stage-evidence.test.js`       | PASS   |
| `RC07-NEG-062..075` | Security hardening, Layer C admission, revoked sessions, untrusted devices, orphan processes    | `tests/rc07-hardening.test.js`            | PASS   |

---

## 4. Positive Acceptance Flows Verification (RC07-FLOW-01..20)

All 20 frozen positive acceptance flows defined in `docs/architecture/rc07-scope-acceptance.md §8.2` are implemented and passing:

| Flow ID        | Description                                       | Suite / Verification Gate                                 | Status |
| :------------- | :------------------------------------------------ | :-------------------------------------------------------- | :----- |
| `RC07-FLOW-01` | Composite Tool Execution Lifecycle (Read-Only)    | `tests/rc07-composite-framework.test.js`                  | PASS   |
| `RC07-FLOW-02` | Composite Approval Flow for Mutation Tools        | `tests/rc07-composite-framework.test.js`                  | PASS   |
| `RC07-FLOW-03` | Clean Git Repository Inspection                   | `tests/rc07-repo-worktree-status.test.js`                 | PASS   |
| `RC07-FLOW-04` | Repository with Staged and Unstaged Modifications | `tests/rc07-repo-worktree-status.test.js`                 | PASS   |
| `RC07-FLOW-05` | Linked Git Worktree Inspection                    | `tests/rc07-repo-worktree-status.test.js`                 | PASS   |
| `RC07-FLOW-06` | Unstaged Diff Review with Line Range Trimming     | `tests/rc07-review-diff.test.js`                          | PASS   |
| `RC07-FLOW-07` | Staged Diff Review with Redacted Secrets          | `tests/rc07-review-diff.test.js`                          | PASS   |
| `RC07-FLOW-08` | Commit-to-Commit Range Diff Review                | `tests/rc07-review-diff.test.js`                          | PASS   |
| `RC07-FLOW-09` | Comprehensive Project Verification Pass           | `tests/rc07-verify.test.js`                               | PASS   |
| `RC07-FLOW-10` | Verification Suite Partial Failure Isolation      | `tests/rc07-verify.test.js`                               | PASS   |
| `RC07-FLOW-11` | Targeted Node Test Suite Execution (Pass)         | `tests/rc07-test.test.js`                                 | PASS   |
| `RC07-FLOW-12` | Targeted Node Test Suite Failure Isolation        | `tests/rc07-test.test.js`                                 | PASS   |
| `RC07-FLOW-13` | GitHub Actions CI Workflow Status Inspection      | `tests/rc07-ci-status.test.js`                            | PASS   |
| `RC07-FLOW-14` | Stage Evidence Aggregation & Verification (RC-06) | `tests/rc07-stage-evidence.test.js`                       | PASS   |
| `RC07-FLOW-15` | Composite Audit Evidence & Step Tracking          | `tests/rc07-stage-evidence.test.js`                       | PASS   |
| `RC07-FLOW-16` | Remote Streamable HTTP Parity                     | `tests/rc07-hardening.test.js`                            | PASS   |
| `RC07-FLOW-17` | Stdio Transport Parity                            | `tests/rc07-hardening.test.js`                            | PASS   |
| `RC07-FLOW-18` | Process Interruption and SIGKILL Escalation       | `tests/rc07-hardening.test.js`                            | PASS   |
| `RC07-FLOW-19` | High-Concurrency Isolation                        | `tests/rc07-hardening.test.js`                            | PASS   |
| `RC07-FLOW-20` | End-to-End Release Candidate Verification         | `tests/rc07-hardening.test.js` & `scripts/verify-rc07.sh` | PASS   |

---

## 5. Quality Gates & Verification Script (`scripts/verify-rc07.sh`)

`scripts/verify-rc07.sh` executes 25 automated gates, failing closed on any error:

- **Gate 1:** Git Branch Check (`feat/rc-07-engineering-aware-tools`)
- **Gate 2:** Frozen Lockfile Install (`pnpm install --frozen-lockfile`)
- **Gate 3:** Code Formatting Check (`pnpm run check:format`)
- **Gate 4:** Static Analysis & Lint Check (`pnpm run lint`)
- **Gate 5:** TypeScript Clean Build (`tsc --build --clean`)
- **Gate 6:** Monorepo Typecheck (`pnpm run typecheck`)
- **Gate 7:** Monorepo Package Build (`pnpm -r run build`)
- **Gate 8:** Dedicated RC-07 Hardening Suite (`tests/rc07-hardening.test.js`)
- **Gate 9:** All 8 RC-07 Owner Suites
- **Gate 10:** Full Monorepo Test Suite (`pnpm run test`)
- **Gate 11:** Git Diff Cleanliness Check (`git diff --check`)
- **Gate 12:** Documentation Completeness (`scripts/check-docs.sh`)
- **Gate 13:** Secret & Credential Scanning (`scripts/check-secrets.sh`)
- **Gate 14:** Dependency Security Audit (`pnpm audit`)
- **Gate 15:** Negative-Control Contiguity & Completeness (`RC07-NEG-001..075`, 75 unique controls)
- **Gate 16:** Positive-Flow Contiguity & Completeness (`RC07-FLOW-01..20`, 20 unique flows)
- **Gate 17:** No Disabled or Deferred RC-07 Tests (`test.skip`, `test.todo`, `describe.skip`, `it.skip`)
- **Gate 18:** Security-Scanner Suppression Check (`gitleaks:allow`, `pragma: allowlist secret`)
- **Gate 19:** Verification Script Integrity Self-Check (no `|| true` masking)
- **Gate 20:** Package Version Consistency (`0.7.0-rc07` across `package.json`, `apps/mcp-server/package.json`, `apps/cli/package.json`, `apps/cli/src/index.ts`, `apps/mcp-server/src/index.ts`)
- **Gate 21:** Health Version & Stage Consistency (`version: 0.7.0-rc07`, `stage: RC-07`)
- **Gate 22:** Required Task-8 Files Check
- **Gate 23:** Final Integration Report Check (`docs/architecture/rc07-final-integration-report.md`)
- **Gate 24:** Scope Document Check (`docs/architecture/rc07-scope-acceptance.md`)
- **Gate 25:** Tool Catalog (exactly 25 tools) and Deterministic Registry (exactly 5 identities)

---

## 6. Release Invariants Verification

- **Production Tool Catalog:** Exactly 25 tools are advertised. Zero tools added in Task 8.
- **Engineering Tools:** All 7 RC-07 tools (`arc_repo_status`, `arc_worktree_status`, `arc_review_diff`, `arc_verify`, `arc_test`, `arc_ci_status`, `arc_stage_evidence`) are fully active.
- **Deterministic Registry:** Exactly 5 entries (`verify-format-v1`, `verify-lint-v1`, `verify-typecheck-v1`, `verify-test-v1`, `arc-test-node-v1`).
- **Audit Store Isolation:** Process state directory is isolated from the audit store root, preventing `AUDIT_STORE_UNRECOGNIZED_ENTRY` errors.
- **No Direct Subprocesses:** All execution is mediated by `ControlledProcessRunner` and sandboxed `GitSubsystem`.
- **Fail-Closed Security:** Policy precedence `DENY > REQUIRE_APPROVAL > ALLOW` is preserved unconditionally.

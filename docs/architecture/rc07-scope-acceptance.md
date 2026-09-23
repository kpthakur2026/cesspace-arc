# RC-07 Scope & Acceptance — Engineering-Aware Tools Architecture Freeze

| Field          | Value                                                                                                                                              |
| :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Stage**      | RC-07                                                                                                                                              |
| **Title**      | Engineering-Aware Tools — Scope, Architecture, Composition Contracts & Acceptance Freeze                                                           |
| **Status**     | **Task-0 Scope Candidate — Frozen Architecture Specification**                                                                                     |
| **Base main**  | `20de2e72bf85dd9178a35881c951f637de9e8ec7`                                                                                                         |
| **Branch**     | `feat/rc-07-engineering-aware-tools`                                                                                                               |
| **Target Ver** | `0.7.0-rc07` (promotion in Task 8 only)                                                                                                            |
| **Target Stg** | `RC-07` (promotion in Task 8 only)                                                                                                                 |
| **Purpose**    | Freeze contracts, composition framework, security boundaries, negative controls, and positive acceptance flows for higher-level engineering tools. |

> **Mandatory Rule:** Implementation MUST NOT begin until this scope is independently reviewed and approved.
> This document is an authoritative normative contract. Every rule herein is designed to be directly code-testable.
> None of the functional tool logic is implemented in Task 0.

---

## 1. Authority and Status

This document is the **authoritative architectural contract** for Stage RC-07 ("Engineering-Aware Tools") of CesSpace ARC.
Upon approval, it establishes the immutable scope, security boundaries, primitive composition rules, negative control catalog, positive acceptance flows, and task ownership matrix for the entire RC-07 milestone.

In accordance with strict Task 0 discipline:

- **Task 0 is documentation-only.** No implementation code, tool handlers, schema additions, or tests are introduced in Task 0.
- **Main branch is untouched.** All work is conducted on `feat/rc-07-engineering-aware-tools` branched from main at commit `20de2e72bf85dd9178a35881c951f637de9e8ec7`.
- **No PR is opened.** Task 0 stops for independent review before Task 1 may commence.

---

## 2. Core Architectural Principle: Strict Composition Over Bypass

RC-07 introduces **Tier-3 Engineering-Aware Tools**: high-level operational capabilities designed to assist autonomous coding agents with repository inspection, diff review, project verification, test suite execution, CI simulation, and release stage evidence aggregation.

### 2.1 The Cardinal Composition Invariant

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                 CARDINAL ARCHITECTURAL PRINCIPLE OF RC-07                        │
│                                                                                  │
│   NO RC-07 tool may reach the operating system, filesystem, Git repository,      │
│   child process subsystem, network stack, or mutation subsystem through a        │
│   weaker path than the corresponding RC-01..RC-06 primitive.                     │
└──────────────────────────────────────────────────────────────────────────────────┘
```

Higher-level engineering tools **MUST COMPOSE** the already-secured, policy-evaluated, jailed, audited, and bounded RC-01..RC-06 primitives. They are strictly prohibited from establishing alternate, direct, or out-of-band execution pathways.

Specifically, RC-07 tools:

1. **MUST NOT** invoke Node's `child_process` directly (`exec`, `execFile`, `spawn`, `fork`). All subprocess execution must pass through `ControlledProcessRunner` / `ITerminalSubsystem` (`packages/terminal`).
2. **MUST NOT** call Node's `fs` or `fs/promises` directly to bypass canonical workspace jailing. All workspace path reads must pass through canonical `JailedFilesystem` (`packages/filesystem`).
3. **MUST NOT** execute raw `git` commands through an unvalidated or ambient child process. All Git operations must traverse the sandboxed, argument-array-bound `GitSubsystem` (`packages/git`).
4. **MUST NOT** instantiate a secondary policy evaluator. All policy checks must be mediated by the authoritative `DeclarativePolicyEngine` (`packages/policy`).
5. **MUST NOT** instantiate a secondary approval manager. All approval lifecycle transitions must flow through the central `ApprovalGate` (`apps/mcp-server/src/approval-gate.ts`).
6. **MUST NOT** instantiate a secondary process registry. Process lifecycle and tracking must use the single `ProcessRegistry` (`packages/processes`).
7. **MUST NOT** instantiate a secondary audit logger or secondary append stream. Every operation must record durable events in the single process-wide `AuditLogger` and persistent store (`packages/audit`).
8. **MUST NOT** bypass durable `STARTED` and `COMPLETED` lifecycle ordering (RC-06 §7, INV-13).
9. **MUST NOT** weaken the fundamental policy precedence: `DENY > REQUIRE_APPROVAL > ALLOW`.
10. **MUST NOT** implicitly authorize `process.cwd()` or accept unvalidated host paths from untrusted callers.
11. **MUST NOT** consume ambient secrets or environment credentials (`GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, etc.).
12. **MUST NOT** expose administrative IPC commands over stdio MCP or remote HTTP endpoints.

---

## 3. Non-Goals & Absolute Prohibitions

The following capabilities are explicitly declared **NON-GOALS** and are prohibited in RC-07:

1. **No Git Mutation in RC-07:**
   RC-07 is strictly an inspection and controlled execution milestone. Task 0 freezes a total ban on introducing new Git mutation operations. Specifically, RC-07 will **NOT** implement:
   - `git commit`
   - `git push`
   - `git checkout` / `git switch`
   - `git reset` (soft, mixed, or hard)
   - `git clean`
   - `git merge`
   - `git rebase`
   - `git tag` mutation
   - Git branch deletion or creation
     Any future requirement for agent Git mutation demands a distinct, dedicated stage and a separately reviewed security architecture.

2. **No Remote CI Provider Network Egress:**
   RC-07 tools operate with **ZERO remote network access**. `arc_ci_status` will NOT query the GitHub API, GitLab API, or any external service. No HTTP client, no ambient token harvesting, and no outbound socket connections are permitted.

3. **No Unrestricted Shell Evaluation:**
   RC-07 tools will NEVER invoke a system shell (`/bin/sh`, `/bin/bash`, `cmd.exe`) with raw string arguments. All subprocess execution uses explicit, array-based token vectors (`argv: string[]`) executed via `execve` with `shell: false`.

4. **No Synthetic or Fabricated Evidence:**
   `arc_stage_evidence` will NEVER synthesize or fabricate stage completion. A green test run alone does not constitute stage approval. All evidence reported must be backed by verifiable, append-only audit records and cryptographic hashes.

5. **No Direct Remote Admin Channel:**
   Administrative IPC remain accessible exclusively via local UNIX domain sockets (`apps/cli/src/admin-client.ts`). Remote MCP clients cannot access admin interfaces.

---

## 4. Frozen RC-07 Tool Contracts

The initial RC-07 tool suite consists of exactly **seven** engineering-aware tools. No tool may be renamed, removed, or added.

| #   | Tool Name             | Execution Mode | Composed Lower-Level Primitives                                             | Default Policy Outcome |
| :-- | :-------------------- | :------------- | :-------------------------------------------------------------------------- | :--------------------- |
| 1   | `arc_repo_status`     | READ-ONLY      | `git_status`, `git_log`, `health`                                           | `ALLOW`                |
| 2   | `arc_worktree_status` | READ-ONLY      | `list_directory`, `read_file`, `git_status`                                 | `ALLOW`                |
| 3   | `arc_review_diff`     | READ-ONLY      | `git_diff`, `git_status`                                                    | `ALLOW`                |
| 4   | `arc_verify`          | EXECUTION      | `run_command`, `process_status`, `process_output`, `terminate_process`      | `REQUIRE_APPROVAL`     |
| 5   | `arc_test`            | EXECUTION      | `run_command`, `process_status`, `process_output`, `terminate_process`      | `REQUIRE_APPROVAL`     |
| 6   | `arc_ci_status`       | READ-ONLY      | `read_file`, `list_directory`, `git_status`, `git_log`                      | `ALLOW`                |
| 7   | `arc_stage_evidence`  | READ-ONLY      | `git_status`, `git_log`, `health`, `packages/audit` verification/inspection | `ALLOW`                |

---

### 4.1 `arc_repo_status`

- **Execution Mode:** READ-ONLY
- **Intent:** Provide a bounded, structured repository status summary for the active workspace, including branch identity, HEAD commit details, clean/dirty state, file change counts, and protected-branch awareness.
- **Input Contract:**
  ```typescript
  export interface ArcRepoStatusRequest {
    workspaceId?: string;
    workspaceRoot?: string;
  }
  ```
- **Output Contract:**
  ```typescript
  export interface ArcRepoStatusResponse {
    branch: string;
    headCommit: {
      hash: string;
      shortHash: string;
      message: string;
      author: string;
      date: string;
    };
    isClean: boolean;
    isProtectedBranch: boolean;
    counts: {
      staged: number;
      unstaged: number;
      untracked: number;
    };
    aheadCount?: number;
    behindCount?: number;
    upstreamBranch?: string;
  }
  ```
- **Security Constraints:**
  - Read-only; causes zero repository mutations.
  - Workspace root strictly validated against authorized workspace records.
  - Protected branches (`main`, `master`, `release/*`) explicitly flagged.
  - Output bounded to a maximum of 64 KiB.

---

### 4.2 `arc_worktree_status`

- **Execution Mode:** READ-ONLY
- **Intent:** Provide bounded worktree status for isolated agent environments, confirming worktree isolation, main repository linkage, branch binding, and lock state without arbitrary filesystem traversal.
- **Input Contract:**
  ```typescript
  export interface ArcWorktreeStatusRequest {
    workspaceId?: string;
    workspaceRoot?: string;
  }
  ```
- **Output Contract:**
  ```typescript
  export interface ArcWorktreeStatusResponse {
    workspaceId: string;
    isWorktree: boolean;
    worktreePath: string;
    mainRepoPath: string;
    branch: string;
    locked: boolean;
    lockReason?: string;
    isDetached: boolean;
    headSha: string;
  }
  ```
- **Security Constraints:**
  - Jailed strictly within authorized workspace boundary.
  - Path traversal (`../`) and external filesystem symlinks rejected.
  - Output bounded to a maximum of 64 KiB.

---

### 4.3 `arc_review_diff`

- **Execution Mode:** READ-ONLY
- **Intent:** Generate a structured, review-oriented unified diff with security annotations, automated secret redaction, and strict buffer truncation. Supports staged, unstaged, and target revision diffs.
- **Input Contract:**
  ```typescript
  export interface ArcReviewDiffRequest {
    mode?: 'staged' | 'unstaged' | 'target';
    targetRevision?: string;
    path?: string;
    maxBytes?: number;
    workspaceId?: string;
  }
  ```
- **Output Contract:**
  ```typescript
  export interface ArcReviewDiffResponse {
    mode: 'staged' | 'unstaged' | 'target';
    targetRevision?: string;
    pathFilter?: string;
    diff: string;
    bytes: number;
    truncated: boolean;
    totalFilesChanged: number;
    fileSummaries: Array<{
      path: string;
      status: 'modified' | 'added' | 'deleted' | 'renamed';
      insertions: number;
      deletions: number;
    }>;
    sensitiveBlocksMasked: number;
  }
  ```
- **Security Constraints:**
  - Composes `git_diff` through `GitSubsystem`.
  - Diff payload filtered through `maskSensitiveDiff` and `purgeSensitiveDiffBlocks`.
  - Max buffer hard-capped at 512 KiB (`MAX_DIFF_BYTES`).
  - Revision argument validated via `validateGitArgument` to prevent command/flag injection.

---

### 4.4 `arc_verify`

- **Execution Mode:** EXECUTION
- **Intent:** Execute an approved, deterministic verification plan (code formatting, linting, typechecking, and test execution) within the authorized workspace. Prohibits arbitrary shell evaluation.
- **Input Contract:**
  ```typescript
  export interface ArcVerifyRequest {
    suite?: 'all' | 'format' | 'lint' | 'typecheck' | 'test';
    fix?: boolean;
    workspaceId?: string;
  }
  ```
- **Output Contract:**
  ```typescript
  export interface ArcVerifyResponse {
    suite: 'all' | 'format' | 'lint' | 'typecheck' | 'test';
    status: 'PASSED' | 'FAILED' | 'TIMED_OUT' | 'CANCELLED';
    totalDurationMs: number;
    steps: Array<{
      stepName: string;
      executable: string;
      args: string[];
      status: 'PASSED' | 'FAILED' | 'SKIPPED' | 'TIMED_OUT';
      exitCode: number | null;
      durationMs: number;
      outputExcerpt: string;
      truncated: boolean;
    }>;
    failedStep?: string;
  }
  ```
- **Security Constraints:**
  - Composes `run_command` via `ControlledProcessRunner`.
  - Commands constructed exclusively from frozen, pre-approved executable/argument definitions (`pnpm`, `npm`, `node`).
  - `shell: false` strictly enforced; zero shell metacharacter expansion.
  - Per-step timeout capped at 30 seconds; overall composite timeout hard-capped at 120 seconds.
  - Defaults to `REQUIRE_APPROVAL` under declarative policy.
  - Response size bounded to 256 KiB.

---

### 4.5 `arc_test`

- **Execution Mode:** EXECUTION
- **Intent:** Execute targeted unit or integration tests under strict subprocess bounds and timeout supervision.
- **Input Contract:**
  ```typescript
  export interface ArcTestRequest {
    testPath?: string;
    filter?: string;
    testRunner?: 'node' | 'pnpm' | 'npm';
    maxDurationMs?: number;
    workspaceId?: string;
  }
  ```
- **Output Contract:**
  ```typescript
  export interface ArcTestResponse {
    testRunner: 'node' | 'pnpm' | 'npm';
    target: string;
    status: 'PASSED' | 'FAILED' | 'TIMED_OUT' | 'CANCELLED';
    exitCode: number | null;
    durationMs: number;
    passedCount?: number;
    failedCount?: number;
    skippedCount?: number;
    outputExcerpt: string;
    truncated: boolean;
    processId: string;
  }
  ```
- **Security Constraints:**
  - Composes `run_command` via `ControlledProcessRunner`.
  - Target `testPath` validated within workspace boundary (`realpath` containment).
  - Target arguments tokenized without shell evaluation.
  - Subprocess timeout hard-capped at 60 seconds (or requested `maxDurationMs` <= 60000).
  - Defaults to `REQUIRE_APPROVAL` under declarative policy.
  - Response size bounded to 256 KiB.

---

### 4.6 `arc_ci_status`

- **Execution Mode:** READ-ONLY
- **Intent:** Provide a local simulation of CI pipeline readiness by inspecting local workflow declarations (`.github/workflows/`), repository status, and local test artifacts. Explicitly prohibits remote network queries.
- **Input Contract:**
  ```typescript
  export interface ArcCiStatusRequest {
    workflowName?: string;
    workspaceId?: string;
  }
  ```
- **Output Contract:**
  ```typescript
  export interface ArcCiStatusResponse {
    localSimulationMode: true;
    workflowsFound: Array<{
      name: string;
      path: string;
      jobCount: number;
      triggers: string[];
    }>;
    localBranch: string;
    headSha: string;
    workingTreeClean: boolean;
    localVerificationMatch: boolean;
    remoteQueryDeferred: true;
    remoteNotice: string;
  }
  ```
- **Security Constraints:**
  - **Zero network egress.** Does not call GitHub or external APIs.
  - Does not read or require `GITHUB_TOKEN` or any credentials.
  - Workflow path inspection strictly confined to `.github/workflows/` within workspace.
  - Response size bounded to 64 KiB.

---

### 4.7 `arc_stage_evidence`

- **Execution Mode:** READ-ONLY
- **Intent:** Aggregate already-existing, verifiable local evidence for a given development stage from Git and the persistent audit ledger. Must never synthesize or fabricate approval.
- **Input Contract:**
  ```typescript
  export interface ArcStageEvidenceRequest {
    targetStage: string;
    workspaceId?: string;
  }
  ```
- **Output Contract:**
  ```typescript
  export interface ArcStageEvidenceResponse {
    stage: string;
    timestamp: string;
    repository: {
      branch: string;
      headSha: string;
      isClean: boolean;
    };
    auditLedger: {
      sequence: number;
      integrity: 'VERIFIED' | 'FAILED';
      lastCheckpointSequence: number | null;
      storeId: string;
    };
    verification: {
      scriptPresent: boolean;
      scriptPath?: string;
      verifiedLocally: boolean;
    };
    acceptanceMet: boolean;
    references: {
      auditStoreId: string;
      terminalRecordHash: string;
      checkpointHash?: string;
    };
    disclaimer: string;
  }
  ```
- **Security Constraints:**
  - Read-only; composes existing audit ledger state and Git status.
  - Anti-fabrication invariant: A passing test command does NOT constitute stage approval.
  - Large artifacts (audit segments, checkpoints) are referenced by cryptographic hash rather than included raw.
  - Response size bounded to 512 KiB.

---

## 5. Composition Architecture & Primitive Ownership Matrix

The table below defines the authoritative mapping between existing ARC primitives and RC-07 composite tools.

| Existing ARC Primitive | `arc_repo_status` | `arc_worktree_status` | `arc_review_diff` | `arc_verify` | `arc_test` | `arc_ci_status` | `arc_stage_evidence` |
| :--------------------- | :---------------: | :-------------------: | :---------------: | :----------: | :--------: | :-------------: | :------------------: |
| `health`               |      COMPOSE      |           -           |         -         |      -       |     -      |        -        |       COMPOSE        |
| `list_directory`       |         -         |        COMPOSE        |         -         |      -       |     -      |     COMPOSE     |          -           |
| `read_file`            |         -         |        COMPOSE        |         -         |      -       |     -      |     COMPOSE     |          -           |
| `search_files`         |         -         |           -           |         -         |      -       |     -      |        -        |          -           |
| `search_text`          |         -         |           -           |         -         |      -       |     -      |        -        |          -           |
| `git_status`           |      COMPOSE      |        COMPOSE        |      COMPOSE      |      -       |     -      |     COMPOSE     |       COMPOSE        |
| `git_diff`             |         -         |           -           |      COMPOSE      |      -       |     -      |        -        |          -           |
| `git_log`              |      COMPOSE      |           -           |         -         |      -       |     -      |     COMPOSE     |       COMPOSE        |
| `system_status`        |         -         |           -           |         -         |      -       |     -      |        -        |          -           |
| `run_command`          |         -         |           -           |         -         |   COMPOSE    |  COMPOSE   |        -        |          -           |
| `process_status`       |         -         |           -           |         -         |   COMPOSE    |  COMPOSE   |        -        |          -           |
| `process_output`       |         -         |           -           |         -         |   COMPOSE    |  COMPOSE   |        -        |          -           |
| `terminate_process`    |         -         |           -           |         -         |   COMPOSE    |  COMPOSE   |        -        |          -           |
| `audit verification`   |         -         |           -           |         -         |      -       |     -      |        -        |       COMPOSE        |

---

## 6. Answers to Mandatory Security Questions

The following 20 answers constitute binding architectural requirements for RC-07:

1. **Which RC-07 tools can run processes?**
   Only `arc_verify` and `arc_test`. The remaining five tools (`arc_repo_status`, `arc_worktree_status`, `arc_review_diff`, `arc_ci_status`, `arc_stage_evidence`) are strictly read-only and invoke zero subprocesses directly.

2. **Which exact executables may they invoke?**
   Only executables explicitly whitelisted in the command policy and executable resolver for the workspace: `pnpm`, `npm`, and `node`. Invocation of arbitrary executables, shell binaries (`sh`, `bash`, `zsh`), or interpreters outside the whitelist is denied.

3. **How are arguments constructed without shell injection?**
   Arguments are passed strictly as discrete array tokens (`string[]`). Subprocess invocation uses `execFile` / `execve` with `shell: false`. No concatenation of shell command strings is permitted. Arguments are validated against a strict token regex rejecting shell metacharacters (`;`, `&`, `|`, `` ` ``, `$()`, `>`, `<`, `\n`, `\r`).

4. **Which lower-level primitive owns cwd validation?**
   `ControlledProcessRunner` (`packages/terminal`) and `JailedFilesystem` (`packages/filesystem`). Any `cwd` specified by or for a composite tool must resolve strictly within the canonical authorized `workspaceRoot` via `realpath`. Composite tools cannot override or escape this check.

5. **How are timeout/output/concurrency limits inherited?**
   Limits are enforced directly by `ControlledProcessRunner` and `ProcessRegistry`:
   - Subprocess execution buffer cap: `MAX_PROCESS_BUFFER_BYTES` (512 KiB).
   - Subprocess output read cap: `MAX_OUTPUT_READ_BYTES` (128 KiB).
   - Workspace concurrency limit: `CONCURRENCY_LIMITS.MAX_RUNNING_PER_WORKSPACE` (4 processes).
   - Overall composite execution timeout: Hard-capped at 120 seconds.

6. **How is actor/session/workspace identity preserved?**
   The calling `CompleteActor` context (`clientId`, `clientType`, `sessionId`, `deviceId`) and validated `targetWorkspaceRecord` (`workspaceId`, `workspaceRoot`) are passed down through the composite execution framework to every composed primitive. No primitive may run with an anonymous, ambient, or elevated identity.

7. **Which tools are eligible for REQUIRE_APPROVAL?**
   `arc_verify` and `arc_test` are eligible for `REQUIRE_APPROVAL` (and default to it in production configurations). The read-only tools default to `ALLOW` for authorized workspaces, but remain subject to declarative policy matching.

8. **How is approval redemption propagated through a composite tool?**
   An approval token is supplied at the composite invocation boundary via the `_arc_approval` parameter. The composite tool validates and consumes this approval token through the central `ApprovalGate`. Sub-operations executed as part of the approved deterministic plan inherit the parent approval context without requiring secondary prompts, provided they strictly match the pre-evaluated plan. Any deviation results in immediate fail-closed termination.

9. **How many audit records are produced for a composite operation?**
   Exactly ONE primary durable `STARTED` record and ONE primary durable `COMPLETED` (or `DENIED` / `FAILED`) record for the composite tool invocation itself, plus individual audit records for each composed primitive call. All records share the single, process-wide monotonic sequence space.

10. **How are parent/child operation IDs represented?**
    The composite tool invocation generates a root UUIDv4 `operationId`. Composed sub-operations include `parentOperationId: <root-operationId>` in their audit metadata and lifecycle records, forming an explicit, verifiable DAG in the audit log.

11. **How does a composite tool behave if a child operation fails?**
    Fail-closed. If an internal primitive fails, the composite operation halts execution immediately (unless designed to record a step outcome, such as a failed lint step in `arc_verify`), marks remaining steps as `SKIPPED`, and emits its terminal `COMPLETED` audit record with `execution.status: 'FAILED'` and the sanitized error details.

12. **How does it behave if audit durability fails?**
    Strict fail-closed:
    - If durable persistence of the composite's `STARTED` record fails, execution halts immediately with zero subsystem calls made.
    - If durable persistence of the `COMPLETED` record fails, the server latches into `DEGRADED_AUDIT_FAILURE` and refuses subsequent privileged calls, refusing to mask unevidenced work as successful.

13. **How is partial execution represented?**
    In the composite response payload, the `status` is set to `'FAILED'` (or `'PARTIAL'`), and the `steps` array indicates the exact status of each step: `'PASSED'`, `'FAILED'`, or `'SKIPPED'`. The audit trail durably documents all completed sub-operations before the failure point.

14. **How are secrets/env values prevented from entering result/evidence output?**
    All composite tool output is processed through the centralized redaction engine (`packages/audit`), `scrubOutput` (`packages/processes`), and `maskSensitiveDiff` (`packages/git`). Environment variables are suppressed, credential patterns are masked, and absolute host paths are sanitized.

15. **What is the maximum response size for each tool?**
    - `arc_repo_status`: 64 KiB
    - `arc_worktree_status`: 64 KiB
    - `arc_review_diff`: 512 KiB (`MAX_DIFF_BYTES`)
    - `arc_verify`: 256 KiB
    - `arc_test`: 256 KiB
    - `arc_ci_status`: 64 KiB
    - `arc_stage_evidence`: 512 KiB

16. **What is the maximum execution time for composite tools?**
    - Read-only tools (`arc_repo_status`, `arc_worktree_status`, `arc_review_diff`, `arc_ci_status`, `arc_stage_evidence`): 15 seconds.
    - Execution tools (`arc_verify`, `arc_test`): 120 seconds hard timeout.

17. **How are cancelled/interrupted composite operations represented?**
    If cancelled by the caller or terminated due to timeout, all running child processes receive `SIGTERM` followed by `SIGKILL` if unyielding. The composite operation terminates and emits a terminal audit record with `execution.status: 'TIMED_OUT'` or `'FAILED'`, accompanied by code `OPERATION_CANCELLED` or `PROCESS_TIMEOUT`.

18. **How are remote and stdio semantics kept identical?**
    All 7 composite tools are registered in the unified `ArcMcpServer` tool dispatch table. Invocations from stdio and remote Streamable HTTP over TLS 1.3 execute through the identical `executeToolCallPipeline`, enforcing identical schemas, workspace bounds, policy checks, approval gates, and durable audit records.

19. **Does `arc_ci_status` perform network access in RC-07?**
    **NO.** Remote network access is explicitly prohibited and deferred. `arc_ci_status` operates exclusively in local simulation mode by inspecting local repository files and workflow definitions.

20. **What evidence may `arc_stage_evidence` report versus merely reference?**
    - **Reported:** Bounded summaries of repository identity (branch, HEAD SHA, clean status), audit sequence count, verification script presence, and test outcome summary.
    - **Referenced:** Large raw artifacts (full diffs, complete audit segments, signed checkpoint files) are referenced by SHA-256 digest and sequence number, never embedded raw.

---

## 7. Negative Security Control Catalog (`RC07-NEG-001`..`075`)

All 75 controls are mandatory, immutable, and assigned to a single future task owner.

### Category 1: Composite Architecture & Framework (Task 1 Owner)

- **`RC07-NEG-001`**: Composite tool invoked without authenticated caller identity (`clientId`, `sessionId`). Rejected with `UNAUTHENTICATED`.
- **`RC07-NEG-002`**: Composite tool invoked with unbound or unapproved `workspaceId`. Rejected with `WORKSPACE_NOT_FOUND`.
- **`RC07-NEG-003`**: Composite tool attempts recursive self-invocation. Call cycle detected and blocked with `RECURSIVE_INVOCATION_DENIED`.
- **`RC07-NEG-004`**: Composite tool attempts to bypass global audit availability gate when audit runtime is degraded. Refused with `AUDIT_UNAVAILABLE`.
- **`RC07-NEG-005`**: Composite tool execution fails to persist durable `STARTED` record. Execution aborted; zero child operations invoked.
- **`RC07-NEG-006`**: Composite tool execution fails to persist durable `COMPLETED` record. Server latches into `DEGRADED_AUDIT_FAILURE`.
- **`RC07-NEG-007`**: Child operation in composite fails to propagate `parentOperationId`. Rejected by framework invariant check.
- **`RC07-NEG-008`**: Malformed reserved `_arc_approval` parameter passed to composite tool. Denied with `INVALID_REQUEST_SCHEMA`.
- **`RC07-NEG-009`**: Expired approval token presented for composite execution. Rejected with `APPROVAL_EXPIRED`.
- **`RC07-NEG-010`**: Already-consumed approval token presented for composite execution. Rejected with `APPROVAL_ALREADY_CONSUMED`.

### Category 2: Repository & Worktree Status Invariants (Task 2 Owner)

- **`RC07-NEG-011`**: `arc_repo_status` invoked on a workspace directory that is not a valid Git repository. Fails with `GIT_REPOSITORY_NOT_FOUND`.
- **`RC07-NEG-012`**: `arc_repo_status` attempts to execute mutating Git subcommands (`commit`, `clean`, `reset`). Blocked by read-only contract.
- **`RC07-NEG-013`**: `arc_repo_status` response size exceeds 64 KiB cap. Output truncated cleanly with `truncated: true`.
- **`RC07-NEG-014`**: `arc_worktree_status` targets a path outside the canonical workspace root. Fails with `PATH_OUTSIDE_WORKSPACE`.
- **`RC07-NEG-015`**: `arc_worktree_status` encounters symlinked `.git` file resolving outside workspace. Fails with `SYMLINK_ESCAPE_DETECTED`.
- **`RC07-NEG-016`**: `arc_worktree_status` invoked with directory traversal argument (`../`). Rejected before resolution.
- **`RC07-NEG-017`**: `arc_repo_status` masks protected branch status on `main` or `release/*`. Invariant violation; protected branch must be flagged.
- **`RC07-NEG-018`**: Unregistered workspace argument passed to `arc_worktree_status`. Rejected with `WORKSPACE_UNREGISTERED`.

### Category 3: Review Diff, Truncation & Redaction (Task 3 Owner)

- **`RC07-NEG-019`**: `arc_review_diff` target revision contains shell metacharacters (`;`, `|`, `&`). Blocked by argument validation.
- **`RC07-NEG-020`**: `arc_review_diff` target revision starts with a hyphen (flag injection attempt, e.g. `--exec`). Rejected with `INVALID_GIT_ARGUMENT`.
- **`RC07-NEG-021`**: `arc_review_diff` path argument attempts directory traversal (`../../etc/passwd`). Rejected with `PATH_OUTSIDE_WORKSPACE`.
- **`RC07-NEG-022`**: `arc_review_diff` output contains unredacted API key or secret token. Blocked; central redaction masks secret.
- **`RC07-NEG-023`**: `arc_review_diff` output contains unredacted private SSH/TLS key block. Blocked; secret masking purges block.
- **`RC07-NEG-024`**: `arc_review_diff` diff size exceeds `MAX_DIFF_BYTES` (512 KiB). Hard truncation enforced with `truncated: true`.
- **`RC07-NEG-025`**: `arc_review_diff` requested with invalid mode (neither `staged`, `unstaged`, nor `target`). Rejected by schema validation.
- **`RC07-NEG-026`**: `arc_review_diff` attempts to diff against sensitive credential files (`.env`, `id_rsa`). Path blocked by sensitive file blacklist.
- **`RC07-NEG-027`**: `arc_review_diff` invoked on non-git workspace. Rejected with `GIT_REPOSITORY_NOT_FOUND`.

### Category 4: Controlled Verification Execution (`arc_verify`) (Task 4 Owner)

- **`RC07-NEG-028`**: `arc_verify` attempts to invoke an unwhitelisted binary (e.g. `/bin/bash`, `curl`, `wget`). Denied by executable policy.
- **`RC07-NEG-029`**: `arc_verify` execution plan contains raw shell string instead of token array. Rejected by framework.
- **`RC07-NEG-030`**: `arc_verify` step arguments contain shell injection tokens (`; rm -rf`, `&& calc`). Blocked by argument validator.
- **`RC07-NEG-031`**: `arc_verify` step execution exceeds per-step timeout (30s). Process terminated via SIGTERM/SIGKILL; step marked `TIMED_OUT`.
- **`RC07-NEG-032`**: `arc_verify` cumulative duration exceeds 120s limit. Composite operation halted with `COMPOSITE_TIMEOUT`.
- **`RC07-NEG-033`**: `arc_verify` invoked without approval when policy dictates `REQUIRE_APPROVAL`. Emits approval request; no process spawned.
- **`RC07-NEG-034`**: `arc_verify` step output exceeds stdout/stderr buffer limits. Output truncated cleanly without memory exhaustion.
- **`RC07-NEG-035`**: `arc_verify` attempts to inherit sensitive parent environment variables. Sanitized environment enforced.
- **`RC07-NEG-036`**: First step of `arc_verify` fails; framework must NOT continue executing subsequent steps. Remaining marked `SKIPPED`.
- **`RC07-NEG-037`**: `arc_verify` executed with unknown suite name. Rejected with `INVALID_REQUEST_SCHEMA`.

### Category 5: Controlled Test Execution (`arc_test`) (Task 5 Owner)

- **`RC07-NEG-038`**: `arc_test` target test path points outside the authorized workspace. Blocked with `PATH_OUTSIDE_WORKSPACE`.
- **`RC07-NEG-039`**: `arc_test` filter argument contains shell control characters. Rejected by argument validator.
- **`RC07-NEG-040`**: `arc_test` attempts to invoke unapproved test runner binary. Denied by executable policy.
- **`RC07-NEG-041`**: `arc_test` execution exceeds requested `maxDurationMs` (or default 60s). Subprocess terminated; marked `TIMED_OUT`.
- **`RC07-NEG-042`**: `arc_test` caller attempts to set `maxDurationMs` exceeding 60000 ms. Clamped or rejected by schema.
- **`RC07-NEG-043`**: `arc_test` attempts concurrent execution beyond workspace limit (4 processes). Enqueued or rejected with `CONCURRENCY_EXCEEDED`.
- **`RC07-NEG-044`**: `arc_test` child process leaks past composite termination. Orphan process caught and reaped by `ProcessRegistry`.
- **`RC07-NEG-045`**: `arc_test` output stream contains private key or secret. Redacted by `scrubOutput` before response formatting.
- **`RC07-NEG-046`**: `arc_test` invoked without required approval token. Yields `REQUIRE_APPROVAL` refusal.

### Category 6: CI Status, Trust & Network Boundary (`arc_ci_status`) (Task 6 Owner)

- **`RC07-NEG-047`**: `arc_ci_status` attempts outbound HTTP/HTTPS connection to api.github.com. Connection refused; zero network access.
- **`RC07-NEG-048`**: `arc_ci_status` attempts to read `GITHUB_TOKEN` or `GH_TOKEN` from environment. Suppressed / rejected.
- **`RC07-NEG-049`**: `arc_ci_status` workflow path points outside `.github/workflows/`. Traversal rejected with `PATH_OUTSIDE_WORKSPACE`.
- **`RC07-NEG-050`**: `arc_ci_status` parses malformed YAML workflow. Handled gracefully with sanitized error; no unhandled crash.
- **`RC07-NEG-051`**: `arc_ci_status` fabricates green CI status based solely on local git clean state. Invariant violation; local simulation clearly flagged.
- **`RC07-NEG-052`**: `arc_ci_status` attempts to execute workflow action binaries locally. Execution prohibited; read-only inspection only.
- **`RC07-NEG-053`**: `arc_ci_status` response size exceeds 64 KiB cap. Output bounded.

### Category 7: Stage Evidence Integrity & Truthfulness (`arc_stage_evidence`) (Task 7 Owner)

- **`RC07-NEG-054`**: `arc_stage_evidence` fabricates stage approval when audit ledger has zero evidence. Rejected with `EVIDENCE_NOT_MET`.
- **`RC07-NEG-055`**: `arc_stage_evidence` treats a single green test execution as sufficient for stage approval. Prohibited by anti-fabrication invariant.
- **`RC07-NEG-056`**: `arc_stage_evidence` attempts to read an unverified, tampered audit ledger. Invariant check halts; reports `integrity: FAILED`.
- **`RC07-NEG-057`**: `arc_stage_evidence` embeds uncompressed multi-megabyte audit segment into response. Prohibited; hashes referenced only.
- **`RC07-NEG-058`**: `arc_stage_evidence` reports success on a dirty Git working tree. Must accurately report `isClean: false`.
- **`RC07-NEG-059`**: `arc_stage_evidence` reports success on an unverified checkpoint signature. Invariant violation; reports unverified.
- **`RC07-NEG-060`**: `arc_stage_evidence` requested for nonexistent stage name. Rejected with `STAGE_NOT_FOUND`.
- **`RC07-NEG-061`**: `arc_stage_evidence` output exceeds 512 KiB cap. Strict truncation enforced.

### Category 8: Cross-Cutting Hardening, Parity & Threat Invariants (Task 8 Owner)

- **`RC07-NEG-062`**: Composite tool invocation via remote Streamable HTTP bypasses Layer C admission limiter. Enforced; charged 1 token.
- **`RC07-NEG-063`**: Remote client presents revoked session token to composite tool. Denied with `INVALID_SESSION_TOKEN`.
- **`RC07-NEG-064`**: Remote client attempts to invoke composite tool without valid device enrollment. Denied with `UNAUTHENTICATED`.
- **`RC07-NEG-065`**: Discrepancy between stdio and remote response schema for any composite tool. Parity check fails closed.
- **`RC07-NEG-066`**: Direct `child_process` import detected in any RC-07 tool implementation file. Static verification rejects build.
- **`RC07-NEG-067`**: Direct `fs` import bypassing `JailedFilesystem` detected in RC-07 implementation. Static verification rejects build.
- **`RC07-NEG-068`**: Git mutation subcommand (`commit`, `push`, `rebase`, etc.) detected in codebase. Static check fails closed.
- **`RC07-NEG-069`**: Failure of a child operation causes parent composite to hang indefinitely. Hard composite timeout aborts operation.
- **`RC07-NEG-070`**: Crash during composite execution leaves orphan process in host OS. Process table sweep reaps orphan on restart.
- **`RC07-NEG-071`**: Redaction pipeline fails to redact sensitive pattern in error message of composite tool. Redaction invariant enforces mask.
- **`RC07-NEG-072`**: Ambient credentials present in environment when composite tools execute. Stripped before subprocess creation.
- **`RC07-NEG-073`**: Concurrent execution of `arc_verify` and `arc_test` exceeds aggregate process pool limit. Second execution waits or fails closed.
- **`RC07-NEG-074`**: Client disconnects during streaming composite response. Child processes terminated immediately via SIGTERM.
- **`RC07-NEG-075`**: Tampered `_arc_approval` signature presented. Rejected with `APPROVAL_INTEGRITY_COMPROMISED`.

---

## 8. Positive Acceptance Flow Catalog (`RC07-FLOW-01`..`20`)

All 20 positive flows are mandatory and assigned to future task owners.

| Flow ID        | Title                                             | Description                                                                                       | Owner  |
| :------------- | :------------------------------------------------ | :------------------------------------------------------------------------------------------------ | :----- |
| `RC07-FLOW-01` | Composite Framework Lifecycle Execution           | Execute minimal composite tool; verify durable `STARTED` and `COMPLETED` records linked by ID.    | Task 1 |
| `RC07-FLOW-02` | Composite Approval Redemption Flow                | Request `REQUIRE_APPROVAL` tool, approve via admin IPC, redeem token; operation succeeds.         | Task 1 |
| `RC07-FLOW-03` | Repository Status Query                           | Query `arc_repo_status` on clean feature branch; receive accurate branch, commit, clean status.   | Task 2 |
| `RC07-FLOW-04` | Dirty Repository Status Detection                 | Query `arc_repo_status` with staged and unstaged edits; verify accurate file counts.              | Task 2 |
| `RC07-FLOW-05` | Worktree Status Verification                      | Query `arc_worktree_status` on linked worktree; receive valid mainRepoPath and worktree binding.  | Task 2 |
| `RC07-FLOW-06` | Bounded Review Diff Generation (Unstaged)         | Generate review diff for modified files; receive structured diff within byte limits.              | Task 3 |
| `RC07-FLOW-07` | Staged Review Diff with Target Revision           | Generate review diff comparing staged changes against `HEAD`; verify insertions/deletions count.  | Task 3 |
| `RC07-FLOW-08` | Review Diff Automated Secret Redaction            | Generate diff containing simulated credential; verify credential is automatically masked.         | Task 3 |
| `RC07-FLOW-09` | Successful Verification Suite Plan (`arc_verify`) | Execute `arc_verify` for lint/typecheck; all steps pass; receive detailed structured report.      | Task 4 |
| `RC07-FLOW-10` | Partial Verification Suite Failure Handling       | Execute `arc_verify` where lint fails; lint marked `FAILED`, subsequent steps marked `SKIPPED`.   | Task 4 |
| `RC07-FLOW-11` | Controlled Test Execution (`arc_test`)            | Execute targeted unit test file via `arc_test`; receive pass/fail summary and excerpt.            | Task 5 |
| `RC07-FLOW-12` | Test Timeout and Child Process Cleanup            | Execute long-running test via `arc_test`; timeout triggers SIGTERM; process cleaned up cleanly.   | Task 5 |
| `RC07-FLOW-13` | Local CI Simulation Status (`arc_ci_status`)      | Query `arc_ci_status`; verify `.github/workflows` detected, local simulation mode confirmed.      | Task 6 |
| `RC07-FLOW-14` | Stage Evidence Aggregation (`arc_stage_evidence`) | Generate stage evidence for completed stage; verify ledger references and git status summary.     | Task 7 |
| `RC07-FLOW-15` | Composite Child Audit Provenance Tracking         | Inspect audit ledger after composite run; verify child records reference `parentOperationId`.     | Task 7 |
| `RC07-FLOW-16` | Remote Streamable HTTP Parity                     | Execute composite tool over remote Streamable HTTP over TLS 1.3; verify identical result.         | Task 8 |
| `RC07-FLOW-17` | Stdio Transport Parity                            | Execute composite tool over stdio transport; verify identical result and schema structure.        | Task 8 |
| `RC07-FLOW-18` | Process Interruption and SIGKILL Escalation       | Cancel running composite execution; verify SIGTERM followed by SIGKILL if process resists.        | Task 8 |
| `RC07-FLOW-19` | High-Concurrency Isolation                        | Run multiple composite read-only queries concurrently; verify clean isolation and no crosstalk.   | Task 8 |
| `RC07-FLOW-20` | End-to-End Release Candidate Verification         | Run full verification script `scripts/verify-rc07.sh`; all gates, negative controls & flows pass. | Task 8 |

---

## 9. Implementation Breakdown (Tasks 1..8)

RC-07 is strictly partitioned into **eight** implementation tasks following Task 0:

| Task  | Title                                                  | Scope & Deliverables                                                                                                  | Negative Controls Owned | Positive Flows Owned |
| :---- | :----------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------- | :---------------------- | :------------------- |
| **1** | Shared Composite-Tool Execution Framework              | Common composite runner, pre-admission validation, parent/child audit lifecycle, approval propagation, failure modes. | `RC07-NEG-001`..`010`   | `RC07-FLOW-01`..`02` |
| **2** | `arc_repo_status` & `arc_worktree_status`              | Repository summary, branch identity, clean/dirty detection, worktree validation, protected-branch flags.              | `RC07-NEG-011`..`018`   | `RC07-FLOW-03`..`05` |
| **3** | `arc_review_diff`                                      | Review diff generation, staged/unstaged/target modes, buffer cap (512 KiB), automated secret masking, file summaries. | `RC07-NEG-019`..`027`   | `RC07-FLOW-06`..`08` |
| **4** | `arc_verify`                                           | Structured verification runner, whitelisted command plans (`pnpm`, `npm`), step sequencing, timeout & cancellation.   | `RC07-NEG-028`..`037`   | `RC07-FLOW-09`..`10` |
| **5** | `arc_test`                                             | Targeted test runner, test path validation within workspace, output streaming & truncation, process supervision.      | `RC07-NEG-038`..`046`   | `RC07-FLOW-11`..`12` |
| **6** | `arc_ci_status`                                        | Local CI workflow parser, simulation reporting, zero-network enforcement, credential isolation.                       | `RC07-NEG-047`..`053`   | `RC07-FLOW-13`       |
| **7** | `arc_stage_evidence` & Cross-Tool Evidence Integration | Evidence aggregation, audit ledger verification linking, cryptographic references, anti-fabrication invariants.       | `RC07-NEG-054`..`061`   | `RC07-FLOW-14`..`15` |
| **8** | Security Hardening, Acceptance, Version & PR Readiness | Full test suite (all 75 NEG, all 20 FLOW), static bypass audits, remote/stdio parity, version bump `0.7.0-rc07`.      | `RC07-NEG-062`..`075`   | `RC07-FLOW-16`..`20` |

---

## 10. Definition of Done (RC-07)

Stage RC-07 is complete when and only when all of the following conditions are verified:

1. **Tool Contracts Implemented:** All seven higher-level engineering tools (`arc_repo_status`, `arc_worktree_status`, `arc_review_diff`, `arc_verify`, `arc_test`, `arc_ci_status`, `arc_stage_evidence`) are fully implemented and conform to their frozen schemas.
2. **Strict Composition Enforced:** Zero direct `child_process` or `fs` bypasses exist. All tools strictly compose lower-level ARC primitives (`packages/terminal`, `packages/filesystem`, `packages/git`, `packages/audit`, `packages/policy`).
3. **No Alternate Execution Paths:** Policy evaluation, approval gating, workspace jailing, and durable audit lifecycle cannot be bypassed by any composite tool.
4. **All Negative Controls Pass:** All 75 frozen negative controls (`RC07-NEG-001` through `RC07-NEG-075`) are implemented as automated tests and pass cleanly.
5. **All Positive Flows Pass:** All 20 frozen positive acceptance flows (`RC07-FLOW-01` through `RC07-FLOW-20`) are implemented as automated tests and pass cleanly.
6. **Zero Regression:** All pre-existing RC-01 through RC-06 regression tests (1841 tests) remain green.
7. **Version & Stage Target:** Version is promoted to `0.7.0-rc07` and health stage reports `RC-07` (in Task 8).
8. **Verification Script:** `scripts/verify-rc07.sh` exists, runs all test suites, negative controls, linting, formatting, typechecking, and secret scanning, and passes with exit code 0.
9. **Zero Vulnerabilities:** `pnpm audit` reports 0 vulnerabilities.
10. **Independent Review & Approval:** Independent peer review approves each task commit and the final PR before merge.

---

## 11. Deferred Items Catalog

The following items are explicitly deferred to future release candidates:

1. **Remote CI Provider API Querying:** Querying GitHub Actions or external CI providers via network HTTP requests is deferred until a formal remote network egress and credential proxy architecture is designed.
2. **Git Mutation Operations:** Agent-initiated `git commit`, `git push`, branch creation/deletion, and merge/rebase operations are deferred until a dedicated branch mutation and approval architecture is specified.
3. **Interactive Debugger / REPL Primitives:** Interactive streaming terminal sessions (e.g. interactive gdb or node repl) remain deferred beyond RC-07.

# RC-04 Scope & Acceptance Criteria — CesSpace ARC

> **Document:** Stage Specification & Quality Gates
> **Status:** SCOPE FREEZE — FINAL SECURITY CONTRACT
> **Target Stage:** `RC-04` — Declarative Policy Engine & Human Approval State Machine
> **Base:** `main` (Verified RC-03 Main Merge at `cff5ce6ac88380341fd69781ab30057b2d165aa3`)

---

## 1. Stage Objective & Governance

The objective of **RC-04** is to establish the declarative policy evaluation engine and the human-in-the-loop approval state machine for CesSpace ARC.

Building upon the verified read-only inspection baseline (RC-01), bounded terminal execution (RC-02), and the verified core filesystem mutation primitives (RC-03), RC-04 provides:

1. **Declarative Policy Specification:** Strict YAML and JSON declarative policy document parsing, schema validation, canonical normalization, and deterministic multi-criteria AST matching.
2. **Permanent Hierarchical Evaluation:** Enforced two-layer authorization architecture with absolute, immutable precedence: `DENY > REQUIRE_APPROVAL > ALLOW`.
3. **Human Approval State Machine:** Complete race-safe lifecycle management (`PENDING`, `APPROVED`, `REJECTED`, `EXPIRED`, `CONSUMED`) for privileged operations requiring human elevation.
4. **Exact Cryptographic Bindings:** High-entropy one-time approval tokens bound immutably to exact execution payload hashes (`executionPayloadHash`), actor session context, workspace root identity, and normalized policy configuration digests (`policyHash`).
5. **Local Administrative Channel:** Dedicated out-of-band administrative interface (`arc approve`, `arc reject`, `arc approvals list`, `arc policy test`) accessible exclusively to trusted local operators over authenticated local IPC.
6. **Controlled Execution of Gated Mutations:** Authorized, atomic execution of previously gated RC-03 mutation tools strictly upon successful redemption and consumption of a valid human approval token.

### 1.1. Core Invariants Maintained

Every policy evaluation and approval redemption in RC-04 must satisfy the following inviolable security invariants:

1. **Absolute Precedence of Permanent Denials:** A human approval token **MUST NEVER** override a `DENY`. If an operation evaluates to `DENY` under the permanent security kernel or operator policy, it is rejected immediately, regardless of any past or present approval token.
2. **Two-Layer Authorization Separation:**
   - **Layer 1 (Permanent Security Kernel):** Hard-coded, non-overridable security invariants (authenticated caller, registered workspace containment, path jailing, sensitive file deny patterns, Git metadata protection, prohibited commands, default-deny).
   - **Layer 2 (Operator Declarative Policy):** Operator-defined rules that may classify otherwise-admissible actions as `DENY`, `REQUIRE_APPROVAL`, or `ALLOW`. Declarative policy may make execution more restrictive, but can **never** weaken, override, or bypass Layer 1 controls.
3. **Mandatory Mutation Approval Floor:** All five RC-03 filesystem mutation tools (`create_file`, `write_file`, `apply_patch`, `delete_file`, `move_file`) have a mandatory minimum policy classification of `REQUIRE_APPROVAL` (or `DENY`). An otherwise-valid declarative rule may contain effect `ALLOW`, but candidate `ALLOW` evaluated against any mutation tool is unconditionally clamped at code level to `REQUIRE_APPROVAL`. Automatic execution of file mutations without human approval is strictly impossible in RC-04.
4. **Out-of-Band Administrative Trust Boundary:** AI agents communicating via MCP have **zero administrative authority**. An agent cannot approve requests, reject requests, list approvals, mint tokens, inspect approval state, or bypass verification. Approval administration is NOT an MCP tool, has no HTTP/SSE remote endpoint, and has no non-loopback TCP listener. Administrative operations are strictly reserved for local human operators through `apps/cli` using an authenticated local IPC channel. If the implementation cannot distinguish the trusted operator from an untrusted local client, it must fail closed rather than assuming "same UID means human".
5. **Atomic One-Time Token Consumption:** Approval tokens are single-use cryptographic capabilities. Transition from `APPROVED` to `CONSUMED` is atomic and occurs **before** subsystem invocation. If execution fails downstream, the token remains consumed and cannot be replayed.
6. **Cryptographic Payload & Context Binding:** Approvals are cryptographically bound to the canonical execution payload hash (`executionPayloadHash`), actor identity (`clientId`, `clientType`, `sessionId`, `deviceId`), target workspace (`workspaceId` and SHA-256 `workspaceRootHash`), and the normalized `policyHash`. Tampering with any parameter, path, or payload invalidates the approval immediately.
7. **Strict 300-Second Absolute TTL:** Approvals are subject to an immutable, server-enforced Time-To-Live (TTL) of 300 seconds from initial creation (`expiresAt = createdAt + 300s`). TTL does not restart on operator approval. Expired approvals fail closed with `APPROVAL_EXPIRED`.
8. **Audit Data Minimization & Bounded Token Storage:** Raw approval tokens necessarily exist transiently during generation and delivery to the operator CLI. ARC itself does not persist or intentionally log the raw token. Raw tokens MUST NOT be retained in `ApprovalStateManager` and MUST NOT be placed in audit logs or error state; only the fixed 32-byte `tokenDigest` (SHA-256 of raw token bytes) is retained. Audit and internal diagnostics use bounded enumerated reason codes only.

---

## 2. Authoritative Architecture Reconciliation & Package Boundaries

RC-04 does not introduce a secondary authorization system or standalone server. It extends the existing foundational monorepo packages and control plane architecture:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Untrusted AI Agent (MCP Client)                      │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ MCP Request (Standard Tools)
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│            apps/mcp-server (ArcMcpServer / Tool Handlers)              │
│  - Schema Admission & Input Length Validation                          │
│  - _arcApproval Parameter Extraction & Pre-policy Stripping           │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│            packages/policy (SecurityKernel & Policy Engine)             │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Layer 1: Permanent Security Kernel (Hard Invariants)             │  │
│  └───────────────────────────────┬──────────────────────────────────┘  │
│                                  │ Passes Layer 1                      │
│                                  ▼                                     │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Layer 2: Declarative Policy Evaluator (Deterministic AST Matcher)│  │
│  │ Outcome: DENY | REQUIRE_APPROVAL | ALLOW                         │  │
│  │ Mutation Tool Floor Enforcement: ALLOW -> REQUIRE_APPROVAL       │  │
│  └───────────────────────────────┬──────────────────────────────────┘  │
│                                  │ Outcome == REQUIRE_APPROVAL         │
│                                  ▼                                     │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Approval State Machine & Token Verifier                          │  │
│  │ - Exact Payload Hash Revalidation (executionPayloadHash)         │  │
│  │ - Actor, Workspace & Normalized Policy Binding Checks            │  │
│  │ - Record Lock: Expiry Check & Atomic State Transitions           │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└──────────────────┬─────────────────────────────────┬───────────────────┘
                   │                                 │
                   │ Execution Authorized            │ Out-of-Band Admin (Local IPC)
                   ▼                                 ▼
┌──────────────────────────────────────┐   ┌─────────────────────────────┐
│ Execution Subsystems                 │   │ apps/cli                    │
│ - packages/filesystem (Mutations)    │   │ - arc approve <requestId>   │
│ - packages/terminal (Processes)      │   │ - arc reject <requestId>    │
│ - packages/git (Read inspection)     │   │ - arc approvals list        │
│                                      │   │ - arc policy test <file>    │
└──────────────────────────────────────┘   └──────────────┬──────────────┘
                                                          │ Local Operator
                                                          ▼
                                           ┌─────────────────────────────┐
                                           │ Trusted Human Operator      │
                                           └─────────────────────────────┘
```

### 2.1. Monorepo Package Allocation

- **`packages/protocol`:**
  - Definitive TypeScript interfaces for declarative policy schemas (`PolicyDocument`, `PolicyRule`, `PolicyMatcher`, `NormalizedPolicy`).
  - Approval state machine types (`ApprovalState`, `ApprovalRequest`, `ApprovalBinding`, `ApprovalTokenDigest`).
  - Formal client control structures (`ArcApprovalControlObject`: `{ requestId: string; token: string }`).
  - Canonical error codes: `APPROVAL_REQUIRED`, `APPROVAL_EXPIRED`, `APPROVAL_REJECTED`, `POLICY_PARSE_ERROR`, `POLICY_LOAD_ERROR`, `RESOURCE_EXHAUSTED`.
  - Structured audit event types: `APPROVAL_REQUESTED`, `APPROVAL_GRANTED`, `APPROVAL_REJECTED`, `APPROVAL_EXPIRED`, `APPROVAL_CONSUMED`, `APPROVED_EXECUTION_SUCCEEDED`, `APPROVED_EXECUTION_FAILED`.
  - Enumerated internal diagnostic reason codes: `TOKEN_MISMATCH`, `PAYLOAD_BINDING_MISMATCH`, `ACTOR_BINDING_MISMATCH`, `WORKSPACE_BINDING_MISMATCH`, `POLICY_BINDING_MISMATCH`, `ALREADY_CONSUMED`.
- **`packages/policy`:**
  - `DeclarativePolicyEngine`: Strict YAML/JSON parser, schema validator, AST matchers, rule precedence resolver, and canonical `policyHash` compiler.
  - `ApprovalStateManager`: In-memory volatile approval store, record-level concurrency locks, high-entropy ID and token generator, SHA-256 digest verifier, state machine transitions, byte quota accountant, and atomic consumption logic.
  - Integrated `SecurityKernel.evaluate()` workflow enforcing Layer 1 before Layer 2, followed by mutation approval floor enforcement.
- **`apps/mcp-server`:**
  - MCP tool dispatch pipeline integration:
    - Pre-admission extraction of `_arcApproval` parameter.
    - Three-way scenario routing (absent -> PENDING / `APPROVAL_REQUIRED`; malformed -> `INVALID_REQUEST_SCHEMA`; invalid -> `APPROVAL_REJECTED`).
    - Token redemption handling: validates `_arcApproval`, passes token digest to `ApprovalStateManager`, and dispatches execution upon verified consumption.
- **`apps/cli`:**
  - Local operator commands: `arc approve`, `arc reject`, `arc approvals list`, `arc approvals inspect`, `arc policy test`.
  - Authenticated local IPC channel to the running server.
- **`packages/audit`:**
  - Automated redaction of `_arcApproval.token` and raw execution payloads from audit logs.
  - Cryptographic hash-chain continuity for all approval lifecycle events.

---

## 3. Two-Layer Authorization Architecture

To eliminate the risk of operator configuration errors opening critical system vulnerabilities, ARC establishes a strict two-layer evaluation hierarchy:

### 3.1. Layer 1: Permanent Security Kernel (Hard Invariants)

Layer 1 contains non-overridable, compile-time security controls implemented directly in `packages/policy` and `packages/filesystem`:

1. **Authentication Requirement:** Unauthenticated callers are permanently denied (`deny-unauthenticated-caller`).
2. **Workspace Jailing:** Access outside authorized workspace roots is permanently denied (`deny-unregistered-workspace`, `PATH_ESCAPES_ROOT`).
3. **Sensitive Credential Blacklist:** Access to `.env*`, `.ssh/**`, `.aws/**`, `.gnupg/**`, private keys (`.pem`, `.key`, `id_rsa`), and system root paths (`/etc`, `/proc`, `/sys`) is permanently denied (`deny-mutation-sensitive-path`, `ACCESS_DENIED`).
4. **Git Metadata Protection:** All filesystem mutation targeting `.git/**` is permanently denied (`deny-mutation-sensitive-path`).
5. **Filesystem Structural Invariants:** Path traversal (`..`), symbolic link following on mutation, and multi-hardlink mutation are permanently denied (`UNSAFE_SYMLINK`, `HARDLINK_DETECTED`).
6. **Command Blacklist:** Prohibited administrative and dangerous commands (e.g. `rm -rf /`, `sudo`, `mkfs`, raw shell wrappers) are permanently denied (`FORBIDDEN_COMMAND`).

**Invariant:** Layer 1 is evaluated **first**. If Layer 1 produces `DENY`, evaluation terminates immediately. Declarative policies and human approvals have **zero power** to bypass Layer 1.

### 3.2. Layer 2: Operator Declarative Policy

If an operation passes Layer 1 without a denial, it enters Layer 2. Layer 2 evaluates operator-authored policy rules configured via YAML or JSON. Rules evaluate tool names, workspace-relative path patterns, parsed command structures, and Git actions:

- An operation may be assigned `DENY`, `REQUIRE_APPROVAL`, or `ALLOW`.
- Declarative policy can make security **stricter** (e.g. requiring approval for specific read tools or denying commands in specific subdirectories), but can **never** permit what Layer 1 forbids.

---

## 4. Absolute Policy Precedence

RC-04 freezes the immutable precedence hierarchy:

$$\mathbf{DENY} > \mathbf{REQUIRE\_APPROVAL} > \mathbf{ALLOW}$$

1. **Absolute Denial:** If any matching rule or kernel gate specifies `DENY`, the final policy outcome is `DENY`.
2. **Human Approval Floor:** If no `DENY` matches, but one or more matching rules (or mandatory kernel floors) specify `REQUIRE_APPROVAL`, the final outcome is `REQUIRE_APPROVAL`.
3. **Strict Allowance:** An operation resolves to `ALLOW` if and only if:
   - It is not denied by Layer 1 or Layer 2.
   - It is not subject to the mutation approval floor.
   - It matches an explicit `ALLOW` rule (or the default baseline policy).

### 4.1. Policy-Change Redemption Semantics (Stale Approvals Voided)

Human approval does **not** grant permanent or immutable authority across policy changes:

- At the moment of token redemption, the approval record's stored `policyHash` is compared against the server's currently effective `policyHash`.
- **Policy Mismatch Behavior:** If `_arcApproval` is presented and the effective policy identity/hash differs from the approval record:
  1. Approval redemption **FAILS**.
  2. The token is **NOT consumed** as a successful authorization.
  3. The operation does **NOT execute** through that stale approval.
  4. The request returns `APPROVAL_REJECTED` (with safe internal diagnostic reason code `POLICY_BINDING_MISMATCH`).
  5. A stale approval **never** becomes authority under a changed policy.
- Following a policy change, the caller may submit a **NEW** ordinary request without the stale approval. That new request is evaluated entirely fresh under the currently active policy:
  - For file mutations, the mandatory approval floor still guarantees `REQUIRE_APPROVAL` (or `DENY`).
  - If the new request evaluates to `REQUIRE_APPROVAL`, a fresh approval request is created with the new `policyHash`.

---

## 5. RC-03 Mutation Approval Floor

To guarantee that file-modifying side-effects never occur autonomously, RC-04 establishes a permanent approval floor for all five mutation tools:

| Tool Name     | Allowed RC-04 Outcomes     | Forbidden RC-04 Outcomes |
| :------------ | :------------------------- | :----------------------- |
| `create_file` | `DENY`, `REQUIRE_APPROVAL` | `ALLOW`                  |
| `write_file`  | `DENY`, `REQUIRE_APPROVAL` | `ALLOW`                  |
| `apply_patch` | `DENY`, `REQUIRE_APPROVAL` | `ALLOW`                  |
| `delete_file` | `DENY`, `REQUIRE_APPROVAL` | `ALLOW`                  |
| `move_file`   | `DENY`, `REQUIRE_APPROVAL` | `ALLOW`                  |

**Normative Evaluation Rule:**

- An otherwise-valid declarative rule in an operator policy document may contain `effect: ALLOW`.
- However, evaluation of any `RC03_MUTATION_TOOL` has a code-enforced mandatory floor of `REQUIRE_APPROVAL`.
- **Floor Clamping:**
  $$\text{candidate Outcome} == \text{ALLOW} \land \text{toolName} \in \text{RC03\_MUTATION\_TOOLS} \implies \text{REQUIRE\_APPROVAL}$$
- ARC does **not** reject the entire policy document merely because a general `ALLOW` rule happens to match a mutation tool. The floor is enforced automatically in code after rule precedence resolution.
- `arc policy test` provides a safe diagnostic indicator informing the operator that the mutation floor was applied to clamp the outcome to `REQUIRE_APPROVAL`.

---

## 6. Preservation of Existing RC-01 / RC-02 Behavior

RC-04 maintains 100% backward compatibility with verified prior stages:

1. **RC-01 Read-Only Inspection:** In the default built-in policy configuration, all 9 RC-01 inspection tools (`health`, `system_status`, `list_directory`, `read_file`, `search_files`, `search_text`, `git_status`, `git_diff`, `git_log`) continue to resolve to `ALLOW` within authorized workspaces. An operator declarative policy may elevate specific sensitive files or directories to `REQUIRE_APPROVAL` or `DENY`.
2. **RC-02 Controlled Terminal Execution:** RC-02 process lifecycle tools (`process_status`, `process_output`, `terminate_process`) and bounded commands evaluated by `validateCommandRequest` continue to execute under their verified constraints. Operator declarative policy rules can enforce `REQUIRE_APPROVAL` on specific binaries or argument patterns.

---

## 7. Declarative Policy Document Format & Schema

Declarative policies are authored in **YAML** (preferred) or **JSON**.

### 7.1. Workspaces in Declarative Policy Are NOT Authorization

**Critical Security Requirement:**

- The `workspaces` section of an operator policy **MUST NEVER** register or authorize a new filesystem root.
- Authorization of workspace directories is established exclusively by `WorkspaceRegistry` through trusted server configuration and startup arguments.
- Entries in the policy `workspaces` block may only:
  1. Reference already-authorized workspace IDs.
  2. Optionally assert an expected canonical workspace root identity.
- If a policy names an unknown workspace ID or its asserted root does not match the server's registered canonical workspace:
  - Policy loading **fails closed** (`health.status = 'UNHEALTHY'`).
- Declarative policy can restrict operations within an authorized workspace; it **cannot** enlarge the set of authorized workspace roots.

### 7.2. Normative Structure (Version 1.0)

```yaml
version: '1.0'
metadata:
  name: 'example-production-policy'
  description: 'Strict project security policy'
  lastModified: '2026-09-18T12:00:00Z'

workspaces:
  - id: 'primary-workspace'
    # References an existing workspace registered in WorkspaceRegistry.
    # Policy CANNOT authorize new filesystem paths.

rules:
  - id: 'deny-critical-config-write'
    effect: 'DENY'
    description: 'Prevent modifying configuration files'
    tools:
      - 'write_file'
      - 'apply_patch'
      - 'delete_file'
    paths:
      patterns:
        - 'config/**'
        - '*.config.js'

  - id: 'deny-hostile-binaries'
    effect: 'DENY'
    description: 'Deny network fetch utilities'
    tools:
      - 'run_command'
    commands:
      blockedBinaries:
        - 'curl'
        - 'wget'

  - id: 'require-approval-terminal-scripts'
    effect: 'REQUIRE_APPROVAL'
    description: 'Require human approval for executing build scripts'
    tools:
      - 'run_command'
    commands:
      allowedBinaries:
        - 'npm'
        - 'pnpm'

  - id: 'allow-source-file-mutations'
    effect: 'ALLOW' # Evaluates to REQUIRE_APPROVAL via mandatory mutation floor
    description: 'Source code modifications require approval under mutation floor'
    tools:
      - 'create_file'
      - 'write_file'
      - 'apply_patch'
    paths:
      patterns:
        - 'src/**'
```

### 7.3. Rule Field Taxonomy

- **`id`** _(string, required)_: Unique identifier `^[a-zA-Z0-9_-]{1,64}$`.
- **`effect`** _(enum, required)_: `'DENY' | 'REQUIRE_APPROVAL' | 'ALLOW'`.
- **`description`** _(string, optional)_: Human-readable rationale (max 256 chars).
- **`tools`** _(string[], optional)_: Exact tool names to match. Max 128 items.
- **`paths.patterns`** _(string[], optional)_: Workspace-relative glob patterns. Max 128 items.
- **`commands.allowedBinaries`** _(string[], optional)_: Positive executable basenames (valid ONLY on `ALLOW` or `REQUIRE_APPROVAL` rules). Max 128 items.
- **`commands.blockedBinaries`** _(string[], optional)_: Negative executable basenames (valid ONLY on `DENY` rules). Max 128 items.
- **`git.protectedBranches`** _(string[], optional)_: Protected Git ref patterns. Max 128 items.
- **`git.actions`** _(string[], optional)_: Specific Git actions. Max 128 items.

---

## 8. Strict Parser Security & Resource Bounds

To prevent Denial of Service, ReDoS, and parser confusion attacks, the declarative policy parser must satisfy strict constraints:

1. **Safe Parser Implementation:** Uses a safe, standards-compliant YAML/JSON parser without execution capabilities. Custom YAML tags (e.g. `!run`, `!include`), JavaScript expressions, code evaluation, and environment-variable expansion are strictly forbidden.
2. **Deterministic File Constraints:**
   - **Document Size Limit:** Maximum **256 KiB** UTF-8 (`262,144 bytes`).
   - **Maximum Rules:** Maximum **256** rules per document.
   - **Maximum Items Per Array:** Maximum **128** items per matcher list.
   - **Maximum Pattern Length:** Maximum **1024** characters per pattern or glob string.
3. **Strict Schema Validation:**
   - Unknown properties anywhere in the document cause immediate schema rejection.
   - Duplicate rule IDs cause immediate rejection.
   - Duplicate keys in YAML mappings cause immediate rejection.
   - Specifying both `allowedBinaries` and `blockedBinaries` in the same rule causes immediate rejection.
   - Specifying `blockedBinaries` on an `ALLOW` or `REQUIRE_APPROVAL` rule causes immediate rejection.
   - Specifying `allowedBinaries` on a `DENY` rule causes immediate rejection.
4. **Self-Contained Policies:** Policy files are strictly self-contained. No external files, network endpoints, or recursive imports may be loaded.

---

## 9. Deterministic Matcher Semantics

Matchers inside a rule follow strict Boolean logic:

1. **Conjunctive Categories (AND):** Different matcher categories within a rule are combined with logical **AND**.
   - Example: A rule specifying `tools: ['write_file']` and `paths.patterns: ['src/**']` matches if and only if the tool is `write_file` **AND** the target path matches `src/**`.
2. **Disjunctive Array Entries (OR):** Within an individual category array, entries are combined with logical **OR**.
   - Example: `tools: ['create_file', 'write_file']` matches if the tool is `create_file` **OR** `write_file`.

### 9.1. Path Glob Grammar (RC-04 v1)

To prevent path confusion and ReDoS, RC-04 establishes an exact, restricted path glob specification:

1. **Normalization:** Path separators are always normalized `/`.
2. **Case Sensitivity:** Path matching is strictly case-sensitive.
3. **Workspace Relative:** Patterns and target paths must be workspace-relative.
   - Patterns containing leading `/` are **rejected by the schema**.
   - Patterns containing traversal segments (`..`) are **rejected by the schema**.
4. **Pattern Syntax:**
   - `*`: Matches zero or more characters within a single path segment (never crosses `/`).
   - `?`: Matches exactly one character other than `/`.
   - `**`: Matches zero or more complete path segments (e.g. `src/**` matches `src/a.ts`, `src/nested/b.ts`, and `src/`).
5. **Forbidden Features:**
   - No brace expansion (e.g. `{ts,js}` is forbidden and rejected).
   - No extended glob syntax (`+(...)`, `@(...)` are forbidden and rejected).
   - No regular expressions.
   - No backslash escape sequences.
6. **Pure In-Memory Evaluation:** Matching is performed solely on normalized string representations without filesystem traversal or stat syscalls.
7. **Syntax Enforcement:** The parser/compiler must reject unsupported pattern syntax rather than silently misinterpreting it.

### 9.2. Command Matcher Semantics

RC-04 v1 establishes unambiguous, deterministic command matching:

1. **Positive Matcher (`commands.allowedBinaries`):**
   - Valid **only** on rules with `effect: ALLOW` or `effect: REQUIRE_APPROVAL`.
   - Matches if the executable basename matches any entry in the array.
2. **Negative Matcher (`commands.blockedBinaries`):**
   - Valid **only** on rules with `effect: DENY`.
   - Matches if the executable basename matches any entry in the array.
3. **Mutual Exclusivity:** A rule **must not** specify both `allowedBinaries` and `blockedBinaries`.
4. **Basename Comparison:** Matching is performed strictly against the executable basename (e.g. `pnpm`), not shell strings or full paths.
5. **Layer 1 Invariant:** Permanent RC-02 forbidden binaries (`sudo`, `mkfs`, etc.) remain non-overridable Layer 1 denials regardless of declarative rules.

---

## 10. Rule Evaluation & Deterministic Precedence Resolution

Policy evaluation is completely order-independent: the physical order of rules in the YAML/JSON document has zero impact on the security decision.

### 10.1. Evaluation Algorithm

1. Evaluate Layer 1 (Permanent Security Kernel). If Layer 1 denies, return `DENY` with the matching kernel rule ID.
2. For each rule in the declarative policy, evaluate whether all defined matcher categories match the request.
3. Collect all matching rules:
   - If any matching rule has `effect === 'DENY'`, candidate outcome is `DENY`.
   - Else if any matching rule has `effect === 'REQUIRE_APPROVAL'`, candidate outcome is `REQUIRE_APPROVAL`.
   - Else if any matching rule has `effect === 'ALLOW'`, candidate outcome is `ALLOW`.
   - Else (no rule matched), see Section 11.
4. **Enforce Mutation Floor:** If candidate outcome is `ALLOW` but `toolName` is in `RC03_MUTATION_TOOLS`, force outcome to `REQUIRE_APPROVAL`.
5. **Deterministic Tie-Breaking:** If multiple matching rules share the winning effect, the canonical `matchingRuleId` is selected as the **lexicographically smallest** rule ID.

---

## 11. Fallback Semantics: Explicit Policy vs Built-in Default

1. **Explicit Operator Policy Configured:** When an operator provides an external policy file, ARC operates in strict Default-Deny mode. If an operation does not match any rule, the outcome is `DENY` with rule ID `default-deny-no-rule-matched`.
2. **No Policy File Configured:** If no external policy is specified, ARC operates under its **Built-in Compatibility Policy**:
   - RC-01 read-only tools resolve to `ALLOW`.
   - RC-02 safe execution commands resolve to `ALLOW`.
   - RC-03 mutation tools resolve to `REQUIRE_APPROVAL`.
   - Unregistered or hostile requests resolve to `DENY`.

---

## 12. Fail-Closed Invalid Policy Health Behavior

When an external policy file is explicitly configured by the operator:

1. **Unhealthy State on Load Failure:** If the policy file is corrupted, malformed, unreadable, schema-invalid, references unknown workspaces, or violates parser constraints:
   - `health.status = 'UNHEALTHY'`
   - `policyEngineActive = false`
2. **Callable Diagnostic Health Probe:** The `health` and `system_status` diagnostic endpoints remain callable to allow operator diagnosis.
3. **Fail-Closed Tool Execution:** All tool executions other than minimal health/status diagnostics fail closed with `POLICY_LOAD_ERROR` or `POLICY_PARSE_ERROR`.
4. **No Fallback to Built-in Policy:** When an operator explicitly provides an invalid policy, ARC **must NOT** fall back to the open/built-in compatibility policy. Doing so would violate the operator's intent to enforce custom constraints.
5. **Information Leakage Prevention:** Raw policy file contents, parser stack traces, and local filesystem paths are suppressed from client responses.

---

## 13. Human Approval State Machine

The approval state machine governs the lifecycle of requests that evaluate to `REQUIRE_APPROVAL`:

```
               ┌──────────────┐
               │   PENDING    │
               └──────┬───────┘
         ┌────────────┼────────────┐
         │ (Approve)  │ (Reject)   │ (TTL Expiry)
         ▼            ▼            ▼
   ┌──────────┐ ┌──────────┐ ┌──────────┐
   │ APPROVED │ │ REJECTED │ │ EXPIRED  │
   └────┬─────┘ └──────────┘ └──────────┘
        │
   ┌────┴─────┐
   │          │ (TTL Expiry)
   ▼          ▼
┌──────────┐ ┌──────────┐
│ CONSUMED │ │ EXPIRED  │
└──────────┘ └──────────┘
```

### 13.1. States & Transitions

- **`PENDING`**: Request created; awaiting human operator review.
  - Allowed transitions: `-> APPROVED`, `-> REJECTED`, `-> EXPIRED`.
- **`APPROVED`**: Trusted human operator granted permission; one-time token generated; awaiting agent redemption.
  - Allowed transitions: `-> CONSUMED`, `-> EXPIRED`.
- **`REJECTED`**: Trusted human operator explicitly denied the request.
  - **Terminal state**. Zero transitions out.
- **`EXPIRED`**: TTL elapsed (300 seconds from initial creation) without successful consumption.
  - **Terminal state**. Zero transitions out.
- **`CONSUMED`**: Token redeemed and verified; operation dispatched to execution subsystem.
  - **Terminal state**. Zero transitions out. Replay is strictly impossible.

**Invariant:** Transition into any terminal state (`REJECTED`, `EXPIRED`, `CONSUMED`) is final. State can never return to `PENDING`, and expired or consumed requests can never be reactivated.

### 13.2. State-Race Winner Rules & Concurrency Serialization

All transitions for an approval request occur under a strict, record-level atomic serialization boundary (in-process mutex or atomic conditional update):

1. **Pre-Transition Expiry Check:** Before executing any non-terminal state transition, server clock is checked (`Date.now() >= expiresAt`). If expired, the record transitions to `EXPIRED`, and the attempted transition fails.
2. **`PENDING` Approve vs Reject Race:**
   - The first valid transition acquired under lock wins (`APPROVED` or `REJECTED`).
   - The competing operation observes a terminal or non-eligible state and fails. No second transition occurs.
3. **`PENDING` Approve vs Expiry Race:**
   - If `Date.now() >= expiresAt` when lock is acquired, `EXPIRED` wins. No approval occurs and no token is generated.
   - If `Date.now() < expiresAt`, the approval transition succeeds and the token is minted.
4. **`APPROVED` Consume vs Expiry Race:**
   - If `Date.now() >= expiresAt` before atomic consumption lock is acquired, `EXPIRED` wins. Consumption fails with `APPROVAL_EXPIRED`.
   - If `Date.now() < expiresAt`, atomic consumption succeeds, status transitions to `CONSUMED`, and tool execution proceeds.
5. **`APPROVED` Reject Attempt:**
   - Forbidden. `REJECTED` is reachable only from `PENDING`. Once approved, an operator cannot reject; the request can only be consumed or expire.
6. **Approval After Expiry:**
   - Strictly impossible. If status is `EXPIRED`, `arc approve` fails with an expiry error and no token is minted.
7. **Creation Race Safety:** Duplicate `PENDING` creation is atomic: concurrent identical requests resolve to the same active record without creating multiple pending entries.

---

## 14. Cryptographic Identifiers & Token Architecture

### 14.1. Approval Request ID (`approvalRequestId`)

- Generated using `crypto.randomBytes(16).toString('hex')` (128 bits of cryptographic entropy, 32 lowercase hex characters).
- Opaque identifier returned to the MCP client in the initial `APPROVAL_REQUIRED` error details.
- Grants **zero authority**. It serves purely as a lookup key for the pending approval record.

### 14.2. One-Time Approval Token & Frozen Token-Digest Construction

- **Raw Token:** 32 cryptographically random bytes encoded as 64 lowercase hexadecimal characters (256 bits of cryptographic entropy).
- **Stored Verifier:**
  $$\text{tokenDigest} = \text{SHA-256}(\text{rawTokenBytes})$$
  Stored as a fixed 32-byte binary buffer (or 64 hex characters).
- **No HMAC Secret Required:** Because the underlying raw token already provides 256 bits of cryptographic entropy, an unkeyed SHA-256 digest is cryptographically irreversible and eliminates the complexity of secondary secret-key management.
- **Timing-Safe Verification:**
  1. The client supplies a bounded UTF-8 token string (max 128 bytes).
  2. The server decodes or hashes the supplied token bytes into a 32-byte candidate digest.
  3. Verification performs a constant-time comparison:
     $$\text{crypto.timingSafeEqual}(\text{storedDigest}, \text{candidateDigest})$$
  4. Raw token strings are **never** compared directly with `===` or `==`.

### 14.3. Raw Token Memory Lifetime & Bounded Claims

- The raw token necessarily exists transiently in memory during generation in `ApprovalStateManager` and output in the local CLI.
- **Storage Constraint:** The raw token **MUST NOT** be retained in `ApprovalStateManager` after issuance. Only `tokenDigest` is stored.
- **Zero Persistence:** The raw token **MUST NOT** be persisted to disk, stored in databases, or included in audit logs, error messages, or debug events.
- **Memory Bounding:** ARC acknowledges that standard JavaScript runtime environments cannot guarantee cryptographic memory zeroization of garbage-collected strings. ARC's guarantee is that ARC itself does not retain, persist, or intentionally log the raw token.

---

## 15. Reserved Agent Request Control Object (`_arcApproval`)

Agents supply approval credentials via a reserved top-level parameter object:

```json
{
  "path": "src/index.ts",
  "content": "console.log('updated');",
  "expectedHash": "0123456789abcdef...",
  "overwrite": true,
  "_arcApproval": {
    "requestId": "a8f3b2c1d4e5f60718293a4b5c6d7e8f",
    "token": "<256-bit-opaque-token-string>"
  }
}
```

### 15.1. Control Object Handling Rules & Anti-Oracle Bounding

1. **Input Length Bounding:** The `token` string is strictly bounded to a maximum of **128 UTF-8 bytes**. Oversized inputs are rejected immediately with `INVALID_REQUEST_SCHEMA`.
2. **Schema Admission:**
   ```typescript
   export const ArcApprovalSchema = z
     .object({
       requestId: z.string().regex(/^[0-9a-fA-F]{32}$/, 'Invalid approval request ID format'),
       token: z.string().min(32).max(128),
     })
     .strict();
   ```
3. **Three Distinct Request Scenarios:**
   - **Scenario A: `_arcApproval` Absent & Policy Evaluates to `REQUIRE_APPROVAL`:**
     - Creates or reuses a `PENDING` request.
     - Returns `isError: true` with error code `APPROVAL_REQUIRED` and opaque `approvalRequestId`.
   - **Scenario B: `_arcApproval` Structurally Malformed:**
     - Missing `requestId` or `token`, invalid types, oversized token string, or unexpected properties.
     - Returns `INVALID_REQUEST_SCHEMA`.
     - **DOES NOT** create or reuse an approval request.
   - **Scenario C: `_arcApproval` Structurally Admitted But Redemption Invalid:**
     - Unknown request ID, token mismatch, payload mismatch, actor mismatch, workspace mismatch, policy mismatch, or expired/already consumed.
     - Returns generic `APPROVAL_REJECTED`.
     - **DOES NOT** create or reuse a `PENDING` request.
4. **Subsystem Isolation:** Before passing business parameters to the underlying subsystem (`FilesystemSubsystem`, `ControlledProcessRunner`), `_arcApproval` is **stripped**. Subsystems never see tokens or approval objects.
5. **Audit Redaction:** `_arcApproval.token` is unconditionally redacted from audit parameters and replaced with metadata `{ approvalRequestId: ..., tokenProvided: true }`.
6. **Rejection of Bypass Properties:** Unofficial properties such as `approvalToken`, `approved`, `bypassApproval`, `autoApprove`, `force`, `admin`, or `sudo` remain strictly forbidden and cause immediate schema rejection.

---

## 16. Initial `REQUIRE_APPROVAL` Flow & Error Semantics

When a tool request evaluates to `REQUIRE_APPROVAL` and does not provide valid `_arcApproval`:

1. **Pending Record Creation / Deduplication:** The server checks if an active `PENDING` request already exists with identical `executionPayloadHash`. If found, it returns the existing `approvalRequestId` and the **remaining TTL** in seconds (does not reset to 300 seconds). If not, it creates a new record in `ApprovalStateManager`.
2. **Structured Audit Log:** Emits an `APPROVAL_REQUESTED` audit record.
3. **Safe Error Response:** Returns MCP tool failure (`isError: true`) with structured JSON:
   ```json
   {
     "code": "APPROVAL_REQUIRED",
     "message": "Action requires human approval. Request ID: a8f3b2c1d4e5f60718293a4b5c6d7e8f",
     "details": {
       "approvalRequestId": "a8f3b2c1d4e5f60718293a4b5c6d7e8f",
       "toolName": "create_file",
       "expiresInSeconds": 300
     }
   }
   ```
4. **Execution Gate:** No subsystem primitive is invoked. Zero file modifications occur.

---

## 17. Approval Time-To-Live (300-Second Absolute TTL)

1. Every approval record stores an immutable expiration timestamp:
   $$\text{expiresAt} = \text{createdAt} + 300\,000\text{ ms}$$
2. **No TTL Reset on Approval:** Operator approval does **not** grant a fresh 300 seconds. The expiration timestamp remains strictly bound to initial creation.
3. **Server Clock Authority:** The server clock (`Date.now()`) is the sole authoritative time source. Client timestamps are ignored.
4. **Expiry Enforcement:** Any transition attempted at timestamp $T \ge \text{expiresAt}$ transitions the record to `EXPIRED` and returns `APPROVAL_EXPIRED`.

---

## 18. Complete `executionPayloadHash` Bindings

To prevent Parameter Tampering and Confused Deputy attacks, an approval is bound immutably to the complete canonical execution payload hash:

$$\text{executionPayloadHash} = \text{SHA-256}(\text{canonicalJson}(\text{payloadToSign}))$$

Where `payloadToSign` consists of:

1. **`schemaVersion`**: Canonical protocol schema version (e.g. `'1.0'`).
2. **`toolName`**: Canonical tool name (e.g. `'create_file'`).
3. **`parameters`**: Exact validated business parameters (including full content bytes or patch string, but excluding `_arcApproval`).
4. **`actor.clientId`**: Calling agent client identifier.
5. **`actor.clientType`**: Calling agent client type.
6. **`actor.sessionId`**: Active session identifier (when present).
7. **`actor.deviceId`**: Caller device identifier (when present).
8. **`workspaceId`**: Target authorized workspace identifier.
9. **`workspaceRootHash`**: SHA-256 digest of the server-resolved canonical registered workspace-root path. (The raw host path is never exposed in the binding).
10. **`policyHash`**: Canonical SHA-256 digest of the validated, normalized effective policy.

**Tampering Invariant:** If an attacker modifies even a single character in the file content, patch body, path, actor context, workspace, or flags between approval and redemption, the recomputed `executionPayloadHash` will mismatch, causing immediate rejection with `APPROVAL_REJECTED` (`PAYLOAD_BINDING_MISMATCH`).

### 18.1. Exact Definition of `policyHash`

`policyHash` is defined as the SHA-256 digest over the canonical JSON string of the validated, normalized effective policy representation:

$$\text{policyHash} = \text{SHA-256}(\text{canonicalJson}(\text{normalizedPolicy}))$$

Normalization is deterministic and order-independent:

1. **Rule Sorting:** Rules are sorted lexicographically by rule `id`.
2. **Key Canonicalization:** All JSON object keys are canonicalized in lexicographical order.
3. **Array Normalization:** Order-insensitive matcher arrays (`tools`, `paths.patterns`, `allowedBinaries`, `blockedBinaries`) are deterministically sorted and deduplicated.
4. **Explicit Defaults:** Default values are represented consistently.
5. **Format Independence:** Comments, whitespace, indentation, and YAML-vs-JSON syntax differences produce identical `policyHash` values if the effective normalized rules are identical.
6. **Built-in Policy:** The built-in compatibility policy has a canonical normalized model from which its fixed `policyHash` is derived.

---

## 19. Mandatory Context Bindings

Approval validation enforces four mandatory context checks:

1. **Actor Binding:** The actor redeeming the token must match the actor who requested it (`clientId`, `clientType`, `sessionId`, `deviceId`). An approval requested by Session A cannot be redeemed by Session B.
2. **Workspace Binding:** The target workspace of the redemption request must match the approved `workspaceId` and canonical `workspaceRootHash`.
3. **Policy Binding:** The effective `policyHash` at redemption time must match the approved `policyHash`. If policy changed, redemption fails with `APPROVAL_REJECTED` (`POLICY_BINDING_MISMATCH`).
4. **Payload Binding:** The computed `executionPayloadHash` of the redemption request must match the approved record's hash.

---

## 20. Pre-Execution Re-evaluation & Atomic One-Time Consumption

During token redemption:

```
[Agent submits tool call with _arcApproval]
                     │
                     ▼
  1. Validate MCP schema & extract _arcApproval
     (Malformed -> INVALID_REQUEST_SCHEMA; Absent -> PENDING flow)
                     │
                     ▼
  2. Evaluate Layer 1 (Permanent Security Kernel)
     ├── DENY ──────────────────────────────────────► Reject with POLICY_DENIED
     └── PASS
          │
          ▼
  3. Re-evaluate Layer 2 (Declarative Policy)
     ├── DENY ──────────────────────────────────────► Reject with POLICY_DENIED
     └── REQUIRE_APPROVAL
          │
          ▼
  4. Lookup approval record by requestId
     ├── Not found / Expired / Rejected ───────────► Reject with APPROVAL_REJECTED / EXPIRED
     └── Found (State == APPROVED)
          │
          ▼
  5. Validate Cryptographic Digest, Payload Hash, Actor, Workspace & Policy Bindings
     ├── Any mismatch ─────────────────────────────► Reject with APPROVAL_REJECTED
     └── Valid
          │
          ▼
  6. Atomic State Transition: APPROVED -> CONSUMED
     ├── Already consumed (race condition) ────────► Reject with APPROVAL_REJECTED
     └── Transition successful
          │
          ▼
  7. Strip _arcApproval and execute in Subsystem
     ├── Subsystem execution succeeds ─────────────► Emit APPROVED_EXECUTION_SUCCEEDED
     └── Subsystem execution fails ────────────────► Emit APPROVED_EXECUTION_FAILED
```

**Atomicity Guarantee:** The transition `APPROVED -> CONSUMED` is performed synchronously under a record lock. Exactly one competing thread can successfully transition an approval record. Subsequent calls with the same token fail closed.

---

## 21. Request Deduplication Semantics

To prevent flooding the approval store with identical requests, repeated invocations of the same pending action are deduplicated:

$$\text{dedupKey} = \text{executionPayloadHash}$$

- Because `executionPayloadHash` already binds `toolName`, `parameters`, `workspaceId`, `workspaceRootHash`, `actor.clientId`, `actor.clientType`, `actor.sessionId`, `actor.deviceId`, and `policyHash`, two different sessions or actors will **never** share a pending approval record.
- If an active record with status `PENDING` matches the `dedupKey`, ARC returns the existing `approvalRequestId` and remaining TTL without creating a duplicate record.
- Once a request reaches a terminal state (`REJECTED`, `EXPIRED`, `CONSUMED`), the deduplication slot is freed, allowing a fresh request to be created.

---

## 22. In-Memory Approval Store & Multi-Tier Resource Quotas

Approval state is maintained exclusively in volatile server memory (`ApprovalStateManager`):

1. **Zero External Dependency:** No SQLite, PostgreSQL, Redis, or disk persistence. Server restart purges all approval state (fail-closed).
2. **Record Count Quotas:**
   - **Maximum Active Global Requests:** **1024**.
   - **Maximum Active Requests Per Actor/Session:** **64**.
3. **Volatile Raw Review Material Byte Quotas:**
   - **Per Approval Record:** Bounded by the underlying tool payload limit (e.g. 1 MiB).
   - **Per Actor/Session:** Maximum **8 MiB** of retained review material.
   - **Process-Wide Global Limit:** Maximum **64 MiB** of retained review material.
4. **Exhaustion Behavior:** If admitting a request would exceed either record count or byte quotas:
   - Request fails immediately with `RESOURCE_EXHAUSTED`.
   - Active requests are **never** evicted to make room.
5. **Deduplication Buffer Sharing:** Deduplicated identical pending requests do not allocate secondary raw review buffers.

---

## 23. Raw Review Material Isolation & Early Drop Lifecycle

To allow local operators to inspect privileged actions without unbounded memory retention or audit privacy leaks:

1. **Volatile Review Retention:** Full review content (e.g. patch diffs, file bodies, executable arguments) is stored only in volatile memory during the `PENDING` state.
2. **Early Reference Dropping:**
   - Once `PENDING` transitions to `APPROVED`, references to raw review buffers are **dropped immediately** after token generation and recording of the approval decision.
   - Raw review references are likewise dropped immediately upon transition to `REJECTED`, `EXPIRED`, or `CONSUMED`.
   - Rationale: During redemption, the agent resubmits the business parameters, which are verified via `executionPayloadHash`. Retaining raw file contents during the `APPROVED` waiting period wastes memory without security benefit.
3. **Total Audit Redaction:** Audit records store only metadata (`path`, `contentBytes`, `patchBytes`, hashes). Raw content is never written to disk or audit logs.

---

## 24. Local Admin Channel Trust Boundary

Human interaction is conducted exclusively through `apps/cli` over a dedicated local administrative IPC channel:

- **`arc approvals list`**: Display all active `PENDING` approval requests with summary metadata (tool, path, caller, elapsed time, remaining TTL).
- **`arc approvals inspect <requestId>`**: Display detailed review material (diff, content, target parameters).
- **`arc approve <requestId>`**: Transition status to `APPROVED`, generate the 256-bit one-time token, and print it to `stdout`.
- **`arc reject <requestId> [--reason <text>]`**: Transition status to `REJECTED`.

### 24.1. Strict Trust Boundary & Same-OS-Principal Threat Model

1. **Not an MCP Tool:** Approval administration is **never** exposed as an MCP tool or capability. MCP clients cannot call administrative actions.
2. **No Remote Endpoints:** No HTTP, SSE, WebSocket, or non-loopback TCP listeners exist for approval administration in RC-04.
3. **Authenticated Operator Identity:** Task 3 must implement a local IPC mechanism that requires authenticated operator identity.
4. **Credential Isolation:** Operator administrative credentials or capability handles **MUST NOT** be accessible or exposed to MCP clients.
5. **Same-OS-Principal Threat Assumption:**
   - In multi-process desktop environments, an untrusted local process running under the same OS user account could attempt to access local sockets.
   - Therefore, file mode or UID restriction alone cannot be claimed to automatically distinguish a human operator from an untrusted local agent process.
   - If the implementation cannot cryptographically or architecturally distinguish the trusted operator from an untrusted local client, approval administration must **fail closed** rather than relying on "same UID means human".

---

## 25. Approval Token Operator Display Protocol

When an operator runs `arc approve <requestId>`:

```text
✔ Request a8f3b2c1d4e5f60718293a4b5c6d7e8f APPROVED.

One-Time Approval Token:
  <256-bit-opaque-approval-token>

Expires at: 2026-09-18T12:05:00.000Z (Remaining: 240s)
Provide this token to the agent. Single-use only.
```

- **CLI Display:** The CLI displays the token, the absolute expiration timestamp (`expiresAt`), and the calculated `remainingSeconds`. (The CLI does not claim "Valid for 300 seconds" unless approved at creation).
- **Bounded ARC Guarantee:** ARC itself does not persist or intentionally log the raw token. Terminal emulator scrollback, shell history, screen recording, or external OS telemetry are outside ARC's direct control and are not claimed impossible.

---

## 26. Client Error Taxonomy & Safe Internal Failure Reasons

### 26.1. Client Error Responses (Anti-Oracle Sanitization)

To prevent attackers from using error messages as an oracle to deduce internal secret state:

| Failure Scenario                  | Returned Error Code      | Client Message                                            |
| :-------------------------------- | :----------------------- | :-------------------------------------------------------- |
| Initial call requiring approval   | `APPROVAL_REQUIRED`      | `"Action requires human approval. Request ID: <id>"`      |
| TTL elapsed                       | `APPROVAL_EXPIRED`       | `"Approval request has expired. Request a new approval."` |
| Explicit operator rejection       | `APPROVAL_REJECTED`      | `"Approval request was rejected by operator."`            |
| Token mismatch / forged token     | `APPROVAL_REJECTED`      | `"Approval validation failed."`                           |
| Payload hash mismatch (tampering) | `APPROVAL_REJECTED`      | `"Approval validation failed."`                           |
| Actor or workspace mismatch       | `APPROVAL_REJECTED`      | `"Approval validation failed."`                           |
| Policy hash mismatch (stale)      | `APPROVAL_REJECTED`      | `"Approval validation failed."`                           |
| Token already consumed (replay)   | `APPROVAL_REJECTED`      | `"Approval validation failed."`                           |
| Unknown / nonexistent request ID  | `APPROVAL_REJECTED`      | `"Approval validation failed."`                           |
| Malformed `_arcApproval` object   | `INVALID_REQUEST_SCHEMA` | `"Invalid approval control object schema."`               |

### 26.2. Safe Internal Diagnostic Reason Codes

While client-facing messages remain strictly generic (`"Approval validation failed."`), internal structured audit logs and server diagnostics use bounded, enumerated reason codes:

- `TOKEN_MISMATCH`
- `PAYLOAD_BINDING_MISMATCH`
- `ACTOR_BINDING_MISMATCH`
- `WORKSPACE_BINDING_MISMATCH`
- `POLICY_BINDING_MISMATCH`
- `ALREADY_CONSUMED`

**Leakage Prevention Rule:** Internal logs and diagnostics **MUST NEVER** log:

- Raw tokens or supplied token fragments
- Raw file content or patch lines
- Absolute host or attacker paths
- Secret environment values

---

## 27. Structured Audit Lifecycle & Hash Chaining

The audit subsystem (`packages/audit`) captures every stage of the approval lifecycle:

1. **`APPROVAL_REQUESTED`**: Logged when an action produces `REQUIRE_APPROVAL`.
2. **`APPROVAL_GRANTED`**: Logged when local operator executes `arc approve`.
3. **`APPROVAL_REJECTED`**: Logged when operator executes `arc reject`.
4. **`APPROVAL_EXPIRED`**: Logged when a request expires.
5. **`APPROVAL_CONSUMED`**: Logged when token verification succeeds immediately before subsystem execution.
6. **`APPROVED_EXECUTION_SUCCEEDED`**: Logged upon successful tool execution.
7. **`APPROVED_EXECUTION_FAILED`**: Logged if the tool execution fails downstream.

All events are linked into the append-only SHA-256 hash chain with strict data minimization (zero raw tokens, zero raw content).

---

## 28. Separation of Semantic Lifecycles

RC-04 strictly distinguishes five distinct semantic states:

$$\mathbf{REQUESTED} \ne \mathbf{APPROVED} \ne \mathbf{EXECUTED} \ne \mathbf{VERIFIED} \ne \mathbf{RECONCILED}$$

- **`REQUESTED`**: Agent expressed intent; policy required elevation.
- **`APPROVED`**: Operator granted authorization; capability minted.
- **`EXECUTED`**: Subsystem performed the operation.
- **`VERIFIED`**: Post-execution assertions validated state changes.
- **`RECONCILED`**: Higher-level state synchronization (deferred to RC-07).

---

## 29. Declarative Policy CLI Interface (`arc policy test`)

Local operators can validate and test policy documents offline:

```bash
arc policy test ./my-policy.yaml --tool create_file --path src/index.ts
```

- Verifies YAML/JSON syntax and schema validity.
- Simulates evaluation against specified tool and parameters.
- Outputs the expected outcome (`DENY`, `REQUIRE_APPROVAL`, `ALLOW`) and matching rule ID.
- Displays a diagnostic notice if the mutation approval floor clamped an `ALLOW` outcome to `REQUIRE_APPROVAL`.
- **Executes zero tools** and creates zero audit records.

---

## 30. Explicit Exclusion of Git Mutation Surface

RC-04 does **not** implement or expose Git write tools (`git_commit`, `git_push`, `git_checkout`, `git_branch`). Protected Git branches remain completely immutable to calling agents.

---

## 31. Out of Scope Catalog

The following capabilities are explicitly deferred beyond RC-04:

- Remote HTTPS/SSE network transport, TLS termination, and mTLS (RC-05).
- Enterprise IdP integration (OIDC, SAML, OAuth2) and device attestation (RC-05).
- Cloud approval services, Slack/Teams webhooks, and mobile push notifications (RC-05/RC-08).
- Multi-party quorum approvals and approval delegation chains (RC-08).
- Web-based graphical approval dashboards (Future).
- Persistent audit log anchoring to external immutable ledgers or SIEM (RC-06).
- Long-lived, ambient, or wildcard approvals (Strictly forbidden by design).

---

## 32. Exhaustive Threat & Race Condition Matrix

| Threat / Race Scenario                                                                  | Mitigating Security Control                                                                        | Outcome                                                                  |
| :-------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------- |
| **Replay Attack:** Agent attempts to use the same token twice.                          | Atomic state transition to `CONSUMED` before execution; subsequent attempts find state `CONSUMED`. | Rejection (`APPROVAL_REJECTED`). Subsystem called once only.             |
| **Concurrent Redemption Race:** Two concurrent calls submit identical valid token.      | Record lock / atomic CAS on approval record state.                                                 | Exactly one call transitions to `CONSUMED`; second call fails.           |
| **Parameter Tampering:** Agent alters file path or content after approval.              | `executionPayloadHash` computed over exact parameters mismatches approved hash.                    | Rejection (`APPROVAL_REJECTED`). Zero filesystem modification.           |
| **Confused Deputy / Cross-Session Hijack:** Agent B intercepts Token A and submits.     | Actor binding check (`clientId`, `sessionId`, `deviceId`) detects caller mismatch.                 | Rejection (`APPROVAL_REJECTED`). Zero execution.                         |
| **Workspace Redirection:** Agent attempts to redeem approval in another workspace.      | Workspace binding check detects `workspaceId` or `workspaceRootHash` mismatch.                     | Rejection (`APPROVAL_REJECTED`).                                         |
| **Stale Approval under Policy Update:** Operator updates policy after approval granted. | Policy hash binding check detects `policyHash` mismatch; approval fails redemption.                | Rejection (`APPROVAL_REJECTED`). Token NOT consumed. Operation blocked.  |
| **Expiry Race before Approval:** Operator approves request after 300s TTL.              | Record lock checks `Date.now() >= expiresAt`; transitions to `EXPIRED`.                            | Expiry failure. Zero token generated.                                    |
| **Expiry Race before Consumption:** Approval expires while redemption is in flight.     | Pre-consumption expiry check under record lock detects expiration; transitions to `EXPIRED`.       | Rejection (`APPROVAL_EXPIRED`). Zero tool execution.                     |
| **Malformed Control Object Spam:** Malicious agent floods bad `_arcApproval` objects.   | Schema validation fails with `INVALID_REQUEST_SCHEMA`; does not create or lookup pending records.  | Rejection (`INVALID_REQUEST_SCHEMA`). Zero state pollution.              |
| **Server Crash & Restart:** Server restarts while approval is `APPROVED`.               | Authoritative store is volatile in-memory; state is purged on restart.                             | Rejection (`APPROVAL_REJECTED`). Client must re-request.                 |
| **Denial of Service via Pending Flooding:** Malicious agent floods approval requests.   | Record quotas (1024 global, 64 per actor) and deduplication via `executionPayloadHash`.            | `RESOURCE_EXHAUSTED` returned once quota hit; active requests preserved. |
| **Raw Review Material Memory Exhaustion:** Large payload spam consumes server heap.     | Multi-tier byte quotas (8 MiB actor, 64 MiB global) and immediate drop on approval/terminal.       | `RESOURCE_EXHAUSTED` returned; memory footprint strictly bounded.        |
| **Token Oracle Attack:** Attacker attempts to brute-force 256-bit token string.         | 256 bits of cryptographic entropy ($2^{256}$ search space) + bounded 128-byte token input limit.   | Computationally infeasible. Generic rejection on mismatch.               |
| **Local Admin Channel Hijack:** Untrusted local process connects to admin socket.       | Authenticated operator identity in local IPC; fails closed if operator identity unverified.        | Administrative access denied. Zero elevation.                            |

---

## 33. Crash & Restart Semantics

1. All approval records and tokens reside exclusively in volatile server memory.
2. In the event of an unhandled exception, process termination, or system restart:
   - All pending and approved requests are immediately extinguished.
   - Any token previously issued is rendered permanently invalid.
3. If a crash occurs during tool execution after token consumption, the token is not recovered. Re-execution requires a brand-new request, review, and approval.

---

## 34. RC-04 Implementation Breakdown

RC-04 implementation will proceed across six discrete, independently reviewable tasks:

- **Task 1: Protocol Contracts & Approval State Machine Core**
  - Define all protocol types in `packages/protocol`.
  - Implement `ApprovalStateManager` with high-entropy token generation and atomic state transitions in `packages/policy`.
  - Comprehensive unit test suite covering state transitions and concurrency.
- **Task 2: Strict Declarative Policy Parser & Matchers**
  - Implement schema validation, YAML/JSON parser, AST matchers, and canonical `policyHash` normalization in `packages/policy`.
  - Order-independent rule evaluation and tie-breaking algorithms.
  - Policy parsing security benchmarks and edge-case unit tests.
- **Task 3: Local Operator Administrative Channel**
  - Implement authenticated local IPC communication between `apps/cli` and `apps/mcp-server`.
  - Implement `arc approve`, `arc reject`, `arc approvals list`, and `arc policy test` commands.
- **Task 4: MCP Approval Request & Token Redemption Integration**
  - Wire `_arcApproval` parameter extraction, validation, and scenario routing into `ArcMcpServer`.
  - Implement initial `APPROVAL_REQUIRED` flow and verified token redemption path.
  - Enable execution of RC-03 mutation tools strictly upon valid approval consumption.
- **Task 5: Security Hardening, Race Condition Verification & Audit Integration**
  - Full audit logging integration for all approval lifecycle events.
  - Extensive concurrency and race-condition test suite (replays, tampering, expiry races).
  - Memory isolation and byte quota verification.
- **Task 6: Verification Gates, Acceptance Documentation & PR**
  - End-to-end negative control test suite.
  - Update `scripts/verify-rc04.sh` covering all quality gates.
  - Final integration report and Pull Request submission.

---

## 35. Required Future Negative Security Controls Catalog

Subsequent implementation tasks must implement and pass direct test controls for at least:

1. `RC04-NEG-01`: Agent attempt to invoke internal approval/rejection API via MCP is rejected with `POLICY_DENIED`.
2. `RC04-NEG-02`: Valid approval token cannot override a Layer 1 permanent `DENY`.
3. `RC04-NEG-03`: Valid approval token cannot override a Layer 2 declarative `DENY`.
4. `RC04-NEG-04`: Declarative policy rule attempting `effect: ALLOW` on file mutation is clamped to `REQUIRE_APPROVAL`.
5. `RC04-NEG-05`: Mutation tool invocation without `_arcApproval` returns `APPROVAL_REQUIRED`.
6. `RC04-NEG-06`: Missing token in `_arcApproval` fails schema admission with `INVALID_REQUEST_SCHEMA`.
7. `RC04-NEG-07`: Nonexistent `requestId` is rejected with `APPROVAL_REJECTED`.
8. `RC04-NEG-08`: Invalid token string is rejected with `APPROVAL_REJECTED` via timing-safe comparison.
9. `RC04-NEG-09`: Expired approval token ($T > 300\text{s}$) is rejected with `APPROVAL_EXPIRED`.
10. `RC04-NEG-10`: Explicitly rejected approval request cannot be redeemed and returns `APPROVAL_REJECTED`.
11. `RC04-NEG-11`: Replay of already `CONSUMED` approval token is rejected with `APPROVAL_REJECTED`.
12. `RC04-NEG-12`: Concurrent redemption race executes tool at most once; second redemption fails.
13. `RC04-NEG-13`: Modifying file content or patch string between approval and redemption causes payload hash mismatch and rejection.
14. `RC04-NEG-14`: Modifying file path between approval and redemption causes payload hash mismatch and rejection.
15. `RC04-NEG-15`: Actor mismatch (different `clientId`, `sessionId`, or `deviceId`) causes rejection with `APPROVAL_REJECTED`.
16. `RC04-NEG-16`: Target workspace mismatch causes rejection with `APPROVAL_REJECTED`.
17. `RC04-NEG-17`: Policy change between request and redemption invalidates pending approval with `POLICY_BINDING_MISMATCH`; token is not consumed.
18. `RC04-NEG-18`: Server restart completely purges active approvals; previously issued tokens are unusable.
19. `RC04-NEG-19`: Malformed YAML policy (syntax error, duplicate mapping keys, custom tags) fails closed with `POLICY_PARSE_ERROR` and sets `health.status = 'UNHEALTHY'`.
20. `RC04-NEG-20`: Duplicate rule IDs in policy document cause immediate rejection.
21. `RC04-NEG-21`: Unmatched action under explicit operator policy fails closed with default `DENY`.
22. `RC04-NEG-22`: Raw approval token never appears in any serialized AuditRecord across all lifecycle states.
23. `RC04-NEG-23`: Raw file content and patch lines never appear in audit records for approved mutations.
24. `RC04-NEG-24`: Bypass fields (`approvalToken`, `bypassApproval`, `sudo`, `force`) remain rejected by schema.
25. `RC04-NEG-25`: Exhaustion of approval quotas (record count or byte limits) safely rejects new requests with `RESOURCE_EXHAUSTED`.
26. `RC04-NEG-26`: Unsupported glob syntax (brace expansion, extglob, regex, leading slash, traversal) is rejected at policy parse time.
27. `RC04-NEG-27`: Rule specifying both `allowedBinaries` and `blockedBinaries` is rejected at policy parse time.
28. `RC04-NEG-28`: Policy attempting to register or authorize a new filesystem root fails closed.
29. `RC04-NEG-29`: Reused pending request returns remaining TTL, not a reset 300s.
30. `RC04-NEG-30`: Expiry race before approval transitions to `EXPIRED` without token minting.

---

## 36. Historical Documentation Reconciliation & Ambiguity Clarification

This section normatively clarifies and supersedes earlier ambiguities in RC-00 architecture documents:

1. **Approval Token Nature & Verifier:** Early documentation referenced both "cryptographic capabilities" and "HMAC tokens". RC-04 clarifies: tokens are 256-bit cryptographically random strings (64 hex characters) generated out-of-band; the server stores only the SHA-256 digest (`tokenDigest`), eliminating secondary secret management and server-side token leakage risks.
2. **TTL Start Boundary & Display:** TTL measurement begins strictly at the moment the `PENDING` request record is created on the server (`createdAt + 300s`). It does not restart on operator approval. Reused pending requests return remaining TTL.
3. **Audit Payload Hash vs Execution Payload Hash:** RC-03 introduced `payloadHash` in `AuditRecord` which hashes sanitized parameters for audit privacy. RC-04 introduces `executionPayloadHash`, a distinct internal cryptographic hash binding the complete, unredacted business parameters, actor context, workspace root hash, and policy hash to guarantee absolute payload immutability.
4. **Local Administrative Trust Boundary:** Clarifies that administrative approval operations belong exclusively to local operator CLI execution over authenticated local IPC. MCP clients have zero administrative surface.
5. **Mutation Policy Floor:** Clarifies that declarative policies cannot authorize automatic file mutation in RC-04; candidate `ALLOW` for any of the five mutation tools is clamped to `REQUIRE_APPROVAL`.
6. **Policy Change Redemption:** Clarifies that an approval token bound to an earlier `policyHash` is voided upon policy change, fails redemption with `APPROVAL_REJECTED`, and is not consumed.

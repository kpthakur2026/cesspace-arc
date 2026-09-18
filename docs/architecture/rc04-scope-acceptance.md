# RC-04 Scope & Acceptance Criteria — CesSpace ARC

> **Document:** Stage Specification & Quality Gates
> **Status:** SCOPE FREEZE DRAFT — INDEPENDENT REVIEW REQUIRED
> **Target Stage:** `RC-04` — Declarative Policy Engine & Human Approval State Machine
> **Base:** `main` (Verified RC-03 Main Merge at `cff5ce6ac88380341fd69781ab30057b2d165aa3`)

---

## 1. Stage Objective & Governance

The objective of **RC-04** is to establish the declarative policy evaluation engine and the human-in-the-loop approval state machine for CesSpace ARC.

Building upon the verified read-only inspection baseline (RC-01), bounded terminal execution (RC-02), and the verified core filesystem mutation primitives (RC-03), RC-04 provides:

1. **Declarative Policy Specification:** Strict YAML and JSON declarative policy document parsing, validation, and deterministic multi-criteria matching.
2. **Permanent Hierarchical Evaluation:** Enforced two-layer authorization architecture with absolute, immutable precedence: `DENY > REQUIRE_APPROVAL > ALLOW`.
3. **Human Approval State Machine:** Complete lifecycle management (`PENDING`, `APPROVED`, `REJECTED`, `EXPIRED`, `CONSUMED`) for privileged operations requiring human elevation.
4. **Exact Cryptographic Bindings:** High-entropy one-time approval tokens bound immutably to exact execution payload hashes, actor session context, workspace identity, and policy configuration hashes.
5. **Local Administrative CLI:** Dedicated out-of-band administrative interface (`arc approve`, `arc reject`, `arc approvals list`, `arc policy test`) accessible exclusively to trusted local operators.
6. **Controlled Execution of Gated Mutations:** Authorized, atomic execution of previously gated RC-03 mutation tools strictly upon successful redemption and consumption of a valid human approval token.

### 1.1. Core Invariants Maintained

Every policy evaluation and approval redemption in RC-04 must satisfy the following inviolable security invariants:

1. **Absolute Precedence of Permanent Denials:** A human approval token **MUST NEVER** override a `DENY`. If an operation evaluates to `DENY` under the permanent security kernel or operator policy, it is rejected immediately, regardless of any past or present approval token.
2. **Two-Layer Authorization Separation:**
   - **Layer 1 (Permanent Security Kernel):** Hard-coded, non-overridable security invariants (authenticated caller, registered workspace containment, path jailing, sensitive file deny patterns, Git metadata protection, prohibited commands, default-deny).
   - **Layer 2 (Operator Declarative Policy):** Operator-defined rules that may classify otherwise-admissible actions as `DENY`, `REQUIRE_APPROVAL`, or `ALLOW`. Declarative policy may make execution more restrictive, but can **never** weaken or bypass Layer 1 controls.
3. **Strict Mutation Approval Floor:** All five RC-03 filesystem mutation tools (`create_file`, `write_file`, `apply_patch`, `delete_file`, `move_file`) have a mandatory minimum policy classification of `REQUIRE_APPROVAL` (or `DENY`). An operator policy is **strictly forbidden** from downgrading any filesystem mutation tool to automatic `ALLOW`.
4. **Out-of-Band Administrative Trust Boundary:** AI agents communicating via MCP have **zero administrative authority**. An agent cannot approve requests, reject requests, list approvals, mint tokens, inspect approval state, or bypass verification. Approval and rejection are strictly reserved for local human operators through `apps/cli`.
5. **Atomic One-Time Token Consumption:** Approval tokens are single-use cryptographic capabilities. Transition from `APPROVED` to `CONSUMED` is atomic and occurs **before** subsystem invocation. If execution fails downstream, the token remains consumed and cannot be replayed.
6. **Cryptographic Payload & Context Binding:** Approvals are cryptographically bound to the canonical execution payload hash (`executionPayloadHash`), requester actor identity (`clientId`, `clientType`, `sessionId`), target workspace (`workspaceId` and root identity), and policy hash. Tampering with any parameter, path, or payload invalidates the approval immediately.
7. **Strict 300-Second Expiry:** Approvals are subject to an immutable, server-enforced Time-To-Live (TTL) of 300 seconds from creation. Expired approvals fail closed with `APPROVAL_EXPIRED`.
8. **Audit Data Minimization & Privacy:** Raw approval tokens, unredacted file content, patch bodies, and sensitive environment values **MUST NEVER** appear in audit records, error responses, debug logs, or CLI diagnostic output. Token storage is strictly digest-based (SHA-256).

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
│  - Schema Admission & Validation                                       │
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
│  └───────────────────────────────┬──────────────────────────────────┘  │
│                                  │ Outcome == REQUIRE_APPROVAL         │
│                                  ▼                                     │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Approval State Machine & Token Verifier                          │  │
│  │ - Exact Payload Hash Revalidation                                │  │
│  │ - Actor, Workspace & Policy Binding Checks                       │  │
│  │ - Atomic APPROVED -> CONSUMED State Transition                   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└──────────────────┬─────────────────────────────────┬───────────────────┘
                   │                                 │
                   │ Execution Authorized            │ Out-of-Band Admin
                   ▼                                 ▼
┌──────────────────────────────────────┐   ┌─────────────────────────────┐
│ Execution Subsystems                 │   │ apps/cli                    │
│ - packages/filesystem (Mutations)    │   │ - arc approve <requestId>   │
│ - packages/terminal (Processes)      │   │ - arc reject <requestId>    │
│ - packages/git (Read inspection)     │   │ - arc approvals list        │
└──────────────────────────────────────┘   │ - arc policy test <file>    │
                                           └──────────────┬──────────────┘
                                                          │ Local Operator
                                                          ▼
                                           ┌─────────────────────────────┐
                                           │ Trusted Human Reviewer      │
                                           └─────────────────────────────┘
```

### 2.1. Monorepo Package Allocation

- **`packages/protocol`:**
  - Definitive TypeScript interfaces for declarative policy schemas (`PolicyDocument`, `PolicyRule`, `PolicyMatcher`).
  - Approval state machine types (`ApprovalState`, `ApprovalRequest`, `ApprovalBinding`, `ApprovalTokenDigest`).
  - Formal client control structures (`ArcApprovalControlObject`: `{ requestId: string; token: string }`).
  - Canonical error codes: `APPROVAL_REQUIRED`, `APPROVAL_EXPIRED`, `APPROVAL_REJECTED`, `POLICY_PARSE_ERROR`.
  - Structured audit event types: `APPROVAL_REQUESTED`, `APPROVAL_GRANTED`, `APPROVAL_REJECTED`, `APPROVAL_EXPIRED`, `APPROVAL_CONSUMED`, `APPROVED_EXECUTION_SUCCEEDED`, `APPROVED_EXECUTION_FAILED`.
- **`packages/policy`:**
  - `DeclarativePolicyEngine`: Strict YAML/JSON parser, schema validator, and deterministic rule matchers.
  - `ApprovalStateManager`: In-memory volatile approval store, cryptographically secure ID/token generator, state machine transitions, and atomic consumption logic.
  - Integrated `SecurityKernel.evaluate()` workflow enforcing Layer 1 before Layer 2.
- **`apps/mcp-server`:**
  - MCP tool dispatch pipeline integration:
    - Pre-admission extraction of `_arcApproval` parameter.
    - Initial `REQUIRE_APPROVAL` handling: creates pending approval record and returns `APPROVAL_REQUIRED` with opaque `approvalRequestId`.
    - Token redemption handling: validates `_arcApproval`, passes token digest to `ApprovalStateManager`, and dispatches execution upon verified consumption.
- **`apps/cli`:**
  - Local operator commands: `arc approve`, `arc reject`, `arc approvals`, `arc policy test`.
  - Secure local inter-process communication (IPC) channel to running server.
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
   - It is not subject to an approval floor.
   - It matches an explicit `ALLOW` rule (or the default baseline policy).

### 4.1. Redemption Time Re-Evaluation

Human approval does **not** grant permanent or irrevocable authority:

- At the moment of token redemption, the operation is **fully re-evaluated** against current policy.
- If an operator changes policy such that an operation now evaluates to `DENY`, the approval token is void and execution is denied with `POLICY_DENIED`.
- If an operation now evaluates to `ALLOW` (for a non-mutation tool), the token is consumed and execution proceeds.
- If an operation still evaluates to `REQUIRE_APPROVAL`, the token is validated, consumed, and executed.

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

**Normative Rule:** Any declarative policy rule that attempts to set `effect: ALLOW` for any of the five mutation tools is **invalid** and must either fail schema validation or be clamped at evaluation time to `REQUIRE_APPROVAL`. Automatic execution of file mutations without human approval is strictly impossible in RC-04.

---

## 6. Preservation of Existing RC-01 / RC-02 Behavior

RC-04 must maintain 100% backward compatibility with verified prior stages:

1. **RC-01 Read-Only Inspection:** In the default built-in policy configuration, all 9 RC-01 inspection tools (`health`, `system_status`, `list_directory`, `read_file`, `search_files`, `search_text`, `git_status`, `git_diff`, `git_log`) continue to resolve to `ALLOW` within authorized workspaces. An operator declarative policy may elevate specific sensitive files or directories to `REQUIRE_APPROVAL` or `DENY`.
2. **RC-02 Controlled Terminal Execution:** RC-02 process lifecycle tools (`process_status`, `process_output`, `terminate_process`) and bounded commands evaluated by `validateCommandRequest` continue to execute under their verified constraints. Operator declarative policy rules can enforce `REQUIRE_APPROVAL` on specific binaries or argument patterns.

---

## 7. Declarative Policy Document Format & Schema

Declarative policies are authored in **YAML** (preferred) or **JSON**.

### 7.1. Normative Structure (Version 1.0)

```yaml
version: '1.0'
metadata:
  name: 'example-production-policy'
  description: 'Strict project security policy'
  lastModified: '2026-09-18T12:00:00Z'

workspaces:
  - id: 'primary-workspace'
    path: 'workspace'

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

  - id: 'require-approval-terminal-scripts'
    effect: 'REQUIRE_APPROVAL'
    description: 'Require human approval for executing build scripts'
    tools:
      - 'run_command'
    commands:
      allowedBinaries:
        - 'npm'
        - 'pnpm'
      blockedBinaries:
        - 'curl'
        - 'wget'

  - id: 'allow-source-file-mutations'
    effect: 'REQUIRE_APPROVAL' # Clamped from ALLOW if authored as ALLOW
    description: 'Permit source code modifications upon approval'
    tools:
      - 'create_file'
      - 'write_file'
      - 'apply_patch'
    paths:
      patterns:
        - 'src/**'
```

### 7.2. Rule Field Taxonomy

- **`id`** _(string, required)_: Unique identifier `^[a-zA-Z0-9_-]{1,64}$`.
- **`effect`** _(enum, required)_: `'DENY' | 'REQUIRE_APPROVAL' | 'ALLOW'`.
- **`description`** _(string, optional)_: Human-readable rationale (max 256 chars).
- **`tools`** _(string[], optional)_: Exact tool names to match.
- **`paths.patterns`** _(string[], optional)_: Workspace-relative glob patterns.
- **`commands.allowedBinaries`** _(string[], optional)_: Whitelisted executable basenames.
- **`commands.blockedBinaries`** _(string[], optional)_: Blacklisted executable basenames.
- **`git.protectedBranches`** _(string[], optional)_: Protected Git ref patterns.
- **`git.actions`** _(string[], optional)_: Specific Git actions.

---

## 8. Strict Parser Security & Resource Bounds

To prevent Denial of Service, ReDoS, and parser confusion attacks, the declarative policy parser must satisfy strict constraints:

1. **Parser Implementation:** Uses a safe, standards-compliant parser without execution capabilities. Custom YAML tags (e.g. `!run`, `!include`), JavaScript expressions, function evaluation, and environment-variable expansion are strictly forbidden.
2. **Deterministic File Constraints:**
   - **Document Size Limit:** Maximum **256 KiB** UTF-8 (`262,144 bytes`).
   - **Maximum Rules:** Maximum **256** rules per document.
   - **Maximum Items Per Array:** Maximum **128** items per matcher list.
   - **Maximum Pattern Length:** Maximum **1024** characters per pattern or glob string.
3. **Strict Validation:**
   - Unknown properties anywhere in the document cause immediate schema rejection.
   - Duplicate rule IDs cause immediate rejection.
   - Duplicate keys in YAML mappings cause immediate rejection.
4. **No Remote or Recursive Includes:** Policy files are self-contained. No external files, network endpoints, or sub-documents may be referenced or loaded.

---

## 9. Deterministic Matcher Semantics

Matchers inside a rule follow strict Boolean logic:

1. **Conjunctive Categories (AND):** Different matcher categories within a rule are combined with logical **AND**.
   - Example: A rule specifying `tools: ['write_file']` and `paths.patterns: ['src/**']` matches if and only if the tool is `write_file` **AND** the target path matches `src/**`.
2. **Disjunctive Array Entries (OR):** Within an individual category array, entries are combined with logical **OR**.
   - Example: `tools: ['create_file', 'write_file']` matches if the tool is `create_file` **OR** `write_file`.
3. **Category Evaluation Rules:**
   - **Tool Matcher:** Exact case-sensitive equality against registered tool name.
   - **Path Matcher:** Evaluated against normalized workspace-relative paths. Target paths containing leading slashes or traversals (`..`) are rejected by Layer 1 before reaching matcher. Absolute host paths can **never** be matched or authorized.
   - **Command Matcher:** Evaluated against parsed executable basename and argv arrays. Shell strings are never parsed or executed.
   - **Git Matcher:** Evaluated against normalized branch references and Git actions.

---

## 10. Rule Evaluation & Deterministic Precedence Resolution

Policy evaluation is completely order-independent: the physical order of rules in the YAML/JSON document has zero impact on the security decision.

### 10.1. Evaluation Algorithm

1. Evaluate Layer 1 (Permanent Security Kernel). If Layer 1 denies, return `DENY` with the matching kernel rule ID.
2. For each rule in the declarative policy, evaluate whether all defined matcher categories match the request.
3. Collect all matching rules:
   - If any matching rule has `effect === 'DENY'`, the candidate outcome is `DENY`.
   - Else if any matching rule has `effect === 'REQUIRE_APPROVAL'`, the candidate outcome is `REQUIRE_APPROVAL`.
   - Else if any matching rule has `effect === 'ALLOW'`, the candidate outcome is `ALLOW`.
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

## 12. Fail-Closed Invalid Policy Handling

If a configured policy file is corrupted, malformed, unreadable, or schema-invalid:

1. ARC fails closed immediately.
2. The server refuses to admit privileged execution or default to open access.
3. The server health probe reports status `DEGRADED` or `UNHEALTHY` with a safe diagnostic code `POLICY_PARSE_ERROR`.
4. Raw file contents and internal parse stack traces are suppressed to prevent information leakage.

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
- **`EXPIRED`**: TTL elapsed (300 seconds) without successful consumption.
  - **Terminal state**. Zero transitions out.
- **`CONSUMED`**: Token redeemed and verified; operation dispatched to execution subsystem.
  - **Terminal state**. Zero transitions out. Replay is strictly impossible.

**Invariant:** Transition into any terminal state (`REJECTED`, `EXPIRED`, `CONSUMED`) is final. State can never return to `PENDING`, and expired/consumed requests can never be reactivated.

---

## 14. Cryptographic Identifiers & Token Architecture

### 14.1. Approval Request ID (`approvalRequestId`)

- Generated using `crypto.randomBytes(16).toString('hex')` (128 bits of cryptographic entropy).
- Opaque string returned to the MCP client in the initial `APPROVAL_REQUIRED` error details.
- Grants **zero authority**. It serves purely as a lookup key for the pending approval record.

### 14.2. One-Time Approval Token (`approvalToken`)

- Generated upon human approval using `crypto.randomBytes(32).toString('hex')` (256 bits of cryptographic entropy).
- Displayed **once** to the local operator in the CLI for injection into the agent's workflow.
- **Storage Security:** The raw token is **NEVER** stored in memory or persistence. The approval record stores only its cryptographic digest:
  $$\text{tokenDigest} = \text{HMAC-SHA256}(\text{internalSecret}, \text{rawToken})$$
  or $\text{SHA-256}(\text{rawToken})$.
- Verification during redemption uses timing-safe equality (`crypto.timingSafeEqual`).

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

### 15.1. Control Object Handling Rules

1. **MCP Admission Validation:** Validated via strict Zod schema:
   ```typescript
   export const ArcApprovalSchema = z
     .object({
       requestId: z.string().regex(/^[0-9a-fA-F]{32}$/, 'Invalid approval request ID format'),
       token: z.string().min(32).max(128),
     })
     .strict();
   ```
2. **Subsystem Isolation:** Before passing business parameters to the underlying subsystem (`FilesystemSubsystem`, `ControlledProcessRunner`), `_arcApproval` is **stripped**. Subsystems never see tokens or approval objects.
3. **Audit Redaction:** `_arcApproval.token` is unconditionally redacted from audit parameters and replaced with metadata `{ approvalRequestId: ..., tokenProvided: true }`.
4. **Rejection of Loose Bypass Properties:** Unofficial properties such as `approvalToken`, `approved`, `bypassApproval`, `autoApprove`, `force`, `admin`, or `sudo` remain strictly forbidden and cause immediate schema admission rejection.

---

## 16. Initial `REQUIRE_APPROVAL` Flow & Error Semantics

When a tool request evaluates to `REQUIRE_APPROVAL` and does not provide valid `_arcApproval`:

1. **Pending Record Creation / Deduplication:** The server checks if an identical `PENDING` request already exists (see Section 21). If not, it creates a new record in `ApprovalStateManager`.
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
4. **Execution Gate:** No subsystem primitive is invoked. Zero file changes occur.

---

## 17. Approval Time-To-Live (300-Second Absolute TTL)

1. Every approval record stores an absolute expiration timestamp:
   $$\text{expiresAt} = \text{createdAt} + 300\,000\text{ ms}$$
2. Server clock (`Date.now()`) is the sole authoritative time source. Client-provided timestamps are completely ignored.
3. Any operation attempted at timestamp $T \ge \text{expiresAt}$ immediately transitions the record to `EXPIRED` and returns `APPROVAL_EXPIRED`.

---

## 18. Exact Execution Payload Binding (`executionPayloadHash`)

To prevent Parameter Tampering and Confused Deputy attacks, approval is bound to the exact payload hash:

$$\text{executionPayloadHash} = \text{SHA-256}(\text{canonicalJson}(\text{payloadToSign}))$$

Where `payloadToSign` consists of:

- `schemaVersion`: Current protocol schema version (e.g. `'1.0'`).
- `toolName`: Canonical tool name (e.g. `'create_file'`).
- `parameters`: Exact validated business parameters (including full content bytes or patch string, but excluding `_arcApproval`).
- `workspaceId`: Target authorized workspace identifier.
- `actor`: Requesting actor binding (`clientId`, `clientType`, `sessionId`).
- `policyHash`: SHA-256 digest of the effective policy document.

**Invariant:** If an attacker modifies even a single character in the file content, patch body, path, or flags between approval and redemption, the recomputed `executionPayloadHash` will mismatch, causing immediate rejection with `APPROVAL_REJECTED`.

---

## 19. Mandatory Context Bindings

Approval validation enforces three mandatory context checks:

1. **Actor Binding:** The actor redeeming the token must match the actor who requested it (`clientId`, `clientType`, and `sessionId` if present). An approval requested by Session A cannot be redeemed by Session B.
2. **Workspace Binding:** The target workspace of the redemption request must match the approved `workspaceId` and root canonical identity.
3. **Policy Binding:** The effective policy configuration hash at redemption time must equal the policy hash recorded at creation time. If policy was reloaded or modified, the approval is voided.

---

## 20. Pre-Execution Re-evaluation & Atomic One-Time Consumption

During token redemption:

```
[Agent submits tool call with _arcApproval]
                     │
                     ▼
  1. Validate MCP schema & extract _arcApproval
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

**Atomicity Guarantee:** The transition `APPROVED -> CONSUMED` is performed synchronously under an in-process lock or atomic conditional update. Exactly one competing thread can successfully transition an approval record. Subsequent calls with the same token fail closed.

---

## 21. Request Deduplication Semantics

To prevent flooding the approval store with identical requests, repeated invocations of the same pending action are deduplicated:

$$\text{dedupKey} = (\text{actor.clientId}, \text{targetWorkspaceId}, \text{toolName}, \text{executionPayloadHash})$$

- If an active record with status `PENDING` matches the `dedupKey`, ARC returns the existing `approvalRequestId` and remaining TTL without creating a new record.
- Once a request reaches a terminal state (`REJECTED`, `EXPIRED`, `CONSUMED`), the deduplication slot is freed, allowing a fresh request to be created.

---

## 22. Authoritative Volatile In-Memory Approval Store & Resource Quotas

Approval state is maintained in volatile server memory (`ApprovalStateManager`):

1. **Zero Database / Cloud Dependency:** No SQLite, PostgreSQL, or external cache is required. Server restart purges all approval state (fail-closed).
2. **Resource Quotas:**
   - **Maximum Active Global Requests:** **1024**.
   - **Maximum Active Requests Per Actor/Session:** **64**.
3. **Exhaustion Behavior:** If quotas are exceeded, new requests fail with `RESOURCE_EXHAUSTED`. Active requests are **never** evicted to admit new ones.

---

## 23. Raw Review Material Isolation & Lifecycle

To allow local operators to make informed decisions without compromising audit privacy:

1. **Volatile Retention:** Full review content (e.g. patch diffs, full file contents, executable arguments) is stored only in volatile memory associated with the `PENDING` approval record.
2. **Total Audit Redaction:** Audit records store only metadata (`path`, `contentBytes`, `patchBytes`, hashes). Raw content is never written to disk or audit logs.
3. **Reference Dropping:** Upon transition to `CONSUMED`, `REJECTED`, or `EXPIRED`, references to raw content buffers are dropped to allow immediate garbage collection.

---

## 24. Trusted Local Operator Administrative Interface (CLI Channel)

Human interaction is conducted exclusively through `apps/cli` over a dedicated local administrative IPC socket or loopback channel:

- **`arc approvals list`**: Display all active `PENDING` approval requests with summary metadata (tool, path, caller, elapsed time, remaining TTL).
- **`arc approvals inspect <requestId>`**: Display detailed review material (diff, content, target parameters).
- **`arc approve <requestId>`**: Transition status to `APPROVED`, generate the 256-bit one-time token, and print it to `stdout`.
- **`arc reject <requestId> [--reason <text>]`**: Transition status to `REJECTED`.

**Security Boundary:** The administrative IPC channel is authenticated via local OS file permissions (POSIX domain socket restricted to operator UID) or loopback bearer authentication. Remote clients have zero access.

---

## 25. Approval Token Operator Display Protocol

When an operator runs `arc approve <requestId>`:

```text
✔ Request a8f3b2c1d4e5f60718293a4b5c6d7e8f APPROVED.

One-Time Approval Token:
  <256-bit-opaque-approval-token>

Provide this token to the agent. Valid for 300 seconds. Single-use only.
```

- The CLI outputs the token directly to the console.
- The token is never saved to CLI history or stored in system logs.

---

## 26. Client Error Taxonomy & Anti-Oracle Sanitization

To prevent attackers from using error messages as an oracle to deduce internal secret state:

| Failure Scenario                  | Returned Error Code | Client Message                                            |
| :-------------------------------- | :------------------ | :-------------------------------------------------------- |
| Initial call requiring approval   | `APPROVAL_REQUIRED` | `"Action requires human approval. Request ID: <id>"`      |
| TTL elapsed                       | `APPROVAL_EXPIRED`  | `"Approval request has expired. Request a new approval."` |
| Explicit operator rejection       | `APPROVAL_REJECTED` | `"Approval request was rejected by operator."`            |
| Token mismatch / forged token     | `APPROVAL_REJECTED` | `"Approval validation failed."`                           |
| Payload hash mismatch (tampering) | `APPROVAL_REJECTED` | `"Approval validation failed."`                           |
| Actor or workspace mismatch       | `APPROVAL_REJECTED` | `"Approval validation failed."`                           |
| Token already consumed (replay)   | `APPROVAL_REJECTED` | `"Approval validation failed."`                           |
| Unknown / nonexistent request ID  | `APPROVAL_REJECTED` | `"Approval validation failed."`                           |

**Anti-Oracle Rule:** All validation failures during token redemption map to a generic `APPROVAL_REJECTED` error code and uniform message. Detailed diagnostic reasons are logged internally to the structured audit log only.

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

| Threat / Race Scenario                                                                 | Mitigating Security Control                                                                        | Outcome                                                                  |
| :------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------- |
| **Replay Attack:** Agent attempts to use the same token twice.                         | Atomic state transition to `CONSUMED` before execution; subsequent attempts find state `CONSUMED`. | Rejection (`APPROVAL_REJECTED`). Subsystem called once only.             |
| **Concurrent Redemption Race:** Two concurrent calls submit identical valid token.     | In-process mutex / atomic CAS on approval record state.                                            | Exactly one call transitions to `CONSUMED`; second call fails.           |
| **Parameter Tampering:** Agent alters file path or content after approval.             | `executionPayloadHash` computed over exact parameters mismatches approved hash.                    | Rejection (`APPROVAL_REJECTED`). Zero filesystem modification.           |
| **Confused Deputy / Cross-Session Hijack:** Agent B intercepts Token A and submits.    | Actor binding check (`clientId`, `sessionId`) detects caller mismatch.                             | Rejection (`APPROVAL_REJECTED`). Zero execution.                         |
| **Workspace Redirection:** Agent attempts to redeem approval in another workspace.     | Workspace binding check detects `workspaceId` mismatch.                                            | Rejection (`APPROVAL_REJECTED`).                                         |
| **Stale Approval under Policy Update:** Operator denies tool while request is pending. | Mandatory re-evaluation at redemption evaluates against new policy; `DENY` wins.                   | Rejection (`POLICY_DENIED`). Token invalidated.                          |
| **Expiry Race:** Approval expires while redemption request is in flight.               | Expiry timestamp checked before atomic consumption; if expired, transitions to `EXPIRED`.          | Rejection (`APPROVAL_EXPIRED`).                                          |
| **Server Crash & Restart:** Server restarts while approval is `APPROVED`.              | Authoritative store is volatile in-memory; state is purged on restart.                             | Rejection (`APPROVAL_REJECTED`). Client must re-request.                 |
| **Denial of Service via Pending Flooding:** Malicious agent floods approval requests.  | Strict quota limits (1024 global, 64 per actor) and deduplication of identical pending requests.   | `RESOURCE_EXHAUSTED` returned once quota hit; active requests preserved. |
| **Token Oracle Attack:** Attacker brute-forces 256-bit token string.                   | 256 bits of cryptographic entropy + rate limiting + timing-safe comparison.                        | Computationally infeasible ($2^{256}$ search space).                     |

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
  - Implement schema validation, YAML/JSON parser, and AST matchers in `packages/policy`.
  - Order-independent rule evaluation and tie-breaking algorithms.
  - Policy parsing security benchmarks and edge-case unit tests.
- **Task 3: Local Operator Administrative CLI Channel**
  - Implement local IPC communication between `apps/cli` and `apps/mcp-server`.
  - Implement `arc approve`, `arc reject`, `arc approvals list`, and `arc policy test` commands.
- **Task 4: MCP Approval Request & Token Redemption Integration**
  - Wire `_arcApproval` parameter extraction and validation into `ArcMcpServer`.
  - Implement initial `APPROVAL_REQUIRED` flow and verified token redemption path.
  - Enable execution of RC-03 mutation tools strictly upon valid approval consumption.
- **Task 5: Security Hardening, Race Condition Verification & Audit Integration**
  - Full audit logging integration for all approval lifecycle events.
  - Extensive concurrency and race-condition test suite (replays, tampering, expiry races).
  - Memory isolation verification (zero token leakage).
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
15. `RC04-NEG-15`: Actor mismatch (different `clientId` or `sessionId`) causes rejection with `APPROVAL_REJECTED`.
16. `RC04-NEG-16`: Target workspace mismatch causes rejection with `APPROVAL_REJECTED`.
17. `RC04-NEG-17`: Policy change between request and redemption invalidates pending approval.
18. `RC04-NEG-18`: Server restart completely purges active approvals; previously issued tokens are unusable.
19. `RC04-NEG-19`: Malformed YAML policy (syntax error, duplicate mapping keys, custom tags) fails closed with `POLICY_PARSE_ERROR`.
20. `RC04-NEG-20`: Duplicate rule IDs in policy document cause immediate rejection.
21. `RC04-NEG-21`: Unmatched action under explicit operator policy fails closed with default `DENY`.
22. `RC04-NEG-22`: Raw approval token never appears in any serialized AuditRecord across all lifecycle states.
23. `RC04-NEG-23`: Raw file content and patch lines never appear in audit records for approved mutations.
24. `RC04-NEG-24`: Bypass fields (`approvalToken`, `bypassApproval`, `sudo`, `force`) remain rejected by schema.
25. `RC04-NEG-25`: Exhaustion of approval quotas (1024 global, 64 per actor) safely rejects new requests with `RESOURCE_EXHAUSTED`.

---

## 36. Historical Documentation Reconciliation & Ambiguity Clarification

This section normatively clarifies and supersedes earlier ambiguities in RC-00 architecture documents:

1. **Approval Token Nature & Format:** Early documentation referenced both "cryptographic capabilities" and "HMAC tokens". RC-04 clarifies: tokens are high-entropy (256-bit) cryptographically random strings generated out-of-band by the local server; the server stores only their cryptographic digest (SHA-256), completely eliminating server-side token leakage risks.
2. **TTL Start Boundary:** TTL measurement begins strictly at the moment the `PENDING` request record is created on the server, not when the operator grants approval or when the agent receives the error.
3. **Audit Payload Hash vs Execution Payload Hash:** RC-03 introduced `payloadHash` in `AuditRecord` which hashes sanitized parameters for audit privacy. RC-04 introduces `executionPayloadHash`, a distinct internal cryptographic hash binding the complete, unredacted business parameters (including full content bytes) to guarantee payload immutability.
4. **Local Administrative Trust Boundary:** Clarifies that administrative approval operations belong exclusively to local operator CLI execution over local IPC. Ordinary MCP connections have zero administrative surface.
5. **Mutation Policy Floor:** Clarifies that declarative policies cannot authorize automatic file mutation in RC-04; the minimum floor for all five mutation tools remains `REQUIRE_APPROVAL`.

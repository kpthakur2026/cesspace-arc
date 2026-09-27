# RC-08 Scope & Acceptance — Integrations, Cross-Client Validation, Fuzzing & Security Review

| Field          | Value                                                                                                                      |
| :------------- | :------------------------------------------------------------------------------------------------------------------------- |
| **Stage**      | RC-08                                                                                                                      |
| **Title**      | Integrations & Security Review — Scope, Threat Model, Fuzzing Framework, Adversarial Testing & Acceptance Freeze           |
| **Status**     | **Task-0 Scope Candidate — Frozen Architecture Specification**                                                             |
| **Base main**  | `264b462da5477037ae9439659cbb9bb4748b0792`                                                                                 |
| **Branch**     | `feat/rc-08-integrations-security-review`                                                                                  |
| **Target Ver** | `0.8.0-rc08` (promotion in Task 8 only; current version remains `0.7.0-rc07`)                                              |
| **Target Stg** | `RC-08` (promotion in Task 8 only; current health stage remains `RC-07`)                                                   |
| **Purpose**    | Freeze cross-client compatibility, protocol/schema fuzzing, penetration boundaries, negative controls, and positive flows. |

> **Mandatory Rule:** Implementation MUST NOT begin until this scope is independently reviewed and approved.
> This document is an authoritative normative contract. Every rule herein is designed to be directly code-testable.
> None of the functional test harnesses, fuzzing runners, or penetration fixtures are implemented in Task 0.

---

## 1. Authority, Mission & Core Question

### 1.1 Authority and Purpose

This document is the **authoritative architectural contract** for Stage RC-08 ("Integrations & Security Review") of CesSpace ARC.
Upon approval, it establishes the immutable scope, security boundaries, fuzzing frameworks, penetration test specifications, client interoperability matrices, negative control catalog (`RC08-NEG-001`..`090`), positive acceptance flows (`RC08-FLOW-01`..`20`), and task ownership matrix for the entire RC-08 milestone.

In accordance with strict Task 0 discipline:

- **Task 0 is documentation-only.** No implementation code, test harnesses, fuzzing engines, or penetration fixtures are introduced in Task 0.
- **Main branch is untouched.** All work is conducted on `feat/rc-08-integrations-security-review` branched from main at commit `264b462da5477037ae9439659cbb9bb4748b0792`.
- **No PR is opened.** Task 0 stops for independent review before Task 1 may commence.

### 1.2 The Authoritative RC-08 Mission

As defined in the authoritative CesSpace ARC roadmap, Stage RC-08 is dedicated to **Integrations & Security Review**, focused on three core target capabilities:

1. **Cross-Client Validation:** Proving strict protocol interoperability, compatibility, and isolation across official MCP SDK clients, streamable HTTP clients, independent raw JSON-RPC harnesses, and vendor client specifications.
2. **Penetration Testing:** Subjecting ARC's authentication, authorization, filesystem jailing, Git mediation, process supervision, audit ledger, and remote transport to rigorous, adversarial, non-destructive local testing.
3. **Fuzzing:** Deploying seeded, bounded, deterministic fuzz and property testing across the externally reachable JSON-RPC protocol parser, HTTP gateway ingress, and all 25 production tool input schemas.

RC-08 represents the **FINAL core release-candidate validation stage** prior to the 1.0 release series.

### 1.3 The RC-08 Core Question

This specification directly answers:

> **"Can CesSpace ARC 0.7.0-rc07 safely and interoperably operate as an MCP agent-to-machine control plane under hostile, malformed, concurrent, cross-client, and protocol-edge conditions?"**

RC-08 is designed primarily to **TEST and HARDEN** the existing product. New production functionality requires a concrete, reproducible acceptance failure; speculative features or unprompted schema expansions are prohibited.

---

## 2. Starting Baseline & Current Release State

The authoritative starting baseline for Stage RC-08 is commit `264b462da5477037ae9439659cbb9bb4748b0792` on branch `main` (the independently verified RC-07 merge commit). RC-07 is fully CLOSED.

### 2.1 Baseline State Summary

- **Package Version:** `0.7.0-rc07`
- **Health Version:** `0.7.0-rc07`
- **Health Stage:** `RC-07`
- **Production Tool Count:** Exactly 25
- **Deterministic Execution Registry Count:** Exactly 5 entries
- **Test Baseline:** 2063 passing tests across 313 test suites (0 failing, 0 skipped)

### 2.2 Production Tool Inventory (25 Tools)

| #   | Tool Name             | Tier / Mode        | Description                                       |
| :-- | :-------------------- | :----------------- | :------------------------------------------------ |
| 1   | `health`              | Tier 1 / Read-Only | System health and stage status                    |
| 2   | `system_status`       | Tier 1 / Read-Only | Host system metrics and resource usage            |
| 3   | `list_directory`      | Tier 1 / Read-Only | Jailed directory content listing                  |
| 4   | `read_file`           | Tier 1 / Read-Only | Jailed file content inspection                    |
| 5   | `search_files`        | Tier 1 / Read-Only | Glob-based file discovery within workspace        |
| 6   | `search_text`         | Tier 1 / Read-Only | Regex/string search within workspace              |
| 7   | `git_status`          | Tier 1 / Read-Only | Repository working tree status                    |
| 8   | `git_diff`            | Tier 1 / Read-Only | Bounded repository diff inspection                |
| 9   | `git_log`             | Tier 1 / Read-Only | Bounded commit history inspection                 |
| 10  | `run_command`         | Tier 2 / Execution | Bounded, non-shell child process execution        |
| 11  | `process_status`      | Tier 2 / Read-Only | Supervised process state query                    |
| 12  | `process_output`      | Tier 2 / Read-Only | Bounded process stdout/stderr retrieval           |
| 13  | `terminate_process`   | Tier 2 / Control   | Supervised process cancellation (SIGTERM/SIGKILL) |
| 14  | `create_file`         | Tier 2 / Mutation  | Jailed file creation with size limits             |
| 15  | `write_file`          | Tier 2 / Mutation  | Jailed file overwrite with size limits            |
| 16  | `delete_file`         | Tier 2 / Mutation  | Jailed file deletion                              |
| 17  | `move_file`           | Tier 2 / Mutation  | Jailed file move / rename within workspace        |
| 18  | `apply_patch`         | Tier 2 / Mutation  | Atomic unified diff patch engine                  |
| 19  | `arc_repo_status`     | Tier 3 / Composite | High-level repository inspection                  |
| 20  | `arc_worktree_status` | Tier 3 / Composite | Worktree discovery and validation                 |
| 21  | `arc_review_diff`     | Tier 3 / Composite | Redacted, bounded code review diff                |
| 22  | `arc_verify`          | Tier 3 / Composite | Deterministic check-only verification suite       |
| 23  | `arc_test`            | Tier 3 / Composite | Supervised, targeted test runner                  |
| 24  | `arc_ci_status`       | Tier 3 / Composite | Local CI simulation (zero-network)                |
| 25  | `arc_stage_evidence`  | Tier 3 / Composite | Stage evidence aggregation from Git & Audit       |

### 2.3 Deterministic Execution Registry (5 Entries)

1. `verify-format-v1`: `prettier --check .`
2. `verify-lint-v1`: `eslint .`
3. `verify-typecheck-v1`: `tsc --noEmit`
4. `verify-test-v1`: `vitest run`
5. `arc-test-node-v1`: `node --test`

---

## 3. In-Scope & Out-of-Scope Boundaries

### 3.1 In-Scope for RC-08

1. **Cross-Client MCP Conformance Testing:**
   - Formal verification against official MCP TypeScript SDK stdio client.
   - Formal verification against official MCP TypeScript SDK Streamable HTTP client over real TLS 1.3, mTLS, device enrollment, and authenticated sessions.
   - Independent raw JSON-RPC client harness executing without ARC server internals.
   - Multi-session concurrency, handshake negotiation, tools/list, tools/call, approval flow, and cancellation.
2. **Protocol & MCP Ingress Fuzzing:**
   - Seeded, bounded, deterministic fuzzing of JSON-RPC wire framing, malformed JSON, protocol edge cases, oversized payloads, chunked transport, and out-of-order execution.
3. **Tool-Schema Fuzzing:**
   - Property-based fuzzing of all 25 production tool input schemas to verify fail-closed rejection before subsystem dispatch.
4. **Local Adversarial & Penetration Testing:**
   - Non-destructive penetration testing against loopback/local test fixtures covering authentication (mTLS/sessions), authorization (approvals/plans), filesystem jailing, Git execution, process supervision, and persistent audit durability.
5. **Resource & DoS Stress Review:**
   - Bounded concurrency, connection exhaustion, slow-trickle HTTP, and buffer pressure tests proving bounded refusal without service crashes.
6. **Cross-Workspace & Cross-Client Isolation:**
   - Rigorous proof that concurrent clients and multiple workspaces maintain strict cryptographic, process, and data isolation.
7. **Production Hardening:**
   - Targeted hardening of existing code exclusively to resolve concrete failures discovered during validation.

### 3.2 Out-of-Scope for RC-08 (Explicit Prohibitions)

The following activities are strictly prohibited during Stage RC-08:

- **No New Production Tools:** Tool count remains frozen at 25.
- **No Schema Expansions:** MCP tool schemas are frozen; additions require concrete failure justification.
- **No Production Cloud Relay:** Hosted cloud relay infrastructure is explicitly out of scope.
- **No OAuth Provider:** OAuth 2.0 / OIDC provider implementation belongs to post-RC08 distribution.
- **No Public Cloud Services:** Exposing public listener endpoints or hosted domains (`mcp.cesspace...`).
- **No Directory Submissions:** Submitting to ChatGPT Plugins Directory or Claude Connectors Directory.
- **No OS-Level Child Network Sandboxing:** OS-level kernel network namespaces for child test processes are deferred beyond RC-08.
- **No Git Mutations:** Agent Git mutating operations (`commit`, `push`, branch mutations) remain prohibited.
- **No Premature Version/Stage Promotion:** Version remains `0.7.0-rc07` and stage remains `RC-07` until Task 8.

---

## 4. Post-RC08 / ARC 1.0 Distribution Boundary

A strict architectural boundary separates RC-08 core validation from the future **ARC 1.0 Distribution & Hosted Services Plan**:

```text
┌──────────────────────────────────────────────┐       ┌──────────────────────────────────────────────┐
│           STAGE RC-08 (CORE CONTROL)         │       │          POST-RC08 / ARC 1.0 DISTRIBUTION    │
│                                              │       │                                              │
│ - Vendor-neutral agent control plane         │       │ - CesSpace hosted cloud relay                │
│ - Local & Remote Streamable HTTP (TLS 1.3)   │  ───► │ - Public mcp.cesspace... service             │
│ - Mutual TLS (mTLS) device enrollment        │       │ - CesSpace multi-tenant account system       │
│ - Ephemeral session authentication           │       │ - OAuth 2.0 / OIDC authorization server      │
│ - Declarative policy engine & approvals      │       │ - Directory publishing (OpenAI / Anthropic)  │
│ - Append-only anchored audit ledger          │       │ - Commercial device-pairing relay service    │
│ - Rigorous cross-client compatibility proof  │       │ - Billing, metering & SaaS subscriptions     │
│ - Local adversarial and fuzzing verification │       │ - Public multi-tenant cloud hosting          │
└──────────────────────────────────────────────┘       └──────────────────────────────────────────────┘
```

RC-08 proves that ARC is technically capable, safe, robust, and interoperable as an MCP server. It does NOT implement or deploy hosted commercial distribution infrastructure.

---

## 5. Frozen Architecture & Security Invariants

RC-08 strictly preserves all architectural and security invariants established across Stages RC-01 through RC-07. RC-08 may NOT weaken:

1. **Default Deny (INV-01):** Unmatched tools, workspaces, or network origins are denied by default.
2. **Mandatory Pipeline (INV-02):** Every privileged tool call MUST traverse: `Authentication -> Policy Evaluation -> Audit STARTED -> Subsystem Execution -> Audit COMPLETED`.
3. **Canonical Workspace Jailing (INV-03):** All filesystem paths are resolved via `fs.realpath` and strictly verified within the canonical workspace boundary. Symlink escapes (`../`) are denied fail-closed.
4. **No Arbitrary Shell Execution (INV-04):** Subprocesses are invoked with `shell: false` using discrete, validated token argument arrays (`argv: string[]`). No shell command strings or shell metacharacters.
5. **Supervised Process Registry (INV-05):** All processes are tracked in `ProcessRegistry` with PID reuse validation via `/proc/[pid]/stat` field 22, bounded buffers, and hard timeouts.
6. **Escalated Process Termination (INV-06):** Unyielding processes receive `SIGTERM`, followed by `SIGKILL` escalation.
7. **Orphan Recovery (INV-07):** Grandchild and orphaned processes are tracked via process group IDs and reaped on server startup or task abort.
8. **Policy Precedence (INV-08):** `DENY > REQUIRE_APPROVAL > ALLOW`. `DENY` unconditionally overrides approvals.
9. **Cryptographic Approval Binding (INV-09):** Approval tokens are single-use 32-byte cryptographically random tokens bound to `toolName`, `workspaceId`, `actorId`, canonical `planHash`, and `policyHash`. Comparison uses `crypto.timingSafeEqual`.
10. **Single Durable Audit Ledger (INV-10):** All events are recorded in a monotonic SHA-256 hash-chained JSONL ledger. Segment files are anchored and signed.
11. **Audit Fail-Closed Latch (INV-11):** Failure to persist durable audit records halts execution immediately or latches the server into `DEGRADED_AUDIT_FAILURE`.
12. **TLS 1.3-Only Remote Transport (INV-12):** Remote transport enforces TLS 1.3 exclusively with secure cipher suites (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_GCM_SHA256`). TLS 1.2 or below is rejected.
13. **Mandatory Mutual TLS (INV-13):** Remote HTTP endpoints mandate valid client certificates enrolled in the device trust store.
14. **Layer-C Admission Control (INV-14):** Token bucket rate and burst limiting protects the gateway against connection and request exhaustion.
15. **Composite Composition Invariant (INV-15):** Tier-3 composite tools compose lower-level primitives; direct `child_process` or `fs` bypasses in composite modules are forbidden.
16. **Anti-Fabrication Invariant (INV-16):** Passing tests or clean Git state never fabricates release approval; stage evidence reports strictly verifiable ledger records.

---

## 6. Cross-Client Compatibility & Conformance Matrix

RC-08 establishes an automated, deterministic cross-client compatibility harness covering the following matrix:

| Client Type                  | Transport               | Security Context                               | Execution Mode  | Scope & Coverage                                                                                                                     |
| :--------------------------- | :---------------------- | :--------------------------------------------- | :-------------- | :----------------------------------------------------------------------------------------------------------------------------------- |
| **MCP Reference SDK Client** | Stdio (Piped JSON-RPC)  | Local Kernel Actor                             | Automated CI    | Full initialize handshake, capability negotiation, tools/list pagination, tools/call execution, error responses, ping/notifications. |
| **MCP Reference SDK Client** | Streamable HTTP         | TLS 1.3, mTLS, Enrolled Device, Bearer Session | Automated CI    | Full HTTP handshake, chunked SSE response parsing, header verification, Layer C admission, remote tool execution parity.             |
| **Raw JSON-RPC Harness**     | Stdio & Streamable HTTP | Local & Remote                                 | Automated CI    | Independent parser and serializer with ZERO internal ARC imports. Verifies strict JSON-RPC 2.0 specification conformance.            |
| **Multi-Session Client**     | Streamable HTTP         | Distinct Client IDs & Devices                  | Automated CI    | Multiple concurrent clients accessing distinct workspaces; verifies credential, process, and workspace state isolation.              |
| **Claude Code / Desktop**    | Stdio / Local MCP       | Local Actor                                    | Manual Evidence | Specification compatibility check; verification of tools/list schemas and parameter acceptance.                                      |
| **ChatGPT MCP / Codex**      | Streamable HTTP         | Remote TLS / Bearer                            | Manual Evidence | Remote interface specification conformance; schema compatibility check.                                                              |

_Note on Vendor Testing:_ Automated CI tests remain vendor-neutral and self-contained. No proprietary cloud accounts or third-party network access are required for CI.

---

## 7. Threat & Adversarial Model

RC-08 tests ARC against an expanded threat model targeting edge cases, protocol malformations, and adversarial bypasses:

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       ADVERSARIAL ATTACK SURFACES                               │
├─────────────────────────┬─────────────────────────┬────────────────────────┬─────────────────────┤
│   Ingress & Protocol    │   Identity & Auth       │   Workspace & Storage  │  Host Execution     │
├─────────────────────────┼─────────────────────────┼────────────────────────┼─────────────────────┤
│ - Deeply nested JSON    │ - Expired/revoked certs │ - Path traversal (..)  │ - Shell injection   │
│ - Fragmented chunks     │ - Untrusted client CAs  │ - Absolute symlinks    │ - Flag injection    │
│ - Malformed JSON-RPC    │ - Stolen session tokens │ - Relative symlinks    │ - Orphan survival   │
│ - Schema type confusion │ - Token replay attacks  │ - TOCTOU rename races  │ - SIGTERM resistance│
│ - Slowloris / trickle   │ - Actor substitution    │ - Secret path leakage  │ - Buffer flooding   │
│ - Replayed request IDs  │ - planHash tampering    │ - Git option injection │ - PATH poisoning    │
│ - Host/Origin mismatch  │ - Cross-session misuse  │ - Audit log tampering  │ - PID reuse races   │
└─────────────────────────┴─────────────────────────┴────────────────────────┴─────────────────────┘
```

---

## 8. Protocol & MCP Fuzzing Policy

To ensure high reliability without compromising CI determinism, fuzzing in RC-08 adheres to the following strict policy:

1. **Deterministic Seeds:** Every fuzz run uses a pseudo-random number generator (PRNG) initialized with an explicit seed. Seeds are printed on startup and can be overridden via `FUZZ_SEED=<seed>`.
2. **Reproducibility Guarantee:** Any failing test case outputs the exact reproduction command, input payload, and seed to `tests/fixtures/fuzz-corpus/failures/`.
3. **Bounded Iterations in CI:** CI runs execute a fixed corpus of 100 iterations per fuzz vector. An extended manual profile (`pnpm run test:fuzz:extended`) runs up to 5,000 iterations for deep fuzzing.
4. **Bounded Input Dimensions:**
   - Maximum payload size: 2 MiB (matching remote `MAX_REQUEST_BODY_BYTES`).
   - Maximum recursion / object nesting depth: 10 levels.
   - Maximum array length: 10,000 items.
   - Maximum string length: 1 MiB.
5. **No Host Harm:** Fuzz inputs target parsers and validators only. No fuzzed inputs are passed to unvalidated filesystem or OS commands.
6. **No Network Access:** Fuzzing runs completely offline against in-memory or loopback fixtures.

---

## 9. Tool-Schema Fuzzing Specification (25 Tools)

All 25 production tools are fuzzed to verify that invalid inputs are rejected at the Zod validation layer before any privileged subsystem or process runner is invoked:

1. **Unknown Fields:** Objects with unauthorized fields are rejected (`additionalProperties: false`).
2. **Missing Required Fields:** Mandatory parameters (`workspaceId`, `path`, `command`, `toolName`) cannot be omitted.
3. **Primitive Type Confusion:** Supplying arrays for strings, booleans for numbers, or objects for booleans fails schema validation.
4. **Numeric Boundary Violations:** Negative numbers, `NaN`, `Infinity`, or values exceeding defined ranges are rejected.
5. **String Boundary Violations:** Empty strings (where disallowed) and strings exceeding maximum character limits are rejected.
6. **Dangerous Characters:** NUL bytes (`\0`), control characters, and Unicode normalization anomalies are caught before dispatch.
7. **Injection Payloads:** Path traversal tokens (`../`), Git flags (`--exec`), and shell metacharacters (`;`, `|`, `&`) in filter or path arguments are blocked at schema or plan materialization.

---

## 10. Penetration & Adversarial Testing Policy

Adversarial testing adheres to strict safety boundaries:

1. **Local Test Fixtures Only:** Tests target exclusively loopback interfaces (`127.0.0.1`), ephemeral temporary workspaces (`os.tmpdir()`), temporary PKI certificates, temporary audit directories, and child processes created by the test runner.
2. **Zero External Probing:** Tests must NEVER scan external IP addresses, communicate with third-party servers, probe corporate networks, or harvest credentials from the host user's environment.
3. **Sanitized Host Environment:** Environment variables such as `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, and user SSH keys are stripped or mocked out.
4. **Fail-Closed Verification:** Penetration tests verify that attacks produce the canonical structured error code and that zero partial execution occurs on authorization failures.

---

## 11. Resource & Denial-of-Service (DoS) Review Policy

ARC enforces bounded refusal across all resource vectors:

1. **Request Body Caps:** Maximum 2 MiB per HTTP request body; exceeding bodies are rejected with HTTP 413 `PAYLOAD_TOO_LARGE` before JSON parsing.
2. **Gateway Admission Limiter:** Layer C token bucket bounds request bursts and sustainable rates per client certificate.
3. **Process Concurrency Caps:** Maximum 4 running processes per workspace (`CONCURRENCY_LIMITS.maxPerWorkspaceRunning = 4`). Subsequent executions fail with `CONCURRENCY_EXCEEDED`.
4. **Buffer & Output Caps:** Process stdout/stderr buffers capped at 512 KiB; output responses capped at 128 KiB or 512 KiB depending on tool tier. Truncation is marked truthfully with `truncated: true`.
5. **Execution Timeouts:** Read-only tools hard-capped at 15s; verification steps at 30s; test runs at 60s; composite operations at 120s.

---

## 12. Security Questions and Binding Answers

The following 25 answers constitute binding architectural commitments for RC-08:

1. **Which RC-08 work is test-only vs production-hardening?**
   The conformance test harnesses, fuzzing runners, penetration test suites, and mock client fixtures are test-only. Production code modifications are restricted to targeted bug fixes and hardening required to close concrete vulnerabilities or unhandled exceptions discovered during testing.
2. **What externally reachable protocol surfaces are fuzzed?**
   The stdio JSON-RPC line parser, the Streamable HTTP gateway body decoder, the JSON-RPC envelope parser (version, id, method), and all 25 production tool input schemas.
3. **What maximum fuzz input sizes are allowed?**
   Maximum payload size is 2 MiB, maximum recursion depth is 10 levels, maximum array length is 10,000 items, and maximum string length is 1 MiB.
4. **How is fuzzing made reproducible?**
   By using deterministic pseudo-random generators with explicit 32-bit seeds logged at test startup, and automatically persisting any failing input payload and seed to `tests/fixtures/fuzz-corpus/failures/`.
5. **How are malformed requests prevented from reaching privileged subsystems?**
   Requests traverse a strict multi-tier pipeline: Wire Parsing -> JSON-RPC Envelope Validation -> Zod Schema Validation -> Policy Evaluation. Any malformation is rejected at earlier layers before filesystem, process, or Git subsystems are invoked.
6. **How is client/session isolation proven?**
   By executing automated concurrent multi-client tests verifying that Session A cannot inspect, consume, or hijack session credentials, process outputs, or approval grants belonging to Session B.
7. **How is workspace isolation proven across simultaneous clients?**
   By testing concurrent clients operating on separate registered workspaces, verifying that cross-workspace file accesses, searches, or process listings fail with `WORKSPACE_NOT_FOUND` or `PATH_OUTSIDE_WORKSPACE`.
8. **How are approval tokens bound and replay-protected under fuzz/adversarial use?**
   Tokens are 32-byte cryptographically secure random values bound to `toolName`, validated business parameters, `workspaceId`, `actorId`, `policyHash`, and `planHash`. Comparison uses `crypto.timingSafeEqual`, and `ApprovalStateManager` atomically marks tokens as consumed on first use to prevent replay attacks.
9. **How are TLS/mTLS failures tested?**
   Using local loopback TLS 1.3 servers and testing expired certificates, untrusted CA signatures, mismatched subject names, cleartext HTTP requests, and attempted TLS 1.2 downgrades.
10. **How are session revocation/replay conditions tested?**
    By actively expiring or revoking active sessions in the session store and verifying that subsequent requests using the revoked token immediately fail with HTTP 401 / `INVALID_SESSION_TOKEN`.
11. **How are resource exhaustion attacks bounded?**
    Via strict limits: 2 MiB HTTP body limit, Layer C admission rate limiting, 4 concurrent processes per workspace, 512 KiB process buffer caps, and strict timeouts (15s to 120s).
12. **How are filesystem race/path attacks tested safely?**
    Within isolated temporary directories (`os.tmpdir()`), verifying that symlink escapes, parent directory traversals (`../`), and TOCTOU file swaps are prevented by canonical `realpath` checks.
13. **How are Git argument/revision attacks tested safely?**
    Within isolated temporary Git repositories, verifying that revisions with flag prefixes (`--exec`) or shell injection tokens (`$(id)`) are safely treated as literal arguments and fail without executing commands.
14. **How are process escape/orphan attacks tested?**
    By spawning test processes that ignore `SIGTERM` or spawn grandchildren, then proving that ARC's `ProcessRegistry` successfully escalates to `SIGKILL` and cleans up orphaned process groups.
15. **How are audit corruption/recovery attacks tested?**
    By modifying hash chains, truncating JSONL files, corrupting signatures, or simulating write failures in temporary audit directories, verifying that audit verification detects tampering and write failures trigger the fail-closed latch (`DEGRADED_AUDIT_FAILURE`).
16. **What behavior is Linux-specific?**
    POSIX process-group signaling (`process.kill(-pid)`), `/proc/[pid]/stat` field 22 verification against PID reuse, and Linux filesystem atomicity guarantees.
17. **What cross-platform behaviors are actually claimed?**
    Linux is the authoritative security and production target. macOS and Windows are supported for core MCP JSON-RPC protocol handling, schema validation, policy evaluation, and in-memory operations; Linux-specific process-group escalation and `/proc` inspection are acknowledged as degraded/deferred on non-Linux platforms. WSL is documented as Linux userspace with host integration.
18. **Which real MCP clients form the compatibility matrix?**
    The official MCP TypeScript SDK stdio client, the official MCP TypeScript SDK Streamable HTTP client, an independent raw JSON-RPC client harness, and manual compatibility profiles for Claude Code and ChatGPT.
19. **What vendor-specific testing is automated vs manual?**
    Automated testing covers the standard MCP SDK clients and raw JSON-RPC harness. Testing involving proprietary Claude Code or ChatGPT cloud services is treated as manual evidence; CI requires zero third-party cloud accounts.
20. **What work is explicitly deferred to post-RC08 distribution?**
    Hosted cloud relays, public domain endpoints (`mcp.cesspace...`), multi-tenant account services, OAuth 2.0 authorization servers, plugin directory submissions, commercial device pairing, billing, and SaaS hosting.
21. **Does RC-08 introduce any new production tool?**
    NO. The production tool catalog remains strictly frozen at 25 tools.
22. **Does RC-08 introduce external network dependencies?**
    NO. ARC framework code makes zero outbound network calls, and all tests run locally and offline.
23. **Does RC-08 claim OS network isolation for project code?**
    NO. Arbitrary project/dependency code executed by `arc_verify` and `arc_test` is not claimed to have OS-level network sandboxing in RC-08; this capability is explicitly deferred.
24. **What makes RC-08 acceptance deterministic rather than flaky?**
    Fixed PRNG seeds for fuzzing, bounded iteration counts, isolated temporary fixtures, loopback networking, deterministic plan hashes, and strict timeout budgets.
25. **What exact evidence permits promotion to RC-08?**
    All 90 negative controls passing, all 20 positive flows passing, zero regressions in the 2063 existing tests, 100% clean formatting/lint/typecheck/build, zero Gitleaks secrets, zero vulnerabilities in `pnpm audit`, and a passing `scripts/verify-rc08.sh`.

---

## 13. Platform Support & Operating System Matrix

| Platform                              | Tier                        | Support Level          | Security & Runtime Claims                                                                                                                           |
| :------------------------------------ | :-------------------------- | :--------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Linux (POSIX)**                     | Tier 1 (Authoritative)      | Production & CI Target | Full security claims: POSIX process groups, `/proc/[pid]/stat` PID reuse protection, atomic filesystem semantics, canonical jailing.                |
| **WSL (Windows Subsystem for Linux)** | Tier 1 (Compatible)         | Development & Testing  | Inherits Linux userspace security; host filesystem mounts (`/mnt/c`) must adhere to canonical jailing.                                              |
| **macOS (Darwin)**                    | Tier 2 (Compatible)         | Developer Workstation  | Supported for core MCP protocol, schema validation, policy, and audit. Process group signaling supported; `/proc` checks fallback to POSIX signals. |
| **Windows (Native)**                  | Tier 3 (Deferred Hardening) | Basic Compatibility    | Basic stdio MCP and tool execution supported. Process-tree termination and POSIX process-group guarantees are deferred to future stages.            |

---

## 14. Decision on OS-Level Network Sandboxing

### 14.1 Explicit Decision: DEFERRED

OS-level network isolation (e.g. Linux network namespaces `unshare -n`, seccomp network filter, or eBPF cgroup egress filtering) for arbitrary child project/dependency code executed by `arc_verify` and `arc_test` is **EXPLICITLY DEFERRED** to post-RC08 hardening.

### 14.2 Rationale & Impact Analysis

- **Threat Addressed:** Malicious or compromised project dependencies attempting outbound network exfiltration during test execution.
- **Target OS:** Linux-specific (`CLONE_NEWNET`, network namespaces, iptables/nftables).
- **Compatibility Impact:** Creating Linux network namespaces requires root privileges (`CAP_SYS_ADMIN` or `CAP_NET_ADMIN`) or user namespaces (`unprivileged_userns_clone`). In containerized CI environments (such as Docker, GitHub Actions, or Kubernetes unprivileged pods), unprivileged user namespaces are frequently restricted or disabled, which would cause severe test flakiness or execution failures.
- **Current Mitigation:** ARC composite framework code operates with **zero outbound network calls**, strips all ambient environment credentials (`GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`), and accepts no client network credentials.
- **Conclusion:** RC-08 maintains truthful documentation that project code is not OS-network sandboxed. OS network sandboxing is scheduled for post-RC08 containerized agent environments.

---

## 15. Production Tool Catalog & Deterministic Registry Freeze

- **Production Tool Count:** Exactly **25 tools**. No tools added, removed, or modified.
- **Deterministic Execution Registry:** Exactly **5 entries**. No entries added, removed, or modified.

---

## 16. Task Breakdown & Ownership Matrix (Tasks 0 to 8)

The RC-08 implementation is partitioned into **nine** discrete tasks (Task 0 through Task 8):

| Task  | Title                                             | Scope & Deliverables                                                                                                            | Negative Controls Owned  | Positive Flows Owned     |
| :---- | :------------------------------------------------ | :------------------------------------------------------------------------------------------------------------------------------ | :----------------------- | :----------------------- |
| **0** | **Scope, Threat Model & Acceptance Freeze**       | Architecture specification, threat model, fuzzing policy, negative controls, positive flows, README update.                     | N/A (Documentation Only) | N/A (Documentation Only) |
| **1** | **Cross-Client MCP Conformance Harness**          | Official MCP SDK stdio client harness, Streamable HTTP client harness, raw JSON-RPC client harness, handshake validation.       | `RC08-NEG-001`..`010`    | `RC08-FLOW-01`..`04`     |
| **2** | **Protocol & Schema Fuzzing Framework**           | Seeded deterministic fuzzer, JSON-RPC malformed input tests, property-based tool schema fuzzing across all 25 tools.            | `RC08-NEG-011`..`025`    | `RC08-FLOW-05`..`06`     |
| **3** | **Remote Gateway Adversarial / Pen Tests**        | TLS 1.3/mTLS penetration tests, untrusted CA rejection, session replay, token forging, Layer C admission stress.                | `RC08-NEG-026`..`037`    | `RC08-FLOW-07`..`08`     |
| **4** | **Filesystem, Git & Workspace Adversarial Tests** | Symlink escapes, path traversals (`../`), TOCTOU races, Git option injection, sensitive rename diff leakage.                    | `RC08-NEG-038`..`048`    | `RC08-FLOW-09`..`10`     |
| **5** | **Process, Approval & Audit Adversarial Tests**   | Shell injection resistance, orphan process reaping, SIGKILL escalation, approval replay/tampering, audit tampering.             | `RC08-NEG-049`..`060`    | `RC08-FLOW-11`..`13`     |
| **6** | **Concurrency, Resource Exhaustion & Robustness** | Process concurrency limits, stream buffer exhaustion, socket storm handling, slow-trickle DoS mitigation.                       | `RC08-NEG-061`..`070`    | `RC08-FLOW-14`           |
| **7** | **Cross-Client & Cross-Workspace Isolation**      | Cross-workspace boundary proofs, cross-session credential isolation, process output separation, client cancellation.            | `RC08-NEG-071`..`080`    | `RC08-FLOW-15`..`17`     |
| **8** | **Final Hardening, Acceptance & Promotion**       | Full verification script `scripts/verify-rc08.sh`, promotion to `0.8.0-rc08` / `RC-08`, final integration report, PR readiness. | `RC08-NEG-081`..`090`    | `RC08-FLOW-18`..`20`     |

---

## 17. Negative Security Control Catalog (`RC08-NEG-001`..`090`)

All 90 negative controls are mandatory, immutable, and assigned to a specific future task owner.

### Category 1: Cross-Client Protocol Conformance (Task 1 Owner)

- **`RC08-NEG-001`**: Client sends `tools/call` before protocol initialization (`initialize`). Rejected with `INVALID_INITIALIZATION_ORDER` (integration).
- **`RC08-NEG-002`**: Client negotiates unsupported MCP protocol version. Handshake rejected with `UNSUPPORTED_PROTOCOL_VERSION` (integration).
- **`RC08-NEG-003`**: Client sends JSON-RPC notification for call-only method (e.g. `tools/call` without id). Rejected or unacknowledged without execution (integration).
- **`RC08-NEG-004`**: Client sends batch JSON-RPC request containing mixed valid and invalid payloads. Processed atomically per-request without session corruption (integration).
- **`RC08-NEG-005`**: Client requests unknown MCP method outside protocol specification. Rejected with `METHOD_NOT_FOUND` / `-32601` (integration).
- **`RC08-NEG-006`**: Client sends duplicate concurrent request IDs over stdio transport. Handled deterministically without state corruption (integration).
- **`RC08-NEG-007`**: Client disconnects during `tools/call` processing. Active server handlers terminate cleanly without leaving hung promises (integration).
- **`RC08-NEG-008`**: Client supplies invalid or corrupted cursor in `tools/list` pagination request. Rejected with `INVALID_PAGINATION_TOKEN` (integration).
- **`RC08-NEG-009`**: Independent raw JSON-RPC client omits required protocol envelopes. Server rejects with `INVALID_REQUEST` / `-32600` (integration).
- **`RC08-NEG-010`**: Unauthenticated client attempts rapid reconnection storm. Terminated without file descriptor leakage (integration).

### Category 2: Protocol & Tool-Schema Fuzzing (Task 2 Owner)

- **`RC08-NEG-011`**: Fuzz: Deeply nested JSON payload (>10 levels) across transport boundaries. Rejected with `PAYLOAD_TOO_DEEP` or `INVALID_REQUEST` (fuzz).
- **`RC08-NEG-012`**: Fuzz: JSON array containing >10,000 items or numbers exceeding IEEE 754 precision. Rejected before dispatch (fuzz).
- **`RC08-NEG-013`**: Fuzz: Invalid UTF-8 bytes or non-standard Unicode escape sequences. Rejected at parse layer with `PARSE_ERROR` / `-32700` (fuzz).
- **`RC08-NEG-014`**: Fuzz: NUL bytes (`\0`) and unprintable control characters in string parameters. Rejected by Zod schemas before subsystem execution (fuzz).
- **`RC08-NEG-015`**: Fuzz: Duplicate object keys in JSON payload. Handled deterministically without prototype pollution (fuzz).
- **`RC08-NEG-016`**: Fuzz: Schema fuzzing across all 25 production tools with unauthorized/unknown properties. Rejected with `INVALID_REQUEST_SCHEMA` (fuzz).
- **`RC08-NEG-017`**: Fuzz: Missing required properties across all 25 production tools. Rejected at schema layer before reaching execution (fuzz).
- **`RC08-NEG-018`**: Fuzz: Primitive type confusion across all 25 tools (arrays for strings, objects for booleans). Rejected with `INVALID_REQUEST_SCHEMA` (fuzz).
- **`RC08-NEG-019`**: Fuzz: Path fields with complex path traversals (`....//`, URL-encoded `%2e%2e`). Blocked with `PATH_OUTSIDE_WORKSPACE` (fuzz).
- **`RC08-NEG-020`**: Fuzz: Git tool arguments with option injection (`--upload-pack`, `-o`, `--exec`). Blocked with `INVALID_GIT_ARGUMENT` (fuzz).
- **`RC08-NEG-021`**: Fuzz: Filter and path fields in composite tools with shell metacharacters (`;`, `|`, `&`, `$()`). Blocked with `INVALID_REQUEST_SCHEMA` (fuzz).
- **`RC08-NEG-022`**: Fuzz: Truncated or fragmented JSON chunks fed into streaming parser. Parsed cleanly or rejected on timeout without process crash (fuzz).
- **`RC08-NEG-023`**: Fuzz: Oversized string fields (>1 MiB) in tool parameters. Rejected before memory allocation blowup (fuzz).
- **`RC08-NEG-024`**: Fuzz: Malformed approval token fields (corrupted hex, wrong length, non-ASCII). Rejected with `INVALID_REQUEST_SCHEMA` / `TOKEN_MISMATCH` (fuzz).
- **`RC08-NEG-025`**: Fuzz: Seeded property testing reproducibility check: re-running failing seed yields identical failure trajectory (fuzz).

### Category 3: Remote Gateway Adversarial Testing (Task 3 Owner)

- **`RC08-NEG-026`**: Remote: Client presents TLS certificate signed by untrusted CA. Terminated at TLS layer with `CERT_UNTRUSTED` (integration).
- **`RC08-NEG-027`**: Remote: Client certificate CN/SAN does not match enrolled device ID. Admission rejected with `UNAUTHENTICATED` (integration).
- **`RC08-NEG-028`**: Remote: Client presents expired client certificate. Terminated at TLS layer (integration).
- **`RC08-NEG-029`**: Remote: Client attempts TLS 1.2 or below connection (downgrade attack). Connection terminated by TLS 1.3-only cipher configuration (integration).
- **`RC08-NEG-030`**: Remote: Cleartext HTTP request sent to remote TLS 1.3 listener port. Socket closed with zero response (integration).
- **`RC08-NEG-031`**: Remote: Host header mismatch (DNS rebinding attack). Request rejected with `INVALID_HOST_HEADER` / 400 (integration).
- **`RC08-NEG-032`**: Remote: Origin header validation failure for browser-originated requests. Rejected with `ORIGIN_MISMATCH` / 403 (integration).
- **`RC08-NEG-033`**: Remote: Malformed or forged session bearer token. Rejected with `INVALID_SESSION_TOKEN` / 401 (integration).
- **`RC08-NEG-034`**: Remote: Replay of expired or revoked session token. Rejected with `SESSION_EXPIRED` / `SESSION_REVOKED` / 401 (integration).
- **`RC08-NEG-035`**: Remote: Slow-trickle / slowloris HTTP request body. Timed out and closed by gateway admission ceiling (integration).
- **`RC08-NEG-036`**: Remote: Layer C admission rate-limit exhaustion by single client. Enforced; bursts beyond token bucket rejected with 429 (integration).
- **`RC08-NEG-037`**: Remote: Request body exceeding `MAX_REQUEST_BODY_BYTES` (2 MiB). Rejected with `PAYLOAD_TOO_LARGE` / 413 before parsing (integration).

### Category 4: Filesystem, Git & Workspace Adversarial Testing (Task 4 Owner)

- **`RC08-NEG-038`**: FS: Absolute symlink pointing outside authorized workspace. Read/write rejected with `SYMLINK_ESCAPE_DETECTED` / `PATH_OUTSIDE_WORKSPACE` (integration).
- **`RC08-NEG-039`**: FS: Relative symlink chain traversing workspace boundary. Rejected with `SYMLINK_ESCAPE_DETECTED` (integration).
- **`RC08-NEG-040`**: FS: TOCTOU file swap / rename race condition during path validation. Handled fail-closed without directory escape (integration).
- **`RC08-NEG-041`**: FS: Direct access attempt to sensitive system paths (`/etc/shadow`, `/proc/kcore`, `~/.ssh`). Blocked with `ACCESS_DENIED` (integration).
- **`RC08-NEG-042`**: FS: Path containing NUL byte injection (`file.txt\0.js`). Rejected before system call (integration).
- **`RC08-NEG-043`**: FS: Creation of file inside non-existent or restricted directory. Fails closed with `DIRECTORY_NOT_FOUND` / `ACCESS_DENIED` (integration).
- **`RC08-NEG-044`**: Git: Revision parameter containing option injection (`--output=/tmp/pwn`). Rejected with `INVALID_GIT_ARGUMENT` (integration).
- **`RC08-NEG-045`**: Git: Revision parameter containing shell command expansion (`$(whoami)`). Rejected with `INVALID_GIT_ARGUMENT` (integration).
- **`RC08-NEG-046`**: Git: Attempt to invoke mutating commands (`git commit`, `git push`, `git checkout`). Rejected by read-only Git surface (integration).
- **`RC08-NEG-047`**: Git: Sensitive path rename disclosure attempt in diff review. Hunks and endpoint references sanitized (integration).
- **`RC08-NEG-048`**: Git: Malicious `.git` config or hook injection attempt inside workspace. Blocked by workspace jailing and policy (integration).

### Category 5: Process, Approval & Audit Adversarial Testing (Task 5 Owner)

- **`RC08-NEG-049`**: Process: Attempted shell injection via command argument array token concatenation. Prevented by `shell: false` argument passing (OS-process).
- **`RC08-NEG-050`**: Process: Binary name containing directory traversal or path separators (`../../bin/sh`). Denied by executable resolver (OS-process).
- **`RC08-NEG-051`**: Process: PATH environment poisoning to substitute trusted binary. Sanitized environment prevents hijack (OS-process).
- **`RC08-NEG-052`**: Process: Stubborn child ignoring SIGTERM. SIGKILL escalation terminates child within grace window (OS-process).
- **`RC08-NEG-053`**: Process: Grandchild process fork attempting orphan survival. Swept and reaped by ProcessRegistry group tracking (OS-process).
- **`RC08-NEG-054`**: Process: High stdout volume spam. Output buffer cap truncates safely without Node buffer overflow (OS-process).
- **`RC08-NEG-055`**: Approval: Actor A attempts to redeem approval token issued for Actor B. Denied with `APPROVAL_ACTOR_MISMATCH` (integration).
- **`RC08-NEG-056`**: Approval: Parameter modification between approval request and redemption (`planHash` mismatch). Denied with `APPROVAL_PLAN_MISMATCH` (integration).
- **`RC08-NEG-057`**: Approval: Replay of consumed approval token. Denied with `APPROVAL_ALREADY_CONSUMED` (integration).
- **`RC08-NEG-058`**: Audit: Tampering with hash chain of audit records on disk. Audit verification detects failure (`integrity: FAILED`) (integration).
- **`RC08-NEG-059`**: Audit: Truncating persistent audit segment file. Audit verification detects broken sequence or missing terminator (integration).
- **`RC08-NEG-060`**: Audit: Durable storage write failure on `STARTED` event. Execution halted fail-closed with zero subsystem execution (integration).

### Category 6: Concurrency & Resource Exhaustion (Task 6 Owner)

- **`RC08-NEG-061`**: Resource: Maximum concurrent running processes per workspace (`CONCURRENCY_LIMITS.maxPerWorkspaceRunning = 4`) strictly enforced. Fifth call rejected with `CONCURRENCY_EXCEEDED` (integration).
- **`RC08-NEG-062`**: Resource: Global concurrent process exhaustion across workspaces. Bounded rejection prevents host exhaustion (integration).
- **`RC08-NEG-063`**: Resource: High concurrent read requests do not corrupt audit record sequence numbering. Sequence remains monotonic (integration).
- **`RC08-NEG-064`**: Resource: Rapid connection/disconnection storm does not exhaust available server socket pool or crash event loop (integration).
- **`RC08-NEG-065`**: Resource: Massive search query payload producing huge match set. Bounded output cap limits memory consumption (integration).
- **`RC08-NEG-066`**: Resource: Subprocess output stream continuous flood. Bounded capture buffers prevent OOM (integration).
- **`RC08-NEG-067`**: Resource: Rapid approval request generation does not cause memory leak in `ApprovalStateManager`. Stale requests cleaned up (integration).
- **`RC08-NEG-068`**: Resource: Bounded audit segment rollover prevents single huge file growth on disk (integration).
- **`RC08-NEG-069`**: Robustness: Client abrupt socket termination during chunked SSE response cleans up server resources without hang (integration).
- **`RC08-NEG-070`**: Robustness: Process registry state persistence survives simulated server crash and restores sweep state on restart (integration).

### Category 7: Cross-Client & Cross-Workspace Isolation (Task 7 Owner)

- **`RC08-NEG-071`**: Isolation: Client in Session A cannot read files from Workspace B (not registered to Session A). Blocked with `WORKSPACE_NOT_FOUND` / `ACCESS_DENIED` (integration).
- **`RC08-NEG-072`**: Isolation: Client in Session A cannot view process status or output of process launched in Session B. Blocked with `PROCESS_NOT_FOUND` (integration).
- **`RC08-NEG-073`**: Isolation: Client in Session A cannot terminate process owned by Session B. Blocked with `PROCESS_NOT_FOUND` / `ACCESS_DENIED` (integration).
- **`RC08-NEG-074`**: Isolation: Policy rule applied to Workspace A does not leak or alter policy evaluation in Workspace B (integration).
- **`RC08-NEG-075`**: Isolation: Session token issued to Client A cannot be used on connection from Client B's mTLS certificate. Denied with `SESSION_DEVICE_MISMATCH` (integration).
- **`RC08-NEG-076`**: Isolation: Audit log entries for Workspace A do not contain confidential metadata from Workspace B operations (integration).
- **`RC08-NEG-077`**: Interruption: Client cancellation of composite tool (`arc_verify`) halts all executing child processes immediately (OS-process).
- **`RC08-NEG-078`**: Interruption: Client disconnect during `arc_test` halts test runner and sweeps process group (OS-process).
- **`RC08-NEG-079`**: Isolation: Concurrent execution across two distinct workspaces does not cross-pollinate environment variables or working directories (integration).
- **`RC08-NEG-080`**: Parity: Tool invocation over stdio and remote HTTP yields identical error classification and error shape for blocked operations (integration).

### Category 8: Cross-Cutting Hardening, Invariants & Verification (Task 8 Owner)

- **`RC08-NEG-081`**: Invariant: Any attempt to add unreviewed production tool beyond the frozen 25 fails discovery audit (static).
- **`RC08-NEG-082`**: Invariant: Any direct Node `child_process` import in composite tool modules fails static lint check (static).
- **`RC08-NEG-083`**: Invariant: Any direct Node `fs` import in composite tool modules fails static lint check (static).
- **`RC08-NEG-084`**: Invariant: Production deterministic registry contains only approved entries (count = 5) (static).
- **`RC08-NEG-085`**: Invariant: Public `run_command` refuses `npm run`, `pnpm run`, or arbitrary shell execution (integration).
- **`RC08-NEG-086`**: Invariant: `arc_ci_status` executes zero outbound network calls under all conditions (integration).
- **`RC08-NEG-087`**: Invariant: Audit degraded latch (`DEGRADED_AUDIT_FAILURE`) permanently blocks subsequent privileged tool executions (integration).
- **`RC08-NEG-088`**: Invariant: Secret redaction engine reliably sanitizes high-entropy keys, TLS certificates, and tokens in error payloads (integration).
- **`RC08-NEG-089`**: Invariant: Stage evidence cannot fabricate approval when required verification gates are unmet (integration).
- **`RC08-NEG-090`**: Invariant: Version and stage promotion rules strictly enforced: promotion occurs only when all quality gates and verification script pass (static).

---

## 18. Positive Acceptance Flow Catalog (`RC08-FLOW-01`..`20`)

All 20 positive acceptance flows are mandatory and assigned to future task owners:

| Flow ID        | Title                                                | Description                                                                                                                 | Owner  |
| :------------- | :--------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------- | :----- |
| `RC08-FLOW-01` | Official MCP SDK Stdio Session                       | Client performs initialize handshake, capability exchange, `tools/list`, and tool execution via stdio.                      | Task 1 |
| `RC08-FLOW-02` | Official MCP SDK Streamable HTTP Session             | Client performs mTLS handshake, device enrollment, session establishment, and tool execution over TLS 1.3.                  | Task 1 |
| `RC08-FLOW-03` | Independent Raw JSON-RPC Client Flow                 | Custom non-SDK client communicates with ARC stdio, verifying pure specification conformance.                                | Task 1 |
| `RC08-FLOW-04` | Multi-Session Client Concurrency                     | Multiple client sessions concurrently initialize, negotiate capabilities, and query tool listings.                          | Task 1 |
| `RC08-FLOW-05` | Deterministic Corpus Fuzz Execution                  | Seeded fuzzer executes full corpus against JSON-RPC transport and 25 tool schemas; all cases properly handled.              | Task 2 |
| `RC08-FLOW-06` | Property-Based Schema Validation Flow                | Fast-check property engine verifies schema boundary invariants with deterministic seed reproduction.                        | Task 2 |
| `RC08-FLOW-07` | Authenticated Remote Gateway Tool Call               | Valid mTLS client executes read-only tool (`read_file`) over TLS 1.3 with chunked SSE response.                             | Task 3 |
| `RC08-FLOW-08` | Remote Layer-C Token Refill Flow                     | Client consumes rate-limit tokens, waits for bucket refill, and verifies subsequent requests succeed.                       | Task 3 |
| `RC08-FLOW-09` | Canonical Filesystem & Symlink Traversal             | Jailed read/list operations traverse legitimate internal symlinks while strictly blocking escapes.                          | Task 4 |
| `RC08-FLOW-10` | Protected Git Inspection Workflow                    | Execute `git_status`, `git_log`, `git_diff` on complex branch history; receive structured, redacted diff.                   | Task 4 |
| `RC08-FLOW-11` | Controlled Process Supervision Flow                  | Launch legitimate command (`node --version`), track status, collect output, process terminates cleanly.                     | Task 5 |
| `RC08-FLOW-12` | Interactive Approval Lifecycle Redemption            | Privileged tool (`arc_verify`) requests approval; token granted by authorized actor, redeemed with matching `planHash`.     | Task 5 |
| `RC08-FLOW-13` | Durable Audit Ledger Anchoring & Verification        | Sequence of operations produces append-only records; checkpoint is signed and verified cleanly.                             | Task 5 |
| `RC08-FLOW-14` | Bounded High-Concurrency Execution                   | Run 10 concurrent read operations across multiple workspaces without latency degradation or crosstalk.                      | Task 6 |
| `RC08-FLOW-15` | Cross-Workspace State Isolation                      | Concurrently operate on Workspace 1 and Workspace 2; verify zero data leakage between actors.                               | Task 7 |
| `RC08-FLOW-16` | Controlled Process Interruption & Clean Exit         | Terminate long-running process; verify orderly SIGTERM followed by confirmation in `ProcessRegistry`.                       | Task 7 |
| `RC08-FLOW-17` | Read-Only Engineering Workflow                       | Agent performs `arc_repo_status`, `arc_worktree_status`, `arc_review_diff`, `arc_ci_status` without mutations or approvals. | Task 7 |
| `RC08-FLOW-18` | Approved Full Verification Suite Flow (`arc_verify`) | Full check-only verification suite passes with valid approval, reporting structured step outcomes.                          | Task 8 |
| `RC08-FLOW-19` | Approved Targeted Test Execution Flow (`arc_test`)   | Targeted test file executes under approval, returning structured test counts and sanitized excerpt.                         | Task 8 |
| `RC08-FLOW-20` | End-to-End Release Candidate 08 Verification         | Execution of `scripts/verify-rc08.sh` validating all quality gates, all 90 negative controls, and all 20 positive flows.    | Task 8 |

---

## 19. Definition of Done (RC-08)

Stage RC-08 is complete when and only when all of the following conditions are independently verified:

1. **All Negative Controls Pass:** All 90 frozen negative controls (`RC08-NEG-001` through `RC08-NEG-090`) are implemented as automated tests and pass cleanly.
2. **All Positive Flows Pass:** All 20 frozen positive acceptance flows (`RC08-FLOW-01` through `RC08-FLOW-20`) are implemented as automated tests and pass cleanly.
3. **Zero Regression:** All 2063 pre-existing RC-01 through RC-07 regression tests remain green.
4. **Tool Catalog Unchanged:** Production tool count remains exactly 25; deterministic execution registry remains exactly 5 entries.
5. **Deterministic Fuzzing:** Protocol and schema fuzz tests execute with seeded PRNGs and 100% reproducibility in CI.
6. **Cross-Client Verification:** Conformance harness passes for stdio, Streamable HTTP over TLS 1.3/mTLS, and independent raw JSON-RPC client.
7. **Zero Network Egress in Framework:** Framework code operates with zero outbound external network connections.
8. **Static Bypass Audits Pass:** Zero direct imports of `child_process` or `fs` in composite modules; zero mutating Git calls in inspection paths.
9. **Verification Script Complete:** `scripts/verify-rc08.sh` executes all test suites, negative controls, formatting, linting, typechecking, build, secret scanning, and passes with exit code 0.
10. **Zero Security Vulnerabilities:** `pnpm audit` reports 0 vulnerabilities; Gitleaks reports 0 secrets across the entire commit range.
11. **Stage & Version Promotion:** Version is promoted to `0.8.0-rc08` and health stage reports `RC-08` (exclusively in Task 8).
12. **Independent Review & Approval:** Independent peer review approves each task commit and the final PR before merge.

---

## 20. Version/Stage Promotion Rule

During Tasks 0 through 7:

- Package version remains: `0.7.0-rc07`
- Health version remains: `0.7.0-rc07`
- Health stage remains: `RC-07`

ONLY the final task (Task 8) is authorized to promote:

- Package version to: `0.8.0-rc08`
- Health version to: `0.8.0-rc08`
- Health stage to: `RC-08`

No interim task may alter version strings or health stages.

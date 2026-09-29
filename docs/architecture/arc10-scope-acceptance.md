# ARC 1.0 Scope & Acceptance — Distribution, Hosted Services & Stable Release Architecture

| Field                    | Frozen value                                                   |
| :----------------------- | :------------------------------------------------------------- |
| **Milestone**            | ARC 1.0                                                        |
| **Title**                | Distribution, Hosted Services & Stable Release Architecture    |
| **Status**               | **Task-0 Scope Candidate — Frozen Architecture Specification** |
| **Base main**            | `82cada15db3e655585fce796a35e970e7a972afe`                     |
| **Planning branch**      | `feat/arc-1.0-scope`                                           |
| **Current version**      | `0.8.0-rc08`                                                   |
| **Current health stage** | `RC-08`                                                        |
| **Stable target**        | `1.0.0`                                                        |

> **Normative rule:** Task 0 is documentation-only. Implementation MUST NOT begin until this specification is independently reviewed and approved. Stable version and stage promotion are reserved for Task 8.

## 1. Authority, Mission & Central Question

ARC 1.0 begins at the independently verified RC-08 merge, `82cada15db3e655585fce796a35e970e7a972afe`. RC-01 through RC-08 are closed; their security invariants, protocol behavior, and acceptance evidence are inherited rather than reinterpreted. Distribution capabilities may add trust boundaries, but MUST NOT weaken or bypass the local ARC security kernel.

The milestone asks:

> Can the verified ARC control plane be installed, upgraded, distributed, and—under a separately declared hosted profile—connected through externally operated identity and relay services as a stable product while preserving tenant isolation, device identity, authorization, audit integrity, and host containment?

The stable product has two deliberately separate profiles:

1. **ARC Core Distribution (required):** reproducible installable artifacts for the existing local/remote ARC control plane.
2. **ARC Hosted Connectivity Profile (optional):** accounts, OAuth/OIDC, opaque relay, pairing, and public MCP routing. It is not required to release Core 1.0, is disabled by default, and may be claimed only if every hosted control assigned below passes.

Task 0 introduces no runtime, schema, service, tool, or release change. Promotion to `1.0.0` may occur only in the final release task after independent acceptance.

## 2. Verified Starting Baseline

The inherited baseline is frozen as follows:

- Main SHA: `82cada15db3e655585fce796a35e970e7a972afe`
- Release and health version: `0.8.0-rc08`
- Health stage: `RC-08`
- Tests: 315 suites; 2,173 tests passed; 0 failed, cancelled, skipped, or todo
- RC-08 evidence: 90/90 negative controls, 20/20 positive flows, 20/20 final verification gates
- Production tools: exactly 25
- Deterministic execution entries: exactly 5

### 2.1 Inherited production tool catalog

1. `health`
2. `system_status`
3. `list_directory`
4. `read_file`
5. `search_files`
6. `search_text`
7. `git_status`
8. `git_diff`
9. `git_log`
10. `run_command`
11. `process_status`
12. `process_output`
13. `terminate_process`
14. `create_file`
15. `write_file`
16. `delete_file`
17. `move_file`
18. `apply_patch`
19. `arc_repo_status`
20. `arc_worktree_status`
21. `arc_review_diff`
22. `arc_verify`
23. `arc_test`
24. `arc_ci_status`
25. `arc_stage_evidence`

### 2.2 Inherited deterministic registry

1. `verify-format-v1`
2. `verify-lint-v1`
3. `verify-typecheck-v1`
4. `verify-test-v1`
5. `arc-test-node-v1`

These are the **inherited core**. Packaging, account metadata, hosted routing, and release services are **new distribution surfaces**. Hosted services do not become MCP tools, deterministic execution entries, host subsystems, or alternate dispatchers.

## 3. Product Boundary

### A. ARC Core

The existing MCP server, CLI, stdio and TLS 1.3/mTLS transports, policy engine, approvals, audit ledger, filesystem/Git/process mediation, and 25-tool catalog. It remains capable of fully local operation with no hosted dependency.

### B. Distribution Layer

Installation artifacts, checksums, signatures, SBOMs, configuration bootstrap, upgrade/migration tooling, rollback metadata, compatibility declarations, and provenance. This layer packages the core; it does not grant host authority.

### C. Identity / Account Plane

An optional hosted-profile boundary holding accounts, immutable tenant membership, OAuth/OIDC grants, and public device enrollment metadata. It authenticates access to hosted routing only. Local ARC device trust, session binding, policy, and approval remain independently authoritative.

### D. Relay / Hosted Connectivity Plane

An optional opaque encrypted transport relay and pairing broker. It routes an end-to-end encrypted tunnel to a specifically paired ARC gateway. It cannot decrypt MCP payloads or authorize host actions.

### E. Hosted Control Plane

An optional service holding tenant/account state, device public identifiers, encrypted routing state, revocation, quotas, and minimized operational/security metadata. Billing and subscription processing are not part of 1.0.

### F. Ecosystem Distribution

Portable client configuration guidance and integration metadata. Publishing to vendor directories or executing arbitrary plugins is deferred; no vendor directory becomes a trust anchor.

## 4. Required vs Deferred Capabilities

Classifications are: **A** required for ARC 1.0.0, **B** optional 1.0 distribution capability, **C** deferred post-1.0, and **D** explicitly excluded.

| Capability                        | Class | Required for stable 1.0? | Security impact / new boundary                                  | Data handled                                 | External dependency            | Milestone | Acceptance evidence                                          |
| :-------------------------------- | :---: | :----------------------: | :-------------------------------------------------------------- | :------------------------------------------- | :----------------------------- | :-------- | :----------------------------------------------------------- |
| Installable distribution          |   A   |           Yes            | Artifact-to-host trust boundary                                 | Config and binaries                          | Artifact host at download time | Task 1    | Install/uninstall, signature, checksum, and clean-host tests |
| Release artifacts                 |   A   |           Yes            | Supply-chain and provenance boundary                            | Source, packages, SBOM, attestations         | Release host                   | Task 1    | Reproducibility and provenance controls                      |
| Upgrade compatibility             |   A   |           Yes            | Persistent configuration/audit migration                        | Config and local state                       | None required                  | Task 2    | Forward, rollback, and interrupted-migration tests           |
| Hosted cloud relay                |   B   |            No            | Network routing and availability boundary                       | Ciphertext plus bounded routing metadata     | Hosted relay                   | Task 4    | Opaque-relay and compromise controls                         |
| Public hosted MCP endpoint        |   B   |            No            | Public ingress and abuse boundary                               | End-to-end ciphertext                        | DNS/relay/identity services    | Task 4    | Authenticated routing and abuse tests                        |
| Multi-tenant accounts             |   B   |            No            | Tenant identity/control-plane boundary                          | Account and membership metadata              | Hosted datastore               | Task 3    | Tenant authority and lifecycle controls                      |
| Tenants                           |   B   |            No            | Cross-tenant isolation boundary                                 | Tenant IDs, roles, quotas                    | Hosted datastore               | Tasks 3/5 | Isolation and anti-enumeration tests                         |
| OAuth 2.0 / OIDC                  |   B   |            No            | Issuer, token, and browser authorization boundaries             | Identity claims and tokens                   | Standards-conformant issuer    | Task 3    | Issuer/audience/PKCE/replay tests                            |
| Device pairing relay              |   B   |            No            | Pairing-code and route-binding boundary                         | One-time codes, public SPKI, encrypted route | Hosted pairing broker          | Task 4    | Consent, expiry, replay, and device-binding tests            |
| Directory publishing/integrations |   C   |            No            | Vendor review and metadata boundary                             | Public integration metadata                  | Vendor directories             | Post-1.0  | Separate architecture and vendor acceptance                  |
| Metering                          |   C   |            No            | Usage-integrity/privacy boundary                                | Coarse service counters only                 | Metering backend               | Post-1.0  | Separate privacy and fraud controls                          |
| Billing                           |   C   |            No            | Financial/regulatory boundary                                   | Billing identity and invoices                | Payment processor              | Post-1.0  | Separate PCI/legal architecture                              |
| SaaS subscriptions                |   C   |            No            | Entitlement/failure boundary                                    | Plan and entitlement metadata                | Billing provider               | Post-1.0  | No host-authorization coupling proof                         |
| Public multi-tenant hosting       |   B   |            No            | Combines identity, tenant, relay, and public ingress boundaries | Metadata and ciphertext only                 | Hosted profile services        | Tasks 3–6 | All hosted-profile controls and flows                        |

An optional capability has only two valid release states: fully implemented with its complete owned acceptance set, or absent/disabled with no public support claim. Partial hosted deployment is forbidden.

## 5. Security Invariant Inheritance

All permanent principles and RC-08 invariants remain binding, including:

- zero implicit trust, default deny, least privilege, and fail closed;
- mandatory `authentication -> policy -> durable STARTED audit -> execution -> COMPLETED audit` mediation;
- canonical workspace jailing and sensitive-path denial;
- discrete `argv`, `shell: false`, trusted executable resolution, supervision, output/process/resource limits, and orphan cleanup;
- `DENY > REQUIRE_APPROVAL > ALLOW`, cryptographic approval binding, one-time redemption, and anti-replay;
- one durable minimized hash-chained audit ledger and the degraded-audit fail-closed latch;
- TLS 1.3, mTLS CA plus enrolled-SPKI trust, server-derived device identity, and bound volatile sessions;
- composite mediation, no direct filesystem/process bypass, stage-evidence anti-fabrication, and bounded ingress;
- exact 25-tool catalog and five-entry deterministic registry unless a later independently approved architecture changes them.

Hosted identity proves only eligibility to request a route. Every host operation still enters the existing ARC gateway and local security kernel. Hosted account roles, subscription state, relay headers, tenant fields, or OAuth scopes MUST NOT directly produce a local `ALLOW`, approval, workspace binding, or process owner.

## 6. New Trust Boundaries

```text
Untrusted MCP Client / Agent
          |
          | browser authorization (outer TLS)
          v
+---------------- Identity / OAuth Boundary ----------------+
| Authorization Server + Hosted Resource Server              |
| authenticates account/tenant membership; never host action |
+-------------------------+----------------------------------+
                          | short-lived route authorization
                          v
+---------------- Opaque Hosted Relay Boundary --------------+
| routes bounded end-to-end encrypted frames                 |
| sees tenant/route IDs, sizes and timing; never MCP payload  |
+-------------------------+----------------------------------+
                          | inner TLS 1.3 + mTLS tunnel
                          v
+---------------- ARC Remote Gateway Boundary ---------------+
| TLS terminates here; enrolled SPKI -> device identity      |
| ARC session authentication terminates here                 |
+-------------------------+----------------------------------+
                          v
+---------------- Local Security Kernel ---------------------+
| workspace + actor policy -> durable audit -> approval      |
+-------------------------+----------------------------------+
                          v
       Filesystem / Git / Terminal / Process Subsystems
```

- Outer HTTPS terminates at hosted identity/relay edges only for account and routing APIs.
- Inner MCP TLS terminates exclusively at the paired ARC Remote Gateway. The relay is **honest-but-curious/untrusted for payload confidentiality and host authorization**.
- Authentication has two independent results: hosted account/tenant identity for routing and local enrolled-device/session identity for MCP admission.
- Tenant and device claims propagate only in server-signed, audience-bound, expiring assertions. The local gateway resolves its own device/session identity and never trusts request JSON or forwarding headers.
- Authorization for host operations and authoritative host audit remain local. Hosted services maintain a separate minimized service-security audit.
- Host authority always belongs to the local operator and local ARC policy.

## 7. Tenancy Model

The optional hosted profile uses control-plane-generated immutable `tenantId` values. The authoritative tenant comes from verified issuer subject membership resolved by the hosted account service—not from URL, header, JSON, route name, or client-supplied claim.

- An account may hold explicit roles in one or more tenants; each request selects only among server-resolved memberships.
- Devices belong to exactly one tenant at a time. Transfer requires local operator removal, session revocation, re-pairing, and new tenant enrollment.
- Workspaces, sessions, routes, approvals, quotas, service-audit records, and deletion jobs are tenant-bound at creation.
- Local workspaces remain locally registered; a hosted tenant cannot discover or create a workspace merely by naming it.
- Cross-tenant reads, process ownership, approval redemption, device/session migration, audit lookup, route use, and quota attribution fail with uniform anti-enumerating responses.
- Tenant deletion first disables issuance and routing, revokes sessions/pairings, drains routes, cryptographically erases tenant secrets, then deletes metadata under a bounded retention policy. Local host data is not deleted remotely.
- Quotas are keyed from authenticated server state. User-provided tenant fields cannot select another bucket.

## 8. Identity / OAuth Model

OAuth/OIDC belongs only to the optional hosted profile:

- **Authorization Server:** a CesSpace-operated or explicitly configured standards-conformant issuer for hosted account access.
- **Resource Servers:** hosted account, pairing, and relay-control APIs. The ARC host gateway is not automatically an OAuth resource server.
- **Clients:** public desktop/CLI clients use Authorization Code with PKCE (`S256`); confidential service clients use separately provisioned asymmetric credentials. Client secrets MUST NOT be embedded in desktop binaries.
- **User / Resource Owner:** the account user authorizing hosted routing; this is not synonymous with local host operator approval.
- **Device identity:** local ARC enrollment remains CA-chain plus SPKI pin. OAuth does not replace mTLS or establish `deviceId`.
- **ARC session identity:** issued and validated by the local SessionManager after local gateway admission.

Tokens require exact issuer, audience, signature algorithm, expiry/not-before, subject, tenant membership, and nonce/state validation. Access tokens are short-lived; authorization codes are single-use; refresh tokens rotate with reuse detection, are encrypted at rest, and are never sent to ARC tools or audit. Revocation disables hosted routing but cannot silently grant or alter local permissions. Scope names authorize hosted APIs only. Any actor mapping into ARC is a bounded, signed, audience-specific assertion combined with the locally derived device/session identity and local policy.

If the hosted profile is omitted, ARC 1.0 continues using current local stdio identity or direct TLS 1.3/mTLS enrolled-device sessions; it exposes no OAuth endpoints.

## 9. Relay Architecture

The selected model is an **opaque transport relay**. Trusted TLS termination proxying and relay-visible MCP JSON are excluded from ARC 1.0.

1. A locally approved host registers an ephemeral route using an outbound authenticated tunnel.
2. A client authenticates to the hosted control plane and receives a short-lived, tenant- and route-bound connection grant.
3. A single-use pairing exchange binds the client-visible route to the locally enrolled host with explicit local consent.
4. The relay forwards bounded opaque frames carrying an inner TLS 1.3/mTLS connection; it cannot inspect, modify, or synthesize valid MCP traffic.
5. The ARC gateway performs its normal device enrollment and session checks before MCP processing.

Route grants are nonce-bound, audience-bound, expiring, replay-detected, and revoked on account/device removal. Routing keys are tenant-scoped and non-enumerable. Backpressure, connection and byte-rate limits, frame/body ceilings, bounded queues, heartbeat/idle deadlines, disconnect propagation, and deterministic cleanup apply. A relay outage closes connections and cannot downgrade to a plaintext/direct bypass. Relay service audit records only route identifier digests, tenant ID, timestamps, byte counts, denial category, and integrity references.

## 10. Data Classification & Privacy

| Data class                  | May transit hosted services?          | May persist hosted?                  | Retention / encryption                         | Scope, redaction, deletion                                 |
| :-------------------------- | :------------------------------------ | :----------------------------------- | :--------------------------------------------- | :--------------------------------------------------------- |
| Account identity            | Yes                                   | Yes                                  | Account lifetime; TLS and encrypted storage    | Tenant-scoped; delete/anonymize on closure                 |
| Tenant metadata             | Yes                                   | Yes                                  | Tenant lifetime plus bounded recovery window   | Tenant-scoped; no host paths/content                       |
| OAuth access/refresh tokens | Control APIs only                     | Refresh-token digest/ciphertext only | Shortest practical TTL; managed-key encryption | Never logs; revoke/rotate/delete                           |
| Device SPKI/fingerprint     | Yes                                   | Yes                                  | Enrollment lifetime                            | Public-key identifier; tenant-bound; remove on deprovision |
| ARC session tokens          | Opaque inner tunnel only              | **Never**                            | Memory at local host only                      | Redact everywhere                                          |
| Approval tokens             | Opaque inner tunnel only              | **Never**                            | Local TTL only                                 | Redact everywhere                                          |
| Workspace metadata          | Opaque payload only                   | **Never** (hosted)                   | Local policy only                              | No absolute path in hosted metadata                        |
| File contents               | Ciphertext transit only               | **Never**                            | No hosted retention                            | Local response only; existing bounds/redaction             |
| Process output              | Ciphertext transit only               | **Never**                            | No hosted retention                            | Existing local caps/scrubbing                              |
| Git diff content            | Ciphertext transit only               | **Never**                            | No hosted retention                            | Existing local sensitive-path suppression                  |
| Local authoritative audit   | Optional encrypted anchor digest only | Raw records **never**                | Digest/anchor per operator policy              | Local ledger remains authoritative                         |
| Service-security audit      | Yes                                   | Yes                                  | Bounded documented retention; encrypted        | Metadata-only, tenant-scoped, export/delete policy         |
| Billing/metering records    | Not in 1.0                            | No                                   | Deferred                                       | Requires separate approval                                 |
| Secrets/private keys        | Ciphertext payload only               | **Never**                            | Local secret store only                        | Never logs or artifacts                                    |
| Operational telemetry       | Yes                                   | Aggregates only                      | Short bounded retention                        | No content, tokens, paths, or per-tool payloads            |

Hosted infrastructure MUST NEVER persist MCP bodies, file content, process output, Git diffs, ARC session/approval tokens, private keys, raw local audit records, environment secrets, or absolute host paths.

## 11. Billing / Metering Boundary

Metering, billing, subscriptions, payment processing, and entitlement-driven SaaS behavior are **Class C: deferred post-1.0**. No 1.0 host operation may depend on payment state. Future metering may observe only idempotent, tenant-bound service units such as relay connection-minutes and encrypted bytes—not tool names, host paths, content, or local execution outcomes. A billing outage or disputed entitlement must never produce host authorization, weaken local policy, or bypass audit.

## 12. Distribution & Packaging

Required stable distribution evidence covers:

- **Authoritative support:** Linux x86-64 on a supported Node.js `^24.0.0` runtime with pnpm `^12.4.2` for source builds.
- **Development-compatible:** WSL Linux userspace, excluding native-Windows and `/mnt/c` security equivalence claims.
- **Validation targets only:** Linux arm64 and macOS protocol/core behavior until dedicated CI evidence exists; no process-tree equivalence claim.
- **Unsupported for 1.0:** native Windows runtime and host-execution security guarantees.
- Signed source archive and lockfile-based source installation; a packaged Linux artifact may be added only with equivalent tests. No unverified platform artifact is advertised.
- SHA-256 checksums, detached signature/attestation, SPDX or CycloneDX SBOM, dependency/license inventory, source-to-artifact provenance, reproducible build instructions, and Gitleaks/dependency scan evidence.
- Configuration initialization with restrictive permissions and no generated credential printed or committed.
- Upgrade from the RC-08 baseline through versioned, transactional, idempotent migrations; preflight backup/validation, crash recovery, and explicit rollback compatibility.
- Clean uninstall removes binaries and ephemeral runtime state but preserves user workspaces and, by default, audit/config data unless the operator explicitly requests verified removal.

## 13. Configuration & Secrets

Public defaults and schemas are shipped artifacts. Operator configuration owns listeners, workspace registrations, policy, trusted CAs, hosted-profile enablement, and endpoints. Secret material includes private keys, OAuth refresh credentials, session/approval tokens, signing keys, and pairing secrets; runtime-generated credentials are owned by the component that issues them.

- Non-secret settings may use validated files or an explicit allowlist of environment variables.
- Secrets use permission-restricted files or an OS credential facility; secret values are never accepted in ordinary CLI arguments.
- Startup validates ownership, mode, schema, issuer/audience, paths, and incompatible combinations before binding listeners.
- Missing, unreadable, overly permissive, expired, or inconsistent security configuration fails closed.
- Rotation overlaps only explicitly permitted verification keys, revokes old credentials, and is auditable.
- No secret enters logs, Git, build cache, SBOM, provenance, crash report, telemetry, or release artifact.

## 14. API / Protocol Compatibility

The 25 MCP tools and current schemas/errors form the stable 1.0 compatibility baseline. Patch releases preserve valid requests and semantic error classifications; additive optional fields require defaults and compatibility tests. Breaking tool/schema changes require a versioned protocol profile, migration path, deprecation notice, and a major release. New production tools require an approved architecture amendment and dedicated security controls.

Configuration and durable audit formats carry explicit schema versions. Readers support documented migration windows and never silently discard unknown security-critical fields. Hosted APIs, if shipped, use an explicit version prefix and bounded negotiation; an unsupported version fails closed. Deprecations require at least one supported release cycle, telemetry-free public notice, and removal only at a declared compatibility boundary.

## 15. Observability

Allowed telemetry includes health, readiness, latency/error aggregates, bounded CPU/memory/disk/connection metrics, tenant-scoped relay usage aggregates, quota state, and security-event counters. Authoritative security audit remains distinct from operational telemetry.

Telemetry MUST NOT contain file contents, snippets, process output, Git diffs, raw MCP bodies, host absolute paths, environment values, private audit records, bearer/session/approval/pairing tokens, private keys, or stable cross-tenant correlation identifiers. Tenant metrics use server-derived scope, bounded cardinality, documented retention, and operator-visible disable/export behavior.

## 16. Extended Threat Model

| Threat                                    | Boundary                 | Frozen mitigation                                                                              | Acceptance evidence                         |
| :---------------------------------------- | :----------------------- | :--------------------------------------------------------------------------------------------- | :------------------------------------------ |
| Malicious tenant / cross-tenant confusion | Tenant/control plane     | Server-derived tenant scope on every object/query/cache/quota                                  | Cross-tenant isolation controls             |
| Compromised account / stolen OAuth token  | Identity                 | Short TTL, audience/issuer checks, PKCE, rotation/reuse detection, revocation                  | Token misuse and revocation tests           |
| Malicious relay client                    | Public relay ingress     | Authenticated grant, bounded framing, inner mTLS, rate limits                                  | Malformed/replay/resource tests             |
| Compromised relay instance                | Relay/ARC gateway        | Opaque end-to-end encrypted tunnel; local mTLS and policy remain authoritative                 | Payload-confidentiality and injection tests |
| Tenant enumeration                        | Hosted APIs              | Uniform errors, non-sequential identifiers, bounded timing                                     | Anti-oracle tests                           |
| Account takeover                          | Identity/account         | Strong reauthentication for sensitive lifecycle changes and session revocation                 | Recovery/deprovision tests                  |
| Pairing hijack                            | Pairing broker           | Local consent, single-use high-entropy code, short TTL, device/SPKI binding                    | Pairing replay/substitution tests           |
| Replay                                    | All network boundaries   | Nonces, expiry, audience, single use, session binding                                          | Deterministic replay controls               |
| SSRF                                      | Hosted service           | Fixed allowlisted destinations; no user URL fetches                                            | URL/metadata endpoint negative tests        |
| Request smuggling/header spoofing         | Public ingress           | HTTP parser bounds, authority validation, no forwarded identity authority                      | Conflicting-length/header tests             |
| Webhook spoofing                          | Ecosystem                | No 1.0 webhooks; absent endpoint proof                                                         | Surface inventory test                      |
| Billing fraud                             | Commercial plane         | Billing deferred; no entitlement coupling                                                      | Absence/configuration tests                 |
| Quota abuse / DoS                         | Hosted and local ingress | Tenant-derived buckets, bounded queues/connections/payloads and cleanup                        | Resource exhaustion tests                   |
| Hosted secret leakage                     | Service/storage          | Data minimization, encryption, redaction, secret scanning                                      | Storage/log inspection tests                |
| Malicious directory integration           | Ecosystem                | Publishing deferred; no directory credentials/code                                             | Surface and artifact tests                  |
| Supply-chain compromise                   | Distribution             | Lockfile, SBOM, signatures, provenance, reproducible builds                                    | Artifact verification controls              |
| Upgrade tampering/downgrade               | Distribution/local state | Signed manifests, version monotonicity, transactional migrations                               | Upgrade/downgrade controls                  |
| Stale/revoked device                      | Identity/relay/gateway   | Immediate route/session revocation plus local enrollment checks                                | Revocation propagation tests                |
| Compromised local ARC host                | Host                     | Hosted plane stores no payload; external digest may expose tampering, not prevent host control | Threat statement and anchor verification    |
| Malicious AI agent                        | MCP/local kernel         | All inherited policy, approval, jail, audit, and supervision invariants                        | Full regression suite                       |

## 17. Failure Model

| Failure                          | Required behavior                                                                                                                      |
| :------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------- |
| Identity provider / OAuth issuer | New hosted authorization fails closed; existing direct local ARC remains independent; no cached privilege extension                    |
| Account database                 | Hosted issuance, membership changes, and routing fail closed; no tenant guessed from request                                           |
| Relay                            | Connections close or retry with bounded backoff; no plaintext/direct downgrade; local service remains available directly if configured |
| Billing/metering                 | Not present in 1.0; any future outage cannot authorize host work                                                                       |
| Directory API                    | Not present; core and hosted profile remain unaffected                                                                                 |
| Audit backend                    | Local durable-audit latch blocks privileged execution; hosted service audit failure blocks affected hosted state changes               |
| Network                          | Bounded timeout and cleanup; no stale approval/session extension or duplicate execution                                                |
| Local ARC agent                  | Hosted route becomes unavailable and is reaped; relay cannot emulate it or execute queued tools                                        |
| Configuration service            | Last-known configuration is usable only while cryptographically valid and unexpired; security changes fail closed                      |

Privileged host execution is never allowed merely because a hosted dependency is unavailable.

## 18. Task / Milestone Decomposition

ARC 1.0 contains **nine tasks (0–8)**:

| Task | Title                                       | Scope / owned area                                                                             | Likely production areas                                                         | Negative controls    | Positive flows      | Prerequisites / promotion restriction   |
| :--: | :------------------------------------------ | :--------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------ | :------------------- | :------------------ | :-------------------------------------- |
|  0   | Scope, Architecture & Acceptance Freeze     | This normative document and roadmap only                                                       | None                                                                            | None                 | None                | Base RC-08; no implementation/promotion |
|  1   | Reproducible Distribution & Installation    | Source/release artifacts, install/uninstall, SBOM, signing/provenance                          | Root manifests, release/build scripts, packaging metadata                       | `ARC10-NEG-001..012` | `ARC10-FLOW-01..03` | Task 0; version unchanged               |
|  2   | Configuration, Upgrade & Migration Safety   | Versioned config/state migration, backup, rollback, secret permissions                         | CLI/config loader, migration package/scripts                                    | `ARC10-NEG-013..022` | `ARC10-FLOW-04..05` | Task 1; version unchanged               |
|  3   | Hosted Identity, Accounts & OAuth Profile   | Optional account/tenant authority, OIDC clients/resource APIs                                  | New isolated hosted identity/account packages/apps if approved                  | `ARC10-NEG-023..034` | `ARC10-FLOW-06..08` | Tasks 1–2; optional profile fully gated |
|  4   | Opaque Relay, Pairing & Public MCP Routing  | Optional encrypted tunnel relay and device pairing                                             | New relay/pairing packages/apps; existing gateway only through reviewed adapter | `ARC10-NEG-035..046` | `ARC10-FLOW-09..11` | Task 3; no trusted MCP termination      |
|  5   | Tenant, Data & Privacy Isolation            | Tenant ownership, deletion, storage minimization, cross-tenant proofs                          | Hosted data layer and policy adapters                                           | `ARC10-NEG-047..058` | `ARC10-FLOW-12..13` | Tasks 3–4                               |
|  6   | Hosted Resilience, Quotas & Observability   | Cleanup, abuse bounds, failure handling, safe metrics                                          | Hosted admission/metrics/service audit                                          | `ARC10-NEG-059..067` | `ARC10-FLOW-14`     | Tasks 3–5                               |
|  7   | Supply Chain, Ecosystem & Release Candidate | Artifact verification, compatibility matrix, integration metadata without directory publishing | Release tooling/docs/CI; no directory credentials                               | `ARC10-NEG-068..075` | `ARC10-FLOW-15..16` | Tasks 1–6; no stable promotion          |
|  8   | Final Verification & Stable Promotion       | Complete verifier, security review, acceptance mapping, `1.0.0` promotion                      | Verification script and authoritative version surfaces only after gates pass    | `ARC10-NEG-076..080` | `ARC10-FLOW-17..18` | All prior tasks; sole promotion owner   |

## 19. Negative Acceptance Control Catalog

The final catalog is frozen at **80 controls**, `ARC10-NEG-001` through `ARC10-NEG-080`. Every row states a code-testable threat, setup/action, expected result, forbidden side effects, evidence, and owner. Optional-profile controls execute against the implementation when enabled; when omitted, the same owner must prove the endpoints, credentials, listeners, claims, and support declarations are absent. Skips and todos are never acceptable.

| ID              | Title / threat                         | Setup and action                                                        | Expected result                                                                | Forbidden side effects                             | Required evidence                                 | Owner |
| :-------------- | :------------------------------------- | :---------------------------------------------------------------------- | :----------------------------------------------------------------------------- | :------------------------------------------------- | :------------------------------------------------ | :---: |
| `ARC10-NEG-001` | Unsigned artifact substitution         | Replace an install artifact without a valid signature/attestation       | Installer rejects before extraction                                            | No executable/config write                         | Verification trace and unchanged install root     |   1   |
| `ARC10-NEG-002` | Checksum mismatch                      | Corrupt one bounded artifact byte                                       | Digest check fails closed                                                      | No partial installation                            | Expected/observed digest metadata without payload |   1   |
| `ARC10-NEG-003` | Provenance subject mismatch            | Present valid attestation for a different artifact                      | Subject binding rejects                                                        | No trust inherited from signer alone               | Attestation verification result                   |   1   |
| `ARC10-NEG-004` | SBOM omission                          | Remove a packaged dependency from SBOM                                  | Release validation fails                                                       | No publishable release bundle                      | Dependency/SBOM reconciliation report             |   1   |
| `ARC10-NEG-005` | Archive path traversal                 | Package entries use `../`, absolute paths, or symlink escape            | Safe extractor rejects                                                         | No write outside staging root                      | Outside sentinel unchanged                        |   1   |
| `ARC10-NEG-006` | Artifact secret contamination          | Seed fixture artifact with token/private-key shapes                     | Release secret gate rejects                                                    | Secret never published or logged raw               | Sanitized scanner finding                         |   1   |
| `ARC10-NEG-007` | Non-reproducible build                 | Build twice from identical source/lock/toolchain                        | Material difference fails release gate                                         | No unverifiable attestation                        | Normalized artifact digest comparison             |   1   |
| `ARC10-NEG-008` | Unsupported platform claim             | Request install on native Windows or unverified target                  | Installer/docs fail with unsupported status                                    | No partial runtime claim/install                   | Platform decision assertion                       |   1   |
| `ARC10-NEG-009` | Privileged install escalation          | Attempt unexpected root/system-path installation                        | Refused unless explicit documented operator mode                               | No ownership/permission weakening                  | Filesystem ownership snapshot                     |   1   |
| `ARC10-NEG-010` | Unsafe uninstall                       | Uninstall beside controlled workspace/audit fixtures                    | Removes only owned artifacts                                                   | No workspace, config, or audit deletion by default | Before/after inventory                            |   1   |
| `ARC10-NEG-011` | Dependency drift                       | Install with lockfile mismatch or unfrozen resolution                   | Build/install refuses                                                          | No unrelated dependency upgrade                    | Lockfile and resolved-tree proof                  |   1   |
| `ARC10-NEG-012` | Package identity/version inconsistency | Compare manifests, archive metadata, CLI and health identity            | Any mismatch blocks release                                                    | No partial version promotion                       | Exact surface matrix                              |   1   |
| `ARC10-NEG-013` | Unknown security config field          | Add misspelled/unknown security-critical property                       | Strict parser rejects                                                          | No listener or subsystem startup                   | Schema error and zero-bind proof                  |   2   |
| `ARC10-NEG-014` | Insecure config permissions            | Start with group/world-readable secret file                             | Startup fails closed                                                           | No secret read into service/log                    | Mode check and sanitized error                    |   2   |
| `ARC10-NEG-015` | Environment override poisoning         | Supply unapproved env key/path/issuer override                          | Rejected or ignored by allowlist                                               | No authoritative config change                     | Effective-config projection                       |   2   |
| `ARC10-NEG-016` | Secret in CLI arguments                | Pass secret through ordinary command argument                           | CLI refuses unsafe channel                                                     | No process-list/log/audit exposure                 | Spawn/argv and log inspection                     |   2   |
| `ARC10-NEG-017` | Interrupted migration                  | Fault after staged write but before commit                              | Original state remains valid or recovery completes atomically                  | No half-migrated state                             | Fault-point journal and reopen result             |   2   |
| `ARC10-NEG-018` | Migration replay                       | Run same migration twice                                                | Second run is idempotent                                                       | No duplicate enrollment/audit/config entry         | State digest equality                             |   2   |
| `ARC10-NEG-019` | Unsupported downgrade                  | Attempt older binary against newer incompatible state                   | Startup refuses with bounded guidance                                          | No destructive reverse migration                   | Version guard result                              |   2   |
| `ARC10-NEG-020` | Rollback after irreversible change     | Request rollback without compatible backup/schema                       | Refused before mutation                                                        | No state loss                                      | Backup/schema compatibility evidence              |   2   |
| `ARC10-NEG-021` | Malicious migration input              | Inject traversal, oversized, or secret-bearing legacy values            | Migration validates and rejects                                                | No external path write or raw secret log           | Fixture sentinel and sanitized diagnostics        |   2   |
| `ARC10-NEG-022` | Audit continuity loss on upgrade       | Upgrade copied ledger/checkpoint with gap or mismatch                   | Authoritative verifier rejects                                                 | No silent new chain genesis                        | Pre/post chain verification                       |   2   |
| `ARC10-NEG-023` | Untrusted OIDC issuer                  | Present correctly formed token from other issuer                        | Hosted resource server rejects uniformly                                       | No account/tenant lookup leakage                   | Issuer-validation trace                           |   3   |
| `ARC10-NEG-024` | Wrong OAuth audience                   | Replay token minted for another resource                                | Rejected before route/account action                                           | No confused-deputy grant                           | Audience assertion                                |   3   |
| `ARC10-NEG-025` | Expired/not-yet-valid token            | Use boundary-expired and future token with injected clock               | Uniform authentication refusal                                                 | No clock-skew privilege extension                  | Deterministic time evidence                       |   3   |
| `ARC10-NEG-026` | Authorization-code replay              | Redeem the same code twice                                              | Exactly one redemption succeeds                                                | No second token set                                | Atomic consumption record                         |   3   |
| `ARC10-NEG-027` | PKCE substitution                      | Redeem public-client code with wrong verifier                           | Token issuance denied                                                          | No verifier/original challenge leak                | PKCE validation result                            |   3   |
| `ARC10-NEG-028` | OAuth state/nonce confusion            | Swap callback state or OIDC nonce across sessions                       | Callback rejected                                                              | No account/session binding                         | Session-bound comparison evidence                 |   3   |
| `ARC10-NEG-029` | Refresh-token reuse                    | Replay rotated refresh token                                            | Family revoked per policy                                                      | No additional access token                         | Rotation-family lifecycle                         |   3   |
| `ARC10-NEG-030` | Client-secret extraction               | Inspect desktop bundle/config/logs                                      | No confidential client secret exists                                           | No embedded reusable credential                    | Artifact/string/secret scan                       |   3   |
| `ARC10-NEG-031` | Client-supplied tenant authority       | Forge tenant header, path, JSON, or claim                               | Server uses verified membership only                                           | No target tenant query/action                      | Resolved tenant evidence                          |   3   |
| `ARC10-NEG-032` | Account enumeration                    | Probe existing/non-existing account/tenant identifiers                  | Same bounded external refusal                                                  | No existence/timing oracle                         | Normalized response/timing bounds                 |   3   |
| `ARC10-NEG-033` | Hosted identity bypasses mTLS          | Use valid OAuth token without enrolled client certificate               | Local ARC handshake/admission fails                                            | No MCP/tool/policy execution                       | Gateway counters and TLS result                   |   3   |
| `ARC10-NEG-034` | Disabled hosted profile exposure       | Start default Core configuration and probe hosted endpoints             | No listener/routes/credentials exist                                           | No outbound hosted connection                      | Socket/surface/config inventory                   |   3   |
| `ARC10-NEG-035` | Relay plaintext downgrade              | Attempt route without inner TLS or strip tunnel negotiation             | Connection closes                                                              | No MCP plaintext accepted                          | Wire bytes and gateway dispatch count             |   4   |
| `ARC10-NEG-036` | Relay payload visibility               | Send known MCP sentinel through instrumented relay                      | Relay observes ciphertext only                                                 | No sentinel in memory/log/storage                  | Relay capture/storage scan                        |   4   |
| `ARC10-NEG-037` | Relay frame tampering                  | Flip/reorder/drop encrypted frames                                      | Inner TLS fails or bounded disconnect occurs                                   | No partial/replayed tool execution                 | Execution counter and TLS result                  |   4   |
| `ARC10-NEG-038` | Cross-tenant route substitution        | Use tenant A grant for tenant B route                                   | Uniform refusal                                                                | No route/device existence leak                     | Server-derived route scope                        |   4   |
| `ARC10-NEG-039` | Pairing-code replay                    | Reuse consumed one-time code                                            | Replay rejected                                                                | No second device/route binding                     | Atomic pairing lifecycle                          |   4   |
| `ARC10-NEG-040` | Pairing-code guessing                  | Submit bounded invalid code corpus                                      | Rate-limited uniform refusal                                                   | No near-match/existence disclosure                 | Attempt/bucket evidence                           |   4   |
| `ARC10-NEG-041` | Pairing without local consent          | Complete hosted steps but withhold host approval                        | Pairing expires denied                                                         | No enrollment/session creation                     | Host approval and expiry state                    |   4   |
| `ARC10-NEG-042` | Forwarded identity spoofing            | Forge host/origin/forwarded/tenant/device headers                       | Headers never select identity                                                  | No limiter/route/session switch                    | Derived identity/key evidence                     |   4   |
| `ARC10-NEG-043` | Relay replay after revocation          | Reuse cached grant after account/device/route revocation                | Immediate bounded refusal                                                      | No stale tunnel or session resurrection            | Revocation propagation evidence                   |   4   |
| `ARC10-NEG-044` | Relay backpressure exhaustion          | Slow consumer while producer exceeds bounded queue                      | Backpressure/closure at frozen bound                                           | No unbounded retained frames/socket                | Queue and holder counters                         |   4   |
| `ARC10-NEG-045` | Relay disconnect orphan                | Destroy either tunnel endpoint mid-request                              | Both directions and holders clean up                                           | No hung promise or host process                    | Before/after resource counters                    |   4   |
| `ARC10-NEG-046` | Relay SSRF/routing injection           | Supply URL/IP/metadata-service shaped route                             | Only registered opaque route IDs accepted                                      | No outbound arbitrary connection                   | Network trap count zero                           |   4   |
| `ARC10-NEG-047` | Cross-tenant account read              | Tenant A requests B account/membership                                  | Uniform not-found/denied                                                       | No B metadata                                      | Query scope and response inspection               |   5   |
| `ARC10-NEG-048` | Cross-tenant device mutation           | A revokes/transfers B device ID                                         | Denied by authoritative ownership                                              | No B state/session change                          | Before/after device lifecycle                     |   5   |
| `ARC10-NEG-049` | Cross-tenant workspace discovery       | Hosted client guesses B workspace/name/path                             | No hosted lookup or disclosure                                                 | No local host path/content                         | Hosted/log response scan                          |   5   |
| `ARC10-NEG-050` | Cross-tenant session migration         | Move A route/session credential to B membership                         | Uniform refusal                                                                | No rebinding                                       | Session/tenant/device binding evidence            |   5   |
| `ARC10-NEG-051` | Cross-tenant approval redemption       | Redeem A approval under B actor/tenant                                  | Local generic approval rejection                                               | No privileged execution/consumption by B           | Approval state and execution count                |   5   |
| `ARC10-NEG-052` | Cross-tenant quota switching           | Forge tenant inputs while exhausting A                                  | Charges remain on derived A key                                                | No B quota impact                                  | Bucket-key/counter evidence                       |   5   |
| `ARC10-NEG-053` | Cache-key tenant omission              | Interleave same object IDs in A and B                                   | Results remain tenant-qualified                                                | No cached crosstalk                                | Concurrent cache/request evidence                 |   5   |
| `ARC10-NEG-054` | Hosted payload persistence             | Exercise file/process/diff calls through relay then inspect stores      | Only allowed metadata/ciphertext-transient state exists                        | No payload/path/token persistence                  | Store/log/backup scan                             |   5   |
| `ARC10-NEG-055` | Telemetry content leakage              | Inject sentinels in MCP content/errors                                  | Aggregates omit sentinel and raw identifiers                                   | No content-level telemetry                         | Exported metric/log scan                          |   5   |
| `ARC10-NEG-056` | Tenant deletion residuals              | Delete controlled tenant after drain                                    | Issuance/routes revoked; deletable metadata erased within policy               | No reusable credential/orphan route                | Deletion job and store scan                       |   5   |
| `ARC10-NEG-057` | Deprovision race                       | Concurrent request with account/device removal                          | Revocation wins before new privileged work                                     | No post-revocation execution                       | Ordered lifecycle and counters                    |   5   |
| `ARC10-NEG-058` | Hosted service audit cross-leak        | Generate distinct tenant sentinels and export service audit             | Each view is scoped/minimized                                                  | No other tenant sentinel                           | Per-tenant export inspection                      |   5   |
| `ARC10-NEG-059` | Identity/control-plane outage          | Fault issuer/account store during new route request                     | Fail closed with bounded timeout                                               | No stale grant extension                           | Injected-failure trace                            |   6   |
| `ARC10-NEG-060` | Relay outage downgrade                 | Stop relay during active/new tunnel                                     | Bounded disconnect/retry; direct local mode only if independently configured   | No plaintext fallback                              | Connection and config evidence                    |   6   |
| `ARC10-NEG-061` | Service-audit write failure            | Fail required hosted security-event append                              | State-changing hosted action blocked/degraded                                  | No unaudited pairing/revocation                    | Write-before-action counter                       |   6   |
| `ARC10-NEG-062` | Connection storm                       | Bounded concurrent authenticated/failed relay connections               | Frozen limits reject and reclaim                                               | No retained sockets/keys                           | Baseline/peak/final counters                      |   6   |
| `ARC10-NEG-063` | Oversized relay frame                  | Send exact-boundary and boundary+1 frames/chunks                        | Overflow rejected before forwarding                                            | No allocation/parse/host dispatch                  | Byte counters and dispatch spy                    |   6   |
| `ARC10-NEG-064` | Slow tunnel                            | Trickle frame/header data past deadline                                 | Connection closes and resources release                                        | No indefinite deadline/socket                      | Deterministic clock and holder counts             |   6   |
| `ARC10-NEG-065` | Quota-key explosion                    | Generate bounded invalid/high-cardinality identities                    | Only authenticated tenant keys allocate within ceiling                         | No unbounded map                                   | Key-count and eviction/refusal evidence           |   6   |
| `ARC10-NEG-066` | Metrics cardinality/secret injection   | Put attacker labels/token shapes into requests                          | Labels normalized/allowlisted/redacted                                         | No raw value or unbounded series                   | Metrics registry snapshot                         |   6   |
| `ARC10-NEG-067` | Retry duplicate execution              | Interrupt response after host completion and retry same logical request | Protocol idempotency/replay semantics prevent silent duplicate privileged work | No second lifecycle                                | Local audit/execution count                       |   6   |
| `ARC10-NEG-068` | Malicious dependency artifact          | Substitute package with changed integrity                               | Frozen install/build fails                                                     | No lifecycle script execution from substitute      | Package-manager integrity result                  |   7   |
| `ARC10-NEG-069` | Release signing-key exposure           | Scan source, history, artifacts, logs, and CI metadata                  | No private signing material exists                                             | No key/token leak                                  | Full-range secret scan                            |   7   |
| `ARC10-NEG-070` | Forged release manifest                | Change version/checksum/platform after signing                          | Signature/binding verification fails                                           | No install/publish                                 | Manifest verification result                      |   7   |
| `ARC10-NEG-071` | Downgrade artifact                     | Offer authentic older artifact over newer state                         | Monotonic policy warns/refuses unsafe downgrade                                | No state rewrite                                   | Version/migration evidence                        |   7   |
| `ARC10-NEG-072` | Dependency vulnerability blocker       | Seed fixture lock/advisory with critical/high release blocker           | Release gate fails                                                             | No stable promotion                                | Audit report and policy decision                  |   7   |
| `ARC10-NEG-073` | License/provenance omission            | Remove dependency license/source provenance                             | Release validation fails                                                       | No incomplete notice/SBOM                          | Inventory reconciliation                          |   7   |
| `ARC10-NEG-074` | Directory credential/integration creep | Inspect runtime, artifacts, network calls, and config                   | No vendor-directory credential, submission, or callback exists                 | No external directory access                       | Surface/network/secret scan                       |   7   |
| `ARC10-NEG-075` | Platform claim without evidence        | Mark validation target as supported absent matrix evidence              | Documentation/release gate fails                                               | No unsupported artifact publication                | Claim-to-evidence mapping                         |   7   |
| `ARC10-NEG-076` | Tool catalog drift                     | Discover stdio/remote production tools                                  | Exact inherited 25 only                                                        | No hidden/unreviewed tool                          | Exact-name set comparison                         |   8   |
| `ARC10-NEG-077` | Deterministic registry drift           | Inspect production registry and invoke arbitrary package/shell attempts | Exact inherited five; arbitrary execution denied                               | No sixth/dynamic entry                             | Exact-ID set and denial tests                     |   8   |
| `ARC10-NEG-078` | Incomplete acceptance ownership        | Audit executable tests for `ARC10-NEG-001..080` and flows               | Every ID exactly owned; no skip/todo/out-of-range                              | No count-only documentation proof                  | Deterministic implementation mapping              |   8   |
| `ARC10-NEG-079` | Premature/inconsistent promotion       | Compare pre-final history and all current identity surfaces             | Pre-final stays RC-08; final changes atomically only after gates               | No partial `1.0.0` claim                           | Provenance SHA and surface matrix                 |   8   |
| `ARC10-NEG-080` | Final verifier masking/bypass          | Inspect/run final script with injected gate failure                     | Non-zero failure; no masking; branch/provenance rules enforced                 | No skipped mandatory gate                          | Gate inventory and fault-injection result         |   8   |

## 20. Positive Acceptance Flow Catalog

The final catalog is frozen at **18 flows**, `ARC10-FLOW-01` through `ARC10-FLOW-18`. Hosted-profile flows validate the real implementation if shipped; if the profile is omitted, its task instead supplies the corresponding disabled-surface controls and cannot claim those flows as supported. Stable promotion requires every flow applicable to the declared release profile and an exact, reviewed profile manifest—never a silent skip.

| Flow            | Title / actors                                            | Starting state and sequence                                                                                            | Expected result / audit evidence                                                                                                        | Cleanup                                                        | Owner |
| :-------------- | :-------------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------- | :---: |
| `ARC10-FLOW-01` | Verified source installation; operator                    | Clean supported Linux host fixture; verify artifact, install with locked dependencies, initialize config, start health | Healthy `0.8.0-rc08` pre-promotion runtime; signature/checksum/SBOM/provenance evidence and install audit                               | Stop and uninstall owned artifacts                             |   1   |
| `ARC10-FLOW-02` | Reproducible release build; release engineer              | Two clean builders use same source, lockfile and toolchain                                                             | Normalized artifact digests match; signed manifest and SBOM bind exact commit                                                           | Destroy builders and test keys                                 |   1   |
| `ARC10-FLOW-03` | Clean uninstall/reinstall; operator                       | Installed core with workspace, config, and audit fixtures                                                              | Uninstall preserves user data; reinstall restores healthy service without authority drift                                               | Remove controlled fixtures explicitly                          |   1   |
| `ARC10-FLOW-04` | RC-08 to 1.0 upgrade; operator                            | Verified RC-08 config, enrollment, policy, and audit state; run versioned migration                                    | Transactional upgrade preserves semantics and audit continuity; migration evidence recorded                                             | Retain backup until verification, then securely remove fixture |   2   |
| `ARC10-FLOW-05` | Compatible rollback/recovery; operator                    | Interrupt migration at deterministic seam, recover, then perform supported rollback                                    | Idempotent recovery and documented rollback restore a verified state                                                                    | Remove backup/recovery fixtures                                |   2   |
| `ARC10-FLOW-06` | OAuth public-client login; account user                   | Hosted profile enabled; registered public client and tenant membership; Authorization Code + PKCE                      | Issuer/audience/nonce validated; short-lived tenant-scoped access issued; minimized service audit                                       | Revoke session and rotate/delete refresh fixture               |   3   |
| `ARC10-FLOW-07` | Tenant/device enrollment; tenant admin and local operator | Authenticated tenant plus unpaired ARC host                                                                            | Local consent binds public SPKI/device to one tenant without granting host tools                                                        | Revoke pairing and prove routes close                          |   3   |
| `ARC10-FLOW-08` | Hosted profile disabled; core operator                    | Default stable Core configuration                                                                                      | Direct stdio or direct mTLS ARC remains fully usable with zero hosted listener/egress                                                   | Close local session                                            |   3   |
| `ARC10-FLOW-09` | Opaque paired relay session; user/device/host             | Valid hosted grant, locally approved pairing, enrolled mTLS device                                                     | Inner TLS 1.3/mTLS establishes through relay and a read-only MCP call succeeds; relay sees no payload                                   | Close tunnel/session and release holders                       |   4   |
| `ARC10-FLOW-10` | Relay revocation; tenant admin                            | Active tunnel and session                                                                                              | Revoke route/device; active tunnel closes and later grants fail while local audit remains truthful                                      | Drain route and delete ephemeral grants                        |   4   |
| `ARC10-FLOW-11` | Relay backpressure recovery; client/host                  | Authenticated tunnel at bounded load                                                                                   | Backpressure holds bounds, traffic resumes after drain, no duplicate MCP execution                                                      | Close tunnel; counters return to baseline                      |   4   |
| `ARC10-FLOW-12` | Concurrent tenant isolation; users A/B                    | Two tenants, devices, routes, and unique safe sentinels                                                                | Concurrent read-only calls return only own data; hosted and local audits verify with no crosstalk                                       | Revoke both sessions/routes and delete fixtures                |   5   |
| `ARC10-FLOW-13` | Tenant deprovisioning; owner/operator                     | Tenant with account, device, and inactive routes                                                                       | Issuance stops, credentials revoke, hosted metadata deletion completes, local host data remains operator-owned                          | Verify retention/deletion report                               |   5   |
| `ARC10-FLOW-14` | Bounded hosted operation; multiple clients                | Mixed healthy, rejected, and disconnecting connections under injected monotonic time                                   | Service remains responsive; quotas, metrics and service audit remain scoped/bounded; counters reclaim                                   | Drain all clients and verify zero holders                      |   6   |
| `ARC10-FLOW-15` | Artifact verification by consumer                         | Download source archive, manifest, signature, SBOM, and provenance from release fixture                                | Offline verification maps artifact to exact reviewed commit and declared platform                                                       | Remove download fixture                                        |   7   |
| `ARC10-FLOW-16` | Compatibility matrix; release engineer                    | Supported Linux plus declared validation environments                                                                  | Core protocol/config/install evidence matches truthful support labels; unsupported targets remain unclaimed                             | Tear down matrix fixtures                                      |   7   |
| `ARC10-FLOW-17` | Full ARC 1.0 verification; reviewer                       | Exact final candidate with declared Core/Hosted profile manifest                                                       | Future `scripts/verify-arc10.sh` passes every applicable control/flow, regressions, artifacts, migration, security, and provenance gate | Preserve signed evidence only                                  |   8   |
| `ARC10-FLOW-18` | Stable promotion and clean install; release authority     | Independently approved candidate and exact reviewed commit                                                             | Atomically promote all authoritative surfaces to `1.0.0`, build signed artifacts, fresh-install and verify health/stage                 | No tag/publish until independent final approval                |   8   |

## 21. Stable Release Gates

Promotion to `1.0.0` is forbidden until Task 8 verifies:

1. exact implementation ownership and successful execution for all applicable `ARC10-NEG-001..080` and `ARC10-FLOW-01..18`, with a reviewed release-profile manifest accounting for optional hosted controls;
2. every inherited RC-01 through RC-08 test and security invariant;
3. full repository tests with zero failure, cancellation, skip, or todo in acceptance controls;
4. build, formatting, lint, typecheck, documentation integrity, secret scans, dependency audit, `git diff --check`, and full-history Gitleaks;
5. exact 25-tool catalog and five-entry deterministic registry unless separately approved architecture explicitly changes them;
6. clean install/uninstall, RC-08 upgrade, interrupted migration recovery, compatible rollback, and fresh-install verification;
7. reproducible artifacts, checksums, signatures/attestations, SBOM, licenses, dependency inventory, provenance, and supported-platform evidence;
8. hosted-profile penetration, tenancy, privacy, revocation, outage, resource, and no-payload-persistence evidence if that profile is declared;
9. independent security review with zero unresolved critical/high release blockers and documented disposition of lower severities;
10. exact source commit, parent, builder/toolchain, artifact digests, release-profile manifest, and version/stage consistency;
11. independent approval before pushing a stable tag or publishing an artifact.

Task 8 will create `scripts/verify-arc10.sh`. It must be deterministic, fail closed, contain no masked gates, audit actual executable acceptance ownership, validate the declared profile, run all quality/security/migration/install/artifact gates, and verify exact provenance. Task 0 does not create it.

## 22. Versioning

The repository remains `0.8.0-rc08` / `RC-08` throughout Task 0 and until an authorized later promotion task. The proposed implementation progression is:

1. `0.8.0-rc08` during Tasks 0–6;
2. optional `1.0.0-rc.1` in Task 7 only if separately authorized after feature freeze;
3. additional `1.0.0-rc.N` only for reviewed corrections, never feature expansion;
4. `1.0.0` exclusively in Task 8 after every stable gate passes.

Intermediate candidates are recommendations, not authorization to change current version surfaces. Historical RC documentation remains unchanged.

## 23. Explicit Out-of-Scope Catalog

The following are not ARC 1.0 capabilities:

- arbitrary shell strings or unrestricted command execution;
- unrestricted/mutating Git commands or protected-branch bypass;
- production cloud-root credentials or cloud administration defaults;
- a claim of OS/kernel network sandboxing for arbitrary project code;
- a general-purpose secrets-management product;
- remote desktop, screen control, or interactive host administration;
- arbitrary third-party plugin code execution;
- unreviewed identity providers, SAML, social-provider-specific behavior, or dynamically trusted issuers;
- mobile clients and native Windows host-execution support;
- a general observability/data-lake platform;
- model hosting, model inference, prompt storage, or agent orchestration;
- directory marketplace publication or vendor webhooks;
- metering, billing, subscriptions, payment processing, or autonomous billing/entitlement decisions;
- trusted relay termination of MCP payloads;
- storage of workspace/file/process/diff content by hosted infrastructure.

## 24. Frozen Decisions and Review Points

No implementation team may invent policy for an unresolved item. Task 0 proposes these conservative decisions for independent approval:

1. **Stable product shape:** Core Distribution is the only mandatory stable profile; Hosted Connectivity is optional and all-or-nothing.
2. **Relay trust:** opaque frame relay with inner end-to-end TLS 1.3/mTLS; relay is untrusted for payload and host authorization.
3. **Tenant authority:** immutable server-generated tenant ID derived from verified account membership; no client field is authoritative.
4. **OAuth relationship:** hosted routing authentication only; it never replaces local device trust, ARC sessions, policy, audit, or approval.
5. **Commercial boundary:** metering, billing, subscriptions, and directory publishing are deferred post-1.0.
6. **Platforms:** Linux x86-64 is the sole mandatory supported security target; WSL is development-compatible; Linux arm64/macOS remain validation targets; native Windows is unsupported.
7. **Hosted data:** content-bearing host data and ARC secrets may transit only inside opaque ciphertext and may never persist in hosted infrastructure.
8. **Release identity:** current version/stage remain RC-08 until Task 8; a release candidate does not itself authorize publication.

Alternatives rejected for 1.0 include trusted MCP termination at the relay (larger breach radius), OAuth-only host admission (weakens SPKI device trust), client-selected tenant IDs (confused deputy risk), and mandatory hosted dependency for local ARC (availability and sovereignty regression).

Independent review must either approve these decisions or return Task 0 for a documentation-only correction. Implementation MUST NOT resolve them implicitly.

# RC-06 Final Integration & Acceptance Report

**Stage:** RC-06 — Audit & Evidence Architecture: Persistent Append-Only Logging, Tiered Anchoring, and Automated Redaction

**Scope title:** Persistent append-only JSONL storage foundation, crash consistency and startup recovery, universal pre-dispatch durability, size and time-based rotation, retention and gzip compression, Tier-2 Ed25519 signed checkpoints, Tier-3 external witness anchoring and spooling, CLI offline verifier and evidence export, and central secrecy hardening with authoritative payloadHash derivation.

**Base main:** `b86b1558f5000846c838147890b0de67fef963be`

**Approved implementation baseline before Task 8:** `d0c8a48dc2038b09a6c2fe71a493e3d01422ac87`

**Task-8 implementation history:**

- Final secrecy hardening, acceptance suites, verification script, and version bump: the commit containing this report

**Branch:** `feat/rc-06-audit-evidence`

> PR and merge status is **not** asserted by this document. It is verified externally after independent review.

---

## 1. Eight-Task Implementation Summary

| Task | Deliverable                                                                                                                                                                                                                                                                                | Commits                                                                                                      |
| :--- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------- |
| 1    | Persistent Append Storage Foundation (0700 dir, 0600 file, `O_NOFOLLOW`, atomic lockfile, V1 canonical JSON schema, bounded 64 KiB records, SHA-256 hash chain).                                                                                                                           | `3b0b16c`, `042f2c7`, `54702de`, `a1dcb92`, `da7bce7`, `8dbc0d4`, `b4c33a0`, `56cc5aa`                       |
| 2    | Crash Recovery & Lifecycle Reconciliation (trailing partial write truncation, mid-line corruption detection, dangling `STARTED` reconciliation to `RECOVERY_INDETERMINATE`, single-recovery-token capability).                                                                             | `490ee02`, `6a35140`, `32da186`, `788540d`                                                                   |
| 3    | Rotation, Retention & Compression (size-based and time-based rotation triggers, timestamped segment naming, gzip compression, verified uncompressed segment deletion, fail-closed retention bounds).                                                                                       | `9d265bb`, `87baf00`, `2326c09`, `e618acc`                                                                   |
| 4    | Signed Checkpoints (Tier-2 Ed25519 public-key signed checkpoint manifests, 1,000-record cadence, storeId binding, public key pinning in `audit-store.json`).                                                                                                                               | `94399f6`, `b973ea1`, `037d71b`                                                                              |
| 5    | External Witness Anchoring & Spooling (Tier-3 HTTPS witness dispatches, mutual Ed25519 receipt verification, outage spooling with exponential backoff, catch-up replay).                                                                                                                   | `83a3079`, `6e1342d`                                                                                         |
| 6    | Durable Audit Runtime Composition (universal pre-dispatch durability, pipeline lifecycle integration, graceful flush and shutdown, restart continuity).                                                                                                                                    | `89aa5ed`, `bc3cf89`, `a83cd18`, `7ed2f8f`                                                                   |
| 7    | Offline CLI Verifier & Evidence Export (`arc audit verify`, `arc audit export`, bounded descriptor authority, atomic metadata parsing and authenticated baseline bytes binding, `AUDIT_SOURCE_UNSTABLE` detection).                                                                        | `1b37ad8`, `389f162`, `23cc2e5`, `dc7c715`, `321d305`, `9bd49ee`, `66a768a`, `1561ced`, `b4cdca7`, `d0c8a48` |
| 8    | Central Secrecy Hardening, Acceptance & Release (authoritative central `payloadHash` derivation from sanitized parameters, `RC06-NEG-100..104`, all 108 negative controls contiguous acceptance, 23 positive flows, `scripts/verify-rc06.sh`, public version `0.6.0-rc06`, stage `RC-06`). | Commit containing this report                                                                                |

---

## 2. Final Architecture Summary

### 2.1 Storage Foundation (`packages/audit/src/storage.ts`)

- **Filesystem Security:** The audit root directory enforces `0700` POSIX permissions and process UID ownership. Segment files enforce `0600` permissions. All path resolutions use `realpathSync` to prohibit symlink traversal and reject non-regular files (`O_NOFOLLOW` / `fstat` descriptor checks).
- **Process Mutual Exclusion:** Exactly one ARC process may hold an active audit directory. Mutual exclusion is guaranteed via `audit.lock`, opened with atomic `O_CREAT | O_EXCL | O_WRONLY` authority. Stale locks require explicit operator intervention; no advisory flock/fcntl locking is claimed.
- **Canonical JSONL Representation:** Every audit line is terminated by `\n` without `\r`. Keys are recursively sorted in lexicographical order. Floats (`NaN`, `Infinity`), unescaped control characters (`< 0x20`, `NUL`), and non-canonical whitespace are rejected before persistence.
- **Record Size & Preimage Bounds:** Single record size is bounded at 64 KiB (`MAX_RECORD_BYTES`). The SHA-256 hash chain preimage excludes `integrity.recordHash` itself, guaranteeing verifiable linear chain integrity starting from the 64-character zero genesis hash.

### 2.2 Crash Consistency & Recovery (`packages/audit/src/recovery.ts`)

- **Startup Recovery Scan:** On server restart, the authoritative storage subsystem performs a linear scan over the active segment before serving requests.
- **Tolerated Trailing Partial Writes:** Truncated trailing writes resulting from an ungraceful shutdown or crash are safely trimmed back to the last valid newline with `fdatasync`, provided all prior records remain pristine and valid.
- **Corrupted Record Rejection:** Mid-file bit flips, torn records, or invalid checksums reject startup unconditionally with `AUDIT_CORRUPT`, requiring manual operator investigation.
- **Lifecycle Reconciliation:** Operations recorded as `STARTED` without a corresponding terminal `COMPLETED` or `DENIED` record are reconciled upon restart with a synthetic terminal record marked `RECOVERY_INDETERMINATE`, preserving total operation observability.

### 2.3 Universal Durability (`apps/mcp-server/src/index.ts`)

- **Pre-Dispatch Durability:** For all tool executions, a `STARTED` audit record is durably committed to disk and flushed via `fdatasync` _before_ the subsystem boundary is crossed.
- **Fail-Closed Gate:** If disk persistence fails or the audit runtime enters a degraded state, privileged tool execution is immediately refused and no subsystem call occurs.
- **Terminal Evidence:** Once tool execution finishes, a `COMPLETED` record with duration, execution status, and changed files is persisted before the final MCP response is returned to the client.

### 2.4 Rotation & Retention (`packages/audit/src/rotation.ts`)

- **Dual Rotation Triggers:** Segments rotate based on size threshold (fixed 10 MiB / `SEGMENT_SIZE_THRESHOLD`) or operational time window (fixed 24 hours / `ROTATION_INTERVAL_MS`). These values are fixed security constants without runtime or configuration override.
- **Timestamped Segment Archiving:** Active segment `audit-active.jsonl` is rotated to a timestamped and sequence-bounded archive `audit-<timestamp>-seq<start>-seq<end>.jsonl.gz`.
- **Gzip Compression:** Closed segments are compressed to `.jsonl.gz` using Node.js `zlib`. The uncompressed segment is unlinked only after the compressed archive is fully written, synced, and validated.
- **Retention Budget & Fail-Closed Behavior:** There is NO automatic deletion, pruning, or wrapping of retained raw evidence. Fixed capacity limits (`MAX_ARCHIVE_SEGMENTS` and `TOTAL_AUDIT_BUDGET_BYTES`) fail closed when the budget is exhausted, refusing new appends rather than deleting history.

### 2.5 Signed Checkpoints (`packages/audit/src/checkpoint.ts`)

- **Tier-2 Verification:** Checkpoints provide cryptographic non-repudiation of audit chain segments without requiring third-party services.
- **Ed25519 Signatures:** Checkpoint manifests are signed using an Ed25519 private key. The public key fingerprint is pinned inside `audit-store.json` at store initialization.
- **AuditCheckpointV1 Structure & Cadence:** Checkpoints are generated every 1,000 records (`CHECKPOINT_INTERVAL`) or upon segment rotation. Each `AuditCheckpointV1` binds coverage range (`sequenceStart`, `sequenceEnd`), `terminalRecordHash`, `previousCheckpointHash`, `checkpointHash`, `storeId`, and Ed25519 signature. Merkle roots or digest trees are explicitly not part of the design.

### 2.6 External Witness Anchoring & Spooling (`packages/audit/src/anchor.ts`)

- **Tier-3 External Trust:** Checkpoints can be dispatched to an external HTTPS witness server to produce Ed25519 signed receipts.
- **Receipt Verification:** Receipts are cryptographically verified against pinned anchor public keys (`AnchorReceiptV1`) before acceptance.
- **Outage Spooling & Replay:** If the external anchor service is temporarily unreachable, pending checkpoint dispatches are spooled to durable disk queue files in `anchor-spool/<checkpointHash>.json` with fixed exponential backoff (1s, 2s, 4s, 8s, 16s) and replay on service recovery.

### 2.7 Offline CLI Verifier & Evidence Export (`apps/cli/src/index.ts`, `packages/audit/src/verify.ts`)

- **Independent Tooling:** The `arc audit` CLI commands operate independently of running server processes.
- **Atomic Generation Binding:** The verifier opens `audit-store.json` read-only with `O_NOFOLLOW` and reads the exact metadata bytes once, computing its SHA-256 digest and parsing JSON from the exact same descriptor read. This prevents race conditions where file rewrites alter metadata between parsing and digest computation (`AUDIT_SOURCE_UNSTABLE`).
- **Cryptographic Chain Validation:** Validates sequential record hashes, sequence numbers, checkpoint signatures, anchor receipts, and archive checksums end-to-end.
- **Evidence Export:** `arc audit export` produces deterministic, self-contained audit evidence bundles containing archived segments, checkpoints, receipts, and an authenticated manifest.

### 2.8 Central Secrecy & Payload Hash Authority (`packages/audit/src/index.ts`)

- **Centralized Pre-Persistence Redaction:** All audit records pass through `AuditLogger.appendRecord`, where fields are sanitized centrally before hash derivation or disk writes.
- **High-Confidence Secret Redaction:** Regex patterns identify and redact session tokens (`Arc-Session-Token`), authorization headers (`Bearer`), enrollment challenge secrets, and multiline PEM private keys/certificates (`[REDACTED_SECRET]`).
- **Path & Env Minimization:** Absolute host filesystem paths (both POSIX and Windows drive formats) are sanitized to relative workspace paths. Environment variables and process arguments are minimized to prevent secret leakage.
- **Authoritative `payloadHash`:** The persisted `payloadHash` is unconditionally computed centrally from the canonically formatted sanitized parameters: `SHA256(canonicalJson(parametersRedacted))`. Caller-supplied digests derived from raw secrets are discarded, closing offline hash oracle attacks.

---

## 3. Security Audit & All-108 Negative Controls Verification

All 108 frozen negative controls defined in `docs/architecture/rc06-scope-acceptance.md §34` are implemented, contiguous, unique, and verified passing:

| Control Range       | Domain                                                                                                                                                                                                                                                        | Primary Suite                           | Status |
| :------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :-------------------------------------- | :----- |
| `RC06-NEG-01..29`   | Filesystem security, permissions (`0700`/`0600`), ownership, symlinks, `O_NOFOLLOW`, atomic lockfile exclusivity, store metadata, line canonicalization, schemaVersion 1, bounded records (64 KiB), hash preimage omission                                    | `tests/rc06-storage.test.js`            | PASS   |
| `RC06-NEG-30..39`   | Crash consistency, restart continuation, torn active-tail recovery, truncate/re-verify                                                                                                                                                                        | `tests/rc06-recovery.test.js`           | PASS   |
| `RC06-NEG-40..45`   | Universal pre-dispatch durability, fail-closed DEGRADED_AUDIT_FAILURE, health status                                                                                                                                                                          | `tests/rc06-runtime-durability.test.js` | PASS   |
| `RC06-NEG-46..47`   | Recovery append durability, dangling STARTED reconciliation to RECOVERY_INDETERMINATE                                                                                                                                                                         | `tests/rc06-recovery.test.js`           | PASS   |
| `RC06-NEG-48..63`   | Size (10 MiB) and interval (24h) rotation triggers, timestamped archive naming, gzip compression, verified deletion, fail-closed retention bounds                                                                                                             | `tests/rc06-rotation.test.js`           | PASS   |
| `RC06-NEG-64..83`   | Tier-2 Ed25519 signed checkpoints, 1,000-record cadence, storeId binding, key security, trust roots                                                                                                                                                           | `tests/rc06-checkpoint.test.js`         | PASS   |
| `RC06-NEG-84..99`   | Tier-3 HTTPS witness anchoring, Ed25519 receipts, spooling, exponential backoff, crash recovery                                                                                                                                                               | `tests/rc06-anchor.test.js`             | PASS   |
| `RC06-NEG-100..104` | Central secrecy hardening, session tokens, authorization headers, PEM keys/certs, env minimization, workspace path masking                                                                                                                                    | `tests/rc06-negative-controls.test.js`  | PASS   |
| `RC06-NEG-105..108` | CLI & export isolation (NEG-105: remote destructive audit MCP tool -> UNKNOWN_TOOL; NEG-106: export destination exists/overwrite -> reject; NEG-107: symlink destination/parent -> reject; NEG-108: audit/workspace-contained or >MAX_EXPORT_BYTES -> reject) | `tests/rc06-cli-verifier.test.js`       | PASS   |

---

## 4. All-23 Positive Acceptance Flows Verification

All 23 frozen positive acceptance flows defined in `docs/architecture/rc06-scope-acceptance.md §32` are implemented and verified passing in `tests/rc06-positive-flows.test.js`:

1. **RC06-FLOW-01: Fresh Persistent Store Initialization** — Fresh directory initialization with `0700` directory permissions, `0600` active segment, valid `audit-store.json`, and initial lock acquisition.
2. **RC06-FLOW-02: Standard Stdio Read-Only Tool Execution** — `read_file` execution produces durable `STARTED` and `COMPLETED` records linked by SHA-256 hash continuity.
3. **RC06-FLOW-03: Standard Stdio Mutation Tool Execution** — Mutation requiring operator approval executes successfully upon redemption, logging full lifecycle records.
4. **RC06-FLOW-04: Remote Authenticated Gateway Tool Execution** — Gateway tool execution binds authenticated remote actor credentials while redacting raw bearer tokens.
5. **RC06-FLOW-05: Policy Denial Audit Logging** — Directory traversal attempt is denied by policy and durably recorded with `status: DENIED`.
6. **RC06-FLOW-06: Operator Approval Lifecycle Persistence** — Approval request creation, granting, and consumption are logged with complete cryptographic hashes.
7. **RC06-FLOW-07: Gateway Admission & Lifecycle Auditing** — Gateway startup, client admission, and clean shutdown events are recorded into the durable audit chain.
8. **RC06-FLOW-08: Clean Process Termination** — Server shutdown flushes pending records and releases `audit.lock` cleanly.
9. **RC06-FLOW-09: Gateway Restart & Hash Continuity** — Server restart verifies existing chain integrity and appends new records with contiguous sequence numbers and hashes.
10. **RC06-FLOW-10: Size-Based Rotation Trigger** — Segment reaching size limit triggers atomic rotation to a timestamped and sequence-bounded archive.
11. **RC06-FLOW-11: Time-Based Operational Rotation Trigger** — Time elapsed past operational window triggers automatic rotation.
12. **RC06-FLOW-12: Compressed Archive Generation & Verified Deletion** — Closed segment is compressed with gzip, verified, and the uncompressed file is deleted.
13. **RC06-FLOW-13: Tier-2 Checkpoint Artifact Generation** — Checkpoint cadence triggers generation of an Ed25519 signed checkpoint manifest.
14. **RC06-FLOW-14: Offline Public-Key Checkpoint Verification** — Standalone verification validates checkpoint signature against pinned public key.
15. **RC06-FLOW-15: Tier-3 External Anchor Dispatch & Cryptographic Receipt** — Checkpoint is dispatched to external anchor and cryptographically signed receipt is stored.
16. **RC06-FLOW-16: Anchor Outage Spooling & Automatic Backoff Catch-Up** — Anchor outage causes requests to be spooled to disk; upon service restoration, spooled anchors are replayed.
17. **RC06-FLOW-17: Local Operator arc audit status** — Operator CLI command inspects audit store status, sequence number, and degradation state.
18. **RC06-FLOW-18: Local Operator arc audit inspect** — Detailed inspection of specific records and chain verification.
19. **RC06-FLOW-19: Universal Pre-Dispatch Durability** — Proves `STARTED` record is synced to disk before subsystem method execution begins.
20. **RC06-FLOW-20: Full Restart Verification of Retained History** — Verifies full historical chain integrity across rotated and compressed archives upon restart.
21. **RC06-FLOW-21: Crash-Indeterminate Lifecycle Reconciliation** — Unclosed `STARTED` record from a simulated crash is reconciled to `RECOVERY_INDETERMINATE` on restart.
22. **RC06-FLOW-22: Standalone Offline Verification Command** — `arc audit verify` performs independent end-to-end verification of an offline store.
23. **RC06-FLOW-23: Deterministic Evidence Export Verification** — `arc audit export` produces an archive bundle containing complete verified audit evidence.

---

## 5. Quality Gates & Verification Summary

The RC-06 verification script (`scripts/verify-rc06.sh`) executes 25 required gates with `set -euo pipefail` and zero error-masking fallbacks:

1. **Gate 1:** Git Branch Check (`feat/rc-06-audit-evidence`)
2. **Gate 2:** Frozen Lockfile Install (`pnpm install --frozen-lockfile`)
3. **Gate 3:** Code Formatting Check (`pnpm run check:format`)
4. **Gate 4:** Static Analysis & Lint Check (`pnpm run lint`)
5. **Gate 5:** TypeScript Clean Build Check (`tsc --build --clean`)
6. **Gate 6:** TypeScript Typecheck (`pnpm run typecheck`)
7. **Gate 7:** Monorepo Package Build (`pnpm -r run build`)
8. **Gate 8:** Dedicated RC-06 Negative-Controls Acceptance Suite (`tests/rc06-negative-controls.test.js`)
9. **Gate 9:** Dedicated RC-06 Positive Flows Acceptance Suite (`tests/rc06-positive-flows.test.js`)
10. **Gate 10:** All 8 RC-06 Owner Suites (`storage`, `recovery`, `runtime-durability`, `rotation`, `checkpoint`, `anchor`, `cli-verifier`, `negative-controls`)
11. **Gate 11:** Full Monorepo Test Suite (`pnpm run test`)
12. **Gate 12:** Git Diff Cleanliness Check (`git diff --check`)
13. **Gate 13:** Documentation Completeness & Links (`bash scripts/check-docs.sh`)
14. **Gate 14:** Secret & Credential Scanning (`bash scripts/check-secrets.sh`)
15. **Gate 15:** Dependency Security Audit (`pnpm audit`)
16. **Gate 16:** Negative-Control Contiguity & Completeness (Contiguous `RC06-NEG-01`..`108` without gaps or duplicates)
17. **Gate 17:** Positive Acceptance Flows Completeness (Contiguous `RC06-FLOW-01`..`23` without gaps or duplicates)
18. **Gate 18:** No Disabled or Deferred Tests (Zero `.skip` / `.todo`)
19. **Gate 19:** Security-Scanner Suppression Check (Zero inline security scanner suppressions)
20. **Gate 20:** Verification Script Integrity Self-Check (No `|| true` error-masking fallback)
21. **Gate 21:** Package Version & Script Consistency (`verify:rc06` mapping to `bash scripts/verify-rc06.sh`, `0.6.0-rc06` across root, CLI, and MCP server advertised version)
22. **Gate 22:** Health Version & Stage Consistency (`0.6.0-rc06` and `RC-06` reported by health endpoint in production source)
23. **Gate 23:** Required Task-8 Files Check (`tests/rc06-negative-controls.test.js`, `tests/rc06-positive-flows.test.js`, `scripts/verify-rc06.sh`, `docs/architecture/rc06-final-integration-report.md`)
24. **Gate 24:** Final Integration Report Check (Presence and non-emptiness of this report)
25. **Gate 25:** Scope Document Check (Presence of `docs/architecture/rc06-scope-acceptance.md`)

---

## 6. Exact Verification Results

### 6.1 Full Monorepo Test Execution Totals

Running the complete test suite across all packages and apps produces:

- **Total Test Files:** 39
- **Total Tests:** 1839 tests passing
- **Total Failures:** 0
- **Total Skipped / Deferred:** 0

### 6.2 CI Configuration Explanation

- **Local Verifier (`pnpm run verify:rc06` / `scripts/verify-rc06.sh`):** Serves as the authoritative local composite verifier. It runs all 25 gates sequentially, including negative-control contiguity checks, flow contiguity checks, script self-integrity validation, artifact presence checks, and owner suites.
- **GitHub Actions CI (`.github/workflows/ci.yml`):** Runs on push to feature branches and pull requests. Executes automated linting, formatting, typechecking, build, secret scanning (`gitleaks`), documentation link checks, dependency review, and the complete test suite across Node.js versions.

---

## 7. Dependency Posture

The RC-06 audit and evidence implementation adheres strictly to zero-external-dependency security principles:

- **Node.js Core Primitives:** Relies entirely on built-in Node.js modules:
  - `node:crypto`: SHA-256 hash chains, Ed25519 key generation and signatures, SPKI extraction.
  - `node:fs` & `node:fs/promises`: POSIX file descriptors, `O_NOFOLLOW`, `O_CREAT | O_EXCL`, `fdatasync`, `fstat`, atomic rename.
  - `node:zlib`: Gzip compression of rotated audit segments.
  - `node:http` & `node:https`: Standard HTTP/HTTPS client for external anchor dispatch.
- **No Heavyweight Database or Ledger Engines:** Implemented as a lightweight, robust, append-only flat-file storage engine without external database engines (e.g. SQLite, RocksDB, PostgreSQL).
- **Vulnerability Status:** `pnpm audit` reports **0 vulnerabilities**.

---

## 8. Deferred Scope Beyond RC-06

The following capabilities are deliberately out of scope for RC-06 and deferred to future releases:

- **Distributed Consensus / Raft Replication:** RC-06 focuses on single-instance authoritative persistent logging with external witness anchoring. Multi-node distributed consensus or replicated write quorums are deferred.
- **Hardware Security Module (HSM) / PKCS#11 Checkpoint Signing:** Signing keys are loaded from secure POSIX files; native PKCS#11 or cloud KMS signing integration is deferred.
- **Real-Time Streaming to Remote SIEM:** Audit records are written to local persistent storage and rotated archives; real-time syslog, OpenTelemetry, or SIEM forwarders are deferred.
- **Public Transparency Log Ingestion:** Tier-3 external anchoring implements HTTPS witness with mutual Ed25519 signed receipts. Native RFC 6962 Certificate Transparency / Sigstore Rekor integration is deferred.
- **Post-Quantum Cryptography:** Signatures utilize Ed25519; post-quantum digital signature algorithms (e.g. ML-DSA) are deferred.

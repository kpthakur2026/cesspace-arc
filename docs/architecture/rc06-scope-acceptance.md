# RC-06 Scope & Acceptance — Audit & Evidence Architecture Freeze

| Field         | Value                                                                                                                                          |
| :------------ | :--------------------------------------------------------------------------------------------------------------------------------------------- |
| **Stage**     | RC-06                                                                                                                                          |
| **Title**     | Audit & Evidence — Persistent Append-Only Logging, Tiered Anchoring, and Automated Redaction                                                   |
| **Status**    | **Task-0 Scope Candidate — Frozen Architecture Specification**                                                                                 |
| **Base main** | `b86b1558f5000846c838147890b0de67fef963be`                                                                                                     |
| **Branch**    | `feat/rc-06-audit-evidence`                                                                                                                    |
| **Purpose**   | Freeze persistent storage, crash consistency, rotation, retention, signed checkpoints, external anchoring, and offline verification semantics. |

> **Implementation MUST NOT begin until this scope is independently approved.**
> This document is a normative contract, not an implementation plan that has been
> accepted. Every rule below is intended to be directly code-testable; none of it
> is implemented by Task 0.

---

## 1. Authority and Status

This document is the **normative contract** for RC-06. On independent approval it
supersedes ambiguous or outdated RC-00 through RC-05 wording for the audit subsystem.
Until that approval, the existing documents remain as they are: **Task 0 modifies no other file**.

Where a historical document states something this contract contradicts, the
specific rule is cataloged in §33 (Historical Documentation Reconciliation) with
the new normative rule declared explicitly.

All architectural decisions required to evolve the in-memory RC-05 audit pipeline
into an authoritative, tamper-evident, persistently stored, and externally anchored
ledger are frozen in this specification.

---

## 2. Repository Baseline (as inspected for Task 0)

Every statement below was verified against the tree at
`b86b1558f5000846c838147890b0de67fef963be`.

### 2.1 Audit Package (`packages/audit`)

- `AuditLogger` is the single centralized audit sink implementing `IAuditLogger`.
- Storage is purely in-memory: records are accumulated in `private records: AuditRecord[] = []`.
- Chain integrity uses a sequential SHA-256 hash chain starting from an all-zero genesis:
  `0000000000000000000000000000000000000000000000000000000000000000`.
- Record hashing in RC-05 computes `computeSha256(canonicalJson(recordToHash))` where
  `canonicalJson` performs deterministic recursive key sorting.
- Redaction is strictly centralized and monotone:
  - Sensitive key names matching `SENSITIVE_KEY_PATTERNS` are replaced with `"[REDACTED_BY_NAME]"`.
  - Sensitive value shapes (AWS keys, GitHub tokens, Bearer tokens, `Arc-Session-Token`,
    `Authorization`, PKCS#8 private keys, X.509 certificate PEMs) are replaced with `"[REDACTED_SECRET]"`.
  - Absolute host paths are replaced with `"[REDACTED_PATH]"`.
  - Large or raw payloads (`content`, `patch`, `env`, `stdout`, `stderr`) are centrally omitted or masked.
  - Workspace targets are minimized: raw paths are cleared, leaving `workspaceRootHash`.
  - Gateway metadata is allowlist-projected against the 14 frozen event types and safe identifier shapes.
- Defensive copy: `getRecords()` and `log()` return defensive `copyBounded()` snapshots,
  preventing caller mutation from corrupting the internal chain.
- Method `clear()` empties the in-memory array and resets sequence to 1.
- **No persistent disk storage, rotation, compression, checkpointing, or external anchoring exists.**

### 2.2 Protocol Audit Definitions (`packages/protocol/src/audit.ts`)

- Defines `AuditRecord`, `AuditApprovalMetadata`, and `AuditGatewayMetadata`.
- Closes the 14 gateway lifecycle event types (`GATEWAY_AUDIT_EVENT_TYPES`) and
  12 gateway refusal reasons (`GATEWAY_AUDIT_REASONS`).
- Establishes admission layers `'A' | 'B' | 'C'`.
- Protocol package contains no disk I/O, crypto signing, or network client dependencies.

### 2.3 Server Integration (`apps/mcp-server`)

- Server instantiates `this.auditLogger = config.auditLogger ?? new AuditLogger()`.
- Captures all tool evaluations, executions, approval requests/redemptions, and gateway lifecycle transitions.
- All operations feed into the single process-wide `AuditLogger` instance.

### 2.4 CLI Interface (`apps/cli`)

- Implements `serve`, `policy`, `approval`, `device`, and `session` command groups.
- No `arc audit` command group exists in the CLI.

---

## 3. Primary Architectural Invariant: Single Authoritative Audit Chain

RC-06 is governed by an absolute architectural invariant:

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                    ONE PROCESS-WIDE AUDIT HASH CHAIN                             │
│                                                                                  │
│   Stdio Tool Invocations ───┐                                                    │
│   Remote MCP Calls ─────────┼──►  AuditLogger.log()  ──►  Canonical JSONL File  │
│   Approval Transitions ─────┤     (Central Redaction)     (Sequential SHA-256)   │
│   Gateway Events ───────────┘                                                    │
└──────────────────────────────────────────────────────────────────────────────────┘
```

1. **Single Sequence Space:** All events (stdio MCP tools, remote Streamable HTTP requests,
   operator approvals, gateway admissions, revocations, and rate limits) share a single
   strictly monotonic sequence space (`sequenceNumber: 1, 2, 3, ...`).
2. **No Secondary Ledgers:** There are no separate "gateway logs", "approval logs", or
   "session logs". Subsystems MUST NOT maintain unchained or independent audit files.
3. **No Unaudited Bypasses:** No caller, subsystem, or transport mode can bypass the canonical
   `AuditLogger` pipeline.
4. **Identity of Hashed and Stored Data:** The exact canonical JSON representation computed for
   the SHA-256 `recordHash` is what is durably serialized to disk. The disk layer must never
   re-serialize or alter record fields.

---

## 4. Persistent Record Format & Canonical JSON V1 Specification

Every persisted audit record represents a canonical `PersistentAuditRecordV1` JSON object:

### 4.1 Schema Version 1 Invariant

1. **Mandatory Version Field:** Every persisted record line MUST contain top-level:
   ```json
   "schemaVersion": 1
   ```
2. **Strict V1 Validation:**
   - Unknown top-level fields outside the V1 schema are strictly rejected.
   - Any record with an unsupported `schemaVersion` (e.g. `2`, `0`, or missing) is rejected
     by the offline verifier with a dedicated `UNSUPPORTED_SCHEMA_VERSION` error.
   - V1 verifiers MUST NOT silently parse or interpret future schema versions as V1.

### 4.2 Canonical Representation Rules

Before hashing or disk serialization, the in-memory record is transformed into canonical JSON:

- Only valid JSON data types (strings, numbers, booleans, arrays, objects, null).
- Values of `undefined` are **strictly forbidden**; optional keys whose value is absent or
  undefined are OMITTED entirely from the persistent representation.
- `NaN` and `Infinity` numeric values are strictly forbidden.
- Object keys are recursively sorted in lexicographical order (ASCII byte order).
- Arrays preserve their original element order.
- Encoded as UTF-8 with no insignificant whitespace (no space after colons or commas).

### 4.3 Exact Hash Preimage Construction

The hash contract is non-circular:

```text
hashPreimage = canonicalJson(full PersistentAuditRecordV1 EXCEPT integrity.recordHash is omitted)
integrity.recordHash = SHA256(hashPreimage)
```

The persisted JSONL line is:

```text
canonicalJson(full PersistentAuditRecordV1 including recordHash) + "\n"
```

Therefore:

- The stored line contains `recordHash`.
- The stored line itself is **NOT** directly hashed to obtain its own `recordHash`.
- The verifier reconstructs the exact hash preimage by removing `integrity.recordHash`,
  canonicalizing, and asserting that `SHA256(reconstructedPreimage) === storedRecordHash`.

### 4.4 Line Framing & Bounds

- Exactly one record per line ending in a single newline (`\n`, `0x0A`). Carriage returns (`\r`) are rejected.
- Maximum single line size: **64 KiB** (`MAX_RECORD_BYTES = 65,536` bytes).

---

## 5. Chain Continuity & Virtual Genesis Semantics

### 5.1 Virtual Genesis Hash

There is **NO synthetic "genesis record"** stored on disk.
The beginning of the cryptographic hash chain is defined by a virtual zero digest:

```text
0000000000000000000000000000000000000000000000000000000000000000
```

The first real audit record emitted in an audit store MUST have:

- `sequenceNumber: 1`
- `integrity.previousRecordHash: "0000000000000000000000000000000000000000000000000000000000000000"`

### 5.2 Restart Continuity

When ARC starts against an existing non-empty audit store:

1. The engine scans the retained history, verifies single-writer lock exclusivity,
   and reads the terminal record of the active segment.
2. The next record emitted MUST have:
   - `sequenceNumber = terminalRecord.sequenceNumber + 1`
   - `integrity.previousRecordHash = terminalRecord.integrity.recordHash`
3. Attempting to reset `sequenceNumber` to 1 or starting with the zero genesis hash while prior
   persistent records exist causes immediate fatal startup failure.

### 5.3 Prohibition of `clear()` in Production

The `clear()` method is designated exclusively for isolated in-memory unit tests.
In persistent production mode, calling `clear()` throws an uncatchable fatal error.

---

## 6. Crash Consistency, Write Ordering & Durability

### 6.1 Durability Primitives

- Every persistent write is executed via synchronous or explicitly synced filesystem APIs.
- The active segment file descriptor is opened with `O_APPEND | O_CREAT | O_WRONLY`.
- After appending a record line, `fdatasync()` is issued before acknowledging completion.
- When creating a new segment or rotating files, the parent directory is `fsync()`ed to
  guarantee directory entry persistence across power loss.

### 6.2 Crash Recovery & Torn-Tail Handling

In the event of an abrupt process crash or power loss:

- **Torn Line at EOF:** If the final line in the active segment lacks a terminating `\n` or
  contains malformed JSON, and all preceding records verify cleanly up to the torn bytes:
  - The torn bytes (up to `MAX_TORN_TAIL_BYTES = 64 KiB`) are copied to a sidecar file (`.torn.<timestamp>`).
  - The active segment is truncated to the last valid newline character.
  - Startup resumes cleanly from the last intact record.
- **Historic Corruption:** If corruption occurs anywhere prior to the final line, or if
  any hash link is broken, automatic recovery is **strictly prohibited**. The engine MUST fail closed and refuse to start.

---

## 7. Universal Audit Lifecycle & Execution Ordering (INV-13 Universal Auditability)

Universal auditability applies to **ALL privileged operations**, including read-only queries as well as mutations.

### 7.1 Protocol Lifecycle Phases

Every privileged operation records distinct lifecycle events bound by a server-generated `operationId`:

```typescript
export type AuditLifecyclePhase = 'STARTED' | 'COMPLETED' | 'DENIED';

export interface AuditLifecycleMetadata {
  operationId: string; // Server-generated UUIDv4
  phase: AuditLifecyclePhase;
}
```

### 7.2 Strict Execution State Machine

For every privileged tool invocation (filesystem reads, Git reads, terminal/process executions, mutations):

```text
  [Request Received]
          │
          ▼
  [Policy / Auth Evaluation]
          │
    ┌─────┴────────────────────────┐
    ▼                              ▼
 [DENY]                         [ALLOW / APPROVED]
    │                              │
    ▼                              ▼
[Sync DENIED Record]            [Sync STARTED Record via fdatasync()]
    │                              │
    ▼                              ├──► FAIL ──► [ABORT: Subsystem Never Dispatched]
 [Return Error]                    │
                                   ▼ SUCCESS
                             [Execute Subsystem Action (Read or Mutation)]
                                   │
                                   ▼
                             [Sync COMPLETED Record via fdatasync()]
                                   │
                                   ├──► FAIL ──► [Transition to DEGRADED_AUDIT_FAILURE]
                                   │              (HALT all subsequent privileged dispatch)
                                   ▼ SUCCESS
                             [Return Result to Caller]
```

1. **Pre-Dispatch Durability:** The `STARTED` record MUST be durably flushed to disk via `fdatasync()`
   before the subsystem operation is initiated. If the audit write fails (e.g. `ENOSPC`, disk error),
   **the subsystem operation MUST NOT be dispatched**.
2. **Post-Dispatch Durability:** After subsystem execution completes, the `COMPLETED` record is synced.
   If this write fails after a read or mutation occurred:
   - The gateway transitions immediately to global `DEGRADED_AUDIT_FAILURE`.
   - All subsequent privileged MCP tool invocations (reads AND mutations) are rejected.
   - No remote "read-only availability" escape hatch is preserved.
   - Only bounded local operator audit status and verification commands remain accessible.
3. **Denied Requests:** A policy `DENY` produces one durable `DENIED` record before returning the denial error.

---

## 8. Local Audit Storage Security & Filesystem Authority

### 8.1 Directory Security

- Configured via `audit.directory`. Default: `~/.cesspace-arc/audit/`.
- Must be an absolute path resolved via `fs.realpathSync`.
- Directory permissions MUST be exactly `0700` (`rwx------`). Group/world access is forbidden.
- Directory MUST be owned by the real process UID (`process.getuid()`).
- The directory and all parent components MUST NOT be symbolic links.
- The audit directory MUST NOT reside inside, overlap with, or be a subdirectory of any agent workspace.

### 8.2 File Security Authority

For all active, archived, checkpoint, spool, and receipt files:

- Must be **regular files only** (`stats.isFile() === true`). FIFOs, sockets, and device nodes are rejected.
- Hard link count MUST be exactly 1 (`stats.nlink === 1`). Hard-linked files are rejected.
- File permissions MUST be exactly `0600` (`rw-------`).
- File ownership MUST match the process real UID.
- Files are opened using `O_NOFOLLOW` semantics where supported, and the resulting file descriptor
  is verified via `fstat()` prior to any I/O. Subsequent operations use the validated descriptor.

---

## 9. Single-Writer Process Locking (`O_CREAT | O_EXCL`)

To prevent concurrent appends, sequence collisions, or competing rotations:

1. **Lock Mechanism:** The server acquires an exclusive lock by atomically creating `audit.lock`
   using `O_CREAT | O_EXCL` (`'wx'`) open flags.
2. **Lock Properties:** Mode `0600`, regular file, no symlinks, no hard links.
3. **Payload:** Contains bounded diagnostic JSON metadata: `{ "pid": <number>, "startedAt": "<ISO-8601>" }`.
4. **Collision Behavior:** If `audit.lock` exists (`EEXIST`), startup fails immediately with `AUDIT_STORE_LOCKED`.
5. **No Automatic Stale-Lock Takeover:** Heartbeat-based automatic takeover is strictly forbidden.
   If a previous process crashed leaving a stale lock, startup fails closed; removal requires
   explicit operator intervention while ARC is stopped.
6. **Clean Release:** On clean shutdown, `audit.lock` is closed, unlinked, and the parent directory is `fsync()`ed.

---

## 10. Segment Rotation & Compression Contract

### 10.1 Rotation Triggers

Active segments rotate when EITHER threshold is met:

1. **Size Threshold (Hard Security Limit):** Active segment reaches or exceeds **10 MiB** (`10,485,760` bytes).
2. **Time Threshold (Operational Convenience):** Exactly **24 hours** (`86,400` seconds) elapsed since first record.
   - _Clock Skew Semantics:_ Wall-clock forward jumps may trigger early rotation; wall-clock rollbacks
     may delay the time trigger, but cannot bypass the 10 MiB hard limit.

### 10.2 Naming Convention & Determinism

Rotated segments follow a deterministic chronological naming schema:

```text
audit-<YYYYMMDDTHHMMSSZ>-seq<startSeq>-seq<endSeq>.jsonl
```

When compressed:

```text
audit-<YYYYMMDDTHHMMSSZ>-seq<startSeq>-seq<endSeq>.jsonl.gz
```

### 10.3 Chain Continuity Across Rotation

- Rotation is purely a physical file boundary; the logical hash chain is contiguous.
- Before closing a segment, a **Tier 2 checkpoint artifact** is emitted, sealing the segment.
- The first record in the next segment contains `sequenceNumber = endSeq + 1` and
  `integrity.previousRecordHash` equal to the `recordHash` of the terminal record in the rotated segment.

### 10.4 Compression & Deletion Contract

- Rotated segments are compressed using streaming `gzip` (`node:zlib`).
- The uncompressed `.jsonl` file MUST NOT be deleted until the resulting `.jsonl.gz` file has been
  decompressed in memory, verified against the SHA-256 chain, and verified intact.
- The `.jsonl.gz` archive is assigned `0600` permissions.

---

## 11. Retention Policy & Fail-Closed Storage Budget

To prevent audit log saturation denial-of-service without risking evidence destruction:

### 11.1 Fixed Capacity Bounds

```text
MAX_ARCHIVE_SEGMENTS = 100
TOTAL_AUDIT_BUDGET_BYTES = 1 GiB (1,073,741,824 bytes)
```

### 11.2 Prohibition of Automatic Retention Deletion

- External anchoring records proof of a checkpoint, not a secondary copy of raw records.
- Therefore, **automatic deletion of historical audit segments is strictly OUT OF SCOPE for RC-06**.
- When `MAX_ARCHIVE_SEGMENTS` or `TOTAL_AUDIT_BUDGET_BYTES` is reached:
  - The server MUST NOT delete, overwrite, or wrap historical evidence.
  - The server enters `AUDIT_STORAGE_EXHAUSTED` mode.
  - All subsequent privileged MCP tool invocations (reads and mutations) are rejected.
  - Local operator status commands expose degraded health, requiring operator storage remediation.

---

## 12. Tier 2: Signed Cryptographic Checkpoint Contract (Artifact Stream)

Checkpoints are cryptographic integrity artifacts authenticating the primary audit chain.
They are **NOT audit events** and MUST NOT consume an audit `sequenceNumber`.

### 12.1 Checkpoint Artifact Stream (`audit-checkpoints.jsonl`)

Checkpoints are stored in a dedicated file in the audit directory: `audit-checkpoints.jsonl` (mode `0600`).
Every entry is an `AuditCheckpointV1` canonical JSON line:

```typescript
export interface AuditCheckpointV1 {
  version: 1;
  checkpointId: string; // UUIDv4
  sequenceStart: number; // Positive integer
  sequenceEnd: number; // Terminal primary audit record sequence covered
  terminalRecordHash: string; // 64 lowercase hex
  previousCheckpointHash: string; // 64 lowercase hex (or 64-zero genesis)
  createdAt: string; // ISO-8601 UTC
  publicKeyFingerprint: string; // 64 lowercase hex SHA-256 of Ed25519 SPKI
  signature: string; // Base64url Ed25519 signature
  checkpointHash: string; // 64 lowercase hex SHA-256
}
```

### 12.2 Cadence & Scope

- Emitted every **1,000 primary audit records** OR upon segment rotation.
- If the 1,000-record interval coincides with segment rotation, exactly ONE checkpoint is emitted.
- `sequenceStart`: sequence of first primary record covered (1 for genesis, or previous `sequenceEnd + 1`).
- `sequenceEnd`: sequence of terminal primary record covered.

### 12.3 Exact Signature & Hash Preimage Construction

The checkpoint signature and hash preimages avoid self-reference:

```text
domain = "CESSPACE-ARC-CHECKPOINT-V1\0"
unsignedCheckpoint = canonicalJson({
  version: 1,
  checkpointId,
  sequenceStart,
  sequenceEnd,
  terminalRecordHash,
  previousCheckpointHash,
  createdAt,
  publicKeyFingerprint
})

signature = Ed25519.sign(domain || UTF8(unsignedCheckpoint), privateKey)

checkpointHash = SHA256(canonicalJson({
  version: 1,
  checkpointId,
  sequenceStart,
  sequenceEnd,
  terminalRecordHash,
  previousCheckpointHash,
  createdAt,
  publicKeyFingerprint,
  signature
}))
```

The next checkpoint's `previousCheckpointHash` equals the prior checkpoint's `checkpointHash`.
Genesis checkpoint uses the 64-zero hex digest for `previousCheckpointHash`.

---

## 13. Checkpoint Signing Key Management & Security

### 13.1 Key Format & Algorithm

- Algorithm: **Ed25519 (RFC 8032)** via native `node:crypto`.
- Format: PKCS#8 Ed25519 private key PEM file.
- Bound: Maximum key file size **4 KiB** (`MAX_SIGNING_KEY_BYTES = 4,096` bytes).

### 13.2 Filesystem Authority & Loading Rules

- Configured via `audit.signingKeyPath`.
- Must be a regular file, mode `0600`, realprocess UID owned, hard-link count == 1 (`nlink == 1`), symlinks rejected.
- Must reside outside all agent workspaces.
- Opened with `O_NOFOLLOW` and validated via `fstat()` prior to parsing.
- Strictly prohibited: `process.argv`, ambient environment variables, MCP headers, configuration literals, logs.
- Memory hygiene: Transient PEM input buffers are zeroized (`.fill(0)`) where practical after `createPrivateKey()`. Key descriptors are closed promptly.

### 13.3 Key Lifecycle & Pinned Identity

- A fresh audit store pins the SHA-256 fingerprint of the configured Ed25519 public key.
- Every subsequent checkpoint MUST use the same key fingerprint.
- Starting an existing non-empty store with a mismatched signing key fails closed immediately.
- Automatic/live key rotation is OUT OF SCOPE for RC-06.

---

## 14. Tier 3: External Anchoring & Receipt Verification Contract

Tier 3 establishes independent external non-repudiation by submitting signed checkpoints to an
external HTTPS anchor receiver and obtaining cryptographically signed receipts.

### 14.1 Anchored Payload

Only **signed checkpoints** (`AuditCheckpointV1`) are transmitted.
Raw audit records, parameters, and tokens are NEVER transmitted to the anchor.

### 14.2 Transport & Receipt Verification

- **Transport:** HTTPS over TLS 1.3 with standard server certificate validation. No plaintext HTTP.
- **No Bearer Tokens:** Authentication is application-level cryptographic proof:
  ARC presents its Ed25519-signed checkpoint; the anchor returns an Ed25519-signed receipt.
- **Trusted Receipt Key:** ARC is configured with `audit.anchorReceiptPublicKeyPath`.
- **Receipt Schema (`AnchorReceiptV1`):**
  ```typescript
  export interface AnchorReceiptV1 {
    version: 1;
    receiptId: string;
    checkpointHash: string; // 64 lowercase hex
    anchorTimestamp: string; // ISO-8601 UTC
    anchorKeyFingerprint: string; // 64 lowercase hex
    signature: string; // Base64url Ed25519 signature
  }
  ```
- **Receipt Validation:**
  ```text
  receiptDomain = "CESSPACE-ARC-ANCHOR-RECEIPT-V1\0"
  unsignedReceipt = canonicalJson({ version: 1, receiptId, checkpointHash, anchorTimestamp, anchorKeyFingerprint })
  Ed25519.verify(receiptDomain || UTF8(unsignedReceipt), signature, anchorReceiptPublicKey) === true
  ```
- HTTP 200/201 alone is NOT acknowledgement; only a cryptographically verified receipt acknowledges a checkpoint.
- Verified receipts are appended to `audit-anchors.jsonl` (mode `0600`).

### 14.3 Spooling, Retries & Backpressure

- Checkpoints awaiting receipt are spooled in `audit-anchor-spool.jsonl` (mode `0600`).
- Retry Schedule: Exactly 5 attempts with fixed backoff: `1s, 2s, 4s, 8s, 16s`.
  After 5 failures, the checkpoint remains in the spool to retry on the next recovery cycle.
- **Backpressure Limits:**
  ```text
  MAX_PENDING_ANCHOR_CHECKPOINTS = 100
  MAX_ANCHOR_SPOOL_BYTES = 1 MiB (1,048,576 bytes)
  ```
  If either limit is reached, ARC enters `ANCHOR_SPOOL_FULL` and rejects all subsequent privileged
  MCP tool invocations (reads and mutations) until receipts are obtained.

---

## 15. Threat Boundaries Across Integrity Tiers

| Threat / Attacker Capability                                | Tier 1: Local Hash Chain | Tier 2: Signed Checkpoints    | Tier 3: External Anchoring      |
| :---------------------------------------------------------- | :----------------------- | :---------------------------- | :------------------------------ |
| Accidental bit rot / disk corruption                        | **Detected**             | **Detected**                  | **Detected**                    |
| Unprivileged local user editing audit file                  | **Detected**             | **Detected**                  | **Detected**                    |
| Unauthorized record deletion or insertion                   | **Detected**             | **Detected**                  | **Detected**                    |
| Tail truncation by local attacker who deletes checkpoints   | _Undetected_             | _Undetected_ (if deleted)     | **Detected** (via witness)      |
| Modification of records within a retained signed checkpoint | _Detected_               | **Detected & Non-repudiated** | **Detected**                    |
| Host root rewrites local chain without signing key          | _Bypassed_               | **Detected**                  | **Detected**                    |
| Host compromise with theft of checkpoint signing key        | _Bypassed_               | _Bypassed_ (locally)          | **Detected** (receipt mismatch) |
| Complete destruction of host storage                        | _Lost_                   | _Lost_                        | **Anchor Proof Preserved**      |

---

## 16. Offline Verification Specification

The offline verifier (`arc audit verify`) validates audit logs independently without trusting the
running server and requiring **public verification keys only**:

1. **Required Public Keys:**
   - Checkpoint public key (`audit.publicKeyPath`).
   - Anchor receipt public key (`audit.anchorReceiptPublicKeyPath`).
2. **Verification Pipeline:**
   - Validates JSON syntax and schema V1 structure (`schemaVersion: 1`).
   - Verifies contiguous sequence numbers (`1, 2, 3, ...`) with zero gaps or duplicates.
   - Verifies that `previousRecordHash` links match preceding records.
   - Recomputes canonical hash preimages and verifies `integrity.recordHash`.
   - Validates segment transitions and rotation continuity across uncompressed and `.jsonl.gz` files.
   - Verifies all checkpoint signatures against the checkpoint public key.
   - Verifies the checkpoint hash chain (`previousCheckpointHash`).
   - Validates anchor receipts in `audit-anchors.jsonl` against the anchor public key and checkpoint hashes.
3. **Exit Codes:** Clean exit (0) on full verification; non-zero exit with precise diagnostics on failure.

---

## 17. Local Operator Evidence Interface & Directory Export Contract

### 17.1 Local CLI Commands

1. `arc audit status`: Reports storage path, active segment, total segments, current sequence,
   last checkpoint sequence, unanchored checkpoint count, and health.
2. `arc audit verify [--dir <path>]`: Runs the full offline verification pipeline.
3. `arc audit inspect [--from <seq>] [--to <seq>] [--limit <n>]`: Displays bounded sanitized
   records (maximum `MAX_INSPECT_RECORDS = 100`).
4. `arc audit export --output <dir> [--from <seq>] [--to <seq>]`: Generates a deterministic evidence bundle directory.

### 17.2 Deterministic Directory Export

Node has no built-in tar/zip packager; export is standardized as a **directory bundle**:

```text
<output-dir>/
  manifest.json
  audit/
  checkpoints/
  anchors/
  public-keys/
```

- The destination directory MUST NOT already exist; created exclusively with mode `0700`.
- Destination MUST NOT reside inside the audit store or any agent workspace. Symlinks rejected.
- Maximum export size: **1 GiB** (`MAX_EXPORT_BYTES = 1,073,741,824` bytes).
- `manifest.json`:
  ```json
  {
    "version": 1,
    "sequenceRange": { "start": 1, "end": 5000 },
    "files": {
      "audit/audit-20260920-seq1-seq1000.jsonl.gz": { "sha256": "...", "bytes": 12345 }
    },
    "checkpointHashes": ["..."],
    "anchorReceiptIds": ["..."]
  }
  ```
- Authenticity is derived from the manifest file hashes, included checkpoint signatures, and anchor receipts.
  No private key is required during export.

---

## 18. Absolute Prohibition of Remote Audit Exposure

Remote MCP clients (stdio or mTLS gateway) MUST NOT receive any tools or endpoints to:

- Delete, truncate, or purge audit logs.
- Trigger log rotation manually.
- Alter audit configuration, paths, or thresholds.
- View, export, or search audit logs across sessions.
- Modify or inspect checkpoint signing keys or anchor credentials.

Audit administration is restricted strictly to local operator shell commands.

---

## 19. Central Redaction Authority & Entropy Reconciliation

### 19.1 Authority

All records passing into `AuditLogger.log()` are sanitized centrally before hash computation or disk append.
No caller or subsystem can bypass redaction.

### 19.2 Historical Entropy Scanning Reconciliation

- **Reconciliation:** ADR-0004 and `audit-model.md §3.2` suggested "Entropy Analysis".
- **Normative Policy:** Entropy analysis is **explicitly rejected** due to high false-positive rates on
  hashes, SPKI pins, and base64 tokens. Redaction normatively enforces:
  1. Structural allowlist projection.
  2. Case-insensitive key-name filtering (`SENSITIVE_KEY_PATTERNS`).
  3. High-confidence regex token scanners (`SENSITIVE_VALUE_REGEXES`).
  4. Absolute host path redaction (`redactAbsolutePaths`).
  5. Parameter omissions (`content`, `patch`, `env`, `stdout`, `stderr`).

---

## 20. Hashing Invariants & Secret Oracle Prevention

1. **No Raw Secret Hashing:** Raw credentials, session tokens, and enrollment secrets are NEVER hashed
   to produce audit identifiers or payload hashes. Hashing raw secrets creates an offline dictionary oracle.
2. **Payload Hash Derivation:** `payloadHash` is computed strictly over the **sanitized/redacted**
   parameter representation (`parametersRedacted`), ensuring reproducible non-repudiation without secret exposure.

---

## 21. Timestamp Semantics & Monotonic Ordering

1. **Monotonic Source:** Monotonic sequence numbers (`sequenceNumber`) are the sole authoritative
   ordering mechanism for the hash chain.
2. **Timestamp Role:** The ISO 8601 UTC timestamp is operational metadata, not a cryptographic ordering source.
3. **Clock Skew Resistance:** A wall-clock rollback or forward jump cannot:
   - Reorder records in the chain.
   - Reset the sequence number.
   - Bypass rotation or retention thresholds.
   - Invalidate previously signed checkpoints.

---

## 22. Startup Full-History Verification & Health Reporting

### 22.1 Full-History Verification on Startup

Before stdio or remote MCP tool service begins, startup MUST verify the complete retained history:

- Every retained compressed archive (`.jsonl.gz`).
- Every retained uncompressed segment (`.jsonl`).
- Sequence continuity from sequence 1 through the active segment.
- Cryptographic hash continuity (`previousRecordHash`).
- Checkpoint artifact chain and signatures in `audit-checkpoints.jsonl`.
- Anchor receipt signatures in `audit-anchors.jsonl`.
- Anchor spool integrity in `audit-anchor-spool.jsonl`.
- Final recoverable torn-tail handling in the active segment.

Any missing or corrupted historical segment fails startup closed.

### 22.2 Health Reporting

Safe health metadata exposes:

```typescript
{
  persistence: 'ACTIVE' | 'DEGRADED' | 'FAILED',
  integrity: 'VERIFIED' | 'FAILED',
  sequence: number,
  lastCheckpointSequence: number | null,
  unanchoredCheckpoints: number,
  anchorState: 'HEALTHY' | 'DEGRADED' | 'FULL'
}
```

Exposing filesystem paths, private keys, public key bodies, or anchor endpoints in health status is strictly forbidden.

---

## 23. Process Restart & Recovery Semantics

| State Component           | Durability across Restart | Post-Restart Behavior                                   |
| :------------------------ | :------------------------ | :------------------------------------------------------ |
| Record Chain & Sequence   | **Persistent**            | Resumes from `lastRecord.sequenceNumber + 1`            |
| `previousRecordHash`      | **Persistent**            | Initialized to `lastRecord.integrity.recordHash`        |
| Checkpoint History        | **Persistent**            | Loaded and bound to `previousCheckpointHash`            |
| Anchor Receipts           | **Persistent**            | Loaded from `audit-anchors.jsonl`                       |
| Unanchored Checkpoint Q   | **Persistent**            | Loaded from `audit-anchor-spool.jsonl`; resumes retries |
| Active Single-Writer Lock | **Volatile**              | Re-acquired exclusively on startup (`O_CREAT            | O_EXCL`) |
| In-Flight Append State    | **Volatile**              | Cleared; re-entrant state initialized fresh             |

---

## 24. Fixed System Constants & Minimal Configuration Model

### 24.1 Fixed Architectural Constants

The following security-critical parameters are fixed constants and cannot be overridden by configuration:

```text
MAX_RECORD_BYTES = 65,536 (64 KiB)
SEGMENT_SIZE_THRESHOLD = 10,485,760 (10 MiB)
ROTATION_INTERVAL = 86,400 (24 hours) operational convenience
MAX_ARCHIVE_SEGMENTS = 100
TOTAL_AUDIT_BUDGET_BYTES = 1,073,741,824 (1 GiB)
CHECKPOINT_INTERVAL = 1,000 primary audit records
MAX_PENDING_ANCHOR_CHECKPOINTS = 100
MAX_ANCHOR_SPOOL_BYTES = 1,048,576 (1 MiB)
MAX_ANCHOR_RECEIPT_BYTES = 2,048 (2 KiB)
MAX_TORN_TAIL_BYTES = 65,536 (64 KiB)
MAX_INSPECT_RECORDS = 100
MAX_EXPORT_BYTES = 1,073,741,824 (1 GiB)
MAX_SIGNING_KEY_BYTES = 4,096 (4 KiB)
RECENT_RECORDS_CACHE_LIMIT = 256 records
```

### 24.2 Minimal Production Configuration

```typescript
export interface AuditConfig {
  /** Storage directory path. Default: '~/.cesspace-arc/audit/'. */
  directory?: string;
  /** Path to Ed25519 private key PEM file for Tier 2 signing. Mandatory. */
  signingKeyPath: string;
  /** Path to Ed25519 public key PEM file for checkpoint verification. Mandatory. */
  publicKeyPath: string;
  /** External Tier 3 anchor HTTPS endpoint. Optional. */
  anchorEndpoint?: string;
  /** Path to Ed25519 public key PEM file for anchor receipt verification. Optional. */
  anchorReceiptPublicKeyPath?: string;
}
```

_Note: Auditing cannot be disabled in production; there is no `enabled: boolean` option._

---

## 25. Bounded Memory Architecture

Production audit logging holds a bounded memory footprint:

- The persistent logger holds only the current sequence number, current `recordHash`, and a ring cache
  of the most recent **256 records** (`RECENT_RECORDS_CACHE_LIMIT = 256`).
- Full-history inspection, verification, rotation compression, and evidence export stream from disk.
- At no point is the 1 GiB history loaded into memory.

---

## 26. Failure Modes & Sanitized Error Model

1. **Storage Unwritable / Full:** Operations aborted; surfaces `AUDIT_PERSISTENCE_FAILED` to remote clients.
2. **Integrity Corruption:** Startup halts immediately; surfaces `AUDIT_CORRUPTION_DETECTED` in local console.
3. **Lock Conflict:** Exits immediately with `AUDIT_STORE_LOCKED`.
4. **Anchor Spool Exhaustion:** Server enters `ANCHOR_SPOOL_FULL`; rejects all privileged tool executions.

---

## 27. Supply Chain & Zero-Dependency Policy

Implemented **strictly using Node.js 24 built-in modules**:

- `node:fs` and `node:fs/promises`: File descriptor I/O, permissions, and atomic creation (`O_CREAT | O_EXCL`).
- `node:crypto`: SHA-256 hashing, Ed25519 digital signing, and signature verification.
- `node:zlib`: Streaming `gzip` compression and decompression.
- `node:https`: TLS 1.3 HTTPS client for external anchoring.
- `node:stream`: Streaming file I/O.

No third-party packages for locking, compression, tar/zip packaging, or crypto are introduced.

---

## 28. Versioning & Health Metadata

- Proposed public version: **`0.6.0-rc06`**.
- Proposed health stage: **`RC-06`**.
- _Task 0 performs no version bump._ Version is updated in Task 8 after all acceptance gates pass.

---

## 29. Out-of-Scope Catalog

The following items are explicitly deferred beyond RC-06:

1. Proprietary cloud SIEM integrations (Splunk, Datadog, AWS CloudWatch, GCP Cloud Logging).
2. Public blockchain or cryptocurrency ledger anchoring.
3. Multi-host distributed Raft/Paxos audit replication.
4. Browser-based GUI dashboard for audit inspection.
5. Hardware Security Module (HSM) or PKCS#11 hardware key integration.
6. Remote MCP audit log management endpoints.
7. User/role permission management for audit access beyond OS user boundaries.
8. Automatic audit segment deletion / pruning.
9. Automatic or live checkpoint signing-key rotation.
10. RC-07 composite engineering tools.
11. RC-08 adversarial fuzzing and penetration testing.

---

## 30. Negative Security Control Catalog (RC06-NEG-01..96)

All 96 controls are contiguous, mandatory, and directly testable:

### Category 1: Filesystem Authority & Locking (RC06-NEG-01..13)

- **`RC06-NEG-01`**: Audit directory is a symlink. Startup rejected; throws `INVALID_AUDIT_PATH`.
- **`RC06-NEG-02`**: Active audit segment file is a symlink. Write rejected; throws `SYMLINK_DETECTED`.
- **`RC06-NEG-03`**: Audit directory permissions wider than `0700` (e.g. `0755`). Startup rejected.
- **`RC06-NEG-04`**: Audit segment file permissions wider than `0600` (e.g. `0644`). Startup rejected.
- **`RC06-NEG-05`**: Audit directory owned by different UID. Startup rejected with `OWNERSHIP_MISMATCH`.
- **`RC06-NEG-06`**: Audit segment owned by different UID. Write rejected with `OWNERSHIP_MISMATCH`.
- **`RC06-NEG-07`**: Target audit path is a non-regular file (FIFO, device). Write rejected.
- **`RC06-NEG-08`**: Target audit path attempts directory traversal (`../`). Path rejected.
- **`RC06-NEG-09`**: Active audit segment file has hard-link count > 1 (`nlink != 1`). Write rejected.
- **`RC06-NEG-10`**: `O_NOFOLLOW` / `fstat` descriptor check detects symlink substitution during open. Rejected.
- **`RC06-NEG-11`**: Second ARC process attempts lock on existing `audit.lock` (`O_CREAT|O_EXCL` fails with `EEXIST`). Startup halts with `AUDIT_STORE_LOCKED`.
- **`RC06-NEG-12`**: Stale lock takeover attempted without operator intervention. Automatic takeover rejected.
- **`RC06-NEG-13`**: Audit lock file is a symlink or hard link. Startup fails immediately.

### Category 2: Record Format & Schema V1 Validation (RC06-NEG-14..22)

- **`RC06-NEG-14`**: Record line missing terminating newline character (`\n`). Line rejected as malformed.
- **`RC06-NEG-15`**: Record line containing carriage return character (`\r`). Line rejected as malformed.
- **`RC06-NEG-16`**: Record containing raw `undefined` or `NaN`/`Infinity` values. Canonicalization fails.
- **`RC06-NEG-17`**: Record containing unescaped control characters (< `0x20` or NUL). Line rejected.
- **`RC06-NEG-18`**: Record with unsupported `schemaVersion` (e.g. `2` or `0`). Verifier rejects with `UNSUPPORTED_SCHEMA_VERSION`.
- **`RC06-NEG-19`**: Record missing mandatory top-level `schemaVersion: 1` field. Verification fails.
- **`RC06-NEG-20`**: Record containing unknown top-level field outside V1 schema. Verification fails.
- **`RC06-NEG-21`**: Single record exceeding `MAX_RECORD_BYTES` (64 KiB). Append rejected with `RECORD_TOO_LARGE`.
- **`RC06-NEG-22`**: Direct hash of stored line bytes asserted as `recordHash`. Rejected; verifier enforces hash preimage omission of `integrity.recordHash`.

### Category 3: Chain Continuity & Record Tampering (RC06-NEG-23..32)

- **`RC06-NEG-23`**: Sequence number gap introduced in persistent record stream. Verification fails.
- **`RC06-NEG-24`**: Duplicate sequence number in persistent record stream. Verification fails.
- **`RC06-NEG-25`**: Broken `previousRecordHash` link between adjacent records. Verification fails.
- **`RC06-NEG-26`**: Tampered record payload with original `recordHash`. Recomputation flags mismatch.
- **`RC06-NEG-27`**: Tampered `recordHash` with original payload. Verification flags mismatch.
- **`RC06-NEG-28`**: Middle record deletion from audit segment. Chain link break detected.
- **`RC06-NEG-29`**: Tail record truncation detectable relative to trusted signed checkpoint. Truncation detected.
- **`RC06-NEG-30`**: Torn final record line from crash. Recovers cleanly via sidecar; historical chain preserved.
- **`RC06-NEG-31`**: Torn final record line accompanied by corrupted historical records. Startup fails closed.
- **`RC06-NEG-32`**: Attempted sequence number reset to 1 on restart with non-empty store. Rejected.

### Category 4: Universal Lifecycle & Execution Ordering (RC06-NEG-33..38)

- **`RC06-NEG-33`**: `STARTED` audit append failure before privileged read operation. Read aborted; zero execution.
- **`RC06-NEG-34`**: `STARTED` audit append failure before privileged mutation operation. Mutation aborted; zero side effects.
- **`RC06-NEG-35`**: `COMPLETED` audit append failure after privileged read. Gateway enters global `DEGRADED_AUDIT_FAILURE`.
- **`RC06-NEG-36`**: `COMPLETED` audit append failure after irreversible mutation. Gateway enters global `DEGRADED_AUDIT_FAILURE`.
- **`RC06-NEG-37`**: Subsequent privileged read attempt while in `DEGRADED_AUDIT_FAILURE`. Rejected immediately.
- **`RC06-NEG-38`**: Subsequent privileged mutation attempt while in `DEGRADED_AUDIT_FAILURE`. Rejected immediately.

### Category 5: Rotation, Compression & Full-History Startup (RC06-NEG-39..50)

- **`RC06-NEG-39`**: Rotation boundary sequence discontinuity between segments. Verifier flags sequence gap.
- **`RC06-NEG-40`**: Rotation boundary `previousRecordHash` mismatch between segments. Verifier flags chain break.
- **`RC06-NEG-41`**: Corrupted gzip archive in rotated segment detected during startup. Startup fails closed.
- **`RC06-NEG-42`**: Missing intermediate rotated segment in archive sequence detected during startup. Startup fails closed.
- **`RC06-NEG-43`**: Premature uncompressed segment deletion before gzip integrity verification. Deletion prohibited.
- **`RC06-NEG-44`**: Rapid rotation causing filename timestamp collision. Sequence range suffix prevents overwrite.
- **`RC06-NEG-45`**: Rotated segment file permissions wider than `0600`. Verification flags insecure permissions.
- **`RC06-NEG-46`**: Compressed archive permissions wider than `0600`. Verification flags insecure permissions.
- **`RC06-NEG-47`**: Compressed archive hard-link count > 1 (`nlink != 1`). Archive loading rejected.
- **`RC06-NEG-48`**: Wall-clock rollback attempt to delay 24h rotation. Defeated by 10 MiB hard limit.
- **`RC06-NEG-49`**: Wall-clock forward jump attempt to bypass retention. Defeated by non-deletion policy.
- **`RC06-NEG-50`**: Startup against non-empty store with corrupted intermediate segment. Fails closed.

### Category 6: Storage Bounds & Non-Deletion Retention (RC06-NEG-51..54)

- **`RC06-NEG-51`**: Disk full (`ENOSPC`) during audit append. Append throws; state remains consistent.
- **`RC06-NEG-52`**: Short write during audit append. Partial write detected; rolls back or fails closed.
- **`RC06-NEG-53`**: Archived segment count reaches `MAX_ARCHIVE_SEGMENTS` (100). Halts privileged ops; zero auto-deletion.
- **`RC06-NEG-54`**: Cumulative storage budget reaches `TOTAL_AUDIT_BUDGET_BYTES` (1 GiB). Halts privileged ops; zero auto-deletion.

### Category 7: Tier 2 Signed Checkpoint Artifacts (RC06-NEG-55..64)

- **`RC06-NEG-55`**: Checkpoint artifact assigned audit `sequenceNumber`. Rejected; checkpoints are separate artifacts.
- **`RC06-NEG-56`**: Checkpoint sequence range mismatch with covered primary audit records. Verification fails.
- **`RC06-NEG-57`**: Checkpoint `terminalRecordHash` mismatch with actual terminal record. Verification fails.
- **`RC06-NEG-58`**: Checkpoint `previousCheckpointHash` chain link break. Verifier flags broken checkpoint chain.
- **`RC06-NEG-59`**: Tampered checkpoint signature bytes. Signature verification fails.
- **`RC06-NEG-60`**: Checkpoint verified with wrong Ed25519 public key. Signature verification fails.
- **`RC06-NEG-61`**: Checkpoint signature algorithm downgrade attempt (e.g. RSA, none). Rejected.
- **`RC06-NEG-62`**: Replayed checkpoint from prior sequence range. Sequence validation fails.
- **`RC06-NEG-63`**: Out-of-order checkpoint artifact in `audit-checkpoints.jsonl`. Sequence continuity check fails.
- **`RC06-NEG-64`**: Checkpoint artifact file permissions wider than `0600` or hard-linked. Loading rejected.

### Category 8: Checkpoint Signing Key Authority (RC06-NEG-65..73)

- **`RC06-NEG-65`**: Signing key provided via command-line argument (`argv`). Startup fails immediately.
- **`RC06-NEG-66`**: Signing key provided via ambient environment variable. Startup fails immediately.
- **`RC06-NEG-67`**: Signing key supplied via remote MCP header or tool argument. Rejected.
- **`RC06-NEG-68`**: Checkpoint signing key file is a symlink. Key loading rejected.
- **`RC06-NEG-69`**: Checkpoint signing key file has hard-link count > 1 (`nlink != 1`). Key loading rejected.
- **`RC06-NEG-70`**: Checkpoint signing key file permissions wider than `0600`. Key loading rejected.
- **`RC06-NEG-71`**: Checkpoint signing key file owned by different UID. Key loading rejected.
- **`RC06-NEG-72`**: Checkpoint signing key exceeds `MAX_SIGNING_KEY_BYTES` (4 KiB). Key loading rejected.
- **`RC06-NEG-73`**: Different signing key loaded on non-empty store with pinned fingerprint. Fails closed.

### Category 9: Tier 3 External Anchoring & Cryptographic Receipts (RC06-NEG-74..82)

- **`RC06-NEG-74`**: External anchor connection attempt over plaintext HTTP. Rejected; HTTPS required.
- **`RC06-NEG-75`**: External anchor HTTPS connection timeout. Checkpoint spooled; backoff retry initiated.
- **`RC06-NEG-76`**: External anchor returns HTTP 5xx error. Checkpoint spooled; backoff retry initiated.
- **`RC06-NEG-77`**: HTTP 200 returned without cryptographic receipt. Not accepted as acknowledgement.
- **`RC06-NEG-78`**: Anchor receipt signed by untrusted key not matching `anchorReceiptPublicKeyPath`. Rejected.
- **`RC06-NEG-79`**: Anchor receipt bound to wrong `checkpointHash`. Receipt rejected.
- **`RC06-NEG-80`**: Duplicate/conflicting receipt for already acknowledged checkpoint. Receipt rejected.
- **`RC06-NEG-81`**: Anchor spool queue exceeds `MAX_PENDING_ANCHOR_CHECKPOINTS` (100). Halts privileged ops.
- **`RC06-NEG-82`**: Anchor spool size exceeds `MAX_ANCHOR_SPOOL_BYTES` (1 MiB). Halts privileged ops.

### Category 10: Anchor Spool Integrity & Redaction Secrecy (RC06-NEG-83..92)

- **`RC06-NEG-83`**: Anchor spool file is a symlink or hard-linked. Spool loading rejected.
- **`RC06-NEG-84`**: Tampered persistent anchor spool entry detected during startup. Fails closed without drop.
- **`RC06-NEG-85`**: Raw `Arc-Session-Token` secret in persistent JSONL. Centrally redacted to `[REDACTED_SECRET]`.
- **`RC06-NEG-86`**: Raw enrollment one-time secret in persistent JSONL. Centrally redacted.
- **`RC06-NEG-87`**: Raw HTTP `Authorization` header in persistent JSONL. Centrally redacted.
- **`RC06-NEG-88`**: Raw PKCS#8 private key block in persistent JSONL. Centrally redacted.
- **`RC06-NEG-89`**: Raw X.509 certificate PEM block in persistent JSONL. Centrally redacted.
- **`RC06-NEG-90`**: Raw tool `content` parameter in persistent JSONL. Omitted; byte length recorded.
- **`RC06-NEG-91`**: Raw tool `patch` parameter in persistent JSONL. Omitted; byte length recorded.
- **`RC06-NEG-92`**: Raw process `stdout`/`stderr` in persistent JSONL. Omitted; byte counts recorded.

### Category 11: Administrative Isolation & Export Integrity (RC06-NEG-93..96)

- **`RC06-NEG-93`**: Remote MCP tool call attempting audit log deletion or truncation. Rejected with `UNKNOWN_TOOL`.
- **`RC06-NEG-94`**: Remote MCP tool call attempting manual log rotation. Rejected with `UNKNOWN_TOOL`.
- **`RC06-NEG-95`**: Evidence export destination directory already exists. Rejected; no overwrite permitted.
- **`RC06-NEG-96`**: Evidence export exceeding `MAX_EXPORT_BYTES` (1 GiB). Rejected; export halted.

---

## 31. Threat-to-Control Matrix

| Threat Description                              | Primary Defense Mechanism                          | Enforcement Tier | Negative Controls |
| :---------------------------------------------- | :------------------------------------------------- | :--------------- | :---------------- |
| Host user edits historical JSONL records        | SHA-256 hash chaining + Ed25519 signatures         | Tier 1 & 2       | NEG-25..28        |
| Tail truncation to conceal malicious tool run   | Tier 2 signed checkpoints & Tier 3 anchor receipts | Tier 2 & 3       | NEG-29, 57        |
| Secret extraction from audit trail              | Centralized pre-hash redaction & minimization      | Tier 1           | NEG-85..92        |
| Disk exhaustion denial-of-service via log flood | Segment size caps, rotation & bounded budgets      | Tier 1           | NEG-21, 53, 54    |
| Side-effect execution without audit record      | Pre-dispatch sync & fail-closed execution order    | Tier 1           | NEG-33..38        |
| Concurrent process audit log corruption         | Exclusive single-writer lockfile (`O_CREAT         | EXCL`)           | Tier 1            | NEG-11, 12, 13 |
| Host root rewrites local chain & checkpoints    | Tier 3 external anchor cryptographic receipts      | Tier 3           | NEG-74..80        |
| Remote MCP agent tampers with audit subsystem   | Strict local operator isolation & no MCP tools     | Architecture     | NEG-93, 94        |
| Signing key exfiltration from environment       | Restricted 0600 file / FD-only key loading         | Tier 2           | NEG-65..72        |

---

## 32. Positive Acceptance Flows (Flows 1..20)

1. **Flow 1: Fresh Persistent Store Initialization:** Server boots with clean audit directory; creates `audit.lock` and active segment; logs first record (`seq: 1`, `prevHash: 000...000` virtual genesis hash); file permissions verified `0600`.
2. **Flow 2: Standard Stdio Read-Only Tool Execution:** Client calls `read_file`; emits durable `STARTED`, executes read, emits durable `COMPLETED`; both records bound by `operationId`.
3. **Flow 3: Standard Stdio Mutation Tool Execution:** Client calls `create_file`; emits durable `STARTED`, executes mutation, emits durable `COMPLETED`.
4. **Flow 4: Remote Authenticated Gateway Tool Execution:** Remote client executes tool; actor metadata (deviceId, spkiPin, mcpSessionId) recorded in unified chain; zero secrets leaked.
5. **Flow 5: Policy Denial Audit Logging:** Unauthorized tool call rejected by policy; single durable `DENIED` record flushed before returning error.
6. **Flow 6: Operator Approval Lifecycle Persistence:** Operator approves tool via admin IPC; transitions (`REQUESTED`, `APPROVED`, `REDEEMED`) logged in contiguous sequence.
7. **Flow 7: Gateway Admission & Lifecycle Auditing:** Gateway boots, admits mTLS client, issues session token, enforces rate limits; all 14 gateway event types logged in single chain.
8. **Flow 8: Clean Process Termination:** Server receives `SIGTERM`; flushes buffers; releases `audit.lock` cleanly.
9. **Flow 9: Gateway Restart & Hash Continuity:** Server restarts against non-empty store; reads terminal record; next record increments sequence and links `previousRecordHash`.
10. **Flow 10: Size-Based Rotation Trigger:** Active segment reaches 10 MiB; rotates to timestamped `.jsonl`; new segment begins with sequence continuity.
11. **Flow 11: Time-Based Operational Rotation Trigger:** Clock passes 24 hours; segment rotates cleanly.
12. **Flow 12: Compressed Archive Generation & Verified Deletion:** Rotated segment compressed to `.jsonl.gz`; uncompressed file verified before removal; permissions verified `0600`.
13. **Flow 13: Tier 2 Checkpoint Artifact Generation:** Chain reaches 1,000 records; generates signed checkpoint in `audit-checkpoints.jsonl`; verifies Ed25519 signature.
14. **Flow 14: Offline Public-Key Checkpoint Verification:** Standalone verifier validates checkpoint signature using public key without accessing private key.
15. **Flow 15: Tier 3 External Anchor Dispatch & Cryptographic Receipt:** Checkpoint transmitted via HTTPS to anchor service; valid signed receipt received and recorded in `audit-anchors.jsonl`.
16. **Flow 16: Anchor Outage Spooling & Automatic Backoff Catch-Up:** Anchor server temporarily down; checkpoints queued in `audit-anchor-spool.jsonl`; server recovers and catches up.
17. **Flow 17: Local Operator `arc audit status`:** Operator executes CLI status command; receives accurate summary of store health and sequence count.
18. **Flow 18: Local Operator `arc audit inspect`:** Operator pages through recent records; receives redacted records within bounded limit.
19. **Flow 19: Universal Pre-Dispatch Durability:** Privileged read and privileged mutation each demonstrate durable `STARTED` -> subsystem dispatch -> durable `COMPLETED`, bound by `operationId`.
20. **Flow 20: Full Restart Verification of Retained History:** Server restarts with compressed archives, active segment, checkpoints, and receipts; verifies full retained history before serving.

---

## 33. Historical Documentation Reconciliation

| Historical Document & Section           | Stale / Ambiguous Claim                            | RC-06 Normative Specification                                                                  |
| :-------------------------------------- | :------------------------------------------------- | :--------------------------------------------------------------------------------------------- |
| `audit-model.md §5`                     | Ambient default path `~/.cesspace-arc/audit/`      | Configured via `audit.directory` with strict `0700` permissions, UID check, symlink rejection. |
| `audit-model.md §5`                     | 50 MB segment rotation threshold                   | Reduced to **10 MiB** to optimize in-memory verification and streaming hash performance.       |
| `audit-model.md §4.2` & `ADR-0004 §2.3` | Tier 2: "Signed HMAC / Private Key"                | Resolved normatively to **asymmetric digital signatures (Ed25519 / RFC 8032)**.                |
| `audit-model.md §4.2`                   | "Supervisor daemon signs checkpoints"              | Integrated in-process cryptographic engine signing via secure 0600 key file or inherited FD.   |
| `audit-model.md §3.2` & `ADR-0004 §2.2` | "Entropy Analysis" for credential detection        | **Explicitly rejected** due to false positives; replaced with allowlist, key-names, & regex.   |
| `audit-model.md §2`                     | `sequenceNumber` described as "per session"        | Unified into **one process-wide monotonic sequence space** across all sessions and gateway.    |
| `audit-model.md §2`                     | Audit schema lacks approval & gateway metadata     | Formally incorporated `AuditApprovalMetadata` and `AuditGatewayMetadata` from RC-04 & RC-05.   |
| `package-ownership.md`                  | "Evidence packager" assigned to `packages/audit`   | Assigned to `packages/audit` engine with CLI exposure in `apps/cli` (`arc audit export`).      |
| `rc05-scope-acceptance.md §16`          | Persistent storage and external anchoring deferred | Fully implemented and closed by RC-06.                                                         |
| Prior Scope Draft                       | Self-referential full-line record hash             | Resolved to explicit hash preimage omitting `integrity.recordHash`.                            |
| Prior Scope Draft                       | Synthetic "genesis record" terminology             | Corrected to virtual zero genesis previous hash.                                               |
| Prior Scope Draft                       | Automatic retention deletion on anchor             | Removed; capacity limits are fail-closed; no auto-deletion of raw evidence in RC-06.           |
| Prior Scope Draft                       | Tar/ZIP evidence export                            | Resolved to deterministic directory bundle export (no external compression libraries).         |
| Prior Scope Draft                       | `fcntl/flock` portable locking                     | Resolved to atomic `O_CREAT                                                                    | O_EXCL` lockfile creation. |
| Prior Scope Draft                       | Bearer token anchor authentication                 | Removed; sender/receiver Ed25519 cryptographic signatures provide mutual authenticity.         |

---

## 34. Implementation Breakdown (Tasks 1..8)

| #   | Title                                               | Scope                                                            | Expected Files                                                                                                                | Invariants & Quality Standards                  | Controls         | Depends On | Stop Boundary                     |
| :-- | :-------------------------------------------------- | :--------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------- | :---------------------------------------------- | :--------------- | :--------- | :-------------------------------- |
| 1   | Persistent Append Storage, Protocol & Lockfile      | Protocol schema V1, disk append engine, 0700/0600, lockfile      | `packages/protocol/src/audit.ts`, `packages/audit/src/storage.ts`, `packages/audit/src/lock.ts`, `tests/rc06-storage.test.js` | Inv-13, O_CREAT\|EXCL, hash preimage rules      | NEG-01..22       | None       | Storage tests pass cleanly        |
| 2   | Restart Recovery, Torn Tails & Chain Continuity     | Virtual genesis, restart continuation, torn-tail recovery        | `packages/audit/src/recovery.ts`, `tests/rc06-recovery.test.js`                                                               | Strict continuity, no sequence reset            | NEG-23..32       | Task 1     | Recovery tests pass cleanly       |
| 3   | Segment Rotation, Compression & Storage Caps        | 10 MiB / 24h rotation, `.jsonl.gz`, fail-closed retention budget | `packages/audit/src/rotation.ts`, `tests/rc06-rotation.test.js`                                                               | Safe uncompressed delete, no auto-delete        | NEG-39..54       | Task 2     | Rotation tests pass cleanly       |
| 4   | Tier 2 Ed25519 Checkpoint Artifacts & Key Security  | Ed25519 signing engine, key security, checkpoint artifact file   | `packages/audit/src/checkpoint.ts`, `tests/rc06-checkpoint.test.js`                                                           | RFC 8032, no key in argv/env, public key verify | NEG-55..73       | Task 3     | Checkpoint tests pass cleanly     |
| 5   | Tier 3 External Anchoring Client, Spool & Receipts  | HTTPS anchor client, spool queue, retry backoff, signed receipts | `packages/audit/src/anchor.ts`, `tests/rc06-anchor.test.js`                                                                   | Bounded spool, backpressure, no bearer tokens   | NEG-74..84       | Task 4     | Anchor tests pass cleanly         |
| 6   | Universal Lifecycle & Full-History Startup Engine   | Wire `ArcMcpServer`, `STARTED`/`COMPLETED` sync, full verify     | `apps/mcp-server/src/index.ts`, `tests/rc06-runtime-durability.test.js`                                                       | INV-13, fail-closed on read/mutation failures   | NEG-33..38       | Task 5     | Runtime tests pass cleanly        |
| 7   | Local Operator CLI & Standalone Offline Verifier    | `arc audit status/verify/inspect/export` & directory bundle pack | `apps/cli/src/audit.ts`, `packages/audit/src/verify.ts`, `tests/rc06-cli-verifier.test.js`                                    | Public key only verifier, directory export      | NEG-93..96       | Task 6     | CLI & verifier tests pass cleanly |
| 8   | Secrecy Hardening, Acceptance & Public Version Bump | Central redaction tests, 96 negative controls, 20 flows, bump    | `tests/rc06-negative-controls.test.js`, `tests/rc06-positive-flows.test.js`, `verify-rc06`                                    | Version 0.6.0-rc06, all 96 controls pass        | NEG-85..92 (All) | Task 7     | All 20 quality gates pass         |

---

## 35. Definition of Done (RC-06)

RC-06 is complete and ready for merge when:

1. **Persistent Single-Chain Storage:** All audit records are written to canonical JSONL files with sequential SHA-256 hash chaining under schema V1.
2. **Universal Lifecycle Durability:** Pre-dispatch audit syncing (`STARTED` phase) satisfies INV-13 for all reads and mutations; torn crash tails are safely recovered without history corruption.
3. **Filesystem Security & Exclusivity:** Auditing operates strictly within owner-only (`0700`/`0600`) directories protected by exclusive `O_CREAT | O_EXCL` writer locks.
4. **Rotation & Compression:** Active segments rotate deterministically at 10 MiB or 24h and compress to `.jsonl.gz` after verified decompression.
5. **Storage Budget Bounds:** Retention limits prevent log-saturation DoS with zero automatic deletion of raw evidence.
6. **Tier 2 Signed Checkpoints:** Checkpoint artifacts signed with Ed25519 are recorded in `audit-checkpoints.jsonl` every 1,000 records or upon segment rotation.
7. **Tier 3 External Anchoring:** Signed checkpoints are dispatched over HTTPS to independent anchors with bounded spooling, backpressure, and verified cryptographic receipts.
8. **Full-History Startup Verification:** Startup verifies all retained archives, uncompressed segments, and cryptographic links before serving MCP tools.
9. **Bounded Production Memory:** Production logger holds bounded cursor and 256-record ring cache; all heavy operations stream from disk.
10. **Offline Verifier:** Standalone CLI tool validates full history and checkpoint signatures using public keys only.
11. **Local Operator Interface:** `arc audit status`, `verify`, `inspect`, and directory-bundle `export` operate locally without exposing remote MCP endpoints.
12. **Universal Redaction:** Central pre-hash redaction guarantees that secrets, tokens, keys, and absolute paths never reach persistent logs.
13. **Negative Controls:** All 96 frozen negative controls (`RC06-NEG-01..96`) are implemented, contiguous, and passing.
14. **Positive Flows:** All 20 integration flows are implemented and verified.
15. **Verification Script:** `scripts/verify-rc06.sh` executes all quality gates cleanly.
16. **CI Passes:** Monorepo tests, lint, formatting, typecheck, doc links, secret scanning, and dependency audit pass with zero failures.
17. **Public Version:** Version bumped to `0.6.0-rc06` and health stage reports `RC-06`.

---

## 36. Open Questions

**Open Questions: None**

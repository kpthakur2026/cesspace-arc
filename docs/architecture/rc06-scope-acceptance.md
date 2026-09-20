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
specific rule is cataloged in §32 (Historical Documentation Reconciliation) with
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
- Record hashing computes `computeSha256(canonicalJson(recordToHash))` where
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

## 4. Persistent Record Format & JSONL Specification

Persistent audit records are stored in JSON Lines (`.jsonl`) format under strict formatting rules:

1. **Line Framing:** Exactly one complete audit record per line, encoded as valid UTF-8.
2. **Newline Termination:** Every line ends with a single UNIX newline character (`\n`, `0x0A`).
   Carriage returns (`\r`, `0x0D`) are strictly prohibited and cause verification failure.
3. **Maximum Serialized Record Size:** A single serialized JSON record line MUST NOT exceed
   **64 KiB** (`65,536` bytes, including the terminating newline). Any attempted record exceeding
   this bound is refused prior to write, logging a sanitized `RECORD_TOO_LARGE` audit error.
4. **Canonical Serialization:** The line content is the exact string generated by `canonicalJson(record)`
   where keys are recursively sorted in lexicographical order, omitting extraneous whitespace.
   This guarantees that raw line hashing directly matches `record.integrity.recordHash`.
5. **No Embedded Unescaped Control Characters:** Literal NUL bytes (`0x00`), unescaped newlines,
   or control characters below `0x20` within JSON string values are strictly prohibited.
6. **Schema Versioning:** Every record implicitly adheres to schema version `1.0`. Any record
   missing mandatory top-level keys (`eventId`, `timestamp`, `sequenceNumber`, `actor`, `target`,
   `invocation`, `policy`, `execution`, `integrity`) is rejected as corrupt.

---

## 5. Chain Continuity & Genesis Semantics

### 5.1 Fresh-Store Genesis

On a completely fresh installation with an empty or non-existent audit store:

- The genesis previous hash is the frozen 64-character zero hex digest:
  `0000000000000000000000000000000000000000000000000000000000000000`.
- The first record emitted MUST have `sequenceNumber: 1` and `integrity.previousRecordHash`
  equal to the zero genesis digest.

### 5.2 Restart Continuity

When ARC starts against an existing, non-empty audit store:

1. The engine scans the persistent audit directory, verifies single-writer lock exclusivity,
   and identifies the active segment file.
2. The engine reads the terminal record of the active segment.
3. The next record emitted MUST have:
   - `sequenceNumber = terminalRecord.sequenceNumber + 1`
   - `integrity.previousRecordHash = terminalRecord.integrity.recordHash`
4. Starting a new chain with `sequenceNumber: 1` or zero previous hash while prior persistent
   records exist is **strictly prohibited** and causes immediate fatal startup failure.

### 5.3 Prohibition of `clear()` in Production

The `clear()` method on `AuditLogger` is designated strictly for ephemeral in-memory unit tests.
In persistent production mode, invoking `clear()` throws an uncatchable fatal error.
Audit history can never be wiped or truncated via application APIs.

---

## 6. Crash Consistency, Write Ordering & Durability

### 6.1 Durability Primitives

- Every persistent write is executed via synchronous or explicitly synced filesystem APIs.
- The file descriptor for the active segment is opened with `O_APPEND | O_CREAT | O_WRONLY`.
- After appending a record line, the engine issues `fdatasync()` (or `fsync()`) to force disk
  flushing before acknowledging operation completion.
- When creating a new segment or rotating files, the parent directory is also `fsync()`ed to
  guarantee directory entry persistence across power loss.

### 6.2 Pre-Execution Durability (INV-13 Universal Auditability)

To satisfy INV-13 and prevent "ghost side effects":

1. **Denied Requests:** The audit record recording the denial is appended and synced before
   returning the error response to the caller.
2. **Read-Only Invocations:** The audit record is appended upon execution completion.
3. **Privileged Mutations & Process Executions:**
   - Before any irreversible filesystem modification or terminal process execution begins,
     an `INVOCATION_INITIATED` audit record (or synchronized execution journal) MUST be durably
     synced to disk.
   - If the pre-execution audit write fails (e.g. `ENOSPC`, disk I/O error), **the privileged
     operation MUST NOT be dispatched**. The request is aborted with an audit failure error.
   - Upon execution completion, the outcome record is appended and synced.
4. **Post-Execution Audit Failure:**
   - If an irreversible mutation succeeded but the outcome audit record append fails, the server
     MUST transition immediately to `DEGRADED_AUDIT_FAILURE` status, emit a high-priority local
     diagnostic, and reject all subsequent mutating requests until operator intervention.

### 6.3 Crash Recovery & Torn-Tail Recovery

In the event of an abrupt process crash or power loss during write:

- **Torn Line at EOF:** If the final line in the active segment lacks a terminating `\n` or
  contains invalid JSON, and all preceding records verify cleanly:
  - The engine logs an operator warning identifying a torn crash tail.
  - The torn bytes are safely moved to a sidecar file (`.torn.<timestamp>`).
  - The segment is truncated to the last valid newline.
  - Startup resumes cleanly from the last intact record.
- **Corrupt Historic Record:** If corruption occurs anywhere prior to the final line, or if
  any hash link is broken, recovery is **forbidden**. The engine MUST fail closed and refuse to start.

---

## 7. Mandatory Auditability vs Execution Ordering

The exact state machine for operations under audit persistence:

```text
  [Request Received]
          │
          ▼
  [Policy Evaluation]
          │
    ┌─────┴────────────────────────┐
    ▼                              ▼
 [DENY]                         [ALLOW / APPROVED]
    │                              │
    ▼                              ▼
[Append Denial Record]          [Is Privileged Mutation?]
    │                             ├──► NO  (Read-only) ──► [Execute Tool]
    ▼                             │                             │
 [Return Error]                   └──► YES (Mutation)           ▼
                                       │              [Append Outcome Record]
                                       ▼                        │
                         [Sync Pre-Exec Audit Record]           ▼
                                       │                 [Return Result]
                                       ├──► FAIL ──► [ABORT Side Effect]
                                       │
                                       ▼ SUCCESS
                                 [Execute Tool]
                                       │
                                       ▼
                             [Append Outcome Record]
                                       │
                                       ├──► FAIL ──► [DEGRADED_AUDIT_FAILURE]
                                       │
                                       ▼ SUCCESS
                                 [Return Result]
```

---

## 8. Local Audit Storage Security & Path Authority

Audit records are privileged security artifacts and must be isolated from untrusted actors.

### 8.1 Path Configuration

- Configured via `audit.directory`. Default: `~/.cesspace-arc/audit/`.
- Must be an absolute path or resolvable to absolute path via `fs.realpathSync`.
- **Symlink Prohibition:** The audit directory and all parent components MUST NOT be symbolic links.
- **Workspace Isolation:** The audit directory MUST NOT reside inside, overlap with, or be a
  subdirectory of any configured agent workspace.
- Audit files are never accessible via MCP filesystem tools (`read_file`, `list_directory`, etc.).

### 8.2 Strict Permissions

- **Directory Permissions:** Exactly `0700` (`rwx------`). Group or world permissions (`0077`)
  are strictly forbidden and fail validation.
- **File Permissions:** Active and rotated audit files must have permissions `0600` (`rw-------`).
- **Owner Verification:** The audit directory and files MUST be owned by the running process's
  real UID. Mismatched ownership fails startup immediately.

---

## 9. Single-Writer Process Locking

To prevent sequence corruption, competing rotations, or split-brain chains:

1. **Lock File:** The engine acquires an exclusive lock on `audit.lock` inside the audit directory.
2. **Locking Mechanism:** Uses `fcntl`/`flock` exclusive locking (`LOCK_EX | LOCK_NB`) or atomic
   `O_CREAT | O_EXCL` file creation with verified process PID and heartbeat timestamp.
3. **Symlink Rejection:** The lock file MUST NOT be a symbolic link.
4. **Collision Behavior:** If another ARC instance holds the lock, the new process MUST fail startup
   immediately with `AUDIT_STORE_LOCKED`. It MUST NOT attempt aggressive takeover or stale lock
   deletion without explicit operator intervention.
5. **Clean Release:** The lock file is released and removed upon clean process shutdown.

---

## 10. Segment Rotation & Compression Contract

### 10.1 Rotation Triggers

An active audit segment is rotated when EITHER condition is met:

1. **Size Threshold:** The active segment file reaches or exceeds **10 MiB** (`10,485,760` bytes).
2. **Time Threshold:** Exactly **24 hours** (`86,400` seconds) elapsed since the first record in the segment.

### 10.2 Naming Convention & Determinism

Rotated segments follow a deterministic, chronological naming schema:

```text
audit-<YYYYMMDDTHHMMSSZ>-seq<startSeq>-seq<endSeq>.jsonl
```

When compressed:

```text
audit-<YYYYMMDDTHHMMSSZ>-seq<startSeq>-seq<endSeq>.jsonl.gz
```

### 10.3 Chain Crossing Rotation Boundaries

- Rotation is purely a physical file boundary; the logical cryptographic chain is uninterrupted.
- The first record in the new segment contains `sequenceNumber = endSeq + 1` and
  `integrity.previousRecordHash` equal to the `recordHash` of the last record in the rotated segment.
- Before closing a segment, a **Tier 2 checkpoint record** is appended, sealing the segment.

### 10.4 Compression & Deletion Contract

- Once rotated, the uncompressed segment is compressed via standard `gzip` (`node:zlib`).
- The uncompressed `.jsonl` file MUST NOT be deleted until the resulting `.jsonl.gz` file has been
  decompressed, re-verified against the SHA-256 chain, and verified intact.
- The `.jsonl.gz` file is given `0600` permissions.

---

## 11. Retention Policy & Log-Saturation Denial-of-Service Defense

To prevent disk-exhaustion denial-of-service attacks:

### 11.1 Numeric Storage Caps

| Parameter                  | Value           | Description                                                        |
| :------------------------- | :-------------- | :----------------------------------------------------------------- |
| `MAX_RECORD_BYTES`         | 64 KiB          | Maximum single JSONL record size                                   |
| `SEGMENT_SIZE_THRESHOLD`   | 10 MiB          | Maximum active uncompressed segment size                           |
| `MAX_ARCHIVE_SEGMENTS`     | 100 segments    | Maximum retained compressed segment files                          |
| `TOTAL_AUDIT_BUDGET_BYTES` | 1 GiB           | Maximum cumulative audit storage cap (1,073,741,824 bytes)         |
| `MAX_PENDING_ANCHOR_QUEUE` | 100 checkpoints | Maximum queued unanchored checkpoints before backpressure halts tx |

### 11.2 Retention Rules & Safe Deletion

- When `MAX_ARCHIVE_SEGMENTS` or `TOTAL_AUDIT_BUDGET_BYTES` is reached, older segments may only be
  purged if they satisfy **all** of the following conditions:
  1. The segment has been signed by a Tier 2 checkpoint.
  2. The segment checkpoint has been acknowledged by a Tier 3 external anchor receipt.
  3. The segment is not the only copy of historical evidence.
- **Fail-Closed on Unanchored Full Disk:** If the storage budget is exhausted and the oldest
  segments have NOT been anchored externally, ARC **MUST NOT delete unanchored evidence**.
  Instead, ARC enters `AUDIT_STORAGE_EXHAUSTED` mode and halts all mutating operations.

---

## 12. Tier 2: Signed Cryptographic Checkpoint Contract

ADR-0004 specifies Tier 2 checkpointing. This specification normatively resolves historical ambiguities
by mandating **asymmetric digital signatures**.

### 12.1 Algorithm & Format

- **Algorithm:** **Ed25519** (PureEd25519 / RFC 8032) via native Node.js `node:crypto`.
- **Public Key Identification:** SHA-256 fingerprint of the Ed25519 SPKI public key (hex encoded).
- **Signature Encoding:** URL-safe Base64 (`base64url`).

### 12.2 Checkpoint Payload Schema

The checkpoint signs a canonical, domain-separated binary string:

```text
ARC-CHECKPOINT-V1\n
checkpointId:<UUIDv4>\n
sequenceStart:<number>\n
sequenceEnd:<number>\n
terminalRecordHash:<64-hex>\n
previousCheckpointHash:<64-hex>\n
timestamp:<ISO-8601-UTC>\n
publicKeyFingerprint:<64-hex>
```

### 12.3 Cadence & Checkpoint Records

- Checkpoints are created every **1,000 records** OR immediately upon segment rotation.
- A checkpoint record is itself represented as a specialized audit record appended to the chain,
  containing the signature and public key fingerprint in its metadata.
- Checkpoints form their own secondary hash chain (`previousCheckpointHash`), binding all
  checkpoints together.

---

## 13. Checkpoint Signing Key Management & Security

The Ed25519 signing private key is privileged server infrastructure.

### 13.1 Permitted Key Sources

1. **Owner-Only File:** A path configured via `audit.signingKeyPath`.
   - Must be a regular file with mode `0600`.
   - Must be owned by the server process UID.
   - Symlinks and group/world-readable files are strictly rejected.
   - Must reside outside all agent workspaces.
2. **Inherited File Descriptor:** A pre-opened file descriptor passed by a trusted supervisor process.

### 13.2 Prohibited Key Sources

The signing private key MUST NOT be accepted via:

- Command-line arguments (`process.argv`).
- Ambient environment variables (e.g. `ARC_SIGNING_KEY=...`).
- Remote MCP headers or tool parameters.
- Inline text in public configuration files.
- Audit records or server logs.

### 13.3 Memory Hygiene

Private key buffers loaded into memory are zeroized (`.fill(0)`) immediately after signing operations.

---

## 14. Tier 3: External Anchoring Contract

Tier 3 establishes external non-repudiation by publishing integrity checkpoints to an independent
external receiver.

### 14.1 Anchored Payload

- Only **signed checkpoints** and root hashes are transmitted to external anchors.
- **Raw audit records, tool parameters, session tokens, and workspace paths are NEVER transmitted
  to the external anchor.**

### 14.2 Protocol & Authentication

- **Transport:** HTTPS over TLS 1.3 (`node:https`).
- **Endpoint:** Configured via `audit.anchorEndpoint`.
- **Authentication:** Mutual TLS (mTLS) client certificate or bearer token (`audit.anchorToken`).
- **Wire Payload:**
  ```json
  {
    "version": "1.0",
    "checkpointId": "uuid",
    "sequenceRange": { "start": 1, "end": 1000 },
    "terminalRecordHash": "hash",
    "previousCheckpointHash": "hash",
    "timestamp": "2026-09-20T18:00:00Z",
    "publicKeyFingerprint": "fingerprint",
    "signature": "base64url-signature"
  }
  ```

### 14.3 Receipt & Confirmation

- The anchor service returns HTTP 200/201 with an anchor receipt:
  `{ "receiptId": "...", "anchorTimestamp": "...", "signature": "..." }`.
- The receipt is stored locally in `audit-anchors.jsonl` and cross-referenced during verification.

### 14.4 Outage Handling & Backpressure

- Anchoring is asynchronous relative to individual tool calls, but bounded:
  - Checkpoints are queued in a persistent spool.
  - Retries use exponential backoff with jitter (initial 1s, max 60s, max 5 attempts).
  - If the unanchored checkpoint queue exceeds **100 checkpoints**, the gateway throttles mutating
    operations and reports degraded health (`ANCHOR_SPOOL_FULL`).

---

## 15. Threat Boundaries Across Integrity Tiers

| Threat / Attacker Capability                               | Tier 1: Local Chain | Tier 2: Signed Checkpoints | Tier 3: External Anchoring |
| :--------------------------------------------------------- | :------------------ | :------------------------- | :------------------------- |
| Accidental bit rot / disk corruption                       | **Detected**        | **Detected**               | **Detected**               |
| Unprivileged local user editing audit file                 | **Detected**        | **Detected**               | **Detected**               |
| Unauthorized record deletion or insertion                  | **Detected**        | **Detected**               | **Detected**               |
| Tail truncation by local user                              | _Undetected_        | **Detected**               | **Detected**               |
| Host root/admin rewriting local chain without private key  | _Bypassed_          | **Detected**               | **Detected**               |
| Host compromise with theft of local checkpoint signing key | _Bypassed_          | _Bypassed_                 | **Detected**               |
| Complete destruction of host and all local storage         | _Lost_              | _Lost_                     | **Anchor Proof Preserved** |

---

## 16. Offline Verification Specification

The offline verification engine (`arc audit verify`) validates audit logs independently without
trusting the running ARC server or requiring private keys:

1. **Public Key Verification:** Uses only the public key (`audit.publicKeyPath` or SPKI fingerprint).
2. **Checks Executed:**
   - Validates JSONL syntax and schema completeness for every line.
   - Verifies contiguous sequence numbers (`1, 2, 3, ...`) with zero gaps or duplicates.
   - Verifies that `integrity.previousRecordHash` strictly matches the preceding record's `recordHash`.
   - Recomputes canonical JSON SHA-256 for every record and verifies `integrity.recordHash`.
   - Validates segment transitions and rotation continuity across uncompressed and `.jsonl.gz` files.
   - Verifies every Tier 2 checkpoint signature against the public key.
   - Verifies the checkpoint hash chain (`previousCheckpointHash`).
   - Cross-references external anchor receipts against signed checkpoints.
3. **Exit Codes:** Clean exit (0) on total verification; non-zero exit with precise failure diagnostics
   identifying the exact segment, sequence number, and corrupt record.

---

## 17. Local Operator Evidence Interface & Export Contract

### 17.1 Local CLI Commands

The local operator CLI (`apps/cli`) provides four dedicated audit subcommands:

1. `arc audit status`: Reports storage path, active segment, total segments, sequence number,
   last checkpoint, anchor queue depth, and integrity status.
2. `arc audit verify [--dir <path>] [--public-key <path>]`: Runs the complete offline verifier.
3. `arc audit inspect [--from <seq>] [--to <seq>] [--limit <n>]`: Displays bounded, sanitized
   records (maximum limit: 100).
4. `arc audit export --output <tar/zip> [--from <seq>] [--to <seq>]`: Generates a self-contained
   evidence bundle.

### 17.2 Evidence Export Bundle

An evidence bundle contains:

- Selected uncompressed and compressed audit segments.
- Associated checkpoint records and public key.
- Anchor receipts (`audit-anchors.jsonl`).
- `manifest.json`: A SHA-256 manifest of all bundle files, signed by the checkpoint key.
- Output path is strictly validated against directory traversal.

---

## 18. Absolute Prohibition of Remote Audit Exposure

Remote MCP clients (whether connecting via stdio or remote mTLS gateway) MUST NOT receive any tools
or endpoints to:

- Delete, truncate, or purge audit logs.
- Trigger log rotation manually.
- Alter audit configuration, paths, or thresholds.
- View, export, or search audit logs across sessions.
- Modify or inspect checkpoint signing keys or anchor credentials.

Audit administration is restricted strictly to local operator shell commands.

---

## 19. Central Redaction Authority & Entropy Reconciliation

### 19.1 Authority

All data passing into `AuditLogger.log()` is sanitized centrally before hash computation or disk append.
No subsystem or caller can bypass redaction.

### 19.2 Historical Entropy Scanning Reconciliation

- **Historical Ambiguity:** ADR-0004 and `audit-model.md §3.2` mentioned "Entropy Analysis" to flag high-entropy strings.
- **Normative Resolution:** Statistical entropy analysis produces unacceptably high false-positive rates
  on legitimate cryptographic hashes, SPKI pins, UUIDs, and base64 identifiers, while failing to catch
  structured low-entropy credentials.
- **RC-06 Policy:** Entropy scanning is **explicitly rejected**. Redaction relies on deterministic
  and verified mechanisms:
  1. Structural allowlist projection (only approved metadata recorded).
  2. Case-insensitive key-name filtering (`SENSITIVE_KEY_PATTERNS`).
  3. High-confidence regex token scanners (`SENSITIVE_VALUE_REGEXES`).
  4. Absolute host path redaction (`redactAbsolutePaths`).
  5. Buffer hygiene and memory zeroization.

---

## 20. Hashing Invariants & Secret Oracle Prevention

1. **No Raw Secret Hashing:** Raw credentials, session tokens, and enrollment secrets are NEVER hashed
   to produce audit identifiers or payload hashes. Hashing a raw secret creates an offline dictionary oracle.
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

## 22. Startup Verification & Health Reporting

On server startup, before serving any stdio or remote traffic:

1. **Verification:**
   - Active lock is acquired.
   - Storage directory permissions (`0700`) and ownership verified.
   - Existing active segment scanned; hash chain verified from start to terminal record.
   - Torn final lines (if any) recovered cleanly.
   - Checkpoint signatures validated.
2. **Health Reporting:**
   - Health check exposes: `audit.active: true`, `audit.sequence: <num>`, `audit.integrity: 'VERIFIED'`,
     `audit.unanchoredCheckpoints: <num>`.
   - Health check NEVER exposes filesystem paths, private keys, or anchor tokens.

---

## 23. Process Restart & Recovery Semantics

| State Component           | Durability across Restart | Post-Restart Behavior                                   |
| :------------------------ | :------------------------ | :------------------------------------------------------ |
| Record Chain & Sequence   | **Persistent**            | Resumes from `lastRecord.sequenceNumber + 1`            |
| `previousRecordHash`      | **Persistent**            | Initialized to `lastRecord.integrity.recordHash`        |
| Checkpoint History        | **Persistent**            | Loaded and bound to `previousCheckpointHash`            |
| Anchor Receipts           | **Persistent**            | Loaded from `audit-anchors.jsonl`                       |
| Unanchored Checkpoint Q   | **Persistent**            | Recovered from disk queue; background anchoring resumes |
| Active Single-Writer Lock | **Volatile**              | Re-acquired exclusively on startup                      |
| In-Flight Append State    | **Volatile**              | Cleared; re-entrant state initialized fresh             |

---

## 24. RC-06 Configuration Model & Numeric Bounds

Configuration options under `audit`:

```typescript
export interface AuditConfig {
  /** Enable persistent disk auditing. Default: true in production. */
  enabled: boolean;
  /** Storage directory path. Default: '~/.cesspace-arc/audit/'. */
  directory?: string;
  /** Active segment rotation size threshold. Default: 10485760 (10 MiB). */
  segmentSizeBytes?: number;
  /** Active segment rotation time threshold. Default: 86400 (24 hours). */
  rotationIntervalSeconds?: number;
  /** Maximum total audit storage budget. Default: 1073741824 (1 GiB). */
  storageBudgetBytes?: number;
  /** Maximum retained archive segments. Default: 100. */
  maxArchiveSegments?: number;
  /** Path to Ed25519 private key PEM file for Tier 2 signing. */
  signingKeyPath?: string;
  /** Path to Ed25519 public key PEM file for verification. */
  publicKeyPath?: string;
  /** Checkpoint record interval. Default: 1000. */
  checkpointInterval?: number;
  /** External Tier 3 anchor HTTPS endpoint. Optional. */
  anchorEndpoint?: string;
  /** Bearer authentication token for external anchor. Optional. */
  anchorToken?: string;
  /** Maximum unanchored checkpoints queue size. Default: 100. */
  maxAnchorQueueSize?: number;
}
```

---

## 25. Failure Modes & Sanitized Error Model

1. **Storage Unwritable / Full:** Throws internal error; surfaces opaque `AUDIT_PERSISTENCE_FAILED`
   to remote callers without leaking host paths.
2. **Integrity Corruption:** Startup halts immediately with fatal exit; surfaces `AUDIT_CORRUPTION_DETECTED`
   in local operator console.
3. **Lock Conflict:** Exits immediately with `AUDIT_STORE_LOCKED`.
4. **Anchor Timeout / Failure:** Retried in background; surfaces degraded health status
   `ANCHOR_UNAVAILABLE` without exposing remote anchor URLs.

---

## 26. Supply Chain & Zero-Dependency Policy

RC-06 is implemented **entirely using Node.js 24 built-in modules**:

- `node:fs` and `node:fs/promises`: File I/O, file descriptor management, permissions, and atomic renames.
- `node:crypto`: SHA-256 hashing, Ed25519 key generation, digital signing, and verification.
- `node:zlib`: Streaming `gzip` compression and decompression.
- `node:https`: HTTPS client for Tier 3 external anchoring.
- `node:stream`: High-performance streaming for log rotation and offline verification.

No third-party packages for file locking, JSON canonicalization, compression, or signing may be added.

---

## 27. Versioning & Health Metadata

- Proposed public version: **`0.6.0-rc06`**.
- Proposed health stage: **`RC-06`**.
- _Task 0 performs no version bump._ The version is updated in Task 8 after all acceptance gates pass.

---

## 28. Out-of-Scope Catalog

The following items are explicitly deferred beyond RC-06:

1. Proprietary cloud SIEM integrations (Splunk, Datadog, AWS CloudWatch, GCP Cloud Logging).
2. Public blockchain or cryptocurrency ledger anchoring.
3. Multi-host distributed Raft/Paxos audit replication.
4. Browser-based GUI dashboard for audit inspection.
5. Hardware Security Module (HSM) or PKCS#11 hardware key integration.
6. Remote MCP audit log management endpoints.
7. User/role permission management for audit access beyond OS user boundaries.
8. RC-07 composite engineering tools.
9. RC-08 adversarial fuzzing and penetration testing.

---

## 29. Negative Security Control Catalog (RC06-NEG-01..80)

All 80 controls are contiguous, mandatory, and directly testable:

### Category 1: Storage & Filesystem Integrity (RC06-NEG-01..11)

- **`RC06-NEG-01`**: Audit directory is a symlink. Rejects startup; throws `INVALID_AUDIT_PATH`. No file written.
- **`RC06-NEG-02`**: Active audit segment file is a symlink. Rejects write; throws `SYMLINK_DETECTED`. No data appended.
- **`RC06-NEG-03`**: Audit directory permissions wider than `0700` (e.g. `0755`, `0777`). Fails validation at startup.
- **`RC06-NEG-04`**: Audit segment file permissions wider than `0600` (e.g. `0644`). Fails validation at startup.
- **`RC06-NEG-05`**: Audit directory owned by different UID. Rejects startup with `OWNERSHIP_MISMATCH`.
- **`RC06-NEG-06`**: Audit segment owned by different UID. Rejects write with `OWNERSHIP_MISMATCH`.
- **`RC06-NEG-07`**: Target audit path is a non-regular file (FIFO, block/character device). Rejects write.
- **`RC06-NEG-08`**: Audit target path attempts directory traversal (`../`). Rejects path configuration.
- **`RC06-NEG-09`**: Second ARC process attempts to acquire active writer lock. Rejects startup with `AUDIT_STORE_LOCKED`.
- **`RC06-NEG-10`**: Stale lock takeover attempted while holder PID is alive. Takeover rejected.
- **`RC06-NEG-11`**: Audit lockfile is a symbolic link. Startup fails immediately with `LOCKFILE_INSECURE`.

### Category 2: Record Integrity & Chain Continuity (RC06-NEG-12..21)

- **`RC06-NEG-12`**: Sequence number gap introduced in persistent record stream. Offline verifier flags failure.
- **`RC06-NEG-13`**: Duplicate sequence number in persistent record stream. Offline verifier flags failure.
- **`RC06-NEG-14`**: Broken `previousRecordHash` link between adjacent records. Verification halts with hash mismatch.
- **`RC06-NEG-15`**: Tampered record payload (modified parameters) with original hash. Hash recomputation fails.
- **`RC06-NEG-16`**: Tampered `recordHash` with original payload. Hash verification fails.
- **`RC06-NEG-17`**: Middle record deletion from audit segment. Chain link break detected.
- **`RC06-NEG-18`**: Tail record truncation detectable relative to signed checkpoint. Truncation detected.
- **`RC06-NEG-19`**: Torn final record line from crash. Recovers cleanly via sidecar; history intact.
- **`RC06-NEG-20`**: Unrecoverable torn line preceded by corrupted history. Startup fails closed.
- **`RC06-NEG-21`**: Single record exceeding 64 KiB ceiling. Rejected with `RECORD_TOO_LARGE`. No file corruption.

### Category 3: Durability & Execution Ordering (RC06-NEG-22..27)

- **`RC06-NEG-22`**: Simulated disk full (`ENOSPC`) during append. Append throws; state remains consistent.
- **`RC06-NEG-23`**: Simulated short write during append. Detects partial write; rolls back or fails closed.
- **`RC06-NEG-24`**: Pre-execution audit write failure before privileged mutation. Mutation aborted; zero side effects.
- **`RC06-NEG-25`**: Post-execution audit append failure after irreversible mutation. Server enters degraded fail-closed state.
- **`RC06-NEG-26`**: Attempt to disable auditing in production configuration. Startup rejected.
- **`RC06-NEG-27`**: Unwritable audit directory at startup. Process exits immediately with failure.

### Category 4: Restart, Rotation & Compression (RC06-NEG-28..39)

- **`RC06-NEG-28`**: Empty or corrupt genesis record in pre-existing audit store. Startup fails closed.
- **`RC06-NEG-29`**: Attempted sequence number reset to 1 on process restart with existing records. Rejected.
- **`RC06-NEG-30`**: Attempted previousRecordHash reset to zero genesis on restart. Rejected.
- **`RC06-NEG-31`**: Non-contiguous sequence jump across process restart. Verification fails.
- **`RC06-NEG-32`**: Rotation boundary sequence discontinuity. Verifier flags sequence gap between segments.
- **`RC06-NEG-33`**: Rotation boundary `previousRecordHash` mismatch. Verifier flags chain break between segments.
- **`RC06-NEG-34`**: Corrupted gzip archive in rotated segment. Verification flags CRC/decompression failure.
- **`RC06-NEG-35`**: Missing intermediate rotated segment in archive sequence. Verifier flags missing segment.
- **`RC06-NEG-36`**: Uncompressed segment deletion before gzip integrity check. Deletion prohibited.
- **`RC06-NEG-37`**: Rapid rotation triggering filename timestamp collision. Sequence range suffix prevents overwrite.
- **`RC06-NEG-38`**: Rotated segment permissions wider than `0600`. Verification flags insecure permissions.
- **`RC06-NEG-39`**: Compressed archive permissions wider than `0600`. Verification flags insecure permissions.

### Category 5: Storage Saturation & Resource Bounds (RC06-NEG-40..43)

- **`RC06-NEG-40`**: Retention archive count cap exceeded. Oldest unanchored segment is protected from deletion.
- **`RC06-NEG-41`**: Total storage budget cap exceeded. Halts mutating operations; does not drop unanchored logs.
- **`RC06-NEG-42`**: Wall-clock rollback attempt to bypass rotation threshold. Monotonic sequence prevents bypass.
- **`RC06-NEG-43`**: Wall-clock forward jump attempt to prematurely expire evidence. Checkpoint linkage intact.

### Category 6: Tier 2 Signed Checkpoints (RC06-NEG-44..51)

- **`RC06-NEG-44`**: Tampered checkpoint signature bytes. Signature verification fails.
- **`RC06-NEG-45`**: Checkpoint terminal record hash mismatch. Integrity verification fails.
- **`RC06-NEG-46`**: Checkpoint sequence range mismatch with actual records. Verification fails.
- **`RC06-NEG-47`**: Checkpoint `previousCheckpointHash` chain break. Verifier flags broken checkpoint chain.
- **`RC06-NEG-48`**: Checkpoint verified with wrong Ed25519 public key. Verification fails.
- **`RC06-NEG-49`**: Checkpoint signature algorithm downgrade attempt (e.g. none, RSA). Rejected.
- **`RC06-NEG-50`**: Replay of historical checkpoint into new sequence range. Rejected.
- **`RC06-NEG-51`**: Out-of-order checkpoint insertion. Sequence continuity check fails.

### Category 7: Signing Key Security (RC06-NEG-52..59)

- **`RC06-NEG-52`**: Signing key provided via `argv` command-line argument. Startup fails immediately.
- **`RC06-NEG-53`**: Signing key provided via ambient environment variable. Startup fails immediately.
- **`RC06-NEG-54`**: Signing key supplied via remote MCP header or tool argument. Rejected; logged as security event.
- **`RC06-NEG-55`**: Checkpoint signing key file is a symlink. Key loading rejected.
- **`RC06-NEG-56`**: Checkpoint signing key file permissions wider than `0600`. Key loading rejected.
- **`RC06-NEG-57`**: Checkpoint signing key file owned by different UID. Key loading rejected.
- **`RC06-NEG-58`**: Malformed or corrupt Ed25519 private key. Startup fails closed.
- **`RC06-NEG-59`**: Missing signing key when Tier 2 is enabled. Startup halts immediately.

### Category 8: Tier 3 External Anchoring (RC06-NEG-60..66)

- **`RC06-NEG-60`**: External anchor HTTPS connection timeout. Checkpoint spooled; backoff retry initiated.
- **`RC06-NEG-61`**: External anchor returns HTTP 5xx error. Checkpoint spooled; backoff retry initiated.
- **`RC06-NEG-62`**: External anchor queue exceeds 100 checkpoints. Mutating operations throttled/halted.
- **`RC06-NEG-63`**: Forged external anchor receipt with invalid signature/digest. Receipt rejected; unanchored state remains.
- **`RC06-NEG-64`**: Replayed anchor acknowledgement from prior checkpoint. Receipt correlation fails.
- **`RC06-NEG-65`**: Insecure HTTP (plaintext) external anchor endpoint configured. Rejected; HTTPS required.
- **`RC06-NEG-66`**: Remote MCP client attempts to configure anchor endpoint. Tool call rejected with `UNKNOWN_TOOL`.

### Category 9: Central Redaction & Secrecy Invariants (RC06-NEG-67..76)

- **`RC06-NEG-67`**: Raw `Arc-Session-Token` secret present in persistent JSONL. Centrally redacted to `[REDACTED_SECRET]`.
- **`RC06-NEG-68`**: Raw enrollment one-time secret present in persistent JSONL. Centrally redacted.
- **`RC06-NEG-69`**: Raw HTTP `Authorization` header present in persistent JSONL. Centrally redacted.
- **`RC06-NEG-70`**: Raw PKCS#8 private key block present in persistent JSONL. Centrally redacted.
- **`RC06-NEG-71`**: Raw X.509 certificate PEM block present in persistent JSONL. Centrally redacted.
- **`RC06-NEG-72`**: Raw tool `content` parameter stored in persistent JSONL. Omitted; length logged.
- **`RC06-NEG-73`**: Raw tool `patch` parameter stored in persistent JSONL. Omitted; length logged.
- **`RC06-NEG-74`**: Raw environment variable values stored in persistent JSONL. Redacted to `[REDACTED_ENV_VALUE]`.
- **`RC06-NEG-75`**: Raw process stdout/stderr stored in persistent JSONL. Omitted; byte counts logged.
- **`RC06-NEG-76`**: Absolute host workspace path stored in persistent target metadata. Replaced with SHA-256 digest.

### Category 10: Administrative Isolation & Verification (RC06-NEG-77..80)

- **`RC06-NEG-77`**: Remote MCP tool call attempting audit log deletion. Rejected with `UNKNOWN_TOOL`.
- **`RC06-NEG-78`**: Remote MCP tool call attempting log rotation. Rejected with `UNKNOWN_TOOL`.
- **`RC06-NEG-79`**: Remote MCP tool call attempting audit export. Rejected with `UNKNOWN_TOOL`.
- **`RC06-NEG-80`**: Local CLI export path traversal (`--output ../../../etc/audit.tar`). Rejected with path error.

---

## 30. Threat-to-Control Matrix

| Threat Description                              | Primary Defense Mechanism                          | Enforcement Tier | Negative Controls |
| :---------------------------------------------- | :------------------------------------------------- | :--------------- | :---------------- |
| Host user edits historical JSONL records        | SHA-256 hash chaining + Ed25519 signatures         | Tier 1 & 2       | NEG-14, 15, 16    |
| Tail truncation to conceal malicious tool run   | Tier 2 signed checkpoints & Tier 3 anchor receipts | Tier 2 & 3       | NEG-18, 45        |
| Secret extraction from audit trail              | Centralized pre-hash redaction & minimization      | Tier 1           | NEG-67..76        |
| Disk exhaustion denial-of-service via log flood | Segment size caps, rotation & bounded budgets      | Tier 1           | NEG-21, 40, 41    |
| Side-effect execution without audit record      | Pre-dispatch sync & fail-closed execution order    | Tier 1           | NEG-24, 25        |
| Concurrent process audit log corruption         | Exclusive single-writer lockfile                   | Tier 1           | NEG-09, 10, 11    |
| Host root rewrites local chain & checkpoints    | Tier 3 external anchor root receipt                | Tier 3           | NEG-60..64        |
| Remote MCP agent tampers with audit subsystem   | Strict local operator isolation & no MCP tools     | Architecture     | NEG-66, 77..79    |
| Signing key exfiltration from environment       | Restricted 0600 file / FD-only key loading         | Tier 2           | NEG-52..57        |

---

## 31. Positive Acceptance Flows (Flows 1..18)

1. **Flow 1: Fresh Persistent Store Initialization:** Server boots with clean audit directory; creates `audit.lock` and active segment; logs genesis record (`seq: 1`, `prevHash: 000...000`); file permissions verified `0600`.
2. **Flow 2: Standard Stdio Tool Execution Logging:** Client calls `read_file`; audit record appended synchronously; `fdatasync()` verified; defensive copy returned.
3. **Flow 3: Remote Authenticated Gateway Invocation Logging:** Remote client executes tool; actor metadata (deviceId, spkiPin, mcpSessionId) recorded; zero secrets leaked.
4. **Flow 4: Approval Lifecycle Persistence:** Operator approves mutation tool via admin IPC; approval state transitions (`REQUESTED`, `APPROVED`, `REDEEMED`) logged in contiguous sequence.
5. **Flow 5: Gateway Admission & Lifecycle Auditing:** Gateway boots, admits mTLS client, issues session token, enforces rate limits; all 14 gateway event types logged in single chain.
6. **Flow 6: Clean Process Termination:** Server receives `SIGTERM`; flushes buffers; logs `GATEWAY_STOPPED`; releases lock cleanly.
7. **Flow 7: Gateway Restart & Hash Continuity:** Server restarts against non-empty store; reads terminal record; next record correctly increments sequence and links `previousRecordHash`.
8. **Flow 8: Size-Based Rotation Trigger:** Active segment reaches 10 MiB; rotates to timestamped `.jsonl`; new segment begins with sequence continuity.
9. **Flow 9: Time-Based Rotation Trigger:** Clock passes 24 hours; segment rotates cleanly.
10. **Flow 10: Compressed Archive Generation & Verification:** Rotated segment compressed to `.jsonl.gz`; uncompressed file verified before removal; permissions verified `0600`.
11. **Flow 11: Tier 2 Ed25519 Checkpoint Generation:** Chain reaches 1,000 records; generates signed checkpoint payload; verifies signature against Ed25519 public key.
12. **Flow 12: Offline Public-Key Checkpoint Verification:** Standalone verifier validates checkpoint signature using public key without accessing private key.
13. **Flow 13: Tier 3 External Anchor Dispatch & Receipt:** Checkpoint transmitted via HTTPS to mock anchor service; valid receipt received and recorded in `audit-anchors.jsonl`.
14. **Flow 14: Anchor Outage Spooling & Automatic Catch-Up:** Anchor server temporarily down; checkpoints queued in spool; server recovers and catches up without dropped evidence.
15. **Flow 15: Local Operator `arc audit status`:** Operator executes CLI status command; receives accurate JSON/table summary of store health and sequence count.
16. **Flow 16: Local Operator `arc audit inspect`:** Operator pages through recent records; receives redacted records within bounded limit.
17. **Flow 17: Full-History Offline Verification:** Standalone tool validates entire multi-segment archive from genesis to terminal record cleanly.
18. **Flow 18: Evidence Bundle Export & Manifest Verification:** Operator executes `arc audit export`; generates zip bundle containing segments, checkpoints, and verified SHA-256 manifest.

---

## 32. Historical Documentation Reconciliation

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

---

## 33. Implementation Breakdown (Tasks 1..8)

| #   | Title                                               | Scope                                                            | Expected Files                                                                              | Invariants & Quality Standards                   | Controls           | Depends On | Stop Boundary                     |
| :-- | :-------------------------------------------------- | :--------------------------------------------------------------- | :------------------------------------------------------------------------------------------ | :----------------------------------------------- | :----------------- | :--------- | :-------------------------------- |
| 1   | Persistent Append Storage & Filesystem Authority    | Disk append engine, 0700/0600 permissions, exclusive lockfile    | `packages/audit/src/storage.ts`, `packages/audit/src/lock.ts`, `tests/rc06-storage.test.js` | Inv-13, atomic writes, symlink rejection         | NEG-01..11, 21..23 | None       | Storage tests pass cleanly        |
| 2   | Restart Recovery, Torn Tails & Chain Continuity     | Genesis, restart continuation, torn-tail recovery, sequence link | `packages/audit/src/recovery.ts`, `tests/rc06-recovery.test.js`                             | Strict continuity, no sequence reset             | NEG-12..20, 28..31 | Task 1     | Recovery tests pass cleanly       |
| 3   | Segment Rotation, Compression & Storage Caps        | 10 MiB / 24h rotation, `.jsonl.gz`, retention budget caps        | `packages/audit/src/rotation.ts`, `tests/rc06-rotation.test.js`                             | Safe uncompressed delete, bounded disk           | NEG-32..43         | Task 2     | Rotation tests pass cleanly       |
| 4   | Tier 2 Ed25519 Checkpoint Signing & Key Mgmt        | Ed25519 signing engine, key security, checkpoint records         | `packages/audit/src/checkpoint.ts`, `tests/rc06-checkpoint.test.js`                         | RFC 8032, no key in argv/env, public key verify  | NEG-44..59         | Task 3     | Checkpoint tests pass cleanly     |
| 5   | Tier 3 External Anchor Client & Spooling            | HTTPS anchor client, bounded queue, retry backoff, receipts      | `packages/audit/src/anchor.ts`, `tests/rc06-anchor.test.js`                                 | Bounded spool, backpressure, no raw secret trans | NEG-60..66         | Task 4     | Anchor tests pass cleanly         |
| 6   | Runtime Engine Integration & Fail-Closed Durability | Wire `ArcMcpServer` & `AuditLogger`, pre-dispatch sync, health   | `apps/mcp-server/src/index.ts`, `tests/rc06-runtime-durability.test.js`                     | INV-13, fail-closed on persistence failure       | NEG-24..27         | Task 5     | Runtime tests pass cleanly        |
| 7   | Local Operator CLI & Offline Verifier               | `arc audit status/verify/inspect/export` in CLI & verifier suite | `apps/cli/src/audit.ts`, `packages/audit/src/verify.ts`, `tests/rc06-cli-verifier.test.js`  | Public key only verifier, path traversal defense | NEG-77..80         | Task 6     | CLI & verifier tests pass cleanly |
| 8   | Secrecy Hardening, Acceptance & Public Version Bump | Central redaction tests, 80 negative controls, 18 flows, bump    | `tests/rc06-negative-controls.test.js`, `tests/rc06-positive-flows.test.js`, `verify-rc06`  | Version 0.6.0-rc06, all 80 controls pass         | NEG-67..76 (All)   | Task 7     | All 20 quality gates pass         |

---

## 34. Definition of Done (RC-06)

RC-06 is complete and ready for merge when:

1. **Persistent Single-Chain Storage:** All audit records are written to canonical JSONL files with sequential SHA-256 hash chaining.
2. **Filesystem Security & Exclusivity:** Auditing operates strictly within owner-only (`0700`/`0600`) directories protected by exclusive writer locks.
3. **Crash Consistency & Durability:** Pre-dispatch audit syncing satisfies INV-13; torn crash tails are safely recovered without history corruption.
4. **Rotation & Compression:** Active segments rotate deterministically at 10 MiB / 24h and compress to `.jsonl.gz` after verification.
5. **Storage Budget Bounds:** Retention limits prevent log-saturation DoS while strictly protecting unanchored evidence.
6. **Tier 2 Signed Checkpoints:** Checkpoint records signed with Ed25519 are appended every 1,000 records or upon segment rotation.
7. **Tier 3 External Anchoring:** Signed checkpoints are dispatched over HTTPS to independent anchors with bounded spooling and backpressure.
8. **Offline Verifier:** Standalone CLI tool validates full history and checkpoint signatures using public keys only.
9. **Local Operator Interface:** `arc audit status`, `verify`, `inspect`, and `export` operate locally without exposing remote MCP endpoints.
10. **Universal Redaction:** Central pre-hash redaction guarantees that secrets, tokens, keys, and absolute paths never reach persistent logs.
11. **Negative Controls:** All 80 frozen negative controls (`RC06-NEG-01..80`) are implemented, contiguous, and passing.
12. **Positive Flows:** All 18 integration flows are implemented and verified.
13. **Verification Script:** `scripts/verify-rc06.sh` executes all quality gates cleanly.
14. **CI Passes:** Monorepo tests, lint, formatting, typecheck, doc links, secret scanning, and dependency audit pass with zero failures.
15. **Public Version:** Version bumped to `0.6.0-rc06` and health stage reports `RC-06`.

---

## 35. Open Questions

**Open Questions: None**

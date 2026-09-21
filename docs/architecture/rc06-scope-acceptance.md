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
4. **Authoritative Record and Preimage Contract:**
   - The authoritative sanitized `PersistentAuditRecordV1` is the source of both hashing and persistence.
   - `recordHash` is computed from the canonical V1 record with only `integrity.recordHash` omitted.
   - After `recordHash` is populated, the complete canonical V1 record is serialized as the JSONL line.
   - No persistence layer may mutate, re-redact, or reorder semantic record content after hash construction.
   - The verifier reconstructs the exact same preimage deterministically.

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

### 5.3 Prohibition of `clear()` and Evidence Deletion in Production

Persistent production audit storage exposes no `clear()` API.

- **Test-Only Isolation:** The `clear()` method is designated exclusively for isolated in-memory unit tests and remains permitted only on the isolated legacy/in-memory test logger (`AuditLogger`) where already required by pre-RC-06 tests.
- **Production Interface Prohibition:** `PersistentAuditStorage` and all future persistent audit production interfaces MUST NOT expose a history-clearing method.
- **No Clearing Vector:** No MCP method, CLI command, configuration option, admin IPC method, or runtime execution path may invoke or expose automatic clearing of persistent audit evidence.
- **Test Helpers Bounded:** Any test-only reset helper or test seam must remain strictly outside production-reachable interfaces.
- **No "Catch-and-Continue":** Production callers must never implement "catch and continue" semantics around an attempted persistent evidence deletion because no such operation exists or is reachable.
- **Zero-Auto-Deletion Invariant:** Persistent production storage strictly adheres to zero automatic audit evidence deletion. No `purge`, `reset`, `clear`, `truncate-history`, `delete-all`, or `log-wrap` functionality exists or may be added to production interfaces.

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

#### 6.2.1 Classification: Recoverable Torn Tail vs Fatal Corruption

During primary-history verification of the active audit segment, the verifier may return exactly one special classification:

```text
RECOVERABLE_TORN_ACTIVE_TAIL
```

This classification is returned **only when**:

1. All preceding complete records in the segment verify successfully (sequential continuity, valid V1 schema, and valid hash chain).
2. The defect is confined strictly to the final active-segment record/framing at EOF.
3. The final tail defect is either:
   - Missing its terminating line feed (`\n`), OR
   - The final JSON record line is malformed/unparseable.
4. The unverified torn bytes do not exceed `MAX_TORN_TAIL_BYTES = 64 KiB` (65,536 bytes).

**Crucial Invariant:** `RECOVERABLE_TORN_ACTIVE_TAIL` is **NOT** successful verification. It defers only the permitted tail preservation and truncation mutation to the dedicated recovery step. After recovery truncation and syncing, the resulting active segment **MUST** be re-verified from virtual genesis before cursors are established or startup proceeds.

#### 6.2.2 Non-Recoverable Fatal Corruptions

The following conditions are corruption, **even if they occur in the final complete record line**:

- `recordHash` mismatch
- `previousRecordHash` mismatch
- Sequence number discontinuity (gap, reset, duplicate)
- Unsupported `schemaVersion` (e.g., 0 or 2)
- Unknown top-level or closed nested field outside schema V1
- Non-canonical JSON formatting (key reordering, insignificant whitespace)
- Invalid field type or structure
- Valid JSON representing a semantically invalid V1 record

These defects **MUST NOT** be truncated away automatically. Automatic recovery is strictly prohibited for historical or structural corruption. The engine MUST fail closed and refuse to start.

#### 6.2.3 Torn Sidecar Filesystem Security Authority

A torn-tail sidecar file is retained forensic evidence and must receive the same strict filesystem authority as primary audit evidence:

- Regular file (`fs.stat().isFile() === true`).
- POSIX permissions mode exactly `0600` (`-rw-------`).
- Owned by the process real UID.
- Hard link count strictly `1` (`nlink === 1`).
- Must not be a symbolic link (`O_NOFOLLOW` open semantics).
- Atomic exclusive creation using `O_CREAT | O_EXCL`.
- File descriptor verification via `fstat()` immediately after open.
- Maximum allowable content size: `MAX_TORN_TAIL_BYTES = 64 KiB`.
- Complete write of all torn bytes.
- Explicit `fsync()` on the sidecar file descriptor before closing.
- Explicit `fsync()` on the parent audit directory after sidecar creation.
- Zero overwrite of existing files.
- Zero automatic deletion of sidecar files.

#### 6.2.4 Torn-Tail Persistence & Recovery Ordering

The exact recovery ordering is strictly:

```text
verify all complete prefix records
 → classify final bytes as RECOVERABLE_TORN_ACTIVE_TAIL
 → create sidecar file exclusively (O_CREAT | O_EXCL)
 → write ALL torn bytes to sidecar
 → fsync() sidecar file descriptor
 → close sidecar
 → fsync() parent audit directory
 → truncate active segment to last verified byte offset
 → fdatasync() active segment file descriptor
 → re-verify resulting active segment from virtual genesis
 → establish runtime cursors
```

**Failure Handling Rules:**

- If sidecar creation, writing, or syncing fails: **do NOT truncate the active segment; startup halts and fails closed.**
- If active segment truncation, syncing, or re-verification fails: **startup halts and fails closed.** Any previously written sidecar remains as retained forensic evidence.

#### 6.2.5 Sidecar Naming Family

Torn sidecar files follow the sibling naming pattern:

```text
audit-active.jsonl.torn.<timestamp>
```

where `<timestamp>` is a filesystem-safe UTC timestamp generated by ARC (e.g., `2026-09-21T06-00-00.000Z`).
The sidecar file MUST be created exclusively (`O_CREAT | O_EXCL`). If a candidate filename already exists, ARC MUST generate another collision-free timestamp/name or fail closed. Pre-existing files must never be overwritten or replaced.

---

## 7. Universal Audit Lifecycle & Execution Ordering (INV-13 Universal Auditability)

Universal auditability applies to **ALL privileged operations**, including read-only queries as well as mutations.

### 7.1 Protocol Lifecycle Phases

Every privileged operation records distinct lifecycle events bound by a server-generated `operationId`:

```typescript
export type AuditLifecyclePhase = 'STARTED' | 'COMPLETED' | 'DENIED' | 'RECOVERY_INDETERMINATE';

export interface AuditLifecycleMetadata {
  operationId: string; // Server-generated UUIDv4
  phase: AuditLifecyclePhase;
}
```

- `COMPLETED` signifies that the underlying subsystem executed and returned a terminal outcome;
  the existing `execution.status` field captures whether that outcome was success, error, timeout, or cancelled.
- `RECOVERY_INDETERMINATE` signifies that ARC cannot establish whether the operation completed
  before a process crash or power loss.

### 7.2 Strict Execution & Lifecycle State Machine

The frozen lifecycle state machine establishes two mutually exclusive execution branches from initial request receipt:

```text
NEW
 ├─→ DENIED
 │    terminal
 │
 └─→ STARTED
      ├─→ COMPLETED
      │    terminal
      │
      └─→ RECOVERY_INDETERMINATE
           terminal
```

There are no other valid transitions. In particular, `STARTED → DENIED` is **NOT** a valid lifecycle transition because policy evaluation strictly precedes subsystem dispatch and `STARTED` emission.

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
3. **Denied Requests & operationId Semantics:** A policy `DENY` produces one durable `DENIED` record before returning the denial error. A durable policy denial carries a server-generated UUIDv4 `operationId`. Its full lifecycle consists solely of `DENIED`. That operation ID represents a standalone terminal branch and MUST NOT later be reused by `STARTED`, `COMPLETED`, or `RECOVERY_INDETERMINATE`.

### 7.3 Crash Recovery for Dangling `STARTED` Operations

A process crash may occur after:

```text
durable STARTED → subsystem may or may not have executed → process dies before durable COMPLETED
```

This state MUST NOT be silently interpreted as success or failure.

#### 7.3.1 Dangling-Operation Determination & Terminal Invariants

An `operationId` is defined as dangling **if and only if** retained history contains one valid `STARTED` record and **no later** valid lifecycle record for that same `operationId` with phase:

- `COMPLETED`
- `RECOVERY_INDETERMINATE`

A policy-denied operation never has a preceding `STARTED` record; its complete lifecycle is solely `DENIED`.
A prior `RECOVERY_INDETERMINATE` record is terminal for reconciliation purposes. Startup MUST NOT append a second recovery marker for an already-reconciled operation.

#### 7.3.2 Lifecycle Structural Invariants

For each `operationId`, only these complete histories are valid in an audit store:

1. `DENIED` (standalone policy/auth rejection)
2. `STARTED → COMPLETED` (normal execution completion)
3. `STARTED → RECOVERY_INDETERMINATE` (reconciled crash recovery)

During a crash before startup reconciliation, this temporary incomplete history is valid:

- `STARTED` (dangling operation requiring Task-2 reconciliation)

Everything else is structural lifecycle corruption.

#### 7.3.3 Strict Malformed Lifecycle Histories Handling

Task-2 recovery and verification MUST fail closed rather than invent semantics or auto-normalize if a cryptographically valid chain contains structurally impossible lifecycle sequences. Fail-closed rejection is enforced for at least:

- `COMPLETED` without prior `STARTED`
- `RECOVERY_INDETERMINATE` without prior `STARTED`
- `STARTED` after `DENIED`
- `DENIED` after `STARTED`
- `DENIED` after `COMPLETED`
- `DENIED` after `RECOVERY_INDETERMINATE`
- Multiple `STARTED` records for the same `operationId`
- Multiple `COMPLETED` records for the same `operationId`
- Multiple `DENIED` records for the same `operationId`
- Multiple `RECOVERY_INDETERMINATE` records for the same `operationId`
- `COMPLETED` after `RECOVERY_INDETERMINATE`
- `RECOVERY_INDETERMINATE` after `COMPLETED`
- Any lifecycle record after a terminal phase (`COMPLETED`, `DENIED`, or `RECOVERY_INDETERMINATE`) for the same `operationId`

Any such structural impossibility halts startup with a bounded recovery/integrity error:

```text
AUDIT_LIFECYCLE_CORRUPTION
```

The recovery engine MUST NOT normalize, repair, or discard these histories.

#### 7.3.4 Canonical Recovery Actor Encoding

The recovery record MUST adhere to the closed V1 actor schema. The canonical recovery actor is frozen as exactly:

```typescript
actor: {
  clientId: 'system';
  clientType: 'SYSTEM';
  deviceId: '';
  sessionId: '';
}
```

Rules:

- No new `actor.type` field exists (closed schema).
- No generic top-level `source` field is introduced.
- `clientType: 'SYSTEM'` is the canonical V1 representation of a system-derived recovery actor.
- Callers cannot supply or override this actor for recovery reconciliation.

#### 7.3.5 Exact `RECOVERY_INDETERMINATE` Record Construction

A recovery record MUST be a valid `PersistentAuditRecordV1`. For each dangling `STARTED` operation, ARC constructs the recovery record with:

- `eventId`: New server-generated UUIDv4.
- `timestamp`: Recovery wall-clock UTC timestamp (ISO-8601).
- `lifecycle`:
  - `operationId`: Exact `operationId` (UUIDv4) from the originating dangling `STARTED`.
  - `phase`: `'RECOVERY_INDETERMINATE'`.
- `actor`: Canonical `SYSTEM` actor (`clientId: 'system'`, `clientType: 'SYSTEM'`, `deviceId: ''`, `sessionId: ''`).

**Context Preservation Rules:**

- **Copied from originating `STARTED` record:**
  - `target`
  - `invocation`
  - `policy`
  - `approval`, if present
- **NOT copied (newly generated, defaulted, or omitted):**
  - `eventId` (new server-generated UUIDv4)
  - `timestamp` (new recovery timestamp)
  - `sequenceNumber` (assigned by persistent storage layer)
  - `integrity` (assigned by persistent storage layer)
  - `actor` (canonical `SYSTEM` actor)
  - `execution` (mandatory recovery block defined below)
  - `error` (mandatory recovery error defined below)
  - `lifecycle` (phase is `RECOVERY_INDETERMINATE`)
  - `gateway` (omitted from recovery record)

#### 7.3.6 Mandatory `execution` Block Representation

The V1 record requires an `execution` block, but recovery must not claim that the underlying operation succeeded or failed. The recovery record's `execution` block is frozen as:

```typescript
execution: {
  status: 'ERROR';
  startTime: recoveryTimestamp; // recovery wall-clock timestamp string
  endTime: recoveryTimestamp; // identical recovery wall-clock timestamp string
  durationMs: 0;
}
```

**Explicit Semantic Invariant:**

> For a record whose lifecycle phase is `RECOVERY_INDETERMINATE`, `execution.status = 'ERROR'` describes the recovery/reconciliation condition only. It MUST NOT be interpreted as evidence that the original privileged operation failed, succeeded, timed out, or was cancelled.

The authoritative underlying-operation outcome remains strictly **`INDETERMINATE`** by virtue of `lifecycle.phase = 'RECOVERY_INDETERMINATE'`. The Task-1 protocol execution status enum (`SUCCESS | ERROR | DENIED | TIMEOUT | CANCELLED`) is preserved without widening.

#### 7.3.7 Mandatory Recovery `error` Block Representation

The recovery record includes a fixed, bounded error block:

```typescript
error: {
  code: 'AUDIT_OUTCOME_INDETERMINATE';
  message: 'Prior operation outcome is indeterminate after crash recovery.';
}
```

Rules:

- The error message is fixed and deterministic.
- No raw exception strings, stack traces, host paths, request payload data, or caller-controlled text may be placed in this block.

#### 7.3.8 Recovery Persistence & Failure Handling

On startup, after active segment verification and torn-tail recovery:

1. Scan lifecycle records across history by `operationId`.
2. Identify all dangling `STARTED` operations.
3. For each dangling operation, append the canonical `RECOVERY_INDETERMINATE` record to the active storage stream.
4. Each recovery record consumes the next sequential sequence number and links into the active SHA-256 hash chain with durable `fdatasync()`.
5. Privileged MCP tool service may begin **ONLY** after every dangling operation has received a durable recovery record.

If any reconciliation append fails:
**Startup halts and fails closed.**

The recovery record is part of the authoritative primary chain, consumes the next sequential audit sequence number, and participates in normal SHA-256 hash chaining. No separate journal is introduced. Total indeterminate recoveries are tracked in health metadata under `audit.indeterminateRecoveries`.

---

## 8. Local Audit Storage Security, Store Metadata & Filesystem Authority

### 8.1 Platform Security Primitives Contract

RC-06 persistent audit mode requires an underlying platform providing robust POSIX-style security primitives:

- Real UID ownership checks (`process.getuid()`).
- POSIX mode bits (`0700` directories, `0600` files).
- File descriptor `O_NOFOLLOW` open semantics.
- Atomic exclusive file creation (`O_CREAT | O_EXCL`).
- File descriptor inspection via `fstat()`.
- Directory persistence syncing via `fsync()`.

If any required security primitive is unsupported or unavailable on the host environment:
Startup halts immediately with `AUDIT_PLATFORM_UNSUPPORTED` and fails closed.
No weaker fallback mechanism or relaxed permission mode is permitted in production.

### 8.2 Directory Security & Path Resolution

- Configured via `audit.directory`. Default: `path.join(os.homedir(), '.cesspace-arc', 'audit')`.
- Configured custom paths MUST already be absolute. Paths containing literal shell-style `~` are rejected
  rather than shell-expanded.
- The directory may be created when absent using exclusive creation with mode `0700` (`rwx------`), then validated.
- Must resolve without traversing symlinks; parent directory trust and ownership are verified.
- Directory permissions MUST be exactly `0700`. Group or world access is forbidden.
- Directory MUST be owned by the real process UID.
- The audit directory and all parent path components MUST NOT be symbolic links.
- The audit directory MUST NOT reside inside, overlap with, or be a subdirectory of any agent workspace.

### 8.3 Persistent Store Metadata (`audit-store.json`)

To eliminate ambiguity across audit stores and bind ledger identity, fresh stores initialize a protected
metadata artifact: `audit-store.json` (mode `0600`).

```typescript
export interface AuditStoreMetadataV1 {
  version: 1;
  storeId: string; // UUIDv4
  createdAt: string; // ISO-8601 UTC
  checkpointPublicKeyFingerprint: string; // 64 lowercase hex SHA-256 of Ed25519 SPKI
  anchorMode: 'DISABLED' | 'ENABLED';
  anchorReceiptPublicKeyFingerprint?: string; // required iff anchorMode === 'ENABLED'
}
```

Rules:

1. Created exactly once for a fresh audit store using atomic exclusive creation (`O_CREAT | O_EXCL`).
2. Mode `0600`, owner real UID, regular file, `nlink === 1`, symlinks rejected.
3. Validated descriptor verified via `fstat()` after open.
4. File and parent directory `fsync()`ed before the first audit record is accepted.
5. Existing non-empty stores require valid `audit-store.json`. Missing, tampered, or unsupported metadata fails startup.
6. `storeId` is an immutable UUIDv4 identifying the audit ledger for its entire operational lifetime.
7. `checkpointPublicKeyFingerprint` is immutable in RC-06; attempting to start an existing store with a different checkpoint signer fails closed.
8. Changing `anchorMode` or `anchorReceiptPublicKeyFingerprint` on an existing non-empty store is strictly OUT OF SCOPE for RC-06.

### 8.4 File Security Authority

For all active, archived, checkpoint, metadata, spool, and receipt files:

- Must be **regular files only** (`stats.isFile() === true`). FIFOs, sockets, character/block devices are rejected.
- Hard link count MUST be exactly 1 (`stats.nlink === 1`). Hard-linked files are rejected.
- File permissions MUST be exactly `0600` (`rw-------`).
- File ownership MUST match the process real UID.
- Files are opened using `O_NOFOLLOW`, and the resulting file descriptor is verified via `fstat()` prior to I/O.
- Subsequent reads, writes, and syncs use the validated descriptor.

---

## 9. Single-Writer Process Locking (`O_CREAT | O_EXCL`)

To prevent concurrent appends, sequence collisions, or competing rotations:

1. **Lock Mechanism:** The server acquires an exclusive lock by atomically creating `audit.lock`
   using `O_CREAT | O_EXCL` (`'wx'`) open flags.
2. **Lock Properties:** Mode `0600`, regular file, no symlinks, no hard links (`nlink === 1`).
3. **Payload:** Contains bounded diagnostic JSON metadata: `{ "pid": <number>, "startedAt": "<ISO-8601>" }`.
4. **Collision Behavior:** If `audit.lock` exists (`EEXIST`), startup fails immediately with `AUDIT_STORE_LOCKED`.
5. **No Automatic Stale-Lock Takeover:** Heartbeat-based automatic takeover is strictly forbidden.
   If a previous process crashed leaving a stale lock, startup fails closed; removal requires
   explicit operator intervention while ARC is stopped.
6. **Clean Release:** On clean shutdown, `audit.lock` is closed, unlinked, and the parent directory is `fsync()`ed.

---

## 10. Segment Rotation & Streaming Compression Contract

### 10.1 Rotation Triggers

Active segments rotate when EITHER threshold is met:

1. **Size Threshold (Hard Security Limit):** Active segment reaches or exceeds **10 MiB** (`10,485,760` bytes).
2. **Time Threshold (Operational Convenience):** Exactly **24 hours** (`86,400` seconds) elapsed since first record.
   - _Clock Skew Semantics:_ Clock manipulation cannot alter record order, sequence continuity, hash integrity,
     checkpoint coverage, or the hard 10 MiB rotation limit. It may affect only the operational 24-hour convenience trigger.

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

### 10.4 Streaming Compression & Deletion Contract

- Rotated segments are compressed using streaming `gzip` (`node:zlib`).
- Gzip compression, verification, and SHA-256 chain verification operate strictly in a streaming manner.
- No complete 10 MiB segment is loaded or buffered in memory.
- Decompressed bytes are validated record-by-record under `MAX_RECORD_BYTES`.
- The uncompressed `.jsonl` file MUST NOT be deleted until the resulting `.jsonl.gz` file has been
  stream-decompressed, verified against the SHA-256 chain, and verified intact.
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
  storeId: string; // UUIDv4 matching audit-store.json
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
  storeId,
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
  storeId,
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

## 13. Trust Roots & Checkpoint Signing Key Authority

### 13.1 Signing Key Authority (`audit.signingKeyPath`)

- Algorithm: **Ed25519 (RFC 8032)** via native `node:crypto`.
- Format: PKCS#8 Ed25519 private key PEM file.
- Bound: Maximum key file size **4 KiB** (`MAX_SIGNING_KEY_BYTES = 4,096` bytes).
- Authority: Regular file, mode `0600`, real process UID owned, `nlink === 1`, symlinks rejected.
- Must reside outside all agent workspaces.
- Opened with `O_NOFOLLOW` and validated via `fstat()` prior to parsing.
- Strictly prohibited: `process.argv`, ambient environment variables, MCP headers, configuration literals, logs.
- Memory hygiene: Transient PEM input buffers are zeroized (`.fill(0)`) where practical after `createPrivateKey()`. Key descriptors are closed promptly.

### 13.2 Trust Root File Authority (`audit.publicKeyPath` & `audit.anchorReceiptPublicKeyPath`)

`audit.publicKeyPath` and `audit.anchorReceiptPublicKeyPath` are security-sensitive trust roots even though
their contents are public keys. Both files are strictly validated under the same security authority:

- Regular file only (`stats.isFile() === true`).
- Mode exactly `0600`.
- Owner real process UID.
- Hard link count strictly 1 (`stats.nlink === 1`).
- Symlinks strictly rejected.
- Maximum size 4 KiB (`MAX_SIGNING_KEY_BYTES = 4,096` bytes).
- Opened with `O_NOFOLLOW` and validated via `fstat()` prior to reading.
- Parse from validated file descriptor; malformed or non-Ed25519 keys rejected.

### 13.3 Pinned Store Fingerprints

- On fresh store initialization, the SHA-256 fingerprint of the configured checkpoint public key is
  written to `audit-store.json.checkpointPublicKeyFingerprint`.
- Every checkpoint emitted must use that fingerprint.
- Starting a non-empty store with a different checkpoint public key fails startup closed.
- When Tier 3 is enabled, the configured receipt public key fingerprint must match
  `audit-store.json.anchorReceiptPublicKeyFingerprint`.
- A fingerprint identifies a key; cryptographic verification uses the actual public key bytes.

---

## 14. Tier 3: External Anchoring, Deterministic Spool & Receipt Verification Contract

Tier 3 establishes independent external non-repudiation by submitting signed checkpoints to an
external HTTPS anchor receiver and obtaining cryptographically signed receipts.

### 14.1 Deployment Modes (Disabled vs. Enabled)

Tier 1 and Tier 2 are mandatory in every RC-06 production audit store.
Tier 3 is an implemented but explicitly selectable deployment mode:

#### Anchor Disabled Mode

```text
anchorMode = DISABLED
anchorEndpoint absent
anchorReceiptPublicKeyPath absent
```

- No anchor spool directory created; no receipts required.
- `anchorState = DISABLED`.
- Offline verifier validates Tier 1 and Tier 2 and explicitly reports that external anchoring is not configured.
- The system MUST NOT claim Tier-3 or full-host-compromise protection.

#### Anchor Enabled Mode

```text
anchorMode = ENABLED
anchorEndpoint required
anchorReceiptPublicKeyPath required
```

- Both `anchorEndpoint` and `anchorReceiptPublicKeyPath` MUST be configured together.
- Partial configuration (e.g. endpoint present without key, or key without endpoint) fails startup immediately.
- Tier-3 positive acceptance flows remain mandatory for RC-06 implementation even when deployment chooses DISABLED.

### 14.2 Anchor Endpoint Validation

When Tier 3 is enabled:

- URI scheme MUST be exactly `https:`. Plaintext HTTP is strictly rejected.
- Embedded credentials (username or password) and URL fragments (`#`) are strictly prohibited.
- Maximum serialized endpoint string length: 2 KiB.
- Transport: TLS 1.3 minimum (`minVersion: 'TLSv1.3'`).
- Hostname and CA certificate verification is strictly mandatory; disabling certificate validation is impossible.
- HTTP redirects (3xx) are NOT automatically followed.
- Response body size is bounded to `MAX_ANCHOR_RECEIPT_BYTES = 2,048` bytes (2 KiB).

### 14.3 Request Timeout & Idempotency

- Total per-attempt network timeout: **5,000 ms** (`ANCHOR_REQUEST_TIMEOUT_MS = 5_000`), covering
  DNS resolution, TLS handshake, request transmission, and receipt body acquisition.
- `checkpointHash` serves as the Tier-3 idempotency key.
- Every anchor submission includes HTTP header:
  ```text
  Idempotency-Key: <checkpointHash>
  ```
- The external anchor contract guarantees that repeat submissions for the same `checkpointHash` return
  the identical logical receipt.
- ARC accepts repeat receipts with matching signatures as idempotent duplicates without duplicate acknowledgement.
- Conflicting receipts for an already acknowledged checkpoint cause ARC to reject the receipt and enter degraded anchor state.

### 14.4 Crash-Recoverable Spool Directory (`anchor-spool/`)

To guarantee crash recovery, pending checkpoints are spooled to individual files in a dedicated directory:

```text
anchor-spool/
  <checkpointHash>.json
```

Each file contains canonical JSON of the pending `AuditCheckpointV1`.

- Directory mode `0700`, owner real UID, no symlinks.
- Spool file mode `0600`, owner real UID, `nlink === 1`, no symlinks, created via `O_CREAT | O_EXCL`.
- Filename MUST match the lowercase 64-hex `checkpointHash`.

**Mandatory Persistence Ordering:**

```text
checkpoint artifact durably appended to audit-checkpoints.jsonl
  │
  ▼
spool file durably created in anchor-spool/ AND directory fsync()ed
  │
  ▼
network transmission to anchor endpoint may begin
```

A checkpoint MUST NEVER be transmitted before its crash-recoverable spool file is durably synced.

### 14.5 Receipt Persistence Ordering & Verification

- **Receipt Schema (`AnchorReceiptV1`):**
  ```typescript
  export interface AnchorReceiptV1 {
    version: 1;
    storeId: string; // UUIDv4 matching audit-store.json
    receiptId: string;
    checkpointHash: string; // 64 lowercase hex
    anchorTimestamp: string; // ISO-8601 UTC
    anchorKeyFingerprint: string; // 64 lowercase hex
    signature: string; // Base64url Ed25519 signature
  }
  ```
- **Receipt Verification:**
  ```text
  receiptDomain = "CESSPACE-ARC-ANCHOR-RECEIPT-V1\0"
  unsignedReceipt = canonicalJson({
    version: 1,
    storeId,
    receiptId,
    checkpointHash,
    anchorTimestamp,
    anchorKeyFingerprint
  })
  Ed25519.verify(receiptDomain || UTF8(unsignedReceipt), signature, anchorReceiptPublicKey) === true
  ```
- HTTP 200/201 alone is NOT acknowledgement; only a cryptographically verified receipt acknowledges a checkpoint.

**Mandatory Receipt Persistence Ordering:**

```text
verify receipt signature, storeId binding, and checkpointHash binding
  │
  ▼
append receipt durably to audit-anchors.jsonl
  │
  ▼
fdatasync() receipt file
  │
  ▼
unlink the pending spool file anchor-spool/<checkpointHash>.json
  │
  ▼
fsync() anchor-spool/ directory
```

### 14.6 Anchor Crash Recovery States

On startup before network retry:

- **State A (Acknowledged):** Checkpoint exists + valid receipt exists in `audit-anchors.jsonl` + spool file absent:
  Checkpoint is fully `ACKNOWLEDGED`.
- **State B (Pending):** Checkpoint exists + no receipt + spool file exists:
  Checkpoint is `PENDING`; network retry schedule continues.
- **State C (Spool Missing):** Checkpoint exists + no receipt + spool file missing:
  Reconstruct spool file durably from checkpoint artifact before serving privileged operations.
- **State D (Stale Spool File):** Checkpoint exists + valid receipt exists + spool file still exists:
  Receipt wins; delete the stale spool file and `fsync()` spool directory.
- **State E (Orphan Spool Entry):** Spool entry exists but no matching checkpoint in `audit-checkpoints.jsonl`:
  Integrity failure; startup fails closed.
- **State F (Orphan Receipt):** Receipt exists in `audit-anchors.jsonl` with no matching checkpoint:
  Integrity failure; startup fails closed.

### 14.7 Spool Backoff & Backpressure Limits

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
   - Anchor receipt public key (`audit.anchorReceiptPublicKeyPath`, when anchor mode is enabled).
2. **Verification Pipeline:**
   - Validates `audit-store.json` schema V1 and verifies pinned key fingerprints.
   - Validates JSON syntax and schema V1 structure (`schemaVersion: 1`).
   - Verifies contiguous sequence numbers (`1, 2, 3, ...`) with zero gaps or duplicates.
   - Verifies that `previousRecordHash` links match preceding records.
   - Recomputes canonical hash preimages and verifies `integrity.recordHash`.
   - Validates segment transitions and rotation continuity across uncompressed and `.jsonl.gz` files via streaming verification.
   - Verifies all checkpoint signatures against the checkpoint public key and verifies `storeId` binding.
   - Verifies the checkpoint hash chain (`previousCheckpointHash`).
   - When anchor mode is enabled, validates anchor receipts in `audit-anchors.jsonl` against the anchor public key, `storeId`, and checkpoint hashes.
   - In anchor disabled mode, reports Tier 1 + Tier 2 verified and notes external anchoring not configured.
3. **Exit Codes:** Clean exit (0) on full verification; non-zero exit with precise diagnostics on failure.

---

## 17. Local Operator Evidence Interface & Directory Export Contract

### 17.1 Local CLI Commands

1. `arc audit status`: Reports storage path, store ID, active segment, total segments, current sequence,
   last checkpoint sequence, unanchored checkpoint count, indeterminate recoveries, and health.
2. `arc audit verify [--dir <path>]`: Runs the full offline verification pipeline using public keys only.
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

Export Security Rules:

- The destination directory MUST NOT already exist; no overwrite is permitted.
- Destination MUST NOT be a symlink, and no parent component may be a symlink.
- Destination directory MUST NOT reside inside the audit store or any agent workspace.
- Maximum export size: **1 GiB** (`MAX_EXPORT_BYTES = 1,073,741,824` bytes).
- If export fails partially, the created output directory is removed ONLY if ARC created it fresh and
  cleanup can be executed safely; otherwise, export fails without touching pre-existing data.
- `manifest.json`:
  ```json
  {
    "version": 1,
    "storeId": "...",
    "sequenceRange": { "start": 1, "end": 5000 },
    "files": {
      "audit/audit-20260920-seq1-seq1000.jsonl.gz": { "sha256": "...", "bytes": 12345 }
    },
    "checkpointHashes": ["..."],
    "anchorReceiptIds": ["..."]
  }
  ```
- Authenticity is derived from the manifest file hashes, included checkpoint signatures, and anchor receipts.
  No private key is required or accessed during export.

---

## 18. Absolute Prohibition of Remote Audit Exposure

Remote MCP clients (stdio or mTLS gateway) MUST NOT receive any tools or endpoints to:

- Delete, truncate, or purge audit logs.
- Trigger log rotation manually.
- Alter audit configuration, paths, or thresholds.
- View, export, or search audit logs across sessions.
- Modify or inspect checkpoint signing keys, trust roots, or anchor credentials.

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
  6. Environment variable value redaction: raw environment variables cannot enter persistent JSONL.

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
3. **Clock Skew Resistance:** Clock manipulation cannot alter record order, sequence continuity, hash integrity,
   checkpoint coverage, or the hard 10 MiB rotation limit. It may affect only the operational 24-hour convenience trigger.

---

## 22. Startup Full-History Verification, Reconciliation & Health Reporting

### 22.1 Exact Full-History Startup Sequence

Before stdio or remote MCP tool service begins, startup MUST execute the following exact sequence:

```text
1.  Validate platform security primitives (Linux/POSIX, UID, 0600/0700, O_NOFOLLOW, O_CREAT|O_EXCL, fstat, fsync)
     │
     ▼
2.  Acquire single-writer process lock (audit.lock via O_CREAT | O_EXCL)
     │
     ▼
3.  Validate audit-store metadata (audit-store.json) and verify pinned trust roots
     │
     ▼
4.  Verify all retained primary segments (compressed archives and active segment)
     │
     ▼
5.  Verify checkpoint artifact chain and Ed25519 signatures in audit-checkpoints.jsonl
     │
     ▼
6.  Verify anchor receipts in audit-anchors.jsonl when anchor mode is enabled
     │
     ▼
7.  Reconcile anchor spool directory state (States A through F)
     │
     ▼
8.  Recover allowed torn active tail (up to 64 KiB to sidecar) if present
     │
     ▼
9.  Detect dangling STARTED operations lacking terminal records
     │
     ▼
10. Append and fdatasync() durable RECOVERY_INDETERMINATE records for all dangling operations
     │
     ▼
11. Establish runtime cursors (next sequence number, previousRecordHash, cache)
     │
     ▼
12. Begin privileged MCP tool service
```

Any error, validation failure, or integrity breach occurring before step 12 halts startup immediately
and fails closed: **no privileged tool dispatch is permitted**.

#### 22.1.1 Relationship Between Step 4 Verification and Step 8 Torn-Tail Recovery

The ordering between Step 4 and Step 8 is normatively defined as follows:

- **Step 4 Classification:** During Step 4 primary-segment verification, the verifier scans all retained segments. If the active segment contains an incomplete trailing record at EOF satisfying the criteria in §6.2.1, the verifier yields the special classification `RECOVERABLE_TORN_ACTIVE_TAIL`.
- **Deferred Tail Mutation:** This classification does NOT represent successful verification. Instead, it defers only the permitted sidecar isolation and segment truncation to Step 8.
- **Mandatory Re-Verification:** In Step 8, after writing the sidecar, fsyncing, and truncating the active segment, the resulting active segment **MUST be re-verified from the beginning**.
- **Fatal Rejection:** If any error other than `RECOVERABLE_TORN_ACTIVE_TAIL` is encountered in Step 4, startup halts immediately and fails closed; Step 8 is never reached.

### 22.2 Health Reporting & Staging

Safe health metadata exposes:

```typescript
{
  persistence: 'ACTIVE' | 'DEGRADED' | 'FAILED',
  integrity: 'VERIFIED' | 'FAILED',
  sequence: number,
  lastCheckpointSequence: number | null,
  unanchoredCheckpoints: number,
  anchorState: 'DISABLED' | 'HEALTHY' | 'DEGRADED' | 'FULL',
  indeterminateRecoveries: number
}
```

- **Task-2 Health Staging Contract:** Task 2 computes and returns `indeterminateRecoveries` as a bounded non-negative integer in its recovery result object. Production wiring of health metadata into `ArcMcpServer` is owned by Task 6 (`audit.indeterminateRecoveries`).
- **Secrecy:** Exposing filesystem paths, private keys, public key bodies, or anchor endpoints in health status is strictly forbidden.

---

## 23. Process Restart & Recovery Semantics

| State Component           | Durability across Restart | Post-Restart Behavior                                    |
| :------------------------ | :------------------------ | :------------------------------------------------------- |
| Record Chain & Sequence   | **Persistent**            | Resumes from `lastRecord.sequenceNumber + 1`             |
| `previousRecordHash`      | **Persistent**            | Initialized to `lastRecord.integrity.recordHash`         |
| Checkpoint History        | **Persistent**            | Loaded and bound to `previousCheckpointHash`             |
| Anchor Receipts           | **Persistent**            | Loaded from `audit-anchors.jsonl`                        |
| Unanchored Checkpoint Q   | **Persistent**            | Reconciled from `anchor-spool/`; resumes retries         |
| Store Metadata & Pin      | **Persistent**            | Verified from `audit-store.json`                         |
| Active Single-Writer Lock | **Volatile**              | Re-acquired exclusively on startup (`O_CREAT \| O_EXCL`) |
| In-Flight Append State    | **Volatile**              | Cleared; re-entrant state initialized fresh              |

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
ANCHOR_REQUEST_TIMEOUT_MS = 5,000 (5 seconds total network timeout)
MAX_TORN_TAIL_BYTES = 65,536 (64 KiB)
MAX_INSPECT_RECORDS = 100
MAX_EXPORT_BYTES = 1,073,741,824 (1 GiB)
MAX_SIGNING_KEY_BYTES = 4,096 (4 KiB)
RECENT_RECORDS_CACHE_LIMIT = 256 records
```

### 24.2 Minimal Production Configuration

```typescript
export interface AuditConfig {
  /** Storage directory path. Default: path.join(os.homedir(), '.cesspace-arc', 'audit'). */
  directory?: string;
  /** Path to Ed25519 private key PEM file for Tier 2 signing. Mandatory. */
  signingKeyPath: string;
  /** Path to Ed25519 public key PEM file for checkpoint verification. Mandatory. */
  publicKeyPath: string;
  /** External Tier 3 anchor HTTPS endpoint. Optional; required if anchor mode enabled. */
  anchorEndpoint?: string;
  /** Path to Ed25519 public key PEM file for anchor receipt verification. Optional; required if anchor mode enabled. */
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
- At no point is the 1 GiB history or a 10 MiB uncompressed segment loaded into memory.

---

## 26. Failure Modes & Sanitized Error Model

1. **Storage Unwritable / Full:** Operations aborted; surfaces `AUDIT_PERSISTENCE_FAILED` to remote clients.
2. **Integrity Corruption:** Startup halts immediately; surfaces `AUDIT_CORRUPTION_DETECTED` in local console.
3. **Lock Conflict:** Exits immediately with `AUDIT_STORE_LOCKED`.
4. **Anchor Spool Exhaustion:** Server enters `ANCHOR_SPOOL_FULL`; rejects all privileged tool executions.
5. **Platform Unsupported:** Startup halts immediately with `AUDIT_PLATFORM_UNSUPPORTED`.
6. **Recovery Reconciliation Failure:** Startup halts immediately with `AUDIT_RECOVERY_FAILED`.

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
10. Changing `anchorMode` or anchor trust key on an existing non-empty audit store.
11. RC-07 composite engineering tools.
12. RC-08 adversarial fuzzing and penetration testing.

---

## 30. Negative Security Control Catalog (RC06-NEG-01..108)

All 108 controls are contiguous, mandatory, and directly testable:

### Category 1: Filesystem Authority, Platform Primitives & Locking (RC06-NEG-01..15)

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
- **`RC06-NEG-11`**: Unsupported platform lacking `O_NOFOLLOW` or required POSIX primitives. Startup halts with `AUDIT_PLATFORM_UNSUPPORTED`.
- **`RC06-NEG-12`**: Second ARC process attempts lock on existing `audit.lock` (`O_CREAT | O_EXCL` fails with `EEXIST`). Startup halts with `AUDIT_STORE_LOCKED`.
- **`RC06-NEG-13`**: Stale lock takeover attempted without operator intervention. Automatic takeover rejected.
- **`RC06-NEG-14`**: Audit lock file is a symlink or hard link. Startup fails immediately.
- **`RC06-NEG-15`**: Configured audit directory path contains unexpanded literal `~`. Startup fails; shell expansion prohibited.

### Category 2: Store Metadata & Trust Roots (RC06-NEG-16..20)

- **`RC06-NEG-16`**: `audit-store.json` missing on non-empty audit store. Startup fails closed.
- **`RC06-NEG-17`**: Tampered or malformed `audit-store.json` metadata. Startup fails closed.
- **`RC06-NEG-18`**: Configured checkpoint public key fingerprint does not match `audit-store.json.checkpointPublicKeyFingerprint`. Startup fails closed.
- **`RC06-NEG-19`**: Configured anchor receipt public key fingerprint does not match `audit-store.json.anchorReceiptPublicKeyFingerprint` when anchor mode is enabled. Startup fails closed.
- **`RC06-NEG-20`**: Attempting to change checkpoint signer or anchor trust settings on existing non-empty store. Rejected.

### Category 3: Record Format & Schema V1 Validation (RC06-NEG-21..29)

- **`RC06-NEG-21`**: Record line missing terminating newline character (`\n`). Line rejected as malformed.
- **`RC06-NEG-22`**: Record line containing carriage return character (`\r`). Line rejected as malformed.
- **`RC06-NEG-23`**: Record containing raw `undefined` or `NaN`/`Infinity` values. Canonicalization fails.
- **`RC06-NEG-24`**: Record containing unescaped control characters (< `0x20` or NUL). Line rejected.
- **`RC06-NEG-25`**: Record with unsupported `schemaVersion` (e.g. `2` or `0`). Verifier rejects with `UNSUPPORTED_SCHEMA_VERSION`.
- **`RC06-NEG-26`**: Record missing mandatory top-level `schemaVersion: 1` field. Verification fails.
- **`RC06-NEG-27`**: Record containing unknown top-level field outside V1 schema. Verification fails.
- **`RC06-NEG-28`**: Single record exceeding `MAX_RECORD_BYTES` (64 KiB). Append rejected with `RECORD_TOO_LARGE`.
- **`RC06-NEG-29`**: Direct hash of stored line bytes asserted as `recordHash`. Rejected; verifier enforces hash preimage omission of `integrity.recordHash`.

### Category 4: Chain Continuity & Record Tampering (RC06-NEG-30..39)

- **`RC06-NEG-30`**: Sequence number gap introduced in persistent record stream. Verification fails.
- **`RC06-NEG-31`**: Duplicate sequence number in persistent record stream. Verification fails.
- **`RC06-NEG-32`**: Broken `previousRecordHash` link between adjacent records. Verification fails.
- **`RC06-NEG-33`**: Tampered record payload with original `recordHash`. Recomputation flags mismatch.
- **`RC06-NEG-34`**: Tampered `recordHash` with original payload. Verification flags mismatch.
- **`RC06-NEG-35`**: Middle record deletion from audit segment. Chain link break detected.
- **`RC06-NEG-36`**: Tail record truncation detectable relative to trusted signed checkpoint. Truncation detected.
  - _Task-2 Staging Contract:_ Detection of tail truncation relative to a signed checkpoint depends on checkpoint signature verification implemented in Task 4. Task 2 MUST NOT implement Ed25519 cryptography, key parsing, or checkpoint file parsing. Instead, Task 2 recovery and verification primitives accept an already-authenticated chain boundary interface:
    ```typescript
    interface TrustedPrimaryChainBoundary {
      sequenceNumber: number;
      recordHash: string; // 64 lowercase hex
    }
    ```
    Task-2 verification treats this boundary as trusted input supplied by an authenticated caller. It verifies that retained primary history contains exactly the specified `sequenceNumber` and `recordHash`. If retained history terminates before `sequenceNumber` or the hash at that sequence differs, truncation is detected and startup recovery fails closed. Task 4 will later produce this boundary after cryptographic Ed25519 checkpoint verification. Task-2 tests inject synthetic trusted boundaries to exercise NEG-36.
- **`RC06-NEG-37`**: Torn final record line from crash. Recovers cleanly via sidecar; historical chain preserved.
- **`RC06-NEG-38`**: Torn final record line accompanied by corrupted historical records. Startup fails closed.
- **`RC06-NEG-39`**: Attempted sequence number reset to 1 on restart with non-empty store. Rejected.

### Category 5: Universal Lifecycle, Crash Recovery & Execution Ordering (RC06-NEG-40..47)

- **`RC06-NEG-40`**: `STARTED` audit append failure before privileged read operation. Read aborted; zero execution.
- **`RC06-NEG-41`**: `STARTED` audit append failure before privileged mutation operation. Mutation aborted; zero side effects.
- **`RC06-NEG-42`**: `COMPLETED` audit append failure after privileged read. Gateway enters global `DEGRADED_AUDIT_FAILURE`.
- **`RC06-NEG-43`**: `COMPLETED` audit append failure after irreversible mutation. Gateway enters global `DEGRADED_AUDIT_FAILURE`.
- **`RC06-NEG-44`**: Subsequent privileged read attempt while in `DEGRADED_AUDIT_FAILURE`. Rejected immediately.
- **`RC06-NEG-45`**: Subsequent privileged mutation attempt while in `DEGRADED_AUDIT_FAILURE`. Rejected immediately.
- **`RC06-NEG-46`**: Dangling `STARTED` after simulated crash. Emits durable `RECOVERY_INDETERMINATE` record before serving.
- **`RC06-NEG-47`**: Recovery reconciliation append failure for dangling `STARTED`. Startup halts fail-closed.

### Category 6: Rotation, Compression & Full-History Startup (RC06-NEG-48..59)

- **`RC06-NEG-48`**: Rotation boundary sequence discontinuity between segments. Verifier flags sequence gap.
- **`RC06-NEG-49`**: Rotation boundary `previousRecordHash` mismatch between segments. Verifier flags chain break.
- **`RC06-NEG-50`**: Corrupted gzip archive in rotated segment detected during startup. Startup fails closed.
- **`RC06-NEG-51`**: Missing intermediate rotated segment in archive sequence detected during startup. Startup fails closed.
- **`RC06-NEG-52`**: Premature uncompressed segment deletion before streaming gzip integrity verification. Deletion prohibited.
- **`RC06-NEG-53`**: Rapid rotation causing filename timestamp collision. Sequence range suffix prevents overwrite.
- **`RC06-NEG-54`**: Rotated segment file permissions wider than `0600`. Verification flags insecure permissions.
- **`RC06-NEG-55`**: Compressed archive permissions wider than `0600`. Verification flags insecure permissions.
- **`RC06-NEG-56`**: Compressed archive hard-link count > 1 (`nlink != 1`). Archive loading rejected.
- **`RC06-NEG-57`**: Wall-clock rollback attempt to delay 24h rotation. Defeated by 10 MiB hard limit.
- **`RC06-NEG-58`**: Wall-clock forward jump attempt to bypass retention. Defeated by non-deletion policy.
- **`RC06-NEG-59`**: Startup against non-empty store with corrupted intermediate segment. Fails closed.

### Category 7: Storage Bounds & Non-Deletion Retention (RC06-NEG-60..63)

- **`RC06-NEG-60`**: Disk full (`ENOSPC`) during audit append. Append throws; state remains consistent.
- **`RC06-NEG-61`**: Short write during audit append. Partial write detected; rolls back or fails closed.
- **`RC06-NEG-62`**: Archived segment count reaches `MAX_ARCHIVE_SEGMENTS` (100). Halts privileged ops; zero auto-deletion.
- **`RC06-NEG-63`**: Cumulative storage budget reaches `TOTAL_AUDIT_BUDGET_BYTES` (1 GiB). Halts privileged ops; zero auto-deletion.

### Category 8: Tier 2 Signed Checkpoint Artifacts (RC06-NEG-64..74)

- **`RC06-NEG-64`**: Checkpoint artifact assigned audit `sequenceNumber`. Rejected; checkpoints are separate artifacts.
- **`RC06-NEG-65`**: Checkpoint sequence range mismatch with covered primary audit records. Verification fails.
- **`RC06-NEG-66`**: Checkpoint `terminalRecordHash` mismatch with actual terminal record. Verification fails.
- **`RC06-NEG-67`**: Checkpoint `previousCheckpointHash` chain link break. Verifier flags broken checkpoint chain.
- **`RC06-NEG-68`**: Checkpoint `storeId` mismatch with `audit-store.json`. Verifier flags ledger identity mismatch.
- **`RC06-NEG-69`**: Tampered checkpoint signature bytes. Signature verification fails.
- **`RC06-NEG-70`**: Checkpoint verified with wrong Ed25519 public key. Signature verification fails.
- **`RC06-NEG-71`**: Checkpoint signature algorithm downgrade attempt (e.g. RSA, none). Rejected.
- **`RC06-NEG-72`**: Replayed checkpoint from prior sequence range. Sequence validation fails.
- **`RC06-NEG-73`**: Out-of-order checkpoint artifact in `audit-checkpoints.jsonl`. Sequence continuity check fails.
- **`RC06-NEG-74`**: Checkpoint artifact file permissions wider than `0600` or hard-linked. Loading rejected.

### Category 9: Trust Roots & Key Authority (RC06-NEG-75..83)

- **`RC06-NEG-75`**: Signing key provided via command-line argument (`argv`). Startup fails immediately.
- **`RC06-NEG-76`**: Signing key provided via ambient environment variable. Startup fails immediately.
- **`RC06-NEG-77`**: Signing key supplied via remote MCP header or tool argument. Rejected.
- **`RC06-NEG-78`**: Checkpoint signing key file is a symlink. Key loading rejected.
- **`RC06-NEG-79`**: Checkpoint signing key file has hard-link count > 1 (`nlink != 1`). Key loading rejected.
- **`RC06-NEG-80`**: Checkpoint signing key file permissions wider than `0600`. Key loading rejected.
- **`RC06-NEG-81`**: Checkpoint signing key file owned by different UID. Key loading rejected.
- **`RC06-NEG-82`**: Checkpoint signing key exceeds `MAX_SIGNING_KEY_BYTES` (4 KiB). Key loading rejected.
- **`RC06-NEG-83`**: Checkpoint public key or anchor receipt public key trust root is a symlink, hard-linked, non-0600, or non-UID owned. Loading rejected.

### Category 10: Tier 3 External Anchoring, Spool & Receipts (RC06-NEG-84..99)

- **`RC06-NEG-84`**: Partial Tier-3 configuration (e.g. endpoint present without key or vice versa). Startup fails closed.
- **`RC06-NEG-85`**: External anchor connection attempt over plaintext HTTP. Rejected; HTTPS required.
- **`RC06-NEG-86`**: External anchor endpoint with embedded credentials or fragment. Startup rejected.
- **`RC06-NEG-87`**: External anchor request exceeds `ANCHOR_REQUEST_TIMEOUT_MS` (5,000 ms). Timeout enforced; checkpoint spooled.
- **`RC06-NEG-88`**: External anchor returns HTTP 5xx error. Checkpoint retained in spool; backoff retry initiated.
- **`RC06-NEG-89`**: HTTP 200 returned without cryptographic receipt. Not accepted as acknowledgement.
- **`RC06-NEG-90`**: Anchor receipt signed by untrusted key not matching `anchorReceiptPublicKeyPath`. Rejected.
- **`RC06-NEG-91`**: Anchor receipt bound to wrong `checkpointHash` or wrong `storeId`. Receipt rejected.
- **`RC06-NEG-92`**: Conflicting receipt identity for an already acknowledged checkpoint. Rejected; enters degraded anchor state.
- **`RC06-NEG-93`**: Repeat submission for same `checkpointHash` with same valid receipt accepted as idempotent duplicate.
- **`RC06-NEG-94`**: Anchor spool entry exists without matching checkpoint artifact in `audit-checkpoints.jsonl`. Startup fails closed.
- **`RC06-NEG-95`**: Checkpoint exists without receipt and spool file missing. Spool file reconstructed during startup before serving.
- **`RC06-NEG-96`**: Receipt persisted but stale spool file remains after crash. Reconciled cleanly without duplicate acknowledgement.
- **`RC06-NEG-97`**: Anchor spool queue exceeds `MAX_PENDING_ANCHOR_CHECKPOINTS` (100). Halts privileged ops.
- **`RC06-NEG-98`**: Anchor spool size exceeds `MAX_ANCHOR_SPOOL_BYTES` (1 MiB). Halts privileged ops.
- **`RC06-NEG-99`**: Anchor spool directory or file permissions wider than 0700/0600 or symlink. Loading rejected.

### Category 11: Central Redaction & Secrecy Hardening (RC06-NEG-100..104)

- **`RC06-NEG-100`**: Raw `Arc-Session-Token` secret in persistent JSONL. Centrally redacted to `[REDACTED_SECRET]`.
- **`RC06-NEG-101`**: Raw enrollment one-time secret or HTTP `Authorization` header in persistent JSONL. Centrally redacted.
- **`RC06-NEG-102`**: Raw PKCS#8 private key or X.509 certificate PEM in persistent JSONL. Centrally redacted.
- **`RC06-NEG-103`**: Raw environment variable values in persistent JSONL. Centrally omitted or masked to byte count.
- **`RC06-NEG-104`**: Absolute host workspace paths in persistent JSONL. Centrally redacted to `[REDACTED_PATH]` / root hash.

### Category 12: Administrative Isolation & Evidence Export Integrity (RC06-NEG-105..108)

- **`RC06-NEG-105`**: Remote MCP tool call attempting audit log deletion, truncation, or manual rotation. Rejected with `UNKNOWN_TOOL`.
- **`RC06-NEG-106`**: Evidence export destination directory already exists or attempts overwrite. Rejected.
- **`RC06-NEG-107`**: Evidence export destination is a symlink or contains symlink parent components. Rejected.
- **`RC06-NEG-108`**: Evidence export inside audit directory or inside an agent workspace, or exceeding `MAX_EXPORT_BYTES` (1 GiB). Rejected.

---

## 31. Threat-to-Control Matrix

| Threat Description                              | Primary Defense Mechanism                                 | Enforcement Tier | Negative Controls |
| :---------------------------------------------- | :-------------------------------------------------------- | :--------------- | :---------------- |
| Host user edits historical JSONL records        | SHA-256 hash chaining + Ed25519 signatures                | Tier 1 & 2       | NEG-30..35        |
| Tail truncation to conceal malicious tool run   | Tier 2 signed checkpoints & Tier 3 anchor receipts        | Tier 2 & 3       | NEG-36, 66        |
| Secret extraction from audit trail              | Centralized pre-hash redaction & minimization             | Tier 1           | NEG-100..104      |
| Disk exhaustion denial-of-service via log flood | Segment size caps, rotation & bounded budgets             | Tier 1           | NEG-28, 62, 63    |
| Side-effect execution without audit record      | Pre-dispatch sync & fail-closed execution order           | Tier 1           | NEG-40..45        |
| Crash after STARTED leaves dangling operation   | Startup reconciliation to RECOVERY_INDETERMINATE          | Tier 1           | NEG-46, 47        |
| Concurrent process audit log corruption         | Exclusive single-writer lockfile (`O_CREAT \| O_EXCL`)    | Tier 1           | NEG-12, 13, 14    |
| Host root rewrites local chain & checkpoints    | Tier 3 external anchor cryptographic receipts             | Tier 3           | NEG-85..93        |
| Remote MCP agent tampers with audit subsystem   | Strict local operator isolation & no MCP tools            | Architecture     | NEG-105           |
| Signing key exfiltration from environment       | Restricted 0600 file / FD-only key loading                | Tier 2           | NEG-75..82        |
| Evidence export directory path traversal        | Strict directory export validation & workspace separation | Tool / Operator  | NEG-106..108      |

---

## 32. Positive Acceptance Flows (Flows 1..23)

1. **Flow 1: Fresh Persistent Store Initialization:** Server boots with clean audit directory; creates `audit-store.json`, `audit.lock`, and active segment; logs first record (`seq: 1`, `prevHash: 000...000` virtual genesis hash); file permissions verified `0600`.
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
12. **Flow 12: Compressed Archive Generation & Verified Deletion:** Rotated segment compressed to `.jsonl.gz`; uncompressed file verified via streaming decompression before removal; permissions verified `0600`.
13. **Flow 13: Tier 2 Checkpoint Artifact Generation:** Chain reaches 1,000 records; generates signed checkpoint in `audit-checkpoints.jsonl` with `storeId`; verifies Ed25519 signature.
14. **Flow 14: Offline Public-Key Checkpoint Verification:** Standalone verifier validates checkpoint signature using public key without accessing private key.
15. **Flow 15: Tier 3 External Anchor Dispatch & Cryptographic Receipt:** Checkpoint transmitted via HTTPS to anchor service; valid signed receipt received and recorded in `audit-anchors.jsonl`.
16. **Flow 16: Anchor Outage Spooling & Automatic Backoff Catch-Up:** Anchor server temporarily down; checkpoints queued in `anchor-spool/<checkpointHash>.json`; server recovers and catches up.
17. **Flow 17: Local Operator `arc audit status`:** Operator executes CLI status command; receives accurate summary of store health, store ID, sequence count, and recoveries.
18. **Flow 18: Local Operator `arc audit inspect`:** Operator pages through recent records; receives redacted records within bounded limit.
19. **Flow 19: Universal Pre-Dispatch Durability:** Privileged read and privileged mutation each demonstrate durable `STARTED` -> subsystem dispatch -> durable `COMPLETED`, bound by `operationId`.
20. **Flow 20: Full Restart Verification of Retained History:** Server restarts with compressed archives, active segment, checkpoints, and receipts; verifies full retained history before serving.
21. **Flow 21: Crash-Indeterminate Lifecycle Reconciliation:** Simulate crash after durable `STARTED` before terminal record; on restart, engine detects dangling `operationId`, appends durable `RECOVERY_INDETERMINATE` record, and begins privileged service only after durable sync succeeds.
22. **Flow 22: Standalone Offline Verification Command:** Run `arc audit verify` against multi-segment history with checkpoints, receipts when enabled, and compressed archives; full verification succeeds using public keys only.
23. **Flow 23: Deterministic Evidence Export Verification:** Run `arc audit export --output <new-dir>`; verify directory bundle structure, recompute every manifest digest, verify selected sequence range and checkpoint signatures, and confirm no private key was read.

---

## 33. Historical Documentation Reconciliation

| Historical Document & Section           | Stale / Ambiguous Claim                            | RC-06 Normative Specification                                                                |
| :-------------------------------------- | :------------------------------------------------- | :------------------------------------------------------------------------------------------- |
| `audit-model.md §5`                     | Ambient default path `~/.cesspace-arc/audit/`      | Resolved to `path.join(os.homedir(), '.cesspace-arc', 'audit')`; literal `~` rejected.       |
| `audit-model.md §5`                     | 50 MB segment rotation threshold                   | Reduced to **10 MiB** to optimize in-memory verification and streaming hash performance.     |
| `audit-model.md §4.2` & `ADR-0004 §2.3` | Tier 2: "Signed HMAC / Private Key"                | Resolved normatively to **asymmetric digital signatures (Ed25519 / RFC 8032)**.              |
| `audit-model.md §4.2`                   | "Supervisor daemon signs checkpoints"              | Integrated in-process cryptographic engine signing via secure 0600 key file or inherited FD. |
| `audit-model.md §3.2` & `ADR-0004 §2.2` | "Entropy Analysis" for credential detection        | **Explicitly rejected** due to false positives; replaced with allowlist, key-names, & regex. |
| `audit-model.md §2`                     | `sequenceNumber` described as "per session"        | Unified into **one process-wide monotonic sequence space** across all sessions and gateway.  |
| `audit-model.md §2`                     | Audit schema lacks approval & gateway metadata     | Formally incorporated `AuditApprovalMetadata` and `AuditGatewayMetadata` from RC-04 & RC-05. |
| `package-ownership.md`                  | "Evidence packager" assigned to `packages/audit`   | Assigned to `packages/audit` engine with CLI exposure in `apps/cli` (`arc audit export`).    |
| `rc05-scope-acceptance.md §16`          | Persistent storage and external anchoring deferred | Fully implemented and closed by RC-06.                                                       |
| Prior Scope Draft                       | Self-referential full-line record hash             | Resolved to explicit hash preimage omitting `integrity.recordHash`.                          |
| Prior Scope Draft                       | Synthetic "genesis record" terminology             | Corrected to virtual zero genesis previous hash.                                             |
| Prior Scope Draft                       | Automatic retention deletion on anchor             | Removed; capacity limits are fail-closed; no auto-deletion of raw evidence in RC-06.         |
| Prior Scope Draft                       | Tar/ZIP evidence export                            | Resolved to deterministic directory bundle export (no external compression libraries).       |
| Prior Scope Draft                       | `fcntl/flock` portable locking                     | Resolved to atomic `O_CREAT \| O_EXCL` lockfile creation.                                    |
| Prior Scope Draft                       | Bearer token anchor authentication                 | Removed; sender/receiver Ed25519 cryptographic signatures provide mutual authenticity.       |
| Prior Scope Draft                       | Spool JSONL file                                   | Resolved to crash-recoverable spool directory `anchor-spool/<checkpointHash>.json`.          |
| Prior Scope Draft                       | Unspecified crash outcome for dangling operations  | Resolved to explicit `RECOVERY_INDETERMINATE` reconciliation record on startup.              |
| Prior Scope Draft                       | Unpinned store identity                            | Resolved to protected `audit-store.json` metadata artifact pinning `storeId` and signer.     |
| Prior Scope Draft                       | Decompressing full 10 MiB segment in memory        | Corrected to streaming gzip decompression and streaming verification.                        |

---

## 34. Implementation Breakdown (Tasks 1..8)

| #   | Title                                                | Scope                                                                                                              | Expected Files                                                                                                                                                  | Invariants & Quality Standards                           | Controls               | Depends On | Stop Boundary                     |
| :-- | :--------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------- | :--------------------- | :--------- | :-------------------------------- |
| 1   | Persistent Append Storage, Protocol, Metadata & Lock | Protocol schema V1, `AuditStoreMetadataV1`, disk append engine, 0700/0600, lockfile, POSIX platform capability     | `packages/protocol/src/audit.ts`, `packages/audit/src/storage.ts`, `packages/audit/src/metadata.ts`, `packages/audit/src/lock.ts`, `tests/rc06-storage.test.js` | Inv-13, O_CREAT\|EXCL, hash preimage, store metadata     | NEG-01..29             | None       | Storage tests pass cleanly        |
| 2   | Restart Recovery, Torn Tails & Dangling Operations   | Virtual genesis, restart continuation, torn-tail recovery, dangling STARTED reconciliation, cursors                | `packages/audit/src/recovery.ts`, `tests/rc06-recovery.test.js`                                                                                                 | Strict continuity, RECOVERY_INDETERMINATE append         | NEG-30..39, 46..47     | Task 1     | Recovery tests pass cleanly       |
| 3   | Segment Rotation, Streaming Compression & Budget     | 10 MiB / 24h rotation, streaming `.jsonl.gz`, fail-closed retention budget, bounded ring cache                     | `packages/audit/src/rotation.ts`, `tests/rc06-rotation.test.js`                                                                                                 | Streaming verification, no auto-delete, 256-cache        | NEG-48..63             | Task 2     | Rotation tests pass cleanly       |
| 4   | Tier 2 Ed25519 Checkpoint Artifacts & Key Authority  | Ed25519 signing engine, key security, trust roots, `AuditCheckpointV1`, storeId binding, checkpoint artifact file  | `packages/audit/src/checkpoint.ts`, `tests/rc06-checkpoint.test.js`                                                                                             | RFC 8032, no key in argv/env, public key verify, storeId | NEG-64..83             | Task 3     | Checkpoint tests pass cleanly     |
| 5   | Tier 3 External Anchoring Client, Spool & Receipts   | Optional anchor mode, HTTPS client, timeout, spool directory, retry/idempotency, `AnchorReceiptV1`, crash recovery | `packages/audit/src/anchor.ts`, `tests/rc06-anchor.test.js`                                                                                                     | Bounded spool dir, backpressure, signed receipts         | NEG-84..99             | Task 4     | Anchor tests pass cleanly         |
| 6   | Universal Lifecycle & Full-History Startup Engine    | Wire `ArcMcpServer`, `STARTED`/`COMPLETED` sync, full-history verify, fail-closed DEGRADED_AUDIT_FAILURE, health   | `apps/mcp-server/src/index.ts`, `tests/rc06-runtime-durability.test.js`                                                                                         | INV-13, fail-closed on read/mutation, health status      | NEG-40..45             | Task 5     | Runtime tests pass cleanly        |
| 7   | Local Operator CLI & Standalone Offline Verifier     | `arc audit status/verify/inspect/export`, directory bundle pack, path isolation                                    | `apps/cli/src/audit.ts`, `packages/audit/src/verify.ts`, `packages/audit/src/export.ts`, `tests/rc06-cli-verifier.test.js`                                      | Public key only verifier, directory export bounds        | NEG-105..108           | Task 6     | CLI & verifier tests pass cleanly |
| 8   | Secrecy Hardening, Acceptance & Public Version Bump  | Central redaction, env/workspace path masking, 108 negative controls, 23 flows, verify script, version bump        | `tests/rc06-negative-controls.test.js`, `tests/rc06-positive-flows.test.js`, `scripts/verify-rc06.sh`                                                           | Version 0.6.0-rc06, all 108 controls & 23 flows pass     | NEG-100..104 (All 108) | Task 7     | All quality gates pass            |

### 34.1 Task 2 Staging Contract, Scope Boundaries & Control Ownership

- **Active Stream Recovery Scope:** Task 2 implements reusable recovery and verification primitives for the currently available primary active stream:
  - Virtual genesis verification (`sequenceNumber === 1`, zero `previousRecordHash`).
  - Sequential continuity and record hash validation.
  - Restart cursor recovery (recovering sequence number and last record hash from active segment).
  - Allowed torn active-tail recovery (`RECOVERABLE_TORN_ACTIVE_TAIL`, sidecar creation, truncation, re-verification).
  - Trusted chain boundary verification (`TrustedPrimaryChainBoundary` for `RC06-NEG-36`).
  - Dangling lifecycle detection, malformed lifecycle history rejection, and canonical `RECOVERY_INDETERMINATE` reconciliation appends.
- **Staging vs Full-History Production Engine:**
  - Task 2 primitives operate against the active segment and synthetic test boundaries.
  - Task 3 later introduces rotated/compressed segments (`.jsonl.gz`).
  - Task 4 later introduces Ed25519 checkpoint verification.
  - Task 5 later introduces external anchoring and receipts.
  - Task 6 composes all of those primitives into the complete production full-history startup engine (`ArcMcpServer`).
  - Task 2 does NOT implement or claim full multi-segment archive, checkpoint signature, or anchor receipt verification.
- **Checkpoint Dependency Staging (`RC06-NEG-36`):**
  - Task 2 accepts an already-authenticated chain boundary interface (`TrustedPrimaryChainBoundary`).
  - Task 2 MUST NOT parse Ed25519 keys, verify checkpoint signatures, or persist checkpoint artifacts.
  - Synthetic trusted boundaries are injected in Task-2 tests to exercise `RC06-NEG-36`.
- **Health Metric Staging:**
  - Task 2 computes and returns `indeterminateRecoveries: number` in its recovery result.
  - Full server health reporting wiring (`audit.indeterminateRecoveries`) is owned by Task 6.
- **Strict Control Ownership:**
  - Task 2 owns exactly: `RC06-NEG-30..39` and `RC06-NEG-46..47`.
  - Task 6 owns: `RC06-NEG-40..45`.
  - Task 3 owns: `RC06-NEG-48..63`.

---

## 35. Definition of Done (RC-06)

RC-06 is complete and ready for merge when:

1. **Persistent canonical V1 single-chain audit storage:** All audit records are written to canonical JSONL files with sequential SHA-256 hash chaining under schema V1.
2. **Universal durable lifecycle for reads and mutations:** Pre-dispatch audit syncing (`STARTED` phase) satisfies INV-13 for all reads and mutations; terminal outcomes recorded via `COMPLETED` or `DENIED`.
3. **Crash-indeterminate operation reconciliation:** Unfinished `STARTED` operations are reconciled on startup with durable `RECOVERY_INDETERMINATE` records before privileged tool dispatch begins.
4. **Secure store metadata and pinned checkpoint identity:** Fresh audit stores initialize `audit-store.json` with immutable `storeId` and pinned checkpoint public key fingerprint.
5. **Secure filesystem authority and Linux/POSIX primitive enforcement:** Auditing operates strictly within owner-only (`0700`/`0600`) directories protected by exclusive `O_CREAT | O_EXCL` writer locks and POSIX platform primitives.
6. **Full-history startup verification:** Startup verifies all retained archives, uncompressed segments, checkpoints, and receipts before serving MCP tools.
7. **Streaming rotation/compression verification:** Active segments rotate deterministically at 10 MiB or 24h and compress to `.jsonl.gz` after streaming verification.
8. **Bounded production memory:** Production logger holds bounded cursor and 256-record ring cache; all verification, inspection, and export procedures stream from disk.
9. **Zero automatic raw-evidence deletion:** Retention limits prevent log-saturation DoS with zero automatic deletion or wrapping of raw evidence.
10. **Ed25519 checkpoint artifacts:** Checkpoint artifacts signed with Ed25519 are recorded in `audit-checkpoints.jsonl` every 1,000 records or upon segment rotation.
11. **Tier-3 anchor implementation with signed receipts and deterministic crash recovery:** Signed checkpoints are dispatched over HTTPS to independent anchors with crash-recoverable spool directory, backpressure, and verified cryptographic receipts.
12. **Optional deployment semantics for Tier 3 with honest health/security claims:** Anchor mode is selectable (`DISABLED` vs `ENABLED`); disabled mode reports no external anchoring and claims no Tier-3 protections.
13. **Offline verifier:** Standalone CLI tool validates full history and checkpoint signatures using public keys only.
14. **Local-only audit status/verify/inspect/export:** `arc audit status`, `verify`, `inspect`, and `export` operate locally without exposing remote MCP endpoints.
15. **Deterministic evidence-directory export:** Generates self-contained directory bundles with canonical `manifest.json` and strict destination path isolation.
16. **Central redaction/secrecy:** Central pre-hash redaction guarantees that secrets, tokens, keys, raw environment variables, and absolute paths never reach persistent logs.
17. **All 108 negative controls contiguous and passing:** Every control from `RC06-NEG-01` through `RC06-NEG-108` is implemented, contiguous, and verified.
18. **All 23 positive acceptance flows passing:** Every flow from Flow 1 through Flow 23 is implemented and verified.
19. **Complete RC-01 through RC-05 regression green:** Existing unit, integration, and gateway test suites pass cleanly.
20. **`scripts/verify-rc06.sh`:** Complete verification script implemented, passing, and runnable.
21. **`pnpm run verify:rc06`:** Package script registered and passing cleanly.
22. **RC-06 final integration report written and accurate:** Comprehensive integration report documenting final architecture, evidence, and verification.
23. **Public version `0.6.0-rc06`; health stage `RC-06`:** Version bumped and health metadata updated.
24. **Exact-head feature push CI green:** GitHub Actions push-CI passes cleanly on feature head.
25. **Final PR opened from reviewed feature head to `main`:** Formal pull request created with verified commits and diff.
26. **PR CI green including Dependency Review:** PR validation passes all checks including GitHub Dependency Review.
27. **Independent final PR review:** PR receives independent sign-off prior to merge.
28. **Merge without unreviewed history mutation:** Merged to `main` preserving exact commit history.
29. **Exact merge-head `main` CI green:** Post-merge CI on `main` passes cleanly.
30. **RC-06 closure only after post-merge independent verification:** Formal milestone closure following independent post-merge audit.

---

## 36. Open Questions

**Open Questions: None**

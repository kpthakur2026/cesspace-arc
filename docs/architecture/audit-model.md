# Audit & Evidence Model — CesSpace ARC

> **Document:** Audit Architecture Specification
> **Status:** RC-00 Proposed Baseline — Pending Independent Review
> **Classification:** Security & Compliance Subsystem

---

## 1. Overview & Purpose

The **CesSpace ARC Audit Subsystem** (`packages/audit`) provides an append-only chronological record of all operations, decisions, and outcomes across the control plane.

Because autonomous agents operate without constant line-by-line human supervision, auditing is critical for:

1. **Security Forensics:** Reconstructing the exact sequence of tool calls and parameter values leading to an incident.
2. **Attribution:** Associating actions with specific agent clients, session tokens, and human approvers.
3. **Stage-Gate Verification:** Providing concrete proof of verification outcomes and test runs.
4. **Data Minimization:** Ensuring sensitive information is excluded at the source.

---

## 2. Structured Audit Event Schema

Audit events are emitted as self-contained JSON objects structured according to the following canonical schema:

```typescript
export interface AuditRecord {
  // Unique event identifier (UUIDv4)
  eventId: string;

  // ISO 8601 UTC timestamp of event generation
  timestamp: string;

  // Sequential sequence number per session (monotonic)
  sequenceNumber: number;

  // Actor identification
  actor: {
    clientId: string; // e.g. "antigravity-worker-01"
    clientType: string; // e.g. "antigravity", "claude-code"
    deviceId: string; // Cryptographic or machine fingerprint
    sessionId: string; // Unique session identifier
  };

  // Target environment
  target: {
    workspaceId: string; // Unique identifier of workspace
    workspacePath: string; // Canonical path (sanitized)
  };

  // Invocation details
  invocation: {
    toolName: string; // e.g. "read_file", "run_command"
    // Tool arguments with sensitive patterns strictly redacted
    parametersRedacted: Record<string, unknown>;
    payloadHash: string; // SHA-256 of canonical JSON payload
  };

  // Policy evaluation details
  policy: {
    decision: 'ALLOW' | 'REQUIRE_APPROVAL' | 'DENY';
    ruleId: string; // ID of winning rule
    evaluationDurationMs: number;
    approvalId?: string; // Reference to human approval record if applicable
  };

  // Execution lifecycle and outcome
  execution: {
    status: 'SUCCESS' | 'ERROR' | 'DENIED' | 'TIMEOUT' | 'CANCELLED';
    startTime: string;
    endTime: string;
    durationMs: number;
    exitCode?: number; // For terminal/process commands
    bytesRead?: number;
    bytesWritten?: number;
    changedFiles?: string[]; // Relative paths modified by operation
  };

  // Sanitized error information (if failed)
  error?: {
    code: string; // Standardized error code
    message: string; // Opaque, sanitized error message
  };

  // Tamper-evidence metadata
  integrity: {
    previousRecordHash: string; // SHA-256 hash of previous audit entry
    recordHash: string; // SHA-256 hash of current audit entry
  };
}
```

---

## 3. Secret Protection: Data Minimization First

No automated redaction algorithm can guarantee zero secret leakage under all arbitrary string representations. Therefore, CesSpace ARC adopts a **Data Minimization First** strategy, using active redaction as defense-in-depth:

### 3.1. Primary Defense: Allowlisted Metadata Logging

- By default, tool arguments are **not dumped verbatim** into the audit log.
- Only allowlisted operational metadata is logged:
  - Tool name, target workspace ID, canonical relative paths.
  - Cryptographic hash (`payloadHash = SHA-256(canonicalPayload)`) for offline non-repudiation without storing raw data.
  - Operation start time, duration, status, and exit code.
- File contents read or written are never logged in full text.

### 3.2. Secondary Defense: Automated Redaction (Defense-in-Depth)

For diagnostic parameters or error messages that may contain incidental credentials:

1. **Key-Name Filtering:** Fields matching sensitive keys (`token`, `secret`, `password`, `key`, `authorization`, `credential`) are masked to `"[REDACTED_BY_NAME]"`.
2. **Regex Scanners:** Standard token patterns (e.g. AWS access keys, GitHub tokens, Bearer headers, OpenAI/Anthropic keys) are replaced with `"[REDACTED_API_KEY]"`.
3. **Entropy Analysis:** High-entropy substrings exceeding normal natural-language thresholds are flagged and masked.

---

## 4. Threat Model & Audit Integrity Boundaries

### 4.1. Local Hash Chaining Limitations

A purely local SHA-256 hash chain provides tamper evidence against uncoordinated append anomalies or accidental file corruption. However, within a rigorous threat model:

> **An attacker or compromised process with write access to the host audit directory can recompute the entire SHA-256 hash chain or truncate records from the tail.** A local hash chain alone cannot be considered "unalterable."

### 4.2. Tiered Integrity Hardening Strategy

To provide defensible non-repudiation across stages:

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│ TIER 1 (RC-01 / RC-06 Local Baseline): Sequential SHA-256 Hash Chain              │
│ - Monotonic sequence numbers and previousRecordHash binding                      │
│ - Restrictive filesystem permissions (0600, dedicated service user)              │
│ - Threat Boundary: Protects against unprivileged tampering and accidental edits  │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│ TIER 2 (Cryptographic Checkpoint Signing): Signed HMAC / Private Key             │
│ - Periodic checkpoint records signed by a supervisor process                     │
│ - Signing key stored outside agent-accessible memory (e.g. OS keychain / root)   │
│ - Threat Boundary: Detects retroactive history rewriting by local user processes  │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│ TIER 3 (External / WORM Anchoring): Remote Append-Only Sink                       │
│ - Real-time streaming to remote syslog / WORM (Write Once Read Many) storage     │
│ - Periodic root hash publication to external timestamping service / ledger        │
│ - Threat Boundary: Full host compromise cannot erase previously anchored logs    │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Storage Format & Rotation

- **Format:** JSON Lines (`.jsonl`), where each line is a valid JSON `AuditRecord`.
- **Location:** Local audit logs are stored in a dedicated directory (`~/.cesspace-arc/audit/`) with restrictive `0600` file permissions.
- **Rotation:** Logs rotate daily or when file size exceeds 50 MB, with automated compression (`.jsonl.gz`).
- **Append-Only Mode:** Files are opened with `O_APPEND | O_CREAT` flags to prevent overwriting historical entries.

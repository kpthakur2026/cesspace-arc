# Audit & Evidence Model — CesSpace ARC

> **Document:** Audit Architecture Specification
> **Status:** RC-00 Approved Baseline
> **Classification:** Security & Compliance Subsystem

---

## 1. Overview & Purpose

The **CesSpace ARC Audit Subsystem** (`packages/audit`) provides an unalterable, append-only chronological record of all operations, decisions, and outcomes across the control plane.

Because autonomous agents operate without constant line-by-line human supervision, auditing is critical for:
1. **Security Forensics:** Reconstructing the exact sequence of tool calls and parameter values leading to an incident.
2. **Attribution:** Associating actions with specific agent clients, session tokens, and human approvers.
3. **Stage-Gate Verification:** Providing concrete, cryptographic proof of verification outcomes and test runs.
4. **Zero Secret Leakage:** Guaranteeing that secrets and credentials never persist in audit storage.

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
    clientId: string;        // e.g. "antigravity-worker-01"
    clientType: string;      // e.g. "antigravity", "claude-code"
    deviceId: string;        // Cryptographic or machine fingerprint
    sessionId: string;       // Unique session identifier
  };

  // Target environment
  target: {
    workspaceId: string;     // Unique identifier of workspace
    workspacePath: string;   // Canonical path (sanitized)
  };

  // Invocation details
  invocation: {
    toolName: string;        // e.g. "read_file", "run_command"
    // Tool arguments with sensitive patterns strictly redacted
    parametersRedacted: Record<string, unknown>;
    payloadHash: string;     // SHA-256 of canonical JSON payload
  };

  // Policy evaluation details
  policy: {
    decision: "ALLOW" | "REQUIRE_APPROVAL" | "DENY";
    ruleId: string;          // ID of winning rule
    evaluationDurationMs: number;
    approvalId?: string;     // Reference to human approval record if applicable
  };

  // Execution lifecycle and outcome
  execution: {
    status: "SUCCESS" | "ERROR" | "DENIED" | "TIMEOUT" | "CANCELLED";
    startTime: string;
    endTime: string;
    durationMs: number;
    exitCode?: number;       // For terminal/process commands
    bytesRead?: number;
    bytesWritten?: number;
    changedFiles?: string[]; // Relative paths modified by operation
  };

  // Sanitized error information (if failed)
  error?: {
    code: string;            // Standardized error code
    message: string;         // Opaque, sanitized error message
  };

  // Tamper-evidence metadata
  integrity: {
    previousRecordHash: string; // SHA-256 hash of previous audit entry
    recordHash: string;         // SHA-256 hash of current audit entry
  };
}
```

---

## 3. Mandatory Automated Secret Redaction

Audit records are intended to be persistent and reviewable by engineers. Therefore, **secrets must NEVER enter the audit log.**

### 3.1. Prohibited Items
The redaction engine permanently masks:
- Bearer tokens, JWTs, and API keys.
- Private cryptographic keys (`BEGIN RSA PRIVATE KEY`, `BEGIN OPENSSH PRIVATE KEY`).
- Passwords and basic auth strings (`user:pass@host`).
- AWS secret access keys, GCP service account tokens.
- Content read from or written to blacklisted paths.

### 3.2. Redaction Mechanics
Before any record is written to disk or transmitted over the wire:
1. **Key-Name Matching:** Any parameter key containing sensitive terms (`token`, `password`, `secret`, `key`, `authorization`, `credential`, `cert`) has its value automatically replaced with `"[REDACTED_BY_NAME]"`.
2. **High-Entropy String Detection:** Values with high Shannon entropy exceeding standard natural language thresholds are evaluated and masked.
3. **Regex Pattern Scanners:** Regexes match known token formats (e.g., `ghp_[A-Za-z0-9_]{36}`, `sk-[A-Za-z0-9]{32,}`, `AKIA[0-9A-Z]{16}`) and replace them with `"[REDACTED_API_KEY]"`.

---

## 4. Tamper-Evident Hash Chaining

To ensure that audit logs cannot be retroactively modified, reordered, or truncated by a rogue agent or compromised process:

1. **Hash Chain:** Each audit record includes `integrity.previousRecordHash`, which contains the SHA-256 digest of the preceding log entry.
2. **Current Record Digest:** `integrity.recordHash` is computed over the canonical JSON serialization of the current record (excluding the hash field itself).
3. **Genesis Record:** The first record in an audit log session uses a known constant for `previousRecordHash` (`0000000000000000000000000000000000000000000000000000000000000000`).
4. **Verification Utility:** An offline verification tool recomputes the hash chain from start to finish to detect any tampering or truncation.

---

## 5. Storage Format & Rotation

- **Format:** JSON Lines (`.jsonl`), where each line is a valid JSON `AuditRecord`.
- **Location:** Local audit logs are stored in a dedicated, permission-restricted directory (e.g. `~/.cesspace-arc/audit/` or designated workspace audit directory) with `0600` file permissions.
- **Rotation:** Logs rotate daily or when file size exceeds 50 MB, with automated compression (`.jsonl.gz`).
- **Append-Only Mode:** Files are opened with `O_APPEND | O_CREAT` flags to prevent overwriting historical entries.

# ADR-0004: Append-Only Structured Audit Logging with Mandatory Secret Redaction

* **Status:** Accepted
* **Date:** 2026-09-17
* **Deciders:** Architecture Team

---

## Context

Autonomous AI agents make hundreds of fine-grained tool calls during engineering sessions. When unexpected failures, unwanted modifications, or security incidents occur, forensic analysis requires an accurate, chronological record of every decision and action.

However, naive audit logging creates a severe secondary risk: sensitive data (such as API keys, bearer tokens, or password arguments) may be permanently captured into log files, turning the audit log into a credential harvesting vector. Furthermore, an attacker gaining local execution might attempt to delete or alter audit records to cover their tracks.

## Decision

We establish an **Append-Only Structured Audit Subsystem** (`packages/audit`) with the following invariants:

1. **Structured JSONL Records:** Every tool invocation, policy decision, approval event, and execution outcome emits a strongly typed JSON audit record.
2. **Mandatory Real-Time Secret Redaction:** All parameters and error payloads pass through a multi-pass redaction filter (sensitive key matching, high-entropy token detection, and pattern scanners) before being written to disk.
3. **Cryptographic Tamper-Evidence:** Records incorporate sequential hash chaining (each entry includes the SHA-256 hash of the previous record), allowing independent verification of log continuity.
4. **Append-Only Storage:** Log files are written strictly in append mode (`O_APPEND`) with restrictive file permissions (`0600`).

## Consequences

### Positive
- Complete forensic traceability and non-repudiation for all agent operations.
- Guarantees zero credential persistence in audit records.
- Enables cryptographic verification that audit logs have not been truncated or tampered with.

### Negative / Trade-offs
- Slight I/O overhead on every tool invocation (mitigated by asynchronous buffered flushing).
- Redaction regexes must be maintained and updated as new token formats emerge.

# ADR-0004: Structured Audit Logging, Data Minimization, and Tiered Anchoring

- **Status:** Accepted
- **Date:** 2026-09-17
- **Deciders:** Architecture Team

---

## Context

Autonomous AI agents make hundreds of fine-grained tool calls during engineering sessions. When unexpected failures, unwanted modifications, or security incidents occur, forensic analysis requires an accurate, chronological record of every decision and action.

However, naive audit logging creates two severe secondary risks:

1. **Secret Leakage:** Sensitive parameters or raw file contents may be recorded, converting the audit trail into a credential harvesting target. Automated redaction alone cannot guarantee zero leakage across arbitrary formats.
2. **Integrity Limits of Local Logs:** A local SHA-256 hash chain alone is tamper-evident against casual editing, but an attacker with host write permissions to the audit directory can recompute or truncate an unanchored hash chain.

## Decision

We establish an authoritative **Structured Audit Subsystem** (`packages/audit`) with data minimization and tiered integrity:

1. **Phased Evolution over Single Pipeline:**
   - **RC-01:** Synchronous in-memory/stream structured audit sink capturing every tool call and decision.
   - **RC-06:** Full persistent append-only storage, log rotation, and external anchoring.
2. **Data Minimization First:**
   - Standard audit records log allowlisted metadata only (tool name, workspace ID, relative paths, duration, exit code, and SHA-256 payload hash).
   - Raw file contents and large argument bodies are never recorded in plaintext.
   - Automated regex/entropy redaction acts as defense-in-depth on parameters and error messages.
3. **Tiered Integrity & Anchoring Strategy:**
   - **Tier 1 (Local Baseline):** Monotonic sequence numbers and local SHA-256 hash chaining with `0600` permissions.
   - **Tier 2 (Signed Checkpoints):** Supervisor daemon signs periodic checkpoint digests using private key material inaccessible to the agent.
   - **Tier 3 (External Anchoring):** Real-time streaming or periodic hash publication to remote WORM (Write Once Read Many) storage or an independent log.

## Consequences

### Positive

- Complete forensic traceability and non-repudiation for all agent operations.
- Data minimization protects user privacy and eliminates secret capture at the source.
- Tiered anchoring prevents history rewriting even if local workspace processes are compromised.

### Negative / Trade-offs

- Remote WORM anchoring requires network configuration during later stages (RC-06).
- Debugging complex payload issues requires recalculating payload hashes rather than reading raw bodies from audit records.

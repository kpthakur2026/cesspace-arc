# Architecture Decision Records (ADRs) — CesSpace ARC

This directory contains the formal records of architecturally significant decisions made for **CesSpace ARC**.

---

## ADR Index

| ADR Number | Title | Status | Date |
| :--- | :--- | :--- | :--- |
| [ADR-0001](0001-mcp-as-standard-protocol.md) | Use Model Context Protocol (MCP) as Standard Agent Interface | **Accepted** | 2026-09-17 |
| [ADR-0002](0002-default-deny-policy-engine.md) | Default-Deny Policy Engine with Strict Precedence | **Accepted** | 2026-09-17 |
| [ADR-0003](0003-canonical-filesystem-jailing.md) | Canonical Path Resolution and Symlink Containment | **Accepted** | 2026-09-17 |
| [ADR-0004](0004-structured-audit-and-redaction.md) | Append-Only Structured Audit Logging with Mandatory Secret Redaction | **Accepted** | 2026-09-17 |
| [ADR-0005](0005-fail-closed-error-handling.md) | Fail-Closed Error Model and Information Disclosure Prevention | **Accepted** | 2026-09-17 |
| [ADR-0006](0006-monorepo-modular-architecture.md) | Monorepo Structure with Strict Layered Dependencies | **Accepted** | 2026-09-17 |

---

## ADR Format

Each record follows the standard Michael Nygard format:
- **Title:** Number and short title.
- **Status:** Proposed, Accepted, Superseded, or Deprecated.
- **Context:** The context, problem statement, and forces influencing the decision.
- **Decision:** The specific architectural choice made.
- **Consequences:** The positive, negative, and neutral trade-offs of the decision.

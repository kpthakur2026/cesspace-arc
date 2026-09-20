# CesSpace ARC — Secure Agent-to-Machine Control Plane

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Stage](https://img.shields.io/badge/Stage-RC--05%20Secure%20Remote%20Gateway-blue.svg)](#roadmap)
[![Security Policy](https://img.shields.io/badge/Security-Default%20Deny-red.svg)](SECURITY.md)
[![Engineering Governance](https://img.shields.io/badge/Governance-Engineering%20Rules-brightgreen.svg)](docs/governance/engineering-governance.md)
[![Node](https://img.shields.io/badge/Node-24-green.svg)](#toolchain)
[![pnpm](https://img.shields.io/badge/pnpm-12.4.2-orange.svg)](#toolchain)

> **CesSpace ARC (Agent Remote Control)** is a secure, vendor-neutral control plane providing policy-enforced, audited access to development machines, virtual machines, repositories, terminals, and processes for authorized AI coding agents.
> **Lead Developer & Architect:** P Thakur

---

## 1. Mission & Vision

Modern AI coding agents (Claude Code, Antigravity, OpenAI Codex, OpenCode, DeepSeek agents) require rich interactions with host environments—reading files, inspecting diffs, running tests, and executing builds. However, giving autonomous agents unrestricted ambient access (such as open SSH keys, raw `/bin/sh` evaluation, or unfettered root access) creates severe security risks:

- Accidental or malicious filesystem destruction.
- Credential harvesting (`~/.ssh`, `~/.aws`, `.env`).
- Indirect prompt injection leading to remote code execution.
- Silent repository or supply chain tampering.

**CesSpace ARC mediates every single agent action through an authoritative policy engine, an OS-level filesystem jail, and an append-only audit trail.**

---

## 2. High-Level Target Architecture

```text
AI Client / Coding Agent (Claude Code / Antigravity / Codex / DeepSeek)
                          │
                          ▼
             MCP Interface (JSON-RPC 2.0)
                          │
     ═════════════════════╪═══════════════════════ Trust Boundary 1 (Ingress)
                          ▼
                 ARC Remote Gateway
                & Authentication Engine
                          │
     ═════════════════════╪═══════════════════════ Trust Boundary 2 (Policy)
                          ▼
                    Policy Engine
            (RC-01: Minimal Security Kernel;
             RC-04: Declarative Rules & Approvals;
             Precedence: DENY > REQUIRE APPROVAL > ALLOW)
                          │
                          ▼
                     Audit Layer
            (RC-01: In-Memory / Stream Sink;
             RC-06: Anchored Persistent Log)
                          │
     ═════════════════════╪═══════════════════════ Trust Boundary 3 (Host Execution)
                          ▼
                    ARC VM Agent
                          │
         ┌────────────────┼────────────────┬────────────────┐
         ▼                ▼                ▼                ▼
    Filesystem           Git            Terminal        Processes
  (Jailed Roots)   (Branch Guard)    (Bounded execve)  (Tree Superv.)
```

> **Mandatory Invariant:** No Filesystem, Git, Terminal, or Process operation may ever execute without traversing the full **Authentication $\to$ Policy Engine $\to$ Audit Layer** pipeline. In RC-01, this invariant is satisfied via the **Minimal Security Kernel**, which enforces default-deny admission, canonical workspace root binding, and audit logging before any tool runs.

---

## 3. The 20 Permanent Security Principles

1. **Zero implicit trust**
2. **Default deny**
3. **Least privilege**
4. **Fail closed**
5. **Separation of authentication and authorization**
6. **Mandatory policy mediation for every privileged operation**
7. **No policy bypass**
8. **Authorized filesystem roots only (strict canonical jailing & descriptor containment)**
9. **Secrets and credential stores permanently inaccessible by default**
10. **Policy-controlled subprocess execution without shell interpolation**
11. **Destructive operations denied by default**
12. **Zero cloud-root or production access in public defaults**
13. **Universal auditability for every privileged action**
14. **Protected Git branches (`main`, `release/*`) immutable to agents**
15. **Explicit human approval for sensitive mutations**
16. **Prohibition of private CES secrets, infrastructure details, and tokens**
17. **Permanence of committed secrets (Git history treated as public and forever)**
18. **Vendor neutrality across AI model providers and platforms**
19. **Code-enforced security invariants (never documentation alone)**
20. **Mandatory negative controls proving blocked operations fail**

---

## 4. Documentation Index

The complete architecture and security foundation of CesSpace ARC is documented below:

| Document                                                                                 | Description                                                                                                |
| :--------------------------------------------------------------------------------------- | :--------------------------------------------------------------------------------------------------------- |
| [**Architecture Overview**](docs/architecture/overview.md)                               | High-level system architecture, component breakdown, MCP standard, and architectural invariants.           |
| [**Trust Boundaries**](docs/architecture/trust-boundaries.md)                            | The 4 security zones and 3 trust boundaries isolating untrusted agents.                                    |
| [**Threat Model**](docs/threat-model/threat-model.md)                                    | STRIDE analysis, AI threat vectors (prompt injection, symlink escapes, DoS).                               |
| [**Security Invariants**](docs/architecture/security-invariants.md)                      | The 20 inviolable security invariants and their verification criteria.                                     |
| [**MCP Tool Taxonomy**](docs/architecture/tool-taxonomy.md)                              | Formal schemas and permission tiers for all read-only, mutating, and composite tools.                      |
| [**Permission Model**](docs/architecture/permission-model.md)                            | `ALLOW`, `REQUIRE APPROVAL`, `DENY` outcomes, precedence, Minimal Security Kernel, and approval lifecycle. |
| [**Filesystem Boundary Model**](docs/architecture/filesystem-boundary.md)                | Workspace jailing, canonical realpath checks, symlink containment, Linux `openat2`, and blacklist.         |
| [**Audit & Evidence Model**](docs/architecture/audit-model.md)                           | Append-only event schemas, data minimization first, redaction, and tiered anchoring.                       |
| [**Structured Error Model**](docs/architecture/error-model.md)                           | Fail-closed error taxonomy and anti-leakage information sanitization.                                      |
| [**Package Ownership**](docs/architecture/package-ownership.md)                          | Monorepo package layout, component boundaries, and dependency DAG.                                         |
| [**Architecture Decision Records**](docs/adr/README.md)                                  | Formal ADRs capturing key design and security decisions.                                                   |
| [**RC-01 Scope & Acceptance**](docs/architecture/rc01-scope-acceptance.md)               | Detailed scope, Minimal Security Kernel, tool list, and negative control criteria for RC-01.               |
| [**RC-02 Scope & Acceptance**](docs/architecture/rc02-scope-acceptance.md)               | Detailed scope, controlled terminal and process execution, and negative control criteria for RC-02.        |
| [**RC-03 Scope & Acceptance**](docs/architecture/rc03-scope-acceptance.md)               | Detailed scope, safe file modification and patch engine, and negative control criteria for RC-03.          |
| [**RC-04 Scope & Acceptance**](docs/architecture/rc04-scope-acceptance.md)               | Detailed scope, declarative policy engine, approval state machine, and the 38 frozen negative controls.    |
| [**RC-04 Final Integration Report**](docs/architecture/rc04-final-integration-report.md) | RC-04 acceptance evidence: architecture summary, control coverage table, and final quality gates.          |
| [**RC-05 Scope & Acceptance**](docs/architecture/rc05-scope-acceptance.md)               | Detailed scope, secure remote gateway, Streamable HTTP over TLS 1.3, mTLS, and 79 negative controls.       |
| [**RC-05 Final Integration Report**](docs/architecture/rc05-final-integration-report.md) | RC-05 acceptance evidence: architecture summary, control coverage table, and final quality gates.          |
| [**Engineering Governance**](docs/governance/engineering-governance.md)                  | Mandatory project engineering, stage-gate, and security governance rules.                                  |
| [**Security Policy**](SECURITY.md)                                                       | Vulnerability disclosure, responsible reporting, and safety invariants.                                    |
| [**Contributing Guide**](CONTRIBUTING.md)                                                | Guidelines for contributing code, tests, and security negative controls.                                   |

---

## 5. Toolchain & Monorepo Configuration

CesSpace ARC is standardized on:

- **Node.js:** `^24.0.0`
- **Package Manager:** `pnpm@12.4.2` (`pnpm-workspace.yaml`)
- **Internal Dependency Protocol:** `workspace:*`
- **Access:** All internal packages are marked `private: true` during development stages.

---

## 6. Development Roadmap & Stages

| Stage     | Name                                   | Target Capabilities                                                                                       | Status      |
| :-------- | :------------------------------------- | :-------------------------------------------------------------------------------------------------------- | :---------- |
| **RC-00** | **Architecture & Security Foundation** | Trust boundaries, threat models, invariants, tool taxonomy, ADRs.                                         | Implemented |
| **RC-01** | **Read-Only MCP Core**                 | Minimal Security Kernel, 9 read-only tools, canonical jailing, negative controls.                         | Implemented |
| **RC-02** | **Controlled Terminal & Processes**    | Bounded process execution, output limits, timeout enforcement.                                            | Implemented |
| **RC-03** | **Safe File Modification**             | Jailed file writing, atomic patches, size limits, approval gating.                                        | Implemented |
| **RC-04** | **Policy Engine & Approvals**          | Declarative YAML policy engine, authenticated admin channel, approval tokens, approval audit lifecycle.   | Implemented |
| **RC-05** | **Secure Remote Gateway**              | Streamable HTTP over TLS 1.3 with SSE response framing, mutual TLS, device enrollment, volatile sessions. | Implemented |
| **RC-06** | **Audit & Evidence**                   | Append-only JSONL logging, tiered anchoring, automated redaction.                                         | Planned     |
| **RC-07** | **Engineering-Aware Tools**            | Composite verification commands (`arc_verify`, `arc_stage_evidence`).                                     | Planned     |
| **RC-08** | **Integrations & Security Review**     | Cross-client validation, penetration testing, fuzzing.                                                    | Planned     |

---

## 7. License

CesSpace ARC is licensed under the [Apache License, Version 2.0](LICENSE).

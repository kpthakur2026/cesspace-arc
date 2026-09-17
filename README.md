# CesSpace ARC — Secure Agent-to-Machine Control Plane

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Stage](https://img.shields.io/badge/Stage-RC--00%20Architecture%20Foundation-orange.svg)](#roadmap)
[![Security Policy](https://img.shields.io/badge/Security-Default%20Deny-red.svg)](SECURITY.md)
[![Agent Guidelines](https://img.shields.io/badge/Agents-AGENTS.md-brightgreen.svg)](AGENTS.md)

> **CesSpace ARC (Agent Remote Control)** is a secure, vendor-neutral control plane providing policy-enforced, audited access to development machines, virtual machines, repositories, terminals, and processes for authorized AI coding agents.

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
            DENY > REQUIRE APPROVAL > ALLOW
                          │
                          ▼
                     Audit Layer
             (Tamper-Evident & Redacted)
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

> **Mandatory Invariant:** No Filesystem, Git, Terminal, or Process operation may ever execute without traversing the full **Authentication $\to$ Policy Engine $\to$ Audit Layer** pipeline.

---

## 3. The 20 Permanent Security Principles

1. **Zero implicit trust**
2. **Default deny**
3. **Least privilege**
4. **Fail closed**
5. **Separation of authentication and authorization**
6. **Mandatory policy mediation for every privileged operation**
7. **No policy bypass**
8. **Authorized filesystem roots only (strict canonical jailing)**
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

| Document | Description |
| :--- | :--- |
| [**Architecture Overview**](docs/architecture/overview.md) | High-level system architecture, components, and communication protocols. |
| [**Trust Boundaries**](docs/architecture/trust-boundaries.md) | The 4 security zones and 3 trust boundaries isolating untrusted agents. |
| [**Threat Model**](docs/threat-model/threat-model.md) | STRIDE analysis, AI threat vectors (prompt injection, symlink escapes, DoS). |
| [**Security Invariants**](docs/architecture/security-invariants.md) | The 20 inviolable security invariants and their verification criteria. |
| [**MCP Tool Taxonomy**](docs/architecture/tool-taxonomy.md) | Formal schemas and permission tiers for all read-only, mutating, and composite tools. |
| [**Permission Model**](docs/architecture/permission-model.md) | `ALLOW`, `REQUIRE APPROVAL`, `DENY` outcomes, precedence, and approval lifecycle. |
| [**Filesystem Boundary Model**](docs/architecture/filesystem-boundary.md) | Workspace jailing, canonical realpath checks, symlink rules, and blacklist. |
| [**Audit & Evidence Model**](docs/architecture/audit-model.md) | Append-only event schemas, real-time secret redaction, and hash chaining. |
| [**Structured Error Model**](docs/architecture/error-model.md) | Fail-closed error taxonomy and anti-leakage information sanitization. |
| [**Package Ownership**](docs/architecture/package-ownership.md) | Monorepo package layout, component boundaries, and dependency DAG. |
| [**Architecture Decision Records**](docs/adr/README.md) | Formal ADRs capturing key design and security decisions. |
| [**RC-01 Scope & Acceptance**](docs/architecture/rc01-scope-acceptance.md) | Detailed scope, tool list, and negative control criteria for RC-01. |
| [**Agent Guidelines**](AGENTS.md) | Mandatory operating directives for autonomous coding agents. |
| [**Security Policy**](SECURITY.md) | Vulnerability disclosure, responsible reporting, and safety invariants. |
| [**Contributing Guide**](CONTRIBUTING.md) | Guidelines for contributing code, tests, and security negative controls. |

---

## 5. Development Roadmap & Stages

| Stage | Name | Target Capabilities | Status |
| :--- | :--- | :--- | :--- |
| **RC-00** | **Architecture & Security Foundation** | Trust boundaries, threat models, invariants, tool taxonomy, ADRs. | **In Review (Current)** |
| **RC-01** | **Read-Only MCP Core** | 9 read-only tools, canonical path jailing, negative controls. | Upcoming |
| **RC-02** | **Controlled Terminal & Processes** | Bounded process execution, output limits, timeout enforcement. | Planned |
| **RC-03** | **Safe File Modification** | Jailed file writing, atomic patches, size limits, approval gating. | Planned |
| **RC-04** | **Policy Engine** | Declarative YAML policy engine, AST matchers, approval tokens. | Planned |
| **RC-05** | **Secure Remote Gateway** | Remote MCP over HTTPS/SSE, mutual TLS, device enrollment. | Planned |
| **RC-06** | **Audit & Evidence** | Append-only JSONL logging, hash chaining, automated redaction. | Planned |
| **RC-07** | **Engineering-Aware Tools** | Composite verification commands (`arc_verify`, `arc_stage_evidence`). | Planned |
| **RC-08** | **Integrations & Security Review**| Cross-client validation, penetration testing, fuzzing. | Planned |

---

## 6. Monorepo Structure

```text
cesspace-arc/
├── apps/
│   ├── mcp-server/         # MCP server runtime (stdio & SSE transports)
│   └── cli/                # Local management and approval CLI
│
├── packages/
│   ├── protocol/           # Core MCP contracts, JSON-RPC types, error schemas
│   ├── policy/             # Policy engine & authorization evaluator
│   ├── audit/              # Append-only audit logger with automated redaction
│   ├── auth/               # Identity, session tokens, and device enrollment
│   ├── filesystem/         # Jailed path resolution and safe filesystem operations
│   ├── git/                # Sandboxed Git operations & branch protection
│   ├── terminal/           # Controlled command runner with timeout supervision
│   └── processes/          # Host process tracking and resource limits
│
├── docs/                   # Complete architecture, threat models, and ADRs
├── examples/               # Sanitized policies and configuration templates
└── scripts/                # Static analysis, secret scanning, and verification scripts
```

---

## 7. License

CesSpace ARC is licensed under the [Apache License, Version 2.0](LICENSE).

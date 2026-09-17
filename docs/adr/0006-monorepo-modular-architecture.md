# ADR-0006: Monorepo Structure with Strict Layered Dependencies

* **Status:** Accepted
* **Date:** 2026-09-17
* **Deciders:** Architecture Team

---

## Context

CesSpace ARC contains protocol definitions, policy enforcement, audit logging, host subsystems (filesystem, git, terminal, processes), and client/server applications (MCP server, CLI).

If components are tightly coupled or organized into a monolithic package, the following risks emerge:
- Circular dependencies between policy evaluation, audit logging, and tool dispatchers.
- Accidental bypasses where execution code calls host system APIs directly without traversing policy middleware.
- Difficulty in isolating dependencies and running focused security verification tests.

## Decision

We adopt a **modular monorepo structure** (npm workspaces) governed by strict unidirectional dependency rules:

```text
packages/protocol (Zero dependencies, pure contracts)
       ▲
       ├── packages/policy (Authorization engine)
       ├── packages/audit (Logging & redaction)
       ├── packages/auth (Session authentication)
       ├── packages/filesystem (Jailed path resolver)
       ├── packages/processes (Process tree supervisor)
       │        ▲
       │        └── packages/git (Git operations)
       │        └── packages/terminal (Subprocess execution)
       │                 ▲
       └─────────────────┴── apps/mcp-server & apps/cli
```

1. **Pure Protocol Base:** `packages/protocol` defines all types, interfaces, schemas, and error codes with zero external dependencies.
2. **Subsystem Isolation:** Host drivers (`filesystem`, `git`, `terminal`, `processes`) do not depend on network transports or application servers.
3. **No Downward Leakage:** Transport layers (`apps/mcp-server`) can import subsystems, but subsystems can never import or depend on transports.
4. **No Circular Dependencies:** Circular imports are disallowed and enforced via static linting.

## Consequences

### Positive
- Enforces clear architectural separation of concerns.
- Makes policy enforcement points obvious and auditable.
- Enables granular unit testing and independent security negative controls per package.

### Negative / Trade-offs
- Managing monorepo package manifests and workspace linkages requires disciplined build and typecheck configurations.

# CesSpace ARC — Secure Agent-to-Machine Control Plane

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Stage](https://img.shields.io/badge/Stage-ARC--1.0%20Core-blue.svg)](#release-and-platform-support)
[![Security Policy](https://img.shields.io/badge/Security-Default%20Deny-red.svg)](SECURITY.md)
[![Node](https://img.shields.io/badge/Node-24-green.svg)](#development)
[![pnpm](https://img.shields.io/badge/pnpm-12.4.2-orange.svg)](#development)

> **CesSpace ARC (Agent Remote Control)** is a secure, vendor-neutral control plane that provides policy-enforced, audited access to development machines, repositories, terminals, and processes for authorized AI clients and coding agents.

## Overview

Modern MCP-compatible AI clients need controlled access to host environments for tasks such as reading files, inspecting diffs, running tests, and managing processes. Direct ambient access creates material security risks, including destructive filesystem actions, credential exposure, prompt-driven command execution, and repository tampering.

CesSpace ARC places an explicit security boundary between the client and the host. Every privileged operation is mediated through authentication, policy evaluation, approval where required, and audit before the relevant subsystem can execute.

## Architecture

```text
AI Client / Coding Agent
          |
          v
MCP Interface
          |
          v
ARC Gateway & Authentication
          |
          v
Policy Engine
          |
          v
Approval + Audit
          |
          v
Authorized Workspace
   |        |        |        |
 Files    Git    Terminal  Processes
```

The core invariant is simple:

> No filesystem, Git, terminal, or process operation may execute without traversing the ARC security pipeline.

## Key capabilities

- **Default-deny policy enforcement** with explicit `DENY > REQUIRE_APPROVAL > ALLOW` precedence.
- **Human approval** for sensitive or mutating operations.
- **Workspace containment** with canonical path checks and strict filesystem boundaries.
- **Controlled Git operations** with protected-branch safeguards.
- **Bounded terminal and process execution** without shell interpolation.
- **Durable audit evidence** with redaction, integrity checks, and fail-closed behavior.
- **Vendor-neutral MCP interoperability** for standards-conformant clients.
- **Local operation** without requiring a CesSpace account or hosted service.

## Release and platform support

The current stable release is **CesSpace ARC Core 1.0.0**.

- **Supported:** Linux x86-64
- **Development-compatible:** WSL Linux userspace
- **Validation-only:** Linux arm64 and macOS
- **Unsupported:** native Windows host execution

Canonical release and publisher information are maintained in [PUBLISHER.md](PUBLISHER.md).

## Security

ARC is designed around zero implicit trust, least privilege, fail-closed behavior, mandatory policy mediation, explicit approval for sensitive actions, and append-only audit evidence.

See:

- [Security Policy](SECURITY.md)
- [Threat Model](docs/threat-model/threat-model.md)
- [Trust Boundaries](docs/architecture/trust-boundaries.md)
- [Security Invariants](docs/architecture/security-invariants.md)
- [Permission Model](docs/architecture/permission-model.md)
- [Filesystem Boundary](docs/architecture/filesystem-boundary.md)
- [Audit & Evidence Model](docs/architecture/audit-model.md)

## Installation and operation

Start with the operator documentation:

- [Installation](docs/distribution/installation.md)
- [Configuration & Upgrade](docs/distribution/configuration-upgrade.md)
- [Stable Release](docs/distribution/stable-release.md)

Example configuration and policy templates are available under [`examples/`](examples/).

## Documentation

Architecture and implementation references:

- [Architecture Overview](docs/architecture/overview.md)
- [MCP Tool Taxonomy](docs/architecture/tool-taxonomy.md)
- [Structured Error Model](docs/architecture/error-model.md)
- [Package Ownership](docs/architecture/package-ownership.md)
- [Architecture Decision Records](docs/adr/README.md)

Historical release-candidate acceptance documents remain in the repository because current source, verification scripts, and tests reference them. They are engineering evidence, not the primary product documentation surface.

## Development

CesSpace ARC uses:

- **Node.js:** `^24.0.0`
- **Package manager:** `pnpm@12.4.2`
- **Workspace protocol:** `workspace:*`

Common checks:

```bash
pnpm install --frozen-lockfile
pnpm run check:format
pnpm run lint
pnpm run typecheck
pnpm run test
pnpm run build
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before proposing changes.

## Public repository policy

The public repository contains ARC Core source, stable release information, operator documentation, security/privacy material, contribution guidance, and technical verification evidence.

Private CesSpace strategy, commercial planning, internal delivery sequencing, and private infrastructure details do not belong on the public branch.

See [Public Repository Policy](docs/governance/public-repository-policy.md).

## Security reporting

Do not open a public issue for a suspected vulnerability.

Follow the private reporting process in [SECURITY.md](SECURITY.md).

## Publisher and identity

Official publisher, release provenance, and distribution identity are documented in [PUBLISHER.md](PUBLISHER.md).

Trademark and branding rules are documented in [TRADEMARKS.md](TRADEMARKS.md).

## Contributing

Contributions are welcome subject to the security and review requirements in [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

CesSpace ARC Core is licensed under the [Apache License, Version 2.0](LICENSE).

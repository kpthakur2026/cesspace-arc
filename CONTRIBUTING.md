# Contributing to CesSpace ARC

Thank you for your interest in contributing to **CesSpace ARC**.

CesSpace ARC is a security-sensitive agent-to-machine control plane. Security, correctness, auditability, compatibility, and maintainability take priority over speed of delivery.

## Contribution principles

1. **Security by default:** New capabilities must preserve default-deny and fail-closed behavior.
2. **No policy bypass:** Privileged operations must continue to traverse the established ARC security pipeline.
3. **Negative testing required:** Security-sensitive changes must include tests proving unauthorized, malformed, or malicious inputs are rejected.
4. **Secret hygiene:** Never commit credentials, private keys, tokens, private infrastructure details, or realistic secret material.
5. **Small, reviewable changes:** Keep pull requests focused and avoid unrelated refactors.
6. **Independent review:** Changes require maintainer review before merge.
7. **Compatibility discipline:** Changes to protocol, tool schemas, policy semantics, audit formats, or platform support must include corresponding documentation and regression coverage.

## Development workflow

Create a topic branch from the current default branch. Clear branch names are preferred, for example:

- `feat/<topic>`
- `fix/<topic>`
- `docs/<topic>`
- `test/<topic>`

Use clear, atomic commits. Conventional commit-style messages are encouraged, for example:

- `feat(policy): add bounded policy capability`
- `fix(filesystem): reject unsafe path transition`
- `docs(security): clarify disclosure process`
- `test(audit): add redaction regression coverage`

## Required verification

Before submitting a pull request, run the checks relevant to the change. The normal repository gate is:

```bash
pnpm install --frozen-lockfile
pnpm run check:format
pnpm run lint
pnpm run typecheck
pnpm run test
pnpm run build
pnpm run check:docs
pnpm run check:secrets
```

Also run `git diff --check` and review the complete diff before submission.

## Pull request expectations

A pull request should:

- explain the problem and the proposed change;
- identify security or compatibility impact when applicable;
- include tests for behavior changes;
- include negative tests for security boundaries;
- update operator or architecture documentation when public contracts change;
- contain no unrelated generated files, credentials, private data, or hidden infrastructure assumptions;
- preserve required licensing and attribution.

Changes that modify the public tool catalog, authentication model, policy semantics, workspace boundary, audit integrity, remote transport, or release process require especially careful review.

## Security reports

Do not report suspected vulnerabilities through a public issue or pull request. Follow the private process in [SECURITY.md](SECURITY.md).

## Public repository scope

The public repository is governed by the [Public Repository Policy](docs/governance/public-repository-policy.md). Private CesSpace strategy, commercial planning, internal delivery sequencing, and private infrastructure details are out of scope for public contributions.

## Code of Conduct

All contributors and participants must follow the [Code of Conduct](CODE_OF_CONDUCT.md).

# Engineering Governance — CesSpace ARC

> **Repository:** `kpthakur2026/cesspace-arc`
> **Status:** Active project governance
> **Classification:** Public engineering specification

## Purpose

This document defines the public engineering rules for changes to CesSpace ARC Core. It describes review, security, compatibility, and release expectations without exposing private CesSpace product planning or internal delivery sequencing.

## Core principles

1. **Security invariants are authoritative.** Default deny, fail closed, least privilege, mandatory policy mediation, workspace containment, explicit approval, and auditability must not be weakened.
2. **Authentication and authorization remain separate.** Establishing caller identity never grants host authority by itself.
3. **No direct privileged bypass.** Filesystem, Git, terminal, process, approval, and audit-sensitive behavior must remain behind the governed ARC execution path.
4. **Negative testing is mandatory.** Security boundaries require tests proving blocked behavior stays blocked.
5. **Secrets do not belong in Git.** Credentials, private topology, customer data, private keys, and production configuration must never be committed.
6. **Protected branches require review.** Changes are developed on topic branches and merged only after maintainer review and required checks.
7. **Compatibility changes are explicit.** Protocol, schema, policy, audit, platform-support, and release-format changes require documentation and regression coverage.
8. **Public claims must be evidence-backed.** Released functionality, supported platforms, and security statements must match the canonical source and release evidence.

## Review model

Changes should be small enough to review directly and should include the evidence needed to evaluate correctness and security impact.

A security-sensitive change normally includes:

- implementation diff;
- positive behavior tests;
- negative or adversarial tests;
- documentation updates when a public contract changes;
- format, lint, type, test, build, documentation, and secret-scan results as applicable.

## Change boundaries

The following are prohibited in public repository changes:

- weakening or bypassing security checks to make a test pass;
- suppressing required verification with force or no-verify mechanisms;
- committing secrets, credentials, private topology, or customer data;
- copying code from incompatible or proprietary sources;
- adding public network exposure, hosted-service behavior, or production deployment assumptions without an approved and reviewed architecture;
- introducing undocumented changes to authentication, authorization, policy, audit, workspace, or release trust boundaries;
- adding private CesSpace strategy, commercial planning, internal delivery sequencing, or private infrastructure details to public documentation.

## Release and maintenance

The current stable release is `1.0.0`.

Release changes must preserve reproducibility, provenance, dependency integrity, platform support truth, and the published security/privacy boundary. A release is not considered supported merely because code exists on the default branch.

Historical acceptance and verification documents may remain in the repository where source, tests, or release tooling still reference them. They are engineering evidence rather than the primary public product documentation.

## Verification baseline

Before merge, run the checks applicable to the change. The normal baseline includes:

1. `git diff --check`
2. formatting
3. linting
4. TypeScript typechecking
5. automated tests
6. build verification
7. documentation link checks
8. secret and credential scanning

Security-sensitive changes may require additional targeted verification.

## Public repository boundary

The [Public Repository Policy](public-repository-policy.md) governs what belongs in the public ARC repository. Public engineering documentation should be sufficient for users, contributors, operators, and security reviewers without exposing private CesSpace planning or infrastructure.

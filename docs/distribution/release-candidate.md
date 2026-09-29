# ARC Core Release-Candidate Verification

ARC's release profile is **Core-only**. The accepted Task-7 parent records the
pre-promotion `0.8.0-rc08` / `RC-08` evidence. Task 8 promotes the current
runtime to `1.0.0` / `ARC-1.0`; it still does not publish an artifact.

The authoritative machine-readable profile is
[`release/arc10-release-profile.json`](../../release/arc10-release-profile.json).
The reviewed profile explicitly disables hosted connectivity, OAuth/OIDC,
multi-tenant accounts, relay and public MCP hosting, directory publishing,
metering, billing, and subscriptions. ARC 1.0 Tasks 3–6 and their hosted
acceptance flows are recorded as profile-not-shipped, not as passed or
silently skipped.

## Consumer verification

A consumer receives the source bundle, signed manifest, detached Ed25519
signature, provenance, SPDX SBOM, dependency/license inventory, and resolved
Core release profile. The trusted public verification key must arrive through
an independent operator trust decision. Verification is offline and checks:

1. the detached signature and every artifact checksum;
2. the archive's exact Git commit and tree provenance;
3. SBOM, inventory, and lockfile agreement;
4. complete dependency license and lockfile-source metadata;
5. the Core-only capability declaration and compatibility matrix;
6. the frozen 25-tool and five-entry deterministic-registry identities; and
7. compatibility with the supplied authoritative Core state schema.

Run the non-publishing verifier with normalized, saved `pnpm audit` evidence:

```sh
pnpm run verify:arc10:rc -- \
  ./bundle ./trusted-release-public.pem ./pnpm-audit.json ./state-metadata.json
```

The verifier neither contacts a registry nor calls a hosted service. It has 12
fail-closed gates and emits bounded JSON containing no signing material.

## Release policy

- Critical, high, or unknown-severity dependency findings block acceptance.
  Moderate and low findings remain visible evidence and require normal release
  review; they are not filtered away.
- Every locked production dependency must have resolved license metadata and a
  lockfile-bound source locator. `UNKNOWN` remains valid raw Task-1 inventory
  syntax, but is incomplete and therefore unacceptable at this release gate.
  This is evidence-completeness policy, not a legal compatibility opinion.
- Release signing private keys must not occur in Git, source, bundles,
  manifests, provenance, SBOMs, inventories, CI metadata, or examples. Tests
  generate ephemeral Ed25519 keys; consumers provide the public key separately.
- Older authentic artifacts cannot open newer Core state. Schema migration or
  rollback must use the transactional Task-2 lifecycle; artifact installation
  cannot reset state or audit continuity.
- No hosted or vendor-directory credential, dependency, endpoint, callback, or
  support claim may enter the Core profile.

## Platform truth

| Target              | Classification         | Evidence meaning                                                                           |
| ------------------- | ---------------------- | ------------------------------------------------------------------------------------------ |
| Linux x86-64        | Supported              | Install, config preflight, migration, runtime health, and MCP regression evidence executed |
| WSL Linux userspace | Development-compatible | Declaration only; not authoritative security equivalence                                   |
| Linux arm64         | Validation-only        | Policy fixture only; no support claim                                                      |
| macOS arm64/x64     | Validation-only        | Policy fixture only; no support claim                                                      |
| Native Windows      | Unsupported            | Installation must refuse                                                                   |

Documentation, the signed Task-1 manifest, and the release-profile matrix must
agree. A validation-only target cannot be promoted by editing one surface.

Stable `1.0.0` promotion is exclusively owned by Task 8 and is proven against
the exact Task-7 parent. The promotion commit creates no tag, GitHub release,
package publication, hosted service, or vendor-directory submission.

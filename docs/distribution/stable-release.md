# CesSpace ARC 1.0.0 Core

CesSpace ARC `1.0.0` has the stable health stage `ARC-1.0`. This repository
contains a reviewed, reproducible **Core-only** release profile. Preparing and
verifying the artifact does not authorize a tag, GitHub Release, package
publication, or hosted deployment.

## Release boundary

The supported host is Linux x86-64. WSL Linux userspace is
development-compatible without an equivalent host-security claim. Linux arm64
and macOS are validation-only. Native Windows host execution is unsupported.

The Core profile contains the existing local and operator-managed remote MCP
control plane. It does not ship accounts, tenant authority, OAuth/OIDC, relay,
public hosted MCP, ChatGPT or Claude hosted connectors, directory publishing,
metering, billing, or subscriptions. The 25 production MCP tools and five
deterministic execution entries remain frozen.

## Final verification

Run the authoritative verifier from the exact reviewed promotion commit:

```sh
bash scripts/verify-arc10.sh
```

Its 30 mandatory gates validate exact parent provenance, stable identity,
acceptance ownership, hosted-profile absence, build and repository quality,
all inherited and ARC 1.0 tests, dependency and secret policy, exact catalogs,
full-history Gitleaks evidence, reproducible signed source artifacts, offline
consumer verification, installation, real MCP health and read behavior,
uninstall preservation, migration recovery, and compatible rollback. A
fail-only injection seam may force a gate to fail for testing; it cannot skip
or convert a failure into success.

The detached Ed25519 signature is verified with a public key supplied through
an independent trust decision. Acceptance uses ephemeral keys only. No release
private key is stored in Git, the artifact, logs, or committed fixtures.

## Acceptance and publication

[`release/arc10-acceptance-ownership.json`](../../release/arc10-acceptance-ownership.json)
maps every `ARC10-NEG-001..080` and `ARC10-FLOW-01..18` identifier exactly once.
Hosted controls are `PROFILE_NOT_SHIPPED`; hosted flows are
`NOT_APPLICABLE_TO_CORE_RELEASE`, with executable absence evidence rather than
fabricated execution.

The project security-review record intentionally leaves release authority as
`PENDING_INDEPENDENT_APPROVAL`. Publication requires a separate explicit
post-review action.

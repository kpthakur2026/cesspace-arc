# Governance

CesSpace ARC is stewarded by the CesSpace ARC maintainers. Governance exists to preserve the security model, compatibility contract, release integrity, and long-term maintainability of the open-source Core.

## Maintainer authority

Maintainers are responsible for:

- reviewing and merging contributions;
- protecting security invariants and trust boundaries;
- maintaining protocol and compatibility discipline;
- managing releases and release provenance;
- maintaining public documentation and repository policy;
- coordinating security response and responsible disclosure.

The current maintainer list is published in [MAINTAINERS.md](MAINTAINERS.md).

## Change acceptance

Changes are evaluated on technical merit, security impact, compatibility, test evidence, maintainability, and alignment with the public ARC Core scope.

No contributor may bypass required review or repository checks. Security-sensitive changes require especially careful review and appropriate negative or adversarial tests.

## Decision making

Routine changes are accepted through reviewed pull requests.

Changes that alter authentication, authorization, policy semantics, workspace containment, audit integrity, public protocol/tool schemas, remote trust boundaries, supported-platform claims, or release provenance require explicit maintainer acceptance and documented verification.

## Releases

A release is official only when published through the canonical CesSpace ARC distribution authority documented in [PUBLISHER.md](PUBLISHER.md).

Development code on the default branch does not by itself constitute a supported release.

## Public and private boundaries

The public repository contains the open-source ARC Core and the material required to use, review, verify, and contribute to it.

Private CesSpace strategy, commercial planning, customer information, internal delivery sequencing, and private infrastructure are outside the public governance scope. See [Public Repository Policy](docs/governance/public-repository-policy.md).

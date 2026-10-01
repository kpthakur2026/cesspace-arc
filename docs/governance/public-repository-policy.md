# CesSpace ARC Public Repository Policy

## Purpose

The CesSpace ARC public repository exists to publish the ARC Core source, stable
release information, operator documentation, security and privacy policies,
contribution guidance, and the technical material required to understand,
build, verify, operate, and review the open-source Core.

It is not the authority for private CesSpace product strategy, commercial
planning, internal delivery sequencing, or private infrastructure design.

## Public content boundary

Public repository content may include:

- ARC Core source and tests;
- stable release and compatibility information;
- installation and configuration documentation;
- protocol, security, privacy, and trust-boundary documentation;
- contribution and governance requirements;
- reproducible verification and supply-chain evidence;
- interoperability information that is technically necessary to operate ARC;
- legally required licenses, notices, and attributions.

Public repository content must not include:

- private CesSpace network topology, credentials, secrets, or deployment data;
- internal business or commercial strategy;
- unreleased pricing or packaging strategy;
- private website or hosted-service implementation roadmaps;
- internal handoff notes, temporary completion reports, or internal planning notes;
- speculative release dates or unsupported capability claims;
- competitor comparisons or promotional name-dropping;
- private customer, tenant, account, or operational data.

## Vendor-neutral public language

General product and architecture documentation uses vendor-neutral terms such
as "MCP-compatible client", "AI client", "external service", and
"cloud-provider credentials".

External product or organization names may appear only when technically,
legally, or operationally required, for example:

- a dependency or license attribution;
- a canonical repository or release host;
- a protocol or integration that cannot be described accurately without naming
  the external system;
- a security example where the exact identifier is part of the implemented
  control.

Such references must be factual and must not be used as marketing comparisons.

## Historical engineering evidence

Normative architecture contracts, security invariants, acceptance tests, and
verification artifacts may remain public when current code, scripts, or release
verification depend on them.

Temporary handoff notes and standalone completion reports should not remain on
the current public branch once they are no longer referenced or required.
Their history remains available through Git history.

## Release truth

Public product claims must distinguish released behavior from development
behavior. The current stable release, canonical release source, supported
platforms, and published security/privacy policies are authoritative.

Unreleased or private CesSpace capabilities must not be presented as available
through the public ARC repository.

## Change review

Before merging a documentation or public-surface change:

1. verify that the information is required for ARC users, operators,
   contributors, or security reviewers;
2. verify that no secret, private topology, internal strategy, or unsupported
   claim is introduced;
3. prefer CesSpace and vendor-neutral terminology;
4. preserve required legal and dependency attribution;
5. run documentation, formatting, secret-scanning, type, test, and build gates
   applicable to the change.

This policy governs the current public repository surface without changing the
ARC runtime security model or the licensing of already published releases.

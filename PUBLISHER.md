# Official CesSpace ARC Publisher Identity

This document identifies the current official publishing authority and
canonical distribution sources for CesSpace ARC.

## Official project

Project name:

CesSpace ARC

Current maintainer / publisher identity:

P Thakur

GitHub publisher account:

@kpthakur2026

Canonical repository:

https://github.com/kpthakur2026/cesspace-arc

## Current stable release

Stable version:

1.0.0

Canonical Git tag:

1.0.0

Canonical stable commit:

1a98cb44238dae870f9cf5b730694ac4be76b119

Canonical GitHub Release:

https://github.com/kpthakur2026/cesspace-arc/releases/tag/1.0.0

## Official artifact rule

An artifact should be treated as an official CesSpace ARC distribution only
when its provenance can be traced to the canonical repository or another
distribution channel explicitly listed in this document or in an official
repository release.

The project currently does not declare any third-party marketplace publisher,
third-party extension or app-directory listing, public package-registry entry,
container-registry image, hosted relay, or hosted CesSpace ARC service as an
official production distribution unless such a channel is explicitly added
here by the official project.

## Third-party extension identity

No third-party extension distribution is currently designated as an official
CesSpace ARC distribution. A package using the CesSpace ARC name must not be
assumed to be official solely because of its name.

## Private remote integration identity

The tagged CesSpace ARC `1.0.0` Core release predates the private remote MCP
integration and does not include a CesSpace-hosted remote connector.

Current development on the canonical `main` branch includes an official,
private/operator-managed remote MCP integration. It is
designed to run on infrastructure controlled by the ARC operator and to connect
through an operator-managed secure tunnel or private remote connection.

This integration does not constitute a CesSpace-hosted remote MCP service, public
relay, hosted account system, or third-party app-directory listing.

Until a newer tagged release is published, users should not assume that the
private remote integration is part of the `1.0.0` release artifact solely because it
exists on `main`.

No third-party app-directory listing, CesSpace-hosted connector, or managed
remote MCP endpoint is currently designated as an official production
distribution.

## Verification

Users should prefer:

1. the canonical GitHub repository;
2. signed or otherwise cryptographically verifiable release artifacts when
   supplied by the project;
3. release provenance bound to the documented source commit and tree;
4. marketplace listings whose publisher identity matches an identity explicitly
   recorded in this document.

A fork or derivative may be legitimate open-source software while still not
being an official CesSpace ARC distribution.

## Reporting impersonation

Suspected impersonation, misleading distribution, or misuse of the CesSpace
ARC identity may be reported through the official GitHub repository.

Security vulnerabilities must instead follow SECURITY.md and must not be
reported publicly.

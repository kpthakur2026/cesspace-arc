# Gitleaks false-positive disposition for historical RC07 fixture

Status: **Pending independent security review**

Decision date: 2026-10-10

Product-owner authorization: **Authorized for preparation and Core repair PR review**

## Scope

This decision proposes one exact Gitleaks fingerprint exception and no other suppression:

```text
815bc2c1d4b141d5d738b5a0cb44f57097c4d7eb:tests/rc07-review-diff.test.js:generic-api-key:218
```

The exception is limited by commit, path, rule, and line. It does not exclude a file, path, rule,
secret type, commit range, or scanner version. It does not change CI, reduce scan coverage, downgrade
Gitleaks, or rewrite Git history. Existing `.gitleaksignore` entries are unchanged.

## Fixture provenance and false-positive rationale

Commit `815bc2c1d4b141d5d738b5a0cb44f57097c4d7eb` introduced the test named
`RC07-NEG-022: Diff contains simulated API key / secret token (masked, count truthful)`. Its setup
creates a temporary `secrets_repo`, writes deterministic simulated tokens into that disposable Git
fixture, calls the review-diff tool, and asserts that each simulated value is absent from the tool
response while a redaction marker and truthful masked count are present.

The value at line 218 is a deterministic AWS-access-key-ID-shaped test sentinel. The fixture does
not contain a corresponding secret access key and is not used for authentication. The complete
historical test file has SHA-256
`82b94f815739d09022fffc2cc213e872cc21f4f2a52ec94834929fa63e54d9bb`.
The immediate child commit `190ba5f6fbea88a52e02eca85ab1f253dd4c8188` retained the same test purpose
while constructing the sentinel from fragments to avoid scanner matching in the current tree.

These facts support classification as a deliberate redaction-test fixture, not an issued or usable
credential. Independent security review of that classification remains required before merge.

## Scanner evidence

- Repository-pinned Gitleaks `8.24.3` is installed by `.github/workflows/ci.yml`. Its Linux x64
  archive SHA-256 is
  `9991e0b2903da4c8f6122b5c3186448b927a5da4deef1fe45271c3793f4ee29c`.
- Gitleaks `8.30.1`, the latest version evaluated for this decision on 2026-10-10, has Linux x64
  archive SHA-256
  `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb`.
- Before this proposed exception, `8.30.1` reported exactly the fingerprint above during a
  full-history scan. With the exact fingerprint present in `.gitleaksignore`, the same full-history
  scan must report no unsuppressed findings.
- The pinned `8.24.3` full-history scan must remain clean.
- A deliberate unrelated canary must still be detected, demonstrating that the exception has not
  weakened general secret detection.

The verification commands and resulting evidence are recorded in the repair review report and the
draft pull request. Scanner output is redacted before retention.

## Required approval

This disposition is not approved for merge by this document. An independent security reviewer must
confirm the fixture provenance, exact fingerprint scope, full-history results for both scanner
versions, and unrelated-canary detection. The product owner is the authorizing stakeholder and must
not be counted as the independent security reviewer.

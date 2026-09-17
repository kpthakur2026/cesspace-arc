# ADR-0003: Canonical Path Resolution and Symlink Containment

* **Status:** Accepted
* **Date:** 2026-09-17
* **Deciders:** Architecture Team

---

## Context

Development machines host both the working project source code and sensitive user data (such as `~/.ssh/id_rsa`, `~/.aws/credentials`, `/etc/shadow`, and shell histories).

Attackers manipulating an AI agent via prompt injection or crafted Git repositories often employ directory traversal techniques:
- Relative path escapes (`../../../../etc/passwd`).
- URL or alternate path encodings (`..%2f`).
- Symlinks inside a Git repository pointing outside the project root to target files in `/root` or `/home`.

Relying on simple string operations (such as checking if a path string begins with `/home/user/project`) is vulnerable to symlink bypasses and canonicalization anomalies.

## Decision

We establish a mandatory **Canonical Path Resolution Pipeline** in `packages/filesystem`:

1. **Explicit Workspace Roots:** Operations must target a registered, canonical workspace directory.
2. **Mandatory Canonicalization:** All candidate paths must be resolved via the operating system's `realpath()` function to evaluate all symlinks and relative path components before any access occurs.
3. **Prefix Enclosure Assertion:** The canonical realpath must match the workspace root or begin with the root followed by a system directory separator.
4. **Symlink Escape Prohibition:** Any symlink whose resolved target resides outside the approved root causes the operation to be denied immediately with `PATH_ESCAPES_ROOT`.
5. **Immutable Blacklist:** Critical credential files (`.env`, `~/.ssh`, `~/.aws`, `.git/hooks`) are permanently blacklisted even if they exist within the workspace boundary.

## Consequences

### Positive
- Completely neutralizes directory traversal and symlink escape vulnerabilities.
- Protects host credentials from accidental or adversarial exfiltration.
- Deterministic behavior across Linux VM environments.

### Negative / Trade-offs
- Non-existent files targeted for creation require canonicalizing their parent directories.
- Legitimate symlinks pointing to external system libraries or shared caches outside the workspace must be explicitly declared or copied into the workspace.

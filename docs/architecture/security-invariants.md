# Permanent Security Invariants — CesSpace ARC

> **Document:** Invariant Specification
> **Status:** RC-00 Approved Baseline
> **Rule:** Inviolable across all development stages

---

## 1. Overview & Enforceability

The 20 Permanent Security Principles of CesSpace ARC are formal system invariants. They represent non-negotiable architectural boundaries. No pull request, optimization, automated refactor, or convenience feature may weaken, bypass, or conditionally disable any of these invariants.

Every invariant is assigned an invariant identifier (`INV-01` through `INV-20`), a formal statement, the precise enforcement mechanism, and verification criteria.

---

## 2. Invariant Specifications

### INV-01: Zero Implicit Trust
* **Statement:** No client, session, agent, or input possesses inherent authority. Every invocation must present verifiable credentials and undergo independent validation.
* **Enforcement:** Ingress filter rejects unauthenticated requests. Internal APIs require explicit context objects.
* **Verification:** Negative tests asserting that missing, expired, or malformed identity payloads result in immediate rejection.

### INV-02: Default Deny
* **Statement:** Any operation, path, parameter, or command not explicitly permitted by an active policy rule is denied by default.
* **Enforcement:** The Policy Engine fallback logic evaluates to `PolicyDecision.DENY`.
* **Verification:** Test cases dispatching unregistered tool names or unclassified commands must result in `DENY`.

### INV-03: Least Privilege
* **Statement:** Host operations run with the absolute minimum operating system privileges required to execute the specific task.
* **Enforcement:** Execution processes drop supplemental groups, never run as root, and isolate child process trees.
* **Verification:** Subprocess UID check asserting non-zero user ID.

### INV-04: Fail Closed
* **Statement:** Any unexpected exception, unparseable payload, filesystem anomaly, timeout, or subsystem crash results in immediate termination of the request and rejection.
* **Enforcement:** Global error handlers catch all uncaught exceptions, log the event, and return standard sanitized error responses with zero execution side effects.
* **Verification:** Fault-injection unit tests asserting that mocked internal errors never allow downstream actions.

### INV-05: Separation of Authentication and Authorization
* **Statement:** Establishing the cryptographic identity of a caller (Authentication) does not confer any operational permissions (Authorization).
* **Enforcement:** `packages/auth` establishes identity only; `packages/policy` independently evaluates permissions against policy matrices.
* **Verification:** Test demonstrating an authenticated agent with zero assigned policy permissions cannot invoke any mutating or sensitive tools.

### INV-06: Mandatory Policy Mediation
* **Statement:** Every privileged operation must pass through policy enforcement prior to execution.
* **Enforcement:** Subsystem drivers (Filesystem, Git, Terminal, Processes) are isolated from transport layers and can only be invoked by the Policy Engine execution pipeline.
* **Verification:** Architecture dependency review verifying no circular or direct imports between `apps/mcp-server` and host execution packages without `packages/policy`.

### INV-07: Agents Must Never Bypass the Policy Engine
* **Statement:** No client-controlled input or tool parameter may alter the dispatch route or bypass the policy evaluation step.
* **Enforcement:** Dispatcher inspects registered tool definitions and binds each to a mandatory policy evaluation middleware.
* **Verification:** Integration tests verifying that tampering with JSON-RPC headers or parameters cannot circumvent policy checks.

### INV-08: Authorized Filesystem Roots Only
* **Statement:** Filesystem inspection and mutation are strictly jailed to explicitly configured and authorized workspace root directories.
* **Enforcement:** Canonical path validation (`realpath`) asserts that resolved target paths reside within the authorized directory prefix. Symlinks escaping the root are rejected.
* **Verification:** Path traversal test suite testing `../`, symlinks to `/etc`, URL-encoded paths, and null-byte injection.

### INV-09: Secrets and Credential Locations Inaccessible by Default
* **Statement:** Critical credential paths (e.g., `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `.env`, `.git/config`) are permanently blacklisted from read and write operations.
* **Enforcement:** The path resolver contains an immutable deny-list of path patterns evaluated prior to filesystem access.
* **Verification:** Explicit unit tests verifying that attempts to access blacklisted paths fail with `ACCESS_DENIED`.

### INV-10: Terminal Execution Must Be Policy-Controlled
* **Statement:** Subprocess execution must strictly validate binary names, argument vectors, working directories, and resource limits against an approved command policy.
* **Enforcement:** Command supervisor dispatches directly via `execve` using strict tokenization without shell evaluation (`/bin/sh -c`).
* **Verification:** Test attempting shell metacharacter injection (`|`, `;`, `&&`, `$()`) verifying that they are treated as literal arguments and rejected by policy.

### INV-11: Destructive Operations Denied by Default
* **Statement:** Highly destructive operations (filesystem formatting, recursive directory deletion outside build caches, process killing of system services) are denied by default.
* **Enforcement:** Policy rules classify destructive commands under `DENY` unless explicitly overridden by manual human-in-the-loop approval.
* **Verification:** Automated verification that commands such as `rm -rf /` or `mkfs` trigger immediate `DENY`.

### INV-12: Zero Cloud-Root/Production Access in Public Defaults
* **Statement:** Default configuration manifests and policies shipped in the repository must never configure, reference, or allow access to cloud root credentials or production infrastructure.
* **Enforcement:** Static check scripts verify that all example configurations use placeholder values and loopback or RFC 5737 test addresses.
* **Verification:** CI secret scanning and configuration linters.

### INV-13: Universal Auditability
* **Statement:** Every privileged operation, policy evaluation, approval decision, and execution outcome must produce a structured, append-only audit record.
* **Enforcement:** Asynchronous write-ahead or synchronous flush audit middleware records every request before and after execution.
* **Verification:** Audit log verification asserting record presence for every executed or denied tool call.

### INV-14: Protected Branch Immutability
* **Statement:** AI agents are forbidden from mutating protected Git branches (`main`, `master`, `release/*`) directly or rewriting Git history.
* **Enforcement:** The Git subsystem rejects any commit, push, or destructive checkout operation targeting protected branch names.
* **Verification:** Test asserting that a `git push origin main` or checkout -B main attempt fails with `PROTECTED_BRANCH_DENIED`.

### INV-15: Explicit Authorization for Sensitive Actions
* **Statement:** Actions that mutate repository files, execute builds, install packages, or create executables require explicit human approval (`REQUIRE APPROVAL`).
* **Enforcement:** The policy engine pauses execution and emits an approval request token; execution resumes only upon receipt of a valid cryptographic approval signature.
* **Verification:** Workflow tests verifying that mutating calls remain suspended until approval is supplied.

### INV-16: Absolute Prohibition of CES Internal Secrets
* **Statement:** No CES-specific private infrastructure data, internal IP addresses, VM hostnames, private keys, or credentials may be committed to this repository.
* **Enforcement:** Automated pre-commit checks and CI secret scanners scanning for internal patterns and high-entropy strings.
* **Verification:** Pre-push and CI secret scanner jobs.

### INV-17: Permanence of Committed Secrets
* **Statement:** Any secret committed to public Git history is considered permanently compromised and cannot be remediated simply by deletion in a subsequent commit.
* **Enforcement:** Any PR containing detected credentials must be rejected and the secret rotated immediately at the provider.
* **Verification:** Git history scanning in CI.

### INV-18: Vendor Neutrality
* **Statement:** The core architecture, protocol schema, and tool definitions must remain vendor-neutral and adhere to open standards.
* **Enforcement:** MCP tools and protocol abstractions cannot rely on vendor-proprietary APIs or closed extensions.
* **Verification:** Compatibility verification against multiple distinct MCP client implementations.

### INV-19: Code-Enforced Security
* **Statement:** Security controls must be implemented as enforceable, testable code logic rather than advisory documentation alone.
* **Enforcement:** Code coverage metrics and architecture boundary linting in CI.
* **Verification:** Zero undocumented or bypassed security gates.

### INV-20: Mandatory Negative Controls
* **Statement:** Every security boundary, policy rule, path resolver, and execution guard must have dedicated negative test cases proving that unauthorized actions fail closed.
* **Enforcement:** CI pipeline requires negative test suites to execute and pass on every commit.
* **Verification:** Automated check verifying the existence and execution of negative control test cases.

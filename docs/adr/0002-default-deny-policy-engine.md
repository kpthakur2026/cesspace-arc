# ADR-0002: Default-Deny Policy Engine with Strict Precedence

- **Status:** Accepted
- **Date:** 2026-09-17
- **Deciders:** Architecture Team

---

## Context

Allowing autonomous AI agents to execute operations on host machines introduces severe risks of accidental damage, command injection, or privilege escalation.

A naive permission model based on an allow-list alone can fail if rules are ambiguous, if regular expressions are too broad, or if edge-case arguments slip past validation. Furthermore, in many developer workflows, certain operations should not be permanently blocked but should require explicit human approval before running.

Moreover, if read-only tools were implemented prior to any policy gate, it would violate the permanent invariant that no host operation executes without authorization.

We need a policy evaluation engine that guarantees safety under all conditions, especially unexpected, malformed, or conflicting rules, starting from the very first operational tool call.

## Decision

We establish an authoritative **Policy Engine** (`packages/policy`) structured as a phased capability over a single unified core:

1. **RC-01 Minimal Security Kernel:** Establishes the non-bypassable admission gate, default-deny baseline, explicit 9-tool allowlist, authorized-workspace registry, and canonical workspace binding before any tool runs.
2. **RC-04 Declarative Extension:** Extends the exact same engine with declarative YAML/JSON rule files, AST command parsing, Git branch protection rules, and human-in-the-loop approval state machines.
3. **Absolute Precedence Hierarchy:**
   ```text
   DENY > REQUIRE APPROVAL > ALLOW
   ```
4. **Default Deny:** Any operation, path, or command not explicitly permitted evaluates strictly to `DENY`.
5. **Absolute Deny Precedence:** If any matching rule evaluates to `DENY`, the request is immediately halted and blocked, overriding all `ALLOW` or `REQUIRE APPROVAL` rules.

## Consequences

### Positive

- **Guaranteed Safety from RC-01:** Eliminates unmonitored tool execution from day one without creating a second or throwaway authorization system.
- **Fail Closed:** Unknown tools, unregistered paths, or malformed contexts are blocked automatically.
- **Unified Architecture:** RC-04 extends the RC-01 kernel rather than replacing it.

### Negative / Trade-offs

- Requires developers to explicitly configure workspace paths and allowed commands.
- Approval workflows require client UI support or CLI notification mechanisms.

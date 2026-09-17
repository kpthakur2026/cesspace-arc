# ADR-0002: Default-Deny Policy Engine with Strict Precedence

* **Status:** Accepted
* **Date:** 2026-09-17
* **Deciders:** Architecture Team

---

## Context

Allowing autonomous AI agents to execute operations on host machines introduces severe risks of accidental damage, command injection, or privilege escalation.

A naive permission model based on an allow-list alone can fail if rules are ambiguous, if regular expressions are too broad, or if edge-case arguments slip past validation. Furthermore, in many developer workflows, certain operations should not be permanently blocked but should require explicit human approval before running.

We need a policy evaluation engine that guarantees safety under all conditions, especially unexpected, malformed, or conflicting rules.

## Decision

We implement a centralized **Policy Engine** (`packages/policy`) with three discrete outcomes and an absolute precedence hierarchy:

```text
DENY > REQUIRE APPROVAL > ALLOW
```

1. **Default Deny:** If an operation, path, or command does not match an explicit `ALLOW` rule, the fallback evaluation is strictly `DENY`.
2. **Absolute Deny Precedence:** If any matching rule evaluates to `DENY`, the request is immediately halted and blocked, overriding all `ALLOW` or `REQUIRE APPROVAL` rules.
3. **Approval Lifecycle:** Operations requiring human consent suspend execution, generate a cryptographically bound approval request token, and proceed only upon valid human authorization.

## Consequences

### Positive
- **Guaranteed Safety:** Eliminates accidental permission grants resulting from rule conflicts or ambiguities.
- **Fail Closed:** Unknown tools, unregistered paths, or malformed contexts are blocked automatically.
- **Human Governance:** Provides an auditable human-in-the-loop approval gate for dangerous operations (source writes, build scripts, branch changes).

### Negative / Trade-offs
- Requires developers to explicitly configure workspace paths and allowed commands.
- Approval workflows require client UI support or CLI notification mechanisms.

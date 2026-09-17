# ADR-0005: Fail-Closed Error Model and Information Disclosure Prevention

- **Status:** Accepted
- **Date:** 2026-09-17
- **Deciders:** Architecture Team

---

## Context

When an operation fails on a host development machine, the runtime or operating system typically returns detailed error messages, stack traces, and absolute path locations (e.g. `/home/developer_name/.config/app/secret.conf`).

If these raw errors are returned directly to an untrusted AI agent or logged into unredacted client transcripts, they create an **information disclosure vulnerability**, revealing:

- Local host usernames and account IDs.
- System directory structures and installed software versions.
- Private repository layouts outside the workspace.
- Potentially sensitive command arguments or secrets in stack traces.

Conversely, if errors are too vague, the agent cannot take corrective action or fix invalid tool parameters.

## Decision

We establish a **Structured, Fail-Closed Error Model** (`packages/protocol`):

1. **Fail-Closed Semantics:** Any unexpected internal failure, parsing error, or timeout halts execution immediately with zero state mutation.
2. **Canonical Error Schema (`ArcError`):** Errors are emitted as structured objects with standard error codes, categories, safe messages, and actionable remediation hints.
3. **Anti-Leakage Scrubbing:** All outgoing error messages are filtered:
   - Absolute paths outside the workspace are stripped or converted to relative paths.
   - Host usernames and machine identifiers are replaced with generic placeholders.
   - Internal stack traces are suppressed in MCP responses and logged exclusively to secure local audit storage.
   - Denied symlink targets are concealed.

## Consequences

### Positive

- AI agents receive actionable, machine-readable errors without leaking host secrets or private directory topology.
- Consistent error taxonomy across all MCP tools and transports.
- Prevents reconnaissance attacks via error message probing.

### Negative / Trade-offs

- Developers debugging internal server bugs must inspect local audit logs rather than relying on client-side JSON-RPC error responses.

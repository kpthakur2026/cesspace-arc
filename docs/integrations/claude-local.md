# Local MCP profile for Claude-compatible clients

Use ARC over MCP stdio when the AI client runs on the same Linux host or WSL userspace as ARC.

## Prerequisites

- ARC Core installed into a user-owned prefix.
- A current, validated ARC Core state directory created and maintained through the normal Core configuration lifecycle.
- The workspace, policy, durable audit keys/store, process state, and optional local admin channel already declared in that Core state.

The integration launcher is:

`<prefix>/runtime/scripts/arc-integration-stdio.mjs`

It accepts one argument: the Core state directory. It runs the existing Core preflight before constructing the MCP server. The client therefore cannot choose a workspace, policy, audit key, or authorization boundary in its MCP profile.

## Generic MCP client profile

Use the sanitized template in `examples/integrations/claude-local.mcp.json` and replace the two absolute-path placeholders.

The effective launch is:

```text
node /absolute/path/to/arc-prefix/runtime/scripts/arc-integration-stdio.mjs \
  /absolute/path/to/arc-core-state
```

The client communicates with ARC over stdio. ARC exposes the reviewed MCP tool catalog and keeps policy, approvals, workspace containment, and durable audit in the execution path.

## Security notes

- Keep workspace authorization in `core-config.json`; do not duplicate it in the client profile.
- Do not add secrets to the MCP client JSON.
- A local MCP connection does not grant approval-administration or device-administration authority.
- ARC Core does not require a CesSpace account.
- Native Windows execution is unsupported; WSL Linux userspace is development-compatible.

Client-specific UI locations and configuration-file paths are intentionally not frozen here because they are owned by the client vendor and can change independently of ARC.

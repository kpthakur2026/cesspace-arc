# Claude Desktop and local MCP clients

ARC-CONNECT-02 provides a local Claude Desktop connection path without adding a second ARC execution server.

## Preferred Claude Desktop flow

After ARC Core is installed and initialized, run:

```text
cesspace-arc connect claude
```

The helper:

- validates the existing ARC Core state and durable audit integrity;
- reuses the existing private loopback ARC adapter when another client such as ChatGPT already started it, or starts that same adapter when needed;
- safely merges one `cesspace-arc` entry into Claude Desktop's `claude_desktop_config.json`;
- configures Claude to launch `cesspace-arc proxy claude` over stdio;
- writes no ARC bearer token, API key, account credential, or payment state into Claude configuration.

The stdio proxy is a transport bridge only. It forwards MCP JSON-RPC to the shared loopback ARC adapter. It has no filesystem, Git, terminal, process, policy, approval, or audit implementation of its own.

Fully quit and reopen Claude Desktop after the config change. Use Claude Desktop's Connectors or developer view to confirm that the ARC tools are available.

## Status and disconnect

```text
cesspace-arc status claude
cesspace-arc disconnect claude
```

Status reports whether the expected `cesspace-arc` entry is present and whether the shared loopback adapter is healthy.

Disconnect removes only the exact Claude config entry owned by this ARC installation. It refuses to remove a conflicting or user-modified entry. It does not stop the shared adapter because another client may still be using it.

## Explicit config path

An explicit Claude Desktop config path can be selected when automatic discovery is inappropriate:

```text
cesspace-arc connect claude --config /absolute/path/to/claude_desktop_config.json
```

The config directory must already exist. ARC does not create a fake Claude installation directory.

## Config safety

The helper preserves unrelated Claude configuration and unrelated MCP entries. It refuses malformed JSON, symlinked or non-regular config files, files owned by another user, group/world-writable config, oversized config, and a conflicting `cesspace-arc` entry unless the operator explicitly uses `--force`.

The generated entry contains only an absolute ARC launcher path and the non-secret arguments `proxy claude`. The local ARC bearer token remains in an owner-only ARC file and is never written into Claude configuration or accepted through argv.

A sanitized example is available at `examples/integrations/claude-local.mcp.json`.

## Generic local MCP clients

The existing `arc-integration-stdio.mjs` launcher remains available for standards-conformant local MCP clients that run as the sole ARC process for a Core state.

When the shared private adapter is already active for ChatGPT or Claude, do not start another full ARC process against the same state: the durable audit store is intentionally single-writer. Clients that need to coexist should use the shared loopback adapter through a reviewed bridge rather than creating a second execution authority.

## Trust boundary

Claude does not choose ARC's workspace, policy, audit keys, device trust, or machine permissions. Those remain inside the validated ARC Core state.

This integration is local. It is distinct from a remote Claude connector and does not require exposing ARC to the public internet or adding a CesSpace-hosted relay. Native Windows ARC execution remains unsupported; WSL Linux userspace remains development-compatible.

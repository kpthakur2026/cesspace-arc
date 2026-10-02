# ARC client integrations

CesSpace ARC is an MCP server. AI clients connect to ARC; they do not receive source-repository access or bypass ARC policy, approval, audit, or workspace containment.

## Supported integration patterns

- **Local stdio:** the recommended path for Claude Code/Desktop-style and other standards-conformant local MCP clients. ARC and the client run on the same host.
- **Private ChatGPT-compatible remote MCP:** available on current ARC main through the opt-in ChatGPT adapter. It is operator-managed, binds locally by default, requires a restricted bearer-token file, and is intended to sit behind private operator-controlled connectivity.
- **Stable ARC Core 1.0.0:** remains fully usable without a CesSpace account or hosted service.

These instructions do not claim a ChatGPT App Directory listing, Claude directory listing, CesSpace-hosted connector, public relay, or managed hosted availability.

See:

- [Local MCP / Claude profile](claude-local.md)
- [Private ChatGPT-compatible profile](chatgpt-private.md)

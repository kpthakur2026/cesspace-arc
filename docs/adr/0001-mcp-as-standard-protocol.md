# ADR-0001: Use Model Context Protocol (MCP) as Standard Agent Interface

* **Status:** Accepted
* **Date:** 2026-09-17
* **Deciders:** Architecture Team

---

## Context

AI coding agents and developer tooling (including Claude Code, Codex, Antigravity, OpenCode, and DeepSeek-driven agents) need to interact with remote and local development machines to inspect workspaces, run commands, and review diffs.

Historically, tools have either used proprietary WebSocket/REST protocols, ad-hoc shell wrappers, or vendor-locked interfaces. This fragments tool development and forces users to create custom bridges for every model provider. Furthermore, exposing raw SSH or unsanitized shell execution gives autonomous agents excessive ambient authority.

We require an open, vendor-neutral protocol that supports:
1. Standardized tool schema discovery and invocation.
2. Structured bidirectional messaging over stdio or HTTP streaming.
3. Broad adoption across top AI models and IDE ecosystems.

## Decision

We adopt the **Model Context Protocol (MCP)** (JSON-RPC 2.0 based) as the primary external interface for CesSpace ARC.

CesSpace ARC will act as an authoritative MCP server exposing controlled tools (`read_file`, `list_directory`, `git_status`, etc.) over standard transports (stdio for local use and SSE/HTTPS for remote gateway sessions).

## Consequences

### Positive
- **Vendor Neutrality:** Compatible with Claude Code, Antigravity, ChatGPT/Codex clients, OpenCode, and future MCP-compliant agents without modification.
- **Strong Typing:** Leverages JSON Schema to validate tool arguments prior to policy processing.
- **Interoperability:** Plugs directly into modern AI developer tools supporting MCP out of the box.

### Negative / Trade-offs
- The protocol overhead of JSON-RPC serialization must be optimized for large payloads (e.g. diffs or large file chunks).
- Remote MCP over SSE requires careful session management and transport-level authentication (addressed in RC-05).

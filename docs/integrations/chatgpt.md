# Private ChatGPT Remote MCP Integration Guide

This guide describes how to configure and run the private, developer-mode Model Context Protocol (MCP) integration for CesSpace ARC with ChatGPT.

## 1. What Is Supported Now

- **Private developer-mode testing:** Operators can connect ChatGPT (in custom action / developer mode) to a private ARC instance.
- **Secure tunnel / reverse proxy transport:** Remote MCP traffic travels over an operator-managed secure tunnel (such as Cloudflare Tunnel, ngrok, tailscale, or reverse proxy) to a local ARC endpoint.
- **Full ARC Core tool catalog:** All 25 standard ARC Core tools are exposed through the remote profile without modification or duplication.
- **Universal policy and audit enforcement:** Every incoming tool invocation is subject to ARC's default-deny security kernel, declarative policy, workspace jailing, argument validation, and durable cryptographic audit.

## 2. What Is NOT Supported

This integration does **NOT** provide or support:

- Public CesSpace-hosted ChatGPT service or multi-tenant infrastructure.
- Public marketplace or app directory listings.
- CesSpace user accounts, profiles, or authentication portals.
- Billing, metering, or subscription management.
- Public relay SaaS or hosted reverse connections managed by CesSpace.
- Automatic or unauthenticated remote machine enrollment.

Marketplace publication and public hosted services are separate future work and are subject to future release milestones.

## 3. Architecture Overview

```
ChatGPT (OpenAI Developer Mode)
  │
  │ HTTPS (Encrypted)
  ▼
Secure MCP Tunnel / Private Reverse Connection (Operator-Managed)
  │
  │ Loopback / Private Interface (127.0.0.1) + Bearer Token
  ▼
ARC Remote MCP Adapter (`ChatGptRemoteAdapter`)
  │
  ▼
Existing ARC Authenticated Execution Pipeline (`executeAuthenticatedToolCall`)
  │
  ├─► Security Kernel (Layer 1 Default-Deny & Invariants)
  ├─► Declarative Policy Engine (Layer 2 Path & Command Rules)
  ├─► Approval State Manager (Human-in-the-Loop Gate)
  ├─► Append-Only Durable Audit Runtime (Cryptographic Trail)
  │
  ▼
Subsystems (Filesystem / Git / Terminal / Processes)
  │
  ▼
Authorized Workspace Jails Only
```

The new ChatGPT-facing transport does **not** call filesystem, git, terminal, process, or approval subsystems directly. All execution flows exclusively through the shared authenticated ARC tool execution pipeline.

## 4. Setup Instructions

### Step 1: Build CesSpace ARC

Ensure dependencies are installed and the TypeScript packages are compiled:

```bash
pnpm install
pnpm run build
```

### Step 2: Configure an Authorized Workspace

Explicitly specify the authorized directory root you want ARC to manage. ARC enforces strict default-deny filesystem boundaries and will never implicitly trust `process.cwd()`:

```bash
export CESSPACE_WORKSPACE="/path/to/my/project"
```

### Step 3: Create a Secure Token File

Generate a high-entropy bearer token and store it in a restricted file on the host. Never pass raw tokens on the command line or store them in version control:

```bash
mkdir -p ~/.cesspace-arc/secrets
openssl rand -hex 32 > ~/.cesspace-arc/secrets/chatgpt-token.txt
chmod 0600 ~/.cesspace-arc/secrets/chatgpt-token.txt
```

Verify that the file is owned by your user account and that group/world permissions are `00` (mode `0600` or `0400`).

### Step 4: Configure the Remote Profile

Configure ARC to enable the ChatGPT remote profile using trusted launch configuration or environment selectors:

```json
{
  "transport": "stdio",
  "authorizedRoots": [{ "id": "main-project", "path": "/path/to/my/project" }],
  "defaultWorkspaceId": "main-project",
  "chatgpt": {
    "enabled": true,
    "bindHost": "127.0.0.1",
    "port": 8443,
    "path": "/mcp",
    "tunnelHostname": "my-arc-tunnel.example.com",
    "authTokenPath": "/home/user/.cesspace-arc/secrets/chatgpt-token.txt"
  }
}
```

### Step 5: Establish the Secure Tunnel

Run your preferred tunnel agent (e.g., Cloudflare Tunnel, ngrok, or reverse proxy) directing traffic to your local bind address (`127.0.0.1:8443`). Ensure TLS termination and public hostname mapping match your `tunnelHostname` setting.

### Step 6: Connect in ChatGPT Developer Mode

1. In ChatGPT (custom GPT or developer actions interface), add a new MCP server endpoint pointing to your public tunnel URL:
   `https://my-arc-tunnel.example.com/mcp`
2. Configure authentication as **Bearer Token** using the token generated in Step 3.
3. Save the configuration.

### Step 7: Verify Connectivity with Read-Only Operations

1. Request tool discovery (`tools/list`).
2. Run a read-only health check or directory listing:
   - Call `health` to verify server state.
   - Call `list_directory` within your authorized workspace.
3. Verify that mutations and commands outside the authorized workspace are rejected.

## 5. Security Warnings & Operational Guidelines

- **Never expose ARC directly to the public internet:** Always bind ARC to loopback (`127.0.0.1`) behind an authenticated, encrypted tunnel or reverse proxy.
- **Never disable authentication:** Unauthenticated access is rejected by design. Do not attempt to bypass token verification.
- **Keep secrets off the command line:** Do not pass token bytes or private keys in command-line arguments (`argv`). Use file selectors with strict POSIX permissions.
- **Never authorize root directories:** Do not configure `/`, `/home`, `/etc`, or sensitive system directories as authorized workspace roots.
- **Manage AI provider exposure:** You are responsible for the data transmitted to and from your AI provider. Refer to [PRIVACY.md](../../PRIVACY.md) and [SECURITY.md](../../SECURITY.md) for details.

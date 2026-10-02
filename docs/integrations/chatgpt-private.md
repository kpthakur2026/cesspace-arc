# Private ChatGPT-compatible MCP profile

Current ARC main includes an opt-in ChatGPT-compatible MCP adapter. This is a private, operator-managed connection path. It is not part of tagged ARC Core 1.0.0 and is not a public ChatGPT App Directory listing or a CesSpace-hosted connector.

## Security model

The launcher first validates the existing ARC Core state. Workspace authorization, policy, durable audit, process state, and any configured local admin authority remain owned by that state rather than by ChatGPT connection settings.

The ChatGPT adapter:

- is disabled by default;
- binds to loopback by default;
- rejects wildcard bind hosts;
- requires a bearer token stored in an owner-only regular file;
- never accepts the bearer token itself through argv or an environment value;
- uses server-generated MCP sessions;
- routes tool execution through ARC's existing policy, approval, containment, and audit pipeline.

## Preferred connection helper

After installing ARC Core and creating a valid Core state, create an OpenAI Secure MCP Tunnel in the OpenAI Platform UI and associate it with the ChatGPT workspace that will use ARC. Then run:

```text
cesspace-arc connect chatgpt --tunnel-id tunnel_...
```

The helper validates Core preflight and audit integrity, creates owner-only local connection secrets, starts the loopback-only ARC adapter, configures `tunnel-client` with file-backed secret references, runs its doctor check, starts the tunnel daemon, and waits for both ARC MCP initialization and tunnel readiness.

ARC Core does not download, bundle, or own the external tunnel runtime. Install the supported `tunnel-client` from the platform tunnel settings first, or provide its absolute path with `--tunnel-client`. This preserves Core's vendor-neutral local execution boundary.

The Platform API key is never accepted as a command-line value. If no protected key file already exists, the helper prompts for it with hidden input and stores it locally with mode `0600`. An existing owner-only key file can instead be selected with `--api-key-file`.

In ChatGPT custom MCP settings select **Tunnel**, use the operator-created `tunnel_...` identifier, and select **No authentication**. ARC's bearer credential remains local between `tunnel-client` and the loopback adapter; it is not entered into ChatGPT.

Re-running the command reuses the saved tunnel identifier and owner-only secrets unless the operator explicitly supplies a different tunnel ID or key file.

## Manual private-adapter path

The steps below remain available for advanced operation and debugging. Build/install ARC and prepare a valid Core state through the normal Core configuration lifecycle. Then create a token file outside the repository:

```text
umask 077
printf '%s\n' '<generate-a-high-entropy-token>' > ~/.cesspace-arc/chatgpt-token
chmod 600 ~/.cesspace-arc/chatgpt-token
```

Set ChatGPT connection selectors, not Core security authority or secret values:

```text
export CESSPACE_ARC_CHATGPT_TOKEN_FILE=$HOME/.cesspace-arc/chatgpt-token
export CESSPACE_ARC_CHATGPT_PORT=4318
# Optional when a private tunnel presents a stable public host:
# export CESSPACE_ARC_CHATGPT_TUNNEL_HOSTNAME=arc.example.private

pnpm run integration:chatgpt-private -- /absolute/path/to/arc-core-state
```

The sole positional argument is the Core state directory. The launcher runs the existing Core preflight and composes the already-reviewed ChatGPT adapter over that validated configuration. It does not add a hosted relay or a second ARC execution path.

## Connectivity

Expose the local adapter only through an operator-controlled private tunnel or equivalent secure connectivity that preserves the expected Host value when `CESSPACE_ARC_CHATGPT_TUNNEL_HOSTNAME` is configured.

The MCP endpoint is `/mcp`. The client presents the bearer token from the restricted token file through the connection configuration used by that client.

Do not expose the loopback listener directly to the public internet and do not weaken the adapter to bind `0.0.0.0`.

## Boundary

Connecting ChatGPT to ARC does not create a CesSpace account, device enrollment, billing entitlement, or local machine authorization. ARC host permission remains governed by the validated Core state, ARC policy, and local operator custody.

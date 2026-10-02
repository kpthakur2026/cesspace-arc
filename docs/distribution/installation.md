# ARC Core source distribution and installation

CesSpace ARC provides a local, signed source-distribution workflow. Task 8 promotes the current Core runtime identity to `1.0.0` / `ARC-1.0`; no hosted profile or publication is implied.

## Supported target

The authoritative installation target is Linux x86-64. WSL's Linux userspace is development-compatible but is not an equivalent security claim. Linux arm64 and macOS are validation-only targets. Native Windows host execution is unsupported.

The source build requires the Node and pnpm versions declared in the root `package.json`. Dependency installation is offline-capable when the required packages are already present in pnpm's store and always uses the exact lockfile with `--prefer-offline --frozen-lockfile --ignore-scripts`. If the store is incomplete, pnpm may retrieve only missing lockfile-bound packages; verification itself never accesses the network.

## Build and verification

Generate an Ed25519 release key outside the repository and keep its private half outside source control. Build a local bundle with:

```text
pnpm run dist:build -- <bundle-directory> <private-key-file> [source-root]
```

The bundle contains a normalized source archive, canonical manifest, detached manifest signature, SPDX 2.3 JSON SBOM, dependency/license inventory, and source provenance. Verify in this order before installation:

The source archive is a deterministic projection of eligible regular-file blobs in the declared Git `HEAD` tree. Bytes and executable modes come from Git objects, never from untracked, ignored, generated, staged-but-uncommitted, or modified working-tree files. Tracked staged or unstaged changes cause the release builder to fail closed.

1. supply a trusted Ed25519 public key independently of the bundle;
2. verify the detached signature over the canonical manifest digest;
3. verify every artifact and archive-entry SHA-256 digest;
4. verify provenance binds the exact source archive, commit, and tree;
5. reconcile the SPDX package set with the locked dependency inventory;
6. verify lockfile, version, stage, tool-count, and deterministic-registry identity;
7. run the release secret gate;
8. perform bounded safe extraction.

```text
pnpm run dist:verify -- <bundle-directory> <trusted-public-key-file>
```

Never trust a public key merely because it is included beside an untrusted artifact. The private key is neither accepted by the verifier nor included in the bundle.

## Prefix-scoped install and uninstall

The ordinary installer accepts a user-writable prefix only:

```text
pnpm run dist:install -- <bundle-directory> <trusted-public-key-file> <user-prefix>
pnpm run dist:uninstall -- <user-prefix>
```

Verification completes before extraction, dependency installation, build, or prefix mutation. Extraction rejects absolute paths, traversal, non-normal paths, duplicate entries, symlinks, hardlinks, and special entries. Installation is staged and records every ARC-owned runtime file in `.cesspace-arc-install.json`. System prefixes such as `/usr`, `/usr/local`, `/etc`, and `/opt` are refused; Task 1 has no system-wide installation mode and never invokes `sudo` or a shell.

Default uninstall removes only paths recorded by the ownership manifest and empty ARC-created directories. Workspace data, configuration, durable audit data, and unrelated files are preserved. Explicit user-data deletion is outside Task 1. Reinstallation uses the same verification and locked-build path.

## First-run Core setup

A verified ARC installation provides three user-scoped launchers under `<user-prefix>/bin`:

- `cesspace-arc-setup` creates the local Core state for one explicitly selected workspace;
- `cesspace-arc` starts the local stdio MCP server from that validated Core state;
- `cesspace-arc-chatgpt` starts the opt-in private ChatGPT-compatible MCP profile from the same Core state.

Create the initial state with:

```text
<user-prefix>/bin/cesspace-arc-setup /absolute/path/to/authorized/workspace
```

By default the state is written under `~/.config/cesspace-arc/state`. The setup command refuses to overwrite an existing state directory. It generates a local Ed25519 audit checkpoint keypair, initializes an empty local device trust store and durable audit store, writes the strict Core configuration, and runs the production Core preflight before reporting success.

The generated policy follows ARC's conservative compatibility policy: read-only inspection and bounded process supervision are available inside the selected workspace; file mutations and deterministic verification/test execution remain approval-gated. System trees and secret-path protection remain enforced by ARC's security kernel.

After setup, a standards-conformant local MCP client can use `<user-prefix>/bin/cesspace-arc` as its stdio command. The client does not need a CesSpace account and does not receive authority outside the configured workspace.

For ChatGPT, after the operator creates an OpenAI Secure MCP Tunnel associated with the intended ChatGPT workspace, the installed launcher also provides:

```text
<user-prefix>/bin/cesspace-arc connect chatgpt --tunnel-id tunnel_...
```

This helper keeps ARC bound to loopback, preserves Core policy/approval/audit authority, stores local connection secrets as owner-only files, uses an operator-installed supported `tunnel-client`, and reports the exact Tunnel/No-authentication settings to use in ChatGPT. The Platform API key is never accepted as a command-line value.

## Core access and commercial boundary

ARC Core is free and open source under Apache-2.0. Local Core installation and use require **no CesSpace login, no CesSpace account, no credit card, no license key, and no subscription**. The website may distribute the installer and documentation, but it does not become a machine-control hop and receives no local ARC filesystem, terminal, approval, or audit authority.

This tooling does not provide OAuth/OIDC, hosted relay, public MCP hosting, directory publishing, tenancy, metering, billing, or subscriptions. Building or verifying a stable artifact does not publish it.

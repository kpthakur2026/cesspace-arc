# ARC Core configuration, upgrade, and migration

ARC 1.0 Task 2 introduced the local Core configuration and state-lifecycle boundary. Task 8 promotes the current schema-2 product and health identity to `1.0.0` / `ARC-1.0`; hosted services remain disabled.

## Configuration authority

`core-config.json` is strict JSON using `schemaVersion: 2`, `productVersion: "1.0.0"`, and `profile: "core"`. Unknown fields, duplicate JSON keys, type confusion, duplicate workspace selectors, unsupported combinations, control characters, and unbounded values fail closed. State-owned selectors are normalized relative paths beneath the live state directory; workspace roots are explicit absolute operator-authorized paths.

The top-level fields are:

- `transport`: `stdio`, or the existing bounded remote selectors;
- `workspaces` and `defaultWorkspaceId`;
- `policy.path`;
- `audit.directory`, `audit.signingKeyPath`, and `audit.publicKeyPath`;
- optional local `admin.socketPath` and `admin.operatorPublicKeyPath`;
- `state.trustStorePath` and `state.processDirectory`;
- `observability.logLevel`.

Configuration precedence is deterministic: the validated JSON file is authoritative, then the sole allowlisted non-secret environment override, `CESSPACE_ARC_LOG_LEVEL`, may replace `observability.logLevel` with `error`, `warn`, or `info`. Other environment names are ignored by this loader and cannot select workspaces, policy, trust, private keys, issuers, executables, or audit signing authority.

Run a current-state preflight with:

```text
pnpm run config:check -- <live-state-directory>
```

Preflight validates configuration, required public files, secret selectors, the device trust store, and the existing durable audit chain before a caller may construct or bind the MCP server.

## Secret files and CLI channels

Configuration contains selectors, never secret bytes. On authoritative Linux, a selected private key must be a single-link, operator-owned regular file opened without following symlinks, no larger than 64 KiB, with exact mode `0400` or `0600`. Group/world-readable files, directories, symlinks, empty files, oversized files, and wrong-owner files fail before secret consumption.

Task-2 commands accept only a state-root path. Private keys, bearer/session tokens, approval tokens, and migration secrets are not valid argv options. The existing admin private key remains accepted only through its inherited file descriptor; Task 2 does not broaden that channel.

## State schemas and migration

Product version, configuration schema, state schema, and migration version are separate identities:

| Identity                 | Value                    |
| :----------------------- | :----------------------- |
| Current product / health | `1.0.0` / `ARC-1.0`      |
| Legacy migration source  | `0.8.0-rc08` / `RC-08`   |
| Legacy source config     | `configSchemaVersion: 1` |
| Current Core config      | `configSchemaVersion: 2` |
| Legacy source state      | `stateSchemaVersion: 1`  |
| Current Core state       | `stateSchemaVersion: 2`  |
| Migration implementation | `migrationVersion: 1`    |

The operator-selected migration root contains authoritative `state/` plus an internal mode-`0700` `.arc10-migration/` area. Migration proceeds as:

1. validate source metadata/configuration, secret modes, device state, and authoritative audit evidence;
2. acquire `.arc10-migration/migration.lock` atomically;
3. create and digest a permission-preserving, no-symlink backup;
4. construct and validate a complete staged state from the verified backup;
5. persist a bounded, content-digest-only journal in `STAGED` state;
6. atomically rename at the `COMMITTING` boundary;
7. reopen configuration, trust state, and audit evidence;
8. persist `COMMITTED` evidence and remove retired/staging state.

Run it with:

```text
pnpm run migrate:arc10 -- <migration-root>
```

The journal contains schema versions, tree digests, fixed step identifiers, lifecycle state, and bounded audit continuity identifiers. It contains no secret values, file contents, private audit payloads, tokens, or absolute host paths.

## Recovery, rollback, and downgrade refusal

An interruption before commit leaves `state/` byte-for-byte authoritative. Recovery verifies its source digest, removes incomplete staging, and permits an idempotent retry. A crash during the two-rename commit boundary completes only from the already-verified staged tree; it never combines source and target files. Lock removal and recovery are explicit: a live Linux PID plus `/proc` start-time identity refuses a second migrator, while a provably dead or PID-reused owner is reclaimed without timing guesses.

Compatible rollback requires a `COMMITTED`, reversible journal and a backup whose schema, digest, device data, and authoritative audit evidence match the recorded source. It stages and atomically restores that backup:

```text
pnpm run rollback:arc10 -- <migration-root>
```

Missing, modified, irreversible, incompatible, or audit-discontinuous backups are refused before authoritative mutation. State newer than the supported maximum is refused rather than rewritten or silently downgraded. Migration and rollback perform no network access and never create a new audit genesis to conceal corrupt evidence.

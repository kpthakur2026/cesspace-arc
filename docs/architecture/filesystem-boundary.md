# Filesystem Boundary & Security Model — CesSpace ARC

> **Document:** Filesystem Security Specification
> **Status:** RC-00 Approved Baseline
> **Classification:** Core Security Mechanism

---

## 1. Filesystem Security Objectives

The filesystem is the primary state storage for development environments. It contains source code, dependencies, build caches, and developer configuration—but it also coexists with sensitive user credentials, private keys, system configuration, and kernel virtual filesystems (`/proc`, `/sys`).

The **CesSpace ARC Filesystem Boundary Model** provides mathematical certainty that:
1. Operations can only access files physically and logically contained within explicitly approved workspace roots.
2. Symlinks, hardlinks, traversal sequences (`../`), or alternate encodings cannot breach the boundary.
3. Sensitive credentials and host configuration remain completely inaccessible even if accidentally placed inside an approved workspace.
4. Race conditions (TOCTOU) cannot be exploited to escape the sandbox.

---

## 2. Authorized Workspace Roots

A workspace root is an absolute, canonical directory path explicitly registered with the control plane at startup or via administrative configuration:

- **Root Registration:** Configured as a list of canonical directories (e.g., `["/home/cespr/cesspace-arc"]`).
- **No Ambient Root:** There is no default root pointing to `/` or `/home`. If no workspace root is configured, all filesystem operations fail closed with `NO_WORKSPACE_CONFIGURED`.
- **Multiple Roots:** If multiple workspaces are configured, the agent must specify which workspace context it is targeting, or the path must unambiguously resolve into exactly one authorized root.

---

## 3. Canonical Path Resolution Algorithm

To prevent directory traversal attacks, path normalization anomalies, and symlink escapes, every path supplied by an agent must pass through the **Canonical Path Resolution Pipeline** before any filesystem API is called:

```
[Agent Input Path: e.g. "src/../.env"]
          │
          ▼
1. SYNTACTIC NORMALIZATION
   - Strip leading/trailing whitespace and control characters.
   - Reject null bytes (`\0`) immediately with `INVALID_PATH_CHARS`.
   - Reject raw URL encoded segments (`%2e%2e`, `%2f`).
   - Normalize directory separators to standard UNIX slashes (`/`).
          │
          ▼
2. WORKSPACE ROOT JOIN
   - If path is relative, resolve against `targetWorkspace.rootPath`:
     `candidatePath = path.resolve(workspaceRoot, inputPath)`
   - If path is absolute, verify it begins syntactically with `workspaceRoot`.
          │
          ▼
3. CANONICAL REALPATH RESOLUTION
   - Resolve all symlinks and relative segments using OS `realpath()`:
     `canonicalPath = fs.realpathSync(candidatePath)`
   - (For write/create of non-existent files, resolve `realpath()` on the parent directory).
          │
          ▼
4. PREFIX ENCLOSURE VERIFICATION
   - Assert:
     `canonicalPath === workspaceRoot || canonicalPath.startsWith(workspaceRoot + "/")`
   - If false: HALT immediately with `PATH_ESCAPES_ROOT`.
          │
          ▼
5. BLACKLIST & SECRET FILTERING
   - Check `canonicalPath` against the immutable sensitive path blacklist.
   - If matched: HALT immediately with `ACCESS_DENIED`.
          │
          ▼
[AUTHORIZED PATH: Safe for Operation]
```

### 3.1. Formal Inclosure Invariant
Let $R$ be the canonical path of the approved workspace root. Let $P_{input}$ be the requested path. The canonical target path $T = \text{realpath}(P_{input})$.

The operation is permitted if and only if:
$$T = R \quad \lor \quad T \text{ starts with } R + \text{"/"}$$

And:
$$T \notin \text{Blacklist}$$

---

## 4. Symlink Containment & Escape Protection

Symlinks represent a significant escape vector in multi-user and agentic environments. An untrusted agent or Git repository could contain a symlink pointing to `/root/.ssh` or `/etc/passwd`.

### Containment Rules:
1. **No External Symlink Targets:** If a symlink within the workspace resolves to a target outside the authorized root, following that symlink is strictly forbidden. The resolution pipeline throws `PATH_ESCAPES_ROOT`.
2. **Symlink Creation Protection:** When file creation tools are implemented (RC-03), creating symlinks pointing outside the workspace is denied by default.
3. **Safe Directory Traversal:** Directory traversal operations (`list_directory`, `search_files`) must not traverse symlinked directories that exit the approved root boundary.

---

## 5. Blacklisted Paths & Secret Locations

Even if located inside or beneath an approved workspace directory, the following path patterns are permanently blacklisted from read, search, and write operations:

| Pattern | Category | Threat Rationale |
| :--- | :--- | :--- |
| `**/.ssh/**` | Credentials | SSH private keys, authorized_keys, known_hosts |
| `**/.aws/**` | Cloud Credentials | AWS credentials and configuration files |
| `**/.gnupg/**` | Cryptographic Keys | GPG private keys and keyrings |
| `**/.kube/**` | Cluster Access | Kubernetes cluster admin configs and tokens |
| `**/.env*` | Secrets | Environment variables, local API keys, database secrets |
| `**/.git/config` | Git Security | Remote URLs containing embedded auth tokens |
| `**/.git/hooks/**` | Code Execution | Git hook scripts executed on host git events |
| `**/id_rsa*` | SSH Keys | RSA private keys |
| `**/id_ed25519*` | SSH Keys | Ed25519 private keys |
| `/etc/**` | Host Configuration | Host system configuration, `/etc/shadow`, `/etc/sudoers` |
| `/proc/**` | Kernel State | Process memory, environment variables of other processes |
| `/sys/**` | Hardware State | Kernel parameters and hardware control |
| `/root/**` | Superuser Data | Root user home directory |
| `/dev/**` | Devices | Raw disk devices, `/dev/kmem` |

---

## 6. Time-of-Check to Time-of-Use (TOCTOU) Mitigations

A common race condition occurs when an attacker replaces a verified file or directory with a symlink between the policy verification check and the actual filesystem read/write call.

### Mitigations:
1. **Atomic File Descriptors:** When opening files, use flags like `O_NOFOLLOW` on supported platforms to fail if the trailing path component is a symlink.
2. **Double-Check on Read:** For file reads, verify `fstat` on the open file descriptor matches the verified canonical path.
3. **Atomic Writes (RC-03 Target):** Write file contents to a randomized temporary file within the same directory (`.tmp.XXXXXX`) and rename atomically using `rename()` to eliminate partial-write windows.

---

## 7. Resource Limits & Content Safety

To protect against resource exhaustion and binary corruption:
- **Maximum Read Size:** Single-file reads are capped at 1 MB by default (with chunked offset/length pagination).
- **Maximum Search Results:** File searches return at most 200 matches per query.
- **Binary File Detection:** Binary files are identified via null-byte inspection in the first 8 KB. Binary files return base64 metadata or size information rather than attempting raw string decoding.
- **Maximum Directory Depth:** Recursive directory listings are capped at depth 5 by default.

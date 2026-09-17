# Filesystem Boundary & Security Model — CesSpace ARC

> **Document:** Filesystem Security Specification
> **Status:** RC-00 Approved Baseline — RC-01 Active
> **Classification:** Core Security Mechanism

---

## 1. Filesystem Security Objectives

The filesystem is the primary state storage for development environments. It contains source code, dependencies, build caches, and developer configuration—but it also coexists with sensitive user credentials, private keys, system configuration, and kernel virtual filesystems (`/proc`, `/sys`).

The **CesSpace ARC Filesystem Boundary Model** provides rigorous defense-in-depth to ensure that:

1. Operations are confined strictly to explicitly approved workspace root directories.
2. Traversal sequences (`../`), encoded path variations, or symlinks escaping the workspace boundary are detected and rejected.
3. Sensitive credential paths (`~/.ssh`, `~/.aws`, `.env`) are blocked by an immutable deny-list.
4. OS-level containment mechanisms are leveraged to minimize race conditions (TOCTOU) and path manipulation.

---

## 2. Threat Analysis & Boundary Edge Cases

Userspace string normalization and `realpath()` checks provide essential baseline validation, but they do not eliminate all host filesystem risks. A secure control plane must explicitly model the following edge cases:

### 2.1. Hardlink Aliasing

- **Threat:** On POSIX filesystems, hardlinks point to an underlying inode without recording path ancestry. If an attacker or compromised tool creates a hardlink inside the workspace pointing to an external file (e.g. `ln /home/user/.ssh/id_rsa ./workspace/key`), `realpath()` on the hardlink resolves to the file path _inside the workspace_.
- **Mitigation:** Subsystem operations inspect inode link counts (`stat.nlink > 1`) and cross-reference device/inode identifiers against known workspace-created inodes. In future stages, hardlink creation is restricted or disabled on workspace mount points.

### 2.2. Parent-Component Symlink Races (TOCTOU)

- **Threat:** An attacker or concurrent process renames an ancestor directory to point to a symlink between the time `realpath()` validates a path and the time `fs.open()` / `fs.readFile()` executes (Time-of-Check to Time-of-Use race).
- **Mitigation:** Userspace path checks are augmented by kernel-enforced descriptor-relative operations (`openat2` with `RESOLVE_BENEATH` on Linux) and descriptor double-checking (`fstat`).

### 2.3. Same-User Ambient Authority

- **Threat:** Because the ARC agent typically runs under the developer's local user account (to access local tools), standard OS Discretionary Access Control (DAC) permissions do not prevent the agent process from opening files in `~/.ssh` or `~/.aws` if path resolution is flawed.
- **Mitigation:** Subsystem-level path blacklisting is mandatory before any I/O call. In containerized or sandboxed VM deployments, sensitive directories are masked via empty mount points.

### 2.4. TOCTOU Residual Risk

- **Threat:** Any string-based userspace file API inherently has a residual time window between path checking and resource opening during which directory trees can be reorganized.
- **Mitigation:** Direct use of file descriptors rather than string paths, pinning the root directory file descriptor and traversing children relative to that descriptor.

---

## 3. Stronger Containment Architecture for Linux

To defend against the edge cases modeled above, CesSpace ARC specifies a tiered containment architecture:

```text
┌──────────────────────────────────────────────────────────────────────────┐
│ TIER 1 (RC-01 Userspace Baseline): Canonical Realpath & Prefix Check     │
│ - realpath() canonicalization of candidate paths                         │
│ - Strict prefix enclosure check: candidate.startsWith(root + "/")        │
│ - Immutable path blacklist (.env, ~/.ssh, ~/.aws, etc.)                  │
│ - Rejection of symlinks pointing outside workspace root                  │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ TIER 2 (Kernel VFS Enforcement): openat2 & RESOLVE_BENEATH               │
│ - Open workspace root directory fd with O_DIRECTORY | O_PATH             │
│ - Open child files using openat2() with RESOLVE_BENEATH flag             │
│ - Linux kernel VFS rejects any symlink or ".." escaping root fd          │
│ - Fully eliminates userspace parent-component TOCTOU races              │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ TIER 3 (Mount & Namespace Isolation): Sandbox Boundary                   │
│ - Unprivileged mount namespaces (unshare -m) for worker processes        │
│ - Workspace mounted in isolated mount namespace with MS_NODEV | MS_NOSUID │
│ - Sensitive directories (~/.ssh, ~/.aws, /etc) masked with tmpfs/ro-bind │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Canonical Path Resolution Algorithm

Every path supplied by an agent must pass through the **Canonical Path Resolution Pipeline** before any filesystem API is called:

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

---

## 5. Blacklisted Paths & Secret Locations

Even if located inside or beneath an approved workspace directory, the following path patterns are permanently blacklisted from read, search, and write operations:

| Pattern            | Category           | Threat Rationale                                         |
| :----------------- | :----------------- | :------------------------------------------------------- |
| `**/.ssh/**`       | Credentials        | SSH private keys, authorized_keys, known_hosts           |
| `**/.aws/**`       | Cloud Credentials  | AWS credentials and configuration files                  |
| `**/.gnupg/**`     | Cryptographic Keys | GPG private keys and keyrings                            |
| `**/.kube/**`      | Cluster Access     | Kubernetes cluster admin configs and tokens              |
| `**/.env*`         | Secrets            | Environment variables, local API keys, database secrets  |
| `**/.git/config`   | Git Security       | Remote URLs containing embedded auth tokens              |
| `**/.git/hooks/**` | Code Execution     | Git hook scripts executed on host git events             |
| `**/id_rsa*`       | SSH Keys           | RSA private keys                                         |
| `**/id_ed25519*`   | SSH Keys           | Ed25519 private keys                                     |
| `/etc/**`          | Host Configuration | Host system configuration, `/etc/shadow`, `/etc/sudoers` |
| `/proc/**`         | Kernel State       | Process memory, environment variables of other processes |
| `/sys/**`          | Hardware State     | Kernel parameters and hardware control                   |
| `/root/**`         | Superuser Data     | Root user home directory                                 |
| `/dev/**`          | Devices            | Raw disk devices, `/dev/kmem`                            |

---

## 6. Resource Limits & Content Safety

To protect against resource exhaustion and binary corruption:

- **Maximum Read Size:** Single-file reads are capped at 1 MB by default (with chunked offset/length pagination).
- **Maximum Search Results:** File searches return at most 200 matches per query.
- **Binary File Detection:** Binary files are identified via null-byte inspection in the first 8 KB. Binary files return base64 metadata or size information rather than attempting raw string decoding.
- **Maximum Directory Depth:** Recursive directory listings are capped at depth 5 by default.

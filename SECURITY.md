# Security Policy — CesSpace ARC

> **Repository:** `kpthakur2026/cesspace-arc`
> **Status:** Open-Source Security Baseline
> **Classification:** Public Repository

---

## 1. Security Philosophy & Foundations

CesSpace ARC is designed as an agent-to-machine control plane. By definition, it mediates between semi-autonomous AI models and host execution environments. Therefore, security is not an add-on; it is the core product requirement.

### The 20 Permanent Security Principles

1. **Zero implicit trust:** Every client, agent, tool invocation, and input must be explicitly validated.
2. **Default deny:** Any action, path, command, or parameter not explicitly allowed by active policy is denied.
3. **Least privilege:** Operations run with the absolute minimum system permissions required.
4. **Fail closed:** Any error, unexpected condition, unparseable input, or crash results in complete rejection.
5. **Separation of authentication and authorization:** Establishing _who_ an agent is does not grant permissions to _what_ it may execute.
6. **Mandatory policy mediation:** No privileged operation may execute without passing through policy enforcement.
7. **No policy bypass:** Subsystems and tools cannot be called directly; all invocations traverse the control plane pipeline.
8. **Authorized filesystem roots only:** Filesystem access is strictly jailed to explicitly configured workspace paths.
9. **Secrets inaccessible by default:** Private keys, cloud credentials, tokens, and configuration files are blacklisted and inaccessible.
10. **Policy-controlled execution:** Process creation and terminal execution are subjected to strict command classification and argument whitelisting.
11. **Destructive operations denied by default:** File deletion, directory wipes, forced resets, and filesystem formatting require explicit elevated approval or are permanently blocked.
12. **Zero cloud-root/production access in defaults:** Public defaults contain no hooks or access to production infrastructure or cloud root accounts.
13. **Universal auditability:** Every privileged action, decision, parameter, and outcome is logged in an append-only audit trail.
14. **Protected branch immutability:** AI agents cannot directly push, force push, or rewrite history on protected branches (`main`, `release/*`).
15. **Explicit authorization for sensitive actions:** Destructive mutations, source patching, package installation, and git pushes require human-in-the-loop approval.
16. **Absolute prohibition of CES internal secrets:** No internal VM addresses, CES network topology, private certificates, or company secrets may ever enter this repository.
17. **Permanence of committed secrets:** Public Git history is permanent. Any accidental secret commit is treated as compromised immediately.
18. **Vendor neutrality:** The control plane protocol and security enforcement must remain standard and vendor-neutral.
19. **Code-enforced security:** Security controls must be implemented as verifiable code invariants, never documentation alone.
20. **Mandatory negative controls:** Security tests must include negative assertions proving that blocked operations cannot succeed.

---

## 2. Public Repository Safety & Secret Handling

This repository (`kpthakur2026/cesspace-arc`) is **public**.

### Strictly Prohibited Artifacts

Under no circumstances may any contributor or automated agent commit:

- API keys (OpenAI, DeepSeek, Google, Anthropic, AWS, GCP, Azure)
- SSH private keys (`id_rsa`, `id_ed25519`, etc.)
- OAuth client secrets, access tokens, refresh tokens
- Service account credentials (JSON/P12/PEM)
- Real `.env` files containing environment secrets
- Private certificates or cryptographic signing keys
- Internal CES network addresses, hostnames, or topology maps
- Private deployment manifests or production credentials

### Allowed Artifacts

- Sanitized templates: `.env.example`, `config.example.yaml`, `policy.example.yaml`
- Documentation placeholders (e.g., `REPLACE_WITH_YOUR_KEY`, `EXAMPLE_TOKEN_DO_NOT_USE`)
- RFC 5737 documentation IP addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)

---

## 3. Reporting a Vulnerability

We welcome vulnerability reports from the security community, researchers, and users.

### Responsible Disclosure Protocol

- **Do NOT open a public GitHub issue** for a potential security vulnerability.
- Please report vulnerabilities privately to the maintainers via GitHub Private Vulnerability Reporting or via email to:
  **`security-cesspace-arc@cespr.dev`** (or repository security advisory portal).
- Please include:
  1. Description of the vulnerability and attack vector.
  2. Steps to reproduce or proof-of-concept (PoC) code.
  3. Affected components, versions, or environments.
  4. Suggested remediation if known.

### Response Timelines

- **Initial Acknowledgement:** Within 48 hours of report receipt.
- **Triage & Severity Assessment:** Within 5 business days.
- **Remediation & Patch Release:** Priority aligned with severity (Critical: < 7 days; High: < 14 days; Moderate: < 30 days).
- **Public Disclosure:** Coordinated after patch availability.

---

## 4. Supported Versions

Only the current active release candidate or stable branch receives security updates.

| Version                | Supported          | Notes                              |
| :--------------------- | :----------------- | :--------------------------------- |
| `0.0.0-rc00` (Current) | :white_check_mark: | Architecture & Security Foundation |
| Future Releases        | :white_check_mark: | Active development stream          |

---

## 5. Security Architecture References

For detailed specifications, see:

- [Threat Model](docs/threat-model/threat-model.md)
- [Trust Boundaries](docs/architecture/trust-boundaries.md)
- [Permanent Security Invariants](docs/architecture/security-invariants.md)
- [Filesystem Security Boundary](docs/architecture/filesystem-boundary.md)
- [Permission Model](docs/architecture/permission-model.md)
- [Audit & Evidence Specification](docs/architecture/audit-model.md)
- [Error Model & Information Disclosure](docs/architecture/error-model.md)

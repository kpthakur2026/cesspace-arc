# CesSpace ARC — Project Handoff & RC-00 Development Specification

**Repository:** `kpthakur2026/cesspace-arc`
**Project name:** CesSpace ARC
**License:** Apache License 2.0
**Repository visibility:** Public
**Status:** Architecture / security foundation only
**Current stage:** `RC-00`
**Lead Developer & Architect:** P Thakur
**Primary target:** Linux development VMs
**Protocol direction:** MCP-based, vendor-neutral
**Document purpose:** This file applies only to the `cesspace-arc` project.

---

## 1. Project Mission

CesSpace ARC is a secure, vendor-neutral **agent-to-machine control plane** for authorized AI agents and development tools.

The long-term goal is to provide one controlled interface through which compatible AI agents can inspect and operate authorized development machines, VMs, repositories, terminals, and processes without giving those agents unrestricted machine access.

CesSpace ARC is not a clone of Desktop Commander. It must be independently designed and implemented.

### Product positioning

> **CesSpace ARC — Secure Agent-to-Machine Infrastructure**

The project should be designed so that compatible clients can eventually include:

- Codex
- ChatGPT-compatible MCP clients
- Claude / Claude Code
- Gemini / Antigravity
- OpenCode
- DeepSeek-backed agents
- future MCP-compatible systems

---

## 2. Non-Goals for Initial Development

The following are explicitly **out of scope** for the first implementation stages:

- GUI desktop control
- screen streaming
- browser automation
- Windows automation
- macOS automation
- multi-tenant SaaS
- billing
- marketplace
- production deployment
- cloud-root administration
- unrestricted shell access
- arbitrary filesystem access
- production database access
- credential management
- copying Desktop Commander implementation/code

---

## 3. Permanent Security Principles

These requirements are mandatory and must not be weakened by implementation agents.

1. **Zero implicit trust.**
2. **Default deny.**
3. **Least privilege.**
4. **Fail closed.**
5. Authentication and authorization are separate concerns.
6. Every privileged operation must pass through policy enforcement.
7. Agents must never bypass the policy engine.
8. Filesystem access must be restricted to explicitly authorized roots.
9. Secrets and credential locations must be inaccessible by default.
10. Terminal execution must be policy-controlled.
11. Destructive operations must be denied by default.
12. Production/cloud-root access must not be available in the public project defaults.
13. Every privileged action must be auditable.
14. Protected Git branches must not be mutated directly.
15. Security-sensitive actions require explicit authorization or approval.
16. No CES-specific secrets, infrastructure details, credentials, VM addresses, tokens, or private deployment configuration may enter this public repository.
17. No secret should ever be committed and then “removed later.” Public Git history must be treated as permanent.
18. The project must remain vendor-neutral.
19. Security controls must be enforced in code, not only documented.
20. Tests must include negative controls proving denied actions actually fail.

---

## 4. Public Repository Safety Rules

Because `kpthakur2026/cesspace-arc` is public, never commit:

- API keys
- DeepSeek keys
- OpenAI keys
- Google keys
- SSH private keys
- OAuth client secrets
- access tokens
- refresh tokens
- service-account JSON
- AWS credentials
- GCP credentials
- database passwords
- real `.env` files
- private certificates
- private keys
- internal CES IP addresses
- private VM hostnames
- production URLs containing secrets
- private network topology
- private deployment manifests
- CES production configuration

Allowed examples:

- `.env.example`
- `config.example.yaml`
- `policy.example.yaml`
- fake IPs / example domains
- documented placeholders
- sanitized sample policies

---

## 5. Proposed Repository Structure

```text
cesspace-arc/
├── apps/
│   ├── mcp-server/
│   └── cli/
│
├── packages/
│   ├── protocol/
│   ├── filesystem/
│   ├── git/
│   ├── terminal/
│   ├── processes/
│   ├── policy/
│   ├── auth/
│   └── audit/
│
├── docs/
│   ├── architecture/
│   ├── threat-model/
│   └── adr/
│
├── examples/
├── tests/
├── .github/
│   └── workflows/
│
├── AGENTS.md
├── SECURITY.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── LICENSE
├── README.md
├── .gitignore
└── package.json
```

The exact implementation layout may evolve during RC-00, but architectural ownership must remain clear.

---

## 6. Target Architecture

```text
AI Client / Coding Agent
          │
          ▼
     MCP Interface
          │
          ▼
   ARC Remote Gateway
          │
     Authentication
          │
          ▼
       Policy Engine
          │
          ▼
        Audit Layer
          │
          ▼
       ARC VM Agent
          │
   ┌──────┼────────┬──────────┐
   │      │        │          │
 Files    Git   Terminal   Processes
```

### Mandatory invariant

**No Files / Git / Terminal / Process operation may execute without going through authorization/policy enforcement.**

---

## 7. Initial Tool Taxonomy

### Read-only tools

Planned early capabilities:

```text
health
list_directory
read_file
search_files
search_text
git_status
git_diff
git_log
system_status
```

### Later controlled tools

```text
run_command
read_command_output
cancel_command
process_list
apply_patch
write_file
create_file
```

These must not be implemented before the policy model is defined.

---

## 8. Permission Model

CesSpace ARC should use at least three policy outcomes:

### ALLOW

Examples:

```text
read approved workspace
search approved workspace
git status
git diff
git log
run tests
run lint
run typecheck
run build
```

### REQUIRE APPROVAL

Examples:

```text
write or patch source
git commit
git push
package installation
creating executable files
changing repository configuration
```

### DENY

Examples:

```text
sudo
root shell
rm -rf /
arbitrary filesystem roots
read ~/.ssh
read cloud credential directories
read production secrets
production DB access
cloud-root access
protected branch mutation
production deployment
disk formatting
shutdown/reboot
```

Precedence must be:

```text
DENY > REQUIRE APPROVAL > ALLOW
```

---

## 9. Development Stages

### RC-00 — Architecture & Security Foundation

**Target:** 3–5 hours

Deliver:

- architecture overview
- threat model
- trust boundaries
- security invariants
- tool taxonomy
- permission model
- filesystem boundary model
- audit model
- error model
- proposed repository structure
- ADRs
- RC-01 acceptance criteria

**No remote command execution. No public service. No deployment.**

---

### RC-01 — Read-Only MCP Core

**Target:** 6–10 hours

Implement read-only capabilities such as:

```text
health
list_directory
read_file
search_files
search_text
git_status
git_diff
git_log
system_status
```

Requirements:

- approved-root enforcement
- canonical path checks
- symlink escape protection
- structured errors
- tests
- negative controls

---

### RC-02 — Controlled Terminal & Process Layer

**Target:** 6–10 hours

Potential capabilities:

```text
run_command
read_command_output
cancel_command
process_list
```

Requirements:

- command policy
- timeout enforcement
- working-directory restrictions
- output limits
- process ownership/tracking
- no shell escalation
- negative tests

---

### RC-03 — Safe File Modification

**Target:** 6–10 hours

Potential capabilities:

```text
apply_patch
write_file
create_file
```

Requirements:

- authorized roots only
- atomic writes where possible
- size limits
- patch validation
- symlink/path protections
- audit evidence
- no secret-location writes

---

### RC-04 — Policy Engine

**Target:** 10–14 hours

Implement:

- explicit policy schema
- ALLOW / APPROVAL / DENY
- deny precedence
- command classification
- path classification
- Git action classification
- policy evaluation tests
- default-deny behavior
- policy decision evidence

---

### RC-05 — Secure Remote Gateway

**Target:** 12–18 hours

Implement only after RC-00 through RC-04 are approved.

Planned capabilities:

- HTTPS remote MCP
- secure authentication
- short-lived credentials
- session identity
- device enrollment model
- rate limiting
- request size limits
- timeout enforcement
- no anonymous access
- no direct unrestricted VM exposure

---

### RC-06 — Audit & Evidence

**Target:** 8–12 hours

Record:

```text
actor
agent/client
device
repository/workspace
tool
policy decision
start time
end time
result
exit code
changed files
```

Never record:

- raw secrets
- auth tokens
- passwords
- private keys

---

### RC-07 — Engineering-Aware Commands

**Target:** 8–12 hours

Potential higher-level tools:

```text
arc_repo_status
arc_worktree_status
arc_review_diff
arc_verify
arc_test
arc_ci_status
arc_stage_evidence
```

These should compose lower-level secured primitives rather than bypassing them.

---

### RC-08 — Integrations + Security Review

**Target:** 18–30 hours

Validate with multiple compatible agent clients.

Perform:

- path traversal testing
- symlink escape testing
- command injection testing
- prompt-injection resistance testing
- secret leakage testing
- privilege-escalation testing
- timeout/resource-abuse testing
- concurrency testing
- interrupted-session recovery
- negative authorization testing

---

## 10. RC-00 Acceptance Criteria

RC-00 is complete only when:

- architecture is documented
- trust boundaries are explicitly drawn/described
- threat model exists
- permanent security invariants are documented
- policy outcomes and precedence are defined
- filesystem security model is documented
- audit/evidence requirements are defined
- error model is defined
- ADRs capture major design decisions
- RC-01 scope and acceptance criteria are explicit
- no remote-access implementation has been introduced
- no secrets or CES-private infrastructure data exist in the repository
- documentation/static checks pass
- complete diff is presented for independent review

---

## 11. Core Operating Rules

For this repository:

- use single-branch development initially
- use separate branches/worktrees for independent tasks
- never allow two writable processes in the same worktree
- `accept-edits` may be used for normal repository file edits
- do not enable unrestricted terminal permissions
- do not deploy
- do not expose services publicly
- do not push directly to protected `main`
- do not merge your own PR
- do not lower tests/gates to make a build pass
- do not use `|| true` or equivalent to suppress required failures
- do not remove security checks to unblock progress
- do not invent secrets or example credentials that resemble real credentials
- stop at stage boundaries for independent review

---

## 12. Initial Prompt Specification — RC-00 Only

Copy the following prompt after cloning the repository:

```text
You are working only in the kpthakur2026/cesspace-arc repository.

Project: CesSpace ARC
License: Apache-2.0
Repository visibility: Public
Current stage: RC-00 Architecture & Security Foundation.

CesSpace ARC is a secure, vendor-neutral agent-to-machine control plane for authorized AI agents and development tools. It will eventually provide policy-controlled MCP access to development machines and VMs for filesystem, Git, terminal, process, and engineering operations.

IMPORTANT: Work ONLY on RC-00.

Do NOT implement:
- terminal execution
- remote networking
- authentication services
- file-write capability
- public deployment
- VM connectivity
- cloud integrations

Produce the architecture/security foundation first.

Required RC-00 outputs:

1. Architecture overview.
2. Trust-boundary definition.
3. Threat model.
4. Permanent security invariants.
5. MCP tool taxonomy.
6. Permission model with ALLOW / REQUIRE APPROVAL / DENY.
7. Filesystem boundary/security model.
8. Audit/evidence model.
9. Structured error model.
10. Proposed repository/package ownership model.
11. Architecture Decision Records for important decisions.
12. Explicit RC-01 scope and acceptance criteria.
13. AGENTS.md with project-specific agent rules.
14. SECURITY.md appropriate for an open-source security-sensitive project.
15. CONTRIBUTING.md with security-conscious contribution rules.

Permanent security requirements:

- zero implicit trust
- default deny
- least privilege
- fail closed
- authentication is separate from authorization
- every privileged operation must pass through policy enforcement
- no arbitrary filesystem access
- authorized workspace roots only
- secrets inaccessible by default
- terminal execution must later be policy controlled
- no production/cloud-root access in defaults
- no direct protected-branch mutation
- every privileged action must be auditable
- DENY must override approval and allow
- no security control may exist only in documentation if it is enforceable in code
- negative controls will be required in implementation stages

Public repository rules:

Never add:
- API keys
- tokens
- passwords
- SSH keys
- cloud credentials
- service-account JSON
- OAuth secrets
- real .env files
- private certificates
- private CES VM addresses
- internal production infrastructure details
- any real CES deployment secret/configuration

Use only sanitized example configuration.

Do not copy Desktop Commander source code or implementation.
Design CesSpace ARC independently.

Do not push, merge, deploy, publish packages, or expose any service.

At completion:
- run all available documentation/static checks
- run git diff --check
- show git status
- present the complete diff summary
- present the RC-00 evidence
- stop for independent review before RC-01
```

---

## 13. First Branch

Recommended initial branch:

```bash
git switch -c feat/rc-00-architecture
```

Development must stay on this branch for RC-00.

---

## 14. Initial Quality Gates

Before RC-01 begins, establish at minimum:

```text
format check
lint
typecheck
unit tests
git diff --check
secret scanning
dependency review
security audit
```

As implementation grows, add:

```text
package boundary checks
cycle detection
SAST
license checks
negative security tests
integration tests
```

Do not create a gate that is silently bypassed.

---

## 15. Open-Source Direction

CesSpace ARC is intended to become open-source infrastructure.

The project should remain useful without private CES infrastructure.

The public core may include:

- MCP protocol/server
- policy engine
- filesystem layer
- terminal layer
- Git layer
- audit framework
- CLI
- SDKs
- examples
- documentation

Private CES deployment material must remain outside this repository.

---

## 16. Stage-Gate Rule

At every stage:

```text
PLAN
  ↓
IMPLEMENT
  ↓
TEST
  ↓
SECURITY NEGATIVE CONTROLS
  ↓
DIFF / EVIDENCE
  ↓
INDEPENDENT REVIEW
  ↓
APPROVAL
  ↓
NEXT STAGE
```

No agent may self-approve its own stage.

---

## 17. Current Instruction

**Start RC-00 only.**

Do not proceed to RC-01 until the RC-00 architecture and security foundation have been independently reviewed and approved.

# Engineering Governance — CesSpace ARC

> **Repository:** `kpthakur2026/cesspace-arc`
> **Status:** Stage-Gated Engineering Rules
> **Classification:** Project Governance Specification

---

## 1. Core Mission & Inviolable Directives

CesSpace ARC is a secure, vendor-neutral **agent-to-machine control plane** designed to provide controlled, policy-enforced access to development environments without exposing unrestricted host access to external clients or automated tools.

Because this repository contains the core security architecture, policy enforcement, and audit mechanisms of that control plane, **all development work operating on this codebase must adhere strictly to these operational constraints.**

### Mandatory Operating Principles

1. **Strict Stage Adherence:** Execute **only** the work explicitly assigned to the current Release Candidate (RC) stage. Never implement features belonging to subsequent stages ahead of time.
2. **Independent Review Boundary:** When a stage is complete, development must stop immediately. No contributor or process may self-approve its own stage. Present the complete diff, verification evidence, and git status, and wait for independent review and approval.
3. **Zero Bypasses:** Never use `|| true`, `--no-verify`, `--force`, or equivalent workarounds to bypass failing tests, typechecks, linters, or security checks. If a check fails, the root cause must be resolved within policy.
4. **Permanent Secret Hygiene:** Never introduce secrets, API keys, credentials, private IP addresses, or internal infrastructure details into this public repository. Once committed to Git, data must be treated as permanently compromised.
5. **No Direct Mutations to Protected Branches:** Never commit directly to `main` or push to remote branches without explicit authorization. Never merge your own pull requests without independent review.
6. **No Independent Service Exposure:** Never bind listeners to public network interfaces, start detached long-running background daemons outside sandbox bounds, or deploy services during development stages.
7. **Negative Testing Mandatory:** Every security control must be backed by negative tests proving that unauthorized, malformed, or malicious attempts are properly rejected with default-deny behavior.

---

## 2. Stage-Gate Lifecycle

Every stage follows a strict linear verification cycle:

```text
  ┌──────────┐
  │   PLAN   │  Analyze requirements, architecture, and threat impact
  └────┬─────┘
       ▼
  ┌──────────┐
  │IMPLEMENT │  Write minimal, type-safe, modular code and documentation
  └────┬─────┘
       ▼
  ┌──────────┐
  │   TEST   │  Unit tests, format checks, linting, typechecking
  └────┬─────┘
       ▼
  ┌──────────┐
  │ NEGATIVE │  Verify fail-closed and default-deny security controls
  │ CONTROLS │
  └────┬─────┘
       ▼
  ┌──────────┐
  │ EVIDENCE │  Generate git diff --check, status, and verification log
  └────┬─────┘
       ▼
  ┌──────────┐
  │  REVIEW  │  STOP HERE. Hand off for independent review
  └────┬─────┘
       ▼
  ┌──────────┐
  │ APPROVAL │  Explicit authorization required to enter next stage
  └──────────┘
```

---

## 3. Prohibited Actions

The following actions are strictly forbidden within this repository:

- **Executing remote commands or opening outbound reverse shells.**
- **Accessing files outside the repository root** (e.g., inspecting `/home`, `~/.ssh`, `~/.aws`, `~/.config`, `/etc`).
- **Modifying `.git/hooks` or `.git/config`** directly.
- **Copying code from Desktop Commander** or any proprietary external source with incompatible licensing.
- **Adding mock credentials that resemble live production keys** (use generic placeholders like `EXAMPLE_TOKEN_DO_NOT_USE`).
- **Weakening path sanitization** or introducing path-traversal vulnerabilities (`../`).
- **Proceeding across stage boundaries** without explicit instruction and approval.

---

## 4. Current Repository State & Context

- **Current Stage:** `RC-00` (Architecture & Security Foundation).
- **Active Branch:** `feat/rc-00-architecture`.
- **Allowed Scope:** Documentation, architectural specifications, threat modeling, ADRs, schema definitions, repository scaffolding, and quality gate verification.
- **Forbidden Scope for RC-00:** Any implementation of terminal execution, remote networking, authentication services, host file writes, or VM connectivity.

---

## 5. Verification Checklist

Before declaring any stage complete, the following must be executed and documented:

1. `git diff --check` (clean whitespace, zero merge conflicts).
2. Secret scanning check (Gitleaks and repository policy check).
3. Documentation completeness and link verification.
4. Static typecheck and linting (TypeScript `tsc --build`, ESLint).
5. Output of `git status` demonstrating clean tracking.
6. Complete diff summary detailing all created and modified files.

# Contributing to CesSpace ARC

Thank you for your interest in contributing to **CesSpace ARC**!

CesSpace ARC is a secure, vendor-neutral agent-to-machine control plane. Because this project mediates between autonomous AI agents and execution machines, **security, correctness, and auditability take priority over speed of delivery.**

---

## 1. Core Contribution Rules

1. **Stage-Gate Discipline:** Work proceeds strictly through designated Release Candidates (RC-00 through RC-08). Never submit PRs implementing features from future stages.
2. **Security by Default:** All new tools, capabilities, or modifications must adhere to **Default Deny** and **Fail Closed** semantics.
3. **Mandatory Negative Controls:** Every PR introducing a security boundary, policy check, or path validator **must include negative tests** proving that unauthorized, malformed, or malicious inputs fail closed.
4. **Zero Secret Policy:** Never commit secrets, tokens, private keys, or internal network topology. Public Git history is permanent. Run secret checks before submitting.
5. **Quality Gates Must Pass:** All format checks, linter runs, typechecks, tests, and `git diff --check` must pass cleanly without suppression (`|| true` or `--no-verify`).
6. **No Self-Approval:** All changes require independent review and approval by repository maintainers.

---

## 2. Development Workflow

### Branching Strategy
- Feature branches must follow the naming pattern:
  - `feat/rc-XX-<feature-name>` (e.g., `feat/rc-00-architecture`)
  - `fix/rc-XX-<issue-description>`
  - `docs/<topic>`
- Do not submit PRs targeting protected branches with unreviewed work.

### Commit Guidelines
- Use clear, conventional commit messages:
  - `feat(policy): implement AST-based command whitelist`
  - `fix(filesystem): prevent symlink traversal across workspace root`
  - `docs(threat-model): add indirect prompt injection analysis`
  - `test(audit): add negative assertions for unredacted token logging`
- Ensure commits are atomic and cleanly formatted. Run `git diff --check` before committing.

---

## 3. Pull Request Checklist

Before submitting a Pull Request, confirm that:

- [ ] The change belongs strictly to the active release candidate stage.
- [ ] No files or directories outside approved scope have been modified.
- [ ] `git diff --check` returns zero errors or trailing whitespace issues.
- [ ] Static checks, linters, and typechecks pass with zero warnings or errors.
- [ ] Negative test cases are included for any policy, path, or execution logic.
- [ ] No secrets, real credentials, or private internal IP addresses are present.
- [ ] Documentation and ADRs have been updated to reflect architectural changes.
- [ ] The PR description includes explicit verification evidence.

---

## 4. Code of Conduct

All contributors and participants are required to adhere to the [Code of Conduct](CODE_OF_CONDUCT.md).

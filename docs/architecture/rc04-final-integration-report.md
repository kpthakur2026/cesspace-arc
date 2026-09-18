# RC-04 Final Integration & Acceptance Report

**Stage:** RC-04 — Declarative Policy Engine & Human Approval

**Scope title:** Declarative policy engine, approval state machine, authenticated
local admin channel, MCP approval redemption, and the approval audit lifecycle.

**Base main:** `cff5ce6ac88380341fd69781ab30057b2d165aa3`

**Approved implementation baseline before Task 6:** `0cf2b24d9d2da4d28a5fdaf40d7937b46a0acf1d`

**Final Task-6 commit:** the commit containing this report.

**Branch:** `feat/rc-04-policy-approvals`

> PR and merge status is **not** asserted by this document. It is tracked
> externally in GitHub against the branch and commit above. A report cannot
> self-certify a review that has not happened.

---

## 1. Six-Task Implementation Summary

| Task | Deliverable                                                                                                                                       | Commit                                                         |
| :--- | :------------------------------------------------------------------------------------------------------------------------------------------------ | :------------------------------------------------------------- |
| 1.3  | Deterministic RC-03 rollback security regression test (no reliance on inode allocation luck).                                                     | `test(rc-03): make replacement inode regression deterministic` |
| 2    | Strict declarative policy parser, normalization, matchers, canonical `policyHash`, benchmark.                                                     | `feat(rc-04): add declarative policy parser`                   |
| 2.1  | Closed the YAML mapping-key node hardening gap (anchors/aliases/tags on mapping keys).                                                            | `fix(rc-04): validate yaml mapping key nodes`                  |
| 3    | Trusted local operator CLI plus Ed25519-authenticated admin IPC over a Unix domain socket.                                                        | `feat(rc-04): add authenticated local admin channel`           |
| 3.1  | Removed security-scanner suppressions; completed private-key buffer hygiene.                                                                      | `fix(rc-04): harden admin key handling`                        |
| 3.2  | Wiped the strict-base64 rejection buffer on the non-canonical path.                                                                               | `fix(rc-04): wipe rejected base64 buffers`                     |
| 4    | MCP approval request, token redemption, and controlled mutation execution.                                                                        | `feat(rc-04): integrate approval redemption`                   |
| 4.1  | Startup order, human-review visibility through the admin channel and CLI, built-in root compatibility.                                            | `fix(rc-04): complete approval review integration`             |
| 4.2  | Canonical review targets and move fail-closed completeness.                                                                                       | `fix(rc-04): canonicalize approval review targets`             |
| 4.3  | Block target-less root file mutations; approval-review invariant.                                                                                 | `fix(rc-04): block root mutation approvals`                    |
| 5    | Security hardening, race verification, and the approval audit lifecycle.                                                                          | `feat(rc-04): harden approval audit lifecycle`                 |
| 5.1  | Closed audit durability and immutability gaps (unaudited-admin mode, flush-failure semantics, defensive `log()` return, central error redaction). | `fix(rc-04): close approval audit durability gaps`             |
| 6A   | Final verification gates and acceptance documentation (this report).                                                                              | `chore(rc-04): finalize verification gates`                    |

---

## 2. Final Architecture Summary

### 2.1 Layer 1 — Permanent Security Kernel

`SecurityKernel` is fixed at build time and is evaluated before any declarative
policy. It performs default-deny admission, canonical workspace-root binding,
permanent sensitive-path denial, and — for every RC-03 file mutation tool — an
unconditional elevation to `REQUIRE_APPROVAL`. Layer 1 is not configurable and
cannot be relaxed by any operator-supplied document.

### 2.2 Layer 2 — Declarative Policy Engine

`DeclarativePolicyEngine` is an immutable engine built from operator YAML or
JSON. It is parsed under a closed schema with `uniqueKeys`, no merge support, no
aliases, and a depth bound of 32. Rules are compiled once; there is no mutation
path and no hot reload. Precedence is `DENY > REQUIRE_APPROVAL > ALLOW`, with the
lexicographically smallest matching rule id as the deterministic tie-break, so
physical rule order never influences a decision. An explicitly configured but
invalid policy fails closed — there is no built-in fallback.

### 2.3 Approval State Machine

`ApprovalStateManager` holds all approval state **in volatile memory**. A record
transitions `PENDING → APPROVED → CONSUMED`, or terminally to `REJECTED`,
`EXPIRED`, or `INVALIDATED`. Every transition is single-shot: a terminal record
never transitions again, and repeated reads never re-emit lifecycle evidence.

### 2.4 Authenticated Local Admin IPC

`AdminIpcServer` listens on a Unix domain socket only. Authentication is an
Ed25519 challenge–response over a single-use connection; the operator private key
is read exclusively from an inherited file descriptor (`--admin-key-fd` /
`CESSPACE_ARC_ADMIN_PRIVATE_KEY_FD`), never from argv, environment text, or a path.
The channel is local-only, same-UID, and there is no network listener.

### 2.5 MCP Approval Redemption

A mutation request that resolves to `REQUIRE_APPROVAL` returns a request id and
executes nothing. Redemption follows a frozen order: control schema → business
schema → workspace → Layer 1 → Layer 2 → mutation floor → approval validation →
atomic `APPROVED → CONSUMED` → strip the reserved control object → subsystem.
The reserved `_arcApproval` object is removed before business validation so it can
never be smuggled into an audited parameter set.

### 2.6 Approval Audit Lifecycle

The state machine emits bounded, synchronous lifecycle events
(`APPROVAL_REQUESTED`, `APPROVAL_GRANTED`, `APPROVAL_REJECTED`,
`APPROVAL_EXPIRED`, `APPROVAL_CONSUMED`, `APPROVAL_INVALIDATED`,
`APPROVED_EXECUTION_SUCCEEDED`, `APPROVED_EXECUTION_FAILED`) through a sink that
buffers them and flushes them into the **one** existing SHA-256 hash chain. One
sink exists per audit chain; a second observer on the same chain would double-write
every transition while remaining individually well-formed and correctly chained.

---

## 3. Frozen Invariants

| Invariant                        | Statement                                                                                                                                                                                                   |
| :------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Mutation execution**           | No file mutation executes without a verified, consumed approval in the **same invocation**. There are three independent clamps: Layer 1, Layer 2, and an MCP-server floor, plus an execution-time backstop. |
| **Approval token properties**    | 256-bit random, disclosed exactly once over the authenticated admin channel, stored only as a SHA-256 digest, compared in constant time over 32-byte buffers. Never logged, persisted, or audited.          |
| **300-second monotonic TTL**     | The deadline is computed from `process.hrtime.bigint()`. Wall clock is used only for human-readable display and cannot extend the deadline.                                                                 |
| **policyHash binding**           | The approval is bound to the canonical `policyHash`. A mismatch permanently `INVALIDATED`s the record; reverting the policy does not revive it.                                                             |
| **executionPayloadHash binding** | Bound to a canonical JSON projection of the validated business parameters, actor, workspace, and policy hash. Any change to content, patch text, or target path breaks redemption.                          |
| **Restart volatility**           | All approval state is in memory. A restart purges every record; previously issued tokens carry no authority anywhere.                                                                                       |
| **Audit minimization**           | Records carry bounded facts only: no token, no token digest, no review material, no file content, no patch text, no environment values, and no raw absolute host path.                                      |
| **Human review behavior**        | The operator sees a bounded review summary and the review material for a `PENDING` request, on the authenticated local channel only. Review buffers are released on every terminal state.                   |
| **No MCP admin authority**       | No approval administration is reachable from the MCP tool surface. Attempts are `POLICY_DENIED` with zero state mutation.                                                                                   |
| **No remote admin endpoint**     | The admin channel is a Unix domain socket only. There is no HTTP/SSE admin listener, no TCP listener, and no remote administration path.                                                                    |

---

## 4. Negative-Control Coverage (RC04-NEG-01 … RC04-NEG-38)

Every control below is executed as a real `node:test` case in
`tests/rc04-negative-controls.test.js`. Deeper regression suites are listed as
secondary references only.

| NEG ID      | Invariant                                                                                  | Authoritative acceptance test                          |
| :---------- | :----------------------------------------------------------------------------------------- | :----------------------------------------------------- |
| RC04-NEG-01 | MCP cannot administer approvals; no approval state is created.                             | `tests/rc04-negative-controls.test.js` → `RC04-NEG-01` |
| RC04-NEG-02 | A valid token cannot override a Layer 1 `DENY`; the token stays unconsumed.                | `tests/rc04-negative-controls.test.js` → `RC04-NEG-02` |
| RC04-NEG-03 | A valid token cannot override a Layer 2 `DENY`; the token stays unconsumed.                | `tests/rc04-negative-controls.test.js` → `RC04-NEG-03` |
| RC04-NEG-04 | A declarative `ALLOW` on a mutation is clamped to `REQUIRE_APPROVAL`.                      | `tests/rc04-negative-controls.test.js` → `RC04-NEG-04` |
| RC04-NEG-05 | A mutation without `_arcApproval` returns `APPROVAL_REQUIRED` and mutates nothing.         | `tests/rc04-negative-controls.test.js` → `RC04-NEG-05` |
| RC04-NEG-06 | A missing token fails schema admission with `INVALID_REQUEST_SCHEMA` and creates no state. | `tests/rc04-negative-controls.test.js` → `RC04-NEG-06` |
| RC04-NEG-07 | An unknown canonical `requestId` is rejected with `APPROVAL_REJECTED`; no new approval.    | `tests/rc04-negative-controls.test.js` → `RC04-NEG-07` |
| RC04-NEG-08 | A wrong token is rejected with `APPROVAL_REJECTED`; the record stays `APPROVED`.           | `tests/rc04-negative-controls.test.js` → `RC04-NEG-08` |
| RC04-NEG-09 | An expired approval (> 300 s) is rejected with `APPROVAL_EXPIRED` and executes nothing.    | `tests/rc04-negative-controls.test.js` → `RC04-NEG-09` |
| RC04-NEG-10 | An operator-rejected request cannot be redeemed (`APPROVAL_REJECTED`).                     | `tests/rc04-negative-controls.test.js` → `RC04-NEG-10` |
| RC04-NEG-11 | Replay of a `CONSUMED` token is rejected; no second execution.                             | `tests/rc04-negative-controls.test.js` → `RC04-NEG-11` |
| RC04-NEG-12 | Concurrent redemption executes the tool at most once.                                      | `tests/rc04-negative-controls.test.js` → `RC04-NEG-12` |
| RC04-NEG-13 | Content and patch-text tampering break the payload binding.                                | `tests/rc04-negative-controls.test.js` → `RC04-NEG-13` |
| RC04-NEG-14 | Path tampering breaks the payload binding.                                                 | `tests/rc04-negative-controls.test.js` → `RC04-NEG-14` |
| RC04-NEG-15 | An actor mismatch is rejected with `APPROVAL_REJECTED` and executes nothing.               | `tests/rc04-negative-controls.test.js` → `RC04-NEG-15` |
| RC04-NEG-16 | A workspace mismatch never executes in the redirected workspace.                           | `tests/rc04-negative-controls.test.js` → `RC04-NEG-16` |
| RC04-NEG-17 | A policy change permanently `INVALIDATED`s the record; the token is not consumed.          | `tests/rc04-negative-controls.test.js` → `RC04-NEG-17` |
| RC04-NEG-18 | Reverting the policy does not revive an `INVALIDATED` record.                              | `tests/rc04-negative-controls.test.js` → `RC04-NEG-18` |
| RC04-NEG-19 | A case-modified token is rejected with `APPROVAL_REJECTED`.                                | `tests/rc04-negative-controls.test.js` → `RC04-NEG-19` |
| RC04-NEG-20 | A token within 128 characters but over 128 UTF-8 bytes fails schema admission.             | `tests/rc04-negative-controls.test.js` → `RC04-NEG-20` |
| RC04-NEG-21 | An uppercase 32-hex `requestId` fails schema admission.                                    | `tests/rc04-negative-controls.test.js` → `RC04-NEG-21` |
| RC04-NEG-22 | Metadata-only changes do not change `policyHash`.                                          | `tests/rc04-negative-controls.test.js` → `RC04-NEG-22` |
| RC04-NEG-23 | Semantic changes alter `policyHash`.                                                       | `tests/rc04-negative-controls.test.js` → `RC04-NEG-23` |
| RC04-NEG-24 | Unknown workspace or mismatched `rootHash` fails closed with `UNHEALTHY`, no fallback.     | `tests/rc04-negative-controls.test.js` → `RC04-NEG-24` |
| RC04-NEG-25 | A workspace assertion declaring `path`/`rootPath`/`directory` is rejected.                 | `tests/rc04-negative-controls.test.js` → `RC04-NEG-25` |
| RC04-NEG-26 | YAML anchors, aliases, and merge keys are rejected with `POLICY_PARSE_ERROR`.              | `tests/rc04-negative-controls.test.js` → `RC04-NEG-26` |
| RC04-NEG-27 | Nesting deeper than 32 is rejected with `POLICY_PARSE_ERROR`.                              | `tests/rc04-negative-controls.test.js` → `RC04-NEG-27` |
| RC04-NEG-28 | An embedded `**` within a path segment is rejected at parse time.                          | `tests/rc04-negative-controls.test.js` → `RC04-NEG-28` |
| RC04-NEG-29 | Unsupported glob syntax (brace, extglob, regex, leading slash, traversal) is rejected.     | `tests/rc04-negative-controls.test.js` → `RC04-NEG-29` |
| RC04-NEG-30 | `allowedBinaries` and `blockedBinaries` in one rule is rejected.                           | `tests/rc04-negative-controls.test.js` → `RC04-NEG-30` |
| RC04-NEG-31 | 16 concurrent identical requests produce one active record and one `requestId`.            | `tests/rc04-negative-controls.test.js` → `RC04-NEG-31` |
| RC04-NEG-32 | A repeat while `APPROVED` reuses the record with no duplicate allocation and no TTL reset. | `tests/rc04-negative-controls.test.js` → `RC04-NEG-32` |
| RC04-NEG-33 | A wall-clock rollback cannot extend the monotonic deadline.                                | `tests/rc04-negative-controls.test.js` → `RC04-NEG-33` |
| RC04-NEG-34 | Quota exhaustion is rejected with `RESOURCE_EXHAUSTED` and preserves existing state.       | `tests/rc04-negative-controls.test.js` → `RC04-NEG-34` |
| RC04-NEG-35 | No raw approval token or token digest ever reaches a serialized `AuditRecord`.             | `tests/rc04-negative-controls.test.js` → `RC04-NEG-35` |
| RC04-NEG-36 | Raw file content and patch lines never reach an `AuditRecord`.                             | `tests/rc04-negative-controls.test.js` → `RC04-NEG-36` |
| RC04-NEG-37 | Bypass fields (`approvalToken`, `bypassApproval`, `sudo`, `force`) remain rejected.        | `tests/rc04-negative-controls.test.js` → `RC04-NEG-37` |
| RC04-NEG-38 | A restart purges approvals and makes previously issued tokens unusable.                    | `tests/rc04-negative-controls.test.js` → `RC04-NEG-38` |

**Coverage:** 38 of 38 frozen controls, each executed against public runtime
behaviour. No control is claimed on the strength of a source grep.

### 4.1 Layered controls verified by ablation

Several controls are enforced by more than one independent mechanism. Where that
is the case the acceptance suite was ablated to confirm the control is genuinely
exercised rather than satisfied incidentally:

- **RC04-NEG-04** is enforced by three independent clamps — the Layer 1 kernel,
  the Layer 2 engine, and an MCP-server floor — plus an execution-time backstop.
  The control fails only when all of them are disabled, and it was verified to
  fail in that configuration.
- **RC04-NEG-36** is enforced by the MCP-side mutation audit sanitizer and by
  central content/patch omission in the audit layer. It was verified to fail only
  when both are disabled.

---

## 5. Final Quality Gates

Executed from the final tree via `pnpm run verify:rc04` (`scripts/verify-rc04.sh`):

| Gate | Check                                                                        | Result       |
| :--- | :--------------------------------------------------------------------------- | :----------- |
| 1    | Git branch is `feat/rc-04-policy-approvals`                                  | PASS         |
| 2    | `pnpm install --frozen-lockfile`                                             | PASS         |
| 3    | `pnpm run check:format`                                                      | PASS         |
| 4    | `pnpm run lint`                                                              | PASS         |
| 5    | `pnpm exec tsc --build --clean` + `pnpm run typecheck` + `pnpm -r run build` | PASS         |
| 6    | `node --test tests/rc04-negative-controls.test.js`                           | PASS (38/38) |
| 7    | `pnpm run test`                                                              | PASS         |
| 8    | `pnpm run bench:rc04-policy`                                                 | PASS         |
| 9    | `git diff --check`                                                           | PASS         |
| 10   | `bash scripts/check-docs.sh`                                                 | PASS         |
| 11   | `bash scripts/check-secrets.sh`                                              | PASS         |
| 12   | `pnpm audit`                                                                 | PASS         |
| 13   | All 38 frozen negative-control IDs present                                   | PASS         |
| 14   | No `test.skip` / `test.todo` / `describe.skip` / `it.skip`                   | PASS         |
| 15   | Zero inline scanner suppressions                                             | PASS         |
| 16   | All required RC-04 artifacts exist                                           | PASS         |
| 17   | Version and health consistency (`0.4.0-rc04` / `RC-04`)                      | PASS         |

### 5.1 Test totals

| Metric  | Value |
| :------ | :---- |
| Tests   | 821   |
| Suites  | 82    |
| Passed  | 821   |
| Failed  | 0     |
| Skipped | 0     |
| Todo    | 0     |

The dedicated acceptance suite contributes 38 tests across 4 suites.

### 5.2 Benchmark

`pnpm run bench:rc04-policy` completed with no asserted timing threshold
(timings are informational only). Policy evaluation is purely in-memory: no
filesystem, network, or process access.

| Reference hash               | Value                                                              |
| :--------------------------- | :----------------------------------------------------------------- |
| maximal policy `policyHash`  | `d06a648eeef1d525d6ec3ec30a893d680c9f11c0d11ab1d89a805cfd76007c65` |
| built-in policy `policyHash` | `730b4e1f9d10bf8bb0a3d51656de64554ff9ef999f83b14f35ceea25c14f26f5` |

### 5.3 Dependency audit

`pnpm audit` — **no known vulnerabilities found**.

### 5.4 Secret scan

`bash scripts/check-secrets.sh` — **PASSED**: Gitleaks reported no leaks,
zero forbidden credential files, and zero private IP addresses. The repository
contains zero inline scanner suppression markers.

### 5.5 Documentation check

`bash scripts/check-docs.sh` — **PASSED**: all required documents present and all
internal markdown links resolve.

---

## 6. Limitations & Deferred Scope

RC-04 deliberately does **not** provide any of the following. None of these are
implied by this report, and none should be read as delivered functionality:

- Remote approval administration.
- HTTP or SSE approval administration endpoints.
- A persistent approval store.
- Token recovery after a restart.
- Policy hot reload.
- Git mutation. (`delete_file`, `move_file`, `create_file`, `write_file`, and
  `apply_patch` are the frozen RC-03 mutation surface; nothing else executes.)
- Production or cloud-root authority.
- A persistent, externally anchored audit ledger. The hash chain is in-memory
  only and is not anchored outside the process.
- RC-05 secure remote gateway functionality, including HTTPS/SSE transport,
  mutual TLS, or device enrollment.

Additional known boundaries:

- Approval state, the audit chain, and all policy state are volatile and are
  destroyed on process exit.
- The admin channel is available only on POSIX platforms; Windows named pipes
  are not implemented in this stage.
- Cancellation of a mutation already handed to a subsystem is not supported;
  consumption happens before execution by design, so a failed execution leaves
  the approval consumed.

---

## 7. Reporting Boundary

This report records what the repository itself can demonstrate: the frozen
contract, the implementation, the executed controls, and the gate output. It
does not assert independent review, PR approval, or merge. Those are external
GitHub state and must be verified there against the exact head commit.

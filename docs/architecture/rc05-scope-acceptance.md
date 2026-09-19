# RC-05 Scope & Acceptance — Secure Remote Gateway

| Field         | Value                                                                                                                                                       |
| :------------ | :---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Stage**     | RC-05                                                                                                                                                       |
| **Title**     | Secure Remote Gateway                                                                                                                                       |
| **Status**    | **Task-0 Scope Candidate — Pending Independent Review**                                                                                                     |
| **Base main** | `f70a5efea4018079de1ac1ee423b7e51574b1262`                                                                                                                  |
| **Branch**    | `feat/rc-05-secure-remote-gateway`                                                                                                                          |
| **Purpose**   | Freeze remote transport, authentication, device identity, session, rate-limit, audit, failure, and trust-boundary semantics **before** any code is written. |

> **Implementation MUST NOT begin until this scope is independently approved.**
> This document is a candidate normative contract, not an implementation plan
> that has been accepted. Every rule below is intended to be directly
> code-testable; none of it is implemented by Task 0.

---

## 1. Authority and Status

This document is the **candidate normative contract** for RC-05. On independent
approval it supersedes ambiguous or outdated RC-00 wording for this stage. Until
that approval, the existing documents remain as they are: **Task 0 modifies no
other file**.

Where a historical document states something this contract contradicts, the
specific rule is restated in §37 (Historical Documentation Reconciliation) with
the new normative rule named explicitly.

---

## 2. Repository Baseline (as inspected for Task 0)

Every statement below was verified against the tree at
`f70a5efea4018079de1ac1ee423b7e51574b1262`.

### 2.1 Server and transport

- `ArcMcpServer` exposes **stdio only**. `ArcServerConfig.transport` is typed as
  the single literal `'stdio'` (`apps/mcp-server/src/index.ts`).
- The only transport ever constructed is `new StdioServerTransport()`.
- **No remote MCP network listener exists anywhere in the repository.**
- `apps/mcp-server` does **not** depend on `@cesspace-arc/auth`.
- `pipefail`-relevant fact: the SDK ships `StreamableHTTPServerTransport`,
  `SSEServerTransport`, and `StdioServerTransport`.

### 2.2 Authentication package

- `packages/auth/src/index.ts` is **16 lines**: two interfaces
  (`AuthTokenClaims`, `IAuthEngine`) with a comment reading
  "Implementation target: RC-05". There is no implementation, no runtime
  dependency, and nothing imports it.

### 2.3 MCP SDK transport inventory (1.30.0)

This is the single most important reconciliation input, because "SSE" is used
loosely in historical documents.

| Transport                       | Status in SDK 1.30.0                                                       |
| :------------------------------ | :------------------------------------------------------------------------- |
| `StdioServerTransport`          | Current.                                                                   |
| `StreamableHTTPServerTransport` | Current. Implements the MCP Streamable HTTP transport spec.                |
| `SSEServerTransport`            | **Explicitly `@deprecated`**: "Use StreamableHTTPServerTransport instead." |

`StreamableHTTPServerTransport` is a Node wrapper over
`WebStandardStreamableHTTPServerTransport` and **supports both SSE streaming and
direct JSON responses** — SSE is a _response framing_ of the current transport,
not a separate legacy endpoint.

Its option surface (authoritative for §5):

| Option                                                           | Meaning                                                                                  | Task-0 relevance                                                             |
| :--------------------------------------------------------------- | :--------------------------------------------------------------------------------------- | :--------------------------------------------------------------------------- |
| `sessionIdGenerator`                                             | Server-generated MCP session ID. Omitted ⇒ **stateless mode**.                           | Stateful mode is mandatory; stateless is forbidden.                          |
| `onsessioninitialized`                                           | Callback on new session.                                                                 | Session registry hook.                                                       |
| `onsessionclosed`                                                | Callback when the client `DELETE`s the session.                                          | Session teardown hook.                                                       |
| `enableJsonResponse`                                             | Return plain JSON instead of opening an SSE stream.                                      | Permitted; framing only, never an auth decision.                             |
| `eventStore`                                                     | Resumability support.                                                                    | **Forbidden in baseline** — resumption is a cross-connection replay surface. |
| `allowedHosts`, `allowedOrigins`, `enableDnsRebindingProtection` | DNS-rebinding protection — **all three `@deprecated`** in favour of external middleware. | Handled by the gateway's own validation (§24), not by these options.         |
| `retryInterval`, `keepAliveMs`                                   | SSE framing cadence.                                                                     | Bounded, gateway-configured.                                                 |

- The SDK also ships `server/auth/**` (`AuthInfo`, OAuth provider scaffolding,
  Express router) and `server/middleware/hostHeaderValidation.js`.
- The SDK's `AuthInfo` models an **OAuth-style bearer access token**
  (`token`, `clientId`, `scopes`, `expiresAt`, `resource`). RC-05 baseline does
  **not** adopt the SDK's OAuth provider; §12 explains why, and §11 defines the
  session model that is used instead.

### 2.4 Protocol error codes already reserved

The `ArcErrorCode` union already contains `UNAUTHENTICATED`,
`INVALID_SESSION_TOKEN`, `DEVICE_NOT_ENROLLED`, and `RATE_LIMIT_EXCEEDED` with
**no factory and no usage anywhere**. `PAYLOAD_TOO_LARGE` has a factory and is
used. §27 defines exactly which of these RC-05 activates.

### 2.5 Facts that must not be weakened

- **RC-04 semantics are frozen.** Layer 1 permanence, Layer 2 declarative policy,
  `DENY > REQUIRE_APPROVAL > ALLOW`, the mutation approval floor, approval
  binding, and the 300-second monotonic TTL are unchanged by RC-05.
- **RC-04 local authenticated admin IPC remains the trusted approval-management
  channel.** RC-04 has no remote approval administration.
- Current test baseline: **822 tests / 82 suites**, 0 failed, 0 skipped, 0 todo.
- Current public stage version: **`0.4.0-rc04`**.
- **RC-06 persistent/anchored audit storage is future work.** RC-05 keeps the
  in-memory hash chain.
- Health surface today: `status`, `version`, `stage`, `policyEngineActive`,
  `auditActive`, `authorizedWorkspacesCount`.

---

## 3. Primary Architectural Invariant

```text
UNTRUSTED REMOTE CLIENT
  → transport admission
  → authenticated device/client identity
  → authenticated session
  → existing schema / workspace / policy / approval pipeline
  → audit
  → subsystem execution
```

**Remote transport must NEVER create an alternate authorization path.**

- Authentication answers **WHO is calling.**
- RC-04 policy answers **WHAT that authenticated actor may do.**
- **A successful remote authentication MUST NOT imply `ALLOW`.**
- `DENY > REQUIRE_APPROVAL > ALLOW` is unchanged.
- There is exactly **one** tool dispatcher. The gateway never invokes a
  subsystem directly and never has a fast path.
- No request capable of reaching policy or a subsystem may bypass authenticated
  identity derivation.

---

## 4. Local stdio Compatibility

| Rule | Normative statement                                                                                                                            |
| :--- | :--------------------------------------------------------------------------------------------------------------------------------------------- |
| L-1  | Local stdio support **remains available** and is not deprecated by RC-05.                                                                      |
| L-2  | Introducing remote mode **must not silently change stdio behaviour**.                                                                          |
| L-3  | Remote authentication requirements **must not** leak into stdio semantics; stdio gains no remote token requirement.                            |
| L-4  | **stdio and remote listeners are MUTUALLY EXCLUSIVE within one process.** A process runs either stdio mode or remote-gateway mode, never both. |
| L-5  | Actor construction is **explicit and distinguishable** by transport (§14).                                                                     |
| L-6  | **No caller may self-assert trusted actor fields** over any transport (§14).                                                                   |

**Rationale for L-4 (explicit decision):** running both would place an
authenticated network listener inside the same process that inherits the
operator's ambient privileges, giving a remote compromise the local stdio
attack surface (and vice versa) for no required capability. Mutually exclusive
listeners keep the remote process's authority exactly equal to what remote
authentication established, and remove a whole class of "which transport
authorized this?" ambiguity from the audit chain. `transport` therefore becomes
a closed union of `'stdio' | 'remote'`, and selecting `'remote'` **removes** the
stdio listener rather than adding to it.

---

## 5. Remote MCP Transport Contract

**Decision: RC-05 supports exactly one remote transport — MCP Streamable HTTP
over TLS 1.3, using the SDK's `StreamableHTTPServerTransport` in stateful mode.
Legacy SSE is NOT supported. Plain HTTP is NEVER allowed. WebSockets are NOT
supported.**

| Aspect                          | Frozen rule                                                                                                                                                                                                                                                           |
| :------------------------------ | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Transport**                   | `StreamableHTTPServerTransport` (SDK 1.30.0). No other remote transport.                                                                                                                                                                                              |
| **Legacy SSE**                  | **Not served.** `SSEServerTransport` is deprecated upstream and carries no RC-05 endpoint. A request to any legacy SSE path is `404`.                                                                                                                                 |
| **Why not "both"**              | Maintaining a deprecated transport would add an endpoint, a session model, and a deprecation-migration path for zero required capability. Historical "SSE" usage in RC-00 documents refers to server-sent _response framing_, which Streamable HTTP already provides. |
| **Streaming framing**           | SSE framing or `enableJsonResponse` JSON framing are both permitted. Framing is a response-shape choice and MUST NOT influence authentication, session, or authorization decisions.                                                                                   |
| **Plain HTTP**                  | **Never.** There is no plaintext listener, no plaintext fallback, and no configuration that enables one.                                                                                                                                                              |
| **WebSocket**                   | **Not supported.** Not justified by any RC-05 invariant; would add a second protocol surface and a second session-identification scheme.                                                                                                                              |
| **Stateful vs stateless**       | **Stateful is mandatory.** `sessionIdGenerator` MUST be supplied with a cryptographically secure generator. Stateless mode is **forbidden** — a sessionless remote request has no durable identity to bind actor context, approvals, or audit to.                     |
| **`eventStore` / resumability** | **Forbidden in baseline.** Message resumption across connections is a replay/reconnect surface that baseline RC-05 does not need.                                                                                                                                     |
| **Bind semantics**              | Explicit host and port. **Default bind is loopback (`127.0.0.1`)**. A wildcard/`0.0.0.0`/`::` bind requires an explicit opt-in flag; selecting it without that flag is a startup failure (§17).                                                                       |
| **IPv4/IPv6**                   | The configured host is bound literally. `::` and `0.0.0.0` are treated as wildcard and gated identically. Dual-stack implicit binding is not used.                                                                                                                    |
| **Endpoint path**               | Exactly one configured path (default `/mcp`). Any other path is `404` and MUST NOT reach policy or a subsystem.                                                                                                                                                       |
| **HTTP methods**                | `POST` = client→server messages. `GET` = server→client SSE stream. `DELETE` = explicit session termination. Any other method is `405` with no processing.                                                                                                             |
| **MCP session identity**        | The `Mcp-Session-Id` header, **server-generated**, 256-bit random, opaque. The client never chooses it.                                                                                                                                                               |
| **Invalid/unknown session ID**  | Rejected before any policy evaluation, with a **sanitized** response that does not confirm whether the ID ever existed (§27).                                                                                                                                         |
| **Teardown**                    | `DELETE` closes the MCP session and revokes the gateway session bound to it. Socket close without `DELETE` closes the connection; the gateway session remains until idle/absolute expiry, and is re-usable only from the same authenticated TLS identity.             |

---

## 6. TLS Contract

| Rule | Normative statement                                                                                                                                                                                                                                                                                                                                                                                    |
| :--- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T-1  | **Minimum TLS version: 1.3. Maximum: 1.3.** TLS 1.2 and below are refused at handshake.                                                                                                                                                                                                                                                                                                                |
| T-2  | **Plaintext HTTP is never accepted.** No listener, no upgrade, no fallback.                                                                                                                                                                                                                                                                                                                            |
| T-3  | **TLS termination MUST occur inside the ARC process.** Delegated/reverse-proxy termination is **OUT OF SCOPE** for baseline RC-05 (§34).                                                                                                                                                                                                                                                               |
| T-4  | If the TLS listener cannot start (missing/unreadable key or cert, key/cert mismatch, unsupported version), the **server fails to start**. It does not start without the listener and it does not fall back to plaintext.                                                                                                                                                                               |
| T-5  | Server certificate identity is established by the operator-configured certificate. **Hostname/SAN validation is performed by the client**; the server MUST NOT accept a client that has not validated it — i.e. the server presents a certificate whose SAN matches the configured public hostname. A configuration whose certificate does not match its configured hostname is a **startup failure**. |
| T-6  | Client certificate identity is the **SPKI digest** of the device certificate (§7).                                                                                                                                                                                                                                                                                                                     |
| T-7  | **Certificate expiry:** an expired client certificate is rejected during handshake. An expired server certificate is a startup failure; there is no "expired but running" state.                                                                                                                                                                                                                       |
| T-8  | **Malformed certificate / unknown CA:** rejected during handshake, before any MCP byte is parsed.                                                                                                                                                                                                                                                                                                      |
| T-9  | **Revocation (CRL/OCSP):** baseline RC-05 does **not** perform network revocation checking. Revocation is enforced by ARC's own device trust store (§10), which is authoritative and local. This is an explicit choice: a network revocation fetch would add a remote availability dependency and an outbound connection to the trust path.                                                            |
| T-10 | **Rotation:** server key/cert rotation is a restart-time operation (reload on restart). Device certificate rotation is handled by re-enrollment plus a pin overlap window (§7).                                                                                                                                                                                                                        |

### 6.1 Why in-process TLS

Terminating TLS in-process keeps the authenticated identity cryptographically
derived from the same bytes the gateway evaluates. Accepting an upstream proxy's
assertion instead would move the entire identity root outside ARC. A proxy
header **MUST NOT** establish actor identity. If a deployment requires an
upstream terminator, that deployment is out of scope until a separately reviewed
design can cryptographically bind it (for example mTLS from ARC's perspective
plus a per-request signed identity assertion) — which baseline RC-05 does not
define.

---

## 7. mTLS, Pinning, and Their Exact Relationship

**Decision: mTLS is MANDATORY for remote mode, and pinning is ADDITIONAL to
normal chain validation — never a replacement for it.**

| Rule | Normative statement                                                                                                                                                                                                                                                                                                                                |
| :--- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P-1  | **mTLS is mandatory.** A remote connection without a client certificate is rejected during handshake.                                                                                                                                                                                                                                              |
| P-2  | **Server trust** is established by the client validating the server certificate against its configured trust anchor and the configured hostname.                                                                                                                                                                                                   |
| P-3  | **Client/device trust** requires **both**: (a) the certificate chains to a configured CA/trust root, **and** (b) its SPKI digest is pinned to an enrolled device. Failing either fails authentication.                                                                                                                                             |
| P-4  | **Pinned object: the certificate's SubjectPublicKeyInfo (SPKI) digest** — not the whole certificate. Pinning the SPKI survives certificate re-issuance with the same key and avoids pinning CA-specific encoding.                                                                                                                                  |
| P-5  | **Digest algorithm: SHA-256**, rendered as **64 lowercase hexadecimal characters**. `sha256(DER(SubjectPublicKeyInfo))`.                                                                                                                                                                                                                           |
| P-6  | **Mismatch behaviour:** authentication fails with a sanitized `UNAUTHENTICATED` (§27). The response MUST NOT reveal that a pin nearly matched, which pin failed, or whether the presented certificate chains to a known CA.                                                                                                                        |
| P-7  | **Rotation:** a device record may hold **more than one active pin** so a key/cert rotation can overlap. A pin is only ever added through the authenticated local operator path (§9). The overlap window is operator-controlled and MUST be explicitly closed by removing the old pin; an unused pin never expires silently into a "no pins" state. |
| P-8  | **Malformed pin configuration** (wrong length, non-hex, duplicates that collapse) is a **startup failure** (§17). Empty pin sets for an enrolled device are invalid.                                                                                                                                                                               |

---

## 8. Device Identity Model

| Field / rule                       | Normative statement                                                                                                                                                                                                                         |
| :--------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`deviceId` format**              | **32 lowercase hexadecimal characters** (16 random bytes). Fixed length, no separators, no caller-supplied form.                                                                                                                            |
| **Generation authority**           | **ARC generates `deviceId`** at enrollment. A client never proposes, supplies, or influences it.                                                                                                                                            |
| **Cryptographic binding**          | A device record binds `deviceId` ↔ enrolled pin(s) (§7). Neither half is meaningful without the other: knowing a `deviceId` grants nothing, and a valid client certificate that is not enrolled is rejected.                                |
| **`clientId` vs `deviceId`**       | **Distinct.** `clientId` is the logical client identity (which agent/tool integration); `deviceId` is the physical enrolled credential holder.                                                                                              |
| **Multiplicity**                   | One `clientId` **may** have multiple `deviceId`s. One `deviceId` belongs to **exactly one** `clientId`.                                                                                                                                     |
| **Duplicate enrollment**           | Enrolling a certificate whose pin already exists **reuses the existing `deviceId`** and does not create a second record. If it is bound to a different `clientId`, enrollment is **rejected**.                                              |
| **Disabled/revoked**               | A revoked device fails authentication on the **next** request on every connection, and every live session for that device is revoked immediately (§11). Revocation is terminal for that `deviceId`; re-enrollment creates a new `deviceId`. |
| **Persisted metadata**             | `deviceId`, `clientId`, `clientType`, pin set, enrollment timestamp, operator-supplied **display label** (non-security), revocation state.                                                                                                  |
| **Never trusted from caller JSON** | `deviceId`, `clientId`, `clientType`, `sessionId`, pin values, revocation state, enrollment time. These are **always** derived server-side from the authenticated connection (§14).                                                         |
| **Impersonation bar**              | A remote client **cannot** choose an arbitrary `deviceId`, present another device's `deviceId`, or assert another `clientId`, and thereby act as that device. Any request carrying such a field is refused at schema admission (§14, §27).  |

---

## 9. Enrollment Bootstrap

**Decision: enrollment is operator-mediated over the existing local
authenticated admin channel. There is NO remote self-enrollment.**

| Rule | Normative statement                                                                                                                                                                                                                                                                                                               |
| :--- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| E-1  | **Who may enroll:** only the authenticated local operator, through the RC-04 admin IPC channel (Ed25519 challenge–response over a Unix socket).                                                                                                                                                                                   |
| E-2  | **Trusted authorising channel:** the local admin IPC. The remote gateway is **never** an enrollment authority.                                                                                                                                                                                                                    |
| E-3  | **Local-operator initiated:** yes. The operator creates a pending enrollment; the device then completes it.                                                                                                                                                                                                                       |
| E-4  | **Proof of possession:** the device MUST prove possession of the private key matching the certificate it presents, by completing the remote handshake with that certificate and confirming the one-time enrollment secret over that authenticated channel. A certificate presented without its private key can never be enrolled. |
| E-5  | **Challenge lifetime:** bounded and short. An unconsumed enrollment is invalid after its TTL and is purged.                                                                                                                                                                                                                       |
| E-6  | **One-time / replay:** an enrollment secret is single-use. A replay attempt is rejected and **MUST NOT** mint a second device or mutate the existing one.                                                                                                                                                                         |
| E-7  | **Pending quotas:** bounded number of concurrent pending enrollments, globally and per operator. Exceeding the quota fails closed and leaves existing devices unchanged.                                                                                                                                                          |
| E-8  | **Cancellation / rejection:** the operator may cancel a pending enrollment; the secret becomes unusable immediately.                                                                                                                                                                                                              |
| E-9  | **Duplicate enrollment:** per §8 — same pin ⇒ same `deviceId`, no duplicate record; pin already bound to another `clientId` ⇒ rejected.                                                                                                                                                                                           |
| E-10 | **Credential issuance/import:** ARC **does not** generate or export device private keys. The operator supplies a certificate/public key; the private key never enters ARC.                                                                                                                                                        |
| E-11 | **Failure/restart:** pending enrollments are volatile and do not survive restart (§16). **Completed enrollments survive restart** (that is the point of persistence).                                                                                                                                                             |

**Unauthenticated remote self-enrollment is not merely discouraged — no such
endpoint exists.** Any remote request that attempts to create, modify, or
complete an enrollment outside the E-4 flow is refused.

---

## 10. Enterprise IdP and Attestation Reconciliation

Historical RC-04 out-of-scope text named OIDC, OAuth2, SAML, enterprise IdP
integration, and device attestation as RC-05 material. The README roadmap
promises only HTTPS/SSE, mTLS, and device enrollment. **Task 0 resolves this in
favour of the narrower baseline.**

| Capability                           | Decision                  | Architectural reason                                                                                                                                                                                                          |
| :----------------------------------- | :------------------------ | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **OIDC**                             | **DEFERRED BEYOND RC-05** | Adds a network federation trust root and a second identity issuance path. The frozen RC-05 threat model is satisfied by operator-mediated enrollment + mTLS; nothing in the baseline requires an external identity authority. |
| **OAuth2**                           | **DEFERRED BEYOND RC-05** | Same as OIDC, plus an authorization-server dependency. RC-05 sessions are gateway-issued, not federated.                                                                                                                      |
| **SAML**                             | **DEFERRED BEYOND RC-05** | XML signature/canonicalisation attack surface with no required capability.                                                                                                                                                    |
| **Enterprise IdP federation**        | **DEFERRED BEYOND RC-05** | Federation changes _who_ may establish device trust. RC-05 deliberately keeps that authority local and operator-mediated.                                                                                                     |
| **Hardware/device attestation**      | **DEFERRED BEYOND RC-05** | Requires platform-specific roots of trust and a hardware verification path. Baseline device trust is the enrolled pin (§7), which is cryptographically explicit and testable today.                                           |
| **`OPTIONAL RC-05 EXTENSION` items** | _None_                    | No capability in this list is optional-in-baseline; each is either baseline-defined (§5–§15) or deferred.                                                                                                                     |

**Explicit consequence:** the SDK's OAuth provider scaffolding
(`server/auth/**`) is **not** adopted in baseline RC-05. Its `AuthInfo` type
models a bearer-token identity; baseline RC-05 uses the session model in §11
bound to the mTLS identity in §7.

---

## 11. Session Token Model

**Decision: opaque, gateway-issued, single-class session token, cryptographically
bound to the device's TLS identity.**

| Property                       | Frozen value                                                                                                                                                                            |
| :----------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Form**                       | **Opaque** (no client-readable claims). Not a JWT; no structured payload.                                                                                                               |
| **Generation**                 | CSPRNG (`crypto.randomBytes`), **256 bits**.                                                                                                                                            |
| **Encoding**                   | **64 lowercase hexadecimal characters**.                                                                                                                                                |
| **Maximum input byte length**  | **128 bytes** for the presented token value (bound checked before decoding).                                                                                                            |
| **Server-side representation** | **SHA-256 digest only.** The raw token is never stored, never re-derivable, and never compared in raw form.                                                                             |
| **Raw-token retention**        | Returned exactly once at issuance. Never logged, never audited, never persisted, never echoed in an error.                                                                              |
| **Verification**               | `timingSafeEqual` over the 32-byte digests. Constant-time.                                                                                                                              |
| **Binding**                    | Bound to `(deviceId, SPKI digest, clientId)`. **A token presented from a different device's TLS identity is rejected.** A stolen token is therefore **not** portable to another device. |
| **TTL (absolute)**             | **3600 s**, enforced on a **monotonic** clock (`process.hrtime.bigint()`); wall clock is display-only and cannot extend it.                                                             |
| **Idle timeout**               | **300 s** monotonic since last authenticated request.                                                                                                                                   |
| **Issue time**                 | Recorded mono + wall (wall for display/audit only).                                                                                                                                     |
| **Expiration**                 | On absolute or idle expiry the session is revoked; the next request is rejected with `INVALID_SESSION_TOKEN`.                                                                           |
| **Rotation**                   | **No per-request rotation.** Rotation occurs only by re-authentication. Per-request rotation was rejected because it introduces a concurrent-request race with no baseline requirement. |
| **Revocation**                 | Explicit (operator, `DELETE`, device revocation, restart). Revocation is immediate and irreversible for that session.                                                                   |
| **Replay after revocation**    | Rejected. Idle/absolute expiry is checked before any identity is derived, so a revoked session's token never reaches policy.                                                            |
| **Concurrent use**             | A token may be used concurrently **within** the per-session concurrency cap (§24). Concurrent use from a different TLS identity is rejected by the binding.                             |
| **Maximum active sessions**    | Per device: **8**. Per client: **64**. Global: **1024**. Exceeding any bound fails the new session closed; existing sessions are unaffected.                                            |
| **Restart behaviour**          | **All sessions are volatile.** A restart revokes every session token.                                                                                                                   |
| **Leakage controls**           | Never in logs, audit records, error bodies, health output, or metrics. Redaction is central, not caller-dependent.                                                                      |

**Domain separation from RC-04:** session tokens travel in the `Authorization`
header over the remote transport and are **a different class** from RC-04
approval tokens (§30). Neither is accepted in the other's position.

---

## 12. Authentication Sequence

Exact order for a remote connection:

```text
1. TCP admission                     (per connection)
2. TLS 1.3 handshake                 (per connection)
3. Client certificate chain check     (per connection)
4. Enrolled device + pin lookup       (per connection)
5. Session token validation OR issuance (per MCP session; token re-validated per request)
6. Session binding to device/SPKI/client (per session)
7. MCP request admission             (per request)
8. Existing schema → workspace → Layer 1 → Layer 2 → approval pipeline
```

| Check                                                        | Frequency                            |
| :----------------------------------------------------------- | :----------------------------------- |
| TCP/TLS admission                                            | Once per connection                  |
| Certificate chain + expiry                                   | Once per connection                  |
| Device lookup + pin match                                    | Once per connection                  |
| Session token validity (digest, expiry, revocation, binding) | **Every request**                    |
| Actor context derivation                                     | **Every request**                    |
| Policy / approval / subsystem                                | Every request (unchanged from RC-04) |

Steps 1–4 happen before any MCP byte is parsed. Step 5 is re-evaluated on every
request so a revoked session or revoked device cannot continue on a live
connection. **No request that can reach policy or a subsystem may skip steps
1–6.**

---

## 13. Actor Context Binding into RC-04

RC-04 binds approvals to `(clientId, clientType, sessionId, deviceId)` and folds
that actor into `executionPayloadHash`. RC-05 must therefore define each field's
origin precisely, or approval binding silently weakens.

| RC-04 actor field | RC-05 source                                                                                                                                                           |
| :---------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `clientId`        | From the **enrolled device record**, resolved from the authenticated TLS identity. Caller-supplied values are ignored and any attempt to supply one is a schema error. |
| `clientType`      | From the **enrolled device record** (operator-set at enrollment). Never caller-supplied.                                                                               |
| `deviceId`        | From the **enrolled device record** (§8), resolved from the presented certificate's pin.                                                                               |
| `sessionId`       | **Gateway-generated** at session issuance, 256-bit random, opaque. Lifetime = the session's lifetime (§11). Never caller-supplied.                                     |

- These four values are computed **server-side, after** steps 1–5 of §12, and
  are the **only** values passed into `SecurityKernel`,
  `DeclarativePolicyEngine`, and the `executionPayloadHash` computation.
- **Remote request parameters MUST NOT override these trusted fields.** A request
  carrying `clientId`, `clientType`, `deviceId`, or `sessionId` is refused at
  schema admission (§27) and nothing is executed.
- `sessionId` participates in approval binding exactly as it does for stdio
  today; because RC-05 sessions expire, an approval requested under a session
  that has since ended cannot be redeemed from a different session (§30).

---

## 14. Authentication vs Authorization Separation

State plainly, in the contract:

- **Valid mTLS ≠ authorization.**
- **Valid device enrollment ≠ authorization.**
- **Valid session token ≠ authorization.**
- **Valid session ≠ workspace access.**
- **Valid session ≠ mutation approval.**

Workspace authorization remains **trusted server configuration**
(`authorizedRoots`). Policy remains the **authorization authority**. The RC-04
mutation approval floor is **unchanged**. The strongest statement available to a
remote actor is "this is an authenticated device"; everything beyond that is
decided by the same code path that decides it for stdio.

---

## 15. Remote Approval and Device Administration Boundary

| Rule | Normative statement                                                                                                                                                                                                                                         |
| :--- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A-1  | RC-04 approval administration is **local authenticated IPC only**, and RC-05 does **not** change that.                                                                                                                                                      |
| A-2  | A remote MCP client gains **no** `approve`, `reject`, approval-inspect, approval-list, policy-administration, or device-administration capability **merely because remote transport exists**.                                                               |
| A-3  | **No MCP administrative tools** are added. The MCP tool surface is unchanged by RC-05.                                                                                                                                                                      |
| A-4  | Device administration — list enrolled devices, inspect device metadata, revoke/disable a device, rename non-security display metadata, list/revoke sessions — belongs to the **existing authenticated local admin IPC and CLI**, extended with new methods. |
| A-5  | These administrative actions are **never** exposed to ordinary remote actor sessions.                                                                                                                                                                       |
| A-6  | Creating a remote operator control plane is **out of scope** for RC-05 baseline and would require its own separately justified, strongly authenticated design plus its own scope review.                                                                    |

---

## 16. Persistence Model

| State class                       | Volatile / Persistent | Storage authority                          | Restart behaviour                                                                   | Corruption / failure behaviour                                                                          |
| :-------------------------------- | :-------------------- | :----------------------------------------- | :---------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------ |
| **Enrolled device trust**         | **Persistent**        | ARC-owned trust store, operator-managed    | Survives restart                                                                    | Unreadable/invalid store ⇒ **startup failure**, no listener. Never silently starts with an empty store. |
| **Session tokens**                | **Volatile**          | In-memory                                  | **All revoked on restart**                                                          | Corrupt entry ⇒ that session fails closed.                                                              |
| **Active connections**            | **Volatile**          | In-memory                                  | Closed on restart                                                                   | n/a                                                                                                     |
| **Rate-limit state**              | **Volatile**          | In-memory                                  | Reset on restart (a restart is an operator action, not an attacker-reachable reset) | Corrupt entry ⇒ treated as over-limit for that key.                                                     |
| **Pending enrollment challenges** | **Volatile**          | In-memory                                  | **Purged on restart**; the operator re-initiates                                    | Corrupt entry ⇒ challenge unusable.                                                                     |
| **Audit chain**                   | **Volatile (RC-05)**  | In-memory hash chain, unchanged from RC-04 | Lost on restart                                                                     | Unchanged from RC-04. **RC-06 owns persistence/anchoring.**                                             |

**Trust-store format (architectural level):** a single ARC-owned file containing
only public material — `deviceId`, `clientId`, `clientType`, SPKI pin set,
timestamps, display label, revocation state. **No private keys, ever.** The file
is written atomically (temp + rename) and is validated in full at startup; any
validation failure is a startup failure (§17).

**Explicit non-regression:** RC-04 approvals remain **volatile**. RC-05 must not
make approval state persistent as a side effect of persisting device trust.

---

## 17. Private Key and Certificate Handling

| Rule | Normative statement                                                                                                                                                                                                                                                                                                             |
| :--- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| K-1  | **Zero real keys/certificates in the repository.** Public examples use generated or clearly-sanitized placeholders.                                                                                                                                                                                                             |
| K-2  | **Zero secret defaults** and **zero credentials embedded in source**.                                                                                                                                                                                                                                                           |
| K-3  | **No secret material in logs, audit records, or errors.**                                                                                                                                                                                                                                                                       |
| K-4  | **No private key passed via an ordinary command-line argument.**                                                                                                                                                                                                                                                                |
| K-5  | **No private key intentionally echoed** to stdout/stderr, ever.                                                                                                                                                                                                                                                                 |
| K-6  | Server private key runtime loading: from a **file path with strict permission validation** (must not be group/world readable, must not be a symlink, must be a regular file owned by the process uid) **or** from an **inherited file descriptor**. Both are approved; the FD form is preferred where the launcher supports it. |
| K-7  | **Environment variables are not approved for long-lived private key _material_.** They are readable by same-uid processes via `/proc/<pid>/environ`, are commonly dumped by crash reporters, and are easy to leak into logs. Environment may carry only non-secret selectors (e.g. a path or an FD number).                     |
| K-8  | Client/device private keys **never enter ARC** (§9 E-10).                                                                                                                                                                                                                                                                       |
| K-9  | Session-token verifier material is derived, not configured: the verifier is a SHA-256 digest computed from the presented token (§11), so there is **no server-side signing or verifier secret to store**.                                                                                                                       |
| K-10 | CA/enrollment signing material: RC-05 baseline needs **no ARC-operated CA** (§9). If a future stage introduces one, it requires its own scope review.                                                                                                                                                                           |

---

## 18. Startup Configuration Validation

Every condition below causes an **explicit startup failure**. There is **no
silent insecure fallback** in any row, and no row degrades to "remote listener
disabled but server running" unless stated.

| Condition                                                | Result              |
| :------------------------------------------------------- | :------------------ |
| `transport: 'remote'` without TLS configuration          | **Startup failure** |
| Server certificate without a private key                 | **Startup failure** |
| Private key without a certificate                        | **Startup failure** |
| Key/cert mismatch                                        | **Startup failure** |
| mTLS enabled without any configured trust root/pins      | **Startup failure** |
| Malformed pin (length/charset/duplicate)                 | **Startup failure** |
| Empty trust store for an enrolled device                 | **Startup failure** |
| Unreadable / invalid device trust store                  | **Startup failure** |
| Unsupported TLS version configured                       | **Startup failure** |
| Invalid listener port or address                         | **Startup failure** |
| Remote mode with authentication disabled                 | **Startup failure** |
| Certificate whose SAN does not match configured hostname | **Startup failure** |
| Wildcard bind without explicit opt-in flag               | **Startup failure** |
| Two enrolled devices sharing one pin                     | **Startup failure** |

**Health reporting:** because these are startup failures, there is no "running
but unauthenticated remote" state to report. A server that cannot satisfy the
remote contract does not start. (Contrast: the existing **policy** failure mode,
which starts and reports `UNHEALTHY` — that remains unchanged for RC-04 reasons.)

---

## 19. Health / Status Model

Additional truthful fields (§24 covers what must **not** appear):

| Field                  | Type    | Meaning                                                          |
| :--------------------- | :------ | :--------------------------------------------------------------- |
| `transportMode`        | string  | `'stdio'` or `'remote'` — the single active mode (§4).           |
| `remoteGatewayActive`  | boolean | True iff the remote listener is bound and serving.               |
| `authenticationActive` | boolean | True iff mTLS + enrollment + session enforcement are all active. |
| `enrolledDevicesCount` | number  | Count of non-revoked enrolled devices.                           |
| `activeSessionsCount`  | number  | Current live sessions.                                           |

**Must not be exposed:** certificate material, private key paths, tokens, pins,
trust-store paths, host topology, listener address, or remote peer addresses.
Counts are safe; material is not.

If remote configuration is present but invalid, the process **does not start**
(§18) — so health never has to report a half-configured gateway.

---

## 20. Message Size and Request Bounds

| Bound                       | Frozen value                                                                                                                                                                                                      |
| :-------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Maximum message body**    | **4 MiB = 4,194,304 bytes.** (Resolves historical "4 MB" to binary mebibytes, measured on **raw request body bytes as received**.)                                                                                |
| **Measurement point**       | Raw bytes on the wire for the request body, **before** any parsing or decoding.                                                                                                                                   |
| **Compressed requests**     | **Not supported.** A request carrying `Content-Encoding` is rejected with `PAYLOAD_TOO_LARGE`-class refusal regardless of decoded size, so the limit cannot be bypassed by compression.                           |
| **Chunked transfer**        | Accepted, but the **cumulative** received body is measured and the limit is enforced **during** the read, not after. Exceeding it aborts the request and closes the connection.                                   |
| **Headers**                 | Total request header block ≤ **16 KiB**. Exceeding it closes the connection.                                                                                                                                      |
| **URL / query**             | Request target ≤ **2 KiB**. Exceeding it is `414`-class refusal with no processing.                                                                                                                               |
| **TLS handshake timeout**   | **5 s** — a handshake that has not completed is aborted.                                                                                                                                                          |
| **Body read timeout**       | **10 s** — a body that has not fully arrived is aborted (slowloris control).                                                                                                                                      |
| **Request (total) timeout** | **60 s** — a request that has not completed is aborted.                                                                                                                                                           |
| **Response size**           | Governed by existing RC-01/RC-02 output bounds; RC-05 adds no new response ceiling and never streams unbounded data to a remote peer.                                                                             |
| **Oversized request**       | A **sanitized error response** is returned where the connection state still allows it, then the connection is closed. Partial processing is forbidden: an oversized request MUST NOT reach policy or a subsystem. |

All values are absolute constants in code (not merely "configurable"), with
configurable **lower** limits permitted and configurable **higher** limits
forbidden.

---

## 21. Rate Limiting

**Two independent limiters with different keys, because a pre-authentication
limiter cannot trust an authenticated key.**

| Layer                   | Key                                              | Algorithm                   | Default                       | Hard maximum           |
| :---------------------- | :----------------------------------------------- | :-------------------------- | :---------------------------- | :--------------------- |
| **Pre-authentication**  | **Peer IP address** (never a client-supplied ID) | Fixed-memory sliding window | 60 requests / min, burst 20   | 600 / min, burst 100   |
| **Post-authentication** | **`deviceId`** (server-derived)                  | Fixed-memory sliding window | 600 requests / min, burst 100 | 6000 / min, burst 1000 |

- **Pre-auth limiter runs before expensive work** — before certificate chain
  validation, before trust-store lookup, before any policy evaluation. A
  connection flood is therefore bounded before it can consume cryptographic
  budget.
- **Never key a pre-auth limiter on an attacker-provided client ID.** The only
  pre-auth key is the peer address.
- **Concurrency limits:** max **4** in-flight requests per session; max **32**
  live connections per peer IP; max **512** live connections globally; max
  **64** concurrent pre-auth handshakes.
- **Enrollment and auth attempts:** enrollment secret attempts are limited to
  **5 per pending enrollment** before the challenge is invalidated; authentication
  failures are limited by the pre-auth limiter.
- **Memory bounds:** limiter state is a fixed-size structure per key with an
  **idle eviction** policy (entries idle beyond **10 minutes** are dropped).
  Total limiter memory is bounded by the connection caps above; there are no
  unbounded maps.
- **Restart behaviour:** limiter state is volatile and resets on restart (§16).
- **Response behaviour:** exceeding a limit returns a **sanitized
  `RATE_LIMIT_EXCEEDED`** error and does not reach policy. Repeated pre-auth
  violations close the connection.
- **Hard maxima:** every configurable limit has an absolute ceiling that
  configuration cannot exceed.

---

## 22. Network Attack Surface

Frozen controls, by attack:

| Attack                                     | Control                                                                                                                           |
| :----------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------- |
| Unauthenticated connection flood           | Pre-auth per-IP limiter (§21) + global/per-IP connection caps; rejections occur before TLS work where possible.                   |
| TLS handshake flood                        | 5 s handshake timeout + max 64 concurrent handshakes; excess connections are refused.                                             |
| Slowloris / partial body                   | 10 s body read timeout, 60 s request timeout, header/URL bounds (§20).                                                            |
| Oversized payload                          | 4 MiB enforced during read; connection aborted (§20).                                                                             |
| Malformed JSON-RPC                         | Rejected by the existing MCP/schema layer; no policy reached.                                                                     |
| Malformed MCP session ID                   | Rejected before identity derivation; sanitized response (§5, §27).                                                                |
| Header abuse                               | 16 KiB header bound; `Host`/`X-Forwarded-*` never establish identity (§6.1).                                                      |
| Request smuggling assumptions              | Single explicit HTTP parser path via the SDK transport; `Content-Length`/`Transfer-Encoding` ambiguity is rejected, not resolved. |
| Credential stuffing / token guessing       | 256-bit tokens; constant-time digest comparison; pre-auth rate limiting; anti-oracle responses.                                   |
| Session fixation                           | Session IDs and tokens are **server-generated only**; a client-supplied value is never adopted.                                   |
| Session hijacking                          | Token bound to `(deviceId, SPKI, clientId)`; a token is unusable from another TLS identity (§11).                                 |
| Token replay                               | Idle/absolute expiry + explicit revocation; replay after revocation rejected.                                                     |
| Cross-device token replay                  | Binding check fails; nothing reaches policy.                                                                                      |
| Certificate replay/cloning                 | Cloning requires the private key; a cloned certificate without the key fails the handshake.                                       |
| Expired certificate                        | Rejected at handshake (§6 T-7).                                                                                                   |
| Revoked device                             | Rejected at every request; live sessions revoked immediately (§11).                                                               |
| Enrollment replay                          | Single-use secrets (§9 E-6).                                                                                                      |
| Enrollment race                            | Enrollment completion is atomic; exactly one completion wins; losers are rejected with no state change.                           |
| Rate-limit bypass                          | Two limiters with independent keys; pre-auth key is not caller-controllable (§21).                                                |
| IPv4/IPv6 ambiguity                        | Literal bind, wildcard gated explicitly (§5).                                                                                     |
| Wildcard bind exposure                     | Explicit opt-in flag required, else startup failure (§18).                                                                        |
| Proxy/header spoofing                      | No proxy header establishes identity; in-process TLS only (§6.1).                                                                 |
| DNS rebinding / browser-origin             | Origin allowlist default-deny; `Host` validated against the configured hostname (§23).                                            |
| Abrupt disconnect during execution         | In-flight work completes or aborts per existing RC-04 semantics; audit records the disconnect.                                    |
| Reconnect after token/session invalidation | Reconnection re-runs §12 in full; no resumption path exists (`eventStore` forbidden, §5).                                         |

---

## 23. CORS / Origin / Browser Client Policy

**Decision: browser-origin remote MCP clients are NOT supported in baseline
RC-05. Default-deny.**

| Rule | Normative statement                                                                                                                     |
| :--- | :-------------------------------------------------------------------------------------------------------------------------------------- |
| C-1  | **No CORS `Access-Control-Allow-Origin` header is emitted.** No wildcard, no echo of the request origin.                                |
| C-2  | A request carrying an `Origin` header is **rejected** unless it matches the configured origin allowlist, which is **empty by default**. |
| C-3  | **Wildcard origin is never combined with credentials**, and in baseline there is no wildcard at all.                                    |
| C-4  | `Host` is validated against the configured hostname; a mismatch is rejected before MCP parsing.                                         |
| C-5  | `X-Forwarded-*` headers are **ignored for identity** and never influence actor derivation (§6.1).                                       |
| C-6  | If a future stage adds browser clients, it must define an exact origin allowlist and its credential model in a separate review.         |

---

## 24. Audit Event Catalog

RC-05 adds gateway lifecycle events to the **existing** append-only hash chain.
Names are frozen:

| Event                         | Emitted when                                            |
| :---------------------------- | :------------------------------------------------------ |
| `GATEWAY_STARTED`             | Remote listener bound and serving.                      |
| `GATEWAY_STOPPED`             | Remote listener shut down.                              |
| `DEVICE_ENROLLMENT_REQUESTED` | Operator creates a pending enrollment.                  |
| `DEVICE_ENROLLED`             | Enrollment completes successfully.                      |
| `DEVICE_ENROLLMENT_REJECTED`  | Enrollment fails, is cancelled, or is replayed.         |
| `DEVICE_REVOKED`              | Operator revokes a device.                              |
| `AUTH_SUCCEEDED`              | Connection authenticated (chain + pin + device active). |
| `AUTH_FAILED`                 | Authentication failed.                                  |
| `SESSION_ISSUED`              | New gateway session established.                        |
| `SESSION_EXPIRED`             | Session reached idle or absolute expiry.                |
| `SESSION_REVOKED`             | Session explicitly revoked.                             |
| `SESSION_CLOSED`              | Session closed via `DELETE`.                            |
| `RATE_LIMITED`                | A limiter refused a request.                            |
| `REMOTE_DISCONNECTED`         | Remote connection ended.                                |

**Safe-field rule:** records carry safe identifiers and digests only. Where a
value must be referenced, reference its digest, not the value.

**Never audited:** raw session tokens, private keys, certificate private
material, `Authorization` header values, cookies/session secrets, raw
credentials, or full attacker-supplied certificate blobs (identify a rejected
certificate by digest only, and only where an operator can act on it).

The chain, sequencing, redaction, and integrity behaviour are **unchanged from
RC-04**. RC-06 owns external persistence and anchoring.

---

## 25. Client-Facing Error Model

**No new `ArcErrorCode` values are required.** The reserved codes
`UNAUTHENTICATED`, `INVALID_SESSION_TOKEN`, `DEVICE_NOT_ENROLLED`, and
`RATE_LIMIT_EXCEEDED` (§2.4) are activated as part of RC-05 implementation, and
`PAYLOAD_TOO_LARGE` is reused. Transport and TLS rejections occur before MCP and
are HTTP-level responses that carry **no MCP error body**.

| Situation                         | Class                            | Externally observable code |
| :-------------------------------- | :------------------------------- | :------------------------- |
| TLS / transport rejection         | Transport (HTTP-level)           | No MCP body                |
| Authentication failure            | Auth                             | `UNAUTHENTICATED`          |
| Device not enrolled / revoked     | Auth                             | `DEVICE_NOT_ENROLLED`      |
| Session expired/revoked/malformed | Session                          | `INVALID_SESSION_TOKEN`    |
| Rate limit                        | Rate                             | `RATE_LIMIT_EXCEEDED`      |
| Oversized request                 | Bounds                           | `PAYLOAD_TOO_LARGE`        |
| Authorization denial              | Authorization (RC-04, unchanged) | `POLICY_DENIED` etc.       |

**Anti-oracle rule:** an authentication failure MUST NOT reveal whether a
`deviceId` exists, whether a token prefix was correct, whether a certificate
nearly matched a pin, or whether a trust-store record exists. All
authentication failures are indistinguishable from one another to the client.
Failures are distinguishable to the **operator** through audit records.

---

## 26. Session and Connection Concurrency

| Rule | Bound / behaviour                                                                                                                                             |
| :--- | :------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| C-1  | Max **512** simultaneous connections; max **32** per peer IP.                                                                                                 |
| C-2  | Max **8** live sessions per device; **64** per client; **1024** globally.                                                                                     |
| C-3  | Max **4** outstanding MCP requests per session.                                                                                                               |
| C-4  | **Duplicate session ID:** a request presenting a session ID with a mismatched identity is rejected, not adopted.                                              |
| C-5  | **Connection takeover:** not supported. A new connection authenticates as the same device but does not inherit another connection's session state.            |
| C-6  | **Concurrent use of one session token** is permitted within C-3 only.                                                                                         |
| C-7  | **Backpressure:** exceeding any bound produces a sanitized refusal; the gateway never queues unbounded work.                                                  |
| C-8  | **Shutdown/drain:** on shutdown the listener stops accepting, in-flight requests get a bounded grace period, then connections close and sessions are revoked. |

**No unbounded maps, queues, or buffers exist anywhere in the gateway path.**
Every per-key structure has an eviction policy and a hard size bound.

---

## 27. Remote Execution Semantics

- Remote access **reuses the existing `ArcMcpServer` authorization and execution
  pipeline**.
- **No duplicated tool dispatcher. No remote-specific fast path. No direct
  subsystem invocation by the gateway.**
- After trusted actor context is established (§13), remote and stdio tool
  semantics **converge**: same schema validation, same workspace resolution,
  same Layer 1, same Layer 2, same approval floor, same audit, same subsystems.
- The only differences between stdio and remote are **transport admission** and
  **actor derivation** — both of which happen strictly before the shared
  pipeline.

---

## 28. Approval Token Interaction

| Rule | Normative statement                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| :--- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| X-1  | RC-04 approval tokens and RC-05 session tokens are **separate classes**. They are never interchangeable.                                                                                                                                                                                                                                                                                                                                                                    |
| X-2  | A **session token MUST NOT** act as an approval token.                                                                                                                                                                                                                                                                                                                                                                                                                      |
| X-3  | A session token **MUST NOT** bypass `REQUIRE_APPROVAL`.                                                                                                                                                                                                                                                                                                                                                                                                                     |
| X-4  | A session token **MUST NOT** extend an approval TTL.                                                                                                                                                                                                                                                                                                                                                                                                                        |
| X-5  | A session token **MUST NOT** revive an expired or invalidated approval.                                                                                                                                                                                                                                                                                                                                                                                                     |
| X-6  | An approval remains bound to the **exact** authenticated actor/session/device context (§13).                                                                                                                                                                                                                                                                                                                                                                                |
| X-7  | **Session expires between approval request and redemption:** redemption fails with `APPROVAL_REJECTED` (the bound `sessionId` no longer matches the authenticated context). The approval record's own TTL is unaffected; it is neither extended nor revived. Re-authentication establishes a **new** `sessionId`, so a new approval must be requested. This is deliberate: silently re-binding an approval to a new session would break the actor binding RC-04 depends on. |

---

## 29. Process Restart and Crash Semantics

| Resource            | Effect of restart                                                                            |
| :------------------ | :------------------------------------------------------------------------------------------- |
| TLS listener        | Rebound from configuration.                                                                  |
| Connections         | All closed.                                                                                  |
| Sessions            | **All revoked.**                                                                             |
| Session tokens      | **All invalid.**                                                                             |
| Device enrollment   | **Survives** (persistent trust store).                                                       |
| Revocations         | **Survive** (persisted).                                                                     |
| Rate-limit state    | Reset.                                                                                       |
| Pending enrollment  | Purged.                                                                                      |
| **RC-04 approvals** | **Still invalidated by restart — unchanged.** RC-05 must not make approval state persistent. |

---

## 30. Package and Ownership Plan

Respecting documented ownership (`docs/architecture/package-ownership.md`):

| Package / app                | RC-05 responsibility                                                                                                                  |
| :--------------------------- | :------------------------------------------------------------------------------------------------------------------------------------ |
| `packages/auth`              | Identity, device enrollment, pin verification, session issuance/validation, actor-context derivation. **Pure logic; no network I/O.** |
| `apps/mcp-server`            | MCP transports and listeners (stdio **or** remote), TLS/mTLS admission, rate limiters, gateway composition, health.                   |
| `packages/protocol`          | Data contracts only (`AuthInfo`-equivalent DTOs, gateway event types, error codes). No logic.                                         |
| `packages/audit`             | Audit structures and the existing hash chain. **No change to chain semantics.**                                                       |
| `apps/cli` + local admin IPC | Operator administration of devices and sessions (§15).                                                                                |

**No new package or app is created in Task 0**, and none is currently proposed:
the documented ownership above already covers every RC-05 responsibility. If
implementation later shows a boundary is insufficient, that is raised as its own
reviewed task.

---

## 31. Dependency Policy

| Candidate dependency                                                | Verdict                                                                                                             |
| :------------------------------------------------------------------ | :------------------------------------------------------------------------------------------------------------------ |
| Node built-ins (`node:tls`, `node:net`, `node:http`, `node:crypto`) | **Sufficient and preferred** for TLS, mTLS, binding, pinning, CSPRNG, timing-safe comparison, and the rate limiter. |
| `@modelcontextprotocol/sdk` `StreamableHTTPServerTransport`         | **Already a dependency.** Provides the MCP Streamable HTTP transport.                                               |
| X.509 parsing for SPKI extraction                                   | **Prefer Node built-ins** (`crypto.X509Certificate.publicKey` → DER SPKI), avoiding a new parsing dependency.       |
| Rate limiting library                                               | **Not proposed.** A fixed-memory sliding window is small, testable, and avoids a supply-chain addition.             |
| JWT/JOSE library                                                    | **Not proposed.** Session tokens are opaque and opaque tokens need no JOSE.                                         |
| OAuth/OIDC/SAML libraries                                           | **Not proposed.** Those capabilities are deferred (§10).                                                            |

**No dependency changes in Task 0.** Any dependency later proposed must justify
purpose, why built-ins are insufficient, security relevance, runtime vs dev-only,
and supply-chain implications.

---

## 32. Versioning

The public RC-05 stage version is proposed as **`0.5.0-rc05`**, matching the
existing `0.<stage>.0-rc0<stage>` convention (`0.4.0-rc04`). **Task 0 performs no
version bump**; no `package.json` is modified.

---

## 33. Out-of-Scope Catalog

Explicitly out of scope for RC-05 baseline:

- Persistent or externally anchored audit ledger (**RC-06**).
- Git mutation (still not separately authorized).
- Cloud-root / production-root defaults.
- Remote shell bypass of the existing terminal tool.
- Arbitrary TCP tunnelling.
- SSH server replacement.
- VPN functionality.
- Generic reverse proxy functionality.
- Unrestricted port forwarding.
- Web approval dashboard.
- Slack/Teams/mobile approval integration (RC-05/RC-08 historically).
- Multi-party approval quorum.
- Wildcard or ambient approvals.
- Automatic trust of local-network peers.
- **Unauthenticated remote mode** — no such mode exists.
- **Insecure HTTP fallback** — no such fallback exists.
- Repository-shipped private keys or certificates.
- **OIDC, OAuth2, SAML, enterprise IdP federation, hardware device attestation** — deferred (§10).
- Remote operator/approval administration (§15).
- TLS termination delegated to an external reverse proxy (§6).
- MCP message resumption / `eventStore` (§5).

---

## 34. Negative Security Control Catalog

`N = 48`. Every material invariant in this scope has at least one direct,
code-testable control. Each control states the attack/input, the expected
rejection/result, and the critical no-side-effect assertion.

### Transport (RC05-NEG-01 … 06)

| ID          | Attack / input                                     | Expected result                   | Critical no-side-effect           |
| :---------- | :------------------------------------------------- | :-------------------------------- | :-------------------------------- |
| RC05-NEG-01 | Plain HTTP request to the remote port              | Connection refused / TLS required | No MCP parse; no policy reached   |
| RC05-NEG-02 | Request to a non-configured path                   | `404`                             | Policy engine not reached         |
| RC05-NEG-03 | Request to a legacy SSE endpoint                   | `404`                             | No session minted                 |
| RC05-NEG-04 | Unknown HTTP method                                | `405`                             | No processing; policy not reached |
| RC05-NEG-05 | Wildcard bind without opt-in flag                  | **Startup failure**               | No listener bound                 |
| RC05-NEG-06 | Stateless transport (`sessionIdGenerator` omitted) | Configuration rejected            | No listener bound                 |

### TLS (RC05-NEG-07 … 12)

| ID          | Attack / input                        | Expected result     | Critical no-side-effect      |
| :---------- | :------------------------------------ | :------------------ | :--------------------------- |
| RC05-NEG-07 | TLS 1.2 handshake attempt             | Handshake refused   | No MCP bytes parsed          |
| RC05-NEG-08 | Connection with no client certificate | Handshake refused   | No device lookup; no session |
| RC05-NEG-09 | Client certificate from an unknown CA | Handshake refused   | Trust store not mutated      |
| RC05-NEG-10 | Expired client certificate            | Handshake refused   | No session minted            |
| RC05-NEG-11 | Malformed certificate                 | Handshake refused   | No MCP parse                 |
| RC05-NEG-12 | Server cert/key mismatch at startup   | **Startup failure** | No listener bound            |

### mTLS / Pinning (RC05-NEG-13 … 16)

| ID          | Attack / input                                         | Expected result         | Critical no-side-effect               |
| :---------- | :----------------------------------------------------- | :---------------------- | :------------------------------------ |
| RC05-NEG-13 | Valid chain, but SPKI not pinned to any device         | `UNAUTHENTICATED`       | Policy engine not reached             |
| RC05-NEG-14 | Pin rotated: old pin inside window, then after removal | Accepted, then rejected | No lingering acceptance after removal |
| RC05-NEG-15 | Malformed / empty pin configuration                    | **Startup failure**     | No listener bound                     |
| RC05-NEG-16 | Two devices sharing one pin                            | **Startup failure**     | No listener bound                     |

### Device Enrollment (RC05-NEG-17 … 24)

| ID          | Attack / input                                          | Expected result                   | Critical no-side-effect                     |
| :---------- | :------------------------------------------------------ | :-------------------------------- | :------------------------------------------ |
| RC05-NEG-17 | Remote self-enrollment attempt                          | Rejected                          | **No device enrolled**                      |
| RC05-NEG-18 | Enrollment secret replay                                | Rejected                          | No second device; existing device unchanged |
| RC05-NEG-19 | Expired enrollment challenge                            | Rejected                          | No device enrolled                          |
| RC05-NEG-20 | Enrollment attempt without proof of possession          | Rejected                          | No device enrolled                          |
| RC05-NEG-21 | Pending-enrollment quota exceeded                       | Rejected                          | Existing pending/enrolled state unchanged   |
| RC05-NEG-22 | Duplicate enrollment of an already-pinned certificate   | Same `deviceId`; no second record | No duplicate trust-store entry              |
| RC05-NEG-23 | Enrollment of a pin already bound to another `clientId` | Rejected                          | Existing binding unchanged                  |
| RC05-NEG-24 | Two concurrent completions of one enrollment            | Exactly one wins                  | Exactly one device record created           |

### Session Tokens (RC05-NEG-25 … 31)

| ID          | Attack / input                                         | Expected result         | Critical no-side-effect                     |
| :---------- | :----------------------------------------------------- | :---------------------- | :------------------------------------------ |
| RC05-NEG-25 | Request with no session token                          | `UNAUTHENTICATED`       | Policy engine not reached                   |
| RC05-NEG-26 | Malformed session token                                | `INVALID_SESSION_TOKEN` | No oracle distinguishing malformed vs wrong |
| RC05-NEG-27 | Expired session token (idle)                           | `INVALID_SESSION_TOKEN` | No request reaches policy                   |
| RC05-NEG-28 | Expired session token (absolute)                       | `INVALID_SESSION_TOKEN` | No request reaches policy                   |
| RC05-NEG-29 | Revoked session token replayed                         | `INVALID_SESSION_TOKEN` | No request reaches policy                   |
| RC05-NEG-30 | Token presented from a different device's TLS identity | `INVALID_SESSION_TOKEN` | **Token unusable cross-device**             |
| RC05-NEG-31 | Session cap exceeded for a device                      | Refused                 | Existing sessions unaffected                |

### Actor Binding (RC05-NEG-32 … 35)

| ID          | Attack / input                                          | Expected result          | Critical no-side-effect                |
| :---------- | :------------------------------------------------------ | :----------------------- | :------------------------------------- |
| RC05-NEG-32 | Request supplies `clientId` / `clientType` / `deviceId` | `INVALID_REQUEST_SCHEMA` | Policy engine not reached              |
| RC05-NEG-33 | Request supplies `sessionId`                            | `INVALID_REQUEST_SCHEMA` | Trusted session context not overridden |
| RC05-NEG-34 | `_arcApproval` object carries actor fields              | `INVALID_REQUEST_SCHEMA` | No approval state mutated              |
| RC05-NEG-35 | Actor context reaching `executionPayloadHash`           | Equals derived context   | No caller value influences the hash    |

### Rate Limiting and Bounds (RC05-NEG-36 … 41)

| ID          | Attack / input                                | Expected result       | Critical no-side-effect                      |
| :---------- | :-------------------------------------------- | :-------------------- | :------------------------------------------- |
| RC05-NEG-36 | Unauthenticated request flood                 | `RATE_LIMIT_EXCEEDED` | Refused **before** cryptographic/policy work |
| RC05-NEG-37 | Attacker-chosen client ID as a rate-limit key | Not honoured          | Pre-auth limiter keyed on peer IP only       |
| RC05-NEG-38 | Body exceeding 4 MiB                          | `PAYLOAD_TOO_LARGE`   | Policy engine not reached                    |
| RC05-NEG-39 | Compressed body via `Content-Encoding`        | Rejected              | Limit not bypassable by compression          |
| RC05-NEG-40 | Slowloris / partial body                      | Connection aborted    | No unbounded buffer held                     |
| RC05-NEG-41 | Per-session concurrency cap exceeded          | Refused               | No unbounded queue                           |

### Authentication-Before-Policy (RC05-NEG-42 … 44)

| ID          | Attack / input                                            | Expected result | Critical no-side-effect             |
| :---------- | :-------------------------------------------------------- | :-------------- | :---------------------------------- |
| RC05-NEG-42 | Unauthenticated request that would otherwise be `ALLOW`ed | Rejected        | **Policy engine not reached** (spy) |
| RC05-NEG-43 | Unauthenticated request that would otherwise execute      | Rejected        | **Subsystem not called** (spy)      |
| RC05-NEG-44 | Authenticated session hitting a `DENY` policy             | `POLICY_DENIED` | Auth success does not imply ALLOW   |

### Approval Separation (RC05-NEG-45 … 46)

| ID          | Attack / input                                          | Expected result     | Critical no-side-effect                          |
| :---------- | :------------------------------------------------------ | :------------------ | :----------------------------------------------- |
| RC05-NEG-45 | Session token used as an approval token                 | `APPROVAL_REJECTED` | Subsystem not called                             |
| RC05-NEG-46 | Session expired between approval request and redemption | `APPROVAL_REJECTED` | Approval not extended, not revived, not re-bound |

### Restart, Audit Secrecy, Admin Isolation (RC05-NEG-47 … 48)

| ID          | Attack / input                                                                                     | Expected result                                                           | Critical no-side-effect       |
| :---------- | :------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------ | :---------------------------- |
| RC05-NEG-47 | Restart: sessions/challenges cleared, device trust retained, **RC-04 approvals still invalidated** | Sessions invalid; enrollment retained; approvals gone                     | Approvals not made persistent |
| RC05-NEG-48 | Audit/log/error inspection after full lifecycle with secrets present                               | No raw token, `Authorization` value, private key, or cookie in any record | No secret audited             |

### 34.1 Additional admin-isolation controls

Remote administrative capability is a distinct invariant and carries its own
controls inside the RC-05 acceptance suite:

| ID          | Attack / input                               | Expected result | Critical no-side-effect       |
| :---------- | :------------------------------------------- | :-------------- | :---------------------------- |
| RC05-NEG-49 | Remote client attempts `approve` / `reject`  | `POLICY_DENIED` | No approval state mutated     |
| RC05-NEG-50 | Remote client attempts approval list/inspect | `POLICY_DENIED` | No review material disclosed  |
| RC05-NEG-51 | Remote client attempts device enroll/revoke  | Rejected        | Trust store unchanged         |
| RC05-NEG-52 | Remote client attempts policy administration | `POLICY_DENIED` | Policy engine state unchanged |

**Final catalog size: N = 52.** The count is derived from the threat model in
§35, not chosen to mirror RC-04.

---

## 35. Threat Matrix

| Threat                                    | Trust Boundary      | Preventive Control                               | Detection / Audit                 | Negative control |
| :---------------------------------------- | :------------------ | :----------------------------------------------- | :-------------------------------- | :--------------- |
| Unauthenticated remote tool invocation    | TB-1 Ingress        | §11–§12 auth sequence; §3 invariant              | `AUTH_FAILED`                     | 25, 42, 43       |
| Plaintext or downgraded transport         | TB-1 Ingress        | §6 TLS 1.3 only, no fallback                     | `AUTH_FAILED` / handshake refusal | 01, 07           |
| Unenrolled device                         | TB-1 → TB-2         | §8 device trust store; §7 pin                    | `DEVICE_NOT_ENROLLED`             | 13               |
| Certificate/key theft (no private key)    | TB-1 Ingress        | §7 mTLS requires the private key                 | `AUTH_FAILED`                     | 08, 11           |
| Session token theft                       | TB-2 Policy         | §11 binding to device + SPKI                     | `INVALID_SESSION_TOKEN`           | 30               |
| Session fixation                          | TB-2 Policy         | §11 server-generated only                        | `INVALID_SESSION_TOKEN`           | 25, 26           |
| Cross-device token replay                 | TB-2 Policy         | §11 binding                                      | `INVALID_SESSION_TOKEN`           | 30               |
| Actor-field spoofing from remote JSON     | TB-2 Policy         | §13 server-derived actor                         | `INVALID_REQUEST_SCHEMA`          | 32, 33, 34, 35   |
| Auth mistaken for authorization           | TB-2 Policy         | §14 separation; RC-04 policy unchanged           | `POLICY_DENIED`                   | 44               |
| Session token used as approval token      | TB-2 Policy         | §28 separation                                   | `APPROVAL_REJECTED`               | 45               |
| Approval re-bound across expiring session | TB-2 Policy         | §28 X-7 fails closed                             | `APPROVAL_REJECTED`               | 46               |
| Connection / handshake flood              | TB-1 Ingress        | §21 pre-auth limits; §26 caps                    | `RATE_LIMITED`                    | 36, 41           |
| Slowloris                                 | TB-1 Ingress        | §20 read timeouts, header bounds                 | `REMOTE_DISCONNECTED`             | 40               |
| Oversized / compressed payload            | TB-1 Ingress        | §20 4 MiB during-read enforcement                | `PAYLOAD_TOO_LARGE`               | 38, 39           |
| Enrollment replay / race                  | TB-1 → TB-2         | §9 single-use secrets, atomic completion         | `DEVICE_ENROLLMENT_REJECTED`      | 18, 24           |
| Rogue enrollment authority                | TB-2 Policy         | §9 local-operator-only bootstrap                 | `DEVICE_ENROLLMENT_REJECTED`      | 17, 20           |
| Device revocation not enforced            | TB-2 Policy         | §8, §11 immediate revocation                     | `DEVICE_REVOKED`                  | 29               |
| Remote administrative escalation          | TB-2 Policy         | §15 admin stays local                            | `POLICY_DENIED`                   | 49, 50, 51, 52   |
| Secret leakage into audit/logs            | TB-3 Host Execution | §17 K-3; central redaction                       | Audit secrecy assertions          | 48               |
| Proxy-header identity spoofing            | TB-1 Ingress        | §6.1 in-process TLS; headers never authoritative | `UNAUTHENTICATED`                 | 13, 23           |
| DNS rebinding / browser origin            | TB-1 Ingress        | §23 default-deny origin, Host validation         | Rejection before parse            | 02, 05           |
| Restart resurrecting authority            | TB-2 Policy         | §29 restart semantics                            | `SESSION_REVOKED`                 | 47               |
| Wildcard bind exposure                    | TB-1 Ingress        | §18 explicit opt-in                              | Startup failure                   | 05               |

---

## 36. Positive Acceptance Flows

These are the required **success** paths. Task 0 does not implement them.

1. **Server startup in stdio-only mode** — starts, listens on stdio, remote
   gateway inactive, health reports `transportMode: 'stdio'` and
   `remoteGatewayActive: false`. **RC-04 behaviour unchanged.**
2. **Remote gateway startup** — valid TLS 1.3 + mTLS config and non-empty trust
   store; listener bound; health reports `transportMode: 'remote'`,
   `remoteGatewayActive: true`, `authenticationActive: true`, and
   `enrolledDevicesCount`.
3. **Trusted device enrollment** — operator initiates on the local admin
   channel; device completes over the remote channel with proof of possession;
   `DEVICE_ENROLLED` is audited; the device's pin is recorded.
4. **Authenticated remote connection** — client completes TLS 1.3 + mTLS with an
   enrolled certificate; `AUTH_SUCCEEDED` audited.
5. **Session establishment** — session token issued once, `SESSION_ISSUED`
   audited, session bound to `(deviceId, SPKI, clientId)`.
6. **Ordinary read-only MCP tool invocation** — passes through the shared
   pipeline with the derived actor; identical semantics to stdio.
7. **Policy `REQUIRE_APPROVAL` invocation** — returns `APPROVAL_REQUIRED` with a
   request id and **no token**; approval is bound to the remote-derived actor.
8. **Approval redemption from the same authenticated session/device** —
   operator approves on the local channel; redemption succeeds from the same
   session; the mutation executes; execution lifecycle audited.
9. **Session expiration and re-authentication** — idle/absolute expiry revokes
   the session; a new session is issued after re-authentication; old token no
   longer works.
10. **Device revocation** — operator revokes; live sessions for that device are
    revoked; subsequent requests fail with `DEVICE_NOT_ENROLLED`; the trust
    store reflects the revocation across restart.

---

## 37. Historical Documentation Reconciliation

| Historical source                            | Historical wording                                                                                                                            | Ambiguity / conflict                                                                    | **Normative RC-05 rule**                                                                                                                                  |
| :------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `README.md`                                  | "Remote MCP over HTTPS/SSE", mutual TLS, device enrollment                                                                                    | "SSE" is a deprecated transport name in SDK 1.30.0                                      | **Streamable HTTP only** (§5). SSE survives as _response framing_, not as a transport.                                                                    |
| `docs/architecture/overview.md`              | "local stdio and remote authenticated HTTPS/SSE"; "device enrollment, token lifecycle management, and session pinning"                        | Suggests both transports can run; does not define session pinning                       | **Mutually exclusive listeners** (§4). "Session pinning" = binding to `(deviceId, SPKI, clientId)` (§11).                                                 |
| `docs/architecture/trust-boundaries.md`      | "TLS 1.3 with pinned certificates"; "Hard ceiling on JSON-RPC message size (default: 4 MB)"; "Sliding-window rate limiter per client session" | Pinning undefined; "4 MB" ambiguous; limiter keyed on "session" only is unsafe pre-auth | **SPKI SHA-256 pin in addition to chain validation** (§7); **4 MiB measured on raw body bytes** (§20); **two limiters, pre-auth keyed on peer IP** (§21). |
| `docs/architecture/trust-boundaries.md`      | "HTTPS/WSS SSE" transport termination                                                                                                         | Implies WebSocket support                                                               | **WebSocket not supported** (§5).                                                                                                                         |
| `docs/threat-model/threat-model.md`          | "Mandatory TLS 1.3, cryptographic session tokens, client device enrollment, stdio inheritance checks (RC-05)"                                 | "stdio inheritance checks" undefined for a remote stage                                 | stdio is a **separate mutually exclusive mode** whose actor is never derived from remote credentials (§4, §13).                                           |
| `docs/architecture/package-ownership.md`     | `packages/auth` owns identity/session/device auth; `apps/mcp-server` owns stdio + HTTPS/SSE transports                                        | Confirms ownership; transport name stale                                                | Ownership **preserved**; transport is **Streamable HTTP** (§30).                                                                                          |
| `docs/architecture/rc04-scope-acceptance.md` | Remote HTTPS/SSE/TLS/mTLS deferred to RC-05; OIDC/SAML/OAuth2 + device attestation "RC-05"; remote approval administration absent             | Conflicts with the narrower README roadmap                                              | Transport per §5; **OIDC/OAuth2/SAML/IdP/attestation deferred beyond RC-05** (§10); **admin stays local** (§15).                                          |
| `docs/architecture/trust-boundaries.md`      | "All remote connections require TLS 1.3 with pinned certificates"                                                                             | Does not say whether a proxy may terminate TLS                                          | **In-process TLS only**; proxy termination out of scope (§6).                                                                                             |
| `packages/auth/src/index.ts`                 | `IAuthEngine.verifyToken` / `generateSessionToken` as the RC-05 target                                                                        | Implies a token engine; silent on binding and enrollment                                | Contract kept conceptually; RC-05 adds **enrollment, pinning, and TLS-identity binding** around it (§8, §11).                                             |

---

## 38. Implementation Breakdown

Nine tasks, derived from independently reviewable security boundaries rather
than inherited from RC-04's count. **Task 0 is not implementation and is not
counted.**

| #   | Title                                                | Scope                                                                                                                                                                                    | Expected files                                                                           | Security invariants                         | Controls           | Depends on | Stop boundary                                       |
| :-- | :--------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------------------------------------------------------------------------------------- | :------------------------------------------ | :----------------- | :--------- | :-------------------------------------------------- |
| 1   | Device identity + trust store                        | `deviceId` generation, SPKI pin derivation/validation, trust-store read/write/validate, revocation state. **No network I/O.**                                                            | `packages/auth/src/**`, `packages/protocol/src/**`, tests                                | §7 P-4/P-5/P-7/P-8, §8 all, §16 trust store | 13, 15, 16, 22, 23 | —          | No transport, no session, no server wiring          |
| 2   | Enrollment lifecycle                                 | Pending enrollment creation (local-channel initiated), one-time secret, PoC completion, quotas, cancel, atomic completion.                                                               | `packages/auth/src/**`, `apps/mcp-server/src/admin-ipc.ts`, `apps/cli/src/**`, tests     | §9 all                                      | 17–24              | 1          | No TLS listener; enrollment is testable without one |
| 3   | TLS + mTLS admission layer                           | TLS 1.3 listener, client-cert requirement, chain validation, pin lookup, startup validation, timeouts.                                                                                   | `apps/mcp-server/src/**`, tests                                                          | §6, §7 P-1..P-3, §18, §20 timeouts          | 01, 05–12          | 1          | No MCP session yet; transport admits, nothing more  |
| 4   | Session issuance, binding, validation                | Opaque token mint/verify, digest store, TTLs, revocation, caps, per-request re-validation.                                                                                               | `packages/auth/src/**`, tests                                                            | §11 all, §26 C-2/C-4                        | 25–31              | 1          | No MCP request handling                             |
| 5   | Actor-context derivation                             | Map authenticated connection → `(clientId, clientType, deviceId, sessionId)`; block caller-supplied actor fields; wire into the shared pipeline.                                         | `apps/mcp-server/src/**`, tests                                                          | §3, §13, §14                                | 32–35, 42–44       | 3, 4       | No new tool logic                                   |
| 6   | Rate limiting + resource bounds                      | Pre-auth and post-auth limiters, concurrency caps, body/header/URL bounds, slowloris timeouts, eviction.                                                                                 | `packages/auth/src/**` or `apps/mcp-server/src/**`, tests                                | §20, §21, §26 C-1/C-3/C-7/C-8               | 36–41              | 3          | Bounds only; no auth decisions                      |
| 7   | Streamable HTTP gateway composition + health         | `StreamableHTTPServerTransport` wiring, session registry, `DELETE` teardown, health fields, mutual exclusion with stdio.                                                                 | `apps/mcp-server/src/**`, `packages/protocol/src/**`, tests                              | §4, §5, §19, §23, §27                       | 02, 03, 04, 06     | 3–6        | Composition only; no policy/approval change         |
| 8   | Operator device/session administration               | CLI + admin IPC methods: list/inspect/revoke devices, list/revoke sessions, revoke-all.                                                                                                  | `apps/cli/src/**`, `apps/mcp-server/src/admin-ipc.ts`, tests                             | §15, §26                                    | 29, 49–52          | 2, 4       | Admin stays local; no remote admin surface          |
| 9   | Audit events, error model, acceptance + finalization | Gateway audit catalog, error-code activation, anti-oracle responses, `tests/rc05-negative-controls.test.js` (all 52), `scripts/verify-rc05.sh`, `verify:rc05`, final integration report. | `packages/audit/src/**`, `packages/protocol/src/**`, `tests/**`, `scripts/**`, `docs/**` | §24, §25, §28–§29, §34–§35                  | all 52             | 1–8        | Finalization only                                   |

---

## 39. Definition of Done (RC-05)

RC-05 is complete only when **all** of the following hold:

1. The remote transport contract of §5 is implemented **exactly** — Streamable
   HTTP, stateful, TLS 1.3, no legacy SSE, no plaintext, no WebSocket.
2. **Authenticated remote MCP only**: no request can reach policy or a subsystem
   without the full §12 sequence.
3. The **TLS contract (§6)** is satisfied, including mandatory mTLS and
   in-process termination.
4. The **device enrollment lifecycle (§9)** is satisfied end to end, including
   restart persistence of _completed_ enrollments.
5. The **session lifecycle (§11)** is satisfied, including binding, TTLs,
   revocation, and restart volatility.
6. **Authentication/authorization separation (§14)** is preserved and
   demonstrated: a valid session hitting `DENY` is denied.
7. **RC-04 policy and approval invariants are preserved** — `DENY >
REQUIRE_APPROVAL > ALLOW`, mutation floor, approval binding, 300 s monotonic
   TTL, restart invalidation — with regression tests proving it.
8. **Local stdio regression is green**: existing stdio behaviour and RC-01…RC-04
   suites unchanged.
9. **All 52 negative controls (§34) are green** in a dedicated acceptance suite,
   with no skips and no todos.
10. **Remote positive flows (§36)** pass as integration tests.
11. **Bounded resource and rate-limit tests** pass, including the caps and
    eviction bounds of §20, §21, and §26.
12. **Audit redaction/secrecy tests** pass: no token, key, `Authorization`
    value, or cookie in any record.
13. **No secret or private credential artifacts** exist in the repository.
14. **`scripts/verify-rc05.sh` and `pnpm run verify:rc05`** exist and pass.
15. The **RC-05 final integration report** is written and accurate.
16. **Exact-head push CI, PR CI including Dependency Review, independent review,
    merge, and post-merge main CI** all complete with attempt 1 green.

---

## 40. Open Questions

None. Every ambiguity raised by the Task-0 brief is resolved above by an explicit
normative rule. Items that could not be resolved without a separate security
design are marked **out of scope** rather than left undefined (§33).

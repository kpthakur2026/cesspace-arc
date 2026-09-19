# RC-05 Scope & Acceptance — Secure Remote Gateway

| Field         | Value                                                                                                                                                       |
| :------------ | :---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Stage**     | RC-05                                                                                                                                                       |
| **Title**     | Secure Remote Gateway                                                                                                                                       |
| **Status**    | **Task-0 Scope Candidate — Frozen Architecture Specification**                                                                                              |
| **Base main** | `f70a5efea4018079de1ac1ee423b7e51574b1262`                                                                                                                  |
| **Branch**    | `feat/rc-05-secure-remote-gateway`                                                                                                                          |
| **Purpose**   | Freeze remote transport, authentication, device identity, session, rate-limit, audit, failure, and trust-boundary semantics **before** any code is written. |

> **Implementation MUST NOT begin until this scope is independently approved.**
> This document is a normative contract, not an implementation plan that has been
> accepted. Every rule below is intended to be directly code-testable; none of it
> is implemented by Task 0.

---

## 1. Authority and Status

This document is the **normative contract** for RC-05. On independent approval it
supersedes ambiguous or outdated RC-00 wording for this stage. Until that approval,
the existing documents remain as they are: **Task 0 modifies no other file**.

Where a historical document states something this contract contradicts, the
specific rule is restated in §37 (Historical Documentation Reconciliation) with
the new normative rule named explicitly.

All 15 architectural blockers identified during Task 0.1 review (enrollment
bootstrap deadlock, numeric bounds, session bootstrap wire protocol, session ID
unification, trust store and CA file integrity, anti-oracle error consistency,
three-layer rate limiting, rate limiter memory bounds, TLS server certificate
validation, runtime certificate expiry, resource caps, positive flows, threat
matrix expansion, and task breakdown decomposition) are normatively resolved in
this specification.

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
- The SDK ships `StreamableHTTPServerTransport`, `SSEServerTransport`, and
  `StdioServerTransport`.

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
| `allowedHosts`, `allowedOrigins`, `enableDnsRebindingProtection` | DNS-rebinding protection — **all three `@deprecated`** in favour of external middleware. | Handled by the gateway's own validation (§23), not by these options.         |
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
used. §25 defines exactly how these codes are activated. In particular,
`DEVICE_NOT_ENROLLED` is preserved strictly as an **internal and operator-facing
audit diagnostic code**; ordinary remote clients never receive it externally
and instead receive generic `UNAUTHENTICATED` to prevent device enumeration.

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
  → Layer A: TCP/TLS connection admission (peer IP, connection/handshake caps)
  → In-process TLS 1.3 handshake (mTLS: client cert chains to configured client CA)
  → Layer B: Secure HTTP pre-session admission (peer IP rate limiter, max 120 req/min)
  → Endpoint router:
      IF POST /enroll/complete:
        → Bootstrap proof-of-possession verification
        → Atomic trust-store update & HTTP 200 response (no MCP session created)
      IF /mcp:
        → Enrolled device & SPKI pin lookup (generic UNAUTHENTICATED on mismatch)
        → Gateway session authentication:
            IF initial initialize: mint session & Mcp-Session-Id, issue Arc-Session-Token header
            IF ordinary request: require Mcp-Session-Id + Authorization: Bearer <token>
        → Layer C: Authenticated session/device rate limiting (max 300 req/min)
        → Server-derived actor context (clientId, clientType, deviceId, sessionId)
        → Existing schema / workspace / Layer 1 / Layer 2 / approval pipeline
        → Append-only audit hash chain
        → Subsystem execution
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
| L-5  | Actor construction is **explicit and distinguishable** by transport (§13).                                                                     |
| L-6  | **No caller may self-assert trusted actor fields** over any transport (§13).                                                                   |

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

**Decision: RC-05 supports exactly one remote MCP transport — MCP Streamable HTTP
over TLS 1.3, using the SDK's `StreamableHTTPServerTransport` in stateful mode.
Legacy SSE is NOT supported. Plain HTTP is NEVER allowed. WebSockets are NOT
supported.**

### 5.1 Endpoints and Bootstrap Distinction

The gateway exposes exactly two HTTP paths:

1. `/mcp` (default, configurable path): The **sole MCP transport endpoint**. It
   accepts `POST` (client→server JSON-RPC), `GET` (server→client SSE stream),
   and `DELETE` (session termination). Any other method is `405`.
2. `POST /enroll/complete`: The **ARC gateway bootstrap endpoint** for
   operator-initiated enrollment completion (§9). It is **NOT** an MCP tool,
   is **NOT** an MCP endpoint, creates no MCP session, reaches no policy, and
   reaches no subsystem.

Any other HTTP request path produces `404` and terminates immediately.

### 5.2 Zero-Enrolled-Devices Remote Startup

The remote gateway is explicitly permitted to start with:

- Valid server TLS configuration (certificate, private key, SAN match).
- Valid client CA / trust roots (regular file, restricted permissions).
- **Zero enrolled devices** in the trust store (`enrolledDevicesCount: 0`).

In this zero-device state:

- The TLS listener binds and accepts mTLS connections chaining to the client CA.
- `/mcp` **rejects all ordinary sessions** with generic `UNAUTHENTICATED`
  because no enrolled device exists.
- `POST /enroll/complete` **is active and functional**, allowing the FIRST device
  to complete an operator-created pending enrollment proof-of-possession.

### 5.3 Session Bootstrap Wire Protocol

The bootstrap sequence on `/mcp` operates as follows:

A. **mTLS Handshake:** Client connects and completes TLS 1.3 + mTLS. ARC
verifies that the client certificate chains to the configured client CA.
B. **Device Resolution:** ARC computes the SHA-256 SPKI digest of the presented
client certificate and looks up the enrolled device record. If not found or
revoked, authentication fails with generic `UNAUTHENTICATED` (§25).
C. **Tokenless Initialize:** The **ONLY** tokenless MCP request permitted on
`/mcp` is the initial MCP `initialize` request for a connection that has no
existing MCP session. Any ordinary tool invocation or request missing a token
is rejected with generic `UNAUTHENTICATED`.
D. **Session ID Generation:** The SDK generates the `Mcp-Session-Id`. If an
attacker presents a client-supplied `Mcp-Session-Id` on initial `initialize`,
it is **never adopted**; the SDK generates a fresh, opaque, server-controlled
session ID.
E. **Gateway Session Minting:** Upon successful `initialize` processing, ARC
creates the gateway session record and mints a 256-bit CSPRNG opaque session
token.
F. **Header Issuance:** The raw session token is returned **exactly once** in
the HTTP response header:

```http
Arc-Session-Token: <token>
```

The token is never echoed in the response body, never logged, and never stored
in raw form on the server.
G. **Subsequent Dual-Header Invariant:** Every subsequent `POST`, `GET`, or
`DELETE` request for that session requires **BOTH**:

```http
Mcp-Session-Id: <server-issued-id>
Authorization: Bearer <session-token>
```

H. **Mismatched Rejection:** If either header is missing, malformed, or does not
match the active session record and the presented TLS SPKI identity, the
request is rejected with generic `INVALID_SESSION_TOKEN` (or `UNAUTHENTICATED`
if pre-session) strictly before policy evaluation.
I. **Session Quotas:** Re-running tokenless `initialize` cannot mint unbounded
sessions; each issuance is accounted against the per-device (8), per-client
(64), and global (1024) session quotas (§11, §26).

### 5.4 Session ID Unification

To eliminate ambiguity across RC-04 approval binding and remote session tracking:

- **`actor.sessionId == Mcp-Session-Id`**.
- There is **NOT** a second independently generated actor session ID.
- The session token is a separate secret credential bound to that session ID.
- The server session record strictly binds:
  `(Mcp-Session-Id, deviceId, clientId, clientType, SPKI digest, token digest, created monotonic, last-auth monotonic, revocation state)`.
- The client necessarily echoes the server-issued `Mcp-Session-Id` HTTP header on
  all subsequent requests.
- The constraint "caller may not self-assert `sessionId`" means callers cannot
  supply `sessionId` in JSON-RPC request bodies, tool parameters, or invent
  unrecognized session IDs. Presenting a known `Mcp-Session-Id` without the
  matching session token and matching mTLS certificate identity grants nothing.

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
| **Bind semantics**              | Explicit host and port. **Default bind is loopback (`127.0.0.1`)**. A wildcard/`0.0.0.0`/`::` bind requires an explicit opt-in flag; selecting it without that flag is a startup failure (§18).                                                                       |
| **IPv4/IPv6**                   | The configured host is bound literally. `::` and `0.0.0.0` are treated as wildcard and gated identically. Dual-stack implicit binding is not used.                                                                                                                    |
| **Endpoint paths**              | Exactly `/mcp` and `/enroll/complete`. Any other path is `404` and MUST NOT reach policy or a subsystem.                                                                                                                                                              |
| **HTTP methods**                | `/mcp`: `POST` = client→server messages; `GET` = server→client SSE stream; `DELETE` = explicit session termination. `/enroll/complete`: `POST` only. Any other method is `405` with no processing.                                                                    |
| **MCP session identity**        | The `Mcp-Session-Id` header, **server-generated**, 256-bit random, opaque. Client-supplied ID on initial initialize is ignored/replaced.                                                                                                                              |
| **Invalid/unknown session ID**  | Rejected before any policy evaluation, with generic `INVALID_SESSION_TOKEN` that does not confirm whether the ID ever existed (§25).                                                                                                                                  |
| **Teardown**                    | `DELETE` closes the MCP session and revokes the gateway session bound to it. Socket close without `DELETE` closes the connection; the gateway session remains until idle/absolute expiry, and is re-usable only from the same authenticated TLS identity.             |

---

## 6. TLS Contract

| Rule | Normative statement                                                                                                                                                                                                                                                                                                                                                                                            |
| :--- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T-1  | **Minimum TLS version: 1.3. Maximum: 1.3.** TLS 1.2 and below are refused at handshake.                                                                                                                                                                                                                                                                                                                        |
| T-2  | **Plaintext HTTP is never accepted.** No listener, no upgrade, no fallback.                                                                                                                                                                                                                                                                                                                                    |
| T-3  | **TLS termination MUST occur inside the ARC process.** Delegated/reverse-proxy termination is **OUT OF SCOPE** for baseline RC-05 (§33).                                                                                                                                                                                                                                                                       |
| T-4  | If the TLS listener cannot start (missing/unreadable key or cert, key/cert mismatch, unsupported version), the **server fails to start**. It does not start without the listener and it does not fall back to plaintext.                                                                                                                                                                                       |
| T-5  | **Server certificate validation:** ARC startup verifies that its configured certificate is currently valid (not expired, not before valid) and that its Subject Alternative Name (SAN) matches the configured public hostname. ARC presents this certificate during TLS. Server-side code does not claim to prove client-side validation occurred; compliant client profiles must validate chain and hostname. |
| T-6  | Client certificate identity is the **SPKI digest** of the device certificate (§7).                                                                                                                                                                                                                                                                                                                             |
| T-7  | **Runtime server-cert expiry:** server certificate validity is verified at startup and re-checked before establishing each new TLS session. Once expired, new TLS handshakes are refused, health reports degraded gateway state (§19), and existing connections drain gracefully within connection TTL. Expired client certs are rejected at handshake.                                                        |
| T-8  | **Malformed certificate / unknown CA:** rejected during handshake, before any HTTP or MCP byte is parsed.                                                                                                                                                                                                                                                                                                      |
| T-9  | **Revocation (CRL/OCSP):** baseline RC-05 does **not** perform network revocation checking. Revocation is enforced by ARC's authoritative local device trust store (§8).                                                                                                                                                                                                                                       |
| T-10 | **Rotation:** server key/cert rotation is a restart-time operation (reload on restart). Device certificate rotation is handled by re-enrollment plus a pin overlap window (§7).                                                                                                                                                                                                                                |
| T-11 | **Client CA trust-root integrity:** configured client CA files must be regular files (`S_ISREG`), not symlinks, owned by the process UID or root, and not group/world writable (`mode & 0022 === 0`). Size capped at 64 KiB, max 4 roots. Empty CA set fails startup in remote mode.                                                                                                                           |

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

| Rule | Normative statement                                                                                                                                                                                                                                                                                                                                  |
| :--- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P-1  | **mTLS is mandatory.** A remote connection without a client certificate is rejected during handshake.                                                                                                                                                                                                                                                |
| P-2  | **Server trust** is established by the client validating the server certificate against its configured trust anchor and the configured hostname. Client validation compliance is verified in client profile test fixtures.                                                                                                                           |
| P-3  | **Client/device trust** requires **both**: (a) the certificate chains to a configured CA/trust root, **and** (b) its SPKI digest is pinned to an enrolled device. Failing either fails authentication.                                                                                                                                               |
| P-4  | **Pinned object: the certificate's SubjectPublicKeyInfo (SPKI) digest** — not the whole certificate. Pinning the SPKI survives certificate re-issuance with the same key and avoids pinning CA-specific encoding.                                                                                                                                    |
| P-5  | **Digest algorithm: SHA-256**, rendered as **64 lowercase hexadecimal characters**. `sha256(DER(SubjectPublicKeyInfo))`.                                                                                                                                                                                                                             |
| P-6  | **Mismatch behaviour:** authentication fails with a sanitized `UNAUTHENTICATED` (§25). The response MUST NOT reveal that a pin nearly matched, which pin failed, whether the device exists, or whether the presented certificate chains to a known CA.                                                                                               |
| P-7  | **Rotation:** a device record may hold **at most 2 active pins** (1 primary + 1 rotation overlap window). A pin is only ever added through the authenticated local operator path (§9). The overlap window is operator-controlled and MUST be explicitly closed by removing the old pin; an unused pin never expires silently into a "no pins" state. |
| P-8  | **Malformed pin configuration** (wrong length, non-hex, duplicates that collapse) is a **startup failure** (§18). Empty pin sets for an enrolled device are invalid.                                                                                                                                                                                 |

---

## 8. Device Identity Model

| Field / rule                       | Normative statement                                                                                                                                                                                                                                 |
| :--------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`deviceId` format**              | **32 lowercase hexadecimal characters** (16 random bytes). Fixed length, no separators, no caller-supplied form.                                                                                                                                    |
| **Generation authority**           | **ARC generates `deviceId`** at enrollment. A client never proposes, supplies, or influences it.                                                                                                                                                    |
| **Cryptographic binding**          | A device record binds `deviceId` ↔ enrolled pin(s) (§7). Neither half is meaningful without the other: knowing a `deviceId` grants nothing, and a valid client certificate that is not enrolled is rejected.                                        |
| **`clientId` vs `deviceId`**       | **Distinct.** `clientId` is the logical client identity (which agent/tool integration); `deviceId` is the physical enrolled credential holder.                                                                                                      |
| **Multiplicity**                   | One `clientId` **may** have multiple `deviceId`s. One `deviceId` belongs to **exactly one** `clientId`.                                                                                                                                             |
| **Resource caps**                  | Max enrolled devices: **256**. Max active pins per device: **2**. Max display label: **64 UTF-8 bytes**. Max serialized trust store size: **256 KiB**. Exceeding any cap rejects enrollment closed with `RESOURCE_EXHAUSTED`.                       |
| **Duplicate enrollment**           | Enrolling a certificate whose pin already exists **reuses the existing `deviceId`** and does not create a second record. If it is bound to a different `clientId`, enrollment is **rejected**.                                                      |
| **Disabled/revoked**               | A revoked device fails authentication on the **next** request with generic `UNAUTHENTICATED` (pre-session) or `INVALID_SESSION_TOKEN` (existing session), and live sessions are revoked immediately (§11). Client never sees `DEVICE_NOT_ENROLLED`. |
| **Persisted metadata**             | `deviceId`, `clientId`, `clientType`, pin set (max 2), enrollment timestamp, operator display label (max 64 bytes), revocation state.                                                                                                               |
| **Never trusted from caller JSON** | `deviceId`, `clientId`, `clientType`, `sessionId`, pin values, revocation state, enrollment time. These are **always** derived server-side from the authenticated connection (§13).                                                                 |
| **Impersonation bar**              | A remote client **cannot** choose an arbitrary `deviceId`, present another device's `deviceId`, or assert another `clientId`. Any request carrying such a field in JSON-RPC is refused at schema admission (§13, §27).                              |

---

## 9. Enrollment Bootstrap

**Decision: enrollment is operator-mediated over the existing local
authenticated admin channel. Remote completion occurs strictly over a dedicated
bootstrap endpoint for pending records. There is NO remote self-enrollment.**

### 9.1 Enrollment Completion Path (`POST /enroll/complete`)

To resolve the enrollment bootstrap deadlock without bypassing authentication:

1. **Local Initiation:** The authenticated local operator creates a pending
   enrollment via the local admin IPC (Unix socket). The pending record records
   the expected `clientId`, `clientType`, expected SPKI pin, a high-entropy
   256-bit one-time enrollment secret (64 hex characters), and monotonic expiry.
2. **Completion Endpoint:** Remote completion is exposed strictly on
   `POST /enroll/complete`.
   - **Bootstrap only:** This is an ARC gateway bootstrap endpoint, NOT an MCP
     endpoint and NOT an MCP tool.
   - **Pre-session isolation:** It does NOT create an MCP session, does NOT issue
     an `Arc-Session-Token`, and does NOT reach policy or subsystems.
   - **mTLS Requirement:** The client connects over TLS 1.3 mTLS. The client
     certificate MUST chain to the configured client trust root.
   - **Proof of Possession:** The presented certificate's SPKI digest MUST
     exactly match the pending enrollment's expected SPKI pin. This proves
     private-key possession via successful TLS 1.3 handshake.
   - **Secret Verification:** The client transmits the one-time secret in the
     JSON request body: `{"secret": "<64-hex-secret>"}` (bounded ≤ 4 KiB).
     Comparison is constant-time (`timingSafeEqual`).
   - **Atomic Single-Use Activation:** Upon match, the pending record is
     consumed and the enrolled device record is atomically committed to the
     persistent trust store (§16). ARC returns HTTP `200 OK`.
   - **Post-Enrollment Normal Authentication:** The device must then authenticate
     normally on `/mcp` via mTLS and tokenless `initialize` (§5.3).
   - **Failure Paths:** Mismatched secret, mismatched SPKI, or expired challenge
     fails closed with HTTP 400/404; trust store state is completely unchanged.

### 9.2 Frozen Enrollment Numeric Bounds

All numeric bounds are concrete, testable constants:

| Metric                                                     | Frozen value          | Rationale and enforcement                                                                    |
| :--------------------------------------------------------- | :-------------------- | :------------------------------------------------------------------------------------------- |
| **Enrollment challenge TTL**                               | **300 s** (5 minutes) | Enforced via monotonic clock (`process.hrtime.bigint()`). Expiration never extends on retry. |
| **Maximum pending enrollments (global)**                   | **16**                | Bounded memory; prevents operator IPC pending table exhaustion. Fails closed with error.     |
| **Maximum pending enrollments per authenticated operator** | **4**                 | Per-operator fairness and DoS isolation.                                                     |
| **Maximum failed secret attempts per challenge**           | **3** attempts        | Immediate challenge invalidation and purge on 3rd failure; prevents online secret guessing.  |
| **Maximum enrolled devices**                               | **256** devices       | Hard cap on persistent device trust store; prevents unbounded trust store growth.            |
| **Maximum active pins per device**                         | **2** pins            | Exactly 1 primary pin + 1 rotation overlap pin. Third pin rejected.                          |
| **Maximum display label size**                             | **64 UTF-8 bytes**    | Bounded operator metadata string; non-security display only.                                 |
| **Maximum serialized trust-store size**                    | **256 KiB**           | Hard file size ceiling on disk; checked before and during parse at startup (§16).            |

| Rule | Normative statement                                                                                                                                                                                                                                      |
| :--- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| E-1  | **Who may enroll:** only the authenticated local operator, through the RC-04 admin IPC channel (Ed25519 challenge–response over a Unix socket).                                                                                                          |
| E-2  | **Trusted authorising channel:** the local admin IPC. The remote gateway is **never** an enrollment authority.                                                                                                                                           |
| E-3  | **Local-operator initiated:** yes. The operator creates a pending enrollment; the device then completes it.                                                                                                                                              |
| E-4  | **Proof of possession:** device proves private key possession by completing mTLS with the pending SPKI certificate and presenting the one-time secret on `POST /enroll/complete`. A certificate presented without its private key can never be enrolled. |
| E-5  | **Challenge lifetime:** 300 s monotonic TTL. Unconsumed enrollments are purged at expiry. Expiration never extends on inspection or retry.                                                                                                               |
| E-6  | **One-time / replay:** an enrollment secret is single-use. Replay attempts fail and MUST NOT mint a second device or mutate state.                                                                                                                       |
| E-7  | **Pending quotas:** max 16 global, max 4 per operator. Exceeding quotas fails closed without mutating state.                                                                                                                                             |
| E-8  | **Cancellation / rejection:** operator may cancel pending enrollment; secret becomes unusable immediately.                                                                                                                                               |
| E-9  | **Duplicate enrollment:** per §8 — same pin ⇒ same `deviceId`, no duplicate record; pin already bound to another `clientId` ⇒ rejected.                                                                                                                  |
| E-10 | **Credential issuance/import:** ARC **does not** generate or export device private keys. The operator supplies a public key/pin; the private key never enters ARC.                                                                                       |
| E-11 | **Failure/restart:** pending enrollments are volatile and purged on restart (§16). **Completed enrollments survive restart** via atomic trust store persistence.                                                                                         |
| E-12 | **Failed attempt lockout:** maximum 3 failed secret submissions per challenge before immediate challenge purging.                                                                                                                                        |

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
bound to the device's TLS identity and unified with `Mcp-Session-Id`.**

| Property                       | Frozen value                                                                                                                                                                            |
| :----------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Form**                       | **Opaque** (no client-readable claims). Not a JWT; no structured payload.                                                                                                               |
| **Generation**                 | CSPRNG (`crypto.randomBytes`), **256 bits**.                                                                                                                                            |
| **Encoding**                   | **64 lowercase hexadecimal characters**.                                                                                                                                                |
| **Maximum input byte length**  | **128 bytes** for the presented token value (bound checked before decoding).                                                                                                            |
| **Server-side representation** | **SHA-256 digest only.** The raw token is never stored, never re-derivable, and never compared in raw form.                                                                             |
| **Raw-token issuance**         | Returned **exactly once** in `Arc-Session-Token: <token>` response header upon initial tokenless `initialize`. Never in body, logs, audit, or error.                                    |
| **Verification**               | `timingSafeEqual` over the 32-byte digests. Constant-time.                                                                                                                              |
| **Binding**                    | Bound to `(Mcp-Session-Id, deviceId, SPKI digest, clientId)`. **A token presented from a different device's TLS identity is rejected.** Stolen tokens are **not** portable.             |
| **TTL (absolute)**             | **3600 s**, enforced on a **monotonic** clock (`process.hrtime.bigint()`); wall clock is display-only and cannot extend it.                                                             |
| **Idle timeout**               | **300 s** monotonic since last authenticated request.                                                                                                                                   |
| **Issue time**                 | Recorded mono + wall (wall for display/audit only).                                                                                                                                     |
| **Expiration**                 | On absolute or idle expiry the session is revoked; the next request is rejected with generic `INVALID_SESSION_TOKEN`.                                                                   |
| **Rotation**                   | **No per-request rotation.** Rotation occurs only by re-authentication. Per-request rotation was rejected because it introduces a concurrent-request race with no baseline requirement. |
| **Revocation**                 | Explicit (operator, `DELETE`, device revocation, restart). Revocation is immediate and irreversible for that session.                                                                   |
| **Replay after revocation**    | Rejected with generic `INVALID_SESSION_TOKEN`. Expiry/revocation checked before identity is derived; revoked session never reaches policy.                                              |
| **Concurrent use**             | A token may be used concurrently **within** the per-session concurrency cap (§26). Concurrent use from a different TLS identity is rejected by the binding.                             |
| **Maximum active sessions**    | Per device: **8**. Per client: **64**. Global: **1024**. Exceeding any bound fails the new session closed; existing sessions are unaffected.                                            |
| **Restart behaviour**          | **All sessions are volatile.** A restart revokes every session token.                                                                                                                   |
| **Leakage controls**           | Never in logs, audit records, error bodies, health output, or metrics. Redaction is central, not caller-dependent.                                                                      |

**Domain separation from RC-04:** session tokens travel in the `Authorization`
header over the remote transport and are **a different class** from RC-04
approval tokens (§28). Neither is accepted in the other's position.

---

## 12. Authentication Sequence

Exact order of evaluation for remote operations:

```text
1. Layer A — TCP/TLS connection admission (peer IP, connection cap, handshake cap)
2. TLS 1.3 handshake (client cert verified against configured CA trust root)
3. Layer B — Secure HTTP pre-session rate limiting (peer IP, max 120 req/min)
4. Endpoint router:
     IF POST /enroll/complete:
       → Verify pending enrollment by expected SPKI
       → Verify one-time secret (constant-time)
       → Atomically commit enrolled device to trust store
       → Return HTTP 200 OK (terminate connection, no MCP session created)
     IF /mcp:
       → SPKI digest extracted from TLS client cert
       → Enrolled device lookup (mismatch ⇒ generic UNAUTHENTICATED)
       → Session authentication:
           IF tokenless initialize:
             → Mint gateway session record & Mcp-Session-Id
             → Return Arc-Session-Token header in response
           IF ordinary request:
             → Require BOTH Mcp-Session-Id AND Authorization: Bearer <token>
             → Verify session digest, SPKI binding, TTL, revocation
             → Mismatch/expired ⇒ generic INVALID_SESSION_TOKEN
5. Layer C — Authenticated session/device rate limiting (max 300 req/min)
6. Derive trusted actor context (clientId, clientType, deviceId, sessionId)
7. Dispatch to shared RC-04 pipeline (schema → workspace → Layer 1 → Layer 2 → approval → audit → subsystem)
```

| Check                                                        | Frequency                            | Refusal result                  |
| :----------------------------------------------------------- | :----------------------------------- | :------------------------------ |
| Layer A: TCP/TLS admission                                   | Once per connection                  | TCP drop / close                |
| TLS 1.3 + CA chain validation                                | Once per connection                  | TLS alert / handshake close     |
| Layer B: Pre-session HTTP limiter                            | Every HTTP request                   | HTTP 429 Too Many Requests      |
| Enrolled device lookup                                       | Once per connection / session init   | generic `UNAUTHENTICATED`       |
| Session token validity (digest, expiry, revocation, binding) | **Every request**                    | generic `INVALID_SESSION_TOKEN` |
| Layer C: Authenticated limiter                               | **Every request**                    | MCP `RATE_LIMIT_EXCEEDED`       |
| Actor context derivation                                     | **Every request**                    | Internal server-side            |
| Policy / approval / subsystem                                | Every request (unchanged from RC-04) | `POLICY_DENIED` etc.            |

Steps 1–3 happen before any MCP byte is parsed. Step 4 ensures revoked devices
or sessions are rejected on every single request. **No request that can reach
policy or a subsystem may skip steps 1–6.**

---

## 13. Actor Context Binding into RC-04

RC-04 binds approvals to `(clientId, clientType, sessionId, deviceId)` and folds
that actor into `executionPayloadHash`. RC-05 defines each field's origin
precisely:

| RC-04 actor field | RC-05 source                                                                                                                                                           |
| :---------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `clientId`        | From the **enrolled device record**, resolved from the authenticated TLS identity. Caller-supplied values are ignored and any attempt to supply one is a schema error. |
| `clientType`      | From the **enrolled device record** (operator-set at enrollment). Never caller-supplied.                                                                               |
| `deviceId`        | From the **enrolled device record** (§8), resolved from the presented certificate's pin.                                                                               |
| `sessionId`       | **Unified with `Mcp-Session-Id`** (§5.4). Server-generated, 256-bit random, opaque. Lifetime = session lifetime (§11). Never caller-asserted.                          |

- These four values are computed **server-side, after** steps 1–5 of §12, and
  are the **only** values passed into `SecurityKernel`,
  `DeclarativePolicyEngine`, and the `executionPayloadHash` computation.
- **Remote request parameters MUST NOT override these trusted fields.** A request
  carrying `clientId`, `clientType`, `deviceId`, or `sessionId` in JSON-RPC
  params is refused at schema admission (§27) and nothing is executed.
- `sessionId` participates in approval binding exactly as it does for stdio
  today; because RC-05 sessions expire, an approval requested under a session
  that has since ended cannot be redeemed from a different session (§28).

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

### 16.1 Security-Critical Trust Store Integrity

The enrolled-device trust store (`devices.json`) is an authentication root. Its
integrity requirements are enforced strictly:

1. **Regular File Only:** The trust-store path MUST be a regular file (`S_ISREG`).
   Symlinks are **strictly rejected** via `O_NOFOLLOW` / `lstat` checks.
2. **File Ownership:** Must be owned by the ARC process UID (`stat.uid === process.getuid()`).
3. **Strict Permissions:** Permissions must be mode `0600` (`mode & 0077 === 0`).
   Any group or world readable/writable trust store is a **startup failure**.
4. **Parent Directory Integrity:** Parent directory must be owned by the process
   UID or root, and must not be world-writable (`mode & 0022 === 0`). Path
   traversal sequences (`..`) or ambiguous paths are rejected.
5. **Bounded File Size:** Total serialized file size on disk MUST NOT exceed
   **256 KiB**. Exceeding 256 KiB fails startup or enrollment.
6. **Strict Closed Schema:** Parsing is strict JSON. Unknown fields, malformed
   data, non-hex pins, duplicate device IDs, or duplicate pins are rejected as
   corruption and trigger **startup failure**.
7. **Atomic Persistence Protocol:**
   - Serialize device records to a temporary file in the same directory (`.devices.json.tmp.<pid>.<timestamp>`).
   - Flush bytes and sync to disk via `fsync(fd)`.
   - Atomically rename the temporary file over the trust store path via `rename(2)`.
   - `fsync` the containing parent directory after rename where supported by the OS.
8. **Fail-Closed Write Contract:** If any write or sync step fails, the operation
   MUST NOT report success to the operator. Trust store updates fail closed;
   partial or corrupt updates leave the pre-existing trust state intact.

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
| K-11 | **Client CA file integrity:** Configured client CA files must be regular files (`S_ISREG`), not symlinks, owned by process UID or root, and not group/world writable (`mode & 0022 === 0`). Size ≤ 64 KiB, max 4 roots. Empty set fails startup in remote mode.                                                                 |

---

## 18. Startup Configuration Validation

Every condition below causes an **explicit startup failure**. There is **no
silent insecure fallback** in any row, and no row degrades to "remote listener
disabled but server running" unless stated.

| Condition                                                   | Result              |
| :---------------------------------------------------------- | :------------------ |
| `transport: 'remote'` without TLS configuration             | **Startup failure** |
| Server certificate without a private key                    | **Startup failure** |
| Private key without a certificate                           | **Startup failure** |
| Key/cert mismatch                                           | **Startup failure** |
| Server certificate expired or not yet valid                 | **Startup failure** |
| Server certificate SAN does not match configured hostname   | **Startup failure** |
| Client CA file is missing, symlink, or group/world-writable | **Startup failure** |
| Client CA file exceeds 64 KiB or contains unparseable PEM   | **Startup failure** |
| Empty client CA / trust-root set in remote mode             | **Startup failure** |
| Trust store path is a symlink or group/world-writable       | **Startup failure** |
| Trust store owned by wrong UID (not process UID)            | **Startup failure** |
| Trust store exceeds 256 KiB on disk                         | **Startup failure** |
| Malformed pin (length/charset/duplicate)                    | **Startup failure** |
| Corrupt / invalid / unparseable device trust store          | **Startup failure** |
| Unsupported TLS version configured                          | **Startup failure** |
| Invalid listener port or address                            | **Startup failure** |
| Remote mode with authentication disabled                    | **Startup failure** |
| Wildcard bind without explicit opt-in flag                  | **Startup failure** |
| Two enrolled devices sharing one pin                        | **Startup failure** |
| Enrolled device count exceeding 256 in trust store          | **Startup failure** |
| Device record holding more than 2 active pins               | **Startup failure** |

**Zero-device startup exception:** An empty trust store (`enrolledDevicesCount: 0`)
is **explicitly permitted** at startup provided the store file itself is valid,
properly secured (mode 0600, process UID, regular file), server TLS configuration
is valid, and client CA roots are configured. This enables bootstrapping the first
device via `POST /enroll/complete` (§5.2, §9).

---

## 19. Health / Status Model

Additional truthful fields (§24 covers what must **not** appear):

| Field                  | Type    | Meaning                                                          |
| :--------------------- | :------ | :--------------------------------------------------------------- |
| `transportMode`        | string  | `'stdio'` or `'remote'` — the single active mode (§4).           |
| `remoteGatewayActive`  | boolean | True iff the remote listener is bound and serving.               |
| `authenticationActive` | boolean | True iff mTLS + enrollment + session enforcement are all active. |
| `enrolledDevicesCount` | number  | Count of non-revoked enrolled devices (0 is valid at startup).   |
| `activeSessionsCount`  | number  | Current live sessions.                                           |
| `degradedReason`       | string  | Optional diagnostic reason (e.g. `'certificate_expired'`).       |

**Runtime cert expiry health degradation:** If the server certificate expires
at runtime (§6 T-7), `remoteGatewayActive` and `authenticationActive` become
`false`, and `degradedReason` reports `'certificate_expired'`.

**Must not be exposed:** certificate material, private key paths, tokens, pins,
trust-store paths, host topology, listener address, or remote peer addresses.
Counts are safe; material is not.

---

## 20. Message Size and Request Bounds

| Bound                       | Frozen value                                                                                                                                                                                                      |
| :-------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Maximum message body**    | **4 MiB = 4,194,304 bytes.** Measured on **raw request body bytes as received**.                                                                                                                                  |
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

---

## 21. Rate Limiting

**Three explicit admission layers with independent keys and boundaries, because
cryptography and HTTP parsing must be protected before they execute.**

```text
INCOMING TCP CONNECTION
  │
  ▼
[ Layer A: TCP/TLS Admission Limiter ]
  • Key: Normalized Peer IP
  • 60 conn/min (burst 20) | Max 32 conn/IP | Max 512 global conn | Max 64 handshakes
  • Refusal: Immediate TCP reset / connection drop (NO HTTP/MCP body)
  │
  ▼ (TLS 1.3 mTLS Handshake completes)
  │
[ Layer B: Secure HTTP Pre-Session Limiter ]
  • Key: Normalized Peer IP
  • 120 req/min (burst 30)
  • Refusal: HTTP 429 Too Many Requests (sanitized plaintext, NO MCP body)
  │
  ▼ (Session authenticated: deviceId & Mcp-Session-Id derived)
  │
[ Layer C: Authenticated Session/Device Limiter ]
  • Key: Server-derived deviceId / sessionId
  • 300 req/min (burst 60)
  • Refusal: MCP JSON-RPC Error: RATE_LIMIT_EXCEEDED
```

### 21.1 Three Admission Layers

1. **Layer A — TCP/TLS admission:**
   - Runs before and during TLS handshake.
   - Keyed on normalized peer network identity.
   - Max 60 connection attempts / min (burst 20).
   - Max 32 concurrent live connections per peer IP.
   - Max 512 concurrent live connections globally.
   - Max 64 concurrent in-flight TLS handshakes.
   - Refusal action: Drop connection / abort socket immediately. No HTTP or MCP
     body is possible or required here. Protects TLS CPU budget.
2. **Layer B — Secure HTTP pre-session admission:**
   - Runs after successful TLS handshake, before session-token lookup, MCP
     JSON-RPC parsing, policy evaluation, or subsystem invocation.
   - Keyed on normalized peer network identity.
   - Max 120 HTTP requests / min (burst 30).
   - Refusal action: HTTP 429 Too Many Requests with sanitized headers and no
     MCP JSON-RPC body. Protects JSON parsing and token verifier budget.
3. **Layer C — Authenticated session/device admission:**
   - Runs after identity and session credentials are authenticated.
   - Keyed on server-derived `deviceId` and `sessionId`.
   - Max 300 MCP requests / min (burst 60).
   - Refusal action: MCP JSON-RPC error with `RATE_LIMIT_EXCEEDED`.

### 21.2 Rate Limiter Memory Bounds

Limiter memory is strictly bounded against source-IP churn attacks:

| Limiter Layer | Maximum Retained Keys | Entry Representation              | Idle Eviction Timeout | Capacity Saturation Behavior                                               |
| :------------ | :-------------------- | :-------------------------------- | :-------------------- | :------------------------------------------------------------------------- |
| **Layer A**   | **4096** keys         | Compact fixed-size struct (~64 B) | **60 s** monotonic    | LRU eviction of expired keys; if full, fail-closed (reject connection)     |
| **Layer B**   | **2048** keys         | Compact fixed-size struct (~64 B) | **60 s** monotonic    | LRU eviction of expired keys; if full, fail-closed (HTTP 429)              |
| **Layer C**   | **1024** keys         | Compact fixed-size struct (~64 B) | **60 s** monotonic    | LRU eviction of expired keys; if full, fail-closed (`RATE_LIMIT_EXCEEDED`) |

Under source-key churn, limiter memory cannot grow beyond the key ceiling.
At capacity, untracked new keys fail closed without allocating memory.

### 21.3 Peer IP Normalization

Peer network identity is normalized deterministically:

- **IPv4:** Canonical dotted-quad representation (e.g. `192.0.2.1`).
- **IPv4-Mapped IPv6:** Unmapped to canonical IPv4 (`::ffff:192.0.2.1` → `192.0.2.1`).
  An attacker cannot bypass IPv4 limits by presenting an IPv4-mapped IPv6 address.
- **IPv6 Grouping:** Grouped by canonical lowercase zero-compressed **/64 CIDR
  prefix** (e.g. `2001:db8:abcd:0012::/64`). An attacker rotating interface
  identifiers within the same `/64` subnet shares one bucket.

---

## 22. Network Attack Surface

Frozen controls, by attack:

| Attack                               | Control                                                                                                                       |
| :----------------------------------- | :---------------------------------------------------------------------------------------------------------------------------- |
| Unauthenticated connection flood     | Layer A TCP admission limiter (§21) + global/per-IP connection caps; connection dropped before TLS.                           |
| TLS handshake flood                  | 5 s handshake timeout + max 64 concurrent handshakes (§20, §21).                                                              |
| HTTP pre-session flood               | Layer B secure HTTP limiter (120 req/min); returns HTTP 429 before MCP parsing (§21).                                         |
| Limiter-key churn memory exhaustion  | Hard key ceilings (4096 / 2048 / 1024), 60 s idle eviction, LRU fail-closed at capacity (§21.2).                              |
| IP normalization bypass              | IPv4-mapped IPv6 unmapped; IPv6 grouped under `/64` CIDR prefix (§21.3).                                                      |
| Slowloris / partial body             | 10 s body read timeout, 60 s request timeout, header/URL bounds (§20).                                                        |
| Oversized payload                    | 4 MiB enforced during read; connection aborted (§20).                                                                         |
| Malformed JSON-RPC                   | Rejected by schema admission; no policy reached.                                                                              |
| Malformed MCP session ID             | Rejected before identity derivation; sanitized generic response (§5, §25).                                                    |
| Header abuse                         | 16 KiB header bound; `Host`/`X-Forwarded-*` never establish identity (§6.1).                                                  |
| Request smuggling assumptions        | Single explicit HTTP parser path via SDK transport; `Content-Length`/`Transfer-Encoding` ambiguity is rejected.               |
| Credential stuffing / token guessing | 256-bit tokens; constant-time digest comparison; pre-auth rate limiting; anti-oracle responses.                               |
| Session fixation                     | Session IDs and tokens are **server-generated only**; client-supplied value is never adopted (§5.3).                          |
| Session hijacking                    | Token bound to `(deviceId, SPKI, clientId)`; token unusable from another TLS identity (§11).                                  |
| Token replay                         | Idle/absolute expiry + explicit revocation; replay after revocation rejected.                                                 |
| Cross-device token replay            | Binding check fails; generic `INVALID_SESSION_TOKEN` returned (§11, §25).                                                     |
| Certificate replay/cloning           | Cloning requires the private key; a cloned certificate without the key fails the handshake.                                   |
| Expired certificate                  | Rejected at handshake (§6 T-7); runtime server cert expiry refuses new sessions.                                              |
| Revoked device                       | Live sessions revoked immediately; subsequent requests return generic `UNAUTHENTICATED` or `INVALID_SESSION_TOKEN` (§8, §25). |
| Enrollment replay                    | Single-use secrets on `POST /enroll/complete` (§9).                                                                           |
| Enrollment challenge lockout         | 3 failed secret attempts immediately purges challenge (§9).                                                                   |
| First-device bootstrap bypass        | `/mcp` rejects all sessions when zero devices are enrolled; only valid `/enroll/complete` accepted (§5.2).                    |
| Attacker-writable trust store / CA   | Mode 0600 (trust store), mode 0644/root (CA), UID checks, no symlinks, atomic write with fsync (§6 T-11, §16).                |
| Wildcard bind exposure               | Explicit opt-in flag required, else startup failure (§18).                                                                    |
| Proxy/header spoofing                | No proxy header establishes identity; in-process TLS only (§6.1).                                                             |
| DNS rebinding / browser-origin       | Origin allowlist default-deny; `Host` validated against configured hostname (§23).                                            |
| Abrupt disconnect during execution   | In-flight work completes or aborts per RC-04 semantics; audit records disconnect.                                             |

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

**Never audited:** raw session tokens, enrollment secrets, private keys,
certificate private material, `Authorization` or `Arc-Session-Token` header values,
cookies/session secrets, raw credentials, or full attacker-supplied certificate blobs.

The chain, sequencing, redaction, and integrity behaviour are **unchanged from
RC-04**. RC-06 owns external persistence and anchoring.

---

## 25. Client-Facing Error Model

### 25.1 Anti-Oracle Error Model

To eliminate enumeration oracles:

1. **Pre-Session Indistinguishability:** Before an authenticated gateway session
   exists, **all application-level device authentication failures return strictly**:
   ```json
   { "code": "UNAUTHENTICATED", "message": "Authentication failed" }
   ```
   This rule covers:
   - Certificate not enrolled in trust store.
   - Known device has been revoked.
   - Pin matches but `clientId` binding differs.
   - Enrollment challenge absent or expired.
   - Zero devices enrolled in trust store.
     The error code `DEVICE_NOT_ENROLLED` is strictly an **internal diagnostic and
     operator audit reason**; ordinary remote clients **NEVER** receive it.
2. **Post-Session Indistinguishability:** After a session previously existed, any
   session lookup, expiration, revocation, token digest mismatch, or binding
   mismatch returns strictly:
   ```json
   { "code": "INVALID_SESSION_TOKEN", "message": "Invalid or expired session token" }
   ```
   The client receives no information on whether expiry, revocation, or a bad
   token caused the failure.
3. **Transport/Admission Responses:** Failures occurring before application
   evaluation are returned at the HTTP/TCP layer with no MCP JSON-RPC body:
   - Layer A TCP refusal: Connection dropped / reset.
   - Layer B HTTP pre-session rate limit: HTTP 429 Too Many Requests.
   - Non-configured path: HTTP 404 Not Found.
   - Invalid HTTP method: HTTP 405 Method Not Allowed.
   - Payload > 4 MiB: HTTP 413 Payload Too Large.

| Situation                         | Protocol Layer                   | Observable Error Code          | Response Framing      |
| :-------------------------------- | :------------------------------- | :----------------------------- | :-------------------- |
| Layer A TCP connection refused    | Network                          | None (TCP close/reset)         | No HTTP response      |
| TLS handshake rejection           | TLS                              | TLS alert                      | No HTTP response      |
| Layer B HTTP pre-session limit    | HTTP                             | HTTP 429 Too Many Requests     | Plaintext HTTP        |
| Device not enrolled / revoked     | Auth (pre-session)               | `UNAUTHENTICATED`              | MCP JSON-RPC Error    |
| Pin mismatch / binding mismatch   | Auth (pre-session)               | `UNAUTHENTICATED`              | MCP JSON-RPC Error    |
| Session expired/revoked/malformed | Session (post-session)           | `INVALID_SESSION_TOKEN`        | MCP JSON-RPC Error    |
| Layer C Authenticated rate limit  | Rate Limiting                    | `RATE_LIMIT_EXCEEDED`          | MCP JSON-RPC Error    |
| Oversized request body (> 4 MiB)  | Bounds                           | `PAYLOAD_TOO_LARGE` / HTTP 413 | HTTP 413 or MCP Error |
| Authorization denial              | Authorization (RC-04, unchanged) | `POLICY_DENIED` etc.           | MCP JSON-RPC Error    |

---

## 26. Session and Connection Concurrency

| Rule | Bound / behaviour                                                                                                                                             |
| :--- | :------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| C-1  | Max **512** simultaneous connections globally; max **32** per peer IP; max **64** in-flight handshakes.                                                       |
| C-2  | Max **8** live sessions per device; **64** per client; **1024** globally.                                                                                     |
| C-3  | Max **4** outstanding MCP requests per session.                                                                                                               |
| C-4  | **Duplicate session ID:** a request presenting a session ID with a mismatched identity is rejected, not adopted.                                              |
| C-5  | **Connection takeover:** not supported. A new connection authenticates as the same device but does not inherit another connection's session state.            |
| C-6  | **Concurrent use of one session token** is permitted within C-3 only.                                                                                         |
| C-7  | **Backpressure:** exceeding any bound produces a sanitized refusal; the gateway never queues unbounded work.                                                  |
| C-8  | **Shutdown/drain:** on shutdown the listener stops accepting, in-flight requests get a bounded grace period, then connections close and sessions are revoked. |

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

---

## 31. Dependency Policy

| Candidate dependency                                                | Verdict                                                                                                             |
| :------------------------------------------------------------------ | :------------------------------------------------------------------------------------------------------------------ |
| Node built-ins (`node:tls`, `node:net`, `node:http`, `node:crypto`) | **Sufficient and preferred** for TLS, mTLS, binding, pinning, CSPRNG, timing-safe comparison, and the rate limiter. |
| `@modelcontextprotocol/sdk` `StreamableHTTPServerTransport`         | **Already a dependency.** Provides the MCP Streamable HTTP transport.                                               |
| X.509 parsing for SPKI extraction                                   | **Prefer Node built-ins** (`crypto.X509Certificate.publicKey` → DER SPKI), avoiding a new parsing dependency.       |
| Rate limiting library                                               | **Not proposed.** Fixed-memory sliding window is small, testable, and avoids a supply-chain addition.               |
| JWT/JOSE library                                                    | **Not proposed.** Session tokens are opaque and opaque tokens need no JOSE.                                         |
| OAuth/OIDC/SAML libraries                                           | **Not proposed.** Those capabilities are deferred (§10).                                                            |

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
- Slack/Teams/mobile approval integration.
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

`N = 79`. Every material invariant in this scope has at least one direct,
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

### TLS & CA Integrity (RC05-NEG-07 … 15)

| ID          | Attack / input                                 | Expected result          | Critical no-side-effect                    |
| :---------- | :--------------------------------------------- | :----------------------- | :----------------------------------------- |
| RC05-NEG-07 | TLS 1.2 handshake attempt                      | Handshake refused        | No MCP bytes parsed                        |
| RC05-NEG-08 | Connection with no client certificate          | Handshake refused        | No device lookup; no session               |
| RC05-NEG-09 | Client certificate from an unknown CA          | Handshake refused        | Trust store not mutated                    |
| RC05-NEG-10 | Expired client certificate                     | Handshake refused        | No session minted                          |
| RC05-NEG-11 | Malformed certificate                          | Handshake refused        | No MCP parse                               |
| RC05-NEG-12 | Server cert/key mismatch at startup            | **Startup failure**      | No listener bound                          |
| RC05-NEG-13 | Server certificate expired at startup          | **Startup failure**      | No listener bound                          |
| RC05-NEG-14 | Server certificate SAN does not match hostname | **Startup failure**      | No listener bound                          |
| RC05-NEG-15 | Server certificate expires during runtime      | New TLS sessions refused | Health degraded; existing drain gracefully |

### mTLS, Pinning & Device Resource Bounds (RC05-NEG-16 … 22)

| ID          | Attack / input                                         | Expected result                  | Critical no-side-effect                     |
| :---------- | :----------------------------------------------------- | :------------------------------- | :------------------------------------------ |
| RC05-NEG-16 | Valid chain, but SPKI not pinned to any device         | `UNAUTHENTICATED`                | Policy engine not reached; no device oracle |
| RC05-NEG-17 | Pin rotated: old pin inside window, then after removal | Accepted, then `UNAUTHENTICATED` | No lingering acceptance after removal       |
| RC05-NEG-18 | Malformed pin configuration at startup                 | **Startup failure**              | No listener bound                           |
| RC05-NEG-19 | Two devices sharing one pin at startup                 | **Startup failure**              | No listener bound                           |
| RC05-NEG-20 | Device enrollment adding a 3rd active pin              | `RESOURCE_EXHAUSTED`             | Max 2 pins enforced; existing pins retained |
| RC05-NEG-21 | Enrolling device beyond 256 global device limit        | `RESOURCE_EXHAUSTED`             | Trust store unchanged; capacity bounded     |
| RC05-NEG-22 | Enrollment request with display label > 64 bytes       | `INVALID_REQUEST_SCHEMA`         | Trust store unchanged                       |

### Trust Store & CA File Integrity (RC05-NEG-23 … 28)

| ID          | Attack / input                                      | Expected result        | Critical no-side-effect                     |
| :---------- | :-------------------------------------------------- | :--------------------- | :------------------------------------------ |
| RC05-NEG-23 | Trust-store file is a symlink                       | **Startup failure**    | Symlink rejected; no listener bound         |
| RC05-NEG-24 | Trust store is group/world writable (`mode & 0077`) | **Startup failure**    | Insecure mode rejected; no listener bound   |
| RC05-NEG-25 | Trust store owned by wrong UID (not process UID)    | **Startup failure**    | Untrusted owner rejected; no listener bound |
| RC05-NEG-26 | Trust store file corrupted or exceeds 256 KiB       | **Startup failure**    | Fails closed; corrupt state rejected        |
| RC05-NEG-27 | Atomic write failure during trust store update      | Operation fails closed | No partial write; trust state preserved     |
| RC05-NEG-28 | Client CA file is symlink or group/world writable   | **Startup failure**    | Insecure CA rejected; no listener bound     |

### Enrollment Bootstrap & Quotas (RC05-NEG-29 … 38)

| ID          | Attack / input                                          | Expected result                    | Critical no-side-effect                      |
| :---------- | :------------------------------------------------------ | :--------------------------------- | :------------------------------------------- |
| RC05-NEG-29 | Remote self-enrollment attempt on `/mcp`                | Rejected (`404`/`UNAUTHENTICATED`) | No device enrolled; policy not reached       |
| RC05-NEG-30 | `POST /enroll/complete` without client cert mTLS        | Handshake refused                  | Endpoint unreachable without mTLS            |
| RC05-NEG-31 | `POST /enroll/complete` with no matching pending record | HTTP 400/404                       | No device enrolled; trust store unchanged    |
| RC05-NEG-32 | `POST /enroll/complete` with mismatched SPKI pin        | HTTP 400                           | Proof of possession failed; state preserved  |
| RC05-NEG-33 | `POST /enroll/complete` with incorrect one-time secret  | HTTP 400                           | Secret attempt counted; state preserved      |
| RC05-NEG-34 | Secret attempts exceed 3 failed tries on a challenge    | Challenge purged immediately       | Challenge eliminated; online guessing halted |
| RC05-NEG-35 | `POST /enroll/complete` after 300 s monotonic expiry    | Challenge rejected (expired)       | Expired challenge purged; clock not extended |
| RC05-NEG-36 | Single-use enrollment secret replayed                   | Rejected                           | Single-use enforced; no duplicate device     |
| RC05-NEG-37 | Pending enrollment quota exceeded (16 global/4 operator | Rejected via Admin IPC             | Existing pending/enrolled state unchanged    |
| RC05-NEG-38 | Gateway with 0 devices: ordinary `/mcp` tool request    | `UNAUTHENTICATED`                  | No session minted; zero-device state safe    |

### Session Bootstrap & Wire Protocol (RC05-NEG-39 … 47)

| ID          | Attack / input                                           | Expected result                 | Critical no-side-effect                      |
| :---------- | :------------------------------------------------------- | :------------------------------ | :------------------------------------------- |
| RC05-NEG-39 | Tokenless ordinary tool request to `/mcp`                | `UNAUTHENTICATED`               | Policy engine not reached                    |
| RC05-NEG-40 | Client-supplied `Mcp-Session-Id` on initial initialize   | Ignored / replaced by server ID | Client cannot fixate or force session ID     |
| RC05-NEG-41 | Tokenless `initialize` from unenrolled/revoked device    | `UNAUTHENTICATED`               | No session minted; no token issued           |
| RC05-NEG-42 | Request with valid `Mcp-Session-Id` but missing token    | `UNAUTHENTICATED`               | Dual-header enforced; policy not reached     |
| RC05-NEG-43 | Request with valid token but wrong `Mcp-Session-Id`      | `INVALID_SESSION_TOKEN`         | Cross-session mismatch rejected              |
| RC05-NEG-44 | Request with valid `Mcp-Session-Id` but wrong token      | `INVALID_SESSION_TOKEN`         | Constant-time check fails; no policy reached |
| RC05-NEG-45 | Valid session token presented from different device SPKI | `INVALID_SESSION_TOKEN`         | Device binding enforced; non-portable token  |
| RC05-NEG-46 | Malformed session token (> 128 bytes or non-hex)         | `INVALID_SESSION_TOKEN`         | Pre-parse bound enforced; no policy reached  |
| RC05-NEG-47 | Tokenless `initialize` flood exceeding active cap (8)    | Refused (`RESOURCE_EXHAUSTED`)  | Existing sessions unaffected                 |

### Actor Binding & Approvals (RC05-NEG-48 … 52)

| ID          | Attack / input                                          | Expected result          | Critical no-side-effect                       |
| :---------- | :------------------------------------------------------ | :----------------------- | :-------------------------------------------- |
| RC05-NEG-48 | Request supplies `clientId` / `clientType` / `deviceId` | `INVALID_REQUEST_SCHEMA` | Policy engine not reached; trusted preserved  |
| RC05-NEG-49 | Request supplies `sessionId` in JSON-RPC parameters     | `INVALID_REQUEST_SCHEMA` | Trusted session context not overridden        |
| RC05-NEG-50 | `_arcApproval` object carries actor fields              | `INVALID_REQUEST_SCHEMA` | No approval state mutated                     |
| RC05-NEG-51 | Actor context reaching `executionPayloadHash`           | Equals derived context   | No caller value influences hash               |
| RC05-NEG-52 | Remote client attempts redeeming under expired session  | `APPROVAL_REJECTED`      | Approval not extended, not revived, not bound |

### Rate Limiting, Admission Layers & Memory Bounds (RC05-NEG-53 … 61)

| ID          | Attack / input                                        | Expected result                   | Critical no-side-effect                     |
| :---------- | :---------------------------------------------------- | :-------------------------------- | :------------------------------------------ |
| RC05-NEG-53 | Layer A: Connection flood exceeding 60 conn/min       | Connection dropped / TCP reset    | Terminated before TLS; no CPU wasted        |
| RC05-NEG-54 | Layer A: Concurrent handshakes exceeding 64 global    | Connection dropped                | Handshake queue bounded                     |
| RC05-NEG-55 | Layer B: Pre-session HTTP flood exceeding 120 req/min | HTTP 429 Too Many Requests        | Refused before session lookup / MCP parse   |
| RC05-NEG-56 | Layer C: Authenticated flood exceeding 300 req/min    | MCP `RATE_LIMIT_EXCEEDED`         | Refused before policy/subsystem execution   |
| RC05-NEG-57 | Source-IP churn attack against rate limiters          | Key cap enforced; LRU fail-closed | Table memory bounded (4096/2048/1024 keys)  |
| RC05-NEG-58 | IPv4-mapped IPv6 address used to bypass IPv4 limit    | Normalized to canonical IPv4      | Shares bucket with IPv4 peer; no bypass     |
| RC05-NEG-59 | IPv6 rotation within `/64` subnet to bypass limit     | Grouped under `/64` prefix        | Shares bucket across subnet; no bypass      |
| RC05-NEG-60 | Request body exceeding 4 MiB during chunked read      | Aborted during read; close socket | Streaming ceiling enforced; no 4 MiB buffer |
| RC05-NEG-61 | Slowloris attack (headers/body read exceeding 10 s)   | Connection aborted                | Buffers freed; worker thread not blocked    |

### Authentication-Before-Policy & Anti-Oracle (RC05-NEG-62 … 67)

| ID          | Attack / input                                         | Expected result         | Critical no-side-effect                      |
| :---------- | :----------------------------------------------------- | :---------------------- | :------------------------------------------- |
| RC05-NEG-62 | Unenrolled device authentication failure               | `UNAUTHENTICATED`       | Anti-oracle: `DEVICE_NOT_ENROLLED` not sent  |
| RC05-NEG-63 | Revoked device authentication failure pre-session      | `UNAUTHENTICATED`       | Anti-oracle: revocation status not disclosed |
| RC05-NEG-64 | Revoked device presenting existing session token       | `INVALID_SESSION_TOKEN` | Anti-oracle: generic rejection returned      |
| RC05-NEG-65 | Unauthenticated remote request that would be ALLOWed   | `UNAUTHENTICATED`       | Policy engine not reached (verified by spy)  |
| RC05-NEG-66 | Unauthenticated remote request targeting mutation tool | `UNAUTHENTICATED`       | Subsystems not called (verified by spy)      |
| RC05-NEG-67 | Authenticated session hitting a `DENY` policy          | `POLICY_DENIED`         | Auth success does not imply authorization    |

### Approval Separation (RC05-NEG-68 … 69)

| ID          | Attack / input                                   | Expected result         | Critical no-side-effect                     |
| :---------- | :----------------------------------------------- | :---------------------- | :------------------------------------------ |
| RC05-NEG-68 | Session token used as an approval token          | `APPROVAL_REJECTED`     | Subsystem not called                        |
| RC05-NEG-69 | Approval token used as a session token in header | `INVALID_SESSION_TOKEN` | Domain separation enforced; no policy reach |

### Restart, Audit Secrecy, Admin Isolation (RC05-NEG-70 … 79)

| ID          | Attack / input                                        | Expected result                   | Critical no-side-effect                   |
| :---------- | :---------------------------------------------------- | :-------------------------------- | :---------------------------------------- |
| RC05-NEG-70 | Restart: sessions cleared, approvals invalidated      | Sessions invalid; approvals gone  | Trust survives; approvals stay volatile   |
| RC05-NEG-71 | Audit log inspection after session bootstrap          | No raw session token in audit     | Central redaction eliminates raw token    |
| RC05-NEG-72 | Audit log inspection after enrollment completion      | No raw enrollment secret in audit | Central redaction eliminates secret       |
| RC05-NEG-73 | Audit log inspection for private keys / cert material | No private cryptographic material | Cryptographic secrecy preserved           |
| RC05-NEG-74 | Remote client attempts `approve` action via MCP       | `POLICY_DENIED`                   | No approval state mutated; admin IPC only |
| RC05-NEG-75 | Remote client attempts `reject` action via MCP        | `POLICY_DENIED`                   | No approval state mutated; admin IPC only |
| RC05-NEG-76 | Remote client attempts approval list/inspect via MCP  | `POLICY_DENIED`                   | No review material disclosed              |
| RC05-NEG-77 | Remote client attempts device enroll/revoke via MCP   | Rejected (`POLICY_DENIED`)        | Trust store unchanged; admin IPC only     |
| RC05-NEG-78 | Remote client attempts policy modification via MCP    | `POLICY_DENIED`                   | Policy engine unchanged                   |
| RC05-NEG-79 | Remote client attempts session revocation for another | Rejected                          | Cross-device session mutation barred      |

**Final catalog size: N = 79.** Every threat in §35 maps to one or more of these
contiguous controls.

---

## 35. Threat Matrix

| Threat                                    | Trust Boundary      | Preventive Control                               | Detection / Audit                   | Negative control       |
| :---------------------------------------- | :------------------ | :----------------------------------------------- | :---------------------------------- | :--------------------- |
| Unauthenticated remote tool invocation    | TB-1 Ingress        | §11–§12 auth sequence; §3 invariant              | `AUTH_FAILED`                       | 39, 65, 66             |
| Plaintext or downgraded transport         | TB-1 Ingress        | §6 TLS 1.3 only, no fallback                     | `AUTH_FAILED` / handshake refusal   | 01, 07                 |
| Untrusted CA client certificate           | TB-1 Ingress        | §6 T-8, §7 P-3 client CA validation              | Handshake refused                   | 09                     |
| Expired client certificate                | TB-1 Ingress        | §6 T-7 client certificate expiry check           | Handshake refused                   | 10                     |
| Unenrolled device authentication attempt  | TB-1 → TB-2         | §8 device trust store; anti-oracle rule          | `AUTH_FAILED`                       | 16, 62                 |
| Pin rotation overlap window abuse         | TB-1 → TB-2         | §7 P-7 explicit window removal                   | `AUTH_FAILED`                       | 17                     |
| Certificate/key theft (no private key)    | TB-1 Ingress        | §7 mTLS requires private key                     | `AUTH_FAILED`                       | 08, 11                 |
| Session token theft                       | TB-2 Policy         | §11 binding to device + SPKI                     | `INVALID_SESSION_TOKEN`             | 45                     |
| Session fixation / client-asserted ID     | TB-2 Policy         | §5.3, §11 server-generated ID & token            | `INVALID_SESSION_TOKEN`             | 40, 49                 |
| Cross-device token replay                 | TB-2 Policy         | §11 binding                                      | `INVALID_SESSION_TOKEN`             | 45                     |
| Malformed session token presented         | TB-2 Policy         | §11 128-byte ceiling, strict hex check           | `INVALID_SESSION_TOKEN`             | 46                     |
| Actor-field spoofing from remote JSON     | TB-2 Policy         | §13 server-derived actor                         | `INVALID_REQUEST_SCHEMA`            | 48, 49, 50, 51         |
| Auth mistaken for authorization           | TB-2 Policy         | §14 separation; RC-04 policy unchanged           | `POLICY_DENIED`                     | 67                     |
| Session token used as approval token      | TB-2 Policy         | §28 separation                                   | `APPROVAL_REJECTED`                 | 68                     |
| Approval token used as session token      | TB-2 Policy         | §28 separation                                   | `INVALID_SESSION_TOKEN`             | 69                     |
| Approval re-bound across expiring session | TB-2 Policy         | §28 X-7 fails closed                             | `APPROVAL_REJECTED`                 | 52                     |
| TCP / TLS handshake flood                 | TB-1 Ingress        | §21 Layer A connection limits & handshake caps   | TCP drop                            | 53, 54                 |
| HTTP pre-session request flood            | TB-1 Ingress        | §21 Layer B pre-session HTTP limiter             | HTTP 429 Too Many Requests          | 55                     |
| Authenticated MCP request flood           | TB-2 Policy         | §21 Layer C authenticated limiter                | MCP `RATE_LIMIT_EXCEEDED`           | 56                     |
| Limiter-key churn memory exhaustion       | TB-1 Ingress        | §21.2 key caps (4096/2048/1024), LRU fail-closed | Connection drop / HTTP 429          | 57                     |
| IP normalization bypass                   | TB-1 Ingress        | §21.3 IPv4 unmapping & IPv6 /64 prefix grouping  | `RATE_LIMITED` / HTTP 429           | 58, 59                 |
| Slowloris / partial body                  | TB-1 Ingress        | §20 read timeouts, header bounds                 | `REMOTE_DISCONNECTED`               | 61                     |
| Oversized / compressed payload            | TB-1 Ingress        | §20 4 MiB during-read enforcement                | `PAYLOAD_TOO_LARGE`                 | 60                     |
| Enrollment replay / race                  | TB-1 → TB-2         | §9 single-use secrets, atomic completion         | `DEVICE_ENROLLMENT_REJECTED`        | 36                     |
| Rogue enrollment authority                | TB-2 Policy         | §9 local-operator-only bootstrap                 | `DEVICE_ENROLLMENT_REJECTED`        | 29, 31                 |
| First-device bootstrap bypass             | TB-1 Ingress        | §5.2, §9 zero-device startup requires completion | `UNAUTHENTICATED`                   | 38                     |
| Enrollment-completion endpoint abuse      | TB-1 Ingress        | §9 mTLS, SPKI match, 3-attempt lockout, 300s TTL | HTTP 400 / purge challenge          | 30, 32, 33, 34, 35     |
| Pending enrollment quota exhaustion       | TB-2 Policy         | §9 E-7 16 global / 4 operator quotas             | Rejected via Admin IPC              | 37                     |
| Attacker-writable trust store             | TB-3 Storage        | §16 regular file, mode 0600, UID check           | Startup failure / write abort       | 24, 25                 |
| Trust-store symlink swap                  | TB-3 Storage        | §16 `O_NOFOLLOW`/`lstat` symlink check           | Startup failure                     | 23                     |
| Attacker-writable CA / trust roots        | TB-3 Storage        | §6 T-11 mode & 0022 check, symlink check         | Startup failure                     | 28                     |
| Malformed / duplicate pin in trust store  | TB-3 Storage        | §7 P-8, §8 malformed/duplicate pin rejection     | Startup failure                     | 18, 19                 |
| Trust store resource exhaustion           | TB-3 Storage        | §8 256 device cap, 256 KiB size cap              | `RESOURCE_EXHAUSTED` / Startup fail | 20, 21, 26             |
| Display label overflow in enrollment      | TB-2 Policy         | §8 64-byte display label bound                   | `INVALID_REQUEST_SCHEMA`            | 22                     |
| Trust store atomic persistence failure    | TB-3 Storage        | §16 atomic write + fsync                         | Operation fails closed              | 27                     |
| Device revocation not enforced            | TB-2 Policy         | §8, §11 immediate revocation                     | `AUTH_FAILED` / `SESSION_REVOKED`   | 63, 64                 |
| Session / token bootstrap abuse           | TB-1 → TB-2         | §5.3, §11 tokenless initialize only, quotas      | `UNAUTHENTICATED` / session cap     | 40, 41, 47             |
| Mismatched session ID + token             | TB-2 Policy         | §5.3, §11 dual-header requirement                | `INVALID_SESSION_TOKEN`             | 42, 43, 44             |
| Server certificate expiring at runtime    | TB-1 Ingress        | §6 T-7 runtime check before new TLS handshakes   | Handshake refused; health degraded  | 15                     |
| Server certificate SAN mismatch or expiry | TB-1 Ingress        | §6 T-5, §18 startup hostname & validity checks   | Startup failure                     | 12, 13, 14             |
| Remote administrative escalation          | TB-2 Policy         | §15 admin stays local IPC                        | `POLICY_DENIED`                     | 74, 75, 76, 77, 78, 79 |
| Secret leakage into audit/logs/errors     | TB-3 Host Execution | §17 K-3, §24 central redaction                   | Audit secrecy assertions            | 71, 72, 73             |
| Proxy-header identity spoofing            | TB-1 Ingress        | §6.1 in-process TLS; headers never authoritative | `UNAUTHENTICATED`                   | 16                     |
| DNS rebinding / browser origin            | TB-1 Ingress        | §23 default-deny origin, Host validation         | Rejection before parse              | 02, 05                 |
| Restart resurrecting authority            | TB-2 Policy         | §29 restart semantics                            | `SESSION_REVOKED`                   | 70                     |
| Wildcard bind exposure                    | TB-1 Ingress        | §18 explicit opt-in                              | Startup failure                     | 05                     |

---

## 36. Positive Acceptance Flows

These are the required **success** paths. Task 0 does not implement them.

1. **Server startup in stdio-only mode** — starts, listens on stdio, remote
   gateway inactive, health reports `transportMode: 'stdio'` and
   `remoteGatewayActive: false`. **RC-04 behaviour unchanged.**
2. **Remote gateway startup with zero enrolled devices** — starts with valid
   server TLS config, valid client CA trust roots, and an empty trust store;
   listener binds; health reports `enrolledDevicesCount: 0`, `remoteGatewayActive: true`,
   `authenticationActive: true`; `/mcp` rejects ordinary sessions; `/enroll/complete`
   is ready for bootstrap.
3. **Remote gateway startup with enrolled devices** — starts with valid TLS config,
   client CA roots, and populated trust store; listener bound; health reports
   enrolled device count.
4. **First-device local enrollment initiation & remote completion** — operator
   creates pending enrollment on local admin IPC; client connects over TLS 1.3
   mTLS to `POST /enroll/complete` with matching SPKI and valid secret; device
   record atomically written to trust store; `DEVICE_ENROLLED` audited.
5. **Session bootstrap via tokenless initialize** — enrolled device connects over
   TLS 1.3 mTLS; issues initial tokenless `initialize` on `/mcp`; server mints
   session, generates `Mcp-Session-Id`, and returns raw token in `Arc-Session-Token`
   response header; `SESSION_ISSUED` audited.
6. **Subsequent authenticated tool request with dual headers** — client issues
   tool request carrying both `Mcp-Session-Id: <id>` and `Authorization: Bearer <token>`;
   passes through shared pipeline with derived actor context; identical semantics
   to stdio.
7. **Ordinary read-only MCP tool invocation** — tool executes and returns result;
   audit records execution with server-derived actor fields.
8. **Policy `REQUIRE_APPROVAL` invocation** — returns `APPROVAL_REQUIRED` with a
   request id and **no token**; approval is bound to the remote-derived actor.
9. **Approval redemption from the same authenticated session/device** —
   operator approves on the local channel; redemption succeeds from the same
   session; the mutation executes; execution lifecycle audited.
10. **Session expiration and re-authentication** — idle/absolute expiry revokes
    the session; a new session is issued after re-authentication; old token no
    longer works.
11. **Device revocation** — operator revokes; live sessions for that device are
    revoked; subsequent requests fail with generic `UNAUTHENTICATED`; the trust
    store reflects the revocation across restart.

---

## 37. Historical Documentation Reconciliation

| Historical source                            | Historical wording                                                                                                                            | Ambiguity / conflict                                                                    | **Normative RC-05 rule**                                                                                                        |
| :------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------ |
| `README.md`                                  | "Remote MCP over HTTPS/SSE", mutual TLS, device enrollment                                                                                    | "SSE" is a deprecated transport name in SDK 1.30.0                                      | **Streamable HTTP only** (§5). SSE survives as _response framing_, not as a transport.                                          |
| `docs/architecture/overview.md`              | "local stdio and remote authenticated HTTPS/SSE"; "device enrollment, token lifecycle management, and session pinning"                        | Suggests both transports can run; does not define session pinning                       | **Mutually exclusive listeners** (§4). "Session pinning" = binding to `(Mcp-Session-Id, deviceId, SPKI, clientId)` (§5.4, §11). |
| `docs/architecture/trust-boundaries.md`      | "TLS 1.3 with pinned certificates"; "Hard ceiling on JSON-RPC message size (default: 4 MB)"; "Sliding-window rate limiter per client session" | Pinning undefined; "4 MB" ambiguous; limiter keyed on "session" only is unsafe pre-auth | **SPKI SHA-256 pin in addition to CA chain validation** (§7); **4 MiB on raw body** (§20); **three-layer rate limiting** (§21). |
| `docs/architecture/trust-boundaries.md`      | "HTTPS/WSS SSE" transport termination                                                                                                         | Implies WebSocket support                                                               | **WebSocket not supported** (§5).                                                                                               |
| `docs/threat-model/threat-model.md`          | "Mandatory TLS 1.3, cryptographic session tokens, client device enrollment, stdio inheritance checks (RC-05)"                                 | "stdio inheritance checks" undefined for a remote stage                                 | stdio is a **separate mutually exclusive mode** whose actor is never derived from remote credentials (§4, §13).                 |
| `docs/architecture/package-ownership.md`     | `packages/auth` owns identity/session/device auth; `apps/mcp-server` owns stdio + HTTPS/SSE transports                                        | Confirms ownership; transport name stale                                                | Ownership **preserved**; transport is **Streamable HTTP** (§30).                                                                |
| `docs/architecture/rc04-scope-acceptance.md` | Remote HTTPS/SSE/TLS/mTLS deferred to RC-05; OIDC/SAML/OAuth2 + device attestation "RC-05"; remote approval administration absent             | Conflicts with the narrower README roadmap                                              | Transport per §5; **OIDC/OAuth2/SAML/IdP/attestation deferred beyond RC-05** (§10); **admin stays local** (§15).                |
| `docs/architecture/trust-boundaries.md`      | "All remote connections require TLS 1.3 with pinned certificates"                                                                             | Does not say whether a proxy may terminate TLS                                          | **In-process TLS only**; proxy termination out of scope (§6).                                                                   |
| `packages/auth/src/index.ts`                 | `IAuthEngine.verifyToken` / `generateSessionToken` as the RC-05 target                                                                        | Implies a token engine; silent on binding and enrollment                                | Contract kept conceptually; RC-05 adds **enrollment, pinning, and TLS-identity binding** around it (§8, §11).                   |

---

## 38. Implementation Breakdown

Ten tasks, derived from independently reviewable security boundaries.
**Task 0 is not implementation and is not counted.**

| #   | Title                                                    | Scope                                                                                                                                                                                                        | Expected files                                                                           | Security invariants                             | Controls                  | Depends on | Stop boundary                                      |
| :-- | :------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------------------------------------------------------------------------------------- | :---------------------------------------------- | :------------------------ | :--------- | :------------------------------------------------- |
| 1   | Device identity, SPKI pinning, and trust-store integrity | `deviceId` generation, SPKI pin derivation/validation, trust-store read/write/validate, file permissions (0600), ownership, symlink check, size cap (256 KiB), atomic fsync persistence. **No network I/O.** | `packages/auth/src/**`, `packages/protocol/src/**`, tests                                | §7 P-4..P-8, §8 all, §16 all                    | 16–27                     | —          | No network I/O, no session logic, no server wiring |
| 2   | Enrollment lifecycle and operator admin IPC              | Pending enrollment creation (local-channel initiated), one-time secret generation, monotonic TTL (300 s), challenge lockout (3 failed tries), quotas (16 global/4 operator), cancel.                         | `packages/auth/src/**`, `apps/mcp-server/src/admin-ipc.ts`, `apps/cli/src/**`, tests     | §9 E-1..E-3, E-5..E-12                          | 33–37                     | 1          | No network listener; testable over local admin IPC |
| 3   | TLS 1.3 & mTLS admission layer                           | TLS 1.3 listener, client-cert requirement, CA chain validation, CA file integrity (mode/symlink), server cert startup/runtime validity and SAN match, Layer A TCP/TLS admission limiter.                     | `apps/mcp-server/src/**`, tests                                                          | §6 all, §7 P-1..P-3, §18, §21 Layer A           | 01, 05, 07–15, 28, 53, 54 | 1          | No MCP session yet; transport admits, nothing more |
| 4   | Enrollment completion bootstrap endpoint                 | `POST /enroll/complete` bootstrap router, mTLS SPKI proof-of-possession verification, single-use secret check, atomic device activation, zero-device bootstrap handling.                                     | `apps/mcp-server/src/**`, `packages/auth/src/**`, tests                                  | §5.1, §5.2, §9 E-4, §12 Step 4                  | 29–32, 38                 | 1, 2, 3    | Bootstrap endpoint only; no MCP session creation   |
| 5   | Session issuance, wire bootstrap, and token lifecycle    | Tokenless `initialize` handling, `Mcp-Session-Id` generator, `Arc-Session-Token` header issuance, dual-header validation (`Mcp-Session-Id` + `Authorization`), token digests, TTLs, caps.                    | `packages/auth/src/**`, tests                                                            | §5.3, §5.4, §11 all, §26 C-2/C-4                | 39–47                     | 1          | Session logic only; no MCP tool execution          |
| 6   | Actor context derivation and RC-04 pipeline wiring       | Map authenticated connection → `(clientId, clientType, deviceId, sessionId)`; block caller-supplied actor fields in JSON-RPC; wire into shared pipeline; anti-oracle generic rejections.                     | `apps/mcp-server/src/**`, tests                                                          | §3, §13, §14, §25                               | 48–52, 62–67              | 3, 5       | No new tool logic                                  |
| 7   | Multi-layer rate limiting and resource bounds            | Layer B secure HTTP pre-session limiter, Layer C authenticated limiter, limiter memory caps (4096/2048/1024), LRU fail-closed, IP normalization and `/64` grouping, body/header bounds.                      | `packages/auth/src/**` or `apps/mcp-server/src/**`, tests                                | §20, §21 Layer B & C, §21.2, §21.3, §26 C-1/C-3 | 55–61                     | 3, 5       | Bounds only; no policy decisions                   |
| 8   | Streamable HTTP gateway composition and health           | `StreamableHTTPServerTransport` integration on `/mcp`, stateful mode, runtime cert expiry health degradation, zero-device health status, mutual exclusion with stdio.                                        | `apps/mcp-server/src/**`, `packages/protocol/src/**`, tests                              | §4, §5, §19, §23, §27                           | 02, 03, 04, 06            | 3–7        | Composition only; no policy/approval change        |
| 9   | Operator device and session administration               | CLI + admin IPC methods: list/inspect/revoke devices, list/revoke sessions, pin overlap window management.                                                                                                   | `apps/cli/src/**`, `apps/mcp-server/src/admin-ipc.ts`, tests                             | §15, §26                                        | 74–79                     | 1, 2, 5    | Admin stays local; no remote admin surface         |
| 10  | Audit events, acceptance test suite + finalization       | Gateway audit catalog, central secret redaction assertions, acceptance test suite for all 79 negative controls, `scripts/verify-rc05.sh`, `verify:rc05`, final documentation.                                | `packages/audit/src/**`, `packages/protocol/src/**`, `tests/**`, `scripts/**`, `docs/**` | §24, §28–§29, §34–§35                           | all 79                    | 1–9        | Finalization only                                  |

---

## 39. Definition of Done (RC-05)

RC-05 is complete only when **all** of the following hold:

1. The remote transport contract of §5 is implemented **exactly** — Streamable
   HTTP, stateful, TLS 1.3, no legacy SSE, no plaintext, no WebSocket.
2. The **enrollment bootstrap endpoint (`POST /enroll/complete`)** is implemented
   per §5.1 and §9, enabling zero-enrolled-device startup and mTLS proof-of-possession
   bootstrap.
3. The **session bootstrap wire protocol (§5.3)** is implemented exactly: tokenless
   `initialize`, `Arc-Session-Token` header response, and subsequent dual-header
   verification (`Mcp-Session-Id` + `Authorization: Bearer <token>`).
4. **Session ID unification (§5.4)** is implemented: `actor.sessionId == Mcp-Session-Id`.
5. **Authenticated remote MCP only**: no request can reach policy or a subsystem
   without the full §12 sequence.
6. The **TLS contract (§6)** is satisfied, including mandatory mTLS, in-process
   termination, client CA file integrity, and runtime certificate expiry handling.
7. The **device identity and trust store integrity model (§8, §16)** is satisfied,
   including regular file verification, mode 0600 permissions, process UID ownership,
   256 KiB size ceiling, 256 device cap, and atomic fsync persistence.
8. The **three-layer rate limiting model (§21)** is satisfied, including Layer A
   connection caps, Layer B HTTP 429 pre-session limiting, Layer C authenticated
   limiting, limiter key bounds, and IPv6 `/64` prefix normalization.
9. The **anti-oracle error model (§25)** is preserved: pre-session failures return
   only generic `UNAUTHENTICATED` (no external `DEVICE_NOT_ENROLLED`), and post-session
   failures return generic `INVALID_SESSION_TOKEN`.
10. **Authentication/authorization separation (§14)** is preserved and
    demonstrated: a valid session hitting `DENY` is denied.
11. **RC-04 policy and approval invariants are preserved** — `DENY >
REQUIRE_APPROVAL > ALLOW`, mutation floor, approval binding, 300 s monotonic
    TTL, restart invalidation — with regression tests proving it.
12. **Local stdio regression is green**: existing stdio behaviour and RC-01…RC-04
    suites unchanged (822 tests / 82 suites passing).
13. **All 79 negative controls (§34) are green** in a dedicated acceptance suite,
    with no skips and no todos.
14. **Remote positive flows (§36)** pass as integration tests.
15. **Audit redaction/secrecy tests** pass: no token, enrollment secret, private key,
    or `Authorization` value appears in any record.
16. **No secret or private credential artifacts** exist in the repository.
17. **`scripts/verify-rc05.sh` and `pnpm run verify:rc05`** exist and pass.
18. The **RC-05 final integration report** is written and accurate.
19. **Exact-head push CI, PR CI including Dependency Review, independent review,
    merge, and post-merge main CI** all complete with attempt 1 green.

---

## 40. Open Questions

None. Every ambiguity raised by the Task-0 brief and Task 0.1 review is resolved
above by an explicit normative rule. Items that could not be resolved without a
separate security design are marked **out of scope** rather than left undefined (§33).

/**
 * CesSpace ARC — RC-05 Task 4 Enrollment Completion Bootstrap Endpoint
 *
 * The first HTTP surface reachable in remote mode, and deliberately the smallest
 * one that can exist: `POST /enroll/complete` is the completion half of an
 * enrollment the operator authorised locally, and `/mcp` is a deny-only
 * placeholder until the later session and transport tasks land.
 *
 * Authoritative contract: §5.1, §5.2, §9.1, §9 E-4, §12 step 4, §25.1, and the
 * Task-4 row of §38. Task 2's secret semantics (E-5..E-12) and Task 1's
 * trust-store invariants are preserved unchanged.
 *
 * Design rules:
 * - The trusted identity selector is the SPKI pin derived from the mTLS peer
 *   certificate by the gateway. It is NEVER read from the body, query, headers,
 *   or URL, and it is passed in already derived.
 * - Every application-level bootstrap failure returns the same uniform response;
 *   the endpoint is not an oracle for whether a challenge existed, expired, was
 *   locked out, or was replayed.
 * - Consumption and durable activation are one synchronous transaction: the
 *   pending challenge is removed only after the trust store has been persisted.
 * - No MCP parsing, no session, no token, no policy, and no subsystem call
 *   happens anywhere in this module.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { ArcError } from '@cesspace-arc/protocol';
import {
  DeviceTrustStore,
  resolveActiveDeviceIdentity,
  type DeviceTrustStoreData,
  type EnrolledDeviceRecord,
  type EnrollmentManager,
  type PendingEnrollmentView,
  type TrustedSessionIdentity,
} from '@cesspace-arc/auth';
import { RequestBodyError, readBoundedRequestBody } from './remote-request-bounds.js';
import type { RemoteMcpSurface } from './remote-mcp-surface.js';

/** The only path that can attempt enrollment completion. */
export const ENROLL_COMPLETE_PATH = '/enroll/complete';

/** The MCP path. Deny-only until the later transport tasks. */
export const MCP_PATH = '/mcp';

/**
 * Maximum raw request body for the bootstrap endpoint, in bytes (Task 4 §6).
 *
 * Deliberately NOT the generic Task-7 4 MiB remote body ceiling: bootstrap
 * carries one 64-character secret, so 4 KiB is already generous. It is passed to
 * the SHARED bounded reader as that endpoint's internal bound, so the generic
 * 4 MiB mechanism exists and is tested without loosening this endpoint.
 */
export const MAX_ENROLL_BODY_BYTES = 4096;

/**
 * The ONE uniform application-level bootstrap failure (§9.1, §25.1 rule 2).
 *
 * No pending-record existence, expiry, failed-attempt count, expected SPKI,
 * device identity, clientId, enrollmentId, or internal reason is disclosed.
 */
export const ENROLLMENT_FAILED_BODY = JSON.stringify({ error: 'Enrollment failed' });

/**
 * The ONE uniform pre-session `/mcp` failure (§25.1 rule 1).
 *
 * Scoped to `/mcp` device and session admission, which covers a device that is
 * not enrolled, a revoked device, a binding mismatch, and the zero-device state.
 */
export const UNAUTHENTICATED_BODY = JSON.stringify({
  code: 'UNAUTHENTICATED',
  message: 'Authentication failed',
});

/** Bounded refusal for a bootstrap body above the endpoint-specific ceiling. */
export const PAYLOAD_TOO_LARGE_BODY = JSON.stringify({ error: 'Payload too large' });

/** Bounded refusal for a recognized path with an unrecognized method. */
export const METHOD_NOT_ALLOWED_BODY = JSON.stringify({ error: 'Method not allowed' });

/** Bounded refusal for an unconfigured path. */
export const NOT_FOUND_BODY = JSON.stringify({ error: 'Not found' });

/** Minimal bounded success. Carries no enrollment internals. */
export const ENROLLED_BODY = JSON.stringify({ status: 'enrolled' });

/**
 * Durable trust-store storage used by the bootstrap transaction.
 *
 * Both operations default to the Task-1 production primitives — the atomic
 * persister behind `DeviceTrustStore.saveToFile` and the validating loader
 * behind `DeviceTrustStore.loadFromFile`. The pair is injected together because
 * rollback must be able to WRITE and then VERIFY what actually reached disk.
 *
 * @internal Reachable ONLY through an internal option object constructed by a
 * test. It is deliberately absent from ArcServerConfig, RemoteConfig, the
 * environment, and every network-reachable surface, so no launch configuration
 * and no request can weaken or bypass durable persistence.
 */
export interface TrustStoreStorage {
  save(store: DeviceTrustStore, filePath: string): void;
  load(filePath: string): DeviceTrustStore;
}

/**
 * Outcome of one authoritative trust-store mutation (RC-05 Task 9).
 *
 * Three outcomes, never two: a domain refusal and a durable-storage failure are
 * DIFFERENT facts and the operator-visible result must not conflate them. Only
 * `COMMITTED` means the authoritative in-memory state and the destination file
 * were both changed, and only `COMMITTED` permits a caller to report success.
 */
export type TrustStoreMutationOutcome =
  | { outcome: 'COMMITTED' }
  /** The mutation was refused by the domain before anything was persisted. */
  | { outcome: 'REJECTED'; error: ArcError }
  /**
   * The mutation could not be proven durable. `latched` reports whether the
   * fail-closed storage latch is now set, which means the installed state could
   * not be proven restored and the gateway will refuse every later mutation.
   */
  | { outcome: 'STORAGE_FAILED'; latched: boolean };

/** @internal Internal seams for the bootstrap controller. */
export interface EnrollmentBootstrapOptions {
  /**
   * @internal Test-only durable-storage injection. Defaults to Task-1 atomic
   * persistence and the Task-1 validating loader. Never populated from
   * configuration, environment, or a request.
   */
  trustStoreStorageForTests?: Partial<TrustStoreStorage>;
  /**
   * @internal Test-only body-read deadline. May only SHORTEN the frozen 10 s.
   * Never populated from configuration, environment, or a request.
   */
  bodyReadTimeoutMsForTests?: number;
}

/**
 * Order-insensitive, content-exact fingerprint of a validated trust store.
 *
 * Used to answer "is what is on disk the state I expected?" by comparing
 * VALIDATED trust-store state, never file existence or raw bytes: the
 * persistence path is a rename plus a directory fsync, so the bytes that reach
 * the destination are produced by the validator and re-reading them through the
 * loader is the only comparison that means anything.
 */
function trustStateFingerprint(store: DeviceTrustStore): string {
  const devices = Array.from(store.toData().devices)
    .map((device) => ({
      deviceId: device.deviceId,
      clientId: device.clientId,
      clientType: device.clientType,
      pins: Array.from(device.pins).sort(),
      enrolledAt: device.enrolledAt,
      displayLabel: device.displayLabel,
      revoked: device.revoked,
    }))
    .sort((a, b) => (a.deviceId < b.deviceId ? -1 : a.deviceId > b.deviceId ? 1 : 0));
  return JSON.stringify({ version: 1, devices });
}

/** Controller driving one gateway's bootstrap HTTP surface. */
export class EnrollmentBootstrap {
  private readonly storage: TrustStoreStorage;
  /** @internal Test-only body-read deadline. Only ever SHORTER than the frozen 10 s. */
  private readonly bodyReadTimeoutMsForTests?: number;
  /**
   * Terminal latch for an uncertain durable authentication root.
   *
   * Set when a failed activation could not be proven rolled back. Once set, no
   * further completion is attempted: the gateway will not keep retrying a write
   * against a trust store whose contents it can no longer vouch for.
   */
  private storageLatched = false;
  /**
   * The Task-8 Streamable HTTP MCP surface, attached by the gateway once the
   * composition exists.
   *
   * Absent means `/mcp` stays the deny-only placeholder, which is the correct
   * behaviour for a gateway constructed without a composed server. Attaching it
   * is the ONLY thing that can make `/mcp` reachable, and it is never reachable
   * from configuration, the environment, or a request.
   */
  private mcpSurface?: RemoteMcpSurface;

  constructor(
    private readonly enrollmentManager: EnrollmentManager,
    private authoritativeTrustStore: DeviceTrustStore,
    private readonly trustStorePath: string,
    options: EnrollmentBootstrapOptions = {},
  ) {
    this.storage = {
      save:
        options.trustStoreStorageForTests?.save ??
        ((store, filePath) => store.saveToFile(filePath)),
      load:
        options.trustStoreStorageForTests?.load ??
        ((filePath) => DeviceTrustStore.loadFromFile(filePath)),
    };
    this.bodyReadTimeoutMsForTests = options.bodyReadTimeoutMsForTests;
  }

  /**
   * Count of NON-REVOKED enrolled devices, for bounded reporting (§19).
   *
   * The health field is "enrolled devices", and a revoked device is no longer an
   * enrolled device: it can neither resolve to an identity nor authenticate, so
   * counting it would overstate the trust root the gateway is actually serving.
   * The count is derived from the authoritative trust-store records, which carry
   * the revoked flag — the same records every admission decision reads — and only
   * the COUNT leaves this method: no record, pin, client, or label is exposed.
   */
  public getEnrolledDeviceCount(): number {
    let active = 0;
    for (const device of this.authoritativeTrustStore.getDevices()) {
      if (!device.revoked) {
        active += 1;
      }
    }
    return active;
  }

  /**
   * Resolves the CURRENT active device for a trusted SPKI pin (RC-05 Task 6).
   *
   * The single authoritative read path for remote request admission. It runs
   * against the CURRENT `authoritativeTrustStore` on every call, so a device
   * revoked between two requests stops resolving immediately — including while
   * later enrollment activation has already swapped in a newer store.
   *
   * The store object itself is deliberately NOT exposed: callers receive either
   * a resolver-minted identity or `undefined`, and nothing else.
   */
  public resolveActiveDeviceIdentity(spkiPin: string): TrustedSessionIdentity | undefined {
    return resolveActiveDeviceIdentity(this.authoritativeTrustStore, spkiPin);
  }

  /**
   * True once durable trust storage could not be proven restored.
   *
   * @internal Deliberately NOT part of the bounded gateway status: the storage
   * reason is never disclosed remotely, and the only observable client-facing
   * effect is that completions keep failing.
   */
  public isStorageFailureLatched(): boolean {
    return this.storageLatched;
  }

  /**
   * Attaches the Task-8 Streamable HTTP MCP surface.
   *
   * Called by the gateway between construction and `start()`, so the surface is
   * always in place before the listener can accept a single request: there is no
   * window in which `/mcp` is reachable but uncomposed.
   */
  public attachMcpSurface(surface: RemoteMcpSurface): void {
    this.mcpSurface = surface;
  }

  /**
   * Immutable snapshot of the authoritative device records (RC-05 Task 9).
   *
   * Every record is rebuilt field by field into a fresh FROZEN object with a
   * frozen pin array, so an administrative reader receives a snapshot rather
   * than the mutable record the trust store itself holds: mutating what it was
   * handed cannot alter trust state, and it cannot retain a live reference into
   * the store's internal map.
   *
   * This is the same authoritative state every remote admission decision reads.
   * There is no second store, no shadow table, and no re-read of the file.
   */
  public snapshotDeviceRecords(): readonly EnrolledDeviceRecord[] {
    return Object.freeze(
      this.authoritativeTrustStore.getDevices().map((device) =>
        Object.freeze({
          deviceId: device.deviceId,
          clientId: device.clientId,
          clientType: device.clientType,
          pins: Object.freeze([...device.pins]),
          enrolledAt: device.enrolledAt,
          displayLabel: device.displayLabel,
          revoked: device.revoked,
        }),
      ),
    );
  }

  /**
   * Applies ONE durable trust-store mutation through the SAME transaction model
   * the enrollment completion path already uses (RC-05 Task 9, §8):
   *
   *   current authoritative snapshot -> isolated candidate -> apply the mutation
   *   to the candidate -> persist the candidate atomically -> make the candidate
   *   authoritative -> report success.
   *
   * The live authoritative store is NEVER mutated first and persisted later, so
   * a filesystem write failure can never produce an operator-visible success
   * while memory and disk disagree. A reported failure is reconciled through
   * {@link restorePreTransactionState}, which proves — by reloading and
   * re-comparing VALIDATED state — whether the prior state is actually back, and
   * sets the fail-closed latch when it is not.
   *
   * When durable storage is already latched, or is latched by this call, every
   * later mutation is refused: the gateway does not keep administering an
   * authentication root whose installed state cannot be proven.
   *
   * Fully synchronous, so no remote request can interleave between the decision
   * and the commit.
   */
  public applyTrustStoreMutation(
    mutate: (candidate: DeviceTrustStore) => void,
  ): TrustStoreMutationOutcome {
    // Fail closed BEFORE any work. An authentication root whose installed state
    // is unproven is not one the gateway will keep mutating.
    if (this.storageLatched) {
      return { outcome: 'STORAGE_FAILED', latched: true };
    }

    const before = this.authoritativeTrustStore.toData();
    const candidate = DeviceTrustStore.fromData(before);

    try {
      mutate(candidate);
    } catch (err: unknown) {
      // A domain refusal is decided against the CANDIDATE, before anything has
      // been written, so the destination file and the authoritative store are
      // both exactly as they were.
      return {
        outcome: 'REJECTED',
        error:
          err instanceof ArcError
            ? err
            : ArcError.internalError('Device trust mutation was rejected.'),
      };
    }

    try {
      this.storage.save(candidate, this.trustStorePath);
    } catch {
      // See activateDevice: a reported save failure does not mean the
      // destination is unchanged, because Task-1 persistence renames over the
      // destination before fsyncing the parent directory. Reconcile and prove.
      this.restorePreTransactionState(before);
      return { outcome: 'STORAGE_FAILED', latched: this.storageLatched };
    }

    // Only now does the new state become authoritative, and only now may a
    // caller report success.
    this.authoritativeTrustStore = candidate;
    return { outcome: 'COMMITTED' };
  }

  /**
   * Handles one authenticated HTTP request.
   *
   * `spkiPin` is the Task-3 mTLS identity, already derived from the verified
   * peer certificate. It is the ONLY source of the identity selector used for
   * challenge lookup.
   */
  public async handle(req: IncomingMessage, res: ServerResponse, spkiPin: string): Promise<void> {
    // Query strings are never consulted, so a secret placed in the query string
    // is simply ignored: the path is matched without it and only the body can
    // carry a proof.
    const pathOnly = (req.url ?? '').split('?')[0];

    if (pathOnly === ENROLL_COMPLETE_PATH) {
      if (req.method !== 'POST') {
        // A wrong method must not verify a secret, mutate a failed-attempt
        // counter, or touch the trust store; it is refused before the body is
        // read, so no state changes at all.
        this.send(res, 405, METHOD_NOT_ALLOWED_BODY, { Allow: 'POST' });
        return;
      }
      await this.handleComplete(req, res, spkiPin);
      return;
    }

    if (pathOnly === MCP_PATH) {
      const surface = this.mcpSurface;
      if (surface === undefined) {
        // Deny-only placeholder. With no composed transport attached, no `/mcp`
        // request may create a transport or session, issue a token, reach
        // policy, or dispatch a tool. A body carrying enrollment fields changes
        // nothing: this branch never reads the body.
        this.send(res, 401, UNAUTHENTICATED_BODY);
        return;
      }
      // The identity is resolved from the CURRENT authoritative trust store on
      // every request, exactly as the completion path does, so a device revoked
      // between two MCP requests stops resolving immediately.
      await surface.handle(req, res, spkiPin, this.resolveActiveDeviceIdentity(spkiPin));
      return;
    }

    // Unknown paths are refused without reading the body or touching any state.
    this.send(res, 404, NOT_FOUND_BODY);
  }

  private async handleComplete(
    req: IncomingMessage,
    res: ServerResponse,
    spkiPin: string,
  ): Promise<void> {
    // Fail closed BEFORE any work: once durable storage is uncertain, the
    // gateway stops attempting completions entirely rather than repeatedly
    // writing against an authentication root it cannot vouch for. The response
    // is the same uniform body, so nothing about the storage state escapes.
    if (this.storageLatched) {
      this.failClosed(res);
      return;
    }

    let body: string;
    try {
      body = await readBoundedRequestBody(req, {
        maxBytes: MAX_ENROLL_BODY_BYTES,
        ...(this.bodyReadTimeoutMsForTests === undefined
          ? {}
          : { bodyReadTimeoutMsForTests: this.bodyReadTimeoutMsForTests }),
      });
    } catch (err: unknown) {
      if (err instanceof RequestBodyError) {
        if (err.kind === 'PAYLOAD_TOO_LARGE' || err.kind === 'UNSUPPORTED_CONTENT_ENCODING') {
          // Oversized or compressed bootstrap requests are refused before the
          // enrollment manager is reached, so no attempt is counted and no
          // state changes. A compressed request is refused under the same
          // bounded payload response, whatever its decoded size would be.
          this.send(res, 413, PAYLOAD_TOO_LARGE_BODY);
          return;
        }
        if (err.kind === 'READ_TIMEOUT') {
          // The reader already aborted the request and destroyed the socket:
          // there is no complete request and no connection left to answer on.
          return;
        }
      }
      this.failClosed(res);
      return;
    }

    const secret = extractSecret(body);
    if (secret === null) {
      // Malformed JSON, a non-object, a missing secret, or a secret of the
      // wrong type are all the same bounded failure as a wrong secret.
      this.failClosed(res);
      return;
    }

    // ONE synchronous transaction: verify -> build candidate -> persist ->
    // swap authoritative state -> consume. `completeBySpki` removes the pending
    // challenge only after the commit callback returns normally, and there is
    // no await between verification and commit, so two concurrent requests for
    // the same challenge cannot both observe it as live.
    const outcome = this.enrollmentManager.completeBySpki(spkiPin, secret, (challenge) => {
      this.activateDevice(challenge);
    });

    if (!outcome.ok) {
      this.failClosed(res);
      return;
    }

    this.send(res, 200, ENROLLED_BODY);
  }

  /**
   * Durable activation of one device.
   *
   * Runs INSIDE the verification transaction and is fully synchronous, so no
   * other request can interleave between a verified proof and its commit.
   *
   * The authoritative in-memory store is never mutated directly: a candidate is
   * built from a snapshot, persisted, and only then swapped in.
   *
   * A throw from this method propagates to `completeBySpki`, which converts it
   * into ACTIVATION_FAILED without consuming the challenge — so the contract
   * this method owes its caller is: on ANY throw, the destination trust store is
   * back at the pre-transaction state, or the fail-closed latch is set.
   */
  private activateDevice(challenge: PendingEnrollmentView): void {
    const before = this.authoritativeTrustStore.toData();
    const candidate = DeviceTrustStore.fromData(before);
    // Duplicate-enrollment semantics are Task-1's (§8): the same pin under the
    // same clientId reuses the existing deviceId, and a pin already bound to a
    // different clientId fails closed here, before anything is persisted.
    candidate.enrollDevice({
      clientId: challenge.clientId,
      clientType: challenge.clientType,
      pin: challenge.spkiPin,
      displayLabel: challenge.displayLabel,
    });

    try {
      this.storage.save(candidate, this.trustStorePath);
    } catch {
      // A reported failure does NOT mean the destination is unchanged.
      //
      // Task-1 persistence renames the temporary file over the destination and
      // only THEN opens and fsyncs the parent directory, propagating an
      // operational open/fsync failure at that point. A save can therefore
      // throw while the destination already holds the candidate, which would
      // leave a device enrolled on disk after a failed HTTP request and
      // diverge from the authoritative in-memory state.
      //
      // Reconcile before reporting the activation as retryable.
      this.restorePreTransactionState(before);
      throw new Error('Enrollment activation could not be persisted.');
    }

    // Only now does the new state become authoritative.
    this.authoritativeTrustStore = candidate;
  }

  /**
   * Proves the destination trust store is back at the pre-transaction state.
   *
   * Compares VALIDATED trust-store state through the Task-1 loader, never file
   * existence: a rename that landed and a rename that never happened are
   * indistinguishable to `existsSync`, and only the loader can say what the
   * authentication root actually contains.
   *
   * If the pre-transaction state is already present, there is nothing to undo.
   * Otherwise the snapshot is written back through the same persistence path and
   * then re-read AND re-compared. If any step of that fails, or the comparison
   * still disagrees, the latch is set: the gateway must not keep serving
   * completions against a trust store it cannot vouch for.
   */
  private restorePreTransactionState(before: DeviceTrustStoreData): void {
    const expected = trustStateFingerprint(DeviceTrustStore.fromData(before));

    let installed: string;
    try {
      installed = trustStateFingerprint(this.storage.load(this.trustStorePath));
    } catch {
      // The destination cannot even be read and validated, so its contents are
      // unknown. Nothing can be proven restored.
      this.storageLatched = true;
      return;
    }

    if (installed === expected) {
      // The candidate never reached the destination: the pre-transaction state
      // is intact and the operation is cleanly retryable.
      return;
    }

    // The candidate (or some other state) reached the destination. Restore the
    // snapshot through trusted persistence, then VERIFY by reloading.
    try {
      this.storage.save(DeviceTrustStore.fromData(before), this.trustStorePath);
    } catch {
      this.storageLatched = true;
      return;
    }

    try {
      const restored = trustStateFingerprint(this.storage.load(this.trustStorePath));
      if (restored !== expected) {
        // A write reported success but the destination still disagrees: the
        // authentication root is not provably back to its prior state.
        this.storageLatched = true;
      }
    } catch {
      this.storageLatched = true;
    }
  }

  private failClosed(res: ServerResponse): void {
    this.send(res, 400, ENROLLMENT_FAILED_BODY);
  }

  /**
   * Writes one bounded response and terminates the connection.
   *
   * Every bootstrap response is terminal: the endpoint creates no session and
   * no durable HTTP connection, so `Connection: close` is set on every path.
   */
  private send(
    res: ServerResponse,
    statusCode: number,
    body: string,
    extraHeaders: Record<string, string> = {},
  ): void {
    if (res.headersSent || res.writableEnded) {
      res.destroy();
      return;
    }
    res.statusCode = statusCode;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Length', Buffer.byteLength(body, 'utf8'));
    res.setHeader('Connection', 'close');
    for (const [name, value] of Object.entries(extraHeaders)) {
      res.setHeader(name, value);
    }
    // `Connection: close` is what actually terminates the exchange: the HTTP
    // server ends the socket once the response is flushed and never serves a
    // second request on it, so the bootstrap endpoint is a one-shot exchange
    // with no durable session and no keep-alive reuse.
    res.end(body);
  }
}

/**
 * The bounded body reader now lives in `remote-request-bounds.ts` as
 * `readBoundedRequestBody`, shared with every future remote body-reading
 * endpoint. Enrollment calls it with its own internal 4096-byte bound
 * ({@link MAX_ENROLL_BODY_BYTES}), which keeps this endpoint's stricter Task-4
 * ceiling exactly as it was while the generic 4 MiB mechanism is implemented and
 * tested once.
 */

/**
 * Extracts the one-time secret from the CLOSED bootstrap schema.
 *
 * The frozen body contract is exactly `{"secret":"..."}` and nothing else. The
 * parser therefore accepts a JSON object whose ONLY own enumerable key is
 * `secret`, whose value is a string of any content.
 *
 * Returns null — a schema failure — for anything else: malformed JSON, a
 * non-object, an array, a missing `secret` own property, a non-string `secret`
 * (number, null, array, object, boolean), or ANY additional field such as
 * enrollmentId, spkiPin, clientId, clientType, deviceId, or operatorId.
 *
 * A schema failure is decided HERE and never reaches the enrollment verifier, so
 * it spends no failed attempt. Identity fields are not merely ignored; a body
 * carrying one is rejected outright, and no identity is ever read from a body.
 *
 * The submitted string is returned VERBATIM — including the empty string, short
 * strings, uppercase, and non-hex — so that Task-2 remains the single owner of
 * secret validity: its regex, dummy digest, SHA-256, `timingSafeEqual`,
 * failed-attempt increment, and third-attempt purge. Re-checking the shape here
 * would silently exempt malformed submissions from the lockout counters.
 */
export function extractSecret(body: string): string | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return null;
  }
  const record = parsed as Record<string, unknown>;
  if (!Object.prototype.hasOwnProperty.call(record, 'secret')) {
    return null;
  }
  const keys = Object.keys(record);
  if (keys.length !== 1 || keys[0] !== 'secret') {
    return null;
  }
  const secret = record.secret;
  if (typeof secret !== 'string') {
    return null;
  }
  return secret;
}

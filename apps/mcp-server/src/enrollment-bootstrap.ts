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
import {
  DeviceTrustStore,
  type EnrollmentManager,
  type PendingEnrollmentView,
} from '@cesspace-arc/auth';

/** The only path that can attempt enrollment completion. */
export const ENROLL_COMPLETE_PATH = '/enroll/complete';

/** The MCP path. Deny-only until the later transport tasks. */
export const MCP_PATH = '/mcp';

/**
 * Maximum raw request body for the bootstrap endpoint, in bytes (Task 4 §6).
 *
 * Deliberately NOT the later Task-7 global 4 MiB MCP bound: bootstrap carries
 * one 64-character secret, so 4 KiB is already generous. Enforced while reading
 * the raw body, before any JSON parsing.
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
 * Trust-store persistence seam.
 *
 * The default is the Task-1 atomic persistence used by `DeviceTrustStore.saveToFile`.
 * A test replaces it to inject a durable-write failure.
 *
 * @internal Reachable ONLY through an internal option object constructed by a
 * test. It is deliberately absent from ArcServerConfig, RemoteConfig, the
 * environment, and every network-reachable surface, so no launch configuration
 * and no request can weaken or bypass durable persistence.
 */
export interface TrustStoreWriter {
  save(store: DeviceTrustStore, filePath: string): void;
}

/** @internal Internal seams for the bootstrap controller. */
export interface EnrollmentBootstrapOptions {
  /**
   * @internal Test-only durable-write injection. Defaults to Task-1 atomic
   * persistence. Never populated from configuration, environment, or a request.
   */
  trustStoreWriterForTests?: TrustStoreWriter;
}

/** Controller driving one gateway's bootstrap HTTP surface. */
export class EnrollmentBootstrap {
  private readonly writer: TrustStoreWriter;

  constructor(
    private readonly enrollmentManager: EnrollmentManager,
    private authoritativeTrustStore: DeviceTrustStore,
    private readonly trustStorePath: string,
    options: EnrollmentBootstrapOptions = {},
  ) {
    this.writer = options.trustStoreWriterForTests ?? {
      save: (store, filePath) => store.saveToFile(filePath),
    };
  }

  /** Enrolled device count, for bounded reporting. Never a device list. */
  public getEnrolledDeviceCount(): number {
    return this.authoritativeTrustStore.getDeviceCount();
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
      // Deny-only placeholder. Task 8 owns Streamable HTTP composition; until
      // then no `/mcp` request may create a transport or session, issue a
      // token, reach policy, or dispatch a tool. A body carrying enrollment
      // fields changes nothing: this branch never reads the body.
      this.send(res, 401, UNAUTHENTICATED_BODY);
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
    let body: string;
    try {
      body = await readBoundedBody(req, MAX_ENROLL_BODY_BYTES);
    } catch (err: unknown) {
      if (err instanceof BodyTooLargeError) {
        // Oversized bootstrap requests are refused before the enrollment
        // manager is reached, so no attempt is counted and no state changes.
        this.send(res, 413, PAYLOAD_TOO_LARGE_BODY);
        return;
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
   * built from a snapshot, persisted, and only then swapped in. A throw from any
   * step leaves the authoritative store, the file, and the pending challenge
   * exactly as they were.
   */
  private activateDevice(challenge: PendingEnrollmentView): void {
    const snapshot = this.authoritativeTrustStore.toData();
    const candidate = DeviceTrustStore.fromData(snapshot);
    // Duplicate-enrollment semantics are Task-1's (§8): the same pin under the
    // same clientId reuses the existing deviceId, and a pin already bound to a
    // different clientId fails closed here, before anything is persisted.
    candidate.enrollDevice({
      clientId: challenge.clientId,
      clientType: challenge.clientType,
      pin: challenge.spkiPin,
      displayLabel: challenge.displayLabel,
    });

    // Durable first. A throw here propagates to completeBySpki, which converts
    // it into ACTIVATION_FAILED without consuming the challenge.
    this.writer.save(candidate, this.trustStorePath);

    // Only now does the new state become authoritative.
    this.authoritativeTrustStore = candidate;
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

/** @internal Raised internally when the bootstrap body exceeds its bound. */
class BodyTooLargeError extends Error {
  constructor() {
    super('Bootstrap request body exceeds the maximum size.');
    this.name = 'BodyTooLargeError';
  }
}

/**
 * Reads the raw body with a hard byte ceiling enforced DURING the read.
 *
 * A declared Content-Length above the bound is refused immediately, and a
 * chunked body is aborted as soon as the cumulative size exceeds it, so an
 * oversized request can never be fully buffered or parsed.
 */
export function readBoundedBody(req: IncomingMessage, maxBytes: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const declared = req.headers['content-length'];
    if (typeof declared === 'string' && declared.length > 0) {
      const declaredBytes = Number.parseInt(declared, 10);
      if (Number.isFinite(declaredBytes) && declaredBytes > maxBytes) {
        reject(new BodyTooLargeError());
        return;
      }
    }

    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;

    const cleanup = () => {
      req.removeListener('data', onData);
      req.removeListener('end', onEnd);
      req.removeListener('error', onError);
    };
    const onData = (chunk: Buffer) => {
      if (settled) {
        return;
      }
      total += chunk.length;
      if (total > maxBytes) {
        settled = true;
        cleanup();
        reject(new BodyTooLargeError());
        return;
      }
      chunks.push(chunk);
    };
    const onEnd = () => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      resolve(Buffer.concat(chunks).toString('utf8'));
    };
    const onError = () => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      // The underlying cause is deliberately discarded: a stream error can
      // carry peer-controlled text, and the caller only needs "no usable body".
      reject(new Error('Request stream failed.'));
    };

    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', onError);
  });
}

/**
 * Extracts the one-time secret from the closed bootstrap schema.
 *
 * Returns null for anything that is not a JSON object carrying a usable
 * `secret` string. Any other field — enrollmentId, spkiPin, clientId,
 * clientType, deviceId, operatorId — is ignored and can never influence
 * selection or activation.
 *
 * The submitted value is returned verbatim (it is NOT validated to the 64-hex
 * shape here) so that a malformed secret still reaches Task-2's constant-time
 * dummy-digest path and is counted exactly like any other wrong secret.
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
  const secret = (parsed as Record<string, unknown>).secret;
  if (typeof secret !== 'string' || secret.length === 0) {
    return null;
  }
  return secret;
}

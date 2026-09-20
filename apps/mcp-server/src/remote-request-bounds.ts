/**
 * CesSpace ARC — RC-05 Task 7 Request-Level Bounds
 *
 * The §20 half of Task 7: the generic request-body ceiling, the request-target
 * bound, the compressed-request refusal, and the request deadlines — everything
 * that is enforced against an in-flight HTTP request.
 *
 * Authoritative contract: §20, and controls RC05-NEG-60 and RC05-NEG-61.
 *
 * Scope boundary — BOUNDS ONLY: nothing here makes a policy decision, evaluates
 * a rule, redeems an approval, or calls a subsystem. Nothing here speaks MCP.
 *
 * Every production number is a module constant. None of them is reachable from
 * `ArcServerConfig`, `RemoteConfig`, the environment, the CLI, HTTP, MCP, or
 * JSON: a launch configuration cannot weaken a frozen bound. The only seam is an
 * internal one that can SHORTEN a deadline for deterministic tests.
 *
 * This module is separate from `remote-resource-limits.ts` so that pure limiter
 * accounting stays free of any request or timer machinery: the remote execution
 * bridge depends on the accounting module only.
 */

import type { IncomingMessage } from 'node:http';

/**
 * Frozen generic remote message-body ceiling: 4 MiB exactly.
 *
 * Measured on RAW received bytes — before JSON parsing, decoding, MCP parsing,
 * or policy — and enforced DURING the read, so an oversized request is never
 * fully buffered and no partial content can reach a parser.
 *
 * The enrollment endpoint keeps its own stricter 4 KiB ceiling and calls the
 * shared reader with that internal bound. No launch configuration, request, or
 * environment value can choose either number.
 */
export const MAX_REMOTE_BODY_BYTES = 4_194_304;

/**
 * Frozen total request header block ceiling: 16 KiB.
 *
 * Enforced at the Node HTTP/HTTPS PARSER boundary, so an oversized header block
 * is refused before the request handler exists and no second unbounded copy of
 * the headers is ever made in order to measure it.
 */
export const MAX_REQUEST_HEADER_BYTES = 16 * 1024;

/** Frozen request-target (URL) ceiling: 2 KiB, measured before routing. */
export const MAX_REQUEST_TARGET_BYTES = 2 * 1024;

/**
 * Frozen header-read deadline: 10 s — an incomplete header block is aborted.
 *
 * This is the slowloris bound for the HEADER phase, and it is deliberately the
 * same 10 s as the body-read deadline: a peer that trickles a request line, a
 * header name, or a header terminator gets exactly one 10 s window in which to
 * deliver a complete header block, whichever half of the request it is stalling.
 *
 * It is enforced by Node's HTTP parser as `headersTimeout`, so it runs BEFORE a
 * complete request exists: an incomplete header block is refused and its socket
 * destroyed without the request ever reaching a handler. The body-read deadline
 * cannot cover this case, because the body reader is not constructed until the
 * header block has already completed.
 *
 * `headersTimeout` is not self-arming: Node evaluates it from a periodic
 * connections checker, so the value alone does not decide when a stalled header
 * block is aborted. {@link HEADER_READ_CHECK_INTERVAL_MS} bounds that
 * granularity, and both values are supplied to the server together.
 */
export const HEADER_READ_TIMEOUT_MS = 10_000;

/**
 * Frozen granularity of Node's connections checker: 1 s.
 *
 * Node does NOT arm a per-socket timer for `headersTimeout`. It evaluates the
 * deadline from a periodic sweep, so an incomplete header block is aborted at
 * the first sweep AFTER the deadline — never at the deadline itself. With Node's
 * own default sweep interval (30 s) a frozen 10 s `headersTimeout` would not be
 * enforced until roughly 30-40 s, which is not the 10 s slowloris boundary.
 *
 * Supplying this as the sweep interval makes the 10 s bound real: an incomplete
 * header block is aborted at 10 s plus at most one 1 s sweep — an order of
 * magnitude below the 60 s total request deadline it must never reach.
 *
 * It is a CHECK GRANULARITY, not a deadline: it never extends the header-read
 * deadline, and lowering it cannot raise any bound.
 */
export const HEADER_READ_CHECK_INTERVAL_MS = 1_000;

/** Frozen body-read deadline: 10 s — a body that has not fully arrived is aborted. */
export const BODY_READ_TIMEOUT_MS = 10_000;

/**
 * Frozen total request deadline: 60 s.
 *
 * Distinct from the 5 s TLS handshake deadline, the 10 s header-read deadline,
 * and the 10 s body-read deadline. It bounds the WHOLE request — parser,
 * routing, and handler — and is armed at HTTP request admission.
 *
 * It is never a substitute for either 10 s deadline: a slowloris stalled in the
 * header phase is aborted at 10 s by {@link HEADER_READ_TIMEOUT_MS}, not at 60 s.
 */
export const TOTAL_REQUEST_TIMEOUT_MS = 60_000;

/** Why a request body was refused or abandoned. Bounded and non-secret. */
export type BodyRefusalKind =
  'PAYLOAD_TOO_LARGE' | 'UNSUPPORTED_CONTENT_ENCODING' | 'READ_TIMEOUT' | 'STREAM_FAILED';

/**
 * A bounded-body failure.
 *
 * Carries a fixed kind and a fixed message. It never carries the received bytes,
 * the declared length, the offending encoding, or any peer-supplied text.
 */
export class RequestBodyError extends Error {
  constructor(public readonly kind: BodyRefusalKind) {
    super('Request body could not be read within its bounds.');
    this.name = 'RequestBodyError';
  }
}

/** Count of body-read deadlines currently armed. @internal Test-visible only. */
let activeBodyReadDeadlines = 0;

/**
 * @internal Live body-read deadline count.
 *
 * Proves that an aborted or completed read releases its deadline, so a stalled
 * request cannot leave a timer behind. Never part of a response or a status.
 */
export function getActiveBodyReadDeadlineCountForTests(): number {
  return activeBodyReadDeadlines;
}

/**
 * Resolves the body-read deadline, applying the internal test seam.
 *
 * Production always resolves the frozen {@link BODY_READ_TIMEOUT_MS}. The seam
 * may only SHORTEN it: a longer value is ignored, so no test, configuration, or
 * request can weaken the slowloris bound.
 */
export function resolveBodyReadTimeoutMs(bodyReadTimeoutMsForTests?: number): number {
  return resolveShortenedDeadline(bodyReadTimeoutMsForTests, BODY_READ_TIMEOUT_MS);
}

/**
 * Resolves the header-read deadline, applying the internal test seam.
 *
 * Production always resolves the frozen {@link HEADER_READ_TIMEOUT_MS}. The seam
 * may only SHORTEN it: a value at or above the frozen 10 s — and any value that
 * is not a positive integer — resolves to the frozen bound, so no test,
 * configuration, environment variable, or request can widen the slowloris window.
 */
export function resolveHeaderReadTimeoutMs(headerReadTimeoutMsForTests?: number): number {
  return resolveShortenedDeadline(headerReadTimeoutMsForTests, HEADER_READ_TIMEOUT_MS);
}

/**
 * Resolves the sweep granularity Node uses to enforce the header-read deadline.
 *
 * ALWAYS at most {@link HEADER_READ_CHECK_INTERVAL_MS}, and never longer than the
 * resolved header-read deadline: a checker that swept less often than the
 * deadline it enforces would let the bound slip. Deriving it from the resolved
 * deadline is what keeps a shortened test seam fast — the sweep must tighten
 * with the deadline, or a shortened deadline would still wait out a full 1 s.
 */
export function resolveHeaderReadCheckIntervalMs(headerReadTimeoutMs: number): number {
  return Math.min(headerReadTimeoutMs, HEADER_READ_CHECK_INTERVAL_MS);
}

/**
 * The ONE place "a seam may only shorten a frozen deadline" is decided.
 *
 * Both request-phase deadlines resolve through here, so the shorten-only rule
 * cannot drift between them.
 */
function resolveShortenedDeadline(seam: number | undefined, frozenMs: number): number {
  return typeof seam === 'number' && Number.isInteger(seam) && seam > 0 && seam < frozenMs
    ? seam
    : frozenMs;
}

/** Inputs for one bounded read. The bound is INTERNAL; a client cannot choose it. */
export interface ReadBoundedBodyOptions {
  /**
   * The applicable ceiling for THIS endpoint, supplied by server code:
   * `MAX_ENROLL_BODY_BYTES` (4096) for enrollment completion,
   * `MAX_REMOTE_BODY_BYTES` (4,194,304) for a generic remote message body.
   */
  maxBytes: number;
  /** @internal Test-only deadline seam. May only shorten the frozen 10 s. */
  bodyReadTimeoutMsForTests?: number;
}

/**
 * Reads a request body with a hard byte ceiling enforced DURING the read (§20).
 *
 * Semantics:
 * - `Content-Encoding` is refused outright. Baseline supports no compressed
 *   request, and nothing here decodes gzip, br, or deflate — not even
 *   `identity` — so no decompression path exists to be bombed.
 * - A declared `Content-Length` above the bound is refused before any body byte
 *   is buffered. It is a cheap early exit, never the enforcement: the cumulative
 *   received bytes are still measured below, because a declared length is
 *   client-controlled and may be absent, wrong, or chunked away.
 * - A chunked body is aborted the moment the cumulative total crosses the bound,
 *   so an oversized request is never fully buffered and no parser, policy
 *   evaluation, or subsystem can observe partial content.
 * - A body that has not fully arrived by the monotonic deadline is aborted: the
 *   request is destroyed, so the connection cannot be held open indefinitely
 *   (slowloris). Buffers, listeners, and the deadline are released on every
 *   path — success, refusal, timeout, stream error, and terminal `close` after an
 *   abort or a peer that vanished mid-body alike.
 */
export function readBoundedRequestBody(
  req: IncomingMessage,
  options: ReadBoundedBodyOptions,
): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const maxBytes = options.maxBytes;

    // §20: any request carrying Content-Encoding is unsupported in baseline.
    // Refused before a single byte is read.
    const encoding = req.headers['content-encoding'];
    if (typeof encoding === 'string' && encoding.length > 0) {
      reject(new RequestBodyError('UNSUPPORTED_CONTENT_ENCODING'));
      return;
    }

    const declared = req.headers['content-length'];
    if (typeof declared === 'string' && declared.length > 0) {
      const declaredBytes = Number.parseInt(declared, 10);
      if (Number.isFinite(declaredBytes) && declaredBytes > maxBytes) {
        reject(new RequestBodyError('PAYLOAD_TOO_LARGE'));
        return;
      }
    }

    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    let deadline: NodeJS.Timeout | undefined;

    const cleanup = () => {
      req.removeListener('data', onData);
      req.removeListener('end', onEnd);
      req.removeListener('error', onError);
      req.removeListener('close', onClose);
      if (deadline !== undefined) {
        clearTimeout(deadline);
        deadline = undefined;
        activeBodyReadDeadlines -= 1;
      }
    };

    const onData = (chunk: Buffer) => {
      if (settled) {
        return;
      }
      total += chunk.length;
      if (total > maxBytes) {
        settled = true;
        // STOP reading at the crossing point. Nothing beyond the bound is
        // buffered, and the partial content is discarded with the reader.
        cleanup();
        reject(new RequestBodyError('PAYLOAD_TOO_LARGE'));
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
      // The underlying cause is discarded: a stream error can carry
      // peer-controlled text, and the caller only needs "no usable body".
      reject(new RequestBodyError('STREAM_FAILED'));
    };
    /**
     * Terminal stream event, whatever the reason.
     *
     * `close` fires after `end` on a complete request, and on an ABORTED request
     * it is the only terminal event — the peer vanished, the socket was
     * destroyed by the total-request deadline, or the connection was reset. It
     * exists so that every abort releases the listeners, the buffered chunks, and
     * the deadline IMMEDIATELY rather than leaving a timer to expire later: a
     * stalled or vanished peer must not retain anything.
     */
    const onClose = () => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      reject(new RequestBodyError('STREAM_FAILED'));
    };

    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', onError);
    req.on('close', onClose);

    // The deadline is armed LAST, so every handler it may run against is already
    // defined and the listener set is already installed.
    deadline = setTimeout(() => {
      if (settled) {
        return;
      }
      settled = true;
      // §20: a body that has not fully arrived is aborted, not answered: there
      // is no complete request to respond to, and the socket must not be held
      // open. Listeners are removed before destroying so the abort cannot
      // re-enter this reader.
      cleanup();
      req.destroy();
      reject(new RequestBodyError('READ_TIMEOUT'));
    }, resolveBodyReadTimeoutMs(options.bodyReadTimeoutMsForTests));
    activeBodyReadDeadlines += 1;
  });
}

/**
 * Byte length of the received request target.
 *
 * Node's HTTP parser decodes the request line as latin1, so one JavaScript code
 * unit is one wire byte and the bound is measured on the received representation
 * exactly as §20 requires. The check is O(1) and runs before any routing, so no
 * query string is ever parsed in order to discover that it is too long.
 */
export function requestTargetBytes(url: string | undefined): number {
  return typeof url === 'string' ? url.length : 0;
}

/** True when the request declares a content encoding, whatever the value is. */
export function hasContentEncoding(req: IncomingMessage): boolean {
  const encoding = req.headers['content-encoding'];
  return typeof encoding === 'string' && encoding.length > 0;
}

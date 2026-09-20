/**
 * CesSpace ARC — RC-05 Task 8 Gateway Request Authority
 *
 * THE ONE Host (`§10`) and Origin (`§11`) authority check for the remote HTTP
 * surface, shared by every configured remote endpoint.
 *
 * It exists as one module because the check has to be applied at the GATEWAY
 * boundary, before endpoint-specific processing, and applied identically to
 * `/mcp` and `/enroll/complete`. A second copy of this logic — one inside the
 * MCP surface and one inside the enrollment bootstrap — is exactly how two
 * endpoints drift apart, so both call {@link checkRequestAuthority} and neither
 * owns a private variant.
 *
 * Position in the request path: this module runs AFTER every Task-3/4/7 ingress
 * control the gateway already enforces (mTLS admission, Layer A, Layer B, the
 * header-read deadline, the request-target bound, and the compressed-request
 * refusal) and BEFORE any endpoint reads a body, verifies an enrollment proof,
 * looks up a session, or parses MCP. It can only ever REFUSE further.
 *
 * Design rules:
 * - One authority header. Only the `Host` header Node's own parser produced is
 *   consulted. `X-Forwarded-Host`, `Forwarded`, `X-Real-Host`, and every other
 *   forwarding header are never read: ARC has no reverse-proxy trust model, so
 *   a forwarded name can never substitute for the real one.
 * - Origin is default-deny, unconditionally. The value is never parsed, never
 *   compared against a list, never folded into an allow-list, and never
 *   reflected. No response on any path carries `Access-Control-Allow-Origin`,
 *   so no browser origin is granted access and no preflight can be satisfied.
 * - Both refusals are byte-identical bounded bodies, so a caller cannot use the
 *   response to tell "browser origin" from "wrong host".
 */

import type { IncomingHttpHeaders, ServerResponse } from 'node:http';

/**
 * §10: the request did not present the configured public hostname.
 *
 * A fixed, bounded body: it names no configuration value, no peer, and no
 * reason beyond the status code.
 */
export const HOST_REFUSED_BODY = JSON.stringify({ error: 'Forbidden' });

/**
 * §11: every request carrying an `Origin` header is refused by default.
 *
 * Byte-identical to the Host refusal on purpose — see the module header.
 */
export const ORIGIN_REFUSED_BODY = HOST_REFUSED_BODY;

/** The closed set of request-authority refusals. */
export type RequestAuthorityRefusal = 'HOST_REFUSED' | 'ORIGIN_REFUSED';

/**
 * True when a value holds any C0 control character or DEL.
 *
 * Written as an explicit code-point scan rather than a control-character
 * regular expression, so the check is plainly readable and needs no lint
 * suppression.
 */
function hasControlCharacters(value: string): boolean {
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) {
      return true;
    }
  }
  return false;
}

/**
 * Normalizes a `Host` header to a bare lowercase hostname, or null when the
 * value cannot be a single well-formed host.
 *
 * A port is allowed and ignored: the listener's port is not a security boundary,
 * and testing and production bind different ones. An IPv6 literal keeps its
 * brackets stripped. Whitespace, control characters, and comma-separated
 * multiple values are refused outright rather than parsed, so a malformed or
 * smuggled `Host` fails closed instead of being reinterpreted.
 */
export function normalizeHostHeader(raw: unknown): string | null {
  if (typeof raw !== 'string') {
    return null;
  }
  const value = raw.trim();
  if (
    value.length === 0 ||
    /\s/.test(value) ||
    hasControlCharacters(value) ||
    value.includes(',')
  ) {
    return null;
  }
  if (value.startsWith('[')) {
    const end = value.indexOf(']');
    if (end === -1) {
      return null;
    }
    const rest = value.slice(end + 1);
    if (rest.length > 0 && !/^:\d+$/.test(rest)) {
      return null;
    }
    return value.slice(1, end).toLowerCase();
  }
  const colon = value.indexOf(':');
  if (colon === -1) {
    return value.toLowerCase();
  }
  if (!/^\d+$/.test(value.slice(colon + 1))) {
    return null;
  }
  return value.slice(0, colon).toLowerCase();
}

/**
 * Applies the Host and Origin authority rules to ONE request.
 *
 * Returns the refusal, or null when the request may proceed. The Host rule is
 * evaluated first so a request that is wrong on BOTH counts is refused as a
 * Host failure, but since the two bodies are identical this ordering is not
 * observable to the caller.
 */
export function checkRequestAuthority(
  headers: IncomingHttpHeaders,
  publicHostname: string,
): RequestAuthorityRefusal | null {
  if (normalizeHostHeader(headers.host) !== publicHostname.toLowerCase()) {
    return 'HOST_REFUSED';
  }
  if (headers.origin !== undefined) {
    return 'ORIGIN_REFUSED';
  }
  return null;
}

/**
 * Writes one bounded JSON refusal and terminates the connection.
 *
 * The `Content-Type` is fixed JSON and the body is a fixed byte string: nothing
 * derived from the peer, the `Host`, or the `Origin` is echoed, and no CORS
 * header is emitted on any path.
 */
export function writeAuthorityRefusal(res: ServerResponse, refusal: RequestAuthorityRefusal): void {
  const body = refusal === 'HOST_REFUSED' ? HOST_REFUSED_BODY : ORIGIN_REFUSED_BODY;
  if (res.headersSent || res.writableEnded) {
    res.destroy();
    return;
  }
  res.writeHead(403, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
    Connection: 'close',
  });
  res.end(body);
}

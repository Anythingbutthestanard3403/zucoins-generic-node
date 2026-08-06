// the auth-errors/route-policy concern.1 — The non-oracularity predicate, as a pure verifier.
//
// Two responses are INDISTINGUISHABLE when, after normalizing the per-request `request_id`
// to the canonical placeholder, they carry the identical HTTP status, the identical
// client-visible header set, and byte-identical body. The contract's guarantee: for any two
// failure states in the same collapse class (e.g. valid-key-wrong-scope vs unknown-key), the
// responses must be indistinguishable — otherwise the response is an existence or scope oracle.
// The header dimension is load-bearing: two 401s differing only in `WWW-Authenticate:
// error="invalid_token"` vs `error="insufficient_scope"` are exactly the RFC 6750 scope oracle
// the frozen error vocabulary closes, and a status+body-only comparison is blind to it. The credential/error
// matrix consumes this verifier to prove the guarantee across every state.
//
// Canonical: the frozen error vocabulary.

import { REQUEST_ID_PLACEHOLDER } from "./envelope.js";

export interface WireResponse {
  readonly status: number;
  readonly body: string;
  // Client-visible response headers, if modeled. Field NAMES compare case-insensitively (RFC
  // 7230); field VALUES compare byte-exact. Omitting the field models an empty header set. The
  // frozen v2 auth-error responses carry the constant CANONICAL_AUTH_ERROR_HEADERS (envelope.ts)
  // — deliberately no `WWW-Authenticate` challenge (CONTRACT J3).
  readonly headers?: Readonly<Record<string, string>>;
}

const REQUEST_ID_FIELD =
  /("request_id":")[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(")/;

// Replace whatever `request_id` a real response carries with the canonical placeholder, so
// the sole legitimately-varying field is neutralized before comparison. Operates on the
// exact body bytes; it never parses and re-serializes (which could mask a key-sequence or
// whitespace oracle — the byte-exact signing rule). Matches a lowercase-canonical UUID in the frozen
// `"request_id":"<uuid>"` position only ("UUIDs use lowercase canonical textual form").
export function normalizeRequestId(body: string): string {
  return body.replace(REQUEST_ID_FIELD, `$1${REQUEST_ID_PLACEHOLDER}$2`);
}

// Canonicalize a response's header set for non-oracular comparison. Field names are lowercased
// (RFC 7230: header field names are case-insensitive), then the name→value pairs are emitted in
// ascending-name sequence as an injective JSON string. Comparison is sequence-independent (HTTP does
// not make header sequence significant and intermediaries reorder it) but FAIL-CLOSED on the set:
// any field present in one response and not the other, or any value difference, changes the
// string. No value is neutralized — unlike the body's `request_id`, the frozen v2 auth-error
// contract has NO per-request response header (`request_id` is body-only) and emits no
// `WWW-Authenticate`, so nothing legitimately varies. A future response header that legitimately
// varies per request must be neutralized HERE with a shape-guarded rule mirroring
// `normalizeRequestId`, never silently dropped from the comparison (dropping = a new oracle hole).
export function canonicalizeHeaders(headers?: Readonly<Record<string, string>>): string {
  if (!headers) return "[]";
  const byLowerName = new Map<string, string>();
  for (const [name, value] of Object.entries(headers)) {
    byLowerName.set(name.toLowerCase(), value);
  }
  const pairs = [...byLowerName.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return JSON.stringify(pairs);
}

// True iff the two responses are indistinguishable modulo `request_id`: identical HTTP status,
// identical client-visible header set (fail-closed), and byte-identical body after normalizing
// the per-request `request_id`.
export function indistinguishable(a: WireResponse, b: WireResponse): boolean {
  if (a.status !== b.status) return false;
  if (canonicalizeHeaders(a.headers) !== canonicalizeHeaders(b.headers)) return false;
  return normalizeRequestId(a.body) === normalizeRequestId(b.body);
}

// Scan a collapse-class group and return the index of the first response that is
// distinguishable from the group's first — i.e. the first oracle leak — or -1 when the whole
// group is non-oracular. A caller feeds the responses for every failure state in one class
// and requires -1.
export function firstOracleDivergence(group: readonly WireResponse[]): number {
  if (group.length <= 1) return -1;
  const head = group[0];
  for (let i = 1; i < group.length; i += 1) {
    if (!indistinguishable(head, group[i])) return i;
  }
  return -1;
}

// True iff every response in the group is indistinguishable from the first.
export function isNonOracular(group: readonly WireResponse[]): boolean {
  return firstOracleDivergence(group) === -1;
}

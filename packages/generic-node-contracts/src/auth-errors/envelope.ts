// the auth-errors/route-policy concern.1 — Frozen v2 error-envelope shape and the byte-exact wire bodies for the two
// non-oracular auth-error responses.
//
// The wire error envelope. The byte-exact signing rule: the wire body is
// byte-exact `JSON.stringify` with EXPLICIT key insertion sequence; it is never reformatted,
// reordered, or prettified. The sequence below — error → {code, message, request_id, details} —
// is the frozen sequence and matches the canonical envelope example verbatim.

import { CANONICAL_AUTH_FAILURE_CODE, CANONICAL_NOT_FOUND_CODE } from "./codes.js";

// The frozen field sequence of the inner error object (the frozen byte sequence the signing rule protects).
export const ERROR_ENVELOPE_FIELD_ORDER = ["code", "message", "request_id", "details"] as const;

// The canonical placeholder `request_id` used by the frozen golden bodies. A real response
// substitutes a per-request UUID here; every other byte is frozen. The non-oracularity
// verifier normalizes `request_id` back to this placeholder before comparing, so two
// responses in the same collapse class are byte-identical iff they differ only in it.
export const REQUEST_ID_PLACEHOLDER = "00000000-0000-0000-0000-000000000000" as const;

// The single frozen diagnostic message for each collapse class. The envelope contract says `message` is
// "diagnostic, not stable" for the error surface at large; for THESE two non-oracular codes
// that latitude is deliberately narrowed to a constant — a per-request or per-subcase
// message would itself be the existence/scope oracle the contract forbids. See CONTRACT.md
// (judgment call J2).
export const CANONICAL_AUTH_FAILURE_MESSAGE = "Invalid API key." as const;
export const CANONICAL_NOT_FOUND_MESSAGE = "Not found." as const;

export interface ErrorEnvelope {
  readonly error: {
    readonly code: string;
    readonly message: string;
    readonly request_id: string;
    readonly details: Record<string, never>;
  };
}

// Build the byte-exact wire body for an auth-error response. Constructs the object with
// explicit key sequence and serializes exactly once (the byte-exact signing rule). `details` is always the
// empty object for auth errors — it never carries scope, tenant, or existence information
// ("details never contains ... existence information outside the caller's tenant").
export function buildAuthErrorBody(code: string, message: string, requestId: string): string {
  return JSON.stringify({
    error: {
      code,
      message,
      request_id: requestId,
      details: {},
    },
  });
}

// The frozen 401 body, with the canonical placeholder `request_id`.
export const CANONICAL_AUTH_FAILURE_BODY = buildAuthErrorBody(
  CANONICAL_AUTH_FAILURE_CODE,
  CANONICAL_AUTH_FAILURE_MESSAGE,
  REQUEST_ID_PLACEHOLDER,
);

// The frozen 404 body, with the canonical placeholder `request_id`.
export const CANONICAL_NOT_FOUND_BODY = buildAuthErrorBody(
  CANONICAL_NOT_FOUND_CODE,
  CANONICAL_NOT_FOUND_MESSAGE,
  REQUEST_ID_PLACEHOLDER,
);

// The frozen client-visible response header set for BOTH non-oracular auth-error responses.
// Header names are lowercased (RFC 7230 field names are case-insensitive). Deliberately IDENTICAL
// for the 401 and the 404 and constant across every collapse-class subcase, so the header channel
// carries no credential / scope / existence signal. Holds the canonical media type and — critically — NO
// `WWW-Authenticate` challenge (judgment call J3): a Bearer challenge's `error="invalid_token"` vs
// `error="insufficient_scope"` is exactly the RFC 6750 scope oracle the frozen error vocabulary closes. `request_id` is
// body-only, so no per-request response header varies. `non-oracular.ts` compares this set
// fail-closed — any added or value-varying header registers as distinguishable.
export const CANONICAL_AUTH_ERROR_HEADERS = {
  "content-type": "application/json; charset=utf-8",
} as const;

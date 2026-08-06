// the auth-errors/route-policy concern.1 — Frozen non-oracular auth-error codes for the generic node v2 HTTP surface.
//
// The API error envelope + status table and authentication classes. Frozen
// error vocabulary — an authenticated key presented outside its scope returns the
// SAME generic 401 as an unknown key, deliberately, so there is no "valid key, wrong scope"
// oracle.
//
// This module freezes the RESOLUTION of the status-table row "403 | Authenticated
// principal lacks scope" AGAINST that canonical 401 posture: a 403/forbidden auth code does
// not exist in the v2 auth-error contract. See CONTRACT.md in this directory.

// An HTTP status paired with its frozen v2 auth-error code.
export interface AuthErrorCode {
  readonly code: string;
  readonly http: number;
}

// The two — and only two — auth-error responses this contract freezes. Every credential
// failure collapses onto the 401; every object-resolution failure that could otherwise
// reveal cross-tenant existence collapses onto the 404. The wider error surface
// (400/409/410/422/429/503 and any 404 sub-taxonomy) is out of scope here and owned by
// the named concern (strict API validation).
export const AUTH_ERROR_CODES = [
  { code: "invalid_api_key", http: 401 },
  { code: "not_found", http: 404 },
] as const satisfies readonly AuthErrorCode[];

export type AuthErrorCodeName = (typeof AUTH_ERROR_CODES)[number]["code"];

// The canonical credential-failure code: the single 401 every auth failure collapses to.
export const CANONICAL_AUTH_FAILURE_CODE = "invalid_api_key" as const;

// The canonical resolution-failure code: absent and cross-tenant objects are identical.
export const CANONICAL_NOT_FOUND_CODE = "not_found" as const;

// Explicitly rejected taxonomy. Kept as data — not merely prose — so a future edit cannot
// silently reintroduce a status/code that re-opens the scope or cross-tenant existence
// oracle. The census freeze test asserts none of these codes appears in AUTH_ERROR_CODES.
// Mirrors the node-core neutrality gate's data-not-special-case discipline.
export const REJECTED_AUTH_ERROR_CODES = [
  {
    code: "forbidden",
    http: 403,
    reason: "reintroduces the scope oracle the frozen error vocabulary closed; scope denial is the generic 401",
  },
  {
    code: "insufficient_scope",
    http: 403,
    reason: "names scope denial distinctly from an unknown key; must collapse to invalid_api_key",
  },
  {
    code: "wrong_tenant",
    http: 404,
    reason: "distinguishes a cross-tenant object from an absent one; must collapse to not_found",
  },
] as const;

export const HTTP_STATUS_BY_AUTH_ERROR_CODE: Readonly<Record<AuthErrorCodeName, number>> =
  Object.freeze(
    Object.fromEntries(AUTH_ERROR_CODES.map((c) => [c.code, c.http])) as Record<
      AuthErrorCodeName,
      number
    >,
  );

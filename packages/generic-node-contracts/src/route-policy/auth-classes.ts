// Centralized authentication/authorization classes and their frozen non-oracular failure
// mapping. Every route inherits its auth behaviour from exactly one class here; no route
// defines bespoke auth handling. Builds on the auth-errors freeze: a credential/scope failure
// on any fully frozen class collapses to the single CANONICAL_AUTH_FAILURE_CODE (401), and a
// cross-tenant or absent object collapses to CANONICAL_NOT_FOUND_CODE (404). No class ever
// fails *authorization* with 403 — authFailureStatus is never 403.
//
// OPERATOR_SESSION may still emit 403 for a closed set of *non-authorization* gates (CSRF
// origin policy, first-login password-change posture). Those statuses live in
// `nonAuthorizationStatuses` so verifiers and served-surface gates can read them as data
// rather than prose (ZTR-1191).
//
// Governed by the API contract's authentication classes, under the frozen non-oracular error
// vocabulary. On any conflict with the auth-errors freeze, the auth-errors freeze wins — its
// codes are imported here, never redefined.

import { CANONICAL_AUTH_FAILURE_CODE, CANONICAL_NOT_FOUND_CODE } from "../auth-errors/index.js";

export const AUTH_CLASSES = [
  "IMPLEMENTER_BEARER",
  "REPORTING_CREDENTIAL",
  "SUBSCRIPTION_HANDLE",
  "OPERATOR_SESSION",
  "PUBLIC",
] as const;

export type AuthClass = (typeof AUTH_CLASSES)[number];

export interface AuthClassPolicy {
  // HTTP status for a credential/authorization failure on this class, or null when the class
  // never authenticates (PUBLIC). Frozen invariant: this is NEVER 403 (auth/scope denial).
  readonly authFailureStatus: number | null;
  // The canonical credential-failure code for this class, or null when the specific code is
  // OPERATOR_SESSION taxonomy lives in admin-auth-errors (ZTR-1196); null here keeps this freeze status-only.
  readonly authFailureCode: string | null;
  // The canonical code for a cross-tenant/absent object on this class, or null when the class
  // does not resolve tenant-scoped objects.
  readonly tenantResolutionCode: string | null;
  // True when the full non-oracular collapse (credential + tenant) is frozen for this class by
  // the route-policy freeze. OPERATOR_SESSION/PUBLIC freeze only the "never 403 for auth
  // denial" status invariant here; their wider code taxonomy belongs to the admin-auth concern.
  readonly nonOracularFrozen: boolean;
  // Closed set of HTTP statuses this class may emit that are NOT credential/scope/authorization
  // denials (e.g. CSRF origin policy, authenticated posture gates). Empty for every class
  // except OPERATOR_SESSION. Verifiers and served-surface gates read this field as data —
  // never hard-code the carve-out beside the policy table (ZTR-1191).
  readonly nonAuthorizationStatuses: readonly number[];
}

// The implementer-facing multi-tenant surface (bearer, reporting credential, subscription
// handle) is where unknown/expired/revoked/wrong-tenant/wrong-scope credentials are probed, so
// its collapse is fully frozen. OPERATOR_SESSION freezes authFailureStatus=401 (never 403 for
// auth denial) plus an explicit nonAuthorizationStatuses carve-out; its specific admin-auth
// codes are deferred. PUBLIC never authenticates.
export const AUTH_CLASS_POLICY = {
  IMPLEMENTER_BEARER: {
    authFailureStatus: 401,
    authFailureCode: CANONICAL_AUTH_FAILURE_CODE,
    tenantResolutionCode: CANONICAL_NOT_FOUND_CODE,
    nonOracularFrozen: true,
    nonAuthorizationStatuses: [],
  },
  REPORTING_CREDENTIAL: {
    authFailureStatus: 401,
    authFailureCode: CANONICAL_AUTH_FAILURE_CODE,
    tenantResolutionCode: CANONICAL_NOT_FOUND_CODE,
    nonOracularFrozen: true,
    nonAuthorizationStatuses: [],
  },
  SUBSCRIPTION_HANDLE: {
    authFailureStatus: 401,
    authFailureCode: CANONICAL_AUTH_FAILURE_CODE,
    tenantResolutionCode: CANONICAL_NOT_FOUND_CODE,
    nonOracularFrozen: true,
    nonAuthorizationStatuses: [],
  },
  OPERATOR_SESSION: {
    authFailureStatus: 401,
    authFailureCode: null,
    tenantResolutionCode: CANONICAL_NOT_FOUND_CODE,
    nonOracularFrozen: false,
    // origin_forbidden + password_change_required (and sibling CSRF-origin posture codes).
    // Authorization/factor failures on approve/bless/device routes collapse to 401.
    nonAuthorizationStatuses: [403],
  },
  PUBLIC: {
    authFailureStatus: null,
    authFailureCode: null,
    tenantResolutionCode: null,
    nonOracularFrozen: false,
    nonAuthorizationStatuses: [],
  },
} as const satisfies Record<AuthClass, AuthClassPolicy>;

// the auth-errors/route-policy concern.1 — The frozen mapping from credential/authorization/resolution failure state to
// canonical response, and the check sequencing that makes the mapping non-oracular.
//
// The status table and authentication classes ("verifies tenant scope before object
// lookup"). Canonical: the frozen error vocabulary.

import { CANONICAL_AUTH_FAILURE_CODE, CANONICAL_NOT_FOUND_CODE } from "./codes.js";

// Every credential/authorization/resolution failure state named by the auth-errors/route-policy concern.1 exit
// criteria — unknown, expired, revoked, wrong-scope, wrong-tenant — plus the missing and
// malformed presentation states, mapped to the frozen canonical code. MISSING_CREDENTIAL
// through OUT_OF_SCOPE all collapse onto the generic 401; ABSENT_OBJECT and
// CROSS_TENANT_OBJECT collapse onto the identical 404. No state maps to a 403.
export const AUTH_FAILURE_STATE_TO_CODE = {
  MISSING_CREDENTIAL: CANONICAL_AUTH_FAILURE_CODE,
  MALFORMED_CREDENTIAL: CANONICAL_AUTH_FAILURE_CODE,
  UNKNOWN_KEY: CANONICAL_AUTH_FAILURE_CODE,
  EXPIRED_KEY: CANONICAL_AUTH_FAILURE_CODE,
  REVOKED_KEY: CANONICAL_AUTH_FAILURE_CODE,
  OUT_OF_SCOPE: CANONICAL_AUTH_FAILURE_CODE,
  ABSENT_OBJECT: CANONICAL_NOT_FOUND_CODE,
  CROSS_TENANT_OBJECT: CANONICAL_NOT_FOUND_CODE,
} as const;

export type AuthFailureState = keyof typeof AUTH_FAILURE_STATE_TO_CODE;

// The frozen sequential gate. Each step's failure short-circuits with its listed code before
// the next step runs. Because scope authorization (step 2) precedes object resolution (step
// 3), an out-of-scope caller never reaches an object lookup and therefore learns nothing
// about whether any object or resource exists. Step 3's tenant predicate is part of the
// lookup itself, so a cross-tenant object is indistinguishable from an absent one.
export const AUTH_CHECK_ORDER = [
  { step: 1, name: "authenticate_credential", failsWith: CANONICAL_AUTH_FAILURE_CODE },
  { step: 2, name: "authorize_scope", failsWith: CANONICAL_AUTH_FAILURE_CODE },
  { step: 3, name: "resolve_object_with_tenant_predicate", failsWith: CANONICAL_NOT_FOUND_CODE },
] as const;

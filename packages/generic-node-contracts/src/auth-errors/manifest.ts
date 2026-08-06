// Auth-errors concern manifest: the single serialized surface the freeze gate snapshots.
//
// `buildAuthErrorsManifest()` aggregates every frozen fact of the auth-errors concern into
// one plain JSON-serializable object; `manifest.freeze.test.ts` diffs it against the
// committed `gen/auth-errors.json`. Any add / remove / rename / value change to a frozen
// fact fails that gate. Evolving a frozen fact is a deliberate paired change: edit the fact
// and regenerate `gen/auth-errors.json` in the same commit.

import { defineConcernManifest } from "../testkit/concernManifest.ts";
import { AUTH_ERROR_CODES, REJECTED_AUTH_ERROR_CODES } from "./codes.js";
import {
  ERROR_ENVELOPE_FIELD_ORDER,
  REQUEST_ID_PLACEHOLDER,
  CANONICAL_AUTH_FAILURE_MESSAGE,
  CANONICAL_NOT_FOUND_MESSAGE,
  CANONICAL_AUTH_FAILURE_BODY,
  CANONICAL_NOT_FOUND_BODY,
  CANONICAL_AUTH_ERROR_HEADERS,
} from "./envelope.js";
import { AUTH_FAILURE_STATE_TO_CODE, AUTH_CHECK_ORDER } from "./classes.js";
import { SHA256_AUTH_FAILURE_BODY, SHA256_NOT_FOUND_BODY } from "./digests.js";
import { REPORTING_REJECTION_CODES, REJECTION_STATUS } from "./reporting-rejection.js";

// Provisional ConcernManifest mirroring the shared { concern, ticket, frozen } shape.
export const authErrorsConcernManifest = {
  concern: "auth-errors",
  ticket: "auth-errors-vocabulary",
  frozen: [
    "AUTH_ERROR_CODES",
    "REJECTED_AUTH_ERROR_CODES",
    "ERROR_ENVELOPE_FIELD_ORDER",
    "AUTH_FAILURE_STATE_TO_CODE",
    "AUTH_CHECK_ORDER",
    "CANONICAL_AUTH_FAILURE_BODY",
    "CANONICAL_NOT_FOUND_BODY",
    "CANONICAL_AUTH_ERROR_HEADERS",
    "REPORTING_REJECTION_CODES",
    "REJECTION_STATUS",
  ],
} as const;

// Build the serializable manifest the freeze gate diffs against gen/auth-errors.json.
export function buildAuthErrorsManifest() {
  return {
    concern: authErrorsConcernManifest.concern,
    ticket: authErrorsConcernManifest.ticket,
    governing: {
      spec: "API error envelope and authentication classes; operations recovery",
      decision: "non-oracular-auth-errors",
    },
    codes: AUTH_ERROR_CODES.map((c) => ({ code: c.code, http: c.http })),
    rejected: REJECTED_AUTH_ERROR_CODES.map((c) => ({
      code: c.code,
      http: c.http,
      reason: c.reason,
    })),
    envelopeFieldOrder: [...ERROR_ENVELOPE_FIELD_ORDER],
    requestIdPlaceholder: REQUEST_ID_PLACEHOLDER,
    messages: {
      invalid_api_key: CANONICAL_AUTH_FAILURE_MESSAGE,
      not_found: CANONICAL_NOT_FOUND_MESSAGE,
    },
    stateToCode: { ...AUTH_FAILURE_STATE_TO_CODE },
    checkOrder: AUTH_CHECK_ORDER.map((s) => ({
      step: s.step,
      name: s.name,
      failsWith: s.failsWith,
    })),
    authErrorHeaders: { ...CANONICAL_AUTH_ERROR_HEADERS },
    bodies: {
      invalid_api_key: CANONICAL_AUTH_FAILURE_BODY,
      not_found: CANONICAL_NOT_FOUND_BODY,
    },
    bodyDigests: {
      invalid_api_key: SHA256_AUTH_FAILURE_BODY,
      not_found: SHA256_NOT_FOUND_BODY,
    },
    reportingRejectionCodes: [...REPORTING_REJECTION_CODES],
    reportingRejectionStatus: { ...REJECTION_STATUS },
  } as const;
}

export type AuthErrorsManifest = ReturnType<typeof buildAuthErrorsManifest>;

/**
 * The auth-errors concern's self-registered ConcernManifest. Wraps the exact `buildAuthErrorsManifest()` output — the same call the
 * freeze gate diffs against `gen/auth-errors.json` — byte-identically under the canonical
 * shape; `authErrorsConcernManifest` above is the provisional form supersedes.
 * Registration export only — the concern-manifest registry assembles `src/registry.ts`.
 */
export const AUTH_ERRORS_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "auth-errors",
  decisionRefs: ["non-oracular-auth-errors"],
  frozenValues: { authErrors: buildAuthErrorsManifest() },
  goldenRefs: [
    {
      path: "src/auth-errors/gen/auth-errors.json",
      sha256: "2a93ff5598bbe13b412e0ce5b19f712f5f05735985e13e8fa9dbef44677de578",
    },
    {
      path: "src/auth-errors/gen/auth-error-401.body.json",
      sha256: "44fa5568b442479b191887b617c06c3d37ccb8c97f8c1c5d063362c540961e7e",
    },
    {
      path: "src/auth-errors/gen/auth-error-404.body.json",
      sha256: "949585168d1c03d64520afd562f8c1f8a11e7ddf7ee7133fad8d6bab1064d147",
    },
  ],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: ["API error envelope and authentication classes", "non-oracular-auth-errors"],
});

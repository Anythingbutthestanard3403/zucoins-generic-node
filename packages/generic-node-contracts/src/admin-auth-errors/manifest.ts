import { defineConcernManifest } from "../testkit/concernManifest.ts";
import { ADMIN_ERROR_CODES } from "./codes.js";
import { ADMIN_ERROR_ENVELOPE_FIELD_ORDER } from "./envelope.js";

export function buildAdminAuthErrorsManifest() {
  return {
    concern: "admin-auth-errors",
    ticket: "ZTR-1196",
    governing: {
      spec: "API error envelope; OPERATOR_SESSION admin-auth taxonomy",
      decision: "operator-session-admin-auth-errors",
    },
    envelopeFieldOrder: [...ADMIN_ERROR_ENVELOPE_FIELD_ORDER],
    codes: ADMIN_ERROR_CODES.map((c) => ({ code: c.code, http: c.http })),
  } as const;
}

export type AdminAuthErrorsManifest = ReturnType<typeof buildAdminAuthErrorsManifest>;

export const ADMIN_AUTH_ERRORS_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "admin-auth-errors",
  decisionRefs: ["operator-session-admin-auth-errors", "non-oracular-auth-errors"],
  frozenValues: { adminAuthErrors: buildAdminAuthErrorsManifest() },
  goldenRefs: [],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "API error envelope and authentication classes",
    "OPERATOR_SESSION admin-auth taxonomy (ZTR-1196)",
    "route-policy auth-classes J2",
  ],
});

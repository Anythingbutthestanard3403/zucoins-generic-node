// Credential-matrix concern manifest: the serialized full credential/error response matrix the
// freeze gate snapshots. buildCredentialMatrixManifest aggregates the matrix and its dimensions
// into one JSON-serializable object; manifest.freeze.test.ts diffs it against
// gen/credential-matrix.json.

import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  MATRIX_AUTH_CLASSES,
  MATRIX_STATES,
  REPRESENTATIVE_ROUTES,
  buildCredentialMatrix,
} from "./matrix.js";

// Provisional ConcernManifest, mirroring the auth-errors/route-policy provisional shape.
export const credentialMatrixConcernManifest = {
  concern: "credential-matrix",
  ticket: "credential-matrix-freeze",
  frozen: ["MATRIX_STATES", "MATRIX_AUTH_CLASSES", "REPRESENTATIVE_ROUTES", "CREDENTIAL_MATRIX"],
} as const;

export function buildCredentialMatrixManifest() {
  return {
    concern: credentialMatrixConcernManifest.concern,
    ticket: credentialMatrixConcernManifest.ticket,
    governing: {
      spec: "API contract: wire conventions and authentication classes",
      decision: "non-oracular-auth-errors",
      dependsOn: ["auth-errors-freeze", "route-policy-freeze"],
    },
    states: [...MATRIX_STATES],
    authClasses: [...MATRIX_AUTH_CLASSES],
    representativeRoutes: Object.fromEntries(
      MATRIX_AUTH_CLASSES.map((cls) => [cls, REPRESENTATIVE_ROUTES[cls].map((r) => `${r.method} ${r.path}`)]),
    ),
    cells: buildCredentialMatrix(),
  } as const;
}

export type CredentialMatrixManifest = ReturnType<typeof buildCredentialMatrixManifest>;

/**
 * The credential-matrix concern's self-registered ConcernManifest. Wraps the exact
 * `buildCredentialMatrixManifest()` output — the same call the freeze gate diffs against
 * `gen/credential-matrix.json` — byte-identically under the canonical shape;
 * `credentialMatrixConcernManifest` above is the provisional form it supersedes.
 * Registration export only — the concern-manifest registry assembles `src/registry.ts`.
 */
export const CREDENTIAL_MATRIX_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "credential-matrix",
  decisionRefs: ["non-oracular-auth-errors"],
  frozenValues: { credentialMatrix: buildCredentialMatrixManifest() },
  goldenRefs: [
    {
      path: "src/credential-matrix/gen/credential-matrix.json",
      sha256: "beaacb10e37900f93a7d9cea08938b5bde8becca59c09091c2bda8baa6d5c85c",
    },
  ],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "API contract: wire conventions and authentication classes",
    "non-oracular-auth-errors: credential/scope/tenant failures collapse to canonical 401/404 bodies; never 403",
  ],
});

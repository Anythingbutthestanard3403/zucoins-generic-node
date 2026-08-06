// the reporting-auth register tuple — Concern manifest: the single serialized surface the freeze gate snapshots.
// buildReportingAuthManifest() aggregates every frozen reporting-identity fact into one plain
// JSON-serializable object; manifest.freeze.test.ts diffs it against gen/reporting-auth.json.

import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  REGISTER_FIELD_ORDER,
  REGISTER_GOLDEN_PREIMAGE,
  REPORTING_KEY_ENROL_WINDOW_SECS,
  REPORTING_REGISTER_CANONICAL_VERSION,
  REPORTING_REGISTER_PURPOSE,
} from "./register-tuple.js";
import {
  ALLOWED_CREDENTIAL_MECHANISMS,
  FORBIDDEN_CREDENTIAL_MECHANISMS,
  LEGACY_PUSH_PURPOSES,
  NODE_EVENT_KEY_ALLOWED_PURPOSES,
  REPORTING_CROSS_PURPOSE_FORBIDDEN,
  REPORTING_KEY_ALLOWED_PURPOSES,
  REPORTING_KEY_CLASSES,
  V2_REPORTING_PURPOSES,
  ED25519_SMALL_ORDER_ENCODINGS_HEX,
} from "./keys.js";
import {
  BOOTSTRAP_TRUST_ROOT,
  REPORTING_KEY_STATES,
  REPORTING_KEY_TRANSITIONS,
  REPORTING_VERIFIER_ORDER,
  RESTORE_GUARD,
  ROTATION_MODEL,
  TERMINAL_KEY_STATES,
} from "./lifecycle.js";
import {
  REGISTER_GOLDEN_POP_SIGNATURE,
  REGISTER_GOLDEN_PREIMAGE_SHA256,
  REGISTER_GOLDEN_REPORTING_PUBKEY,
} from "./digests.js";
import { REGISTER_PROOF_VERIFICATION_STAGES } from "./verifier.js";

export const reportingAuthConcernManifest = {
  concern: "reporting-auth",
  ticket: "reporting.1",
  frozen: [
    "REPORTING_KEY_CLASSES",
    "REGISTER_TUPLE",
    "REPORTING_KEY_TRANSITIONS",
    "ROTATION_MODEL",
    "V2_REPORTING_PURPOSES",
    "LEGACY_PUSH_PURPOSES",
    "REGISTER_PROOF_VERIFIER",
  ],
} as const;

export function buildReportingAuthManifest() {
  return {
    concern: reportingAuthConcernManifest.concern,
    ticket: reportingAuthConcernManifest.ticket,
    governing: {
      spec: "canonical-fields: suite serializer, register tuple, event signing; signing-custody: keys and signing matrix; api-contract: signed reporting",
      decisions: ["reporting-ingest-auth", "signed-event-log", "sealed-store", "reporting-channel", "reporting-key-enrolment"],
      dependsOn: "B-03",
    },
    keyClasses: REPORTING_KEY_CLASSES.map((k) => ({
      key: k.key,
      owner: k.owner,
      algorithm: k.algorithm,
      nodeStores: k.nodeStores,
    })),
    keySeparation: {
      reportingKeyAllowedPurposes: [...REPORTING_KEY_ALLOWED_PURPOSES],
      nodeEventKeyAllowedPurposes: [...NODE_EVENT_KEY_ALLOWED_PURPOSES],
      crossPurposeForbidden: [...REPORTING_CROSS_PURPOSE_FORBIDDEN],
    },
    credentialMechanisms: {
      allowed: [...ALLOWED_CREDENTIAL_MECHANISMS],
      forbidden: [...FORBIDDEN_CREDENTIAL_MECHANISMS],
    },
    separationFromLegacy: {
      v2Purposes: [...V2_REPORTING_PURPOSES],
      legacyPushPurposes: [...LEGACY_PUSH_PURPOSES],
    },
    registerTuple: {
      purpose: REPORTING_REGISTER_PURPOSE,
      canonicalVersion: REPORTING_REGISTER_CANONICAL_VERSION,
      enrolWindowSecs: REPORTING_KEY_ENROL_WINDOW_SECS,
      fieldOrder: [...REGISTER_FIELD_ORDER],
      goldenPreimage: REGISTER_GOLDEN_PREIMAGE,
      goldenPreimageSha256: REGISTER_GOLDEN_PREIMAGE_SHA256,
      goldenProofOfPossessionSignature: REGISTER_GOLDEN_POP_SIGNATURE,
      goldenReportingPubkey: REGISTER_GOLDEN_REPORTING_PUBKEY,
    },
    registerProofVerifier: {
      stages: [...REGISTER_PROOF_VERIFICATION_STAGES],
      publicKeyBytes: {
        encoding: "padded_base64url",
        decodedLengthBytes: 32,
        exactReencodeRequired: true,
        canonicalCompressedEncoding: {
          yLessThanFieldPrime: true,
          negativeZeroRejected: true,
        },
        rejectedTorsionEncodingsHex: [...ED25519_SMALL_ORDER_ENCODINGS_HEX],
      },
      signatureBytes: {
        encoding: "padded_base64url",
        decodedLengthBytes: 64,
        exactReencodeRequired: true,
      },
      pointCallback: {
        required: true,
        requirements: [
          "canonical_encoding",
          "on_curve",
          "main_prime_order_subgroup",
          "nonidentity",
          "nonsmall_order",
        ],
        successReturn: "literal_true_only",
        calledBeforeProofOfPossession: true,
        anyOtherReturnOrThrow: "fail_closed_without_proof_of_possession",
      },
      verifyDetachedCallback: {
        argumentShape: "named_object_publicKey_preimage_signature",
        calledOnlyAfterPointValidationSuccess: true,
        successReturn: "literal_true_only",
        anyOtherReturnOrThrow: "fail_closed",
        preimageBytes: "original_exact_utf8",
      },
      callbackBytes: "fresh_copies",
      bytePrevalidationClaim: "canonical_prevalidated_bytes_only",
      runtimeCompletePointValidationClaim: false,
    },
    lifecycle: {
      states: [...REPORTING_KEY_STATES],
      terminalStates: [...TERMINAL_KEY_STATES],
      transitions: REPORTING_KEY_TRANSITIONS.map((t) => ({ from: t.from, to: t.to })),
      verifierOrder: [...REPORTING_VERIFIER_ORDER],
      rotationModel: { ...ROTATION_MODEL, slots: [...ROTATION_MODEL.slots] },
      restoreGuard: { ...RESTORE_GUARD },
      bootstrapTrustRoot: {
        ...BOOTSTRAP_TRUST_ROOT,
        requiresAll: [...BOOTSTRAP_TRUST_ROOT.requiresAll],
      },
    },
  } as const;
}

export type ReportingAuthManifest = ReturnType<typeof buildReportingAuthManifest>;

/**
 * the reporting-auth register tuple's self-registered ConcernManifest (the concern-manifest registry
 * leave-behind"). Wraps the exact `buildReportingAuthManifest()` output — the same call the
 * freeze gate diffs against `gen/reporting-auth.json` — byte-identically under the canonical
 * shape; `reportingAuthConcernManifest` above is the provisional form supersedes.
 * Registration export only — the concern-manifest registry assembles `src/registry.ts`.
 */
export const REPORTING_AUTH_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "reporting",
  decisionRefs: ["reporting-ingest-auth", "signed-event-log", "sealed-store", "reporting-channel", "reporting-key-enrolment"],
  frozenValues: { reportingAuth: buildReportingAuthManifest() },
  goldenRefs: [
    {
      path: "src/reporting-auth/gen/reporting-auth.json",
      sha256: "7adb9e12864c832fc5583989e7ac10335a7f67ae01105b7e9dfb1eeb598a36df",
    },
    {
      path: "src/reporting-auth/gen/zp-reporting-register-v1.preimage.txt",
      sha256: "98fba788ad4ba2141dc400f1cd0f58db3a03b34a00b5a04ecdcfe239e9912e7e",
    },
  ],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "canonical-fields: suite serializer, register tuple, golden fixtures, negative vectors",
    "signing-custody: keys and signing matrix",
    "api-contract: signed reporting",
    "decision: reporting-ingest-auth",
    "decision: signed-event-log",
    "decision: sealed-store",
    "decision: reporting-channel",
    "decision: reporting-key-enrolment",
  ],
});

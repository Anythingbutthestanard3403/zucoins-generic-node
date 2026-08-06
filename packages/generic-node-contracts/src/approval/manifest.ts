/**
 * The approval concern manifest + the local review-diff snapshot builder.
 * `APPROVAL_CONCERN_MANIFEST` is the self-registered leave-behind
 * the concern-manifest registry aggregates; `buildApprovalManifest` produces the JSON-serializable snapshot
 * `gen/approval.json` pins (edit a contract without regenerating that file and
 * `manifest.freeze.test.ts` goes red). Registration import only — the concern-manifest registry assembles the package
 * `src/registry.ts`/`index.ts`.
 */
import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  APPROVAL_PURPOSE,
  APPROVAL_CANONICAL_VERSION,
  APPROVAL_PREIMAGE_CONSTRUCTION,
  APPROVAL_AUTH,
  APPROVAL_ORDERING,
  APPROVAL_FORMATION_TIME_FACTS,
  APPROVAL_FIELD_TYPES,
  APPROVAL_FIELD_ROLES,
  APPROVAL_TUPLE,
} from "./approval-tuple.contract.ts";
import {
  FORMATION_STATES,
  FORMATION_TRANSITIONS,
  APPROVAL_CARDINALITY,
  SIGN_INTENT_BOUND_INPUTS,
  SIGN_INTENT_FROZEN_AFTER_EXISTS,
  APPROVAL_CONSUMPTION,
  REDELIVERY_RULE,
  REPLACEMENT_RULE,
  TIMER_SEPARATION,
} from "./sign-intent.contract.ts";
import {
  CRASH_DURABLE_STATES,
  RECOVERY_ACTIONS,
  FORBIDDEN_RECOVERY_ACTIONS,
  CRASH_MATRIX,
  CRASH_POINTS,
  DETERMINISTIC_RESIGN,
} from "./crash-recovery.contract.ts";

const GOLDEN_DIR = "goldens/approval";

/** The one published approval golden (appendix A.8). Digest = the artifact's pinned SHA-256;
 *  the signature is the OPTIONAL additive device signature (seed byte 0x01). File sha256s are the
 *  raw byte-golden digests `goldens.test.ts` pins against disk. */
export const APPROVAL_GOLDEN = {
  purpose: APPROVAL_PURPOSE,
  artifactDigestSha256: "d7c03561bd9bc87e302c533f03741c34d44058fc0aaf1b59b17a4f28f8022146",
  deviceSignatureB64: "HLd6EN7uw2KHCgRAryuyEh6ljmHsjgvCJ6Ke1Gq3fb0PDV1Vsn3QCzuo51o0VnH9LCbDI3c_s6AFK3NO013ZCA==",
  devicePublicKeyB64: "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=",
} as const;

export const APPROVAL_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "approval",
  decisionRefs: ["approval-tuple-freeze", "two-timer-separation"],
  frozenValues: {
    APPROVAL_PURPOSE,
    APPROVAL_CANONICAL_VERSION,
    APPROVAL_PREIMAGE_CONSTRUCTION,
    APPROVAL_AUTH,
    APPROVAL_ORDERING,
    APPROVAL_FORMATION_TIME_FACTS,
    APPROVAL_FIELD_TYPES,
    APPROVAL_FIELD_ROLES,
    APPROVAL_TUPLE,
    FORMATION_STATES,
    FORMATION_TRANSITIONS,
    APPROVAL_CARDINALITY,
    SIGN_INTENT_BOUND_INPUTS,
    SIGN_INTENT_FROZEN_AFTER_EXISTS,
    APPROVAL_CONSUMPTION,
    REDELIVERY_RULE,
    REPLACEMENT_RULE,
    TIMER_SEPARATION,
    CRASH_DURABLE_STATES,
    RECOVERY_ACTIONS,
    FORBIDDEN_RECOVERY_ACTIONS,
    CRASH_MATRIX,
    CRASH_POINTS,
    DETERMINISTIC_RESIGN,
  },
  goldenRefs: [
    { path: `${GOLDEN_DIR}/zp-send-external-approval-v1.preimage.txt`, sha256: "d7c03561bd9bc87e302c533f03741c34d44058fc0aaf1b59b17a4f28f8022146" },
    { path: `${GOLDEN_DIR}/zp-send-external-approval-v1.digest.hex`, sha256: "b8a162f4b807402a1c74443fdc113b874b517be527f726714cae883ea3d34e3b" },
    { path: `${GOLDEN_DIR}/zp-send-external-approval-v1.sig.b64`, sha256: "a112a12ce9b9187eb9e75e7404c76ee4da67eb5e24a9ae6adfe43a3f082c86e3" },
  ],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
    "byte-golden:packages/generic-node-contracts/goldens/approval",
  ],
  sourceDocCitations: [
    "canonical serialization A.1.1",
    "approval tuple A.4.1",
    "byte goldens A.8",
    "negative vectors A.9",
    "signing custody and security invariants",
    "operation flows",
    "build/test gates",
    "approval-tuple freeze",
    "two-timer separation",
  ],
});

/**
 * The JSON-serializable freeze snapshot pinned by `gen/approval.json`. JSON round-tripped so both
 * sides of the `manifest.freeze.test.ts` deep-equal are plain data (no readonly-tuple identity).
 */
export const buildApprovalManifest = (): unknown =>
  JSON.parse(
    JSON.stringify({
      concern: "approval",
      governing: {
        decisions: ["approval-tuple-freeze", "two-timer-separation"],
        gate: "CONTRACT_FREEZE",
        spec: [
          "canonical serialization A.1.1, tuple A.4.1, goldens A.8, negative vectors A.9",
          "signing custody and security invariants",
          "operation flows",
          "build/test gates",
        ],
      },
      approvalTuple: {
        purpose: APPROVAL_PURPOSE,
        canonicalVersion: APPROVAL_CANONICAL_VERSION,
        serializer: APPROVAL_TUPLE.serializer,
        optionalSignatureKeyRole: APPROVAL_TUPLE.optionalSignatureKeyRole,
        construction: APPROVAL_PREIMAGE_CONSTRUCTION,
        fieldTypes: APPROVAL_FIELD_TYPES,
        fieldRoles: APPROVAL_FIELD_ROLES,
        fields: APPROVAL_TUPLE.fields,
      },
      auth: APPROVAL_AUTH,
      precedence: { phases: APPROVAL_ORDERING, timeFacts: APPROVAL_FORMATION_TIME_FACTS },
      formation: {
        states: FORMATION_STATES,
        transitions: FORMATION_TRANSITIONS,
        cardinality: APPROVAL_CARDINALITY,
        signIntentBoundInputs: SIGN_INTENT_BOUND_INPUTS,
        frozenAfterExists: SIGN_INTENT_FROZEN_AFTER_EXISTS,
        consumption: APPROVAL_CONSUMPTION,
        redelivery: REDELIVERY_RULE,
        replacement: REPLACEMENT_RULE,
        timers: TIMER_SEPARATION,
      },
      crash: {
        durableStates: CRASH_DURABLE_STATES,
        recoveryActions: RECOVERY_ACTIONS,
        forbiddenActions: FORBIDDEN_RECOVERY_ACTIONS,
        matrix: CRASH_MATRIX,
        crashPoints: CRASH_POINTS,
        deterministicResign: DETERMINISTIC_RESIGN,
      },
      golden: APPROVAL_GOLDEN,
    }),
  );

export const SOURCE = "approval concern manifest; approval-tuple freeze; two-timer separation" as const;

/**
 * Covers A.1.1 and A.3-A.7 (the `zp-*-v1` suite purposes); the artifacts freeze (frozen signed
 * surfaces), compatibility-literal preservation (established purposes are never renamed).
 *
 * the fixture-provenance purposes census — the closed census of every v2-suite purpose literal, its signing-key role, its
 * serializer, and its freeze disposition. Until this module the purpose vocabulary existed only
 * scattered across per-tuple contract modules; this is the single machine-checkable census those
 * modules are cross-checked against. It is DATA ONLY (no functions) so `gen/purposes.json`
 * stays a clean review-diff snapshot; byte authority stays here, never in the emitted JSON.
 *
 * Field sequences are NOT re-frozen here: each frozen tuple's exact field sequence remains owned
 * by the per-tuple contract module named in `fieldSequenceOwner` (artifacts, approval,
 * reporting-tuples, reporting-auth) or by this concern's own `suite-tuples.contract.ts` for the
 * three tuples no earlier concern froze. The census asserts ownership, not a second copy.
 */

/** Manifest version (v1 `*_CONTRACT_VERSION` discipline): bump on any reviewed change. */
export const PURPOSES_CONTRACT_VERSION = 1 as const;

/** Every v2-suite purpose is serialized with the A.1.1 domain-separated canonical serializer. */
export const SUITE_SERIALIZER = "suite" as const;

/** The frozen purpose suffix. A contract change is a NEW purpose/version, never an in-place
 *  edit of a `-v1` surface (the artifacts freeze).*/
export const SUITE_PURPOSE_SUFFIX = "-v1" as const;

/** Closed set of signing-key roles a suite purpose may bind (purpose-specific key custody). */
export const SUITE_SIGNING_KEY_ROLES = [
  "node_identity",
  "device",
  "reporting",
  "node_event",
  "none",
] as const;

export type SuiteSigningKeyRole = (typeof SUITE_SIGNING_KEY_ROLES)[number];

/** Closed set of freeze dispositions. `frozen` = exact field sequence and goldens are committed;
 *  `deferred-c4` = architecture-only, field sequence and byte-exact golden deferred to the
 *  byte-freeze child under binding condition C4. */
export const SUITE_PURPOSE_DISPOSITIONS = ["frozen", "deferred-c4"] as const;

export type SuitePurposeDisposition = (typeof SUITE_PURPOSE_DISPOSITIONS)[number];

export interface SuitePurposeEntry {
  readonly purpose: string;
  /** `false` only for `zp-wallet-head-fingerprint-v1` (A.7): suite serializer + SHA-256, no signature. */
  readonly signed: boolean;
  readonly signingKeyRole: SuiteSigningKeyRole;
  readonly serializer: typeof SUITE_SERIALIZER;
  readonly disposition: SuitePurposeDisposition;
  /** Package-relative module that owns the exact field sequence, or the C4 deferral owner. */
  readonly fieldSequenceOwner: string;
  readonly specCitation: string;
}

/**
 * The closed census of every live `zp-*-v1` purpose, in Appendix A declaration sequence
 * (A.3 expected artifacts, A.4 approval/custody, A.5 reporting, A.6 event, A.7 fingerprint).
 * Adding, removing, renaming, or re-sequencing an entry is a contract change (the artifacts freeze/compatibility-literal preservation).
 */
export const SUITE_PURPOSE_CENSUS: readonly SuitePurposeEntry[] = [
  {
    purpose: "zp-receive-expected-v1",
    signed: true,
    signingKeyRole: "node_identity",
    serializer: SUITE_SERIALIZER,
    disposition: "frozen",
    fieldSequenceOwner: "src/artifacts/expected-artifacts.contract.ts",
    specCitation: "A.3.1",
  },
  {
    purpose: "zp-move-internal-expected-v1",
    signed: true,
    signingKeyRole: "node_identity",
    serializer: SUITE_SERIALIZER,
    disposition: "frozen",
    fieldSequenceOwner: "src/artifacts/expected-artifacts.contract.ts",
    specCitation: "A.3.2",
  },
  {
    purpose: "zp-send-external-expected-v1",
    signed: true,
    signingKeyRole: "node_identity",
    serializer: SUITE_SERIALIZER,
    disposition: "frozen",
    fieldSequenceOwner: "src/artifacts/expected-artifacts.contract.ts",
    specCitation: "A.3.3",
  },
  {
    purpose: "zp-send-external-approval-v1",
    signed: true,
    signingKeyRole: "device",
    serializer: SUITE_SERIALIZER,
    disposition: "frozen",
    fieldSequenceOwner: "src/approval/approval-tuple.contract.ts",
    specCitation: "A.4.1",
  },
  {
    purpose: "zp-destination-bless-v1",
    signed: true,
    signingKeyRole: "device",
    serializer: SUITE_SERIALIZER,
    disposition: "frozen",
    fieldSequenceOwner: "src/machine-manifests/suite-tuples.contract.ts",
    specCitation: "A.4.2",
  },
  {
    purpose: "zp-device-enrol-v1",
    signed: true,
    signingKeyRole: "device",
    serializer: SUITE_SERIALIZER,
    disposition: "frozen",
    fieldSequenceOwner: "src/machine-manifests/suite-tuples.contract.ts",
    specCitation: "A.4.3",
  },
  {
    purpose: "zp-report-request-v1",
    signed: true,
    signingKeyRole: "reporting",
    serializer: SUITE_SERIALIZER,
    disposition: "frozen",
    fieldSequenceOwner: "src/reporting-tuples/request-tuple.ts",
    specCitation: "A.5",
  },
  {
    purpose: "zp-reporting-register-v1",
    signed: true,
    signingKeyRole: "reporting",
    serializer: SUITE_SERIALIZER,
    disposition: "frozen",
    fieldSequenceOwner: "src/reporting-auth/register-tuple.ts",
    specCitation: "A.5",
  },
  {
    purpose: "zp-node-event-v1",
    signed: true,
    signingKeyRole: "node_event",
    serializer: SUITE_SERIALIZER,
    disposition: "frozen",
    fieldSequenceOwner: "src/reporting-tuples/event-tuple.ts",
    specCitation: "A.6",
  },
  {
    purpose: "zp-wallet-head-fingerprint-v1",
    signed: false,
    signingKeyRole: "none",
    serializer: SUITE_SERIALIZER,
    disposition: "frozen",
    fieldSequenceOwner: "src/machine-manifests/suite-tuples.contract.ts",
    specCitation: "A.7",
  },
];

/**
 * The three implementer-scoped continuity tuples (A.6 Option 1 dual continuity):
 * architecture frozen, exact field sequence and byte-exact golden DEFERRED to the byte-freeze
 * child under binding condition C4. They are census members with disposition `deferred-c4` —
 * never usable as frozen verification targets until that child lands.
 */
export const DEFERRED_SUITE_PURPOSE_CENSUS: readonly SuitePurposeEntry[] = [
  {
    purpose: "zp-implementer-event-v1",
    signed: true,
    signingKeyRole: "node_event",
    serializer: SUITE_SERIALIZER,
    disposition: "deferred-c4",
    fieldSequenceOwner: "deferred — byte-freeze child (binding condition C4)",
    specCitation: "A.6",
  },
  {
    purpose: "zp-implementer-checkpoint-v1",
    signed: true,
    signingKeyRole: "node_event",
    serializer: SUITE_SERIALIZER,
    disposition: "deferred-c4",
    fieldSequenceOwner: "deferred — byte-freeze child (binding condition C4)",
    specCitation: "A.6",
  },
  {
    purpose: "zp-implementer-keyrotation-v1",
    signed: true,
    signingKeyRole: "node_event",
    serializer: SUITE_SERIALIZER,
    disposition: "deferred-c4",
    fieldSequenceOwner: "deferred — byte-freeze child (binding condition C4)",
    specCitation: "A.6",
  },
];

/**
 * Legacy push-channel purposes (compatibility-literal preservation compatibility literals, owned by
 * `src/reporting-auth/keys.ts` — referenced here, never duplicated). They must NEVER verify on
 * the v2 pull/suite path (A.9 negative vector 10: cross-purpose verification rejects).
 */
export const LEGACY_PUSH_PURPOSES_REFERENCE = {
  owner: "src/reporting-auth/keys.ts",
  purposes: ["zupay-reporting-v1", "zupay-reporting-transport-v1", "zupay-reporting-handshake-v1"],
  verifyOnV2SuitePath: false,
} as const;

export const SOURCE = "suite purposes A.1.1, A.3-A.7; purpose-specific key custody; artifacts-freeze; compatibility-literals" as const;

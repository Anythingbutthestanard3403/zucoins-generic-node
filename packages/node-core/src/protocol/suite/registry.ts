// The closed suite-tuple registry: versioned-purpose dispatch, per-purpose signing key
// class, and each tuple's exact field-sequenced schema. This is the single authority the serializer
// walks; adding or reordering a field here is a byte-contract change (the byte-exact signing rule).
//
// Field tables and sequences; the purpose is both the domain prefix and
// payload field 1. The signing matrix keeps key classes separate. Field sequences are
// transcribed verbatim from Appendix A; the golden reproduction test is the proof they are byte-correct.

import {
  type CanonicalEncoder,
  closedEnum,
  encodeAfterLanding,
  encodeAnchor,
  encodeCanonicalVersion,
  encodeCanonicalTimestamp,
  encodeEd25519Signature,
  encodeEmptyOrSignature,
  encodeExpiryUnixTimeSecs,
  encodeHttpMethod,
  encodeLabel,
  encodeOriginPath,
  encodePositiveDecimalSeq,
  encodePositiveZkzAmount,
  encodeSha256Hex,
  encodeSourceSelector,
  encodeUuid,
  encodeWalletPublicKey,
  encodeZkzBalance,
} from "./encoders.js";

// The five closed suite purposes-by-key-class. A key class may sign ONLY the purposes mapped to it
// The serializer exposes this so a signer can be refused a cross-class purpose before it
// ever forms bytes. `unsigned` is the wallet-head fingerprint — it uses the serializer and SHA-256
// but is deliberately never signed (A.7).
export type SuiteKeyClass = "node_identity" | "device" | "reporting" | "node_event" | "unsigned";

// The nine closed neutral event literals (Appendix). Kept here as the serializer's own datum;
// the census test cross-checks it against the frozen set so the two can never drift.
export const NEUTRAL_EVENT_TYPES = [
  "receive.ready",
  "receive.landed",
  "internal_move.created",
  "internal_move.landed",
  "external_send.created",
  "external_send.awaiting_redemption",
  "external_send.landed",
  "operation.needs_attention",
  "operation.expired",
] as const;

const WALLET_STATE_KINDS = ["GENESIS", "HEAD"] as const;

export interface SuiteFieldSpec {
  readonly name: string;
  readonly encoder: CanonicalEncoder;
  // When true, JSON `null` is a permitted value and is emitted present, never omitted (A.1.1 rule 7).
  // When false, a `null` value is rejected; an empty-string sentinel (`""`) is a distinct, separately
  // encoded value (e.g. previous-state signatures) — the serializer keeps null and "" distinct.
  readonly nullable: boolean;
}

export interface SuitePurposeSpec {
  readonly purpose: string;
  readonly keyClass: SuiteKeyClass;
  readonly fields: readonly SuiteFieldSpec[];
  // Ceremony freshness ceiling in seconds for a tuple carrying both `issued_at` and `expires_at`
  // (A.4.1–A.4.3, A.5, A.5.1): the signed window must satisfy `0 < expires_at − issued_at ≤ N`,
  // measured against the SIGNED `issued_at`, never receipt time. Absent for tuples with no window.
  readonly windowSeconds?: number;
}

// A.4.1–A.4.3 and A.5.1 all state the same ceremony ceiling; A.5's automated-read credential is the
// tighter 60-second class. Named so a reader sees the two classes are deliberately different.
const CEREMONY_WINDOW_SECS = 300;
const REPORTING_READ_WINDOW_SECS = 60;

function field(name: string, encoder: CanonicalEncoder, nullable = false): SuiteFieldSpec {
  return { name, encoder, nullable };
}

// Field 1 is always `purpose` (a single-member closed enum equal to the dispatch purpose — this is
// where an A.9 #2 prefix/payload mismatch is caught) and field 2 is always `canonical_version` (the
// number 1). Every schema below begins with these two, then lists the tuple's remaining fields in
// exact Appendix A sequence.
function header(purpose: string): readonly SuiteFieldSpec[] {
  return [
    field("purpose", closedEnum("purpose", [purpose])),
    field("canonical_version", encodeCanonicalVersion),
  ];
}

function spec(
  purpose: string,
  keyClass: SuiteKeyClass,
  rest: readonly SuiteFieldSpec[],
  windowSeconds?: number,
): SuitePurposeSpec {
  return { purpose, keyClass, fields: [...header(purpose), ...rest], windowSeconds };
}

// A.3.1 zp-receive-expected-v1 — node identity key.
const RECEIVE_EXPECTED = spec("zp-receive-expected-v1", "node_identity", [
  field("node_id", encodeUuid),
  field("implementer_id", encodeUuid),
  field("operation_id", encodeUuid),
  field("receiver_wallet_id", encodeUuid),
  field("receiver_pubkey", encodeWalletPublicKey),
  field("amount_zkz", encodePositiveZkzAmount),
  field("discriminator", encodeUuid),
  field("anchor", encodeAnchor),
  field("receiver_t0_fingerprint", encodeSha256Hex),
  field("expiry_unix_time_secs", encodeExpiryUnixTimeSecs, true),
  field("after_landing", encodeAfterLanding),
  field("transfer_code_sha256", encodeSha256Hex),
]);

// A.3.2 zp-move-internal-expected-v1 — node identity key.
const MOVE_INTERNAL_EXPECTED = spec("zp-move-internal-expected-v1", "node_identity", [
  field("node_id", encodeUuid),
  field("implementer_id", encodeUuid),
  field("operation_id", encodeUuid),
  field("source_wallet_id", encodeUuid),
  field("source_pubkey", encodeWalletPublicKey),
  field("destination_id", encodeUuid),
  field("destination_wallet_id", encodeUuid),
  field("destination_pubkey", encodeWalletPublicKey),
  field("amount_zkz", encodePositiveZkzAmount),
  field("spawned_from_operation_id", encodeUuid, true),
  field("references_operation_id", encodeUuid, true),
]);

// A.3.3 zp-send-external-expected-v1 — node identity key.
const SEND_EXTERNAL_EXPECTED = spec("zp-send-external-expected-v1", "node_identity", [
  field("node_id", encodeUuid),
  field("implementer_id", encodeUuid),
  field("operation_id", encodeUuid),
  field("source_selector", encodeSourceSelector),
  field("source_pubkey", encodeWalletPublicKey),
  field("destination_address", encodeWalletPublicKey),
  field("amount_zkz", encodePositiveZkzAmount),
  field("references_operation_id", encodeUuid, true),
]);

// A.4.1 zp-send-external-approval-v1 — operator device key.
const SEND_EXTERNAL_APPROVAL = spec("zp-send-external-approval-v1", "device", [
  field("node_id", encodeUuid),
  field("operation_id", encodeUuid),
  field("source_selector", encodeSourceSelector),
  field("source_pubkey", encodeWalletPublicKey),
  field("destination_address", encodeWalletPublicKey),
  field("amount_zkz", encodePositiveZkzAmount),
  field("references_operation_id", encodeUuid, true),
  field("nonce", encodeUuid),
  field("issued_at", encodeCanonicalTimestamp),
  field("expires_at", encodeCanonicalTimestamp),
], CEREMONY_WINDOW_SECS);

// A.4.2 zp-destination-bless-v1 — operator device key.
const DESTINATION_BLESS = spec("zp-destination-bless-v1", "device", [
  field("node_id", encodeUuid),
  field("destination_id", encodeUuid),
  field("wallet_id", encodeUuid),
  field("wallet_pubkey", encodeWalletPublicKey),
  field("nonce", encodeUuid),
  field("issued_at", encodeCanonicalTimestamp),
  field("expires_at", encodeCanonicalTimestamp),
], CEREMONY_WINDOW_SECS);

// A.4.3 zp-device-enrol-v1 — existing trusted device or approved break-glass key.
const DEVICE_ENROL = spec("zp-device-enrol-v1", "device", [
  field("node_id", encodeUuid),
  field("new_device_key_id", encodeUuid),
  field("new_device_public_key", encodeWalletPublicKey),
  field("label", encodeLabel),
  field("nonce", encodeUuid),
  field("issued_at", encodeCanonicalTimestamp),
  field("expires_at", encodeCanonicalTimestamp),
], CEREMONY_WINDOW_SECS);

// A.5 zp-report-request-v1 — implementer reporting key.
const REPORT_REQUEST = spec("zp-report-request-v1", "reporting", [
  field("node_id", encodeUuid),
  field("implementer_id", encodeUuid),
  field("method", encodeHttpMethod),
  field("path", encodeOriginPath),
  field("body_sha256", encodeSha256Hex),
  field("nonce", encodeUuid),
  field("issued_at", encodeCanonicalTimestamp),
  field("expires_at", encodeCanonicalTimestamp),
], REPORTING_READ_WINDOW_SECS);

// A.5.1 zp-reporting-register-v1 — implementer reporting key (proof-of-possession self-sign; platform holds zero keys).
const REPORTING_REGISTER = spec("zp-reporting-register-v1", "reporting", [
  field("node_id", encodeUuid),
  field("implementer_id", encodeUuid),
  field("new_reporting_key_id", encodeUuid),
  field("new_reporting_public_key", encodeWalletPublicKey),
  field("supersedes_key_id", encodeUuid, true),
  field("nonce", encodeUuid),
  field("issued_at", encodeCanonicalTimestamp),
  field("expires_at", encodeCanonicalTimestamp),
], CEREMONY_WINDOW_SECS);

// A.6 zp-node-event-v1 — node event key.
const NODE_EVENT = spec("zp-node-event-v1", "node_event", [
  field("node_id", encodeUuid),
  field("event_id", encodeUuid),
  field("seq", encodePositiveDecimalSeq),
  field("operation_id", encodeUuid, true),
  field("wallet_id", encodeUuid, true),
  field("event_type", closedEnum("event_type", NEUTRAL_EVENT_TYPES)),
  field("data_sha256", encodeSha256Hex),
  field("previous_event_hash", encodeSha256Hex, true),
  field("created_at", encodeCanonicalTimestamp),
]);

// A.7 zp-wallet-head-fingerprint-v1 — unsigned (uses the serializer + SHA-256, never a signature).
// `wallet_public_key` replaces the usual `purpose`/`node_id` opener after the two-field header; the
// state signatures are the empty-or-signature sentinel ("" at genesis), while inner_sha256 and the
// step signatures are true nullable at genesis.
// `b_amount` uses foreign-preserving encodeZkzBalance (parseObservedZkzBalance): A.7 binds the
// role-relative observed head balance verbatim (Byte-exact), never node-authored shortest form.
const WALLET_HEAD_FINGERPRINT = spec("zp-wallet-head-fingerprint-v1", "unsigned", [
  field("wallet_public_key", encodeWalletPublicKey),
  field("state_kind", closedEnum("state_kind", WALLET_STATE_KINDS)),
  field("s_signature", encodeEmptyOrSignature),
  field("p_signature", encodeEmptyOrSignature),
  field("b_amount", encodeZkzBalance),
  // Byte-exact: caller-supplied scalar — never re-derive from parsed inner (canonical-field rule v15, signing rule r4)
  field("inner_sha256", encodeSha256Hex, true),
  field("step_1_signature", encodeEd25519Signature, true),
  field("step_2_signature", encodeEd25519Signature, true),
]);

const ALL_SPECS: readonly SuitePurposeSpec[] = [
  RECEIVE_EXPECTED,
  MOVE_INTERNAL_EXPECTED,
  SEND_EXTERNAL_EXPECTED,
  SEND_EXTERNAL_APPROVAL,
  DESTINATION_BLESS,
  DEVICE_ENROL,
  REPORT_REQUEST,
  REPORTING_REGISTER,
  NODE_EVENT,
  WALLET_HEAD_FINGERPRINT,
];

const REGISTRY: ReadonlyMap<string, SuitePurposeSpec> = new Map(
  ALL_SPECS.map((entry) => [entry.purpose, entry]),
);

// The closed, sequenced list of registered suite purposes (versioned literals). A purpose absent here
// cannot be serialized — this list IS the versioned-purpose dispatch surface.
export const SUITE_PURPOSES: readonly string[] = ALL_SPECS.map((entry) => entry.purpose);

export function suitePurposeSpec(purpose: string): SuitePurposeSpec | undefined {
  return REGISTRY.get(purpose);
}

export function keyClassForPurpose(purpose: string): SuiteKeyClass | undefined {
  return REGISTRY.get(purpose)?.keyClass;
}

// Whether a signer of the given key class is permitted to sign this purpose. Exact class match; an
// unknown purpose or the `unsigned` fingerprint is never signable (A.9 #10, cross-purpose rejection).
export function mayKeyClassSign(purpose: string, keyClass: SuiteKeyClass): boolean {
  const expected = keyClassForPurpose(purpose);
  if (expected === undefined || expected === "unsigned") return false;
  return expected === keyClass;
}

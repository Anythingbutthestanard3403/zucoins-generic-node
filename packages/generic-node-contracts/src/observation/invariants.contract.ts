/**
 * SOURCE: the data model (the six `gateway_observations` CHECK constraints) and the
 * observation-verification contract.
 *
 * Each entry names a machine-checkable field-presence or format invariant of a single raw
 * observation row. record-verifier.ts enforces exactly this closed set and tags every
 * rejection with an `id` below; the census test asserts the two lists agree, so the verifier
 * can never silently enforce a rule that is not frozen here.
 */

export interface RecordInvariant {
  readonly id: string;
  readonly rule: string;
}

export const RECORD_INVARIANTS = [
  {
    id: "ENUM_DOMAINS",
    rule: "parse_result and relationship, and wallet_role when non-null, are members of their frozen vocabularies",
  },
  {
    id: "FIELD_A_FINGERPRINT_IFF_VERIFIED",
    rule: "semantic_fingerprint is non-null exactly when parse_result is VERIFIED_GENESIS or VERIFIED_HEAD",
  },
  {
    id: "FIELD_B_STATE_CHANGED_IFF_VERIFIED",
    rule: "state_changed is non-null exactly when parse_result is verified",
  },
  {
    id: "FIELD_C_HEAD_MATERIAL_IFF_HEAD",
    rule: "inner_preimage_text, step_1_signature, step_2_signature, completed_transaction_text, and completed_transaction_sha256 are all non-null exactly when parse_result is VERIFIED_HEAD",
  },
  {
    id: "FIELD_D_GENESIS_SHAPE",
    rule: "VERIFIED_GENESIS requires wallet_role='genesis', s_signature='', p_signature='', b_amount='0', and null head material",
  },
  {
    id: "FIELD_E_HEAD_SHAPE",
    rule: "VERIFIED_HEAD requires wallet_role in {sender,receiver}, padded s/step_1/step_2 signatures, empty-or-padded p_signature, non-null b_amount, and non-empty inner_preimage_text and completed_transaction_text",
  },
  {
    id: "FIELD_F_NONVERIFIED_SHAPE",
    rule: "a non-verified parse_result requires relationship='NOT_APPLICABLE' and null wallet_role, s_signature, p_signature, b_amount, and all head material",
  },
  {
    id: "SCALAR_FORMATS",
    rule: "endpoint_fingerprint/raw_response_sha256 and any non-null semantic_fingerprint/completed_transaction_sha256 match sha256_hex; wallet_public_key matches padded_base64url_pubkey; any non-null b_amount matches zkz_balance_text; wallet_seq is a positive integer; raw_response_bytes is present",
  },
] as const satisfies readonly RecordInvariant[];

export type RecordInvariantId = (typeof RECORD_INVARIANTS)[number]["id"];

export const RECORD_INVARIANT_IDS = RECORD_INVARIANTS.map((invariant) => invariant.id) as readonly RecordInvariantId[];

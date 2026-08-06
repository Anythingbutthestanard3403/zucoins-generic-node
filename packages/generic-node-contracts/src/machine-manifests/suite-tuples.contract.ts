/**
 * Covers A.3.4
 * (artifact envelope), A.4.2 (`zp-destination-bless-v1`), A.4.3 (`zp-device-enrol-v1`),
 * A.6 (deferred implementer tuples), A.7 (`zp-wallet-head-fingerprint-v1`).
 *
 * the fixture-provenance purposes census — the suite-tuple field sequences no earlier concern froze. The expected-artifact
 * approval, reporting-request/register, and node-event sequences stay owned by the artifacts /
 * approval / reporting-tuples / reporting-auth concerns (see `purposes.contract.ts`'s census);
 * this module freezes the remaining three — destination-bless, device-enrol, and the unsigned
 * wallet-head fingerprint — plus the A.3.4 artifact envelope and the ceremony window rule.
 * DATA ONLY so `gen/suite-tuples.json` stays a clean review-diff snapshot.
 */

/** Manifest version (v1 `*_CONTRACT_VERSION` discipline): bump on any reviewed change. */
export const SUITE_TUPLES_CONTRACT_VERSION = 1 as const;

/** Closed set of field value-type tokens used across these tuples (frozen for census). */
export const SUITE_TUPLE_FIELD_TYPES = [
  "purpose_literal",
  "canonical_version_literal",
  "uuid",
  "ed25519_pubkey_padded",
  "external_address_padded",
  "unicode_label",
  "canonical_timestamp",
  "state_kind_literal",
  "signature_padded_or_empty",
  "signature_padded_nullable",
  "zkz_balance_string",
  "sha256_hex_nullable",
] as const;

export type SuiteTupleFieldType = (typeof SUITE_TUPLE_FIELD_TYPES)[number];

export interface SuiteTupleFieldDescriptor {
  readonly name: string;
  readonly type: SuiteTupleFieldType;
  /** `true` means the field is ALWAYS present and MAY be JSON `null`; it is never omitted
   *  (A.1.1 rule 7). `false` means a concrete non-null value is always required. */
  readonly nullable: boolean;
}

/** A.4.2 `zp-destination-bless-v1` — 9 fields in exact sequence. Signed by an existing operator
 *  device key; TOTP alone cannot bless custody. */
export const DESTINATION_BLESS_TUPLE = {
  purpose: "zp-destination-bless-v1",
  canonicalVersion: 1,
  signingKeyRole: "device",
  serializer: "suite",
  fields: [
    { name: "purpose", type: "purpose_literal", nullable: false },
    { name: "canonical_version", type: "canonical_version_literal", nullable: false },
    { name: "node_id", type: "uuid", nullable: false },
    { name: "destination_id", type: "uuid", nullable: false },
    { name: "wallet_id", type: "uuid", nullable: false },
    { name: "wallet_pubkey", type: "ed25519_pubkey_padded", nullable: false },
    { name: "nonce", type: "uuid", nullable: false },
    { name: "issued_at", type: "canonical_timestamp", nullable: false },
    { name: "expires_at", type: "canonical_timestamp", nullable: false },
  ],
} as const;

/** A.4.3 `zp-device-enrol-v1` — 9 fields in exact sequence. Signed by an existing trusted
 *  device or an explicitly frozen break-glass key, never authorized by bare login alone. */
export const DEVICE_ENROL_TUPLE = {
  purpose: "zp-device-enrol-v1",
  canonicalVersion: 1,
  signingKeyRole: "device",
  serializer: "suite",
  fields: [
    { name: "purpose", type: "purpose_literal", nullable: false },
    { name: "canonical_version", type: "canonical_version_literal", nullable: false },
    { name: "node_id", type: "uuid", nullable: false },
    { name: "new_device_key_id", type: "uuid", nullable: false },
    { name: "new_device_public_key", type: "ed25519_pubkey_padded", nullable: false },
    { name: "label", type: "unicode_label", nullable: false },
    { name: "nonce", type: "uuid", nullable: false },
    { name: "issued_at", type: "canonical_timestamp", nullable: false },
    { name: "expires_at", type: "canonical_timestamp", nullable: false },
  ],
} as const;

/** A.4.3 field 6 (`label`) rules: 1-80 Unicode scalar values AND at most 320 UTF-8 bytes;
 * well-formed UTF-8; no normalization, fail-closed on the denylisted categories. The category
 * tables are pinned to Unicode 17.0. */
export const DEVICE_ENROL_LABEL_RULES = {
  minScalars: 1,
  maxScalars: 80,
  maxUtf8Bytes: 320,
  normalization: "none",
  internalWhitespacePermitted: "U+0020 only",
  leadingTrailingSpace: "reject",
  denylistedCategories: [
    "C0/C1 controls (U+0000-U+001F, U+007F-U+009F)",
    "surrogates (U+D800-U+DFFF)",
    "noncharacters (U+FDD0-U+FDEF, U+xFFFE/xFFFF)",
    "line/paragraph separators (U+2028/U+2029)",
    "BOM/ZWNBSP (U+FEFF)",
    "BiDi/zero-width format controls (U+200B-U+200D, U+202A-U+202E, U+2066-U+2069)",
  ],
  malformedUtf8: "reject (overlong, truncated, lone surrogate)",
  unicodeVersionPin: "17.0",
} as const;

/** A.7 `zp-wallet-head-fingerprint-v1` — 10 fields in exact sequence. Uses the suite serializer
 *  and SHA-256 but is NOT signed: node and platform compare semantic state independently of the
 *  gateway transport. */
export const WALLET_HEAD_FINGERPRINT_TUPLE = {
  purpose: "zp-wallet-head-fingerprint-v1",
  canonicalVersion: 1,
  signed: false,
  serializer: "suite",
  fields: [
    { name: "purpose", type: "purpose_literal", nullable: false },
    { name: "canonical_version", type: "canonical_version_literal", nullable: false },
    { name: "wallet_public_key", type: "ed25519_pubkey_padded", nullable: false },
    { name: "state_kind", type: "state_kind_literal", nullable: false },
    { name: "s_signature", type: "signature_padded_or_empty", nullable: false },
    { name: "p_signature", type: "signature_padded_or_empty", nullable: false },
    { name: "b_amount", type: "zkz_balance_string", nullable: false },
    { name: "inner_sha256", type: "sha256_hex_nullable", nullable: true },
    { name: "step_1_signature", type: "signature_padded_nullable", nullable: true },
    { name: "step_2_signature", type: "signature_padded_nullable", nullable: true },
  ],
} as const;

/** A.7 exclusions: transport facts are never fingerprint inputs. */
export const WALLET_HEAD_FINGERPRINT_EXCLUSIONS = [
  "gateway envelope",
  "endpoint",
  "observation time",
  "HTTP status",
  "raw-response hash",
] as const;

/** A.3.4 artifact envelope — NOT itself signed; exact fields (the API contract repeats it verbatim). */
export const ARTIFACT_ENVELOPE_FIELD_SEQUENCE = [
  "key_id",
  "preimage_text",
  "preimage_sha256",
  "signature",
] as const;

/** The ceremony window (A.4.1-A.4.3): `0 < expires_at − issued_at ≤ 300s`, checked against
 *  the SIGNED `issued_at` before signature verification. A deployment MAY tighten, MUST NOT
 *  exceed 300s, and a permanent-authority ceremony (bless/enrol) MUST NOT be looser than
 *  `zp-send-external-approval-v1`'s window. */
export const CEREMONY_WINDOW_RULE = {
  maxSeconds: 300,
  lowerBoundExclusiveSeconds: 0,
  checkedAgainst: "signed issued_at, never receipt time",
  deploymentMayTighten: true,
  permanentCeremonyMustNotBeLooserThanApproval: true,
} as const;

/** The reporting-request window is deliberately tighter than the ceremony class (A.5). */
export const REPORT_REQUEST_WINDOW_MAX_SECONDS = 60 as const;

/** A.6 dual-continuity tuples: architecture frozen, field sequence and byte-exact golden
 *  DEFERRED to the byte-freeze child (binding condition C4). Frozen here only as a deferral
 *  record — never as usable field sequences. */
export const DEFERRED_IMPLEMENTER_TUPLES = [
  { purpose: "zp-implementer-event-v1", disposition: "deferred-c4" },
  { purpose: "zp-implementer-checkpoint-v1", disposition: "deferred-c4" },
  { purpose: "zp-implementer-keyrotation-v1", disposition: "deferred-c4" },
] as const;

export const SOURCE = "suite tuples A.3.4, A.4.2, A.4.3, A.6, A.7; artifacts-freeze" as const;

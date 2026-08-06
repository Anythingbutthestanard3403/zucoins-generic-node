/**
 * The artifacts freeze (A.1.1, A.1.3, A.2, A.3.1-A.3.3 byte contract): exactly one
 * domain-separated, node-identity-signed expected-action
 * artifact exists per operation. This module freezes the three surfaces as data only —
 * purposes, canonical version, exact field sequence, per-field type/nullability/role, and the
 * suite domain-separation construction. It is DATA ONLY (no functions) so `gen/artifacts.json`
 * stays a clean review-diff snapshot; the verifier and signing contract live in sibling files.
 *
 * These bytes are frozen. Any field/sequence/semantic change requires a NEW purpose/version and
 * newly reviewed goldens, never an in-place rewrite of a `-v1` surface.
 */

/** The three frozen expected-artifact purposes, in canonical operation sequence. */
export const EXPECTED_ARTIFACT_PURPOSES = [
  "zp-receive-expected-v1",
  "zp-move-internal-expected-v1",
  "zp-send-external-expected-v1",
] as const;

export type ExpectedArtifactPurpose = (typeof EXPECTED_ARTIFACT_PURPOSES)[number];

/** Every expected artifact is version 1 as a JSON number (never the string "1"; A.9 rule 3). */
export const CANONICAL_VERSION = 1 as const;

/** The single signing-key role for all three artifacts: the node identity key (A.3 preamble;
 *  purpose-specific key custody). No wallet, device, reporting, or event key may sign one. */
export const ARTIFACT_SIGNING_KEY_ROLE = "node_identity" as const;

/**
 * Suite domain-separation construction (A.1.1). Distinct from SplitChain native
 * signing (A.1.2), which uses NO purpose prefix — the two schemes never share bytes.
 */
export const SUITE_PREIMAGE_CONSTRUCTION = {
  payloadObject: "object built in the exact field sequence below",
  payloadJson: "JSON.stringify(payload_object)",
  preimageText: 'purpose + "\\n" + payload_json',
  preimageBytes: "UTF8(preimage_text)",
  digest: "lowercase_hex(SHA256(preimage_bytes))",
  signature: "padded_base64url(Ed25519.sign(preimage_bytes, node_identity_key))",
  domainSeparationPrefix: "purpose",
  // `purpose` appears twice by design: once as the prefix, once as payload field 1. A verifier
  // requires BOTH copies to equal the expected literal before checking the signature (A.1.1).
  purposeAppearsAsPrefixAndField1: true,
  splitchainNativeSharesBytes: false,
} as const;

/** Closed set of field value-type tokens used across the three artifacts (frozen for census). */
export const ARTIFACT_FIELD_TYPES = [
  "purpose_literal",
  "canonical_version_literal",
  "uuid",
  "operation_uuid",
  "ed25519_pubkey_padded",
  "external_address_padded",
  "zkz_amount_positive",
  "anchor",
  "sha256_hex",
  "integer_string_nullable",
  "after_landing_object",
  "source_selector_object",
  "uuid_nullable",
] as const;

/** Closed set of per-field semantic roles (frozen for census). */
export const ARTIFACT_FIELD_ROLES = [
  "IDENTITY",
  "PARTY",
  "AMOUNT",
  "REFERENCE",
  "POLICY",
  "BINDING",
  "EXPIRY",
] as const;

export type ArtifactFieldType = (typeof ARTIFACT_FIELD_TYPES)[number];
export type ArtifactFieldRole = (typeof ARTIFACT_FIELD_ROLES)[number];

export interface ArtifactFieldDescriptor {
  readonly name: string;
  readonly type: ArtifactFieldType;
  /** `true` means the field is ALWAYS present and MAY be JSON `null`; it is never omitted
   *  (A.1.1 rule 7). `false` means a concrete non-null value is always required. */
  readonly nullable: boolean;
  readonly role: ArtifactFieldRole;
}

/** A.3.1 `zp-receive-expected-v1` — 14 fields in exact sequence. */
export const RECEIVE_EXPECTED = {
  purpose: "zp-receive-expected-v1",
  canonicalVersion: CANONICAL_VERSION,
  signingKeyRole: ARTIFACT_SIGNING_KEY_ROLE,
  serializer: "suite",
  fields: [
    { name: "purpose", type: "purpose_literal", nullable: false, role: "IDENTITY" },
    { name: "canonical_version", type: "canonical_version_literal", nullable: false, role: "IDENTITY" },
    { name: "node_id", type: "uuid", nullable: false, role: "IDENTITY" },
    { name: "implementer_id", type: "uuid", nullable: false, role: "IDENTITY" },
    { name: "operation_id", type: "uuid", nullable: false, role: "IDENTITY" },
    { name: "receiver_wallet_id", type: "uuid", nullable: false, role: "PARTY" },
    { name: "receiver_pubkey", type: "ed25519_pubkey_padded", nullable: false, role: "PARTY" },
    { name: "amount_zkz", type: "zkz_amount_positive", nullable: false, role: "AMOUNT" },
    { name: "discriminator", type: "operation_uuid", nullable: false, role: "REFERENCE" },
    { name: "anchor", type: "anchor", nullable: false, role: "BINDING" },
    { name: "receiver_t0_fingerprint", type: "sha256_hex", nullable: false, role: "BINDING" },
    { name: "expiry_unix_time_secs", type: "integer_string_nullable", nullable: true, role: "EXPIRY" },
    { name: "after_landing", type: "after_landing_object", nullable: false, role: "POLICY" },
    { name: "transfer_code_sha256", type: "sha256_hex", nullable: false, role: "BINDING" },
  ],
} as const;

/** A.3.2 `zp-move-internal-expected-v1` — 13 fields in exact sequence. A parent receive
 *  artifact is NOT a substitute for this move artifact (A.3.2). */
export const MOVE_INTERNAL_EXPECTED = {
  purpose: "zp-move-internal-expected-v1",
  canonicalVersion: CANONICAL_VERSION,
  signingKeyRole: ARTIFACT_SIGNING_KEY_ROLE,
  serializer: "suite",
  fields: [
    { name: "purpose", type: "purpose_literal", nullable: false, role: "IDENTITY" },
    { name: "canonical_version", type: "canonical_version_literal", nullable: false, role: "IDENTITY" },
    { name: "node_id", type: "uuid", nullable: false, role: "IDENTITY" },
    { name: "implementer_id", type: "uuid", nullable: false, role: "IDENTITY" },
    { name: "operation_id", type: "uuid", nullable: false, role: "IDENTITY" },
    { name: "source_wallet_id", type: "uuid", nullable: false, role: "PARTY" },
    { name: "source_pubkey", type: "ed25519_pubkey_padded", nullable: false, role: "PARTY" },
    { name: "destination_id", type: "uuid", nullable: false, role: "PARTY" },
    { name: "destination_wallet_id", type: "uuid", nullable: false, role: "PARTY" },
    { name: "destination_pubkey", type: "ed25519_pubkey_padded", nullable: false, role: "PARTY" },
    { name: "amount_zkz", type: "zkz_amount_positive", nullable: false, role: "AMOUNT" },
    { name: "spawned_from_operation_id", type: "uuid_nullable", nullable: true, role: "REFERENCE" },
    { name: "references_operation_id", type: "uuid_nullable", nullable: true, role: "REFERENCE" },
  ],
} as const;

/** A.3.3 `zp-send-external-expected-v1` — 10 fields in exact sequence. This artifact binds
 *  immutable economic intent; it does NOT bind a later-formed SplitChain inner (A.3.3, the approval-tuple freeze).
 *  It carries no expiry field — the time bound lives on the separate `zp-send-external-approval-v1`
 *  tuple (A.4.1), which is outside the artifacts freeze's frozen-artifact scope. */
export const SEND_EXTERNAL_EXPECTED = {
  purpose: "zp-send-external-expected-v1",
  canonicalVersion: CANONICAL_VERSION,
  signingKeyRole: ARTIFACT_SIGNING_KEY_ROLE,
  serializer: "suite",
  fields: [
    { name: "purpose", type: "purpose_literal", nullable: false, role: "IDENTITY" },
    { name: "canonical_version", type: "canonical_version_literal", nullable: false, role: "IDENTITY" },
    { name: "node_id", type: "uuid", nullable: false, role: "IDENTITY" },
    { name: "implementer_id", type: "uuid", nullable: false, role: "IDENTITY" },
    { name: "operation_id", type: "uuid", nullable: false, role: "IDENTITY" },
    { name: "source_selector", type: "source_selector_object", nullable: false, role: "PARTY" },
    { name: "source_pubkey", type: "ed25519_pubkey_padded", nullable: false, role: "PARTY" },
    { name: "destination_address", type: "external_address_padded", nullable: false, role: "PARTY" },
    { name: "amount_zkz", type: "zkz_amount_positive", nullable: false, role: "AMOUNT" },
    { name: "references_operation_id", type: "uuid_nullable", nullable: true, role: "REFERENCE" },
  ],
} as const;

export type ExpectedArtifactManifest =
  | typeof RECEIVE_EXPECTED
  | typeof MOVE_INTERNAL_EXPECTED
  | typeof SEND_EXTERNAL_EXPECTED;

/** All three manifests in canonical operation sequence. */
export const EXPECTED_ARTIFACTS = [
  RECEIVE_EXPECTED,
  MOVE_INTERNAL_EXPECTED,
  SEND_EXTERNAL_EXPECTED,
] as const;

export const SOURCE =
  "expected-artifact byte contract A.1, A.3, goldens A.8-A.9; artifacts freeze" as const;

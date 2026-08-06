/**
 * The approval-tuple schema CONTRACT_FREEZE: the A.1.1 suite serializer, the A.4.1
 * `zp-send-external-approval-v1` field sequence, the A.8 golden bytes, and the A.9 negative
 * vectors. This freezes the approval tuple that binds one send's IMMUTABLE
 * economic intent — the exact field sequence, per-field type/role, the suite serializer, and the
 * authentication semantics (fresh single-use TOTP authenticates the guarded mutation and is NOT a
 * signature; an optional additive device key MAY sign the exact approval bytes). It is DATA ONLY
 * (no functions) so a review-diff snapshot stays clean; the pure verifier lives in `verify.ts`.
 *
 * These bytes are frozen. Any change to a field, its sequence, or its type requires a new
 * purpose/version and newly reviewed goldens (the artifacts freeze and approval-tuple freeze rules), never an in-place rewrite of the `-v1`
 * surface. A changed source, destination, amount, operation/reference, nonce, issue time, or
 * expiry is a DIFFERENT economic intent and demands a fresh approval.
 */

/** The frozen approval purpose (a compatibility-preserved `zp-*-v1` literal). It appears twice by design:
 *  once as the suite domain-separation prefix and once as payload field 1 (A.1.1). */
export const APPROVAL_PURPOSE = "zp-send-external-approval-v1" as const;
export type ApprovalPurpose = typeof APPROVAL_PURPOSE;

/** Canonical version as the JSON number 1 — never the string "1" (A.9 rule 3). */
export const APPROVAL_CANONICAL_VERSION = 1 as const;

/**
 * Suite domain-separation construction (A.1.1), identical to the expected-artifact
 * surfaces and DISTINCT from SplitChain native signing (A.1.2), which uses NO purpose prefix.
 * The two schemes therefore never share preimage bytes — the approval-preimage isolation this
 * concern proves in `reproduction.test.ts` (A.9 vector 15).
 */
export const APPROVAL_PREIMAGE_CONSTRUCTION = {
  payloadObject: "object built in the exact field sequence below",
  payloadJson: "JSON.stringify(payload_object)",
  preimageText: 'purpose + "\\n" + payload_json',
  preimageBytes: "UTF8(preimage_text)",
  digest: "lowercase_hex(SHA256(preimage_bytes))",
  domainSeparationPrefix: "purpose",
  purposeAppearsAsPrefixAndField1: true,
  splitchainNativeSharesBytes: false,
} as const;

/**
 * Authentication semantics. The MANDATORY gate on the approval mutation
 * is a fresh single-use TOTP, consumed before the mutation and never restored after a downstream
 * failure. TOTP authenticates a guarded mutation; it does NOT sign the tuple, run over the tuple,
 * or prove non-repudiation. An OPTIONAL additive device Ed25519 signature MAY cover the exact
 * approval preimage bytes; it never replaces the TOTP. This is the frozen distinction A.9 vectors
 * 13 (TOTP accepted as if it were a tuple signature) and 14 (device signature used without the
 * mandatory fresh TOTP) forbid.
 */
export const APPROVAL_AUTH = {
  mandatoryGate: "fresh_single_use_totp",
  totpIsDigitalSignature: false,
  totpBinding: "guarded_mutation",
  optionalDeviceSignature: true,
  deviceSignatureKind: "additive_hardening",
  deviceSignatureSignsExactApprovalBytes: true,
  deviceSignatureReplacesTotp: false,
  deviceSignatureAloneAuthorizes: false,
} as const;

/**
 * Sequencing fact. Approval strictly PRECEDES source-lease acquisition and
 * fresh chain formation. At approval time no source lease is held and no SplitChain inner exists,
 * so the tuple deliberately carries no `split_inner_sha256` and binds no later-formed inner
 * (A.4.1). It fixes economic intent only; the exact chain bytes are bound later, once, by the
 * post-approval sign intent (frozen in `sign-intent.contract.ts`).
 */
export const APPROVAL_ORDERING = ["APPROVAL", "SOURCE_LEASE_ACQUISITION", "FRESH_CHAIN_FORMATION"] as const;
export type ApprovalOrderingPhase = (typeof APPROVAL_ORDERING)[number];

export const APPROVAL_FORMATION_TIME_FACTS = {
  sourceLeaseHeldAtApprovalTime: false,
  splitchainInnerFormedAtApprovalTime: false,
  bindsLaterFormedSplitchainInner: false,
  carriesSplitInnerSha256Field: false,
} as const;

/** Closed set of value-type tokens across the approval tuple (frozen for census). */
export const APPROVAL_FIELD_TYPES = [
  "purpose_literal",
  "canonical_version_literal",
  "uuid",
  "operation_uuid",
  "source_selector_object",
  "ed25519_pubkey_padded",
  "external_address_padded",
  "zkz_amount_positive",
  "uuid_nullable",
  "canonical_timestamp",
] as const;
export type ApprovalFieldType = (typeof APPROVAL_FIELD_TYPES)[number];

/**
 * Closed set of per-field economic-intent roles (frozen for census). The approval-tuple freeze names the immutable
 * economic intent as exactly: source, destination, amount, operation/reference, nonce, issue time,
 * and expiry — each modelled as its own role so the census can prove the intent decomposition is
 * complete and that no field silently changes role.
 */
export const APPROVAL_FIELD_ROLES = [
  "IDENTITY",
  "SOURCE",
  "DESTINATION",
  "AMOUNT",
  "REFERENCE",
  "NONCE",
  "ISSUE_TIME",
  "EXPIRY",
] as const;
export type ApprovalFieldRole = (typeof APPROVAL_FIELD_ROLES)[number];

export interface ApprovalFieldDescriptor {
  readonly name: string;
  readonly type: ApprovalFieldType;
  /** `true` means the field is ALWAYS present and MAY be JSON `null`; it is never omitted
   *  (A.1.1 rule 7). `false` means a concrete non-null value is always required. */
  readonly nullable: boolean;
  readonly role: ApprovalFieldRole;
}

/**
 * A.4.1 `zp-send-external-approval-v1` — 12 fields in exact sequence. `expires_at` must be a
 * canonical timestamp strictly later than `issued_at`. Only `references_operation_id` is nullable.
 */
export const APPROVAL_TUPLE = {
  purpose: APPROVAL_PURPOSE,
  canonicalVersion: APPROVAL_CANONICAL_VERSION,
  serializer: "suite",
  optionalSignatureKeyRole: "device",
  fields: [
    { name: "purpose", type: "purpose_literal", nullable: false, role: "IDENTITY" },
    { name: "canonical_version", type: "canonical_version_literal", nullable: false, role: "IDENTITY" },
    { name: "node_id", type: "uuid", nullable: false, role: "IDENTITY" },
    { name: "operation_id", type: "operation_uuid", nullable: false, role: "REFERENCE" },
    { name: "source_selector", type: "source_selector_object", nullable: false, role: "SOURCE" },
    { name: "source_pubkey", type: "ed25519_pubkey_padded", nullable: false, role: "SOURCE" },
    { name: "destination_address", type: "external_address_padded", nullable: false, role: "DESTINATION" },
    { name: "amount_zkz", type: "zkz_amount_positive", nullable: false, role: "AMOUNT" },
    { name: "references_operation_id", type: "uuid_nullable", nullable: true, role: "REFERENCE" },
    { name: "nonce", type: "uuid", nullable: false, role: "NONCE" },
    { name: "issued_at", type: "canonical_timestamp", nullable: false, role: "ISSUE_TIME" },
    { name: "expires_at", type: "canonical_timestamp", nullable: false, role: "EXPIRY" },
  ],
} as const;

export type ApprovalTupleManifest = typeof APPROVAL_TUPLE;

/**
 * WALLET_ID closure (the A.4.1 `source_selector` field). A resolved `source_selector` inside
 * SIGNED approval bytes is ALWAYS the exact two-key object `{kind:"WALLET_ID", wallet_id}`, in
 * that key sequence. Every other selector kind (an unresolved reference, alias, or lookup) is a
 * PRE-resolution concept the node resolves to a concrete `wallet_id` before signing; it never
 * itself reaches signed bytes. The verifier (`verify.ts` `isValidSourceSelector`) enforces this
 * closure by rejecting any other `kind` or any selector with a third key.
 */
export const SOURCE_SELECTOR_SIGNED_CLOSURE = {
  signedKind: "WALLET_ID",
  signedKeyOrder: ["kind", "wallet_id"],
  signedKeyCount: 2,
  onlyResolvedSelectorReachesSignedBytes: true,
} as const;

export const SOURCE = "canonical serialization A.1.1, tuple A.4.1, goldens A.8, negative vectors A.9; approval-tuple freeze; two-timer separation" as const;

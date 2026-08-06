// the crypto-goldens freeze — A.9 negative vector definitions with documented rejection reasons.
// Each vector describes a mutation that a conforming verifier MUST reject.
// The A.9 required negative vectors; artifacts freeze, compatibility-literal preservation,
// reporting-key enrolment.

export interface NegativeVector {
  readonly id: string;
  readonly category: "general" | "reporting-register";
  readonly rejectionReason: string;
  readonly specRef: string;
}

// A.9 general negative vectors (17 cases, applicable to every tuple)
export const GENERAL_NEGATIVE_VECTORS: readonly NegativeVector[] = [
  {
    id: "field-reorder",
    category: "general",
    rejectionReason: "Field reorder, missing field, unexpected field, or optional field omitted instead of null",
    specRef: "A.9 #1",
  },
  {
    id: "purpose-mismatch",
    category: "general",
    rejectionReason: "Prefix purpose/payload purpose mismatch",
    specRef: "A.9 #2",
  },
  {
    id: "version-string",
    category: "general",
    rejectionReason: "Canonical version as string \"1\" or any value other than number 1",
    specRef: "A.9 #3",
  },
  {
    id: "uuid-uppercase",
    category: "general",
    rejectionReason: "UUID uppercase/non-canonical spelling",
    specRef: "A.9 #4",
  },
  {
    id: "unpadded-key",
    category: "general",
    rejectionReason: "Unpadded key/signature, invalid decoded length, or non-canonical re-encode",
    specRef: "A.9 #5",
  },
  {
    id: "amount-numeric",
    category: "general",
    rejectionReason: "Amount as JSON number, exponent, signed value, leading zero, or more than 32 decimals",
    specRef: "A.9 #6",
  },
  {
    id: "timestamp-malformed",
    category: "general",
    rejectionReason: "Timestamp without exactly three fractional digits or without Z",
    specRef: "A.9 #7",
  },
  {
    id: "preimage-whitespace",
    category: "general",
    rejectionReason: "Newline/BOM/whitespace appended to the preimage",
    specRef: "A.9 #8",
  },
  {
    id: "nfc-substitution",
    category: "general",
    rejectionReason: "NFC/NFD substitution in any UTF-8 string",
    specRef: "A.9 #9",
  },
  {
    id: "cross-purpose-signature",
    category: "general",
    rejectionReason: "Cross-purpose signature verification",
    specRef: "A.9 #10",
  },
  {
    id: "transfer-code-decoded",
    category: "general",
    rejectionReason: "Transfer-code hash after decoding or padding repair instead of exact input-string hash",
    specRef: "A.9 #11",
  },
  {
    id: "report-request-mutation",
    category: "general",
    rejectionReason: "Reporting request method/path/body change or nonce replay",
    specRef: "A.9 #12",
  },
  {
    id: "totp-as-signature",
    category: "general",
    rejectionReason: "TOTP accepted as if it were a tuple signature",
    specRef: "A.9 #13",
  },
  {
    id: "device-sig-without-totp",
    category: "general",
    rejectionReason: "Device signature used without the mandatory fresh TOTP guarded mutation",
    specRef: "A.9 #14",
  },
  {
    id: "jsonb-reconstruction",
    category: "general",
    rejectionReason: "Any reconstruction of SplitChain preimages from JSONB",
    specRef: "A.9 #15",
  },
  {
    id: "golden-key-live-chain",
    category: "general",
    rejectionReason: "Any golden fixture key used when live-chain mode is enabled",
    specRef: "A.9 #16",
  },
  {
    id: "funded-sender-genesis-predecessor",
    category: "general",
    rejectionReason: "Validly re-signed RECEIVE target whose funded sender uses an empty genesis predecessor (funded-sender/genesis-predecessor during sender preflight)",
    specRef: "A.9 #17",
  },
] as const;

// A.9 zp-reporting-register-v1 specific negative vectors (6 cases)
export const REGISTER_NEGATIVE_VECTORS: readonly NegativeVector[] = [
  {
    id: "register-supersedes-omitted",
    category: "reporting-register",
    rejectionReason: "supersedes_key_id omitted instead of null",
    specRef: "A.9 register #1",
  },
  {
    id: "register-key-invalid",
    category: "reporting-register",
    rejectionReason: "new_reporting_public_key unpadded, wrong-length, non-canonically re-encoded, small-subgroup, or identity element (rejected before PoP signature)",
    specRef: "A.9 register #2",
  },
  {
    id: "register-pop-wrong-key",
    category: "reporting-register",
    rejectionReason: "PoP signature by any key other than the in-tuple new_reporting_public_key",
    specRef: "A.9 register #3",
  },
  {
    id: "register-window-exceeded",
    category: "reporting-register",
    rejectionReason: "Enrolment expires_at more than 300 seconds after issued_at",
    specRef: "A.9 register #4",
  },
  {
    id: "register-nonce-replay",
    category: "reporting-register",
    rejectionReason: "Nonce replayed for the same (implementer_id, node_id)",
    specRef: "A.9 register #5",
  },
  {
    id: "register-revoked-key",
    category: "reporting-register",
    rejectionReason: "Revoked or post-overlap key still accepted",
    specRef: "A.9 register #6",
  },
] as const;

export const ALL_NEGATIVE_VECTORS: readonly NegativeVector[] = [
  ...GENERAL_NEGATIVE_VECTORS,
  ...REGISTER_NEGATIVE_VECTORS,
] as const;

export const GENERAL_NEGATIVE_COUNT = GENERAL_NEGATIVE_VECTORS.length;
export const REGISTER_NEGATIVE_COUNT = REGISTER_NEGATIVE_VECTORS.length;
export const TOTAL_NEGATIVE_COUNT = ALL_NEGATIVE_VECTORS.length;

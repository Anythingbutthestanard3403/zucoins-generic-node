/**
 * The protocol scalar types and reference scalar domains; the amounts-grammar freeze (bounded balance
 * domain override).
 *
 * the fixture-provenance purposes census — the schema-vocabulary manifest category: the ten protocol rule 2 scalar types and the data model 1
 * database reference domains. The committed regex constants are OWNED by
 * `src/observation/scalars.contract.ts` (including the amounts-grammar freeze `zkz_balance_text` override) and
 * restated here with their owner named, with the census test asserting both freezes agree.
 * DATA ONLY so `gen/schema-vocabs.json` stays a clean review-diff snapshot. (Emitted contract
 * modules are import-free leaves: the emitter runs plain Node type-stripping.)
 */

/** Manifest version (v1 `*_CONTRACT_VERSION` discipline): bump on any reviewed change. */
export const SCHEMA_VOCABS_CONTRACT_VERSION = 1 as const;

export interface ScalarTypeEntry {
  readonly name: string;
  readonly wire: string;
  readonly rule: string;
}

/** The protocol rule 2 scalar-type table, transcribed verbatim in declaration sequence. Runtime schemas
 *  MUST validate these at every trust boundary. */
export const SCALAR_TYPES: readonly ScalarTypeEntry[] = [
  {
    name: "Uuid",
    wire: "lowercase canonical UUID string",
    rule: "RFC 4122 textual form; APIs reject alternate spellings",
  },
  {
    name: "WalletPublicKey",
    wire: "ASCII string",
    rule: "padded base64url; decodes to exactly 32 bytes; canonical re-encode equals input; normally 44 chars",
  },
  {
    name: "Ed25519Signature",
    wire: "ASCII string",
    rule: "padded base64url; decodes to exactly 64 bytes; canonical re-encode equals input; normally 88 chars",
  },
  {
    name: "ZkzAmount",
    wire: "decimal ASCII string",
    rule: "^(0|[1-9][0-9]*)(\\.[0-9]{1,32})?$; non-negative; no sign, exponent, separators, leading zero, or trailing decimal point",
  },
  {
    name: "PositiveZkzAmount",
    wire: "ZkzAmount",
    rule: "mathematically greater than zero and at most 100000000",
  },
  {
    name: "UnixTimeSecsV2",
    wire: "decimal ASCII string",
    rule: "finite non-negative decimal emitted by the wallet-compatible clock path; never converted to number after construction",
  },
  {
    name: "ExpiryUnixTimeSecs",
    wire: "decimal ASCII string",
    rule: "integer seconds; request-specific protocol bounds apply",
  },
  {
    name: "Sha256Hex",
    wire: "ASCII string",
    rule: "exactly 64 lowercase hexadecimal characters",
  },
  {
    name: "CanonicalVersion",
    wire: "integer",
    rule: "value 1 for all *-v1 v2-suite tuples",
  },
  {
    name: "OpaqueReference",
    wire: "UTF-8 string",
    rule: "limits set by API schema; never interpolated into signed SplitChain fields unless explicitly named",
  },
];

/** The unbounded data model 1 `zkz_amount_text` reference domain regex. */
export const ZKZ_AMOUNT_TEXT_PATTERN = "^(0|[1-9][0-9]*)(\\.[0-9]{1,32})?$" as const;

export const ZKZ_AMOUNT_MAX_DECIMAL_PLACES = 32 as const;
export const POSITIVE_ZKZ_AMOUNT_MAX = "100000000" as const;

/** `sha256_hex` — lowercase hex digest. OWNED by `src/observation/scalars.contract.ts`. */
export const SHA256_HEX_PATTERN = "^[0-9a-f]{64}$" as const;

/** `padded_base64url_pubkey` — 43 base64url chars + one `=`. OWNED by
 *  `src/observation/scalars.contract.ts`. */
export const PADDED_BASE64URL_PUBKEY_PATTERN = "^[A-Za-z0-9_-]{43}=$" as const;
export const PADDED_BASE64URL_PUBKEY_LENGTH = 44 as const;

/** `padded_base64url_signature` — 86 base64url chars + `==`. OWNED by
 *  `src/observation/scalars.contract.ts`. */
export const PADDED_BASE64URL_SIGNATURE_PATTERN = "^[A-Za-z0-9_-]{86}==$" as const;
export const PADDED_BASE64URL_SIGNATURE_LENGTH = 88 as const;

/** The amounts-grammar freeze bounded balance domain (`zkz_balance_text`): role-relative balances allow "0" and
 *  bound the integer part to 8 digits. OWNED by `src/observation/scalars.contract.ts`. */
export const ZKZ_BALANCE_TEXT_PATTERN = "^(0|[1-9][0-9]{0,7})(\\.[0-9]{1,32})?$" as const;

/** The data model 1 reference scalar domains (name → regex). The regexes are a first boundary only:
 *  runtime validation MUST decode, length-check, canonically re-encode, and compare
 *  key/signature material — database insertion is not proof of valid Ed25519 material. */
export const DB_REFERENCE_DOMAINS = {
  zkz_amount_text: ZKZ_AMOUNT_TEXT_PATTERN,
  sha256_hex: SHA256_HEX_PATTERN,
  padded_base64url_pubkey: PADDED_BASE64URL_PUBKEY_PATTERN,
  padded_base64url_signature: PADDED_BASE64URL_SIGNATURE_PATTERN,
} as const;

/** protocol rule 2 canonical decimal formatter rules for newly constructed values. */
export const CANONICAL_DECIMAL_FORMATTER_RULES = {
  removesTrailingFractionalZeros: true,
  removesDecimalPointWhenFractionEmpty: true,
  emitsZeroNeverNegativeZero: true,
  foreignSignedBytesNeverRewrittenToMatch: true,
} as const;

export const SOURCE = "protocol scalar types; reference scalar domains; canonical amount bound" as const;

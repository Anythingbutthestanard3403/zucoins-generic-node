/**
 * The exact SplitChain v2 inner and its signed preimages (protocol rules 3 and 4.1); A.1.2
 * (SplitChain native signing — NO suite prefix).
 *
 * the fixture-provenance purposes census — the frozen SplitChain inner field vocabulary: the exact 14-position field
 * sequence, the required/optional split, the state-object and settled-text sequences, and the
 * preimage constructions. The byte-exact signing rule territory: this is the byte-compatibility surface.
 * Object spread, alphabetical sorting, schema serializers that reorder keys, and parse/rebuild
 * cycles are forbidden on the signing path (protocol rule 3). DATA ONLY — byte authority lives here, never
 * in `gen/fields.json`.
 *
 * This module freezes the SplitChain-native (no suite prefix) encoding of A.1.2. The
 * domain-separated suite encoding of A.1.1 is a DIFFERENT byte class (`prefixes.contract.ts`);
 * the two encodings never share bytes and are never conflated in one manifest entry.
 */

/** Manifest version (v1 `*_CONTRACT_VERSION` discipline): bump on any reviewed change. */
export const FIELDS_CONTRACT_VERSION = 1 as const;

/**
 * The exact 14-position inner field sequence (protocol rule 3; A.1.2). Positions 13-14 are the only
 * optional fields, and only in this trailing placement — `expiry__unix_time_secs` precedes
 * `message` when both are present.
 */
export const SPLITCHAIN_INNER_FIELD_SEQUENCE = [
  "type",
  "version",
  "unix_time_secs",
  "signer_steps",
  "step_1_signer",
  "step_2_signer",
  "step_1_key_public__base64urlsafe",
  "step_2_key_public__base64urlsafe",
  "step_1_state",
  "step_2_state",
  "previous_step_1_state_signature",
  "previous_step_2_state_signature",
  "expiry__unix_time_secs",
  "message",
] as const;

/** The 12 always-present fields, in the same frozen sequence. */
export const SPLITCHAIN_INNER_REQUIRED_FIELD_SEQUENCE =
  SPLITCHAIN_INNER_FIELD_SEQUENCE.slice(0, 12);

/** The only optional inner fields; trailing placement only (protocol rule 3). */
export const SPLITCHAIN_INNER_OPTIONAL_FIELDS = ["expiry__unix_time_secs", "message"] as const;

/** The fixed inner literals (protocol rule 3 positions 1, 2, 4, 5, 6). `unix_time_secs` units are a
 *  Byte fact: a SECONDS string, never milliseconds. */
export const SPLITCHAIN_INNER_FIXED_LITERALS = {
  type: "unique_combinable",
  version: "2",
  signerSteps: 2,
  step1Signer: "sender",
  step2Signer: "receiver",
  unixTimeSecsUnit: "seconds",
} as const;

/** Each `step_*_state` object: `amount` first, then optional `metadata` (protocol rule 3 positions 9-10).
 *  `amount` is the role's post-transaction ABSOLUTE balance, never a delta (protocol rule 1.3). */
export const SPLITCHAIN_STATE_OBJECT_FIELD_SEQUENCE = ["amount", "metadata"] as const;

/** The settled ledger text's exact top-level sequence (A.1.2; protocol rule 4.1). It is constructed
 *  once and retained verbatim; it MUST NOT be re-derived with
 *  `JSON.stringify(JSON.parse(stored_text))`. */
export const SPLITCHAIN_SETTLED_TEXT_FIELD_SEQUENCE = [
  "inner",
  "step_1_signature",
  "step_2_signature",
] as const;

/** The step-2 preimage object's exact field sequence: `inner` inserted first,
 *  `step_1_signature` second (protocol rule 4.1). */
export const SPLITCHAIN_STEP_2_PREIMAGE_FIELD_SEQUENCE = ["inner", "step_1_signature"] as const;

/** The native preimage constructions (protocol rule 4.1). There is no prefix, newline, hash,
 *  canonical-JSON pass, or whitespace; signatures are canonical padded base64url. */
export const SPLITCHAIN_PREIMAGE_CONSTRUCTION = {
  step1PreimageText: "JSON.stringify(inner)",
  step2PreimageText: "JSON.stringify({inner,step_1_signature})",
  settledTextTemplate:
    '{"inner":<exact step_1_preimage_text>,"step_1_signature":<JSON string>,"step_2_signature":<JSON string>}',
  utf8EncodeExactStrings: true,
  detachedEd25519: true,
  noPrefixNewlineHashCanonicalJsonOrWhitespace: true,
  signatureEncoding: "canonical padded base64url",
  suitePrefixUsed: false,
} as const;

/** Construction/verification prohibitions (protocol rule 3). */
export const SPLITCHAIN_INNER_PROHIBITIONS = {
  objectSpreadOnSigningPath: false,
  alphabeticalSorting: false,
  schemaSerializersThatReorderKeys: false,
  parseRebuildCycles: false,
  unknownTopLevelFields: "fail-closed until a future protocol version supports them",
  foreignMetadataPreservedAsOpaqueSignedData: true,
  foreignMetadataAsApplicationChannel: false,
  jsonbReconstruction: false,
} as const;

export const SOURCE = "SplitChain inner field rules; A.1.2; artifacts-freeze" as const;

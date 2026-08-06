/**
 * The gateway response-evidence rules (gateway
 * response evidence), the transport boundary and submit outcomes, and envelope
 * mutation vs preimage verification; the frozen form-transport + response-shape rule.
 *
 * the fixture-provenance purposes census — the gateway-envelope manifest category. The form-transport and response-envelope
 * literals stay OWNED by the transfer-code concern (`candidate-intake.contract.ts`) and
 * are restated here with their owner named, with the census test asserting both freezes agree;
 * this module's own freeze is the response-evidence rules EVIDENCE contract — raw bytes before decode,
 * digest-retained, never a signed blob. DATA ONLY so `gen/gateway-envelopes.json` stays a
 * clean review-diff snapshot. (Emitted contract modules are import-free leaves: the emitter
 * runs plain Node type-stripping.)
 */

/** Manifest version (v1 `*_CONTRACT_VERSION` discipline): bump on any reviewed change. */
export const GATEWAY_ENVELOPES_CONTRACT_VERSION = 1 as const;

/** Official gateway form transport (protocol rule 8; the frozen transport rule). OWNED by
 *  `src/transfer-code/candidate-intake.contract.ts`; restated for category completeness. */
export const GATEWAY_FORM_BODY_PARAM = "v" as const;
export const GATEWAY_ACTION_FIELD_SEQUENCE = ["action_name", "action_data"] as const;
export const GATEWAY_FORM_BODY_TEMPLATE =
  "v=<encodeURIComponent(JSON.stringify({action_name,action_data}))>" as const;

/** Gateway response envelope field sequence `{status, code, message, data}` (the frozen response shape). OWNED by
 *  `src/transfer-code/candidate-intake.contract.ts`; restated for category completeness. */
export const GATEWAY_RESPONSE_FIELD_SEQUENCE = ["status", "code", "message", "data"] as const;

/**
 * Gateway response evidence (protocol rule 4.3): the complete HTTP response body is captured as bytes
 * BEFORE decoding or JSON parsing, retained with its SHA-256 digest and transport metadata. It
 * is NOT a signed blob — the fixture-provenance surface `unsigned-evidence` byte class. SplitChain signatures
 * authenticate the transaction fields/preimages INSIDE an accepted response; they never
 * authenticate the transport facts around it.
 */
export const GATEWAY_EVIDENCE_CONTRACT = {
  captureRawBytesBeforeDecode: true,
  retainedWith: ["raw_body_bytes", "sha256_digest", "transport_metadata"],
  signedBlob: false,
  byteClass: "unsigned-evidence",
  signatureNeverAuthenticates: [
    "HTTP status",
    "gateway envelope fields",
    "whitespace",
    "field formatting outside the signed transaction",
    "transport metadata",
  ],
} as const;

/**
 * Envelope-mutation rule (protocol rule 10 vector 11): mutating the raw gateway envelope does NOT change
 * signed-preimage verification, but the changed response bytes are retained as distinct raw
 * evidence and classified `EQUIVALENT_STATE_DIFFERENT_ENVELOPE` when the verified semantic head
 * is unchanged. The relationship literal itself is OWNED by
 * `src/observation/enums.contract.ts`.
 */
export const GATEWAY_ENVELOPE_MUTATION_RULE = {
  preimageVerificationAffected: false,
  changedBytesRetainedAsDistinctEvidence: true,
  unchangedSemanticHeadClassification: "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
} as const;

/** The closed set of submit outcome categories (protocol rule 8). OWNED by
 *  `src/transfer-code/candidate-intake.contract.ts` (`SUBMIT_OUTCOME_CATEGORIES`); restated for
 *  category completeness. Only the two verified-landing categories mark a transaction landed;
 *  there is no generic `PROVEN_NOT_LANDED` outcome (protocol rule 8). */
export const GATEWAY_SUBMIT_OUTCOME_CATEGORIES = [
  "deterministic_rejection",
  "receipt_acknowledgement",
  "indeterminate_transport",
  "verified_exact_landing",
  "verified_complete_path_landing",
  "incomplete_or_conflicting_or_resource_exhausted",
  "regression_or_gap_or_unrelated_or_unverifiable",
] as const;

export const GATEWAY_NO_PROVEN_NOT_LANDED = true as const;

export const SOURCE = "gateway response evidence and transport boundary; frozen form-transport rule" as const;

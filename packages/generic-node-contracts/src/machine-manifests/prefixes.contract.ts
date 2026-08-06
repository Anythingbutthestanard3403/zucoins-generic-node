/**
 * Covers A.1.1 (suite domain separation) and A.2 (receive message, transfer-code digest);
 * Protocol rule 4.2 (suite tuples never alter a SplitChain inner).
 *
 * the fixture-provenance purposes census — the frozen prefix vocabulary: the suite domain-separation prefix rule, the `zp1:`
 * receive-message prefix and format, and the transfer-code digest input rule. DATA ONLY so
 * `gen/prefixes.json` stays a clean review-diff snapshot.
 *
 * The `zp`/`zupay` compatibility literals themselves are OWNED by
 * `src/compat-literals/` (compatibility-literal preservation) and are deliberately not duplicated here — this module freezes
 * only the prefix RULES (domain separator, message prefix, digest input).
 */

/** Manifest version (v1 `*_CONTRACT_VERSION` discipline): bump on any reviewed change. */
export const PREFIXES_CONTRACT_VERSION = 1 as const;

/**
 * Suite domain separation (A.1.1): `preimage_text = purpose + "\n" + payload_json`. The
 * displayed `\n` is one LF byte (0x0a), never the two characters backslash+n, and there is no
 * trailing LF. `purpose` appears twice by design — once as the prefix, once as payload field 1 —
 * and a verifier requires BOTH copies to equal the expected literal before signature
 * verification.
 */
export const SUITE_DOMAIN_SEPARATOR = {
  preimageTextConstruction: 'purpose + "\\n" + payload_json',
  separatorByte: "0x0a",
  separatorCharCount: 1,
  trailingNewline: false,
  purposeAppearsAsPrefixAndField1: true,
  noBom: true,
  noInsignificantWhitespace: true,
  noKeySorting: true,
  noUnicodeNormalization: true,
} as const;

/**
 * The receive-message prefix (A.2): the exact signed SplitChain `message` is
 * `"zp1:" + discriminator + ":" + anchor`. The fixed-width UUID discriminator and the anchor
 * alphabet make the split unambiguous; the result stays below the 256-scalar protocol limit
 * (protocol rule 3 field 14). No whitespace or normalization is added.
 */
export const RECEIVE_MESSAGE_PREFIX = "zp1:" as const;
export const RECEIVE_MESSAGE_FORMAT = '"zp1:" + discriminator + ":" + anchor' as const;
export const RECEIVE_MESSAGE_DISCRIMINATOR = "operation UUID (lowercase canonical, fixed-width)" as const;
export const RECEIVE_ANCHOR_PATTERN = "^[A-Za-z0-9_-]{1,96}$" as const;
export const RECEIVE_MESSAGE_MAX_SCALARS = 256 as const;

/**
 * Transfer-code digest input rule (A.2):
 * `transfer_code_sha256 = lowercase_hex(SHA256(UTF8(exact_transfer_code_string)))` — the exact
 * stored string bytes are hashed as-is. No newline, URL decode, base64 decode, padding repair,
 * or JSON parse occurs before hashing (A.9 negative vector 11).
 */
export const TRANSFER_CODE_DIGEST_RULE =
  "lowercase_hex(SHA256(UTF8(exact_transfer_code_string)))" as const;
export const TRANSFER_CODE_DIGEST_FORBIDDEN_PREPROCESSING = [
  "newline insertion",
  "URL decode",
  "base64 decode",
  "padding repair",
  "JSON parse",
] as const;

/** The `zp`/`zupay` compatibility literals are owned by the compat-literals concern (compatibility-literal preservation);
 *  they are referenced, never re-frozen, here. */
export const COMPATIBILITY_LITERALS_OWNER = "src/compat-literals" as const;

export const SOURCE = "suite prefixes A.1.1, A.2, A.9; compatibility-literals" as const;

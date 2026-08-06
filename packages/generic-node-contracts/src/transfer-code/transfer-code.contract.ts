/**
 * The transfer-code byte contract (A.2, A.8). Frozen: the encode pipeline, the
 * code-matching rule (receive/send-code v1 template + expiry bound), the wire version and
 * inner retention
 * (single wire version "1"), the expired-code rule (expired-code gateway disposition).
 *
 * Wallet-parity provenance (the reference SplitChain wallet implementation,
 * site/js/splitchain.js): top-level and incoming_data field sequences are the
 * exact sequences the wallet's `filter_transfer_code_structure__v1` builds (splitchain.js:1647-1789);
 * the encode pipeline is `encode_transfer_code` (splitchain.js:1791-1868); decode is
 * `decode_transfer_code` (splitchain.js:1872+). The send code's `partial_transaction` shape is the
 * wallet's `filter_transaction_structure__v2` (splitchain.js:4067-4200), step_2_signature omitted
 * while the transaction is a partial.
 *
 * This concern freezes the two transfer-code envelopes the generic node must emit/accept. It carries
 * no gateway client, submit path, network, DB, or key material (CONTRACT_FREEZE).
 */

/**
 * The one on-wire transfer-code version literal. The receiving wallet hard-maps the code version to
 * the transaction-inner version it builds and signs: a v1 code -> a v2 `unique_combinable` inner the
 * live gateway accepts (the code-matching rule). The single node-side constant that keeps the receive-code
 * version, the send-code envelope version, and the push label suffix from silently desyncing is
 * `TRANSFER_CODE_WIRE_VERSION`'s frozen value.
 */
export const TRANSFER_CODE_WIRE_VERSION = "1";

/**
 * Frozen top-level insertion sequence for every transfer-code envelope (splitchain.js:1651-1655).
 * `JSON.stringify` emits keys in insertion sequence, so this sequence is a byte contract.
 */
export const TRANSFER_CODE_TOP_LEVEL_FIELDS = ["version", "type", "incoming_data"] as const;

/**
 * Envelope `type` discriminators. RECEIVE codes make the external party's wallet the step-1 sender
 * (the node is receiver); SEND codes carry the node's step-1 partial for an external recipient to
 * co-sign as step 2. The explicit sender variant exists in the wallet but the code-matching rule uses the
 * non-explicit RECEIVE variant (no sender pinning).
 */
export const RECEIVE_CODE_TYPE = "sender_create_transaction";
export const RECEIVE_CODE_TYPE_EXPLICIT = "sender_create_transaction_explicit";
export const SEND_CODE_TYPE = "receiver_confirm_partial_transaction";

export const TRANSFER_CODE_TYPES = [
  RECEIVE_CODE_TYPE,
  RECEIVE_CODE_TYPE_EXPLICIT,
  SEND_CODE_TYPE,
] as const;

export type TransferCodeType = (typeof TRANSFER_CODE_TYPES)[number];

/**
 * `sender_create_transaction` `incoming_data` — required fields first, then optional fields in this
 * exact sequence (splitchain.js:1666-1723). The explicit variant additionally inserts
 * `SENDER_CREATE_EXPLICIT_PREFIX_FIELD` before the required fields.
 */
export const SENDER_CREATE_REQUIRED_FIELDS = [
  "receiver_key_public__base64urlsafe",
  "inner_state_amount",
] as const;

export const SENDER_CREATE_OPTIONAL_FIELDS = [
  "expiry__unix_time_secs",
  "message",
  "inner_state_metadata",
  "user_share_message",
] as const;

export const SENDER_CREATE_EXPLICIT_PREFIX_FIELD = "sender_key_public__base64urlsafe";

/**
 * `receiver_confirm_partial_transaction` `incoming_data` carries exactly one field: the node's
 * step-1 `partial_transaction` (splitchain.js:1725-1731). The partial's inner bytes are kept
 * exactly and never reserialized on the emit path (see SEND_CODE_INNER_KEPT_VERBATIM below).
 */
export const RECEIVER_CONFIRM_INCOMING_DATA_FIELDS = ["partial_transaction"] as const;

/**
 * Encode pipeline (matches the wallet's splitchain.js byte-for-byte). Applied in this exact sequence. The final step
 * strips every `=` padding character.
 */
export const TRANSFER_CODE_ENCODE_PIPELINE = [
  "JSON.stringify",
  "encodeURIComponent",
  "base64url",
  "strip-padding",
] as const;

/**
 * Decode pipeline (splitchain.js:1872+). base64url decode tolerates missing padding, reversing the
 * encode pipeline's padding strip.
 */
export const TRANSFER_CODE_DECODE_PIPELINE = [
  "base64url-decode-tolerant-padding",
  "decodeURIComponent",
  "JSON.parse",
] as const;

/**
 * Expiry byte contract. The transfer-code expiry field is `expiry__unix_time_secs`, an integer
 * string of SECONDS — never milliseconds (a ms value is a distinct, wrong byte string).
 * the code-matching rule bounds it to at most 59,999,880 seconds ahead of gateway block time. the expired-code rule: an expired code
 * is hard-rejected by the gateway with no grace, so expiry is validated before co-sign/submit.
 */
export const EXPIRY_FIELD = "expiry__unix_time_secs";
export const EXPIRY_UNIT = "seconds";
export const EXPIRY_MAX_SECONDS_AHEAD_OF_BLOCK = 59999880;
export const EXPIRED_CODE_GATEWAY_DISPOSITION = "hard_reject";

/**
 * Receive-message byte contract (A.2). The signed SplitChain `inner.message` is exactly
 * `"zp1:" + discriminator + ":" + anchor`; the fixed-width UUID discriminator and the anchor alphabet
 * make the split unambiguous. No whitespace or normalization is added. The `zp1:` prefix is a frozen
 * a preserved compatibility literal. `message` is at most 256 Unicode scalar values and is copied verbatim
 * into the signed inner (the code-matching rule). `user_share_message` is trimmed, at most 300 chars, NOT signed, and
 * never used for matching (the code-matching rule; splitchain.js:1719).
 */
export const RECEIVE_MESSAGE_PREFIX = "zp1:";
export const RECEIVE_MESSAGE_ANCHOR_PATTERN = "^[A-Za-z0-9_-]{1,96}$";
export const RECEIVE_MESSAGE_MAX_LENGTH = 256;
export const USER_SHARE_MESSAGE_MAX_LENGTH = 300;
export const USER_SHARE_MESSAGE_IS_SIGNED = false;

/**
 * Transfer-code digest rule (A.2): the hash is SHA-256 over the exact UTF-8 bytes of the encoded
 * transfer-code string. No newline, URL-decode, base64-decode, padding repair, or JSON parse occurs
 * before hashing.
 */
export const TRANSFER_CODE_SHA256_RULE = "sha256(utf8(exact_encoded_string))" as const;

/**
 * Inner-retention rule. The send code is constructed from the persisted exact
 * inner text and persisted step-1 signature without parsing or reserializing either. A re-delivered
 * send code returns the identical persisted bytes; it never rebuilds. The frozen SEND golden's decoded
 * `partial_transaction.inner` therefore byte-equals the exact signed step-1 preimage.
 */
export const SEND_CODE_INNER_KEPT_VERBATIM = true;

export const SOURCE =
  "transfer-code bytes A.2, A.8; transfer-code-encoding; code-matching-window; wire-version-freeze; inner-retention; expiry-seconds-encoding; wallet splitchain.js parity" as const;

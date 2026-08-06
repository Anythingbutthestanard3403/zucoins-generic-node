/**
 * Immutable, offline byte evidence. No fixture contains a private key and no test signs.
 *
 * Wallet evidence provenance:
 * - wallet PWA 199.11, captured 2026-07-14 by the pre-existing offline capture script;
 * - splitchain.js SHA-256 e5ee76d2c7324151555c48df8c90c95f0d8abf33f8824b92fb075e39296a26dc;
 * - main.js SHA-256 8ce1d88bfb814153cc33b6ac5025dbf460c1eb8f125d6f5ac9d2e41e67d09624;
 * - source: get_default_transaction__v2 at splitchain.js:1972, fractional clock at :5467,
 *   sender build/sign bytes at main.js:7725-7921, receiver step-2 bytes at :10063-10073;
 * - original committed sidecars: packages/splitchain/test/fixtures/signing/genesis-receiver.*.
 *
 * Appendix evidence provenance:
 */

export const CANONICAL_INNER_FIELD_ORDER = Object.freeze([
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
] as const);

export const A8_INNER_PREIMAGE_TEXT =
  '{"type":"unique_combinable","version":"2","unix_time_secs":"1784332800.125","signer_steps":2,"step_1_signer":"sender","step_2_signer":"receiver","step_1_key_public__base64urlsafe":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=","step_2_key_public__base64urlsafe":"7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=","step_1_state":{"amount":"7.75"},"step_2_state":{"amount":"2.25"},"previous_step_1_state_signature":"","previous_step_2_state_signature":"","expiry__unix_time_secs":"1784336400","message":"zp1:33333333-3333-4333-8333-333333333333:ord_7YQ3"}';
export const A8_INNER_PREIMAGE_LENGTH = 549;
export const A8_INNER_PREIMAGE_SHA256 =
  "f0e12e993cc4d6b452162cd49b2699b9f912d7a2bf3d8ddd418e3a29c6bbf0b7";

export const WALLET_SENDER_PUBLIC_KEY = "0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc=";
export const WALLET_RECEIVER_PUBLIC_KEY = "oJql9HpnWYAv-VX43C0qFKXJnSO-l_hkEn_5ODRVpPA=";
export const WALLET_SENDER_PREVIOUS_SETTLED_SIGNATURE =
  "CRU32GIIF6E1VIv4H7vcL3iIhgFIrVt7U2AaM7886-kUpKdgA9ZG245jPYH9FsbCUEEXjjxqpygg0TJu3wRWCg==";
export const WALLET_STEP_1_SIGNATURE =
  "HKnR0ZDj7W2CBU_JjViC8T-N9_NERsegxf8J6iS1PoJmoHWgwAGJREoNOxE3eIP_525WMYNi0kXUQdqjcZx_CA==";
export const WALLET_STEP_2_SIGNATURE =
  "ioIjKt3HSXFgwMve1dyp7Fgzcnf0FUReShA5rtq2FXwUc6X9iso_u5vmxGUkWjpSjpfbqTrvyqAafKVNHkYpCA==";

export const WALLET_INNER_PREIMAGE_TEXT =
  '{"type":"unique_combinable","version":"2","unix_time_secs":"1718000000.123","signer_steps":2,"step_1_signer":"sender","step_2_signer":"receiver","step_1_key_public__base64urlsafe":"0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc=","step_2_key_public__base64urlsafe":"oJql9HpnWYAv-VX43C0qFKXJnSO-l_hkEn_5ODRVpPA=","step_1_state":{"amount":"7.5"},"step_2_state":{"amount":"2.5"},"previous_step_1_state_signature":"CRU32GIIF6E1VIv4H7vcL3iIhgFIrVt7U2AaM7886-kUpKdgA9ZG245jPYH9FsbCUEEXjjxqpygg0TJu3wRWCg==","previous_step_2_state_signature":"","expiry__unix_time_secs":"1718000300","message":"zup_sess_3f9a1c00d24b48e7"}';
export const WALLET_STEP_2_PREIMAGE_TEXT =
  '{"inner":{"type":"unique_combinable","version":"2","unix_time_secs":"1718000000.123","signer_steps":2,"step_1_signer":"sender","step_2_signer":"receiver","step_1_key_public__base64urlsafe":"0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc=","step_2_key_public__base64urlsafe":"oJql9HpnWYAv-VX43C0qFKXJnSO-l_hkEn_5ODRVpPA=","step_1_state":{"amount":"7.5"},"step_2_state":{"amount":"2.5"},"previous_step_1_state_signature":"CRU32GIIF6E1VIv4H7vcL3iIhgFIrVt7U2AaM7886-kUpKdgA9ZG245jPYH9FsbCUEEXjjxqpygg0TJu3wRWCg==","previous_step_2_state_signature":"","expiry__unix_time_secs":"1718000300","message":"zup_sess_3f9a1c00d24b48e7"},"step_1_signature":"HKnR0ZDj7W2CBU_JjViC8T-N9_NERsegxf8J6iS1PoJmoHWgwAGJREoNOxE3eIP_525WMYNi0kXUQdqjcZx_CA=="}';
export const WALLET_SETTLED_TRANSACTION_TEXT =
  '{"inner":{"type":"unique_combinable","version":"2","unix_time_secs":"1718000000.123","signer_steps":2,"step_1_signer":"sender","step_2_signer":"receiver","step_1_key_public__base64urlsafe":"0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc=","step_2_key_public__base64urlsafe":"oJql9HpnWYAv-VX43C0qFKXJnSO-l_hkEn_5ODRVpPA=","step_1_state":{"amount":"7.5"},"step_2_state":{"amount":"2.5"},"previous_step_1_state_signature":"CRU32GIIF6E1VIv4H7vcL3iIhgFIrVt7U2AaM7886-kUpKdgA9ZG245jPYH9FsbCUEEXjjxqpygg0TJu3wRWCg==","previous_step_2_state_signature":"","expiry__unix_time_secs":"1718000300","message":"zup_sess_3f9a1c00d24b48e7"},"step_1_signature":"HKnR0ZDj7W2CBU_JjViC8T-N9_NERsegxf8J6iS1PoJmoHWgwAGJREoNOxE3eIP_525WMYNi0kXUQdqjcZx_CA==","step_2_signature":"ioIjKt3HSXFgwMve1dyp7Fgzcnf0FUReShA5rtq2FXwUc6X9iso_u5vmxGUkWjpSjpfbqTrvyqAafKVNHkYpCA=="}';

export const WALLET_INNER_PREIMAGE_LENGTH = 611;
export const WALLET_STEP_2_PREIMAGE_LENGTH = 731;
export const WALLET_SETTLED_TRANSACTION_LENGTH = 841;
export const WALLET_INNER_PREIMAGE_SHA256 =
  "3a9d63289fbacd281f21a935b8293582c28b93730f7bd7e19c031dcf71c7c93c";
export const WALLET_STEP_2_PREIMAGE_SHA256 =
  "aafbedf7824dd3ada37ce203700e5c25d1582d8e45c1ee7da1b07204c04b9085";
export const WALLET_SETTLED_TRANSACTION_SHA256 =
  "f6b47c079171e4dc74d27755091d2a82d6c16387d13e56333dd61eb00756d185";

// Non-ASCII message golden. Proves JSON.stringify emits BMP/emoji chars raw (no
// \uXXXX escaping beyond JSON-required control chars) and computeInnerDigest is deterministic
// over multi-byte UTF-8. Same canonical field order as buildSplitChainInnerV2; same key/state
// values as the A.8.1 appendix vector, differing only in the message field.
export const NON_ASCII_MESSAGE = "Payment for services \u2014 \u00a55000 \ud83d\udcb0";
export const NON_ASCII_INNER_PREIMAGE_TEXT =
  '{"type":"unique_combinable","version":"2","unix_time_secs":"1784332800.125","signer_steps":2,"step_1_signer":"sender","step_2_signer":"receiver","step_1_key_public__base64urlsafe":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=","step_2_key_public__base64urlsafe":"7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=","step_1_state":{"amount":"7.75"},"step_2_state":{"amount":"2.25"},"previous_step_1_state_signature":"","previous_step_2_state_signature":"","expiry__unix_time_secs":"1784336400","message":"Payment for services \u2014 \u00a55000 \ud83d\udcb0"}';
export const NON_ASCII_INNER_PREIMAGE_LENGTH = 531;
export const NON_ASCII_INNER_PREIMAGE_BYTE_LENGTH = 536;
export const NON_ASCII_INNER_PREIMAGE_SHA256 =
  "38e82d51e251ae2755fc933a9033fe794c5dc97d0cb33f77cde87dcb0f787dc5";

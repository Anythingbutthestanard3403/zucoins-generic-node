// RECEIVE_EXTERNAL unsigned transfer-code assembly (step 5).
// packages/generic-node-contracts transfer-code.contract (RECEIVE_CODE_TYPE, encode pipeline);
// transfer-code encode/decode / pre-formed sender transfer code / transfer-code wire version / fractional unix_time_secs string; the byte-exact signing rule.
//
// Built from the observed T0 balance (B0), the reserved receiver pubkey, the operation UUID
// discriminator, the request anchor, and the byte-frozen expiry string. The encoded string is
// hashed with zero preprocessing (A.2: no newline / URL-decode / base64-decode / padding repair /
// JSON parse before SHA-256).

import { createHash } from "node:crypto";

import { addZkz, parsePositiveZkzAmount, parseZkzBalance, type PositiveZkzAmount } from "./amounts.js";
import {
  parseExpiryUnixTimeSecs,
  parseUuid,
  parseWalletPublicKey,
  type ExpiryUnixTimeSecs,
  type Uuid,
  type WalletPublicKey,
} from "./scalars.js";

/** Wire version for every transfer-code envelope (TRANSFER_CODE_WIRE_VERSION). */
export const RECEIVE_TRANSFER_CODE_WIRE_VERSION = "1" as const;

/** Envelope type for a node-formed RECEIVE_EXTERNAL code (external party is step-1 sender). */
export const RECEIVE_TRANSFER_CODE_TYPE = "sender_create_transaction" as const;

/** A.2 receive-message prefix — frozen compatibility-literal allowlist compatibility literal. */
export const RECEIVE_MESSAGE_PREFIX = "zp1:" as const;

/** Anchor alphabet bound by the expected artifact. */
const ANCHOR_PATTERN = /^[A-Za-z0-9_-]{1,96}$/;

export class ReceiveTransferCodeError extends Error {
  readonly code = "RECEIVE_TRANSFER_CODE_REJECTED";

  constructor(readonly reason: string) {
    super(`receive transfer code rejected (${reason})`);
    this.name = "ReceiveTransferCodeError";
  }
}

export interface BuildReceiveTransferCodeInput {
  /** Reserved receiver wallet public key (padded base64url). */
  readonly receiverPubkey: string;
  /** Request amount_zkz (positive canonical). */
  readonly amountZkz: string;
  /** Observed T0 balance B0 (canonical balance text; genesis is "0"). */
  readonly b0: string;
  /** Operation UUID — the discriminator. */
  readonly discriminator: string;
  /** Request anchor (opaque, A.2 alphabet). */
  readonly anchor: string;
  /** integer-SECONDS decimal string, frozen at formation (receive TTL policy; destination binding). */
  readonly expiryUnixTimeSecs: string;
}

export interface ReceiveTransferCode {
  /** Exact encoded transfer-code string (pipeline). */
  readonly transferCodeText: string;
  /** A.2 digest: lowercase hex SHA-256 of UTF-8(transferCodeText). */
  readonly transferCodeSha256: string;
  /** Exact SplitChain message embedded in the code: "zp1:" + discriminator + ":" + anchor. */
  readonly receiveMessage: string;
  /** inner_state_amount = B0 + amount (canonical). */
  readonly innerStateAmount: string;
  readonly expiryUnixTimeSecs: ExpiryUnixTimeSecs;
  readonly discriminator: Uuid;
  readonly receiverPubkey: WalletPublicKey;
  readonly amountZkz: PositiveZkzAmount;
}

/**
 * A.2 receive message: `"zp1:" + discriminator + ":" + anchor`.
 * No whitespace or normalization. Fixed-width UUID + anchor alphabet make the split unambiguous.
 */
export function buildReceiveMessage(discriminator: string, anchor: string): string {
  const disc = parseUuid(discriminator);
  if (!ANCHOR_PATTERN.test(anchor)) {
    throw new ReceiveTransferCodeError("invalid_anchor");
  }
  return `${RECEIVE_MESSAGE_PREFIX}${disc}:${anchor}`;
}

/**
 * A.2 digest: SHA-256 over the exact UTF-8 bytes of the encoded transfer-code string.
 * No newline, URL-decode, base64-decode, padding repair, or JSON parse before hashing.
 */
export function hashTransferCodeText(transferCodeText: string): string {
  return createHash("sha256").update(Buffer.from(transferCodeText, "utf8")).digest("hex");
}

/**
 * RFC 8259 JSON string literal for a protocol-validated scalar.
 * Hand-built so the money-path never calls `JSON.stringify` on an object graph
 * (the byte-exact signing rule) — same assembly style as send-transfer-code.ts.
 */
function jsonStringLiteral(value: string): string {
  let out = '"';
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code === 0x22) out += '\\"';
    else if (code === 0x5c) out += "\\\\";
    else if (code === 0x08) out += "\\b";
    else if (code === 0x0c) out += "\\f";
    else if (code === 0x0a) out += "\\n";
    else if (code === 0x0d) out += "\\r";
    else if (code === 0x09) out += "\\t";
    else if (code < 0x20) out += `\\u${code.toString(16).padStart(4, "0")}`;
    else out += value[i]!;
  }
  return `${out}"`;
}

/**
 * Construct the unsigned receiver transfer code and its A.2 digest.
 *
 * Envelope field insertion sequence is the wallet's filter_transfer_code_structure__v1
 * sequence (version, type, incoming_data) with incoming_data keys
 * receiver → amount → expiry → message (SENDER_CREATE_REQUIRED then OPTIONAL present fields).
 * Encoding: hand-built JSON → encodeURIComponent → base64url (transfer-code encode/decode). Node's `"base64url"`
 * codec already emits the unpadded alphabet, so the wallet-side trailing pad strip is a no-op
 * here (contracts `transfer-code-codec.ts` documents the equivalence).
 *
 * `inner_state_amount` is B0 + amount_zkz via the protocol amount adder (never raw arithmetic).
 * For a genesis pool wallet (B0="0") this equals amount_zkz.
 */
export function buildReceiveTransferCode(input: BuildReceiveTransferCodeInput): ReceiveTransferCode {
  const receiverPubkey = parseWalletPublicKey(input.receiverPubkey);
  const amountZkz = parsePositiveZkzAmount(input.amountZkz);
  const b0 = parseZkzBalance(input.b0);
  const discriminator = parseUuid(input.discriminator);
  const expiryUnixTimeSecs = parseExpiryUnixTimeSecs(input.expiryUnixTimeSecs);
  if (!ANCHOR_PATTERN.test(input.anchor)) {
    throw new ReceiveTransferCodeError("invalid_anchor");
  }

  const innerStateAmount = addZkz(b0, amountZkz);
  const receiveMessage = buildReceiveMessage(discriminator, input.anchor);
  if (receiveMessage.length > 256) {
    throw new ReceiveTransferCodeError("message_too_long");
  }

  // Explicit key insertion sequence IS the byte contract (the byte-exact signing rule).
  // Template-splice validated scalars — never JSON.stringify of an object graph.
  const envelopeJson =
    '{"version":' +
    jsonStringLiteral(RECEIVE_TRANSFER_CODE_WIRE_VERSION) +
    ',"type":' +
    jsonStringLiteral(RECEIVE_TRANSFER_CODE_TYPE) +
    ',"incoming_data":{"receiver_key_public__base64urlsafe":' +
    jsonStringLiteral(receiverPubkey) +
    ',"inner_state_amount":' +
    jsonStringLiteral(innerStateAmount) +
    ',"expiry__unix_time_secs":' +
    jsonStringLiteral(expiryUnixTimeSecs) +
    ',"message":' +
    jsonStringLiteral(receiveMessage) +
    "}}";
  const uriEncoded = encodeURIComponent(envelopeJson);
  const transferCodeText = Buffer.from(uriEncoded, "utf8").toString("base64url");
  const transferCodeSha256 = hashTransferCodeText(transferCodeText);

  return Object.freeze({
    transferCodeText,
    transferCodeSha256,
    receiveMessage,
    innerStateAmount,
    expiryUnixTimeSecs,
    discriminator,
    receiverPubkey,
    amountZkz,
  });
}

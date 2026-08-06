// SEND_EXTERNAL transfer-code assembly from persisted material.
// packages/generic-node-contracts transfer-code.contract (SEND_CODE_INNER_KEPT_VERBATIM);
// exact partial only the byte-exact signing rule.
//
// Built from the *persisted* inner preimage text and *persisted* step-1 signature without
// parsing/reserializing either. The digest is SHA-256 over the exact UTF-8 bytes of the
// encoded string — zero preprocessing (decode/pad/repair).

import { createHash } from "node:crypto";

/** Wire version for every transfer-code envelope (TRANSFER_CODE_WIRE_VERSION). */
export const SEND_TRANSFER_CODE_WIRE_VERSION = "1" as const;

/** Envelope type for a node-formed SEND_EXTERNAL partial (wallet filter). */
export const SEND_TRANSFER_CODE_TYPE = "receiver_confirm_partial_transaction" as const;

/**
 * RFC 8259 escaping of one string scalar for splicing into the hand-assembled envelope JSON.
 *
 * The `typeof` guard is the enforcement, not a formality. `JSON.stringify` is dangerous in this
 * file because of object-key sequence: handed an object it commits the emitted field sequence to
 * V8's property sequence, and those bytes are what `hashTransferCodeText` hashes. The guard makes
 * that unreachable at runtime for every binding form there is — a shadowed const, a destructuring
 * pattern, an enum, an import, or a syntax TypeScript has not shipped yet: anything that
 * substitutes a non-string throws here instead of reaching `JSON.stringify`. The byte-exact signing rule / exact partial only.
 */
function jsonEscapeString(value: string): string {
  if (typeof value !== "string") {
    throw new TypeError("jsonEscapeString requires a string");
  }
  return JSON.stringify(value);
}

/**
 * Assemble the encoded transfer-code string by template-splicing the exact persisted
 * inner preimage and step-1 signature into the frozen envelope shape, then applying the
 * encode pipeline (JSON → encodeURIComponent → base64url). Node's `"base64url"`
 * codec already emits the unpadded alphabet, so the wallet-side trailing pad strip is a no-op
 * here and is not called (contracts `transfer-code-codec.ts` documents the equivalence).
 *
 * The intermediate JSON embeds `innerPreimageText` verbatim — never `JSON.parse` then
 * `JSON.stringify` of the inner. The byte-exact signing rule.
 */
export function buildSendTransferCodeText(
  innerPreimageText: string,
  step1Signature: string,
): string {
  const partialJson =
    '{"inner":' +
    innerPreimageText +
    ',"step_1_signature":' +
    jsonEscapeString(step1Signature) +
    "}";
  const envelopeJson =
    '{"version":' +
    jsonEscapeString(SEND_TRANSFER_CODE_WIRE_VERSION) +
    ',"type":' +
    jsonEscapeString(SEND_TRANSFER_CODE_TYPE) +
    ',"incoming_data":{"partial_transaction":' +
    partialJson +
    "}}";
  const uriEncoded = encodeURIComponent(envelopeJson);
  return Buffer.from(uriEncoded, "utf8").toString("base64url");
}

/**
 * Digest: SHA-256 over the exact UTF-8 bytes of the encoded transfer-code string.
 * No newline, URL-decode, base64-decode, padding repair, or JSON parse before hashing.
 */
export function hashTransferCodeText(transferCodeText: string): string {
  return createHash("sha256").update(Buffer.from(transferCodeText, "utf8")).digest("hex");
}

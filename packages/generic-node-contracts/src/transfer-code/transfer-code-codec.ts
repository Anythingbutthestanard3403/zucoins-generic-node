import { createHash } from "node:crypto";

import { TRANSFER_CODE_WIRE_VERSION } from "./transfer-code.contract.ts";

/**
 * Pure, stateless transfer-code codec (CONTRACT_FREEZE: no network/DB/keys). These mirror the
 * wallet's `encode_transfer_code`/`decode_transfer_code` (splitchain.js:1791-1868, 1872+) and the
 * the frozen encode pipeline byte-for-byte. `Buffer.toString("base64url")` emits the same URL-safe alphabet
 * (`-`/`_`) as libsodium's `to_base64(..., URLSAFE)` and omits padding, matching the wallet's
 * trailing `.replace(/=/g, "")`; `Buffer.from(code, "base64url")` decodes tolerantly of missing
 * padding, matching the wallet's `decode_base64urlsafe_w_variants`. Byte parity with libsodium was
 * verified against both frozen goldens (see goldens/transfer-code/*.meta.json).
 */
export const encodeTransferCode = (transferCode: unknown): string => {
  const json = JSON.stringify(transferCode);
  const uriEncoded = encodeURIComponent(json);
  return Buffer.from(uriEncoded, "utf8").toString("base64url").replace(/=/g, "");
};

export const decodeTransferCode = (encodedTransferCode: string): unknown => {
  const uriEncoded = Buffer.from(encodedTransferCode, "base64url").toString("utf8");
  return JSON.parse(decodeURIComponent(uriEncoded));
};

/**
 * A.2 transfer-code digest: SHA-256 over the exact UTF-8 bytes of the encoded string. No newline,
 * URL-decode, base64-decode, padding repair, or JSON parse occurs before hashing.
 */
export const transferCodeSha256 = (encodedTransferCode: string): string =>
  createHash("sha256").update(Buffer.from(encodedTransferCode, "utf8")).digest("hex");

/** SHA-256 hex over the exact UTF-8 bytes of any preimage string (used for the JSON preimage golden). */
export const sha256Utf8 = (preimage: string): string =>
  createHash("sha256").update(Buffer.from(preimage, "utf8")).digest("hex");

/** Own-key insertion sequence of an object — the sequence that `JSON.stringify` will emit. */
export const objectKeySequence = (value: Record<string, unknown>): string[] => Object.keys(value);

/**
 * Pure version verifier: rejects any envelope whose `version` is not the one frozen wire version.
 * A v2 or v3 code literal is a hard reject — the receiving wallet would build the wrong inner
 * version (the code-matching rule) or drop the notification entirely (the frozen intake rule).
 */
export const assertWireVersion = (envelope: { readonly version?: unknown }): void => {
  if (envelope.version !== TRANSFER_CODE_WIRE_VERSION) {
    throw new Error(
      `transfer-code version must be "${TRANSFER_CODE_WIRE_VERSION}", got ${JSON.stringify(envelope.version)}`,
    );
  }
};

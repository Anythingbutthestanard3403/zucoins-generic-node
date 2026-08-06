import ece from "http_ece";

import { ecdhFromPrivateKeyBytes } from "./crypto.js";
import { assertHttpEceKeyLoggingDisabled } from "./http-ece-keylog.js";

export interface DecryptWebPushPayloadParams {
  readonly body: Buffer;
  readonly ecdhPrivateKeyBytes: Uint8Array;
  readonly authSecret: Uint8Array;
}

export class WebPushDecryptError extends Error {
  /** Discriminator retained from the pre-dedupe app-side error. */
  readonly code = "PUSH_DECRYPT_FAILED" as const;
  constructor(message: string, readonly cause?: unknown) {
    super(message);
    this.name = "WebPushDecryptError";
  }
}

/** Decrypt and authenticate one RFC 8291 aes128gcm delivery. */
export function decryptWebPushPayload(params: DecryptWebPushPayloadParams): Buffer {
  assertHttpEceKeyLoggingDisabled(ece);
  const privateKey = ecdhFromPrivateKeyBytes(Buffer.from(params.ecdhPrivateKeyBytes));
  try {
    return ece.decrypt(params.body, {
      version: "aes128gcm",
      privateKey,
      authSecret: Buffer.from(params.authSecret),
    });
  } catch (cause) {
    // Deliberately omit key/auth/body material from the failure surface.
    throw new WebPushDecryptError("aes128gcm decrypt failed", cause);
  }
}

// Thin WebPushPayloadDecryptor adapter over node-core's single RFC 8291 aes128gcm
// implementation. The app still supplies the port so compose stays free of
// library details; all ECE framing / CEK derivation / AES-GCM open lives in
// @zucoins/node-core (`decryptWebPushPayload`).

import {
  decryptWebPushPayload,
  type WebPushPayloadDecryptor,
} from "@zucoins/node-core";

export function createEceDecryptor(): WebPushPayloadDecryptor {
  return {
    async decrypt({ body, ecdhPrivateKeyBytes, authSecret }) {
      return decryptWebPushPayload({ body, ecdhPrivateKeyBytes, authSecret });
    },
  };
}

import { describe, expect, test } from "vitest";

import { decryptWebPushPayload } from "../../src/push/index.js";

describe("ECE_KEYLOG subprocess probe", () => {
  test.skipIf(process.env.ZTR_ECE_PROBE === undefined)(
    "decrypts normally without dependency output",
    () => {
      const input = JSON.parse(process.env.ZTR_ECE_PROBE!) as {
        body: string;
        privateKey: string;
        authSecret: string;
      };
      if (process.env.ZTR_ECE_MODE === "enabled-then-unset") delete process.env.ECE_KEYLOG;
      if (process.env.ZTR_ECE_MODE === "call-time-enabled") process.env.ECE_KEYLOG = "1";
      expect(decryptWebPushPayload({
        body: Buffer.from(input.body, "base64url"),
        ecdhPrivateKeyBytes: Buffer.from(input.privateKey, "base64url"),
        authSecret: Buffer.from(input.authSecret, "base64url"),
      })).toEqual(Buffer.from("push-aes128gcm-plaintext-marker-never-log"));
    },
  );
});
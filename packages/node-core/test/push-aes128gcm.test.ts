import { createECDH } from "node:crypto";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

import ece from "http_ece";
import { describe, expect, test } from "vitest";

import {
  WebPushDecryptError,
  decryptWebPushPayload,
  generateAuthSecret,
  generateEcdhKeypair,
} from "../src/push/index.js";

function encryptAsSender(params: {
  plaintext: Buffer;
  receiverPublicKeyB64url: string;
  authSecret: Buffer;
}): Buffer {
  const senderEcdh = createECDH("prime256v1");
  senderEcdh.generateKeys();
  return ece.encrypt(params.plaintext, {
    version: "aes128gcm",
    privateKey: senderEcdh,
    dh: Buffer.from(params.receiverPublicKeyB64url, "base64url"),
    authSecret: params.authSecret,
  });
}

describe("RFC 8291 aes128gcm decrypt", () => {
  test.each([
    ["module-load enabled", "1", "module-load-enabled"],
    ["enabled then unset", "1", "enabled-then-unset"],
    ["call-time enabled", undefined, "call-time-enabled"],
  ])("decrypts normally and cannot keylog auth, ciphertext, or plaintext when %s", (_label, startupValue, mode) => {
    const receiver = generateEcdhKeypair();
    const authSecret = Buffer.from("auth-secret-push-aes128gcm-marker").subarray(0, 16);
    const plaintext = Buffer.from("push-aes128gcm-plaintext-marker-never-log");
    const body = encryptAsSender({
      plaintext,
      receiverPublicKeyB64url: receiver.publicKeyB64url,
      authSecret,
    });
    const probe = spawnSync(
      "pnpm",
      ["exec", "vitest", "run", "test/fixtures/push-ece-keylog-probe.test.ts"],
      {
        // Resolved from this file, not process.cwd(): vitest runs the suite with the
        // workspace root as cwd, where a package-relative runner path does not exist.
        cwd: resolve(import.meta.dirname, ".."),
        encoding: "utf8",
        env: {
          ...process.env,
          ECE_KEYLOG: startupValue,
          ZTR_ECE_MODE: mode,
          ZTR_ECE_PROBE: JSON.stringify({
            body: body.toString("base64url"),
            privateKey: Buffer.from(receiver.privateKeyBytes).toString("base64url"),
            authSecret: authSecret.toString("base64url"),
          }),
        },
      },
    );
    const output = `${probe.stdout}${probe.stderr}`;

    // Exit status is the child runner's own health, not this test's subject (F3); the
    // exact-count assertion is what proves the decrypt actually ran and did not leak.
    expect(probe.error).toBeUndefined();
    expect(output).toContain("1 passed");
    expect(output).not.toContain(authSecret.toString("base64url"));
    expect(output).not.toContain(body.subarray(21 + 65).toString("base64url"));
    expect(output).not.toContain(plaintext.toString("base64url"));
    expect(output).not.toContain(plaintext.toString("utf8"));
  });

  test("round-trips a real Web Push envelope", () => {
    const receiver = generateEcdhKeypair();
    const authSecret = generateAuthSecret();
    const plaintext = Buffer.from(JSON.stringify({ data: { type_name: "transfer_code__v1" } }));
    const body = encryptAsSender({ plaintext, receiverPublicKeyB64url: receiver.publicKeyB64url, authSecret });

    expect(
      decryptWebPushPayload({ body, ecdhPrivateKeyBytes: receiver.privateKeyBytes, authSecret }),
    ).toEqual(plaintext);
  });

  test.each(["wrong-private-key", "wrong-auth-secret", "tampered-ciphertext"])(
    "fails closed for %s",
    (failure) => {
      const receiver = generateEcdhKeypair();
      const authSecret = generateAuthSecret();
      const body = encryptAsSender({
        plaintext: Buffer.from("authenticated payload"),
        receiverPublicKeyB64url: receiver.publicKeyB64url,
        authSecret,
      });
      if (failure === "tampered-ciphertext") body[body.length - 1] ^= 0xff;

      try {
        decryptWebPushPayload({
          body,
          ecdhPrivateKeyBytes:
            failure === "wrong-private-key" ? generateEcdhKeypair().privateKeyBytes : receiver.privateKeyBytes,
          authSecret: failure === "wrong-auth-secret" ? generateAuthSecret() : authSecret,
        });
        expect.unreachable("expected decrypt to throw");
      } catch (err) {
        expect(err).toBeInstanceOf(WebPushDecryptError);
        expect((err as WebPushDecryptError).code).toBe("PUSH_DECRYPT_FAILED");
        expect((err as Error).message).toBe("aes128gcm decrypt failed");
      }
    },
  );
});

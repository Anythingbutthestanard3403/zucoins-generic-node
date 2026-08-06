import { createECDH } from "node:crypto";

import { generateAuthSecret, generateEcdhKeypair } from "@zucoins/node-core";
import ece from "http_ece";
import { expect, test } from "vitest";

import { createEceDecryptor } from "../../src/push/ece-decryptor.js";

test("generic-node decrypts with the patched dependency", async () => {
  const receiver = generateEcdhKeypair();
  const sender = createECDH("prime256v1");
  sender.generateKeys();
  const authSecret = generateAuthSecret();
  const plaintext = Buffer.from("push-aes128gcm-generic-plaintext-marker-never-log");
  const body = ece.encrypt(plaintext, {
    version: "aes128gcm",
    privateKey: sender,
    dh: Buffer.from(receiver.publicKeyB64url, "base64url"),
    authSecret,
  });

  expect(await createEceDecryptor().decrypt({
    body,
    ecdhPrivateKeyBytes: receiver.privateKeyBytes,
    authSecret,
  })).toEqual(plaintext);
});

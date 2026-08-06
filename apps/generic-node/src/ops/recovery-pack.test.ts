// Unit tests for zp-node-recovery-pack-v1 crypto.

import { createHash, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  createRecoveryPack,
  isValidRecoveryPasscode,
  openRecoveryPack,
  peekPackContentSha256,
  RecoveryPackError,
  RECOVERY_PACK_FORMAT,
  RECOVERY_PACK_KDF,
} from "./recovery-pack.js";

const MASTER = "test-master-key-32chars!!!!!!!!!!!";

describe("recovery-pack passcode", () => {
  it("accepts 4–6 digits only", () => {
    expect(isValidRecoveryPasscode("1234")).toBe(true);
    expect(isValidRecoveryPasscode("12345")).toBe(true);
    expect(isValidRecoveryPasscode("123456")).toBe(true);
    expect(isValidRecoveryPasscode("123")).toBe(false);
    expect(isValidRecoveryPasscode("1234567")).toBe(false);
    expect(isValidRecoveryPasscode("12a4")).toBe(false);
    expect(isValidRecoveryPasscode("")).toBe(false);
  });
});

describe("createRecoveryPack / openRecoveryPack", () => {
  it("round-trips master under 6-digit passcode", () => {
    const { envelope, fileBytes } = createRecoveryPack({
      vaultMasterKey: MASTER,
      passcode: "424242",
    });
    expect(envelope.format).toBe(RECOVERY_PACK_FORMAT);
    expect(envelope.kdf.alg).toBe("argon2id");
    expect(envelope.kdf.memory_kib).toBe(RECOVERY_PACK_KDF.memory_kib);
    expect(envelope.kdf.iterations).toBe(3);
    expect(envelope.kdf.parallelism).toBe(1);
    expect(envelope.kdf.hash_len).toBe(32);
    expect(envelope.aead.alg).toBe("aes-256-gcm");
    expect(envelope.pack_content_sha256).toMatch(/^[0-9a-f]{64}$/);

    const opened = openRecoveryPack({ fileBytes, passcode: "424242" });
    expect(opened.v).toBe(1);
    expect(opened.vault_master_key).toBe(MASTER);
  });

  it("works with 4-digit passcode", () => {
    const { fileBytes } = createRecoveryPack({
      vaultMasterKey: MASTER,
      passcode: "9999",
    });
    expect(openRecoveryPack({ fileBytes, passcode: "9999" }).vault_master_key).toBe(MASTER);
  });

  it("rejects wrong passcode without leaking payload", () => {
    const { fileBytes } = createRecoveryPack({
      vaultMasterKey: MASTER,
      passcode: "111111",
    });
    expect(() => openRecoveryPack({ fileBytes, passcode: "222222" })).toThrow(RecoveryPackError);
    try {
      openRecoveryPack({ fileBytes, passcode: "222222" });
    } catch (e) {
      expect(e).toBeInstanceOf(RecoveryPackError);
      expect((e as RecoveryPackError).code).toBe("decrypt_failed");
      expect(String(e)).not.toContain(MASTER);
    }
  });

  it("rejects unknown format", () => {
    const { envelope } = createRecoveryPack({
      vaultMasterKey: MASTER,
      passcode: "123456",
    });
    const bad = { ...envelope, format: "other-v0" };
    expect(() =>
      openRecoveryPack({ fileBytes: JSON.stringify(bad), passcode: "123456" }),
    ).toThrow(/unknown recovery pack format|invalid_format/);
  });

  it("rejects tampered ciphertext digest", () => {
    const { envelope } = createRecoveryPack({
      vaultMasterKey: MASTER,
      passcode: "123456",
    });
    const bad = {
      ...envelope,
      pack_content_sha256: "a".repeat(64),
    };
    expect(() =>
      openRecoveryPack({ fileBytes: JSON.stringify(bad), passcode: "123456" }),
    ).toThrow(RecoveryPackError);
  });

  it("pack_content_sha256 is sha256 of ciphertext bytes", () => {
    const salt = randomBytes(16);
    const nonce = randomBytes(12);
    const { envelope } = createRecoveryPack({
      vaultMasterKey: MASTER,
      passcode: "555555",
      salt,
      nonce,
    });
    const ct = Buffer.from(envelope.ciphertext_b64url, "base64url");
    expect(envelope.pack_content_sha256).toBe(
      createHash("sha256").update(ct).digest("hex"),
    );
  });

  it("file bytes are UTF-8 JSON envelope without master plaintext", () => {
    const { fileBytes } = createRecoveryPack({
      vaultMasterKey: MASTER,
      passcode: "121212",
    });
    const text = fileBytes.toString("utf8");
    expect(text).not.toContain(MASTER);
    expect(JSON.parse(text).format).toBe(RECOVERY_PACK_FORMAT);
  });

  it("peekPackContentSha256 reads digest without decrypt", () => {
    const { envelope, fileBytes } = createRecoveryPack({
      vaultMasterKey: MASTER,
      passcode: "343434",
    });
    expect(peekPackContentSha256(fileBytes)).toBe(envelope.pack_content_sha256);
  });

  it("refuses short master", () => {
    expect(() =>
      createRecoveryPack({ vaultMasterKey: "short", passcode: "1234" }),
    ).toThrow(RecoveryPackError);
  });

  it("refuses non-digit passcode on create", () => {
    expect(() =>
      createRecoveryPack({ vaultMasterKey: MASTER, passcode: "abcd" }),
    ).toThrow(RecoveryPackError);
  });
});

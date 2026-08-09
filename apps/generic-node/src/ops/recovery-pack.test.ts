// Unit tests for zp-node-recovery-pack-v2 crypto.

import { createHash } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";

import {
  createRecoveryPack,
  estimateRecoverySecretEntropyBits,
  generateRecoverySecret,
  openRecoveryPack,
  peekPackContentSha256,
  recoverySecretWeakness,
  reissueRecoveryPack,
  RecoveryPackError,
  RECOVERY_PACK_FORMAT,
  RECOVERY_PACK_FORMAT_LEGACY_V1,
  RECOVERY_PACK_KDF,
  RECOVERY_PACK_MIN_ENTROPY_BITS,
  RECOVERY_PACK_PAYLOAD_VERSION,
} from "./recovery-pack.js";

const MASTER = "test-master-key-32chars!!!!!!!!!!!";
const SECRET = "9F3KQ2XW7HB4TMZ0RCJ8PNVA5D";
const WRONG_SECRET = "2QX8MJ4TB7WKZ0HRVC5NDA3F9P";

/**
 * Frozen v1 artifact, generated out of repo under the superseded digit-passcode
 * format (Argon2id 64 MiB/t=3/p=1 over JSON.stringify({v:1,vault_master_key})),
 * with a fixed salt/nonce so it is reproducible by hand. Pinned by digest below;
 * no test writes it. Its whole purpose is to prove a real v1 pack still restores.
 */
const LEGACY_V1_PACK_JSON =
  '{"format":"zp-node-recovery-pack-v1","kdf":{"alg":"argon2id","salt_b64url":"ehyeTSsPaDUdTnyaA7X2gg","memory_kib":65536,"iterations":3,"parallelism":1,"hash_len":32},"aead":{"alg":"aes-256-gcm","nonce_b64url":"Dx4tPEtaaXiHlqW0"},"ciphertext_b64url":"MXHL9B1Nd1d1mBBvirlOWtZqT6UDkO9DaJtAt0fg3PvwM44DPLEw9QBRlLQQJonKyVJCbULD4KY5wLKPD7g5BdBOlrmt8DMr6TTdFF-J","pack_content_sha256":"a4396aaa578eed0f63bbea9861af4226dfe415c3839d49baefccbc59ed89fef5"}';
const LEGACY_V1_PACK_SHA256 =
  "cd68753ce0c6c389e31f47ac723fb3d3ec98b1ddec5c0f690e8c616efb2fbc22";
const LEGACY_V1_PASSCODE = "482913";
const LEGACY_V1_MASTER = "legacy-v1-master-key-32chars!!!!!";

/**
 * One real v2 artifact shared by every assertion that only needs *a* pack.
 * Argon2id at 64 MiB costs ~2 s per derivation, so this file seals once and
 * re-reads rather than re-sealing per test.
 */
const V2_PACK = createRecoveryPack({ vaultMasterKey: MASTER, secret: SECRET });

describe("recovery secret entropy floor", () => {
  it("refuses digits only regardless of length", () => {
    expect(recoverySecretWeakness("1234")).toMatch(/digits only/);
    // Long enough to clear 128 bits under the charset estimate — still refused.
    expect(estimateRecoverySecretEntropyBits("1".repeat(64))).toBeGreaterThan(
      RECOVERY_PACK_MIN_ENTROPY_BITS,
    );
    expect(recoverySecretWeakness("0".repeat(40) + "1".repeat(40))).toMatch(/digits only/);
  });

  it("refuses a secret under the floor, and reports the floor not a length", () => {
    const weak = recoverySecretWeakness("Ab3Kq9ZtWm");
    expect(weak).toMatch(/at least 128 bits of entropy/);
    expect(weak).not.toMatch(/character(s)? long|length/);
  });

  it("refuses a long but repetitive secret", () => {
    expect(recoverySecretWeakness("abab".repeat(20))).toMatch(/distinct characters/);
  });

  it("accepts the generated secret", () => {
    expect(recoverySecretWeakness(SECRET)).toBeNull();
    for (let i = 0; i < 25; i++) {
      const generated = generateRecoverySecret();
      expect(recoverySecretWeakness(generated)).toBeNull();
      expect(estimateRecoverySecretEntropyBits(generated)).toBeGreaterThanOrEqual(
        RECOVERY_PACK_MIN_ENTROPY_BITS,
      );
    }
  });

  it("generates a different secret each call", () => {
    const seen = new Set(Array.from({ length: 25 }, () => generateRecoverySecret()));
    expect(seen.size).toBe(25);
  });
});

describe("entropy floor is enforced at creation", () => {
  // Independent of RECOVERY_PACK_PROVE_FAIL_THRESHOLD: no lockout store, no HTTP,
  // no prove call. A weak secret can never produce an artifact in the first place.
  it("refuses to build a pack under a digit passcode", () => {
    expect(() => createRecoveryPack({ vaultMasterKey: MASTER, secret: "482913" })).toThrow(
      RecoveryPackError,
    );
    try {
      createRecoveryPack({ vaultMasterKey: MASTER, secret: "482913" });
      expect.unreachable("digit passcode must not seal a pack");
    } catch (e) {
      expect((e as RecoveryPackError).code).toBe("weak_secret");
      expect((e as RecoveryPackError).message).toMatch(/digits only/);
      expect(String(e)).not.toContain(MASTER);
    }
  });

  it("refuses to build a pack under a sub-floor secret", () => {
    try {
      createRecoveryPack({ vaultMasterKey: MASTER, secret: "Tr0ub4dor&3" });
      expect.unreachable("sub-floor secret must not seal a pack");
    } catch (e) {
      expect((e as RecoveryPackError).code).toBe("weak_secret");
      expect((e as RecoveryPackError).message).toMatch(/128 bits of entropy/);
    }
  });

  it("generates a secret when the caller supplies none", () => {
    const built = createRecoveryPack({ vaultMasterKey: MASTER });
    expect(recoverySecretWeakness(built.secret)).toBeNull();
    expect(
      openRecoveryPack({ fileBytes: built.fileBytes, secret: built.secret }).vault_master_key,
    ).toBe(MASTER);
  });
});

describe("Argon2id parameters are pinned", () => {
  // 64 MiB / t=3 / p=1 / 32-byte output. Unchanged from v1 by design — the KDF
  // was never the weakness, and moving it would strand every existing pack.
  it("pins the frozen constants", () => {
    expect(RECOVERY_PACK_KDF).toStrictEqual({
      alg: "argon2id",
      memory_kib: 65_536,
      iterations: 3,
      parallelism: 1,
      hash_len: 32,
    });
  });

  it("writes the same parameters into the envelope", () => {
    expect(V2_PACK.envelope.kdf).toStrictEqual({
      alg: "argon2id",
      salt_b64url: V2_PACK.envelope.kdf.salt_b64url,
      memory_kib: 65_536,
      iterations: 3,
      parallelism: 1,
      hash_len: 32,
    });
  });

  it("refuses an envelope whose parameters were downgraded", () => {
    const weakened = {
      ...V2_PACK.envelope,
      kdf: { ...V2_PACK.envelope.kdf, memory_kib: 8 },
    };
    expect(() =>
      openRecoveryPack({ fileBytes: JSON.stringify(weakened), secret: SECRET }),
    ).toThrow(/kdf rejected/);
  });
});

describe("createRecoveryPack / openRecoveryPack", () => {
  it("round-trips master and seals payload v2", () => {
    expect(V2_PACK.envelope.format).toBe(RECOVERY_PACK_FORMAT);
    expect(V2_PACK.envelope.format).toBe("zp-node-recovery-pack-v2");
    expect(V2_PACK.envelope.aead.alg).toBe("aes-256-gcm");
    expect(V2_PACK.envelope.pack_content_sha256).toMatch(/^[0-9a-f]{64}$/);

    const opened = openRecoveryPack({ fileBytes: V2_PACK.fileBytes, secret: SECRET });
    expect(opened.v).toBe(RECOVERY_PACK_PAYLOAD_VERSION);
    expect(opened.v).toBe(2);
    expect(opened.vault_master_key).toBe(MASTER);
  });

  it("rejects wrong secret without leaking payload", () => {
    try {
      openRecoveryPack({ fileBytes: V2_PACK.fileBytes, secret: WRONG_SECRET });
      expect.unreachable("wrong secret must not open the pack");
    } catch (e) {
      expect(e).toBeInstanceOf(RecoveryPackError);
      expect((e as RecoveryPackError).code).toBe("decrypt_failed");
      expect(String(e)).not.toContain(MASTER);
    }
  });

  it("rejects unknown format", () => {
    const bad = { ...V2_PACK.envelope, format: "other-v0" };
    expect(() => openRecoveryPack({ fileBytes: JSON.stringify(bad), secret: SECRET })).toThrow(
      /unknown recovery pack format|invalid_format/,
    );
  });

  it("rejects tampered ciphertext digest", () => {
    const bad = { ...V2_PACK.envelope, pack_content_sha256: "a".repeat(64) };
    expect(() => openRecoveryPack({ fileBytes: JSON.stringify(bad), secret: SECRET })).toThrow(
      RecoveryPackError,
    );
  });

  it("pack_content_sha256 is sha256 of ciphertext bytes", () => {
    const ct = Buffer.from(V2_PACK.envelope.ciphertext_b64url, "base64url");
    expect(V2_PACK.envelope.pack_content_sha256).toBe(
      createHash("sha256").update(ct).digest("hex"),
    );
  });

  it("file bytes are UTF-8 JSON envelope without master plaintext or secret", () => {
    const text = V2_PACK.fileBytes.toString("utf8");
    expect(text).not.toContain(MASTER);
    expect(text).not.toContain(V2_PACK.secret);
    expect(JSON.parse(text).format).toBe(RECOVERY_PACK_FORMAT);
  });

  it("peekPackContentSha256 reads digest without decrypt", () => {
    expect(peekPackContentSha256(V2_PACK.fileBytes)).toBe(V2_PACK.envelope.pack_content_sha256);
  });

  it("refuses short master", () => {
    expect(() => createRecoveryPack({ vaultMasterKey: "short", secret: SECRET })).toThrow(
      RecoveryPackError,
    );
  });
});

describe("legacy v1 pack", () => {
  it("fixture matches its pinned digest", () => {
    expect(
      createHash("sha256").update(Buffer.from(LEGACY_V1_PACK_JSON, "utf8")).digest("hex"),
    ).toBe(LEGACY_V1_PACK_SHA256);
    expect(JSON.parse(LEGACY_V1_PACK_JSON).format).toBe(RECOVERY_PACK_FORMAT_LEGACY_V1);
  });

  it("is never silently reinterpreted as v2", () => {
    try {
      openRecoveryPack({ fileBytes: LEGACY_V1_PACK_JSON, secret: LEGACY_V1_PASSCODE });
      expect.unreachable("v1 must not open without the explicit opt-in");
    } catch (e) {
      expect(e).toBeInstanceOf(RecoveryPackError);
      expect((e as RecoveryPackError).code).toBe("legacy_pack_v1");
      expect(String(e)).not.toContain(LEGACY_V1_MASTER);
    }
  });

  it("restores through the explicit legacy path", () => {
    const opened = openRecoveryPack({
      fileBytes: LEGACY_V1_PACK_JSON,
      secret: LEGACY_V1_PASSCODE,
      allowLegacyV1: true,
    });
    expect(opened.v).toBe(1);
    expect(opened.vault_master_key).toBe(LEGACY_V1_MASTER);
  });

  it("relabelling a v1 file as v2 does not smuggle it past the opt-in", () => {
    const relabelled = JSON.stringify({
      ...(JSON.parse(LEGACY_V1_PACK_JSON) as Record<string, unknown>),
      format: RECOVERY_PACK_FORMAT,
    });
    expect(() =>
      openRecoveryPack({ fileBytes: relabelled, secret: LEGACY_V1_PASSCODE }),
    ).toThrow(/superseded v1 recovery pack/);
  });
});

describe("reissueRecoveryPack", () => {
  // The re-issue itself is the expensive part (one open + one seal), so each
  // group re-seals once in a hook and the assertions read the result.
  describe("from a v1 pack", () => {
    let reissued: ReturnType<typeof reissueRecoveryPack>;
    beforeAll(() => {
      reissued = reissueRecoveryPack({
        fileBytes: LEGACY_V1_PACK_JSON,
        secret: LEGACY_V1_PASSCODE,
        allowLegacyV1: true,
      });
    });

    it("emits a v2 envelope under a generated secret and names the artifact it replaces", () => {
      expect(reissued.previousVersion).toBe(1);
      expect(reissued.previousPackContentSha256).toBe(
        (JSON.parse(LEGACY_V1_PACK_JSON) as { pack_content_sha256: string }).pack_content_sha256,
      );
      expect(reissued.envelope.format).toBe(RECOVERY_PACK_FORMAT);
      expect(recoverySecretWeakness(reissued.secret)).toBeNull();
      expect(reissued.secret).not.toBe(LEGACY_V1_PASSCODE);
    });

    it("carries the same master forward under the new secret", () => {
      const opened = openRecoveryPack({
        fileBytes: reissued.fileBytes,
        secret: reissued.secret,
      });
      expect(opened.v).toBe(2);
      expect(opened.vault_master_key).toBe(LEGACY_V1_MASTER);
    });

    it("leaves the superseded passcode useless against the replacement", () => {
      expect(() =>
        openRecoveryPack({ fileBytes: reissued.fileBytes, secret: LEGACY_V1_PASSCODE }),
      ).toThrow(RecoveryPackError);
    });
  });

  describe("from a v2 pack", () => {
    const NEXT_SECRET = "8HZ4PQ2WKX7NRB0MJ5TVDC93FA";
    let reissued: ReturnType<typeof reissueRecoveryPack>;
    beforeAll(() => {
      reissued = reissueRecoveryPack({
        fileBytes: V2_PACK.fileBytes,
        secret: SECRET,
        newSecret: NEXT_SECRET,
      });
    });

    it("re-seals under the caller-supplied secret as a distinct artifact", () => {
      expect(reissued.previousVersion).toBe(2);
      expect(reissued.secret).toBe(NEXT_SECRET);
      expect(reissued.envelope.pack_content_sha256).not.toBe(
        V2_PACK.envelope.pack_content_sha256,
      );
    });

    it("opens under the new secret", () => {
      expect(
        openRecoveryPack({ fileBytes: reissued.fileBytes, secret: NEXT_SECRET })
          .vault_master_key,
      ).toBe(MASTER);
    });
  });

  it("refuses a v1 source without the explicit opt-in", () => {
    expect(() =>
      reissueRecoveryPack({ fileBytes: LEGACY_V1_PACK_JSON, secret: LEGACY_V1_PASSCODE }),
    ).toThrow(/superseded v1 recovery pack/);
  });

  it("refuses a weak new secret before it decrypts anything", () => {
    expect(() =>
      reissueRecoveryPack({
        fileBytes: V2_PACK.fileBytes,
        secret: SECRET,
        newSecret: "123456",
      }),
    ).toThrow(/digits only/);
  });

  it("refuses when the existing secret is wrong", () => {
    expect(() =>
      reissueRecoveryPack({
        fileBytes: V2_PACK.fileBytes,
        secret: WRONG_SECRET,
        newSecret: "5T7YQ2ZXK4B0NRJ8MHVDC93FA",
      }),
    ).toThrow(RecoveryPackError);
  });
});

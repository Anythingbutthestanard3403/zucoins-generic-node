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

  it("refuses a non-alphabet / wrong-length secret (ZTR-1220 shape)", () => {
    // Former charset×length accept path — dictionary / mixed-case phrases.
    expect(recoverySecretWeakness("Ab3Kq9ZtWm")).toMatch(/Crockford base32 alphabet/);
    expect(recoverySecretWeakness("Tr0ub4dor&3")).toMatch(/Crockford base32 alphabet/);
    expect(recoverySecretWeakness("correct horse battery staple zz")).toMatch(
      /Crockford base32 alphabet/,
    );
    expect(recoverySecretWeakness("qwertyuiopasdfghjklzxcvbnm1234")).toMatch(
      /Crockford base32 alphabet/,
    );
    // 28-digit PIN + letter — long enough for the old proxy, wrong alphabet.
    expect(recoverySecretWeakness("1".repeat(28) + "A")).toMatch(/Crockford base32 alphabet/);
    // Wrong length inside the alphabet.
    expect(recoverySecretWeakness("9F3KQ2XW7HB4TMZ0RCJ8PNVA5")).toMatch(
      /Crockford base32 alphabet/,
    );
    expect(recoverySecretWeakness(SECRET + "0")).toMatch(/Crockford base32 alphabet/);
  });

  it("refuses a tiled substring even with ≥10 distinct chars (ZTR-1220)", () => {
    // Period-2 with only 2 distinct — distinct-char guard fires first.
    expect(recoverySecretWeakness("AB".repeat(13))).toMatch(/distinct characters/);
    // Exact tiling of a 13-char unit (2×13=26) with ≥10 distinct — the case the
    // old distinct-char guard alone missed (ticket: "abcdefghij".repeat(3)).
    const periodTiling = "0123456789ABC".repeat(2);
    expect(periodTiling).toHaveLength(26);
    expect(new Set(periodTiling).size).toBeGreaterThanOrEqual(10);
    expect(recoverySecretWeakness(periodTiling)).toMatch(/repeated substring/);
    // Ticket lowercase phrase still refused (alphabet), not accepted via proxy.
    expect(recoverySecretWeakness("abcdefghij".repeat(3))).toMatch(/Crockford base32 alphabet/);
  });

  it("refuses a long sequential alphabet run", () => {
    // 26-char monotone run through Crockford — full distinct set, exact length.
    const run = "0123456789ABCDEFGHJKMNPQRS";
    expect(run).toHaveLength(26);
    expect(recoverySecretWeakness(run)).toMatch(/sequential run/);
  });

  it("refuses Review B residual low-entropy Crockford×26 secrets", () => {
    // Named residuals that cleared the prior exact-tiling / ±1-only floor.
    const residuals: Array<{ secret: string; want: RegExp }> = [
      {
        // Crockford-mapped "correct horse battery staple".
        secret: "C0RRECTH0RSEBATTERYSTAP1E0",
        want: /letter-only run|repeated substring|sequential run|same-character|dictionary/,
      },
      {
        // Near-tile "letmein" ×3 + pad — period 7 does not divide 26.
        secret: "1ETME1N1ETME1N1ETME1NABCD0",
        want: /repeated substring/,
      },
      {
        secret: "HVNTER2HVNTER2HVNTER2AB012",
        want: /repeated substring/,
      },
      {
        secret: "PACKSECRETPACKSECRETPACK01",
        want: /repeated substring|letter-only run|dictionary/,
      },
      {
        // Triple-letter blocks — same-symbol structure, not ±1 monotone.
        secret: "AAABBBCCCDDDEEEFFFGGGHHHJK",
        want: /same-character run|letter-only run|repeated substring/,
      },
      {
        // Arithmetic step-2 through the alphabet (not ±1).
        secret: "02468ACEGJMPRTWY02468ACEGJ",
        want: /sequential run|repeated substring/,
      },
      {
        // Human mnemonic-ish letter run.
        secret: "MYVAV1TMASTERKEYBACKP20240",
        want: /letter-only run|repeated substring|dictionary/,
      },
    ];
    for (const { secret, want } of residuals) {
      expect(secret).toHaveLength(26);
      expect(new Set(secret).size).toBeGreaterThanOrEqual(10);
      expect(recoverySecretWeakness(secret)).toMatch(want);
      expect(() => createRecoveryPack({ vaultMasterKey: MASTER, secret })).toThrow(
        RecoveryPackError,
      );
      try {
        createRecoveryPack({ vaultMasterKey: MASTER, secret });
        expect.unreachable(`residual must not seal: ${secret}`);
      } catch (e) {
        expect((e as RecoveryPackError).code).toBe("weak_secret");
      }
    }
  });

  it("refuses Review B r2 residual digit-broken dictionary / keyboard / alternation", () => {
    // Named residuals that still sealed under the r2 letter-run / near-tile floor.
    const residualWant =
      /dictionary|keyboard-row|alternation|pair sequence|letter-only run|repeated substring|sequential run|same-character/;
    const residuals = [
      // Digit-broken "correct horse battery staple" variants.
      "C0RRECTH0RSEBATTERY0STAP1E",
      "C0RRECTH0RSEBATT3RYSTAP1E0",
      "C0RRECTH0RSEBATT3RYSTAP1EX",
      // CORRECT with a digit after every letter.
      "C001R2R3E4C5T6H708R9S0E1B2",
      // Digit-broken English mnemonics.
      "P1EASE1ETME1NT0THEN0DE2024",
      "W1NTER1SC0M1NGN0RTHKEY2024",
      "MAYTHEF0RCEBEW1THY0V2024XX",
      "NEVERG0NNAG1VEY0VVP2024KEY",
      // Keyboard rows + digit break.
      "QWERTYASD1FGHZXCVBN12345AB",
      // Strict alternating digit×letter / pair sequences.
      "0A1B2C3D4E5F6G7H8J9KMNPRST",
      "A1B2C3D4E5F6G7H8J9K0M1N2P3",
      // Multi short-token English markov (CODE/PIN/PASS/NODE).
      "MANC0DE7P1NGETP1NPASS4N0DE",
      // Alt-digit MASTERKEY / PASSWORD skeletons.
      "M0A1S2T3E4R5K6E7Y8B9A0C1K2",
      "P0A1S2S3W4R5D6H7N8T9R0X1Y2",
    ];
    for (const secret of residuals) {
      expect(secret).toHaveLength(26);
      expect(new Set(secret).size).toBeGreaterThanOrEqual(10);
      expect(recoverySecretWeakness(secret)).toMatch(residualWant);
      expect(() => createRecoveryPack({ vaultMasterKey: MASTER, secret })).toThrow(
        RecoveryPackError,
      );
      try {
        createRecoveryPack({ vaultMasterKey: MASTER, secret });
        expect.unreachable(`r2 residual must not seal: ${secret}`);
      } catch (e) {
        expect((e as RecoveryPackError).code).toBe("weak_secret");
      }
    }
  });

  it("refuses Review B r3 residual keyboard-column / media / reverse-dict / broken-step class", () => {
    // Opposed bar from tasks/ztr-1220-review-B-r3.md — class still open at r3 tip.
    const residualWant =
      /dictionary|keyboard-row|alternation|pair sequence|letter-only run|repeated substring|sequential run|same-character/;
    const residuals = [
      // Keyboard columns (vertical 1QAZ/2WSX/…) and reverse stitches.
      "1QAZ2WSX3EDC4RFV5TGB6YHN0P",
      "1QAZ2WSX3EDC4RFV5TGB6YHN7V",
      "ZAQ1XSW2CDE3VFR4BGT5NHY6MJ",
      "P0MJV7NHY6BGT5VFR4CDE3XSW2",
      // Off-list English / media / song mnemonics (Crockford-mapped).
      "THEQV1CKBR0WNFXJVMPS2024AX",
      "QV1CKBR0WNF0XJVMPS0VER2024",
      "STR4NGERTH1NGS2024KEYABCXX",
      "BR4K1NGB4DHE1SENBERG2024XX",
      "HACKTHEP1ANET2024KEYM0RPHX",
      "JACKD4WSAXEMYFR0ZENV0WABXX",
      "H0WZVBR0WNDC0WF4RMSXYZ01XX",
      "A11W0RKANDN0P1AY2024ABCDXX",
      "0NCEVP0NAT1ME1N20241ANDXXX",
      "Y0DASH411N0TP4SS2024KEYXXX",
      "F00BARBAZQVXM0RPH2024KEYXX",
      "D0NTST0PBE1EV1N2024KEYABCX",
      "YE110WSVBMAR1NE2024KEYABCX",
      "STA1RW4YT0HE4VEN2024KEYXXX",
      "B0HEM1ANRHAPS0DY2024KEYXXX",
      "10REM1PSVMT0RPH2024KEYABCD",
      // Reversed dictionary skeleton (CORRECT HORSE BATTERY STAPLE).
      "TCERR0CESR0HYRETTABE1PATS2",
      // Ticket / structured-id mnemonic.
      "ZTR1220ENTR0PYF100R2024AB2",
      // Broken step-k / high-structure walks.
      "BP1CQ2DR3ES4FT5GV6HW7JX8KY",
      "5AFMS49EKRX8DJQW1CHPV05GNT",
      // Paired doubles + digit noise.
      "AA1BB2CC3DD4EE5FF6GG7HH8JJ",
      // Wordy single-LEN4 + media pad.
      "MANP1NXG3TXKEYN0DE2024ABC2",
      // Fibonacci digit-prefix walk.
      "112358DN2QSG9S2VXRND2FH0HH",
    ];
    for (const secret of residuals) {
      expect(secret).toHaveLength(26);
      expect(new Set(secret).size).toBeGreaterThanOrEqual(10);
      const weakness = recoverySecretWeakness(secret);
      expect(weakness, `accepted residual: ${secret}`).toBeTypeOf("string");
      expect(weakness).toMatch(residualWant);
      expect(() => createRecoveryPack({ vaultMasterKey: MASTER, secret })).toThrow(
        RecoveryPackError,
      );
      try {
        createRecoveryPack({ vaultMasterKey: MASTER, secret });
        expect.unreachable(`r3 residual must not seal: ${secret}`);
      } catch (e) {
        expect((e as RecoveryPackError).code).toBe("weak_secret");
      }
    }
  });

  it("refuses Review B r4 residual off-list English/media/geo/π human-pattern class", () => {
    // Opposed bar from tasks/ztr-1220-review-B-r4.md — finite dict arms race residual.
    const residualWant =
      /dictionary|keyboard-row|alternation|pair sequence|letter-only run|repeated substring|sequential run|same-character|human pattern/;
    const residuals = [
      "THECAKE1SA11EP0RTA12024XXA",
      "H0GWARTSEXPRESS2024KEYABXA",
      "GANGNAMSTY1E2024KEYABCDEXA",
      "HARRYP0TTERWAND2024KEYABXA",
      "STARWARSJED1K1GHT2024ABXAB",
      "GAME0FTHR0NES2024KEYABCXXA",
      "314159265358979323846ABCDA",
      "TAB1ECHA1RH0VSEWATER2024XA",
      "NEWY0RKC1TY2024KEYABCDEXAB",
      "SPH1NX0FB1ACKQVARTZ2024XXA",
    ];
    for (const secret of residuals) {
      expect(secret).toHaveLength(26);
      expect(new Set(secret).size).toBeGreaterThanOrEqual(10);
      const weakness = recoverySecretWeakness(secret);
      expect(weakness, `accepted residual: ${secret}`).toBeTypeOf("string");
      expect(weakness).toMatch(residualWant);
      expect(() => createRecoveryPack({ vaultMasterKey: MASTER, secret })).toThrow(
        RecoveryPackError,
      );
      try {
        createRecoveryPack({ vaultMasterKey: MASTER, secret });
        expect.unreachable(`r4 residual must not seal: ${secret}`);
      } catch (e) {
        expect((e as RecoveryPackError).code).toBe("weak_secret");
      }
    }
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

  it("refuses to build a pack under a sub-floor / non-shape secret", () => {
    try {
      createRecoveryPack({ vaultMasterKey: MASTER, secret: "Tr0ub4dor&3" });
      expect.unreachable("sub-floor secret must not seal a pack");
    } catch (e) {
      expect((e as RecoveryPackError).code).toBe("weak_secret");
      expect((e as RecoveryPackError).message).toMatch(
        /Crockford base32 alphabet|128 bits of entropy/,
      );
    }
  });

  it("refuses the ZTR-1220 charset×length false-accept cases at seal time", () => {
    const falseAccepts = [
      "abcdefghij".repeat(3),
      "qwertyuiopasdfghjklzxcvbnm1234",
      "correct horse battery staple zz",
      "1".repeat(28) + "A",
      "0123456789ABC".repeat(2),
      // Review B residual class (Crockford×26 that previously sealed).
      "C0RRECTH0RSEBATTERYSTAP1E0",
      "1ETME1N1ETME1N1ETME1NABCD0",
      "AAABBBCCCDDDEEEFFFGGGHHHJK",
      "02468ACEGJMPRTWY02468ACEGJ",
      "PACKSECRETPACKSECRETPACK01",
      // Review B r2 residual class (digit-broken dict / keyboard / alternation).
      "C0RRECTH0RSEBATTERY0STAP1E",
      "C0RRECTH0RSEBATT3RYSTAP1E0",
      "C001R2R3E4C5T6H708R9S0E1B2",
      "P1EASE1ETME1NT0THEN0DE2024",
      "QWERTYASD1FGHZXCVBN12345AB",
      "0A1B2C3D4E5F6G7H8J9KMNPRST",
      "A1B2C3D4E5F6G7H8J9K0M1N2P3",
      "MANC0DE7P1NGETP1NPASS4N0DE",
      // Review B r3 residual class (columns / media / reverse-dict / broken-step).
      "1QAZ2WSX3EDC4RFV5TGB6YHN0P",
      "ZAQ1XSW2CDE3VFR4BGT5NHY6MJ",
      "THEQV1CKBR0WNFXJVMPS2024AX",
      "STR4NGERTH1NGS2024KEYABCXX",
      "HACKTHEP1ANET2024KEYM0RPHX",
      "TCERR0CESR0HYRETTABE1PATS2",
      "BP1CQ2DR3ES4FT5GV6HW7JX8KY",
      "AA1BB2CC3DD4EE5FF6GG7HH8JJ",
    ];
    for (const secret of falseAccepts) {
      expect(() => createRecoveryPack({ vaultMasterKey: MASTER, secret })).toThrow(
        RecoveryPackError,
      );
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

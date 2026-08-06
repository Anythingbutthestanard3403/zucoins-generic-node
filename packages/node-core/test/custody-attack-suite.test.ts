// RUNTIME adversarial attack suite for the custody boundary:
//   - per-wallet AES-256-GCM vault envelope
//   - lease-bound WalletSigningCapability signer
//
// This is the only place frozen acceptance criterion ("Arbitrary caller-supplied
// preimages cannot be signed") is proven rather than asserted. It drives breaking inputs
// through the live seams and asserts each attack fails CLOSED with a typed rejection.
//
// Pattern mirror: src/reporting/reporting-attack-suite*.test.ts.

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  sign as edSign,
} from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import {
  AAD_GOLDEN as FROZEN_AAD_GOLDEN,
  buildWalletSecretAad as frozenBuildWalletSecretAad,
} from "@zucoins/generic-node-contracts/vault";

import {
  LeaseSignerBoundary,
  NotSignerLeaderError,
  SignerBoundaryError,
  UnknownSigningPurposeError,
  type ActiveLeaseRecord,
  type SignerAuditEntry,
  type SignerLeadershipLatch,
  type VaultSigner,
  type WalletSigningCapability,
} from "../src/core/signer-boundary.js";
import {
  AUTH_TAG_LENGTH_BYTES,
  buildWalletDekInfo,
  buildWalletSecretAad,
  DEK_LENGTH_BYTES,
  deriveEd25519PublicKeyBase64Url,
  deriveRootKey,
  EncryptedWalletKeyStore,
  InMemoryVaultAccessAuditLog,
  InMemoryVaultStore,
  NONCE_LENGTH_BYTES,
  openWalletSecret,
  sealWalletSecret,
  toBase64UrlPadded,
  VaultOpenError,
  type SealedEnvelope,
  type WalletIdentity,
} from "../src/vault/index.js";

/* ─── fixtures ───────────────────────────────────────────────────────────── */

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const TEST_SEED = Buffer.from("a".repeat(64), "hex");
const MASTER_KEY = Buffer.from("test-master-key-for-vault-tests!");
const SALT = Buffer.from("test-salt-16bytes");
const FIXED_TIME = "2026-01-15T00:00:00.000Z";

function sha256HexBytes(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function sha256HexText(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function makeTestSecretKey(seed: Buffer = TEST_SEED): { secretKey: Buffer; publicKey: string } {
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const rawPub = Buffer.from(spki).subarray(-32);
  return {
    publicKey: toBase64UrlPadded(rawPub),
    secretKey: Buffer.concat([seed, rawPub]),
  };
}

const { secretKey: TEST_SECRET_KEY, publicKey: TEST_PUBLIC_KEY } = makeTestSecretKey();
const OTHER = makeTestSecretKey(Buffer.from("b".repeat(64), "hex"));

const IDENTITY: WalletIdentity = {
  nodeId: "11111111-1111-4111-8111-111111111111",
  walletId: "22222222-2222-4222-8222-222222222222",
  keyVersion: 1,
  publicKey: TEST_PUBLIC_KEY,
  keyOrigin: "node_generated",
};

const ROOT_KEY = deriveRootKey(MASTER_KEY, SALT);

function deriveWalletDek(rootKey: Uint8Array, identity: WalletIdentity): Buffer {
  const info = buildWalletDekInfo({
    nodeId: identity.nodeId,
    walletId: identity.walletId,
    keyVersion: identity.keyVersion,
  });
  return Buffer.from(
    hkdfSync("sha256", Buffer.from(rootKey), Buffer.alloc(0), Buffer.from(info, "utf8"), DEK_LENGTH_BYTES),
  );
}

/** Manual GCM open against a sealed envelope with a caller-supplied AAD string. */
function tryGcmOpen(envelope: SealedEnvelope, rootKey: Uint8Array, identity: WalletIdentity, aadText: string): "ok" | "auth_fail" {
  const dek = deriveWalletDek(rootKey, identity);
  try {
    const decipher = createDecipheriv("aes-256-gcm", dek, Buffer.from(envelope.nonce));
    decipher.setAAD(Buffer.from(aadText, "utf8"));
    decipher.setAuthTag(Buffer.from(envelope.authTag));
    decipher.update(Buffer.from(envelope.ciphertext));
    decipher.final();
    return "ok";
  } catch {
    return "auth_fail";
  }
}

function makeCapability(overrides: Partial<WalletSigningCapability> = {}): WalletSigningCapability {
  const preimageText = overrides.preimageText ?? '{"amount":"1000","sender":"wallet-1"}';
  return {
    walletId: "wallet-1",
    operationId: "op-1",
    leaseEpoch: 1n,
    purpose: "SPLITCHAIN_STEP_1",
    preimageText,
    expectedPreimageSha256: sha256HexText(preimageText),
    ...overrides,
  };
}

function makeLease(overrides: Partial<ActiveLeaseRecord> = {}): ActiveLeaseRecord {
  return {
    walletId: "wallet-1",
    operationId: "op-1",
    epoch: 1n,
    role: "SEND_SOURCE",
    lifecycle: "ACTIVE",
    ...overrides,
  };
}

function makeBoundary(
  lease: ActiveLeaseRecord | null,
  options: {
    leadership?: SignerLeadershipLatch;
    vaultSigner?: VaultSigner;
  } = {},
) {
  const auditEntries: SignerAuditEntry[] = [];
  const vaultSigner: VaultSigner = options.vaultSigner ?? {
    sign: vi.fn().mockResolvedValue("c2lnbmF0dXJlLWJ5dGVz"),
  };
  const leaseReader = { readActiveLease: vi.fn().mockResolvedValue(lease) };
  const boundary = new LeaseSignerBoundary({
    leadership: options.leadership ?? { held: true },
    leaseReader,
    vaultSigner,
    auditLog: {
      append: vi.fn().mockImplementation(async (e: SignerAuditEntry) => {
        auditEntries.push(e);
      }),
    },
    now: () => FIXED_TIME,
    assertMoneyAdmitted: () => {},
    assertCanOperate: () => {},
    assertWalletMaySign: async () => {},
  });
  return { boundary, auditEntries, vaultSigner, leaseReader };
}

/* ─── 1. Six independent AAD-field mutations ─────────────────────────────── */

describe("attack suite — vault AAD field mutations (vector 1)", () => {
  const envelope = sealWalletSecret(ROOT_KEY, IDENTITY, TEST_SECRET_KEY);
  const honestAad = buildWalletSecretAad(IDENTITY);

  it("pins the frozen AAD golden digest used by the attack fixtures", () => {
    const aad = frozenBuildWalletSecretAad(FROZEN_AAD_GOLDEN.inputs);
    expect(sha256HexBytes(Buffer.from(aad, "utf8"))).toBe(FROZEN_AAD_GOLDEN.aad_sha256);
    expect(FROZEN_AAD_GOLDEN.aad_sha256).toBe(
      "a88fa5bc689d90bd4d6b76b4bf6678b181864bf979b7fb9627117aca109f0e84",
    );
  });

  it("honest AAD opens (control — attack suite is not stuck closed)", () => {
    expect(tryGcmOpen(envelope, ROOT_KEY, IDENTITY, honestAad)).toBe("ok");
    const opened = openWalletSecret(ROOT_KEY, envelope, IDENTITY);
    expect(Buffer.from(opened.bytes)).toEqual(TEST_SECRET_KEY);
    opened.wipe();
  });

  it.each([
    {
      field: "domain label",
      aad: honestAad.replace("zp-wallet-secret-v1", "zp-wallet-secret-v0"),
    },
    {
      field: "node_id",
      aad: buildWalletSecretAad({
        ...IDENTITY,
        nodeId: "99999999-9999-4999-8999-999999999999",
      }),
    },
    {
      field: "wallet_id",
      aad: buildWalletSecretAad({
        ...IDENTITY,
        walletId: "99999999-9999-4999-8999-999999999999",
      }),
    },
    {
      field: "key_version",
      aad: buildWalletSecretAad({ ...IDENTITY, keyVersion: 2 }),
    },
    {
      field: "public_key",
      aad: buildWalletSecretAad({ ...IDENTITY, publicKey: OTHER.publicKey }),
    },
    {
      field: "key_origin",
      aad: buildWalletSecretAad({ ...IDENTITY, keyOrigin: "imported" }),
    },
  ] as const)("mutating AAD field $field alone breaks GCM auth", ({ field, aad }) => {
    expect(aad, `${field} must actually change the AAD`).not.toBe(honestAad);
    // Domain is a constant in the production open path (reconstructed from the frozen
    // label, never a WalletIdentity field). Prove GCM auth fails under a mutated domain
    // via the low-level decrypt path; identity-field mutations exercise openWalletSecret.
    if (field === "domain label") {
      expect(tryGcmOpen(envelope, ROOT_KEY, IDENTITY, aad)).toBe("auth_fail");
      return;
    }

    const openIdentity: WalletIdentity =
      field === "node_id"
        ? { ...IDENTITY, nodeId: "99999999-9999-4999-8999-999999999999" }
        : field === "wallet_id"
          ? { ...IDENTITY, walletId: "99999999-9999-4999-8999-999999999999" }
          : field === "key_version"
            ? { ...IDENTITY, keyVersion: 2 }
            : field === "public_key"
              ? { ...IDENTITY, publicKey: OTHER.publicKey }
              : { ...IDENTITY, keyOrigin: "imported" };

    // Domain / key_origin / public_key leave the DEK unchanged — pure AAD auth failure.
    // node_id / wallet_id / key_version also re-derive a different DEK; either way auth fails.
    expect(tryGcmOpen(envelope, ROOT_KEY, openIdentity, aad)).toBe("auth_fail");
    expect(() => openWalletSecret(ROOT_KEY, envelope, openIdentity)).toThrow(VaultOpenError);
    try {
      openWalletSecret(ROOT_KEY, envelope, openIdentity);
    } catch (error) {
      expect((error as VaultOpenError).code).toBe("AUTH_TAG_FAILURE");
    }
  });
});

/* ─── 2. Ciphertext / auth-tag / wrong master key ────────────────────────── */

describe("attack suite — ciphertext, auth-tag, wrong KEK (vector 2)", () => {
  it("ciphertext byte flip fails closed", () => {
    const envelope = sealWalletSecret(ROOT_KEY, IDENTITY, TEST_SECRET_KEY);
    const tampered = { ...envelope, ciphertext: Buffer.from(envelope.ciphertext) };
    tampered.ciphertext[0] ^= 0xff;
    expect(() => openWalletSecret(ROOT_KEY, tampered, IDENTITY)).toThrow(VaultOpenError);
    try {
      openWalletSecret(ROOT_KEY, tampered, IDENTITY);
    } catch (error) {
      expect((error as VaultOpenError).code).toBe("AUTH_TAG_FAILURE");
    }
  });

  it("auth-tag byte flip fails closed", () => {
    const envelope = sealWalletSecret(ROOT_KEY, IDENTITY, TEST_SECRET_KEY);
    const tampered = { ...envelope, authTag: Buffer.from(envelope.authTag) };
    tampered.authTag[0] ^= 0xff;
    expect(() => openWalletSecret(ROOT_KEY, tampered, IDENTITY)).toThrow(VaultOpenError);
    try {
      openWalletSecret(ROOT_KEY, tampered, IDENTITY);
    } catch (error) {
      expect((error as VaultOpenError).code).toBe("AUTH_TAG_FAILURE");
    }
  });

  it("wrong master key / KEK fails closed", () => {
    const envelope = sealWalletSecret(ROOT_KEY, IDENTITY, TEST_SECRET_KEY);
    const wrongRoot = deriveRootKey(Buffer.from("wrong-master-key-not-the-real!!"), SALT);
    expect(() => openWalletSecret(wrongRoot, envelope, IDENTITY)).toThrow(VaultOpenError);
  });
});

/* ─── 3. key_origin DB-write flip (B1-smuggle tripwire) ──────────────────── */

describe("attack suite — key_origin DB-write flip (vector 3)", () => {
  it("pubkey unchanged, AAD auth breaks when key_origin is smuggled", async () => {
    const store = new InMemoryVaultStore();
    const auditLog = new InMemoryVaultAccessAuditLog();
    const service = new EncryptedWalletKeyStore({ rootKey: ROOT_KEY, store, auditLog });
    await service.seal(IDENTITY, TEST_SECRET_KEY);

    // Attacker flips only key_origin on the authoritative open path (DB column smuggle).
    // Ciphertext and public_key are untouched — pure B1 tripwire.
    const smuggled: WalletIdentity = { ...IDENTITY, keyOrigin: "imported" };
    await expect(service.open(smuggled, "signing")).rejects.toThrow(VaultOpenError);
    expect(auditLog.entries.at(-1)?.outcome).toBe("AUTH_TAG_FAILURE");
  });
});

/* ─── 4. Non-canonical pubkey + public/private mismatch on decrypt ──────── */

describe("attack suite — non-canonical pubkey and substitution (vector 4)", () => {
  it("non-canonical / unpadded public key fails closed before decrypt", () => {
    const envelope = sealWalletSecret(ROOT_KEY, IDENTITY, TEST_SECRET_KEY);
    // Drop the padding `=` — still base64url alphabet but not the canonical padded form.
    const unpadded = IDENTITY.publicKey.replace(/=+$/, "");
    expect(unpadded).not.toBe(IDENTITY.publicKey);
    const bad: WalletIdentity = { ...IDENTITY, publicKey: unpadded };
    expect(() => openWalletSecret(ROOT_KEY, envelope, bad)).toThrow(VaultOpenError);
    try {
      openWalletSecret(ROOT_KEY, envelope, bad);
    } catch (error) {
      expect((error as VaultOpenError).code).toBe("NON_CANONICAL_PUBLIC_KEY");
    }
  });

  it("public/private mismatch after decrypt fails closed (substitution control)", () => {
    // Craft ciphertext of OTHER.secret under DEK+AAD for IDENTITY (which claims TEST_PUBLIC_KEY).
    // Bypass seal()'s match check so open reaches the post-decrypt derive-pubkey assert.
    const dek = deriveWalletDek(ROOT_KEY, IDENTITY);
    const aad = Buffer.from(buildWalletSecretAad(IDENTITY), "utf8");
    const nonce = Buffer.alloc(NONCE_LENGTH_BYTES, 7);
    const cipher = createCipheriv("aes-256-gcm", dek, nonce);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(OTHER.secretKey), cipher.final()]);
    const authTag = cipher.getAuthTag();
    expect(authTag.length).toBe(AUTH_TAG_LENGTH_BYTES);

    const forged: SealedEnvelope = {
      walletId: IDENTITY.walletId,
      keyVersion: IDENTITY.keyVersion,
      ciphertext,
      nonce,
      authTag,
      ciphertextSha256: sha256HexBytes(ciphertext),
    };

    expect(() => openWalletSecret(ROOT_KEY, forged, IDENTITY)).toThrow(VaultOpenError);
    try {
      openWalletSecret(ROOT_KEY, forged, IDENTITY);
    } catch (error) {
      expect((error as VaultOpenError).code).toBe("PUBLIC_KEY_MISMATCH");
    }
    // Control: the forged secret really is OTHER, not TEST.
    expect(deriveEd25519PublicKeyBase64Url(OTHER.secretKey)).toBe(OTHER.publicKey);
    expect(OTHER.publicKey).not.toBe(TEST_PUBLIC_KEY);
  });
});

/* ─── 5. wallet_active_leases mismatches ─────────────────────────────────── */

describe("attack suite — lease mismatches (vector 5)", () => {
  it("wrong wallet_id on the lease row is rejected", async () => {
    const { boundary, auditEntries, vaultSigner } = makeBoundary(
      makeLease({ walletId: "wallet-OTHER" }),
    );
    await expect(boundary.sign(makeCapability())).rejects.toMatchObject({
      code: "WALLET_MISMATCH",
    });
    expect(vaultSigner.sign).not.toHaveBeenCalled();
    expect(auditEntries[0].outcome).toBe("REJECTED");
  });

  it("wrong operation_id is rejected", async () => {
    const { boundary, vaultSigner } = makeBoundary(makeLease({ operationId: "op-OTHER" }));
    await expect(boundary.sign(makeCapability())).rejects.toMatchObject({
      code: "OPERATION_MISMATCH",
    });
    expect(vaultSigner.sign).not.toHaveBeenCalled();
  });

  it("stale / wrong lease_epoch is rejected", async () => {
    const { boundary, vaultSigner } = makeBoundary(makeLease({ epoch: 99n }));
    await expect(boundary.sign(makeCapability({ leaseEpoch: 1n }))).rejects.toMatchObject({
      code: "EPOCH_MISMATCH",
    });
    expect(vaultSigner.sign).not.toHaveBeenCalled();
  });

  it("wrong lease_role (non-signing) is rejected", async () => {
    const { boundary, vaultSigner } = makeBoundary(makeLease({ role: "MOVE_DESTINATION" }));
    await expect(boundary.sign(makeCapability())).rejects.toMatchObject({
      code: "ROLE_NOT_PERMITTED",
    });
    expect(vaultSigner.sign).not.toHaveBeenCalled();
  });

  it("no current lease row at all is rejected", async () => {
    const { boundary, vaultSigner } = makeBoundary(null);
    await expect(boundary.sign(makeCapability())).rejects.toMatchObject({ code: "NO_LEASE" });
    expect(vaultSigner.sign).not.toHaveBeenCalled();
  });
});

/* ─── 6. Wrong purpose literal; purpose-before-signature ─────────────────── */

describe("attack suite — purpose exact literal (vector 6)", () => {
  it.each([
    "SPLITCHAIN_STEP_1 ", // trailing space
    "splitchain_step_1", // case fold
    "SPLITCHAIN_STEP_3", // unknown step
    "zp-recovery-verification-v1", // recovery-lane purpose on money path
    "SPLITCHAIN_STEP_1\n", // newline smuggle
    "", // empty
  ])("rejects non-literal purpose %j before the vault", async (badPurpose) => {
    const { boundary, auditEntries, vaultSigner, leaseReader } = makeBoundary(makeLease());
    await expect(
      boundary.sign(makeCapability({ purpose: badPurpose as WalletSigningCapability["purpose"] })),
    ).rejects.toBeInstanceOf(UnknownSigningPurposeError);
    // Distinguishing branch: purpose gate, not lease / preimage / vault.
    expect(vaultSigner.sign).not.toHaveBeenCalled();
    expect(leaseReader.readActiveLease).not.toHaveBeenCalled();
    expect(auditEntries).toHaveLength(0);
  });

  it("accepts both exact money-path purpose literals and no other", async () => {
    // Each SplitChain step is presented under the lease role that owns it: an
    // originating role for step 1, a receiving role for step 2. This vector is about the
    // purpose literal, so it must not also be exercising a cross-step role.
    for (const [purpose, role] of [
      ["SPLITCHAIN_STEP_1", "SEND_SOURCE"],
      ["SPLITCHAIN_STEP_2", "RECEIVE_WINDOW"],
    ] as const) {
      const { boundary, vaultSigner } = makeBoundary(makeLease({ role }));
      await expect(boundary.sign(makeCapability({ purpose }))).resolves.toMatchObject({
        signature: "c2lnbmF0dXJlLWJ5dGVz",
      });
      expect(vaultSigner.sign).toHaveBeenCalledTimes(1);
    }
  });

  it("purpose comparison runs before signature verification (valid lease, bad purpose)", async () => {
    let vaultReached = false;
    const { boundary } = makeBoundary(makeLease(), {
      vaultSigner: {
        sign: async () => {
          vaultReached = true;
          return "should-not-sign";
        },
      },
    });
    await expect(
      boundary.sign(
        makeCapability({ purpose: "NOT_A_PURPOSE" as WalletSigningCapability["purpose"] }),
      ),
    ).rejects.toBeInstanceOf(UnknownSigningPurposeError);
    expect(vaultReached).toBe(false);
  });
});

/* ─── 7. No signer-leadership lock ───────────────────────────────────────── */

describe("attack suite — no signer leadership (vector 7)", () => {
  it("refuses when readiness / leadership latch is not held", async () => {
    const { boundary, vaultSigner, leaseReader, auditEntries } = makeBoundary(makeLease(), {
      leadership: { held: false, reason: "not leader" },
    });
    await expect(boundary.sign(makeCapability())).rejects.toBeInstanceOf(NotSignerLeaderError);
    expect(vaultSigner.sign).not.toHaveBeenCalled();
    expect(leaseReader.readActiveLease).not.toHaveBeenCalled();
    expect(auditEntries).toHaveLength(0);
  });
});

/* ─── 8. Arbitrary caller-supplied preimage (exit criterion) ─────── */

describe("attack suite — arbitrary preimage cannot be signed (vector 8)", () => {
  it("rejects when expectedPreimageSha256 does not match preimageText bytes", async () => {
    const { boundary, vaultSigner, auditEntries } = makeBoundary(makeLease());
    const forged = makeCapability({
      preimageText: '{"attacker":"controlled","amount":"999999"}',
      expectedPreimageSha256: sha256HexText('{"honest":"persisted-preimage"}'),
    });
    let caught: unknown;
    try {
      await boundary.sign(forged);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(SignerBoundaryError);
    expect(caught).toMatchObject({ code: "PREIMAGE_DIGEST_MISMATCH" });
    expect(vaultSigner.sign).not.toHaveBeenCalled();
    expect(auditEntries).toHaveLength(1);
    expect(auditEntries[0].outcome).toBe("REJECTED");
    expect(auditEntries[0].rejectionReason).toBe("preimage digest mismatch");
  });

  it("end-to-end: vault-backed signer never sees a mismatched preimage", async () => {
    const store = new InMemoryVaultStore();
    const auditLog = new InMemoryVaultAccessAuditLog();
    const vault = new EncryptedWalletKeyStore({ rootKey: ROOT_KEY, store, auditLog });
    await vault.seal(IDENTITY, TEST_SECRET_KEY);

    let vaultSignCalls = 0;
    const vaultSigner: VaultSigner = {
      sign: async (walletId, preimageBytes) => {
        vaultSignCalls += 1;
        expect(walletId).toBe(IDENTITY.walletId);
        const secret = await vault.open(IDENTITY, "signing");
        try {
          const seed = Buffer.from(secret.bytes).subarray(0, 32);
          const key = createPrivateKey({
            key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
            format: "der",
            type: "pkcs8",
          });
          return toBase64UrlPadded(edSign(null, Buffer.from(preimageBytes), key));
        } finally {
          secret.wipe();
        }
      },
    };

    const { boundary } = makeBoundary(makeLease({ walletId: IDENTITY.walletId }), { vaultSigner });
    const honestText = '{"step":1,"amount":"1"}';
    const honest = makeCapability({
      walletId: IDENTITY.walletId,
      preimageText: honestText,
      expectedPreimageSha256: sha256HexText(honestText),
    });
    const signed = await boundary.sign(honest);
    expect(signed.preimageSha256).toBe(sha256HexText(honestText));
    expect(vaultSignCalls).toBe(1);

    // Attacker swaps the body but keeps the honest digest claim — rejected before vault open.
    const attack = makeCapability({
      walletId: IDENTITY.walletId,
      preimageText: '{"step":1,"amount":"999999999"}',
      expectedPreimageSha256: sha256HexText(honestText),
    });
    await expect(boundary.sign(attack)).rejects.toMatchObject({
      code: "PREIMAGE_DIGEST_MISMATCH",
    });
    expect(vaultSignCalls).toBe(1);
  });
});

/* ─── 9. Concurrent / racing signer calls ────────────────────────────────── */

describe("attack suite — concurrent signer serialization (vector 9)", () => {
  it("serializes concurrent signs on one wallet — no overlap, no double-sign race, no deadlock", async () => {
    let concurrent = 0;
    let maxConcurrent = 0;
    let signCount = 0;
    const vaultSigner: VaultSigner = {
      sign: async () => {
        concurrent += 1;
        maxConcurrent = Math.max(maxConcurrent, concurrent);
        signCount += 1;
        await new Promise((r) => setTimeout(r, 40));
        concurrent -= 1;
        return `sig-${signCount}`;
      },
    };
    const { boundary } = makeBoundary(makeLease(), { vaultSigner });
    const cap = makeCapability();

    const results = await Promise.all([
      boundary.sign(cap),
      boundary.sign(cap),
      boundary.sign(cap),
    ]);

    expect(maxConcurrent).toBe(1);
    expect(signCount).toBe(3);
    expect(new Set(results.map((r) => r.signature)).size).toBe(3);
  });

  it("a rejected concurrent call does not deadlock the wallet queue", async () => {
    const { boundary, vaultSigner } = makeBoundary(makeLease());
    const good = makeCapability();
    const bad = makeCapability({ expectedPreimageSha256: "0".repeat(64) });

    const outcomes = await Promise.allSettled([
      boundary.sign(bad),
      boundary.sign(good),
      boundary.sign(bad),
      boundary.sign(good),
    ]);

    expect(outcomes.filter((o) => o.status === "fulfilled")).toHaveLength(2);
    expect(outcomes.filter((o) => o.status === "rejected")).toHaveLength(2);
    expect(vaultSigner.sign).toHaveBeenCalledTimes(2);
  });
});

/* ─── 10. Log / DB / error / metric leakage ──────────────────────────────── */

describe("attack suite — secret leakage surfaces (vector 10)", () => {
  it("private-key bytes never appear in vault audit, signer audit, errors, or results", async () => {
    const store = new InMemoryVaultStore();
    const vaultAudit = new InMemoryVaultAccessAuditLog();
    const vault = new EncryptedWalletKeyStore({ rootKey: ROOT_KEY, store, auditLog: vaultAudit });
    await vault.seal(IDENTITY, TEST_SECRET_KEY);

    const secretHex = Buffer.from(TEST_SECRET_KEY).toString("hex");
    const secretB64 = Buffer.from(TEST_SECRET_KEY).toString("base64");
    const secretB64url = Buffer.from(TEST_SECRET_KEY).toString("base64url");

    const signerAudit: SignerAuditEntry[] = [];
    const vaultSigner: VaultSigner = {
      sign: async (_walletId, preimageBytes) => {
        const secret = await vault.open(IDENTITY, "signing");
        try {
          const seed = Buffer.from(secret.bytes).subarray(0, 32);
          const key = createPrivateKey({
            key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
            format: "der",
            type: "pkcs8",
          });
          return toBase64UrlPadded(edSign(null, Buffer.from(preimageBytes), key));
        } finally {
          secret.wipe();
        }
      },
    };

    const boundary = new LeaseSignerBoundary({
      leadership: { held: true },
      leaseReader: {
        readActiveLease: async () => makeLease({ walletId: IDENTITY.walletId }),
      },
      vaultSigner,
      auditLog: {
        append: async (e) => {
          signerAudit.push(e);
        },
      },
      now: () => FIXED_TIME,
        assertMoneyAdmitted: () => {},
      assertCanOperate: () => {},
      assertWalletMaySign: async () => {},
  });

    const preimageText = '{"leak-check":true}';
    const result = await boundary.sign(
      makeCapability({
        walletId: IDENTITY.walletId,
        preimageText,
        expectedPreimageSha256: sha256HexText(preimageText),
      }),
    );

    // Force a few fail-closed paths and capture error messages.
    const errorMessages: string[] = [];
    const sealed = await store.findByWalletId(IDENTITY.walletId);
    const attacks: Array<() => Promise<unknown> | unknown> = [
      () =>
        openWalletSecret(ROOT_KEY, sealed!, {
          ...IDENTITY,
          keyOrigin: "imported",
        }),
      () =>
        boundary.sign(
          makeCapability({
            walletId: IDENTITY.walletId,
            expectedPreimageSha256: "0".repeat(64),
          }),
        ),
      () =>
        boundary.sign(
          makeCapability({
            purpose: "bad" as WalletSigningCapability["purpose"],
          }),
        ),
    ];
    for (const attack of attacks) {
      try {
        await attack();
      } catch (error) {
        errorMessages.push(String(error));
        if (error instanceof Error) errorMessages.push(error.message);
      }
    }

    const surfaces = [
      JSON.stringify(vaultAudit.entries),
      JSON.stringify(signerAudit, (_k, v) => (typeof v === "bigint" ? v.toString() : v)),
      JSON.stringify(result),
      ...errorMessages,
      // Persisted vault row: ciphertext only, never plaintext secret.
      JSON.stringify({
        ...(await store.findByWalletId(IDENTITY.walletId)),
        ciphertext: "omitted",
        nonce: "omitted",
        authTag: "omitted",
      }),
    ].join("\n");

    expect(surfaces).not.toContain(secretHex);
    expect(surfaces).not.toContain(secretB64);
    expect(surfaces).not.toContain(secretB64url);
    // Purpose error must not echo attacker-controlled purpose into the message.
    expect(errorMessages.some((m) => m === "UnknownSigningPurposeError: unknown signing purpose" || m === "unknown signing purpose")).toBe(true);

    // Result shape is signature + digest only.
    expect(Object.keys(result).sort()).toEqual(["preimageSha256", "signature"]);
  });
});

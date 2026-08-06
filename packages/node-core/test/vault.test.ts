import {
  createCipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  randomBytes,
} from "node:crypto";

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  AAD_GOLDEN as FROZEN_AAD_GOLDEN,
  HKDF_INFO_GOLDEN as FROZEN_HKDF_INFO_GOLDEN,
  buildWalletDekInfo as frozenBuildWalletDekInfo,
  buildWalletSecretAad as frozenBuildWalletSecretAad,
} from "@zucoins/generic-node-contracts/vault";

import {
  AAD_GOLDEN,
  AUTH_TAG_LENGTH_BYTES,
  buildWalletDekInfo,
  buildWalletSecretAad,
  DEK_LENGTH_BYTES,
  ED25519_SECRET_KEY_BYTES,
  deriveEd25519PublicKeyBase64Url,
  deriveRootKey,
  EncryptedWalletKeyStore,
  HKDF_INFO_GOLDEN,
  InMemoryVaultAccessAuditLog,
  InMemoryVaultStore,
  keyMaterialHygiene,
  NONCE_LENGTH_BYTES,
  openWalletSecret,
  sealWalletSecret,
  toBase64UrlPadded,
  VaultOpenError,
  VaultRecordNotFoundError,
  VaultSealError,
  type KeyMaterialWipeRole,
  type VaultAccessAuditLog,
  type WalletIdentity,
} from "../src/vault/index.js";

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

// Deterministic test keypair: 32-byte seed → 64-byte libsodium-format secret (seed || pubkey).
// Generated once with node:crypto generateKeyPairSync("ed25519") and hardcoded for repeatability.
const TEST_SEED = Buffer.from("a".repeat(64), "hex"); // 32 bytes of 0xaa

function makeTestSecretKey(): { secretKey: Buffer; publicKey: string } {
  const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, TEST_SEED]),
    format: "der",
    type: "pkcs8",
  });
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const rawPub = Buffer.from(spki).subarray(-32);
  const publicKey = toBase64UrlPadded(rawPub);
  const secretKey = Buffer.concat([TEST_SEED, rawPub]);
  return { secretKey, publicKey };
}

const { secretKey: TEST_SECRET_KEY, publicKey: TEST_PUBLIC_KEY } = makeTestSecretKey();

const IDENTITY: WalletIdentity = {
  nodeId: "11111111-1111-4111-8111-111111111111",
  walletId: "22222222-2222-4222-8222-222222222222",
  keyVersion: 1,
  publicKey: TEST_PUBLIC_KEY,
  keyOrigin: "node_generated",
};

const MASTER_KEY = Buffer.from("test-master-key-for-vault-tests!");
const SALT = Buffer.from("test-salt-16bytes");

describe("vault serialization", () => {
  it("buildWalletSecretAad reproduces the frozen golden SHA-256", () => {
    const aad = buildWalletSecretAad(AAD_GOLDEN.fields);
    expect(sha256Hex(Buffer.from(aad, "utf8"))).toBe(AAD_GOLDEN.aadSha256);
    // Pin must come from the frozen package, not a local re-declaration (AC6).
    expect(AAD_GOLDEN.aadSha256).toBe(FROZEN_AAD_GOLDEN.aad_sha256);
  });

  it("buildWalletDekInfo reproduces the frozen golden SHA-256", () => {
    const info = buildWalletDekInfo(HKDF_INFO_GOLDEN.fields);
    expect(sha256Hex(Buffer.from(info, "utf8"))).toBe(HKDF_INFO_GOLDEN.infoSha256);
    expect(HKDF_INFO_GOLDEN.infoSha256).toBe(FROZEN_HKDF_INFO_GOLDEN.info_sha256);
  });

  it("node-core adapters are byte-identical to the frozen contracts builders", () => {
    // Cross-package identity: a local reimplementation could keep the self-referential
    // golden green while drifting from. Comparing both builders' bytes closes that.
    const aad = buildWalletSecretAad(AAD_GOLDEN.fields);
    const frozenAad = frozenBuildWalletSecretAad(FROZEN_AAD_GOLDEN.inputs);
    expect(aad).toBe(frozenAad);
    expect(aad).toBe(FROZEN_AAD_GOLDEN.aad_text);

    const info = buildWalletDekInfo(HKDF_INFO_GOLDEN.fields);
    const frozenInfo = frozenBuildWalletDekInfo(FROZEN_HKDF_INFO_GOLDEN.inputs);
    expect(info).toBe(frozenInfo);
    expect(info).toBe(FROZEN_HKDF_INFO_GOLDEN.info_text);
  });

  it("toBase64UrlPadded pads to a multiple of four", () => {
    const result = toBase64UrlPadded(Buffer.from([1]));
    expect(result.length % 4).toBe(0);
    expect(result).toContain("=");
  });
});

describe("vault envelope seal/open roundtrip", () => {
  const rootKey = deriveRootKey(MASTER_KEY, SALT);

  it("deriveRootKey produces a 32-byte key", () => {
    expect(rootKey.length).toBe(DEK_LENGTH_BYTES);
  });

  it("seal then open returns the original secret key", () => {
    const envelope = sealWalletSecret(rootKey, IDENTITY, TEST_SECRET_KEY);
    expect(envelope.ciphertext.length).toBe(64);
    expect(envelope.nonce.length).toBe(NONCE_LENGTH_BYTES);
    expect(envelope.authTag.length).toBe(AUTH_TAG_LENGTH_BYTES);

    const opened = openWalletSecret(rootKey, envelope, IDENTITY);
    expect(Buffer.from(opened.bytes)).toEqual(TEST_SECRET_KEY);
    opened.wipe();
    expect(Buffer.from(opened.bytes)).toEqual(Buffer.alloc(64));
  });

  // key_version is the wallet rotation epoch, not the envelope wire format.
  // Rotation reseals at keyVersion+1; open must serve any positive epoch.
  it("seal then open succeeds at keyVersion: 2 (rotation epoch, not format version)", () => {
    const rotated: WalletIdentity = { ...IDENTITY, keyVersion: 2 };
    const envelope = sealWalletSecret(rootKey, rotated, TEST_SECRET_KEY);
    expect(envelope.keyVersion).toBe(2);
    const opened = openWalletSecret(rootKey, envelope, rotated);
    expect(Buffer.from(opened.bytes)).toEqual(TEST_SECRET_KEY);
    opened.wipe();
  });

  it("seal produces unique nonces per call", () => {
    const e1 = sealWalletSecret(rootKey, IDENTITY, TEST_SECRET_KEY);
    const e2 = sealWalletSecret(rootKey, IDENTITY, TEST_SECRET_KEY);
    expect(Buffer.from(e1.nonce)).not.toEqual(Buffer.from(e2.nonce));
  });

  it("open fails closed with wrong root key", () => {
    const envelope = sealWalletSecret(rootKey, IDENTITY, TEST_SECRET_KEY);
    const wrongRoot = deriveRootKey(Buffer.from("wrong-key"), SALT);
    expect(() => openWalletSecret(wrongRoot, envelope, IDENTITY)).toThrow(VaultOpenError);
  });

  it("open fails closed with tampered ciphertext", () => {
    const envelope = sealWalletSecret(rootKey, IDENTITY, TEST_SECRET_KEY);
    const tampered = { ...envelope, ciphertext: Buffer.from(envelope.ciphertext) };
    tampered.ciphertext[0] ^= 0xff;
    expect(() => openWalletSecret(rootKey, tampered, IDENTITY)).toThrow(VaultOpenError);
  });

  it("open fails closed with wrong wallet identity (AAD mismatch)", () => {
    const envelope = sealWalletSecret(rootKey, IDENTITY, TEST_SECRET_KEY);
    const wrongIdentity: WalletIdentity = {
      ...IDENTITY,
      walletId: "99999999-9999-4999-8999-999999999999",
    };
    expect(() => openWalletSecret(rootKey, envelope, wrongIdentity)).toThrow(VaultOpenError);
  });

  it("seal rejects a secret key that does not match the public key", () => {
    // Different seed → different derived pubkey → mismatch with IDENTITY.publicKey.
    const otherSeed = Buffer.from("b".repeat(64), "hex");
    const otherKey = createPrivateKey({
      key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), otherSeed]),
      format: "der",
      type: "pkcs8",
    });
    const otherSpki = createPublicKey(otherKey).export({ format: "der", type: "spki" });
    const otherSecret = Buffer.concat([otherSeed, Buffer.from(otherSpki).subarray(-32)]);
    expect(() => sealWalletSecret(rootKey, IDENTITY, otherSecret)).toThrow(VaultSealError);
  });

  it("seal rejects non-64-byte input", () => {
    expect(() => sealWalletSecret(rootKey, IDENTITY, Buffer.alloc(32))).toThrow(VaultSealError);
  });

  it("deriveEd25519PublicKeyBase64Url returns null for malformed input", () => {
    expect(deriveEd25519PublicKeyBase64Url(Buffer.alloc(10))).toBeNull();
  });
});

// Option A — prove temporary-key zeroization via role-tagged wipe
// obligations + path-exit residual on production-owned state. Forbidden:
// harness Buffer identity pins (wipedRefs.has / first-pin concat / list[0]===gcmUpdate /
// first derive-arg) and decoy-satisfiable asserts (correct-role wipe of Buffer.from/alloc
// while real owned stays live). Mutation bar: drop real wipe, wrong role, OR correct-role
// decoy/orphan → red; unmutated green.
describe("vault envelope key-material zeroization", () => {
  const rootKey = deriveRootKey(MASTER_KEY, SALT);

  afterEach(() => {
    vi.restoreAllMocks();
  });

  /**
   * Spy production wipe entry point. Records roles + pre-wipe content snapshots.
   * Delegates to real `zeroize` so brand check + liveOwnedCount residual stay enforced
   * (a plain Buffer decoy under the correct role throws / leaves residual ≠ 0).
   * No identity pins (no wipedRefs.has / SameValueZero on harness-captured buffers).
   */
  function installWipeSpy() {
    const roles = new Set<KeyMaterialWipeRole>();
    const byRole = new Map<KeyMaterialWipeRole, Uint8Array[]>();
    // Path-relative residual baseline (avoids cross-test pollution from abandoned SecureBuffers).
    const residualBaseline = keyMaterialHygiene.liveOwnedCount();
    const realZeroize = keyMaterialHygiene.zeroize.bind(keyMaterialHygiene);
    const spy = vi.spyOn(keyMaterialHygiene, "zeroize").mockImplementation((buf, role) => {
      // Snapshot before the real wipe zeroes + unbrands.
      const snap = Buffer.from(buf);
      const list = byRole.get(role) ?? [];
      list.push(snap);
      byRole.set(role, list);
      // Real zeroize: brand check + fill(0) + liveOwnedCount--. Decy Buffer → TypeError.
      realZeroize(buf, role);
      roles.add(role);
    });
    return {
      spy,
      roles,
      byRole,
      /** Assert every required role fired (set containment — order-independent). */
      expectObligations(required: readonly KeyMaterialWipeRole[]) {
        for (const role of required) {
          expect(roles.has(role), `missing wipe obligation role: ${role}`).toBe(true);
        }
      },
      /**
       * Path-exit residual on production-owned state (delta since spy install).
       * Not an identity pin: scalar residual only. Correct-role decoy / GCM orphan → residual
       * above expected (M5/M5b/M6).
       */
      expectPathExitResidual(expectedDelta: number) {
        const delta = keyMaterialHygiene.liveOwnedCount() - residualBaseline;
        expect(
          delta,
          `path-exit liveOwned residual delta expected ${expectedDelta} (decoy/orphan leaves residual)`,
        ).toBe(expectedDelta);
      },
    };
  }

  function forgePublicKeyMismatchEnvelope(): {
    walletId: string;
    keyVersion: number;
    ciphertext: Buffer;
    nonce: Buffer;
    authTag: Buffer;
    ciphertextSha256: string;
  } {
    // Ciphertext of a wrong 64-byte secret under the correct DEK+AAD so GCM authenticates
    // but the primary substitution control (derive-pubkey) fails.
    const info = buildWalletDekInfo({
      nodeId: IDENTITY.nodeId,
      walletId: IDENTITY.walletId,
      keyVersion: IDENTITY.keyVersion,
    });
    const dek = Buffer.from(
      hkdfSync("sha256", Buffer.from(rootKey), Buffer.alloc(0), Buffer.from(info, "utf8"), 32),
    );
    const wrongSecret = Buffer.alloc(64, 0x55);
    const aad = Buffer.from(buildWalletSecretAad(IDENTITY), "utf8");
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", dek, nonce);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(wrongSecret), cipher.final()]);
    const authTag = cipher.getAuthTag();
    dek.fill(0);
    return {
      walletId: IDENTITY.walletId,
      keyVersion: IDENTITY.keyVersion,
      ciphertext,
      nonce,
      authTag,
      ciphertextSha256: "00",
    };
  }

  it("sealWalletSecret fires dek + seal_plaintext + seed + pkcs8 obligations", () => {
    const wipe = installWipeSpy();
    const envelope = sealWalletSecret(rootKey, IDENTITY, TEST_SECRET_KEY);
    expect(envelope.ciphertext.length).toBe(64);

    // assertSealInputs → derive wipes seed+pkcs8; seal body wipes dek + owned plaintext copy.
    wipe.expectObligations(["dek", "seal_plaintext", "seed", "pkcs8"]);
    wipe.expectPathExitResidual(0);

    const dekSnaps = wipe.byRole.get("dek")!;
    expect(dekSnaps.some((b) => b.length === DEK_LENGTH_BYTES && b.some((x) => x !== 0))).toBe(true);
    const plainSnaps = wipe.byRole.get("seal_plaintext")!;
    expect(plainSnaps.some((b) => Buffer.from(b).equals(TEST_SECRET_KEY))).toBe(true);
    // Caller-owned secret input is intentionally untouched.
    expect(TEST_SECRET_KEY.some((byte) => byte !== 0)).toBe(true);
    expect(wipe.spy).toHaveBeenCalled();
  });

  it("openWalletSecret success fires dek + gcm_update + seed + pkcs8; secure_buffer on wipe", () => {
    const envelope = sealWalletSecret(rootKey, IDENTITY, TEST_SECRET_KEY);
    const wipe = installWipeSpy();

    const opened = openWalletSecret(rootKey, envelope, IDENTITY);
    // Success: DEK + GCM update intermediate + pubkey-derive scratch; assembled plaintext
    // ownership transfers to SecureBuffer (no failure_plaintext). Residual 1 = released secret.
    wipe.expectObligations(["dek", "gcm_update", "seed", "pkcs8"]);
    expect(wipe.roles.has("failure_plaintext")).toBe(false);
    expect(wipe.roles.has("secure_buffer")).toBe(false);
    expect(Buffer.from(opened.bytes)).toEqual(TEST_SECRET_KEY);
    wipe.expectPathExitResidual(1);
    // Production-owned transferred secret still holds real bytes (byte post-condition).
    expect(Buffer.from(opened.bytes).every((b) => b === 0)).toBe(false);

    const gcmSnaps = wipe.byRole.get("gcm_update")!;
    expect(gcmSnaps.some((b) => b.length === ED25519_SECRET_KEY_BYTES && Buffer.from(b).equals(TEST_SECRET_KEY))).toBe(
      true,
    );

    opened.wipe();
    expect(Buffer.from(opened.bytes)).toEqual(Buffer.alloc(64));
    // Byte post-condition on production-owned transferred buffer after wipe.
    expect(Buffer.from(opened.bytes).every((b) => b === 0)).toBe(true);
    wipe.expectObligations(["dek", "gcm_update", "seed", "pkcs8", "secure_buffer"]);
    wipe.expectPathExitResidual(0);
    const released = wipe.byRole.get("secure_buffer")!;
    expect(released.some((b) => b.length === ED25519_SECRET_KEY_BYTES && Buffer.from(b).equals(TEST_SECRET_KEY))).toBe(
      true,
    );
  });

  it("openWalletSecret AUTH_TAG_FAILURE fires dek + gcm_update (no failure_plaintext)", () => {
    const envelope = sealWalletSecret(rootKey, IDENTITY, TEST_SECRET_KEY);
    const tampered = { ...envelope, ciphertext: Buffer.from(envelope.ciphertext) };
    tampered.ciphertext[0] ^= 0xff;

    const wipe = installWipeSpy();
    let thrown: unknown;
    try {
      openWalletSecret(rootKey, tampered, IDENTITY);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(VaultOpenError);
    expect((thrown as VaultOpenError).code).toBe("AUTH_TAG_FAILURE");

    // final() fails before assembled plaintext exists → gcm_update + dek only (no seed/pkcs8).
    wipe.expectObligations(["dek", "gcm_update"]);
    expect(wipe.roles.has("failure_plaintext")).toBe(false);
    expect(wipe.roles.has("secure_buffer")).toBe(false);
    // Path-exit residual 0: real GCM intermediate must have been wiped (M6 orphan → residual 1).
    wipe.expectPathExitResidual(0);

    const gcmSnaps = wipe.byRole.get("gcm_update")!;
    expect(gcmSnaps.length).toBeGreaterThanOrEqual(1);
    // Intermediate held nonzero bytes; not authenticated true secret (tag failed).
    expect(gcmSnaps.some((b) => b.length === ED25519_SECRET_KEY_BYTES && b.some((x) => x !== 0))).toBe(true);
    expect(gcmSnaps.every((b) => !Buffer.from(b).equals(TEST_SECRET_KEY))).toBe(true);
    expect(wipe.spy).toHaveBeenCalled();
  });

  it("openWalletSecret PUBLIC_KEY_MISMATCH fires dek + gcm_update + failure_plaintext + seed + pkcs8", () => {
    const forged = forgePublicKeyMismatchEnvelope();
    const wipe = installWipeSpy();

    try {
      openWalletSecret(rootKey, forged, IDENTITY);
      expect.unreachable("expected PUBLIC_KEY_MISMATCH");
    } catch (err) {
      expect(err).toBeInstanceOf(VaultOpenError);
      expect((err as VaultOpenError).code).toBe("PUBLIC_KEY_MISMATCH");
    }

    // GCM succeeds (update intermediate wiped after concat), assemble → derive seed/pkcs8,
    // then failure_plaintext + dek on the exception path.
    wipe.expectObligations(["dek", "gcm_update", "failure_plaintext", "seed", "pkcs8"]);
    expect(wipe.roles.has("secure_buffer")).toBe(false);
    // Path-exit residual 0: M5/M5b correct-role decoy leaves assembled plaintext residual.
    wipe.expectPathExitResidual(0);

    const plainSnaps = wipe.byRole.get("failure_plaintext")!;
    expect(plainSnaps.some((b) => b.length === 64 && b.every((x) => x === 0x55))).toBe(true);
    expect(wipe.spy).toHaveBeenCalled();
  });

  it("deriveEd25519PublicKeyBase64Url fires seed + pkcs8 on success and garbage input", () => {
    const wipe = installWipeSpy();

    const pub = deriveEd25519PublicKeyBase64Url(TEST_SECRET_KEY);
    expect(pub).toBe(TEST_PUBLIC_KEY);
    wipe.expectObligations(["seed", "pkcs8"]);
    wipe.expectPathExitResidual(0);
    expect(wipe.byRole.get("seed")!.some((b) => b.length === 32)).toBe(true);
    expect(wipe.byRole.get("pkcs8")!.some((b) => b.length === 48)).toBe(true);

    wipe.roles.clear();
    wipe.byRole.clear();
    // Malformed length returns null before allocating seed — no wipe needed.
    expect(deriveEd25519PublicKeyBase64Url(Buffer.alloc(10))).toBeNull();
    expect(wipe.roles.size).toBe(0);
    wipe.expectPathExitResidual(0);

    // 64-byte garbage still builds seed+pkcs8 then finally wipes.
    deriveEd25519PublicKeyBase64Url(Buffer.alloc(64, 0x01));
    wipe.expectObligations(["seed", "pkcs8"]);
    wipe.expectPathExitResidual(0);
  });

  it("zeroize rejects plain Buffer decoy (brand check — shape 3)", () => {
    // Correct role + content-matched decoy cannot discharge an obligation.
    expect(() => keyMaterialHygiene.zeroize(Buffer.alloc(64, 0x55), "failure_plaintext")).toThrow(
      /not module-owned/,
    );
    expect(() => keyMaterialHygiene.zeroize(Buffer.from(TEST_SECRET_KEY), "seal_plaintext")).toThrow(
      /not module-owned/,
    );
  });

  it("deriveRootKey does not wipe caller-owned master key input", () => {
    const master = Buffer.from("caller-owned-master-key-material!!");
    const before = Buffer.from(master);
    const spy = vi.spyOn(keyMaterialHygiene, "zeroize");
    deriveRootKey(master, SALT);
    expect(master.equals(before)).toBe(true);
    // Root derivation intentionally does not call the hygiene hook on master input.
    expect(spy).not.toHaveBeenCalled();
    expect(keyMaterialHygiene.liveOwnedCount()).toBe(0);
  });
});

describe("EncryptedWalletKeyStore", () => {
  function makeStore() {
    const rootKey = deriveRootKey(MASTER_KEY, SALT);
    const store = new InMemoryVaultStore();
    const auditLog = new InMemoryVaultAccessAuditLog();
    const service = new EncryptedWalletKeyStore({ rootKey, store, auditLog });
    return { service, store, auditLog, rootKey };
  }

  it("seal persists and open retrieves the secret", async () => {
    const { service, auditLog } = makeStore();
    await service.seal(IDENTITY, TEST_SECRET_KEY);
    const opened = await service.open(IDENTITY, "signing");
    expect(Buffer.from(opened.bytes)).toEqual(TEST_SECRET_KEY);
    opened.wipe();

    expect(auditLog.entries).toHaveLength(1);
    expect(auditLog.entries[0].outcome).toBe("OPEN_OK");
    expect(auditLog.entries[0].purpose).toBe("signing");
  });

  it("seal rejects duplicate wallet", async () => {
    const { service } = makeStore();
    await service.seal(IDENTITY, TEST_SECRET_KEY);
    await expect(service.seal(IDENTITY, TEST_SECRET_KEY)).rejects.toThrow("already exists");
  });

  it("open records NOT_FOUND audit entry for missing wallet", async () => {
    const { service, auditLog } = makeStore();
    await expect(service.open(IDENTITY, "signing")).rejects.toThrow("no vault row");
    expect(auditLog.entries).toHaveLength(1);
    expect(auditLog.entries[0].outcome).toBe("NOT_FOUND");
  });

  it("open records failure code on auth tag mismatch", async () => {
    const { service, store, auditLog } = makeStore();
    await service.seal(IDENTITY, TEST_SECRET_KEY);

    // Corrupt the stored ciphertext to trigger auth failure.
    const record = await store.findByWalletId(IDENTITY.walletId);
    const corrupted = { ...record!, ciphertext: Buffer.from(record!.ciphertext) };
    corrupted.ciphertext[0] ^= 0xff;
    await store.update(corrupted);

    await expect(service.open(IDENTITY, "signing")).rejects.toThrow(VaultOpenError);
    expect(auditLog.entries).toHaveLength(1);
    expect(auditLog.entries[0].outcome).toBe("AUTH_TAG_FAILURE");
  });

  it("wipes decrypted plaintext exactly once when the durable OPEN_OK audit rejects", async () => {
    const rootKey = deriveRootKey(MASTER_KEY, SALT);
    const store = new InMemoryVaultStore();
    const auditFailure = new Error("audit unavailable");
    const service = new EncryptedWalletKeyStore({
      rootKey,
      store,
      auditLog: { record: async () => { throw auditFailure; } },
    });
    await service.seal(IDENTITY, TEST_SECRET_KEY);
    const before = keyMaterialHygiene.liveOwnedCount();
    const zeroize = vi.spyOn(keyMaterialHygiene, "zeroize");
    await expect(service.open(IDENTITY, "signing")).rejects.toBe(auditFailure);
    expect(keyMaterialHygiene.liveOwnedCount()).toBe(before);
    expect(zeroize.mock.calls.filter(([, role]) => role === "secure_buffer")).toHaveLength(1);
  });

  it("rotate reseals under a new root key and verifies roundtrip", async () => {
    const { service } = makeStore();
    await service.seal(IDENTITY, TEST_SECRET_KEY);

    const newRootKey = deriveRootKey(Buffer.from("new-master-key-32bytes-long!!!!!"), SALT);
    const rotated = await service.rotate(IDENTITY, newRootKey);
    expect(rotated.rotatedAt).not.toBeNull();

    const opened = openWalletSecret(newRootKey, rotated, IDENTITY);
    expect(Buffer.from(opened.bytes)).toEqual(TEST_SECRET_KEY);
    opened.wipe();
  });

  it("wipes the decrypted secret when the post-decrypt OPEN_OK audit write rejects", async () => {
    const { service, rootKey, store } = makeStore();
    await service.seal(IDENTITY, TEST_SECRET_KEY);
    const baseline = keyMaterialHygiene.liveOwnedCount();

    const failingAuditLog: VaultAccessAuditLog = {
      record: () => Promise.reject(new Error("audit sink unavailable")),
    };
    const auditedService = new EncryptedWalletKeyStore({ rootKey, store, auditLog: failingAuditLog });

    await expect(auditedService.open(IDENTITY, "signing")).rejects.toThrow("audit sink unavailable");
    // The audit failure, not a synthetic wipe error, must be what the caller sees, and the
    // SecureBuffer this caller never received must not remain live.
    expect(keyMaterialHygiene.liveOwnedCount()).toBe(baseline);
  });

  it("rejects with VaultRecordNotFoundError, not the audit rejection, for a missing row (D1)", async () => {
    const { rootKey, store } = makeStore();
    const failingAuditLog: VaultAccessAuditLog = {
      record: () => Promise.reject(new Error("audit sink unavailable")),
    };
    const auditedService = new EncryptedWalletKeyStore({ rootKey, store, auditLog: failingAuditLog });

    const rejection: unknown = await auditedService.open(IDENTITY, "signing").catch((err) => err);
    expect(rejection).toBeInstanceOf(VaultRecordNotFoundError);
    // The swallowed audit rejection must still be traceable via .cause, not silently dropped.
    expect((rejection as Error).cause).toBeInstanceOf(Error);
    expect(((rejection as Error).cause as Error).message).toBe("audit sink unavailable");
  });

  it("rejects with VaultOpenError, not the audit rejection, for a corrupt envelope (D1)", async () => {
    const { service, rootKey, store } = makeStore();
    await service.seal(IDENTITY, TEST_SECRET_KEY);

    const record = await store.findByWalletId(IDENTITY.walletId);
    const corrupted = { ...record!, ciphertext: Buffer.from(record!.ciphertext) };
    corrupted.ciphertext[0] ^= 0xff;
    await store.update(corrupted);

    const failingAuditLog: VaultAccessAuditLog = {
      record: () => Promise.reject(new Error("audit sink unavailable")),
    };
    const auditedService = new EncryptedWalletKeyStore({ rootKey, store, auditLog: failingAuditLog });

    const rejection: unknown = await auditedService.open(IDENTITY, "signing").catch((err) => err);
    expect(rejection).toBeInstanceOf(VaultOpenError);
    expect((rejection as Error).cause).toBeInstanceOf(Error);
    expect(((rejection as Error).cause as Error).message).toBe("audit sink unavailable");
  });

  it("rejects with VaultRecordNotFoundError when record throws synchronously", async () => {
    const { rootKey, store } = makeStore();
    const syncThrowLog: VaultAccessAuditLog = {
      record(): never {
        throw new Error("audit adapter sync failure");
      },
    };
    const auditedService = new EncryptedWalletKeyStore({ rootKey, store, auditLog: syncThrowLog });

    const rejection: unknown = await auditedService.open(IDENTITY, "signing").catch((err) => err);
    expect(rejection).toBeInstanceOf(VaultRecordNotFoundError);
    expect((rejection as Error).cause).toBeInstanceOf(Error);
    expect(((rejection as Error).cause as Error).message).toBe("audit adapter sync failure");
  });

  it("rejects with VaultOpenError when record throws synchronously on corrupt envelope", async () => {
    const { service, rootKey, store } = makeStore();
    await service.seal(IDENTITY, TEST_SECRET_KEY);

    const record = await store.findByWalletId(IDENTITY.walletId);
    const corrupted = { ...record!, ciphertext: Buffer.from(record!.ciphertext) };
    corrupted.ciphertext[0] ^= 0xff;
    await store.update(corrupted);

    const syncThrowLog: VaultAccessAuditLog = {
      record(): never {
        throw new Error("audit adapter sync failure");
      },
    };
    const auditedService = new EncryptedWalletKeyStore({ rootKey, store, auditLog: syncThrowLog });

    const rejection: unknown = await auditedService.open(IDENTITY, "signing").catch((err) => err);
    expect(rejection).toBeInstanceOf(VaultOpenError);
    expect((rejection as Error).cause).toBeInstanceOf(Error);
    expect(((rejection as Error).cause as Error).message).toBe("audit adapter sync failure");
  });

  // `async recordAccess` converts a sync adapter throw into a rejected promise at
  // the seam. Without `async`, the call throws before any `.then`/`.catch` can attach — the
  // open() try/catch belt still catches that today, so this probes the private method
  // directly and fails if the keyword is dropped again.
  it("recordAccess turns a synchronous adapter throw into a rejected promise", async () => {
    const syncThrowLog: VaultAccessAuditLog = {
      record(): never {
        throw new Error("audit adapter sync failure");
      },
    };
    const service = new EncryptedWalletKeyStore({
      rootKey: deriveRootKey(Buffer.from("record-access-async-key!!!!!!!!!!!"), SALT),
      store: new InMemoryVaultStore(),
      auditLog: syncThrowLog,
    });
    // Private seam — accessed only to pin the async conversion contract.
    const recordAccess = (
      service as unknown as {
        recordAccess: (
          walletId: string,
          keyVersion: number,
          purpose: string,
          outcome: "OPEN_OK",
        ) => Promise<void>;
      }
    ).recordAccess.bind(service);

    let threwSynchronously = false;
    let returned: Promise<void> | undefined;
    try {
      returned = recordAccess(IDENTITY.walletId, IDENTITY.keyVersion, "signing", "OPEN_OK");
    } catch {
      threwSynchronously = true;
    }
    expect(threwSynchronously).toBe(false);
    expect(returned).toBeInstanceOf(Promise);
    await expect(returned).rejects.toThrow("audit adapter sync failure");
  });

  it("audit log never contains key material", async () => {
    const { service, auditLog } = makeStore();
    await service.seal(IDENTITY, TEST_SECRET_KEY);
    await service.open(IDENTITY, "signing");

    for (const entry of auditLog.entries) {
      const serialized = JSON.stringify(entry);
      expect(serialized).not.toContain(TEST_SECRET_KEY.toString("base64"));
      expect(serialized).not.toContain(TEST_SECRET_KEY.toString("hex"));
    }
  });
});

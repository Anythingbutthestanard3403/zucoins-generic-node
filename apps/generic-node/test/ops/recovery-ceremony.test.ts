// Full restore ceremony composition (no light/fake stamp path).
// Seals real vault envelopes, builds a real archive, runs runRestoreRecoveryCeremony
// through throwaway RestoredInstance + RestoredVaultAccess + createSqlRecoveryLiveDatabase.

import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
} from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  BACKUP_COVERAGE_TABLES,
  buildBackupArchive,
  createSqlRecoveryLiveDatabase,
  deriveRootKey,
  EncryptedWalletKeyStore,
  InMemoryVaultAccessAuditLog,
  InMemoryVaultStore,
  RECOVERY_STAMP_SQL,
  runRestoreRecoveryCeremony,
  sealWalletSecret,
  toBase64UrlPadded,
  type BackupSnapshot,
  type RecoveryStampInput,
} from "@zucoins/node-core";

import { publicKeyFromSeed, signWithSecret64, signWithSeed } from "../../src/ops/ed25519-ops.js";
import {
  createRestoredVaultAccess,
  createThrowawayRestoredInstance,
} from "../../src/ops/restored-instance.js";
import { composeRestoreRecoveryCeremony } from "../../src/ops/run-recovery-ceremony.js";

const NODE_ID = "00000000-0000-4000-8000-000000000905";
const WALLET_A = "00000000-0000-4000-8000-0000000009a1";
const WALLET_B = "00000000-0000-4000-8000-0000000009a2";
const CEREMONY_ID = "00000000-0000-4000-8000-0000000009c1";
const EXPORT_ID = "00000000-0000-4000-8000-0000000009e1";
const ISSUED_AT = "2026-07-29T12:00:00.000Z";
const CEREMONY_NONCE = "d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d9c=";
const MASTER = "ceremony-master-key-32b-min!!!!!!!!!!!!!!!!";
const VAULT_ROOT_KDF_SALT = Buffer.from("zupayments-vault-root-kdf-salt-v1", "utf8");

function makeSeed(): Buffer {
  const der = generateKeyPairSync("ed25519").privateKey.export({ format: "der", type: "pkcs8" });
  return Buffer.from(der.subarray(der.length - 32));
}

function secret64FromSeed(seed: Buffer): Buffer {
  const pub = Buffer.from(publicKeyFromSeed(seed), "base64url");
  return Buffer.concat([seed, pub]);
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

interface LiveWallet {
  walletId: string;
  publicKey: string;
  recoveryVerifiedAt: string | null;
  recoveryVerificationId: string | null;
  keyOrigin: string;
  keyVersion: number;
  secret64: Buffer;
  envelope: {
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    authTag: Uint8Array;
    ciphertextSha256: string;
    createdAt: string;
  };
}

function provisionLive(): {
  rootKey: Buffer;
  identitySeed: Buffer;
  wallets: LiveWallet[];
  archiveText: string;
} {
  const rootKey = deriveRootKey(MASTER, VAULT_ROOT_KDF_SALT);
  const identitySeed = makeSeed();
  const wallets: LiveWallet[] = [];

  for (const walletId of [WALLET_A, WALLET_B]) {
    const seed = makeSeed();
    const secret64 = secret64FromSeed(seed);
    const publicKey = publicKeyFromSeed(seed);
    const identity = {
      nodeId: NODE_ID,
      walletId,
      keyVersion: 1,
      publicKey,
      keyOrigin: "node_generated" as const,
    };
    const sealed = sealWalletSecret(rootKey, identity, secret64);
    wallets.push({
      walletId,
      publicKey,
      recoveryVerifiedAt: null,
      recoveryVerificationId: null,
      keyOrigin: "node_generated",
      keyVersion: 1,
      secret64,
      envelope: {
        ciphertext: sealed.ciphertext,
        nonce: sealed.nonce,
        authTag: sealed.authTag,
        ciphertextSha256: sealed.ciphertextSha256,
        createdAt: "2026-07-01T00:00:00.000Z",
      },
    });
  }

  const snapshot: BackupSnapshot = {
    nodeId: NODE_ID,
    exportId: EXPORT_ID,
    exportedAt: "2026-07-29T11:00:00.000Z",
    wallets: wallets.map((w) => ({
      walletId: w.walletId,
      publicKey: w.publicKey,
      keyOrigin: w.keyOrigin,
      keyVersion: w.keyVersion,
      vault: {
        wallet_id: w.walletId,
        key_version: w.keyVersion,
        ciphertext: toBase64UrlPadded(w.envelope.ciphertext),
        nonce: toBase64UrlPadded(w.envelope.nonce),
        auth_tag: toBase64UrlPadded(w.envelope.authTag),
        ciphertext_sha256: w.envelope.ciphertextSha256,
        created_at: w.envelope.createdAt,
        rotated_at: null,
      },
      signer: {
        sign: (preimage) => signWithSecret64(w.secret64, preimage),
      },
    })),
    nodeSigningKeys: [
      {
        signingKeyId: randomUUID(),
        purpose: "NODE_IDENTITY",
        publicKey: publicKeyFromSeed(identitySeed),
        vaultSecretRef: "operator-env/NODE_IDENTITY_SEED",
        sealedCiphertextSha256: sha256Hex(randomBytes(32)),
      },
    ],
    evidenceTables: [
      {
        table: "wallets",
        primaryKey: [{ column: "id", kind: "uuid" }],
        rows: wallets.map((w) => ({
          id: w.walletId,
          wallet_id: w.walletId,
          public_key: w.publicKey,
          key_origin: w.keyOrigin,
          key_version: w.keyVersion,
        })),
      },
    ],
    settingsValues: { source: "unit-test" },
    identitySigner: {
      sign: (preimage) => signWithSeed(identitySeed, preimage),
    },
  };

  const { archiveJson } = buildBackupArchive(snapshot);
  return { rootKey, identitySeed, wallets, archiveText: archiveJson };
}

function makeMemoryLiveSql(wallets: LiveWallet[]) {
  const verifications = new Set<string>();
  const stamps: RecoveryStampInput[] = [];
  const summaries: unknown[] = [];

  return {
    stamps,
    summaries,
    async query<R>(text: string, params: readonly unknown[] = []): Promise<{ rows: R[] }> {
      if (text === RECOVERY_STAMP_SQL.READ_WALLETS) {
        return {
          rows: wallets.map((w) => ({
            wallet_id: w.walletId,
            public_key: w.publicKey,
            recovery_verified_at: w.recoveryVerifiedAt,
          })) as R[],
        };
      }
      if (text === RECOVERY_STAMP_SQL.HAS_VERIFICATION) {
        const key = `${params[0]}|${params[1]}`;
        return { rows: (verifications.has(key) ? [{ ok: 1 }] : []) as R[] };
      }
      if (text === RECOVERY_STAMP_SQL.STAMP) {
        // params: auditId, nodeId, verifier, walletId, details, detailsSha, verifiedAt, verifId, pub, exportSha
        const walletId = String(params[3]);
        const publicKey = String(params[8]);
        const exportSha = String(params[9]);
        const verifiedAt = String(params[6]);
        const verificationId = String(params[7]);
        const w = wallets.find((x) => x.walletId === walletId);
        if (w === undefined || w.publicKey !== publicKey || w.recoveryVerifiedAt !== null) {
          return { rows: [] };
        }
        w.recoveryVerifiedAt = verifiedAt;
        w.recoveryVerificationId = verificationId;
        verifications.add(`${walletId}|${exportSha}`);
        stamps.push({
          ceremonyId: CEREMONY_ID,
          walletId,
          method: "AUDITED_EXPORT",
          publicKey,
          keyVersion: w.keyVersion,
          exportId: EXPORT_ID,
          exportSha256: exportSha,
          verifierIdentity: String(params[2]),
          censusMatchedRestored: true,
          censusMatchedLive: true,
          archivedProofVerified: true,
          probeSignature: "unit",
          probePreimageSha256: "0".repeat(64),
          probeVerified: true,
        });
        return { rows: [{ wallet_id: walletId }] as R[] };
      }
      if (text === RECOVERY_STAMP_SQL.SUMMARY) {
        summaries.push(params);
        return { rows: [] };
      }
      throw new Error(`unexpected SQL: ${text.slice(0, 80)}`);
    },
  };
}

describe("restore recovery ceremony composition", () => {
  it("stamps both wallets via real ceremony (vault open + probe + sql stamp)", async () => {
    const { rootKey, wallets, archiveText } = provisionLive();
    const liveSql = makeMemoryLiveSql(wallets);

    const bundle = createThrowawayRestoredInstance();
    const restoredVault = createRestoredVaultAccess({
      rootKey,
      nodeId: NODE_ID,
      bundle,
    });

    const liveDatabase = createSqlRecoveryLiveDatabase({
      sql: liveSql,
      nodeId: NODE_ID,
      proveCurrentKeyPossession: async () => true,
      now: () => new Date(ISSUED_AT),
      newId: () => randomUUID(),
    });

    const result = await runRestoreRecoveryCeremony({
      ceremonyId: CEREMONY_ID,
      ceremonyNonce: CEREMONY_NONCE,
      issuedAt: ISSUED_AT,
      verifierIdentity: "operator:unit-test",
      liveNodeId: NODE_ID,
      archiveText,
      restoredInstance: bundle.instance,
      restoredVault,
      liveDatabase,
    });

    expect(result.accepted).toBe(true);
    expect(result.instanceDestroyed).toBe(true);
    expect(bundle.destroyCalls()).toBe(1);
    expect(result.outcomes.get(WALLET_A)).toBe("stamped");
    expect(result.outcomes.get(WALLET_B)).toBe("stamped");
    expect(wallets.every((w) => w.recoveryVerifiedAt !== null)).toBe(true);
    expect(wallets.every((w) => w.recoveryVerificationId !== null)).toBe(true);
    expect(liveSql.stamps).toHaveLength(2);
    expect(liveSql.summaries).toHaveLength(1);
    // evidence coverage tables present in archive path
    expect(BACKUP_COVERAGE_TABLES.length).toBeGreaterThan(10);
  });

  it("composeRestoreRecoveryCeremony wires seams and stamps ≥1 wallet", async () => {
    const { rootKey, wallets, archiveText } = provisionLive();
    // leave only A unstamped later path — both start null
    const liveSql = makeMemoryLiveSql(wallets);

    const { result, destroyCalls } = await composeRestoreRecoveryCeremony({
      archiveText,
      rootKey,
      nodeId: NODE_ID,
      liveSql,
      verifierIdentity: "operator:compose",
      ceremonyId: CEREMONY_ID,
      ceremonyNonce: CEREMONY_NONCE,
      issuedAt: ISSUED_AT,
      now: () => new Date(ISSUED_AT),
      newId: () => randomUUID(),
      proveCurrentKeyPossession: async () => true,
    });

    expect(result.accepted).toBe(true);
    expect(destroyCalls).toBe(1);
    const stamped = [...result.outcomes.values()].filter((o) => o === "stamped").length;
    expect(stamped).toBeGreaterThanOrEqual(1);
    expect(wallets.some((w) => w.recoveryVerifiedAt !== null)).toBe(true);
  });

  it("never stamps when current master key possession fails", async () => {
    const { rootKey, wallets, archiveText } = provisionLive();
    const liveSql = makeMemoryLiveSql(wallets);

    const { result } = await composeRestoreRecoveryCeremony({
      archiveText,
      rootKey,
      nodeId: NODE_ID,
      liveSql,
      verifierIdentity: "operator:compose",
      ceremonyId: CEREMONY_ID,
      ceremonyNonce: CEREMONY_NONCE,
      issuedAt: ISSUED_AT,
      proveCurrentKeyPossession: async () => false,
    });

    expect(result.accepted).toBe(false);
    expect(result.abortReasons).toContain("current_key_possession_failed");
    expect(wallets.every((w) => w.recoveryVerifiedAt === null)).toBe(true);
    expect(liveSql.stamps).toHaveLength(0);
  });

  it("uses EncryptedWalletKeyStore open path compatible with RestoredVaultAccess", async () => {
    const rootKey = deriveRootKey(MASTER, VAULT_ROOT_KDF_SALT);
    const seed = makeSeed();
    const secret64 = secret64FromSeed(seed);
    const publicKey = publicKeyFromSeed(seed);
    const walletId = WALLET_A;
    const store = new InMemoryVaultStore();
    const vault = new EncryptedWalletKeyStore({
      rootKey,
      store,
      auditLog: new InMemoryVaultAccessAuditLog(),
    });
    await vault.seal(
      {
        nodeId: NODE_ID,
        walletId,
        keyVersion: 1,
        publicKey,
        keyOrigin: "node_generated",
      },
      secret64,
    );
    const record = await store.findByWalletId(walletId);
    expect(record).not.toBeNull();
    const open = await vault.open(
      {
        nodeId: NODE_ID,
        walletId,
        keyVersion: 1,
        publicKey,
        keyOrigin: "node_generated",
      },
      "TEST",
    );
    try {
      expect(toBase64UrlPadded(open.bytes.subarray(32))).toBe(publicKey);
    } finally {
      open.wipe();
      secret64.fill(0);
    }
  });
});

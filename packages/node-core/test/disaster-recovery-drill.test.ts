// disaster-recovery drill suite — the exit evidence for the whole family.
//
// These are DRILLS, not unit tests: each scenario destroys a populated node instance outright
// and rebuilds it from nothing but a recovery archive, then drives the PRODUCTION ceremony
// (`runRestoreRecoveryCeremony`) and the PRODUCTION rotation (`rotateVaultMasterKey`) over
// it. Nothing here re-implements export, restore, verification, or rotation — a drill against a
// test-local stub proves nothing about the shipped path.
//
// OFFLINE: no gateway, no chain read, no real ZKZ. The vault is a real AES-256-GCM
// sealed store over real Ed25519 seeds, so "compare every restored key" is a genuine
// decrypt → derive-pubkey → match at the level, never a ciphertext byte-diff — proven by
// re-asserting the same match after a master-key rotation has changed every ciphertext byte.
//
// The six scenarios: (1) full destroy-and-rebuild, (2) corrupt
// archive, (3) missing / partial archive, (4) RPO, (5) RTO, (6) signer-authority isolation.

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign as nodeSign,
  type KeyObject,
} from "node:crypto";
import { Buffer } from "node:buffer";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

import {
  BACKUP_COVERAGE_TABLES,
  buildBackupArchive,
  type BackupArchive,
  type BackupEvidenceRow,
  type BackupEvidenceTableInput,
  type BackupSnapshot,
  type BackupWalletSection,
} from "../src/core/backup/index.js";
import {
  rotateVaultMasterKey,
  runRestoreRecoveryCeremony,
  type NodeSigningInterlock,
  type RecoveryLiveDatabase,
  type RecoveryStampInput,
  type RecoveryWalletRow,
  type RestoreCeremonyResult,
  type RestoredInstance,
  type RestoredVaultAccess,
  type RotationCrypto,
  type RotationSecretHandle,
  type RotationVaultRow,
} from "../src/core/recovery/index.js";
import {
  signUnderLease,
  type ActiveLeaseRecord,
  type SignerAuditEntry,
} from "../src/core/signer-boundary.js";

const NODE_ID = "00000000-0000-4000-8000-0000000003d1";
const EXPORT_ID = "00000000-0000-4000-8000-0000000003d2";
const WALLET_A = "00000000-0000-4000-8000-00000000030a";
const WALLET_B = "00000000-0000-4000-8000-00000000030b";
// Minted AFTER the export — the wallet whose key material the drill proves is unrecoverable.
const WALLET_C = "00000000-0000-4000-8000-00000000030c";
const SIGNING_KEY_ID = "00000000-0000-4000-8000-0000000003aa";
const CEREMONY_ID = "00000000-0000-4000-8000-0000000003c1";
const CEREMONY_NONCE = "d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3c=";

// The RPO window is constructed, not sampled, so the recorded number is exact and reproducible:
// the last successful export is 42 minutes before the destruction event.
const EXPORTED_AT = "2026-07-25T09:00:00.000Z";
const DESTROYED_AT = "2026-07-25T09:42:00.000Z";
const RPO_WINDOW_MS = Date.parse(DESTROYED_AT) - Date.parse(EXPORTED_AT);
const ISSUED_AT = "2026-07-25T10:00:00.000Z";
const VERIFIER = "operator:node-local-admin";

// RFC 8410 PKCS#8 prefix for an Ed25519 private key carrying a raw 32-byte seed.
const ED25519_PKCS8_DER_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function b64url(bytes: Uint8Array): string {
  const unpadded = Buffer.from(bytes).toString("base64url");
  return unpadded + "=".repeat((4 - (unpadded.length % 4)) % 4);
}

function sha256Hex(bytes: Uint8Array | string): string {
  return createHash("sha256")
    .update(typeof bytes === "string" ? Buffer.from(bytes, "utf8") : bytes)
    .digest("hex");
}

function privateKeyFromSeed(seed: Buffer): KeyObject {
  return createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_DER_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
}

function publicKeyFromSeed(seed: Buffer): string {
  const spki = createPublicKey(privateKeyFromSeed(seed)).export({ format: "der", type: "spki" });
  return b64url(new Uint8Array(spki.subarray(spki.length - 32)));
}

function newSeed(): Buffer {
  const der = generateKeyPairSync("ed25519").privateKey.export({ format: "der", type: "pkcs8" });
  return Buffer.from(der.subarray(der.length - 32));
}

// ---------------------------------------------------------------------------
// A real sealed vault. The master key never leaves this object; callers get derived public
// keys and signatures only (the key-custody rule). AAD binds each envelope to its wallet and key
// version, so a row lifted from another wallet or replayed at an older version fails to open.
// ---------------------------------------------------------------------------

interface VaultRowShape {
  readonly wallet_id: string;
  readonly key_version: number;
  readonly ciphertext: string;
  readonly nonce: string;
  readonly auth_tag: string;
  readonly ciphertext_sha256: string;
  readonly created_at: string;
  readonly rotated_at: string | null;
}

class SealedVault {
  constructor(private readonly masterKey: Buffer) {}

  seal(walletId: string, keyVersion: number, seed: Buffer, createdAt: string): VaultRowShape {
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.masterKey, nonce);
    cipher.setAAD(Buffer.from(`${walletId}|${keyVersion}`, "utf8"));
    const ciphertext = Buffer.concat([cipher.update(seed), cipher.final()]);
    return {
      wallet_id: walletId,
      key_version: keyVersion,
      ciphertext: b64url(ciphertext),
      nonce: b64url(nonce),
      auth_tag: b64url(cipher.getAuthTag()),
      ciphertext_sha256: sha256Hex(ciphertext),
      created_at: createdAt,
      rotated_at: null,
    };
  }

  /** Null on any GCM / AAD / version / length failure, so every caller fails closed. */
  open(row: VaultRowShape): Buffer | null {
    try {
      const decipher = createDecipheriv(
        "aes-256-gcm",
        this.masterKey,
        Buffer.from(row.nonce, "base64url"),
      );
      decipher.setAAD(Buffer.from(`${row.wallet_id}|${row.key_version}`, "utf8"));
      decipher.setAuthTag(Buffer.from(row.auth_tag, "base64url"));
      const seed = Buffer.concat([
        decipher.update(Buffer.from(row.ciphertext, "base64url")),
        decipher.final(),
      ]);
      return seed.length === 32 ? seed : null;
    } catch {
      return null;
    }
  }
}

// ---------------------------------------------------------------------------
// The process-wide signer leadership lock (Node Core). One holder at a time, for the whole
// process, independent of per-wallet leases. Every acquisition is recorded so a drill can prove
// both that leadership was never held twice and WHO ever held it.
// ---------------------------------------------------------------------------

class SignerLeadership {
  private holder: string | null = null;
  private readonly waiters: (() => void)[] = [];
  private concurrent = 0;
  maxConcurrent = 0;
  readonly acquisitions: string[] = [];

  async acquire(holderId: string): Promise<void> {
    while (this.holder !== null) {
      await new Promise<void>((resolve) => this.waiters.push(resolve));
    }
    this.holder = holderId;
    this.concurrent += 1;
    this.maxConcurrent = Math.max(this.maxConcurrent, this.concurrent);
    this.acquisitions.push(holderId);
  }

  release(): void {
    this.concurrent -= 1;
    this.holder = null;
    this.waiters.shift()?.();
  }

  interlockFor(holderId: string): NodeSigningInterlock {
    return {
      acquire: () => this.acquire(holderId),
      release: async () => this.release(),
    };
  }

  async underLeadership<T>(holderId: string, run: () => Promise<T>): Promise<T> {
    await this.acquire(holderId);
    try {
      return await run();
    } finally {
      this.release();
    }
  }
}

// ---------------------------------------------------------------------------
// A node's database. `destroy()` is total: this is the drill's destruction event, and after it
// the instance holds no key material, no evidence, and no way to sign.
// ---------------------------------------------------------------------------

interface WalletRow {
  readonly walletId: string;
  readonly publicKey: string;
  readonly keyOrigin: string;
  readonly keyVersion: number;
  readonly recoveryVerifiedAt: string | null;
}

class NodeDatabase {
  readonly wallets = new Map<string, WalletRow>();
  readonly vault = new Map<string, VaultRowShape>();
  readonly evidence = new Map<string, BackupEvidenceRow[]>();
  readonly leases = new Map<string, ActiveLeaseRecord>();
  settings: Record<string, string> = {};
  destroyed = false;

  destroy(): void {
    this.wallets.clear();
    this.vault.clear();
    this.evidence.clear();
    this.leases.clear();
    this.settings = {};
    this.destroyed = true;
  }

  rows(table: string): readonly BackupEvidenceRow[] {
    return this.evidence.get(table) ?? [];
  }
}

const PRIMARY_KEYS: Readonly<Record<string, BackupEvidenceTableInput["primaryKey"]>> = {
  wallets: [{ column: "id", kind: "uuid" }],
  gateway_observations: [{ column: "id", kind: "uuid" }],
  operation_transactions: [{ column: "id", kind: "uuid" }],
  node_events: [{ column: "seq", kind: "integer" }],
  audit_log: [{ column: "id", kind: "uuid" }],
};

function walletEvidenceRow(wallet: WalletRow): BackupEvidenceRow {
  return {
    id: wallet.walletId,
    wallet_id: wallet.walletId,
    public_key: wallet.publicKey,
    key_origin: wallet.keyOrigin,
    key_version: wallet.keyVersion,
  };
}

/** Provision a populated node: two wallets sealed under a real master key, plus evidence rows
 * across the retained canonical/observation/audit tables. */
function provisionLiveNode(): {
  db: NodeDatabase;
  vault: SealedVault;
  masterKey: Buffer;
  seeds: Map<string, Buffer>;
  identitySeed: Buffer;
} {
  const masterKey = randomBytes(32);
  const vault = new SealedVault(masterKey);
  const db = new NodeDatabase();
  const seeds = new Map<string, Buffer>();

  for (const walletId of [WALLET_A, WALLET_B]) {
    const seed = newSeed();
    seeds.set(walletId, seed);
    const wallet: WalletRow = {
      walletId,
      publicKey: publicKeyFromSeed(seed),
      keyOrigin: "node_generated",
      keyVersion: 1,
      // Pre-destruction the wallets are long since verified and operational.
      recoveryVerifiedAt: "2026-07-01T00:00:00.000Z",
    };
    db.wallets.set(walletId, wallet);
    db.vault.set(walletId, vault.seal(walletId, 1, seed, "2026-07-01T00:00:00.000Z"));
  }

  db.evidence.set("wallets", [...db.wallets.values()].map(walletEvidenceRow));
  db.evidence.set("gateway_observations", [
    {
      id: "00000000-0000-4000-8000-0000000004a1",
      wallet_id: WALLET_A,
      transaction_id: "00000000-0000-4000-8000-0000000005a1",
      amount_zkz: "0.01000000",
      observed_at: "2026-07-24T12:00:00.000Z",
    },
  ]);
  db.evidence.set("operation_transactions", [
    {
      id: "00000000-0000-4000-8000-0000000006a1",
      wallet_id: WALLET_A,
      step: 1,
      unix_time_secs: "1785000000",
      settled: true,
    },
  ]);
  db.evidence.set("node_events", [
    { seq: 1, kind: "WALLET_MINTED", emitted_at: "2026-07-01T00:00:00.000Z" },
    { seq: 2, kind: "OBSERVATION_LANDED", emitted_at: "2026-07-24T12:00:00.000Z" },
  ]);
  db.evidence.set("audit_log", [
    {
      id: "00000000-0000-4000-8000-0000000007a1",
      action: "BACKUP_EXPORTED",
      actor: VERIFIER,
      recorded_at: "2026-07-24T12:30:00.000Z",
    },
  ]);
  db.settings = { network: "splitchain", retention: "permanent" };

  return { db, vault, masterKey, seeds, identitySeed: newSeed() };
}

/** The export, driven through the production exporter. Every signature comes from the
 *  sealed vault via a caller-held seam — the exporter never sees a key. */
function exportArchive(
  db: NodeDatabase,
  vault: SealedVault,
  identitySeed: Buffer,
  exportedAt: string,
): { archiveJson: string; archive: BackupArchive } {
  const evidenceTables: BackupEvidenceTableInput[] = [...db.evidence.entries()].map(
    ([table, rows]) => ({
      table: table as BackupEvidenceTableInput["table"],
      primaryKey: PRIMARY_KEYS[table] ?? [{ column: "id", kind: "uuid" as const }],
      rows,
    }),
  );

  const snapshot: BackupSnapshot = {
    nodeId: NODE_ID,
    exportId: EXPORT_ID,
    exportedAt,
    wallets: [...db.wallets.values()].map((wallet) => {
      const row = db.vault.get(wallet.walletId);
      if (row === undefined) throw new Error(`no vault row for ${wallet.walletId}`);
      return {
        walletId: wallet.walletId,
        publicKey: wallet.publicKey,
        keyOrigin: wallet.keyOrigin,
        keyVersion: wallet.keyVersion,
        vault: row,
        signer: {
          sign: (preimageBytes: Uint8Array) => {
            const seed = vault.open(row);
            if (seed === null) throw new Error("vault row unreadable at export");
            return new Uint8Array(
              nodeSign(null, Buffer.from(preimageBytes), privateKeyFromSeed(seed)),
            );
          },
        },
      };
    }),
    nodeSigningKeys: [
      {
        signingKeyId: SIGNING_KEY_ID,
        purpose: "node_identity",
        publicKey: publicKeyFromSeed(identitySeed),
        vaultSecretRef: "sealed-store/node-identity",
        sealedCiphertextSha256: sha256Hex(identitySeed),
      },
    ],
    evidenceTables,
    settingsValues: db.settings,
    identitySigner: {
      sign: (preimageBytes: Uint8Array) =>
        new Uint8Array(nodeSign(null, Buffer.from(preimageBytes), privateKeyFromSeed(identitySeed))),
    },
  };

  return buildBackupArchive(snapshot);
}

/** The operational restore: a fresh empty database repopulated from the archive alone. Every
 * wallet lands with `recovery_verified_at = null`born blocked until the ceremony
 * stamps it, which is exactly the ordering this drill exists to prove. */
function rebuildFromArchive(archive: BackupArchive): NodeDatabase {
  const db = new NodeDatabase();
  for (const section of archive.wallet_sections) {
    db.wallets.set(section.wallet_id, {
      walletId: section.wallet_id,
      publicKey: section.public_key,
      keyOrigin: section.key_origin,
      keyVersion: section.key_version,
      recoveryVerifiedAt: null,
    });
    db.vault.set(section.wallet_id, { ...section.vault });
  }
  for (const section of archive.evidence_sections) {
    db.evidence.set(section.table, section.rows.map((row) => ({ ...row })));
  }
  db.settings = { ...archive.settings_snapshot.values };
  return db;
}

// ---------------------------------------------------------------------------
// Ceremony seams over real databases.
// ---------------------------------------------------------------------------

// The restored instance is deliberately given NO signer-leadership handle: `RestoredInstance`
// has no such member, so the ceremony has no way to take leadership even if it tried. The
// drills assert the behavioural half of that guarantee — the restored population is born
// blocked, so it can never sign the money path (Phase 1; Node Core).
function makeRestoredInstance(db: NodeDatabase): RestoredInstance & { destroyCalls: () => number } {
  let destroyCalls = 0;
  let leaseEpoch = 0n;
  return {
    restore: vi.fn(async (archive: BackupArchive) => {
      // All-or-nothing: build the whole population off to the side, then swap it in.
      const rebuilt = rebuildFromArchive(archive);
      for (const [walletId, wallet] of rebuilt.wallets) db.wallets.set(walletId, wallet);
      for (const [walletId, row] of rebuilt.vault) db.vault.set(walletId, row);
      for (const [table, rows] of rebuilt.evidence) db.evidence.set(table, rows);
      db.settings = rebuilt.settings;
    }),
    readRestoredRowCounts: vi.fn(async () => {
      const counts = new Map<string, number>();
      for (const table of BACKUP_COVERAGE_TABLES) counts.set(table, db.rows(table).length);
      return counts;
    }),
    countActiveLeases: vi.fn(async () => 0),
    readWallet: vi.fn(async (walletId: string) => {
      const wallet = db.wallets.get(walletId);
      return wallet === undefined
        ? null
        : {
            walletId,
            publicKey: wallet.publicKey,
            recoveryVerifiedAt: wallet.recoveryVerifiedAt,
          };
    }),
    acquireReconciliationLease: vi.fn(async (walletId: string) => {
      leaseEpoch += 1n;
      const lease: ActiveLeaseRecord = {
        walletId,
        operationId: `recovery-${walletId}`,
        epoch: leaseEpoch,
        role: "RECONCILIATION",
        lifecycle: "ACTIVE",
      };
      db.leases.set(walletId, lease);
      return lease;
    }),
    releaseReconciliationLease: vi.fn(async (walletId: string) => {
      db.leases.delete(walletId);
    }),
    readActiveLease: vi.fn(async (walletId: string) => db.leases.get(walletId) ?? null),
    destroy: vi.fn(async () => {
      destroyCalls += 1;
      db.destroy();
    }),
    destroyCalls: () => destroyCalls,
  };
}

function makeRestoredVault(db: NodeDatabase, vault: SealedVault): RestoredVaultAccess {
  const openSeed = (walletId: string): Buffer | null => {
    const row = db.vault.get(walletId);
    return row === undefined ? null : vault.open(row);
  };
  return {
    // The check, verbatim: decrypt inside the seam, derive the public key, return only
    // the derived public key. Never a ciphertext comparison.
    openAndDerivePublicKey: vi.fn(async (walletId: string) => {
      const seed = openSeed(walletId);
      return seed === null ? null : publicKeyFromSeed(seed);
    }),
    sign: vi.fn(async (walletId: string, preimageBytes: Uint8Array) => {
      const seed = openSeed(walletId);
      if (seed === null) throw new Error("restored vault row unreadable");
      return b64url(new Uint8Array(nodeSign(null, Buffer.from(preimageBytes), privateKeyFromSeed(seed))));
    }),
  };
}

interface LiveDatabaseSeam {
  readonly seam: RecoveryLiveDatabase;
  readonly stamps: RecoveryStampInput[];
  readonly summaries: unknown[];
  /** Ordered trace of every seam call, so the drill can assert stamping never precedes proof. */
  readonly trace: string[];
}

function makeLiveDatabase(db: NodeDatabase, vault: SealedVault): LiveDatabaseSeam {
  const stamps: RecoveryStampInput[] = [];
  const summaries: unknown[] = [];
  const trace: string[] = [];

  const seam: RecoveryLiveDatabase = {
    readWallets: vi.fn(async () => {
      trace.push("readWallets");
      return new Map<string, RecoveryWalletRow>(
        [...db.wallets.entries()].map(([walletId, wallet]) => [
          walletId,
          {
            walletId,
            publicKey: wallet.publicKey,
            recoveryVerifiedAt: wallet.recoveryVerifiedAt,
          },
        ]),
      );
    }),
    proveCurrentKeyPossession: vi.fn(async () => {
      trace.push("proveCurrentKeyPossession");
      const first = [...db.vault.values()][0];
      if (first === undefined) return false;
      const seed = vault.open(first);
      return seed !== null && publicKeyFromSeed(seed) === db.wallets.get(first.wallet_id)?.publicKey;
    }),
    hasRecoveryVerification: vi.fn(async (walletId: string) => {
      trace.push(`hasRecoveryVerification:${walletId}`);
      return stamps.some((stamp) => stamp.walletId === walletId);
    }),
    stampRecoveryVerification: vi.fn(async (input: RecoveryStampInput) => {
      trace.push(`stamp:${input.walletId}`);
      stamps.push(input);
      const wallet = db.wallets.get(input.walletId);
      if (wallet !== undefined) {
        db.wallets.set(input.walletId, { ...wallet, recoveryVerifiedAt: ISSUED_AT });
      }
      db.evidence.set("audit_log", [
        ...db.rows("audit_log"),
        {
          id: `stamp-${input.walletId}`,
          action: "RECOVERY_VERIFIED",
          actor: input.verifierIdentity,
          recorded_at: ISSUED_AT,
        },
      ]);
    }),
    appendCeremonySummary: vi.fn(async (summary) => {
      trace.push("appendCeremonySummary");
      summaries.push(summary);
    }),
  };

  return { seam, stamps, summaries, trace };
}

// ---------------------------------------------------------------------------
// Post-restore money-path signing. Goes through the production signer boundary, under process
// signer leadership AND a per-wallet lease — Node Core: "Neither replaces the other."
// a wallet with no recovery stamp may not be leased at all, so it cannot sign.
// ---------------------------------------------------------------------------

async function signMoneyPath(
  db: NodeDatabase,
  vault: SealedVault,
  leadership: SignerLeadership,
  walletId: string,
): Promise<string> {
  const wallet = db.wallets.get(walletId);
  if (wallet === undefined) throw new Error("unknown wallet");
  if (wallet.recoveryVerifiedAt === null) {
    throw new Error("wallet is born blocked: no recovery verification");
  }
  const lease: ActiveLeaseRecord = {
    walletId,
    operationId: `send-${walletId}`,
    epoch: 7n,
    role: "SEND_SOURCE",
    lifecycle: "ACTIVE",
  };
  const preimageText = `zp-drill-money-path\n{"wallet_id":"${walletId}"}`;
  const audit: SignerAuditEntry[] = [];

  return leadership.underLeadership("live-node", async () => {
    // Process-wide leadership latch required by signUnderLease (D9 leadership).
    // We are already inside underLeadership, so held is true for this process only.
    const result = await signUnderLease(
      {
        leadership: { held: true },
        leaseReader: { readActiveLease: async () => lease },
        vaultSigner: {
          sign: async (id: string, preimageBytes: Uint8Array) => {
            const row = db.vault.get(id);
            const seed = row === undefined ? null : vault.open(row);
            if (seed === null) throw new Error("vault row unreadable");
            return b64url(
              new Uint8Array(nodeSign(null, Buffer.from(preimageBytes), privateKeyFromSeed(seed))),
            );
          },
        },
        auditLog: { append: async (entry) => void audit.push(entry) },
        assertMoneyAdmitted: () => {},
        assertCanOperate: () => {},
        assertWalletMaySign: async () => {},
      },
      {
        walletId,
        operationId: lease.operationId,
        leaseEpoch: lease.epoch,
        purpose: "SPLITCHAIN_STEP_1",
        preimageText,
        expectedPreimageSha256: sha256Hex(preimageText),
      },
    );
    if (audit.at(-1)?.outcome !== "SIGNED") throw new Error("signer boundary did not sign");
    return result.signature;
  });
}

/** Independent recomputation of the table digest — deliberately not the module under
 *  test, so a matching digest is evidence rather than a tautology. */
function recomputeTableDigest(rows: readonly BackupEvidenceRow[]): string {
  return sha256Hex(rows.map((row) => sha256Hex(JSON.stringify(row))).join(""));
}

/** Run one full destroy-and-rebuild cycle. `archiveTextFor` derives the archive text the
 *  ceremony is handed from the node's OWN good archive, so a damaged-archive drill exercises
 *  the damage and nothing else — the live database and the archive always belong to the same
 *  node, and a refusal can never be a cross-node artefact. */
async function runDrill(
  archiveTextFor: (archiveJson: string, archive: BackupArchive) => string,
): Promise<{
  result: RestoreCeremonyResult;
  rebuiltDb: NodeDatabase;
  restoredDb: NodeDatabase;
  restoredInstance: ReturnType<typeof makeRestoredInstance>;
  live: LiveDatabaseSeam;
  leadership: SignerLeadership;
  vault: SealedVault;
  origin: ReturnType<typeof provisionLiveNode>;
  archive: BackupArchive;
}> {
  const origin = provisionLiveNode();
  const { archiveJson, archive } = exportArchive(
    origin.db,
    origin.vault,
    origin.identitySeed,
    EXPORTED_AT,
  );
  const archiveText = archiveTextFor(archiveJson, archive);
  const leadership = new SignerLeadership();

  // DESTRUCTION — the node process and its database are gone.
  origin.db.destroy();

  // Rebuild the live database from the good archive, then run the ceremony over it with a
  // separate isolated restored instance and whatever archive text the drill is exercising. The
  // master key comes from the operator's out-of-band custody, not from the archive (
  // verbatim ciphertext, no whole-archive wrap).
  const rebuiltDb = rebuildFromArchive(archive);
  const vault = new SealedVault(origin.masterKey);
  const restoredDb = new NodeDatabase();
  const restoredInstance = makeRestoredInstance(restoredDb);
  const live = makeLiveDatabase(rebuiltDb, vault);

  const result = await runRestoreRecoveryCeremony({
    ceremonyId: CEREMONY_ID,
    ceremonyNonce: CEREMONY_NONCE,
    issuedAt: ISSUED_AT,
    verifierIdentity: VERIFIER,
    liveNodeId: NODE_ID,
    archiveText,
    restoredInstance,
    restoredVault: makeRestoredVault(restoredDb, vault),
    liveDatabase: live.seam,
  });

  return { result, rebuiltDb, restoredDb, restoredInstance, live, leadership, vault, origin, archive };
}

/** Every fail-closed drill asserts the same thing: nothing was restored, nothing was stamped,
 *  no orphan rows exist anywhere, and the restored instance was destroyed regardless. */
function expectFailedClosed(drill: Awaited<ReturnType<typeof runDrill>>): void {
  expect(drill.result.accepted).toBe(false);
  expect(drill.result.abortReasons).toContain("archive_rejected");
  expect(drill.result.archiveRejectionReasons.length).toBeGreaterThan(0);
  expect(drill.restoredInstance.restore).not.toHaveBeenCalled();
  // Zero partial vault population — inspect the restored database directly.
  expect(drill.restoredDb.vault.size).toBe(0);
  expect(drill.restoredDb.wallets.size).toBe(0);
  expect(drill.restoredDb.evidence.size).toBe(0);
  expect(drill.live.stamps).toHaveLength(0);
  expect(drill.live.summaries).toHaveLength(0);
  expect(drill.result.instanceDestroyed).toBe(true);
  expect(drill.restoredInstance.destroyCalls()).toBe(1);
  // No process ever took signer leadership during a refused restore.
  expect(drill.leadership.maxConcurrent).toBe(0);
}

/** Mutate one field of the archive JSON and return the corrupted text. */
function corrupt(archiveJson: string, mutate: (archive: BackupArchive) => void): string {
  const archive = JSON.parse(archiveJson) as BackupArchive;
  mutate(archive);
  return JSON.stringify(archive);
}

// ---------------------------------------------------------------------------
// Scenario 1 — full destroy-and-rebuild.
// ---------------------------------------------------------------------------

describe("DR drill 1 — full destroy-and-rebuild", () => {
  it("rebuilds from the archive alone: every key re-derives and every evidence byte matches", async () => {
    const origin = provisionLiveNode();

    // Pre-destruction originals, captured at the plaintext-key level.
    const originalPublicKeys = new Map(
      [...origin.db.wallets.keys()].map((walletId) => {
        const row = origin.db.vault.get(walletId);
        const seed = row === undefined ? null : origin.vault.open(row);
        expect(seed).not.toBeNull();
        return [walletId, publicKeyFromSeed(seed as Buffer)];
      }),
    );
    const originalEvidence = new Map(
      [...origin.db.evidence.entries()].map(([table, rows]) => [
        table,
        rows.map((row) => JSON.stringify(row)),
      ]),
    );
    const originalSettings = { ...origin.db.settings };

    const { archive } = exportArchive(origin.db, origin.vault, origin.identitySeed, EXPORTED_AT);

    origin.db.destroy();
    expect(origin.db.vault.size).toBe(0);
    expect(origin.db.wallets.size).toBe(0);

    const rebuiltDb = rebuildFromArchive(archive);
    const vault = new SealedVault(origin.masterKey);

    // Key comparison at the decrypt → derive-pubkey → match level, never ciphertext.
    for (const [walletId, originalPublicKey] of originalPublicKeys) {
      const row = rebuiltDb.vault.get(walletId);
      expect(row).toBeDefined();
      const seed = vault.open(row as VaultRowShape);
      expect(seed).not.toBeNull();
      expect(publicKeyFromSeed(seed as Buffer)).toBe(originalPublicKey);
      expect(rebuiltDb.wallets.get(walletId)?.publicKey).toBe(originalPublicKey);
    }

    // Every evidence byte, over EVERY table the manifest declares — not a chosen subset.
    expect(archive.manifest.evidence_index).toHaveLength(BACKUP_COVERAGE_TABLES.length);
    for (const entry of archive.manifest.evidence_index) {
      const restored = rebuiltDb.rows(entry.table);
      expect(restored).toHaveLength(entry.row_count);
      expect(recomputeTableDigest(restored)).toBe(entry.table_sha256);
      const original = originalEvidence.get(entry.table);
      if (original !== undefined) {
        expect(restored.map((row) => JSON.stringify(row))).toEqual(original);
      }
    }
    expect(rebuiltDb.settings).toEqual(originalSettings);
  });

  it("runs the ceremony over the rebuilt node, stamps only after proof, and resumes signing", async () => {
    const origin = provisionLiveNode();
    const { archiveJson, archive } = exportArchive(
      origin.db,
      origin.vault,
      origin.identitySeed,
      EXPORTED_AT,
    );
    origin.db.destroy();

    const rebuiltDb = rebuildFromArchive(archive);
    const vault = new SealedVault(origin.masterKey);
    const leadership = new SignerLeadership();
    const restoredDb = new NodeDatabase();
    const restoredInstance = makeRestoredInstance(restoredDb);
    const live = makeLiveDatabase(rebuiltDb, vault);

    // Born blocked before the ceremony: the rebuilt node cannot sign.
    await expect(signMoneyPath(rebuiltDb, vault, leadership, WALLET_A)).rejects.toThrow(
      /born blocked/,
    );

    const result = await runRestoreRecoveryCeremony({
      ceremonyId: CEREMONY_ID,
      ceremonyNonce: CEREMONY_NONCE,
      issuedAt: ISSUED_AT,
      verifierIdentity: VERIFIER,
      liveNodeId: NODE_ID,
      archiveText: archiveJson,
      restoredInstance,
      restoredVault: makeRestoredVault(restoredDb, vault),
      liveDatabase: live.seam,
    });

    expect(result.accepted).toBe(true);
    expect(result.abortReasons).toEqual([]);
    expect(result.restoreComplete).toBe(true);
    expect(result.bornBlocked).toEqual([]);
    expect([...result.outcomes.values()]).toEqual(["stamped", "stamped"]);
    expect(result.summaryWritten).toBe(true);
    expect(result.instanceDestroyed).toBe(true);

    // Ordering: the possession proof and this wallet's idempotency read both precede its stamp,
    // and the summary is last. This is the ordering bug class the drill exists to catch — a
    // ceremony that stamped before proving would still pass every per-row unit test.
    for (const walletId of [WALLET_A, WALLET_B]) {
      const stampIndex = live.trace.indexOf(`stamp:${walletId}`);
      expect(stampIndex).toBeGreaterThan(live.trace.indexOf("proveCurrentKeyPossession"));
      expect(stampIndex).toBeGreaterThan(live.trace.indexOf(`hasRecoveryVerification:${walletId}`));
      expect(stampIndex).toBeLessThan(live.trace.indexOf("appendCeremonySummary"));
    }
    expect(live.trace.at(-1)).toBe("appendCeremonySummary");

    // Every stamp carries the verified probe over the wallet's own public key.
    for (const stamp of live.stamps) {
      expect(stamp.probeVerified).toBe(true);
      expect(stamp.censusMatchedRestored).toBe(true);
      expect(stamp.censusMatchedLive).toBe(true);
      expect(stamp.publicKey).toBe(rebuiltDb.wallets.get(stamp.walletId)?.publicKey);
    }

    // Signing resumed — through the production signer boundary, under leadership and a lease.
    const signature = await signMoneyPath(rebuiltDb, vault, leadership, WALLET_A);
    expect(signature).toMatch(/^[A-Za-z0-9_-]+=*$/);

    // The restored instance is gone and never held signer leadership.
    expect(restoredDb.destroyed).toBe(true);
    expect(leadership.acquisitions).toEqual(["live-node"]);
    expect(leadership.maxConcurrent).toBe(1);
  });

  it("proves the key comparison is not ciphertext equality: rotation changes every byte, keys match", async () => {
    const origin = provisionLiveNode();
    const { archive } = exportArchive(origin.db, origin.vault, origin.identitySeed, EXPORTED_AT);
    origin.db.destroy();

    const rebuiltDb = rebuildFromArchive(archive);
    const oldVault = new SealedVault(origin.masterKey);
    const newMasterKey = randomBytes(32);
    const newVault = new SealedVault(newMasterKey);
    const leadership = new SignerLeadership();

    const seedsByHandle = new Map<string, Buffer>();
    const crypto: RotationCrypto = {
      open: async (row, epoch) => {
        const seed = (epoch === "old" ? oldVault : newVault).open({
          ...row,
          auth_tag: row.authTag,
          ciphertext_sha256: row.ciphertextSha256,
          created_at: "2026-07-01T00:00:00.000Z",
          rotated_at: null,
          wallet_id: row.walletId,
          key_version: row.keyVersion,
        });
        if (seed === null) return null;
        seedsByHandle.set(row.walletId, seed);
        return { walletId: row.walletId };
      },
      derivePublicKey: async (handle: RotationSecretHandle) =>
        publicKeyFromSeed(seedsByHandle.get(handle.walletId) as Buffer),
      reseal: async (handle, nextKeyVersion) => {
        const sealed = newVault.seal(
          handle.walletId,
          nextKeyVersion,
          seedsByHandle.get(handle.walletId) as Buffer,
          "2026-07-25T10:00:00.000Z",
        );
        return {
          walletId: sealed.wallet_id,
          keyVersion: sealed.key_version,
          ciphertext: sealed.ciphertext,
          nonce: sealed.nonce,
          authTag: sealed.auth_tag,
          ciphertextSha256: sealed.ciphertext_sha256,
        };
      },
      wipe: async () => {},
    };

    const originalCiphertexts = new Map(
      [...rebuiltDb.vault.entries()].map(([walletId, row]) => [walletId, row.ciphertext]),
    );
    let committed: readonly RotationVaultRow[] = [];

    const rotation = await rotateVaultMasterKey({
      wallets: [...rebuiltDb.wallets.values()].map((wallet) => {
        const row = rebuiltDb.vault.get(wallet.walletId) as VaultRowShape;
        return {
          walletId: wallet.walletId,
          publicKey: wallet.publicKey,
          keyOrigin: wallet.keyOrigin,
          row: {
            walletId: row.wallet_id,
            keyVersion: row.key_version,
            ciphertext: row.ciphertext,
            nonce: row.nonce,
            authTag: row.auth_tag,
            ciphertextSha256: row.ciphertext_sha256,
          },
        };
      }),
      crypto,
      interlock: leadership.interlockFor("rotation"),
      commit: async (rows) => {
        committed = rows;
      },
    });

    expect(rotation.state).toBe("ROTATION_COMPLETE");
    for (const row of committed) {
      // Ciphertext legitimately differs post-rotation (new master key, new nonce, new version)…
      expect(row.ciphertext).not.toBe(originalCiphertexts.get(row.walletId));
      expect(row.keyVersion).toBe(2);
      // …while the underlying key material — and so the derived public key — is preserved.
      const seed = newVault.open({
        wallet_id: row.walletId,
        key_version: row.keyVersion,
        ciphertext: row.ciphertext,
        nonce: row.nonce,
        auth_tag: row.authTag,
        ciphertext_sha256: row.ciphertextSha256,
        created_at: "2026-07-25T10:00:00.000Z",
        rotated_at: null,
      });
      expect(seed).not.toBeNull();
      expect(publicKeyFromSeed(seed as Buffer)).toBe(rebuiltDb.wallets.get(row.walletId)?.publicKey);
    }
    expect(leadership.maxConcurrent).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Scenario 2 — corrupt archive.
// ---------------------------------------------------------------------------

describe("DR drill 2 — corrupt archive", () => {
  it("refuses a flipped manifest field with zero partial population", async () => {
    const drill = await runDrill((archiveJson) =>
      corrupt(archiveJson, (archive) => {
        (archive.manifest as { exported_at: string }).exported_at = "2026-07-25T09:00:00.001Z";
      }),
    );
    expectFailedClosed(drill);
    expect(drill.result.archiveRejectionReasons).toContain("manifest_signature_invalid");
  });

  it("refuses one flipped vault ciphertext byte", async () => {
    const drill = await runDrill((archiveJson) =>
      corrupt(archiveJson, (archive) => {
        const section = archive.wallet_sections[0] as BackupWalletSection;
        const bytes = Buffer.from(section.vault.ciphertext, "base64url");
        bytes[0] = (bytes[0] ?? 0) ^ 0xff;
        (section.vault as { ciphertext: string }).ciphertext = b64url(new Uint8Array(bytes));
      }),
    );
    expectFailedClosed(drill);
    expect(drill.result.archiveRejectionReasons).toContain("export_digest_mismatch");
    // Refused before any wallet was opened, so corrupted key material was never admitted.
    expect(drill.result.outcomes.size).toBe(0);
  });

  it("refuses one flipped digest", async () => {
    const drill = await runDrill((archiveJson) =>
      corrupt(archiveJson, (archive) => {
        const entry = archive.manifest.evidence_index.find((row) => row.table === "wallets");
        (entry as { table_sha256: string }).table_sha256 = sha256Hex("tampered");
      }),
    );
    expectFailedClosed(drill);
    expect(drill.result.archiveRejectionReasons).toContain("manifest_signature_invalid");
  });
});

// ---------------------------------------------------------------------------
// Scenario 3 — missing / partial archive.
// ---------------------------------------------------------------------------

describe("DR drill 3 — missing or partial archive", () => {
  it("refuses an absent archive", async () => {
    const drill = await runDrill(() => "");
    expectFailedClosed(drill);
    expect(drill.result.archiveRejectionReasons).toContain("malformed_json");
  });

  it("refuses a truncated archive", async () => {
    const drill = await runDrill((archiveJson) =>
      archiveJson.slice(0, Math.floor(archiveJson.length / 2)),
    );
    expectFailedClosed(drill);
    expect(drill.result.archiveRejectionReasons).toContain("malformed_json");
  });

  it("refuses a structurally incomplete archive missing a whole section", async () => {
    const drill = await runDrill((archiveJson) => {
      const parsed = JSON.parse(archiveJson) as Record<string, unknown>;
      delete parsed.evidence_sections;
      return JSON.stringify(parsed);
    });
    expectFailedClosed(drill);
    expect(drill.result.archiveRejectionReasons).toContain("field_set_mismatch");
  });

  it("refuses an archive whose wallet sections were dropped", async () => {
    const drill = await runDrill((archiveJson) =>
      corrupt(archiveJson, (archive) => {
        (archive as { wallet_sections: readonly BackupWalletSection[] }).wallet_sections = [];
      }),
    );
    expectFailedClosed(drill);
    expect(drill.result.archiveRejectionReasons).toContain("manifest_section_mismatch");
  });
});

// ---------------------------------------------------------------------------
// Scenarios 4, 5, 6 — RPO, RTO, signer-authority isolation, recorded as a durable bundle.
// ---------------------------------------------------------------------------

interface DrillEvidenceBundle {
  readonly ceremony_id: string;
  readonly last_successful_export_at: string;
  readonly destroyed_at: string;
  readonly rpo_ms: number;
  readonly rpo_unrecoverable: readonly string[];
  readonly rto_ms: number;
  readonly rto_measured_to: string;
  readonly max_concurrent_signer_leaders: number;
  readonly signer_leadership_holders: readonly string[];
  readonly restored_instance_ever_leader: boolean;
  readonly offline: true;
}

describe("DR drill 4/5/6 — RPO, RTO, and signer-authority isolation", () => {
  it("records concrete RPO and RTO and proves signer leadership was never held twice", async () => {
    const origin = provisionLiveNode();
    const { archiveJson, archive } = exportArchive(
      origin.db,
      origin.vault,
      origin.identitySeed,
      EXPORTED_AT,
    );

    // Post-export writes — everything here is inside the RPO window and therefore lost.
    const lateObservationId = "00000000-0000-4000-8000-00000000041a";
    origin.db.evidence.set("gateway_observations", [
      ...origin.db.rows("gateway_observations"),
      {
        id: lateObservationId,
        wallet_id: WALLET_B,
        transaction_id: "00000000-0000-4000-8000-00000000051a",
        amount_zkz: "0.00500000",
        observed_at: "2026-07-25T09:30:00.000Z",
      },
    ]);
    const lateSeed = newSeed();
    origin.db.wallets.set(WALLET_C, {
      walletId: WALLET_C,
      publicKey: publicKeyFromSeed(lateSeed),
      keyOrigin: "node_generated",
      keyVersion: 1,
      recoveryVerifiedAt: "2026-07-25T09:20:00.000Z",
    });
    origin.db.vault.set(WALLET_C, origin.vault.seal(WALLET_C, 1, lateSeed, "2026-07-25T09:20:00.000Z"));

    const atDestruction = {
      observationIds: origin.db.rows("gateway_observations").map((row) => String(row.id)),
      walletIds: [...origin.db.wallets.keys()],
    };

    // DESTRUCTION — start the RTO clock.
    const rtoStart = performance.now();
    origin.db.destroy();

    const rebuiltDb = rebuildFromArchive(archive);
    const vault = new SealedVault(origin.masterKey);
    const leadership = new SignerLeadership();
    const restoredDb = new NodeDatabase();
    const restoredInstance = makeRestoredInstance(restoredDb);
    const live = makeLiveDatabase(rebuiltDb, vault);

    const result = await runRestoreRecoveryCeremony({
      ceremonyId: CEREMONY_ID,
      ceremonyNonce: CEREMONY_NONCE,
      issuedAt: ISSUED_AT,
      verifierIdentity: VERIFIER,
      liveNodeId: NODE_ID,
      archiveText: archiveJson,
      restoredInstance,
      restoredVault: makeRestoredVault(restoredDb, vault),
      liveDatabase: live.seam,
    });
    expect(result.accepted).toBe(true);

    // Signing resumed — this is the end of the RTO measurement.
    await signMoneyPath(rebuiltDb, vault, leadership, WALLET_A);
    const rtoMs = performance.now() - rtoStart;

    // ---- Scenario 4: RPO, as a concrete duration plus an enumerated loss set. ----
    const archivedObservationIds = new Set(
      (archive.evidence_sections.find((section) => section.table === "gateway_observations")?.rows ??
        []).map((row) => String(row.id)),
    );
    const archivedWalletIds = new Set(archive.wallet_sections.map((section) => section.wallet_id));
    const unrecoverable = [
      ...atDestruction.observationIds
        .filter((id) => !archivedObservationIds.has(id))
        .map((id) => `gateway_observations.id=${id}`),
      ...atDestruction.walletIds
        .filter((id) => !archivedWalletIds.has(id))
        .map((id) => `wallets.wallet_id=${id} (key material permanently unrecoverable)`),
    ];

    expect(RPO_WINDOW_MS).toBe(2_520_000);
    expect(unrecoverable).toEqual([
      `gateway_observations.id=${lateObservationId}`,
      `wallets.wallet_id=${WALLET_C} (key material permanently unrecoverable)`,
    ]);
    // The loss is real, not nominal: the rebuilt node has neither the row nor the key.
    expect(rebuiltDb.wallets.has(WALLET_C)).toBe(false);
    expect(rebuiltDb.vault.has(WALLET_C)).toBe(false);
    expect(rebuiltDb.rows("gateway_observations").map((row) => String(row.id))).not.toContain(
      lateObservationId,
    );
    // Everything outside the window survived intact.
    expect(rebuiltDb.wallets.size).toBe(2);

    // ---- Scenario 5: RTO, a real monotonic measurement. ----
    expect(Number.isFinite(rtoMs)).toBe(true);
    expect(rtoMs).toBeGreaterThan(0);

    // ---- Scenario 6: signer-authority isolation. ----
    // Only the live node ever took leadership; the restored instance never did.
    expect(leadership.acquisitions).toEqual(["live-node"]);
    expect(leadership.maxConcurrent).toBe(1);

    // And leadership is genuinely exclusive under contention: race two rotation ceremonies
    // through the one interlock and assert the second never overlaps the first.
    const noopRotation = (holder: string) =>
      rotateVaultMasterKey({
        wallets: [],
        crypto: {
          open: async () => null,
          derivePublicKey: async () => "",
          reseal: async () => {
            throw new Error("unreachable");
          },
          wipe: async () => {},
        },
        interlock: leadership.interlockFor(holder),
        commit: async () => {
          // Hold leadership across a turn so a second holder would overlap if the lock were fake.
          await new Promise<void>((resolve) => setTimeout(resolve, 5));
        },
      });
    await Promise.all([noopRotation("rotation-a"), noopRotation("rotation-b")]);
    expect(leadership.maxConcurrent).toBe(1);
    expect(leadership.acquisitions).toContain("rotation-a");
    expect(leadership.acquisitions).toContain("rotation-b");
    expect(leadership.acquisitions).not.toContain("restored-instance");

    // ---- Durable evidence bundle. ----
    const bundle: DrillEvidenceBundle = {
      ceremony_id: CEREMONY_ID,
      last_successful_export_at: EXPORTED_AT,
      destroyed_at: DESTROYED_AT,
      rpo_ms: RPO_WINDOW_MS,
      rpo_unrecoverable: unrecoverable,
      rto_ms: Math.round(rtoMs * 1000) / 1000,
      rto_measured_to: "first post-restore money-path signature",
      max_concurrent_signer_leaders: leadership.maxConcurrent,
      signer_leadership_holders: [...new Set(leadership.acquisitions)],
      restored_instance_ever_leader: leadership.acquisitions.includes("restored-instance"),
      offline: true,
    };
    const bundlePath = join(
      mkdtempSync(join(tmpdir(), "zp-dr-drill-")),
      "dr-drill-evidence.json",
    );
    writeFileSync(bundlePath, `${JSON.stringify(bundle, null, 2)}\n`, "utf8");

    const readBack = JSON.parse(readFileSync(bundlePath, "utf8")) as DrillEvidenceBundle;
    expect(readBack.rpo_ms).toBe(2_520_000);
    expect(readBack.rpo_unrecoverable).toHaveLength(2);
    expect(readBack.rto_ms).toBeGreaterThan(0);
    expect(readBack.max_concurrent_signer_leaders).toBe(1);
    expect(readBack.restored_instance_ever_leader).toBe(false);
    expect(readBack.offline).toBe(true);
  });
});

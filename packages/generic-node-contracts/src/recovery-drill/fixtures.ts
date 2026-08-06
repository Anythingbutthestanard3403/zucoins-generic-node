/**
 * SOURCE: the signing-custody-security spec the archive section (archive),
 * the ceremony (ceremony), the drill matrix (drill matrix); the data model wallet/vault schema (wallets/vault/wallet_recovery_
 * verifications schema); the wallet-vault envelope freeze/the wallet-DEK HKDF rule/the backup-archive freeze/the recovery-purposes freeze/the backup-archive freeze.
 *
 * A deterministic synthetic node world for the recovery-drill lane destroy-restore and corrupt-recovery
 * drills: three wallets (AVAILABLE / QUARANTINED / RETIRED — the ceremony stamps ALL sections
 * regardless of state, ceremony-procedure Phase 2), their vault rows sealed under a synthetic boot root, the
 * node identity key, and the frozen evidence coverage set. Every key is a filled-byte test seed
 * and every nonce/timestamp is a fixed synthetic value, so the archive golden is reproducible
 * byte-for-byte. NONE of this material may ever touch live ZKZ.
 */
import { deriveWalletDek } from "./hkdf.ts";
import { sealWalletSecret, type SealedEnvelope } from "./envelope.ts";
import { ready, walletKeyFromSeedByte } from "./keys.ts";
import { encodeBase64Url as encodeBase64UrlLocal } from "../testkit/independentCrypto.ts";
import { COVERAGE_TABLES } from "./coverage.contract.ts";
import { EMPTY_TABLE_SHA256 } from "./canonical.ts";

export const NODE_ID = "11111111-1111-4111-8111-111111111111";
export const EXPORT_ID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
export const CEREMONY_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
export const IDENTITY_SIGNING_KEY_ID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";

export const CREATED_AT = "2026-07-20T00:00:00.000Z";
export const EXPORTED_AT = "2026-07-20T01:00:00.000Z";
export const KEY_VERSION = 1;

/** Synthetic boot roots (already-derived PBKDF2 outputs; PBKDF2 itself is the wallet-vault envelope freeze's frozen
 *  once-at-boot parameter, pinned in the vault lane). Epoch 1 seals the golden archive. */
export const ROOT_EPOCH_1 = new Uint8Array(32).fill(0xa1);
export const ROOT_EPOCH_2 = new Uint8Array(32).fill(0xa2);
export const ROOT_WRONG = new Uint8Array(32).fill(0xbb);

export type WalletState = "AVAILABLE" | "QUARANTINED" | "RETIRED";

export interface WalletDef {
  readonly id: string;
  readonly seedByte: number;
  readonly state: WalletState;
  readonly quarantineReason: string | null;
  readonly retiredAt: string | null;
}

/** Three wallets in ascending wallet_id byte sequence; states span the census's state-independence. */
export const WALLET_DEFS: readonly WalletDef[] = [
  {
    id: "aaaaaaaa-0000-4000-8000-000000000001",
    seedByte: 0x11,
    state: "AVAILABLE",
    quarantineReason: null,
    retiredAt: null,
  },
  {
    id: "aaaaaaaa-0000-4000-8000-000000000002",
    seedByte: 0x12,
    state: "QUARANTINED",
    quarantineReason: "drill-custody-investigation",
    retiredAt: null,
  },
  {
    id: "aaaaaaaa-0000-4000-8000-000000000003",
    seedByte: 0x13,
    state: "RETIRED",
    quarantineReason: null,
    retiredAt: CREATED_AT,
  },
];

/** The non-secret settings snapshot (the coverage table): keys in lexicographic ascending sequence. */
export const SETTINGS_SNAPSHOT = {
  values: {
    gateway_url: "gateway.splitchain.example",
    node_label: "fixture-drill-node",
  },
} as const;

export interface FixtureWallet {
  readonly def: WalletDef;
  readonly publicKeyB64Url: string;
  readonly secret64: Uint8Array;
  readonly envelope: SealedEnvelope;
  readonly vaultRow: Record<string, unknown>;
  readonly walletRow: Record<string, unknown>;
}

export interface DrillWorld {
  readonly root: Uint8Array;
  readonly identityPublicKeyB64Url: string;
  readonly identitySecret64: Uint8Array;
  readonly wallets: readonly FixtureWallet[];
  readonly sealedStoreRows: readonly Record<string, unknown>[];
  readonly evidenceByTable: Readonly<Record<string, readonly Record<string, unknown>[]>>;
}

const fixedNonce = (index: number): Uint8Array => new Uint8Array(12).fill(index + 1);

const buildVaultRow = (walletId: string, envelope: SealedEnvelope): Record<string, unknown> => ({
  wallet_id: walletId,
  key_version: KEY_VERSION,
  ciphertext: encodeBase64UrlLocal(envelope.ciphertext),
  nonce: encodeBase64UrlLocal(envelope.nonce),
  auth_tag: encodeBase64UrlLocal(envelope.authTag),
  ciphertext_sha256: envelope.ciphertextSha256,
  created_at: CREATED_AT,
  rotated_at: null,
});

const buildWalletRow = (def: WalletDef, publicKeyB64Url: string): Record<string, unknown> => ({
  id: def.id,
  node_id: NODE_ID,
  public_key: publicKeyB64Url,
  key_origin: "node_generated",
  state: def.state,
  recovery_verified_at: null,
  recovery_verification_id: null,
  created_at: CREATED_AT,
  retired_at: def.retiredAt,
  quarantine_reason: def.quarantineReason,
});

/**
 * Build the synthetic world with every vault row sealed under `root` (default epoch 1). Caller
 * must have awaited `ready()`. The sealed node-identity ciphertext is a synthetic stand-in: the
 * sealed store's concrete shape is the vault concern.x sub-freeze (the coverage table item 5), and the archive covers
 * its ciphertext bytes plus the public `node_signing_keys` row whatever that shape.
 */
export const buildDrillWorld = (
  root: Uint8Array = ROOT_EPOCH_1,
  defs: readonly WalletDef[] = WALLET_DEFS,
): DrillWorld => {
  const identity = walletKeyFromSeedByte(0x00);
  const wallets: FixtureWallet[] = defs.map((def, index) => {
    const key = walletKeyFromSeedByte(def.seedByte);
    const dek = deriveWalletDek(root, {
      nodeId: NODE_ID,
      walletId: def.id,
      keyVersion: String(KEY_VERSION),
    });
    const envelope = sealWalletSecret(
      dek,
      {
        nodeId: NODE_ID,
        walletId: def.id,
        keyVersion: String(KEY_VERSION),
        publicKey: key.publicKeyB64Url,
        keyOrigin: "node_generated",
      },
      key.secret64,
      fixedNonce(index),
    );
    return {
      def,
      publicKeyB64Url: key.publicKeyB64Url,
      secret64: key.secret64,
      envelope,
      vaultRow: buildVaultRow(def.id, envelope),
      walletRow: buildWalletRow(def, key.publicKeyB64Url),
    };
  });

  const sealedCiphertext = new Uint8Array(64).fill(0x5e);
  const sealedStoreRows = [
    {
      vault_secret_ref: `sealed://${IDENTITY_SIGNING_KEY_ID}`,
      sealed_ciphertext: encodeBase64UrlLocal(sealedCiphertext),
    },
  ];

  const evidenceByTable: Record<string, readonly Record<string, unknown>[]> = {};
  for (const table of COVERAGE_TABLES) {
    if (table === "wallets") evidenceByTable[table] = wallets.map((wallet) => wallet.walletRow);
    else if (table === "node_signing_key_sealed_store") evidenceByTable[table] = sealedStoreRows;
    else evidenceByTable[table] = [];
  }

  return {
    root,
    identityPublicKeyB64Url: identity.publicKeyB64Url,
    identitySecret64: identity.secret64,
    wallets,
    sealedStoreRows,
    evidenceByTable,
  };
};

/** A model live `wallets` row (the authoritative row the ceremony cross-checks and stamps). */
export interface LiveWalletRecord {
  readonly id: string;
  readonly publicKey: string;
  recoveryVerifiedAt: string | null;
  recoveryVerificationId: string | null;
}

/** A model live current-epoch `vault` row (opened read-only for the current-key possession check). */
export interface LiveVaultRow {
  readonly walletId: string;
  readonly keyVersion: number;
  readonly ciphertext: Uint8Array;
  readonly nonce: Uint8Array;
  readonly authTag: Uint8Array;
}

/** A model "live" node database: authoritative wallets, current-epoch vault, evidence counters,
 *  and the active-lease projection (which the ceremony must NEVER write). */
export interface LiveDb {
  readonly nodeId: string;
  readonly wallets: Map<string, LiveWalletRecord>;
  readonly currentEpochVault: Map<string, LiveVaultRow>;
  recoveryVerificationCount: number;
  auditLogCount: number;
  walletActiveLeases: number;
}

/** Build a model "live" database matching the world: every wallet born-blocked (unverified) and a
 *  current-epoch vault row per wallet sealed under the world's root at KEY_VERSION. The current
 *  epoch equals the archive epoch here; epoch-divergent drills supply their own live vault. */
export const buildLiveDb = (world: DrillWorld): LiveDb => {
  const wallets = new Map<string, LiveWalletRecord>();
  const currentEpochVault = new Map<string, LiveVaultRow>();
  for (const wallet of world.wallets) {
    wallets.set(wallet.def.id, {
      id: wallet.def.id,
      publicKey: wallet.publicKeyB64Url,
      recoveryVerifiedAt: null,
      recoveryVerificationId: null,
    });
    currentEpochVault.set(wallet.def.id, {
      walletId: wallet.def.id,
      keyVersion: KEY_VERSION,
      ciphertext: wallet.envelope.ciphertext,
      nonce: wallet.envelope.nonce,
      authTag: wallet.envelope.authTag,
    });
  }
  return {
    nodeId: NODE_ID,
    wallets,
    currentEpochVault,
    recoveryVerificationCount: 0,
    auditLogCount: 0,
    walletActiveLeases: 0,
  };
};

export { ready, EMPTY_TABLE_SHA256 };

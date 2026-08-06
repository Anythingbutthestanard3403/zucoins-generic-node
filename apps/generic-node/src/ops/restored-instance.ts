// Isolated RestoredInstance + RestoredVaultAccess for the recovery ceremony (throwaway, no leadership).
// Vault open is real AES-GCM over the archive's verbatim ciphertext under the operator
// master key. Process-local throwaway: never joins the network, never runs money workers,
// destroyed on every ceremony exit path.

import {
  deriveEd25519PublicKeyBase64Url,
  openWalletSecret,
  toBase64UrlPadded,
  type ActiveLeaseRecord,
  type BackupArchive,
  type BackupArchiveVault,
  type RestoredInstance,
  type RestoredVaultAccess,
  type SealedEnvelope,
  type WalletIdentity,
} from "@zucoins/node-core";

import { signWithSecret64 } from "./ed25519-ops.js";

function decodeB64Url(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, "base64url"));
}

function vaultToEnvelope(vault: BackupArchiveVault): SealedEnvelope {
  return {
    walletId: vault.wallet_id,
    keyVersion: vault.key_version,
    ciphertext: decodeB64Url(vault.ciphertext),
    nonce: decodeB64Url(vault.nonce),
    authTag: decodeB64Url(vault.auth_tag),
    ciphertextSha256: vault.ciphertext_sha256,
  };
}

export interface RestoredWalletMeta {
  readonly publicKey: string;
  readonly keyOrigin: string;
  readonly keyVersion: number;
}

export interface ThrowawayRestoredBundle {
  readonly instance: RestoredInstance;
  readonly destroyCalls: () => number;
  readonly readVault: (walletId: string) => BackupArchiveVault | undefined;
  readonly readMeta: (walletId: string) => RestoredWalletMeta | undefined;
}

export function createThrowawayRestoredInstance(): ThrowawayRestoredBundle {
  const wallets = new Map<string, RestoredWalletMeta>();
  const vaultByWallet = new Map<string, BackupArchiveVault>();
  const evidenceCounts = new Map<string, number>();
  const leases = new Map<string, ActiveLeaseRecord>();
  let leaseEpoch = 0n;
  let destroyCalls = 0;
  let destroyed = false;

  const assertAlive = (): void => {
    if (destroyed) throw new Error("restored instance destroyed");
  };

  const instance: RestoredInstance = {
    async restore(archive: BackupArchive): Promise<void> {
      assertAlive();
      wallets.clear();
      vaultByWallet.clear();
      evidenceCounts.clear();
      leases.clear();
      for (const section of archive.evidence_sections) {
        evidenceCounts.set(section.table, section.rows.length);
      }
      for (const section of archive.wallet_sections) {
        wallets.set(section.wallet_id, {
          publicKey: section.public_key,
          keyOrigin: section.key_origin,
          keyVersion: section.key_version,
        });
        vaultByWallet.set(section.wallet_id, section.vault);
      }
    },

    async readRestoredRowCounts(): Promise<ReadonlyMap<string, number>> {
      assertAlive();
      return new Map(evidenceCounts);
    },

    async countActiveLeases(): Promise<number> {
      assertAlive();
      return leases.size;
    },

    async readWallet(walletId: string) {
      assertAlive();
      const row = wallets.get(walletId);
      if (row === undefined) return null;
      return {
        walletId,
        publicKey: row.publicKey,
        recoveryVerifiedAt: null,
      };
    },

    async acquireReconciliationLease(walletId: string): Promise<ActiveLeaseRecord> {
      assertAlive();
      if (!wallets.has(walletId)) {
        throw new Error(`no restored wallet ${walletId}`);
      }
      leaseEpoch += 1n;
      const lease: ActiveLeaseRecord = {
        walletId,
        operationId: `recovery-${walletId}`,
        epoch: leaseEpoch,
        role: "RECONCILIATION",
        lifecycle: "ACTIVE",
      };
      leases.set(walletId, lease);
      return lease;
    },

    async releaseReconciliationLease(walletId: string): Promise<void> {
      assertAlive();
      leases.delete(walletId);
    },

    async readActiveLease(walletId: string): Promise<ActiveLeaseRecord | null> {
      assertAlive();
      return leases.get(walletId) ?? null;
    },

    async destroy(): Promise<void> {
      destroyCalls += 1;
      destroyed = true;
      wallets.clear();
      vaultByWallet.clear();
      evidenceCounts.clear();
      leases.clear();
    },
  };

  return {
    instance,
    destroyCalls: () => destroyCalls,
    readVault: (walletId) => vaultByWallet.get(walletId),
    readMeta: (walletId) => wallets.get(walletId),
  };
}

export interface RestoredVaultAccessDeps {
  readonly rootKey: Uint8Array;
  readonly nodeId: string;
  readonly bundle: ThrowawayRestoredBundle;
}

export function createRestoredVaultAccess(deps: RestoredVaultAccessDeps): RestoredVaultAccess {
  const openSecret = (walletId: string) => {
    const vault = deps.bundle.readVault(walletId);
    const wallet = deps.bundle.readMeta(walletId);
    if (vault === undefined || wallet === undefined) return null;
    const identity: WalletIdentity = {
      nodeId: deps.nodeId,
      walletId,
      keyVersion: vault.key_version,
      publicKey: wallet.publicKey,
      keyOrigin: wallet.keyOrigin,
    };
    try {
      return openWalletSecret(deps.rootKey, vaultToEnvelope(vault), identity);
    } catch {
      return null;
    }
  };

  return {
    async openAndDerivePublicKey(walletId: string): Promise<string | null> {
      const secret = openSecret(walletId);
      if (secret === null) return null;
      try {
        return deriveEd25519PublicKeyBase64Url(secret.bytes);
      } finally {
        secret.wipe();
      }
    },

    async sign(walletId: string, preimageBytes: Uint8Array): Promise<string> {
      const secret = openSecret(walletId);
      if (secret === null) throw new Error("restored vault row unreadable");
      try {
        return toBase64UrlPadded(signWithSecret64(secret.bytes, preimageBytes));
      } finally {
        secret.wipe();
      }
    },
  };
}

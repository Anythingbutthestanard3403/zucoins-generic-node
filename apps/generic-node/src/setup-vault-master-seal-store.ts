// Durable vault-master seal marker.
//
// Persists phase + fingerprint only — never the master key plaintext.
// Survives process restart so show-once cannot re-issue after generate/seal.

import {
  createConfiguredVaultMasterState,
  createVirginVaultMasterState,
  type VaultMasterBootstrapState,
  type VaultMasterPhase,
} from "./setup-vault-master.js";

export type DurableVaultMasterPhase = Exclude<VaultMasterPhase, "virgin">;

export interface DurableVaultMasterSeal {
  readonly phase: DurableVaultMasterPhase;
  readonly keyFingerprintHex: string;
  readonly offlineBackupAcked: boolean;
}

export interface VaultMasterSealStore {
  load(nodeId: string): Promise<DurableVaultMasterSeal | null>;
  save(nodeId: string, seal: DurableVaultMasterSeal): Promise<void>;
}

export interface VaultMasterSealSqlExecutor {
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[],
  ): Promise<{ rows: T[] }>;
}

/** In-memory seal store — tests simulate restart by hydrating a fresh bootstrap from load(). */
export function createMemoryVaultMasterSealStore(
  seed: ReadonlyMap<string, DurableVaultMasterSeal> | Record<string, DurableVaultMasterSeal> = {},
): VaultMasterSealStore {
  const map = new Map<string, DurableVaultMasterSeal>();
  if (seed instanceof Map) {
    for (const [k, v] of seed) map.set(k, { ...v });
  } else {
    for (const [k, v] of Object.entries(seed)) map.set(k, { ...v });
  }
  return {
    async load(nodeId) {
      const row = map.get(nodeId);
      return row ? { ...row } : null;
    },
    async save(nodeId, seal) {
      map.set(nodeId, { ...seal });
    },
  };
}

export function createSqlVaultMasterSealStore(sql: VaultMasterSealSqlExecutor): VaultMasterSealStore {
  return {
    async load(nodeId) {
      const { rows } = await sql.query(
        `SELECT phase, key_fingerprint_hex, offline_backup_acked
           FROM operator_vault_master_seal
          WHERE node_id = $1
          LIMIT 1`,
        [nodeId],
      );
      const row = rows[0];
      if (!row) return null;
      const phase = String(row["phase"]);
      if (phase !== "shown" && phase !== "sealed" && phase !== "configured") {
        return null;
      }
      const fp = String(row["key_fingerprint_hex"] ?? "");
      if (!/^[0-9a-f]{64}$/.test(fp)) return null;
      const acked =
        row["offline_backup_acked"] === true ||
        row["offline_backup_acked"] === "t" ||
        row["offline_backup_acked"] === "true";
      return {
        phase,
        keyFingerprintHex: fp,
        offlineBackupAcked: acked,
      };
    },
    async save(nodeId, seal) {
      await sql.query(
        `INSERT INTO operator_vault_master_seal (
           node_id, phase, key_fingerprint_hex, offline_backup_acked, updated_at
         ) VALUES ($1, $2, $3, $4, now())
         ON CONFLICT (node_id) DO UPDATE SET
           phase = EXCLUDED.phase,
           key_fingerprint_hex = EXCLUDED.key_fingerprint_hex,
           offline_backup_acked = EXCLUDED.offline_backup_acked,
           updated_at = now()`,
        [nodeId, seal.phase, seal.keyFingerprintHex, seal.offlineBackupAcked],
      );
    },
  };
}

/**
 * Hydrate process-local bootstrap from a durable seal row.
 * Never restores plaintext — pendingPlaintext is always null after restart.
 */
export function bootstrapFromDurableSeal(seal: DurableVaultMasterSeal): VaultMasterBootstrapState {
  const digest = Buffer.from(seal.keyFingerprintHex, "hex");
  return {
    phase: seal.phase,
    pendingPlaintext: null,
    offlineBackupAcked: seal.offlineBackupAcked || seal.phase === "sealed",
    keyFingerprintHex: seal.keyFingerprintHex,
    keyDigest: digest.length === 32 ? digest : null,
  };
}

/** Snapshot durable fields from live bootstrap (null if virgin or missing fingerprint). */
export function durableSealFromBootstrap(
  state: VaultMasterBootstrapState,
): DurableVaultMasterSeal | null {
  if (state.phase === "virgin") return null;
  if (!state.keyFingerprintHex || !/^[0-9a-f]{64}$/.test(state.keyFingerprintHex)) {
    return null;
  }
  return {
    phase: state.phase,
    keyFingerprintHex: state.keyFingerprintHex,
    offlineBackupAcked: state.offlineBackupAcked || state.phase === "sealed",
  };
}

/**
 * Apply a durable seal into an existing mutable bootstrap object (in-place).
 * Used at boot after createProductionRouteSurface allocated the singleton.
 */
export function applyDurableSealInPlace(
  state: VaultMasterBootstrapState,
  seal: DurableVaultMasterSeal,
): void {
  // Env-configured wins: keep configured phase, only merge offline ack.
  if (state.phase === "configured") {
    if (seal.offlineBackupAcked) state.offlineBackupAcked = true;
    return;
  }
  const hydrated = bootstrapFromDurableSeal(seal);
  state.phase = hydrated.phase;
  state.pendingPlaintext = null;
  state.offlineBackupAcked = hydrated.offlineBackupAcked;
  state.keyFingerprintHex = hydrated.keyFingerprintHex;
  state.keyDigest = hydrated.keyDigest;
}

/** Resolve boot bootstrap: env configured > durable seal > virgin. */
export function resolveVaultMasterBootstrap(opts: {
  readonly vaultMasterKey?: string | null;
  readonly durableSeal?: DurableVaultMasterSeal | null;
}): VaultMasterBootstrapState {
  const key = opts.vaultMasterKey?.trim();
  if (key !== undefined && key !== null && key.length >= 32) {
    return createConfiguredVaultMasterState(key, opts.durableSeal?.offlineBackupAcked ?? false);
  }
  if (opts.durableSeal) {
    return bootstrapFromDurableSeal(opts.durableSeal);
  }
  return createVirginVaultMasterState();
}

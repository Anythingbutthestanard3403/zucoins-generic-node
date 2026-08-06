// Durable secret-free setup_state persistence.
//
// In-memory default for tests; SQL adapter for production (migration 0003 + 0005).

import {
  EMPTY_SETUP_FLAGS,
  isPwaInstallEvidence,
  type PwaInstallEvidence,
  type SetupStateFlags,
} from "./setup-wizard.js";

export interface SetupStateStore {
  get(nodeId: string): Promise<SetupStateFlags>;
  put(nodeId: string, flags: SetupStateFlags): Promise<void>;
}

function cloneFlags(f: SetupStateFlags): SetupStateFlags {
  return { ...f };
}

export function createMemorySetupStateStore(
  seed: ReadonlyMap<string, SetupStateFlags> | Record<string, SetupStateFlags> = {},
): SetupStateStore {
  const map = new Map<string, SetupStateFlags>();
  if (seed instanceof Map) {
    for (const [k, v] of seed) map.set(k, cloneFlags(v));
  } else {
    for (const [k, v] of Object.entries(seed)) map.set(k, cloneFlags(v));
  }
  return {
    async get(nodeId) {
      return cloneFlags(map.get(nodeId) ?? EMPTY_SETUP_FLAGS);
    },
    async put(nodeId, flags) {
      map.set(nodeId, cloneFlags(flags));
    },
  };
}

export interface SetupStateSqlExecutor {
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[],
  ): Promise<{ rows: T[] }>;
}

function evidenceFromRow(raw: unknown): PwaInstallEvidence | null {
  if (isPwaInstallEvidence(raw)) return raw;
  return null;
}

/** Map a DB row (snake_case booleans + completed_at) onto SetupStateFlags. */
export function flagsFromRow(row: Record<string, unknown>): SetupStateFlags {
  const b = (k: string): boolean => row[k] === true || row[k] === "t" || row[k] === "true";
  const completed = row["completed_at"];
  const pwaAt = row["pwa_installed_at"];
  return {
    w0_secure_context_ok: b("w0_secure_context_ok"),
    w3_pwa_ack: b("w3_pwa_ack"),
    w3_pwa_skipped: b("w3_pwa_skipped"),
    pwa_installed_at:
      pwaAt instanceof Date
        ? pwaAt.toISOString()
        : typeof pwaAt === "string"
          ? pwaAt
          : null,
    pwa_install_evidence: evidenceFromRow(row["pwa_install_evidence"]),
    w4_device_enrolled: b("w4_device_enrolled"),
    w4_break_glass_ack: b("w4_break_glass_ack"),
    w5_vault_ready: b("w5_vault_ready"),
    w5_offline_backup_ack: b("w5_offline_backup_ack"),
    w6_ceremony_placeholder_ack: b("w6_ceremony_placeholder_ack"),
    w7_recovery_wallet_ok: b("w7_recovery_wallet_ok"),
    w8_implementer_key_ack: b("w8_implementer_key_ack"),
    w8_implementer_skipped: b("w8_implementer_skipped"),
    w9_reporting_key_ok: b("w9_reporting_key_ok"),
    w10_packs_ack: b("w10_packs_ack"),
    w10_packs_skipped: b("w10_packs_skipped"),
    w11_mini_steps_ack: b("w11_mini_steps_ack"),
    w11_mini_steps_skipped: b("w11_mini_steps_skipped"),
    completed_at:
      completed instanceof Date
        ? completed.toISOString()
        : typeof completed === "string"
          ? completed
          : null,
  };
}

export function createSqlSetupStateStore(sql: SetupStateSqlExecutor): SetupStateStore {
  return {
    async get(nodeId) {
      const { rows } = await sql.query(
        `SELECT w0_secure_context_ok, w3_pwa_ack, w3_pwa_skipped,
                pwa_installed_at, pwa_install_evidence,
                w4_device_enrolled, w4_break_glass_ack,
                w5_vault_ready, w5_offline_backup_ack,
                w6_ceremony_placeholder_ack, w7_recovery_wallet_ok,
                w8_implementer_key_ack, w8_implementer_skipped,
                w9_reporting_key_ok,
                w10_packs_ack, w10_packs_skipped,
                w11_mini_steps_ack, w11_mini_steps_skipped,
                completed_at
           FROM operator_setup_state
          WHERE node_id = $1
          LIMIT 1`,
        [nodeId],
      );
      const row = rows[0];
      if (!row) return { ...EMPTY_SETUP_FLAGS };
      return flagsFromRow(row);
    },
    async put(nodeId, flags) {
      await sql.query(
        `INSERT INTO operator_setup_state (
           node_id,
           w0_secure_context_ok, w3_pwa_ack, w3_pwa_skipped,
           pwa_installed_at, pwa_install_evidence,
           w4_device_enrolled, w4_break_glass_ack,
           w5_vault_ready, w5_offline_backup_ack,
           w6_ceremony_placeholder_ack, w7_recovery_wallet_ok,
           w8_implementer_key_ack, w8_implementer_skipped,
           w9_reporting_key_ok,
           w10_packs_ack, w10_packs_skipped,
           w11_mini_steps_ack, w11_mini_steps_skipped,
           completed_at, updated_at
         ) VALUES (
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20, now()
         )
         ON CONFLICT (node_id) DO UPDATE SET
           w0_secure_context_ok = EXCLUDED.w0_secure_context_ok,
           w3_pwa_ack = EXCLUDED.w3_pwa_ack,
           w3_pwa_skipped = EXCLUDED.w3_pwa_skipped,
           pwa_installed_at = EXCLUDED.pwa_installed_at,
           pwa_install_evidence = EXCLUDED.pwa_install_evidence,
           w4_device_enrolled = EXCLUDED.w4_device_enrolled,
           w4_break_glass_ack = EXCLUDED.w4_break_glass_ack,
           w5_vault_ready = EXCLUDED.w5_vault_ready,
           w5_offline_backup_ack = EXCLUDED.w5_offline_backup_ack,
           w6_ceremony_placeholder_ack = EXCLUDED.w6_ceremony_placeholder_ack,
           w7_recovery_wallet_ok = EXCLUDED.w7_recovery_wallet_ok,
           w8_implementer_key_ack = EXCLUDED.w8_implementer_key_ack,
           w8_implementer_skipped = EXCLUDED.w8_implementer_skipped,
           w9_reporting_key_ok = EXCLUDED.w9_reporting_key_ok,
           w10_packs_ack = EXCLUDED.w10_packs_ack,
           w10_packs_skipped = EXCLUDED.w10_packs_skipped,
           w11_mini_steps_ack = EXCLUDED.w11_mini_steps_ack,
           w11_mini_steps_skipped = EXCLUDED.w11_mini_steps_skipped,
           completed_at = EXCLUDED.completed_at,
           updated_at = now()`,
        [
          nodeId,
          flags.w0_secure_context_ok,
          flags.w3_pwa_ack,
          flags.w3_pwa_skipped,
          flags.pwa_installed_at,
          flags.pwa_install_evidence,
          flags.w4_device_enrolled,
          flags.w4_break_glass_ack,
          flags.w5_vault_ready,
          flags.w5_offline_backup_ack,
          flags.w6_ceremony_placeholder_ack,
          flags.w7_recovery_wallet_ok,
          flags.w8_implementer_key_ack,
          flags.w8_implementer_skipped,
          flags.w9_reporting_key_ok,
          flags.w10_packs_ack,
          flags.w10_packs_skipped,
          flags.w11_mini_steps_ack,
          flags.w11_mini_steps_skipped,
          flags.completed_at,
        ],
      );
    },
  };
}

// SQL-backed operator halt ports over node_settings (kind-scoped operator halt).
// Single durable record — no schema migration. HaltStore state is overlaid with
// display metadata (reason/actor/time) on the same JSON row.

import {
  HALTED,
  type HaltState,
  type HaltStore,
} from "./halt.js";
import {
  createDurableHaltEvidenceRecorder,
  type HaltEvidenceRecorder,
  type HaltEvidenceStore,
} from "./halt-evidence.js";
import type { SqlExecutor } from "./sql-store.js";

/** node_settings key — operational latch, hunamespaced under ops. */
export const OPERATOR_HALT_SETTING_KEY = "ops.operator_halt";

/** Sibling key for the append-only evidence trail (truncated to newest N). */
export const OPERATOR_HALT_EVIDENCE_SETTING_KEY = "ops.operator_halt_evidence";

export interface OperatorHaltDisplay {
  readonly engaged: boolean;
  readonly reason: string | null;
  readonly updatedAt: string | null;
  readonly updatedBy: string | null;
}

interface HaltRowValue {
  readonly state: HaltState;
  readonly reason: string | null;
  readonly updated_by: string | null;
  readonly updated_at: string | null;
}

export interface OperatorHaltStore extends HaltStore {
  /** Best-effort display read (GET). Corrupt/missing → disengaged for display only. */
  readDisplay(): Promise<OperatorHaltDisplay>;
  /** Durable write that keeps reason/actor metadata with the state flip. */
  writeWithMeta(
    state: HaltState,
    meta: { readonly reason: string | null; readonly actor: string },
  ): Promise<void>;
}

function parseHaltRow(raw: string): HaltRowValue | null {
  let decoded: unknown;
  try {
    decoded = JSON.parse(raw);
  } catch {
    return null;
  }
  if (decoded === null || typeof decoded !== "object" || Array.isArray(decoded)) {
    return null;
  }
  const obj = decoded as Record<string, unknown>;
  if (obj.state !== "HALTED" && obj.state !== "RUNNING") return null;
  return {
    state: obj.state,
    reason: typeof obj.reason === "string" ? obj.reason : null,
    updated_by: typeof obj.updated_by === "string" ? obj.updated_by : null,
    updated_at: typeof obj.updated_at === "string" ? obj.updated_at : null,
  };
}

export function createNodeSettingsHaltStore(sql: SqlExecutor): OperatorHaltStore {
  const readRaw = async (): Promise<string | null> => {
    const result = await sql.query<{ setting_value: string }>(
      "SELECT setting_value FROM node_settings WHERE setting_key = $1",
      [OPERATOR_HALT_SETTING_KEY],
    );
    return result.rows[0]?.setting_value ?? null;
  };

  const writeRaw = async (value: string): Promise<void> => {
    await sql.query(
      `INSERT INTO node_settings (setting_key, setting_value, row_version, updated_at)
       VALUES ($1, $2, 1, now())
       ON CONFLICT (setting_key) DO UPDATE
       SET setting_value = EXCLUDED.setting_value,
           row_version = node_settings.row_version + 1,
           updated_at = now()`,
      [OPERATOR_HALT_SETTING_KEY, value],
    );
  };

  return {
    read: async () => {
      const raw = await readRaw();
      if (raw === null) return null;
      const parsed = parseHaltRow(raw);
      return parsed === null ? null : parsed.state;
    },
    write: async (state) => {
      const raw = await readRaw();
      const prev = raw === null ? null : parseHaltRow(raw);
      const next: HaltRowValue = {
        state,
        reason: prev?.reason ?? null,
        updated_by: prev?.updated_by ?? null,
        updated_at: new Date().toISOString(),
      };
      await writeRaw(JSON.stringify(next));
    },
    writeWithMeta: async (state, meta) => {
      const next: HaltRowValue = {
        state,
        reason: meta.reason,
        updated_by: meta.actor,
        updated_at: new Date().toISOString(),
      };
      await writeRaw(JSON.stringify(next));
    },
    readDisplay: async () => {
      const raw = await readRaw();
      if (raw === null) {
        return { engaged: false, reason: null, updatedAt: null, updatedBy: null };
      }
      const parsed = parseHaltRow(raw);
      if (parsed === null) {
        return { engaged: false, reason: null, updatedAt: null, updatedBy: null };
      }
      return {
        engaged: parsed.state === HALTED,
        reason: parsed.reason,
        updatedAt: parsed.updated_at,
        updatedBy: parsed.updated_by,
      };
    },
  };
}

export function createNodeSettingsHaltEvidenceStore(sql: SqlExecutor): HaltEvidenceStore {
  return {
    read: async () => {
      const result = await sql.query<{ setting_value: string }>(
        "SELECT setting_value FROM node_settings WHERE setting_key = $1",
        [OPERATOR_HALT_EVIDENCE_SETTING_KEY],
      );
      return result.rows[0]?.setting_value ?? null;
    },
    write: async (value) => {
      await sql.query(
        `INSERT INTO node_settings (setting_key, setting_value, row_version, updated_at)
         VALUES ($1, $2, 1, now())
         ON CONFLICT (setting_key) DO UPDATE
         SET setting_value = EXCLUDED.setting_value,
             row_version = node_settings.row_version + 1,
             updated_at = now()`,
        [OPERATOR_HALT_EVIDENCE_SETTING_KEY, value],
      );
    },
  };
}

export function createNodeSettingsHaltEvidenceRecorder(
  sql: SqlExecutor,
): HaltEvidenceRecorder {
  return createDurableHaltEvidenceRecorder(createNodeSettingsHaltEvidenceStore(sql));
}

/** In-memory HaltStore used by unit tests and fail-closed boots without SQL. */
export function createInMemoryOperatorHaltStore(
  initial: HaltState | null = null,
): OperatorHaltStore {
  let value: HaltRowValue | null =
    initial === null
      ? null
      : {
          state: initial,
          reason: null,
          updated_by: null,
          updated_at: null,
        };
  return {
    read: async () => value?.state ?? null,
    write: async (state) => {
      value = {
        state,
        reason: value?.reason ?? null,
        updated_by: value?.updated_by ?? null,
        updated_at: new Date().toISOString(),
      };
    },
    writeWithMeta: async (state, meta) => {
      value = {
        state,
        reason: meta.reason,
        updated_by: meta.actor,
        updated_at: new Date().toISOString(),
      };
    },
    readDisplay: async () => {
      if (value === null) {
        return { engaged: false, reason: null, updatedAt: null, updatedBy: null };
      }
      return {
        engaged: value.state === HALTED,
        reason: value.reason,
        updatedAt: value.updated_at,
        updatedBy: value.updated_by,
      };
    },
  };
}

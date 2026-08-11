// Dual-control approval policy.
//
// Modes:
// - single_operator: same admin_operator may issue the approval-challenge and approve.
// - two_human: distinct admin_operator on challenge vs approve; same operator both sides → fail closed.
//
// Server enforces; SPA copy must match. An unset setting means the deployment added
// no optional policy — doc 01 §4.2 makes node policy opt-in — which is single_operator.
// A setting that is PRESENT but unrecognised never resolves to a mode; see
// parseDualControlMode.
//
// Durable home (ZTR-1214): node_settings key ops.dual_control_mode + audit_log on change.
// Guarded admin POST requires fresh TOTP. Boot-validated DUAL_CONTROL_MODE is the
// pre-mutation default when the row is absent; after setMode the DB is source of truth.

import { createHash, randomUUID } from "node:crypto";

import type { SqlExecutor } from "./sql-store.js";

export const DUAL_CONTROL_MODES = ["single_operator", "two_human"] as const;
export type DualControlMode = (typeof DUAL_CONTROL_MODES)[number];

export const DUAL_CONTROL_SETTING_KEY = "ops.dual_control_mode" as const;

/** Plain-language labels for inbox + Pack P / security notes. */
export const DUAL_CONTROL_COPY: Readonly<
  Record<
    DualControlMode,
    {
      readonly short: string;
      readonly long: string;
      readonly approve_hint: string;
    }
  >
> = {
  single_operator: {
    short: "Single-operator",
    long: "One human may both request the approval challenge and approve. TOTP + device still required when enrolled.",
    approve_hint: "You may approve sends you challenged (single-operator mode).",
  },
  two_human: {
    short: "Two-human dual control",
    long: "A different admin operator must approve than the one who requested the challenge. Same person on both sides is rejected.",
    approve_hint: "A different operator must approve (two-human dual control).",
  },
};

/**
 * Resolve a configured dual-control setting, fail closed (doc 01 §4.2).
 *
 * Only an exact mode literal selects a mode. Absence selects the documented
 * "no optional policy" default. Everything else — `two-human`, `TWO_HUMAN`,
 * `" two_human"`, `""` — is `"invalid"`: the caller must refuse to boot rather
 * than pick a mode, because silently picking one always picks the weaker one.
 * The production caller is the frozen schema's DUAL_CONTROL_MODE field
 * (apps/generic-node/src/config/env-schema.ts), which rejects the same set.
 */
export function parseDualControlMode(
  raw: string | null | undefined,
): DualControlMode | "invalid" {
  if (raw === null || raw === undefined) return "single_operator";
  return (DUAL_CONTROL_MODES as readonly string[]).includes(raw)
    ? (raw as DualControlMode)
    : "invalid";
}

/**
 * Effective mode for a stored node_settings value.
 * - absent/null → `defaultMode` (boot-validated env, or single_operator)
 * - exact literal → that mode
 * - unrecognised → `two_human` (stricter; never silently weaken)
 */
export function effectiveDualControlMode(
  raw: string | null | undefined,
  defaultMode: DualControlMode = "single_operator",
): DualControlMode {
  if (raw === null || raw === undefined) return defaultMode;
  const parsed = parseDualControlMode(raw);
  if (parsed === "invalid") return "two_human";
  return parsed;
}

export function dualControlModeLabel(mode: DualControlMode): string {
  return DUAL_CONTROL_COPY[mode].short;
}

export type DualControlCheckResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly code: "same_operator_both_sides";
      readonly detail: string;
    };

/**
 * Enforce two-human distinctness. `challengeOperatorId` is the admin_operators.id
 * that issued/refreshed the approval challenge; `approverOperatorId` is the
 * session user approving.
 */
export function enforceDualControlOperators(
  mode: DualControlMode,
  challengeOperatorId: string | null | undefined,
  approverOperatorId: string,
): DualControlCheckResult {
  if (mode !== "two_human") {
    return { ok: true };
  }
  if (
    typeof challengeOperatorId === "string" &&
    challengeOperatorId.length > 0 &&
    challengeOperatorId === approverOperatorId
  ) {
    return {
      ok: false,
      code: "same_operator_both_sides",
      detail:
        "Two-human dual control requires a different admin operator to approve than the one who requested the challenge.",
    };
  }
  // No recorded challenge issuer → cannot prove distinctness; fail closed in two_human.
  if (challengeOperatorId === null || challengeOperatorId === undefined || challengeOperatorId.length === 0) {
    return {
      ok: false,
      code: "same_operator_both_sides",
      detail:
        "Two-human dual control requires a recorded challenge issuer; re-issue the approval challenge.",
    };
  }
  return { ok: true };
}

export interface DualControlPolicySetMeta {
  readonly actorId: string;
  readonly nodeId: string;
}

export interface DualControlPolicyPort {
  getMode(): DualControlMode | Promise<DualControlMode>;
  /**
   * Persist a new mode. High-authority: callers must gate with fresh TOTP.
   * Implementations write audit_log. Optional only for pure read ports in tests.
   */
  setMode?(
    mode: DualControlMode,
    meta: DualControlPolicySetMeta,
  ): void | Promise<void>;
}

export function fixedDualControlPolicy(mode: DualControlMode): DualControlPolicyPort {
  return { getMode: () => mode };
}

/**
 * In-memory policy for tests / lab.
 * Default `two_human` matches fail-closed so an unwired test mount does not
 * silently admit same-operator EXTERNAL SEND approve (peer device-sig → required).
 */
export class InMemoryDualControlPolicy implements DualControlPolicyPort {
  readonly auditEntries: Array<{
    readonly mode: DualControlMode;
    readonly actorId: string;
    readonly nodeId: string;
  }> = [];

  constructor(private mode: DualControlMode = "two_human") {}

  getMode(): DualControlMode {
    return this.mode;
  }

  setMode(mode: DualControlMode, meta: DualControlPolicySetMeta): void {
    this.mode = mode;
    this.auditEntries.push({
      mode,
      actorId: meta.actorId,
      nodeId: meta.nodeId,
    });
  }
}

function detailsSha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/**
 * SQL-backed policy over `node_settings` + `audit_log`.
 *
 * When the row is absent, `defaultMode` (boot-validated DUAL_CONTROL_MODE) is
 * returned so env still drives pre-mutation behaviour. After setMode the DB row
 * is source of truth across restarts.
 *
 * Fail closed (doc 01 §4.2 / ZTR-1214): unreadable store and corrupt stored
 * values both resolve to `two_human` — never silently weaken a durable two_human
 * row to boot defaultMode on a transient query fault (peer device-sig → required).
 */
export function createSqlDualControlPolicy(
  sql: SqlExecutor,
  opts?: {
    readonly newId?: () => string;
    readonly defaultMode?: DualControlMode;
  },
): DualControlPolicyPort {
  const newId = opts?.newId ?? (() => randomUUID());
  const defaultMode = opts?.defaultMode ?? "single_operator";

  async function readRaw(): Promise<
    { readonly ok: true; readonly value: string | null } | { readonly ok: false }
  > {
    try {
      const result = await sql.query<{ setting_value: string }>(
        "SELECT setting_value FROM node_settings WHERE setting_key = $1",
        [DUAL_CONTROL_SETTING_KEY],
      );
      return { ok: true, value: result.rows[0]?.setting_value ?? null };
    } catch {
      return { ok: false };
    }
  }

  return {
    async getMode(): Promise<DualControlMode> {
      const raw = await readRaw();
      // Unreadable ≠ absent: absence may use boot defaultMode; read fault never
      // weakens past two_human (same class as corrupt stored values).
      if (!raw.ok) return "two_human";
      return effectiveDualControlMode(raw.value, defaultMode);
    },

    async setMode(
      mode: DualControlMode,
      meta: DualControlPolicySetMeta,
    ): Promise<void> {
      if (mode !== "single_operator" && mode !== "two_human") {
        throw new Error("unrecognised dual-control policy mode");
      }
      // Previous mode is resolved fail-closed before the write so the audit row
      // records the effective gate an operator was changing, not a weakened default.
      const previous = await readRaw();
      const previousMode = previous.ok
        ? effectiveDualControlMode(previous.value, defaultMode)
        : "two_human";

      const details =
        "setting_key=" +
        DUAL_CONTROL_SETTING_KEY +
        ";previous=" +
        previousMode +
        ";next=" +
        mode;
      const detailsSha = detailsSha256(details);

      // Single statement: settings upsert + audit insert. Either both land or
      // neither does — even when the caller has not opened an outer TX. When
      // bound to the admin mutation PoolClient, this also rides that TX so a
      // later ROLLBACK undoes the policy flip with the idempotency row.
      await sql.query(
        `WITH upserted AS (
           INSERT INTO node_settings (setting_key, setting_value, row_version, updated_at)
           VALUES ($1, $2, 1, now())
           ON CONFLICT (setting_key) DO UPDATE
           SET setting_value = EXCLUDED.setting_value,
               row_version = node_settings.row_version + 1,
               updated_at = now()
           RETURNING setting_key
         )
         INSERT INTO audit_log (
           id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
           details_text, details_sha256, created_at
         )
         SELECT
           $3::uuid, $4::uuid, 'OPERATOR_SESSION', $5,
           'ops.dual_control_mode_changed', NULL, NULL,
           $6, $7, now()
         FROM upserted`,
        [
          DUAL_CONTROL_SETTING_KEY,
          mode,
          newId(),
          meta.nodeId,
          meta.actorId,
          details,
          detailsSha,
        ],
      );
    },
  };
}

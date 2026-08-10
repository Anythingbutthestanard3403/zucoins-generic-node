// Additive device-signature policy for external-send approval (doc 07 §17.10).
// Server-side source of truth in node_settings — never decided by the request alone.
// Fail closed (doc 01 §4.2): unreadable, absent, or unrecognised ⇒ require the device factor.

import { createHash, randomUUID } from "node:crypto";

import type { SqlExecutor } from "./sql-store.js";

export const DEVICE_SIGNATURE_POLICY_MODES = ["required", "optional"] as const;
export type DeviceSignaturePolicyMode = (typeof DEVICE_SIGNATURE_POLICY_MODES)[number];

/** node_settings key — auditable approval factor policy. */
export const DEVICE_SIGNATURE_POLICY_SETTING_KEY =
  "ops.approval_device_signature" as const;

export const DEVICE_SIGNATURE_POLICY_COPY: Record<
  DeviceSignaturePolicyMode,
  { readonly short: string; readonly long: string; readonly approve_hint: string }
> = {
  required: {
    short: "Device signature required",
    long: "External-send approval requires both a fresh single-use TOTP and a valid signature from an enrolled operator device (additive device policy).",
    approve_hint: "Approve with TOTP and a signature from an enrolled device key.",
  },
  optional: {
    short: "Device signature optional",
    long: "External-send approval requires a fresh single-use TOTP. A device signature is optional; when an enrolled device volunteers one it is verified.",
    approve_hint: "Approve with TOTP. Device signature is optional but verified when supplied.",
  },
};

/**
 * Parse a configured device-signature setting.
 * Only the exact literals are accepted; everything else is `invalid`
 * (including empty string and near-miss spellings). Callers must fail closed.
 */
export function parseDeviceSignaturePolicyMode(
  raw: string | null | undefined,
): DeviceSignaturePolicyMode | "invalid" {
  if (raw === "required" || raw === "optional") return raw;
  return "invalid";
}

/**
 * Resolve whether the device signature is required.
 * Fail closed: only the exact literal `optional` yields false. Absent,
 * unrecognised, empty, or any other value requires the device factor.
 */
export function resolveDeviceSignatureRequired(
  raw: string | null | undefined,
): boolean {
  return parseDeviceSignaturePolicyMode(raw) !== "optional";
}

/** Effective mode after fail-closed resolution (always a real mode). */
export function effectiveDeviceSignaturePolicyMode(
  raw: string | null | undefined,
): DeviceSignaturePolicyMode {
  return resolveDeviceSignatureRequired(raw) ? "required" : "optional";
}

/**
 * Combine server policy with a volunteered request pair.
 * Policy alone must never be the only gate that can turn the factor off;
 * a caller may still supply device fields when policy is optional, and those
 * must be verified (`policy OR request`).
 */
export function combineDeviceSignatureRequirement(
  policyRequires: boolean,
  requestSupplied: boolean,
): boolean {
  return policyRequires || requestSupplied;
}

export interface DeviceSignaturePolicySetMeta {
  readonly actorId: string;
  readonly nodeId: string;
}

export interface DeviceSignaturePolicyPort {
  /** True when approvals must carry a device signature (fail closed on fault). */
  requiresDeviceSignature(): boolean | Promise<boolean>;
  /** Effective mode after fail-closed resolution. */
  getMode(): DeviceSignaturePolicyMode | Promise<DeviceSignaturePolicyMode>;
  /**
   * Persist a new mode. High-authority: callers must gate with fresh TOTP.
   * Implementations write audit_log. Optional only for pure read ports in tests.
   */
  setMode?(
    mode: DeviceSignaturePolicyMode,
    meta: DeviceSignaturePolicySetMeta,
  ): void | Promise<void>;
}

export function fixedDeviceSignaturePolicy(
  mode: DeviceSignaturePolicyMode,
): DeviceSignaturePolicyPort {
  return {
    requiresDeviceSignature: () => mode === "required",
    getMode: () => mode,
  };
}

/**
 * In-memory policy. Default `required` matches fail-closed so an unwired
 * test mount does not silently admit TOTP-only approvals.
 */
export class InMemoryDeviceSignaturePolicy implements DeviceSignaturePolicyPort {
  readonly auditEntries: Array<{
    readonly mode: DeviceSignaturePolicyMode;
    readonly actorId: string;
    readonly nodeId: string;
  }> = [];

  constructor(private mode: DeviceSignaturePolicyMode = "required") {}

  requiresDeviceSignature(): boolean {
    return this.mode === "required";
  }

  getMode(): DeviceSignaturePolicyMode {
    return this.mode;
  }

  setMode(mode: DeviceSignaturePolicyMode, meta: DeviceSignaturePolicySetMeta): void {
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
 * Read errors and missing rows fail closed (require device signature).
 */
export function createSqlDeviceSignaturePolicy(
  sql: SqlExecutor,
  opts?: { readonly newId?: () => string },
): DeviceSignaturePolicyPort {
  const newId = opts?.newId ?? (() => randomUUID());

  async function readRaw(): Promise<
    { readonly ok: true; readonly value: string | null } | { readonly ok: false }
  > {
    try {
      const result = await sql.query<{ setting_value: string }>(
        "SELECT setting_value FROM node_settings WHERE setting_key = $1",
        [DEVICE_SIGNATURE_POLICY_SETTING_KEY],
      );
      return { ok: true, value: result.rows[0]?.setting_value ?? null };
    } catch {
      return { ok: false };
    }
  }

  return {
    async requiresDeviceSignature(): Promise<boolean> {
      const raw = await readRaw();
      if (!raw.ok) return true;
      return resolveDeviceSignatureRequired(raw.value);
    },

    async getMode(): Promise<DeviceSignaturePolicyMode> {
      const raw = await readRaw();
      if (!raw.ok) return "required";
      return effectiveDeviceSignaturePolicyMode(raw.value);
    },

    async setMode(
      mode: DeviceSignaturePolicyMode,
      meta: DeviceSignaturePolicySetMeta,
    ): Promise<void> {
      if (mode !== "required" && mode !== "optional") {
        throw new Error("unrecognised device-signature policy mode");
      }
      // Previous mode is resolved fail-closed before the write so the audit row
      // records the effective gate an operator was changing, not a raw NULL.
      const previous = await readRaw();
      const previousMode = previous.ok
        ? effectiveDeviceSignaturePolicyMode(previous.value)
        : "required";

      const details =
        "setting_key=" +
        DEVICE_SIGNATURE_POLICY_SETTING_KEY +
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
           'approval.device_signature_policy_changed', NULL, NULL,
           $6, $7, now()
         FROM upserted`,
        [
          DEVICE_SIGNATURE_POLICY_SETTING_KEY,
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

// Operator policy gating NODE_VERIFIED at admission (ZTR-1301).
//
// Storage: node_settings key ops.allow_node_verified (contracts ALLOW_NODE_VERIFIED_SETTING_KEY)
// + audit_log on change (ALLOW_NODE_VERIFIED_POLICY_CHANGED_ACTION). Parallel to
// ops.auto_approve_sends / dual-control-policy: fail-closed. Absent key, unreadable
// store, invalid JSON, unknown fields, bad types, or enabled:false all refuse
// NODE_VERIFIED. Never silently downgrade a denied NODE_VERIFIED to INDEPENDENT.
//
// Document shape (closed keys):
//   { "enabled": boolean, "implementers": [ { "implementer_id": uuid, "enabled": boolean } ] }
// An implementer is allowed only when the document is enabled AND that implementer's
// entry exists with enabled:true. Duplicate implementer ids invalidate the document.

import { createHash, randomUUID } from "node:crypto";

import {
  ALLOW_NODE_VERIFIED_POLICY_CHANGED_ACTION,
  ALLOW_NODE_VERIFIED_SETTING_KEY,
  DEFAULT_VERIFICATION_MODE,
  VERIFICATION_MODES,
  type VerificationMode,
} from "@zucoins/generic-node-contracts/operations";

import { parseUuid } from "../protocol/scalars.js";

export {
  ALLOW_NODE_VERIFIED_POLICY_CHANGED_ACTION,
  ALLOW_NODE_VERIFIED_SETTING_KEY,
  DEFAULT_VERIFICATION_MODE,
  VERIFICATION_MODES,
};
export type { VerificationMode };

export type AllowNodeVerifiedDisabledReason =
  | "absent"
  | "unreadable"
  | "invalid"
  | "off";

export interface AllowNodeVerifiedImplementerEntry {
  readonly implementer_id: string;
  readonly enabled: boolean;
}

export type AllowNodeVerifiedPolicyDocument =
  | {
      readonly status: "disabled";
      readonly disabledReason: AllowNodeVerifiedDisabledReason;
      /** Present when disabledReason is "off" so operators can edit parked entries. */
      readonly implementers?: readonly AllowNodeVerifiedImplementerEntry[];
    }
  | {
      readonly status: "enabled";
      readonly implementers: readonly AllowNodeVerifiedImplementerEntry[];
    };

export interface AllowNodeVerifiedPolicySetMeta {
  readonly actorId: string;
  readonly nodeId: string;
}

/**
 * Read port used at admission. Implementations must fail closed: any uncertainty
 * returns false for isNodeVerifiedAllowed.
 */
export interface AllowNodeVerifiedPolicyPort {
  getPolicy(): AllowNodeVerifiedPolicyDocument | Promise<AllowNodeVerifiedPolicyDocument>;
  /**
   * True only when operator policy explicitly enables NODE_VERIFIED for this
   * implementer. Fail-closed on every other state.
   */
  isNodeVerifiedAllowed(implementerId: string): boolean | Promise<boolean>;
  /**
   * Persist a new policy document. High-authority: callers must gate with fresh TOTP.
   * Optional only for pure read ports in tests.
   */
  setPolicy?(
    documentJson: string,
    meta: AllowNodeVerifiedPolicySetMeta,
  ): void | Promise<void>;
}

// ─── fail-closed parser ────────────────────────────────────────────────────

const ENTRY_KEYS = new Set(["implementer_id", "enabled"]);
const TOP_KEYS = new Set(["enabled", "implementers"]);
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

type ParseStructureResult =
  | { readonly ok: false; readonly reason: "absent" | "invalid" }
  | {
      readonly ok: true;
      readonly enabled: boolean;
      readonly implementers: readonly AllowNodeVerifiedImplementerEntry[];
    };

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Structural parse only. Unknown keys / bad types / duplicate implementer ids
 * invalidate the whole document (no partial apply).
 */
export function parseAllowNodeVerifiedPolicyStructure(
  raw: string | null | undefined,
): ParseStructureResult {
  if (raw === null || raw === undefined) {
    return { ok: false, reason: "absent" };
  }
  if (typeof raw !== "string" || raw.length === 0) {
    return { ok: false, reason: "invalid" };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    return { ok: false, reason: "invalid" };
  }
  if (!isPlainObject(parsed)) return { ok: false, reason: "invalid" };

  for (const key of Object.keys(parsed)) {
    if (!TOP_KEYS.has(key)) return { ok: false, reason: "invalid" };
  }
  if (typeof parsed.enabled !== "boolean") return { ok: false, reason: "invalid" };
  if (!Array.isArray(parsed.implementers)) return { ok: false, reason: "invalid" };

  const implementers: AllowNodeVerifiedImplementerEntry[] = [];
  const seen = new Set<string>();

  for (const entry of parsed.implementers) {
    if (!isPlainObject(entry)) return { ok: false, reason: "invalid" };
    for (const key of Object.keys(entry)) {
      if (!ENTRY_KEYS.has(key)) return { ok: false, reason: "invalid" };
    }
    if (typeof entry.implementer_id !== "string") return { ok: false, reason: "invalid" };
    if (typeof entry.enabled !== "boolean") return { ok: false, reason: "invalid" };
    if (!UUID_RE.test(entry.implementer_id)) return { ok: false, reason: "invalid" };
    let implementerId: string;
    try {
      implementerId = parseUuid(entry.implementer_id);
    } catch {
      return { ok: false, reason: "invalid" };
    }
    if (seen.has(implementerId)) return { ok: false, reason: "invalid" };
    seen.add(implementerId);
    implementers.push({ implementer_id: implementerId, enabled: entry.enabled });
  }

  return { ok: true, enabled: parsed.enabled, implementers };
}

/**
 * Fail-closed parse of the ops.allow_node_verified JSON document.
 * Only a fully valid document with enabled:true yields status "enabled".
 */
export function parseAllowNodeVerifiedPolicyDocument(
  raw: string | null | undefined,
): AllowNodeVerifiedPolicyDocument {
  const structured = parseAllowNodeVerifiedPolicyStructure(raw);
  if (!structured.ok) {
    return { status: "disabled", disabledReason: structured.reason };
  }
  if (!structured.enabled) {
    return {
      status: "disabled",
      disabledReason: "off",
      implementers: structured.implementers,
    };
  }
  return { status: "enabled", implementers: structured.implementers };
}

/** Serialise a validated document back to canonical JSON text for storage. */
export function serializeAllowNodeVerifiedPolicyDocument(
  implementers: readonly AllowNodeVerifiedImplementerEntry[],
  enabled = true,
): string {
  return JSON.stringify({
    enabled,
    implementers: implementers.map((e) => ({
      implementer_id: e.implementer_id,
      enabled: e.enabled,
    })),
  });
}

/**
 * Pure allow check. NODE_VERIFIED is admitted only when the document is enabled
 * and the implementer has an entry with enabled:true.
 */
export function isNodeVerifiedAllowedByPolicy(
  policy: AllowNodeVerifiedPolicyDocument,
  implementerId: string | null | undefined,
): boolean {
  if (policy.status !== "enabled") return false;
  if (
    implementerId === null ||
    implementerId === undefined ||
    implementerId.length === 0
  ) {
    return false;
  }
  let id: string;
  try {
    id = parseUuid(implementerId);
  } catch {
    return false;
  }
  const entry = policy.implementers.find((e) => e.implementer_id === id);
  return entry !== undefined && entry.enabled === true;
}

/**
 * Resolve the admission-time verification mode from an optional request field.
 * Omitted / undefined → INDEPENDENT (DEFAULT_VERIFICATION_MODE).
 */
export function resolveVerificationMode(
  requested: VerificationMode | null | undefined,
): VerificationMode {
  if (requested === null || requested === undefined) {
    return DEFAULT_VERIFICATION_MODE;
  }
  if ((VERIFICATION_MODES as readonly string[]).includes(requested)) {
    return requested;
  }
  // Callers must validate against VERIFICATION_MODES before this; refuse unknown.
  return DEFAULT_VERIFICATION_MODE;
}

/**
 * Whether the resolved mode may proceed under the given policy.
 * INDEPENDENT always allowed; NODE_VERIFIED only when policy allows the implementer.
 */
export function admitVerificationMode(
  mode: VerificationMode,
  policy: AllowNodeVerifiedPolicyDocument,
  implementerId: string,
): { readonly ok: true } | { readonly ok: false; readonly code: "verification_mode_not_allowed" } {
  if (mode === "INDEPENDENT") return { ok: true };
  if (mode === "NODE_VERIFIED" && isNodeVerifiedAllowedByPolicy(policy, implementerId)) {
    return { ok: true };
  }
  return { ok: false, code: "verification_mode_not_allowed" };
}

/** Fixed refuse-all port — default when operator policy is unwired (fail closed). */
export function refuseAllNodeVerifiedPolicy(): AllowNodeVerifiedPolicyPort {
  const disabled: AllowNodeVerifiedPolicyDocument = {
    status: "disabled",
    disabledReason: "absent",
  };
  return {
    getPolicy: () => disabled,
    isNodeVerifiedAllowed: () => false,
  };
}

/** In-memory policy for tests / lab. */
export class InMemoryAllowNodeVerifiedPolicy implements AllowNodeVerifiedPolicyPort {
  readonly auditEntries: Array<{
    readonly documentJson: string;
    readonly actorId: string;
    readonly nodeId: string;
  }> = [];

  private document: AllowNodeVerifiedPolicyDocument;

  constructor(
    initial: AllowNodeVerifiedPolicyDocument = {
      status: "disabled",
      disabledReason: "absent",
    },
  ) {
    this.document = initial;
  }

  getPolicy(): AllowNodeVerifiedPolicyDocument {
    return this.document;
  }

  isNodeVerifiedAllowed(implementerId: string): boolean {
    return isNodeVerifiedAllowedByPolicy(this.document, implementerId);
  }

  setPolicy(documentJson: string, meta: AllowNodeVerifiedPolicySetMeta): void {
    this.document = parseAllowNodeVerifiedPolicyDocument(documentJson);
    this.auditEntries.push({
      documentJson,
      actorId: meta.actorId,
      nodeId: meta.nodeId,
    });
  }

  /** Test helper: enable NODE_VERIFIED for one implementer. */
  allowImplementer(implementerId: string): void {
    this.document = {
      status: "enabled",
      implementers: [{ implementer_id: parseUuid(implementerId), enabled: true }],
    };
  }
}

function detailsSha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** Narrow SQL surface — pg.Pool / PoolClient both satisfy it. */
export interface AllowNodeVerifiedSqlExecutor {
  query<R>(text: string, params: readonly unknown[]): Promise<{ rows: R[] }>;
}

/**
 * SQL-backed policy over node_settings + audit_log.
 * Unreadable store → disabled/unreadable (never allow NODE_VERIFIED).
 */
export function createSqlAllowNodeVerifiedPolicy(
  sql: AllowNodeVerifiedSqlExecutor,
  opts?: { readonly newId?: () => string },
): AllowNodeVerifiedPolicyPort {
  const newId = opts?.newId ?? (() => randomUUID());

  async function readRaw(): Promise<
    { readonly ok: true; readonly value: string | null } | { readonly ok: false }
  > {
    try {
      const result = await sql.query<{ setting_value: string }>(
        "SELECT setting_value FROM node_settings WHERE setting_key = $1",
        [ALLOW_NODE_VERIFIED_SETTING_KEY],
      );
      return { ok: true, value: result.rows[0]?.setting_value ?? null };
    } catch {
      return { ok: false };
    }
  }

  async function loadDocument(): Promise<AllowNodeVerifiedPolicyDocument> {
    const raw = await readRaw();
    if (!raw.ok) {
      return { status: "disabled", disabledReason: "unreadable" };
    }
    return parseAllowNodeVerifiedPolicyDocument(raw.value);
  }

  return {
    getPolicy: () => loadDocument(),

    async isNodeVerifiedAllowed(implementerId: string): Promise<boolean> {
      const policy = await loadDocument();
      return isNodeVerifiedAllowedByPolicy(policy, implementerId);
    },

    async setPolicy(
      documentJson: string,
      meta: AllowNodeVerifiedPolicySetMeta,
    ): Promise<void> {
      // Refuse to persist an invalid document (fail closed at write too).
      const next = parseAllowNodeVerifiedPolicyDocument(documentJson);
      if (next.status === "disabled" && next.disabledReason === "invalid") {
        throw new Error("invalid allow-node-verified policy document");
      }
      // Canonicalise via serialize when enabled/off-with-entries so storage is stable.
      const canonical =
        next.status === "enabled"
          ? serializeAllowNodeVerifiedPolicyDocument(next.implementers, true)
          : next.disabledReason === "off" && next.implementers !== undefined
            ? serializeAllowNodeVerifiedPolicyDocument(next.implementers, false)
            : documentJson;

      const previous = await readRaw();
      const previousSha = previous.ok
        ? previous.value === null
          ? "absent"
          : detailsSha256(previous.value)
        : "unreadable";
      const nextSha = detailsSha256(canonical);
      const details =
        "setting_key=" +
        ALLOW_NODE_VERIFIED_SETTING_KEY +
        ";previous_sha256=" +
        previousSha +
        ";next_sha256=" +
        nextSha;

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
           $6, NULL, NULL,
           $7, $8, now()
         FROM upserted`,
        [
          ALLOW_NODE_VERIFIED_SETTING_KEY,
          canonical,
          newId(),
          meta.nodeId,
          meta.actorId,
          ALLOW_NODE_VERIFIED_POLICY_CHANGED_ACTION,
          details,
          detailsSha256(details),
        ],
      );
    },
  };
}

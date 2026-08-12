// Auto-approve policy for external sends (ZTR-1234).
//
// Bound, operator-configured rules let a single leader-gated worker (ZTR-1235)
// commit CREATED→APPROVED without a per-send human TOTP factor. Fail closed:
// the safe state is OFF. Absent key, unreadable store, invalid JSON, unknown
// fields, bad types, non-canonical amounts, or duplicate implementer ids all
// resolve the entire policy to DISABLED — every send then falls through to the
// manual approval queue. Auto-approve never rejects a send.
//
// Window spend is derived from existing AUTO_POLICY approval rows (no counter
// table). Spend counts at approval time and is never released — an approved-
// then-expired unredeemed send still consumes cap. Conservative by design.
//
// Race posture: the intended sole *caller* is one leader-gated worker, but the
// TX itself is multi-writer safe. commitAutoApproval takes an implementer-
// scoped pg_advisory_xact_lock before reading window spend or writing
// AUTO_POLICY, so concurrent commits for the same implementer serialize cap
// accounting. FOR UPDATE on the send row + frozen CAS still arbitrate same-
// operation contention with a concurrent manual decide. Different implementers
// use distinct advisory keys and do not block each other.
//
// Storage: node_settings key ops.auto_approve_sends + audit_log on change,
// mirroring dual-control-policy / device-signature-policy.

import { createHash, randomUUID } from "node:crypto";

import { addAmounts, compareAmounts } from "@zucoins/generic-node-contracts";

import { parsePositiveZkzAmount } from "../protocol/amounts.js";
import { parseUuid, parseWalletPublicKey } from "../protocol/scalars.js";
import { buildSendExternalApproval } from "../protocol/suite/builders.js";
import {
  APPROVAL_CANONICAL_VERSION,
  APPROVAL_CHALLENGE_FRESHNESS_MS,
  APPROVAL_PURPOSE,
  toCanonicalTimestamp,
} from "./approve.js";
import { DECISION_STATEMENTS } from "./decide.js";
import type { SqlExecutor, SqlTxFn } from "./sql-store.js";

export const AUTO_APPROVE_SETTING_KEY = "ops.auto_approve_sends" as const;
export const AUTO_APPROVE_POLICY_CHANGED_ACTION =
  "ops.auto_approve_sends_changed" as const;
export const AUTO_APPROVE_APPLIED_ACTION = "send.auto_approved" as const;

export type AutoApproveDisabledReason = "absent" | "unreadable" | "invalid" | "off";

export interface AutoApproveRule {
  readonly rule_id: string;
  readonly implementer_id: string;
  readonly per_send_max_zkz: string;
  readonly per_send_min_zkz: string | null;
  readonly window_hours: number;
  readonly window_cap_zkz: string;
  readonly expires_at: string | null;
  readonly enabled: boolean;
}

export type AutoApprovePolicyDocument =
  | { readonly status: "disabled"; readonly disabledReason: AutoApproveDisabledReason }
  | { readonly status: "enabled"; readonly rules: readonly AutoApproveRule[] };

export type AutoApproveFallThroughReason =
  | "disabled"
  | "no_rule"
  | "rule_disabled"
  | "expired"
  | "below_min"
  | "above_max"
  | "window_cap"
  | "missing_implementer"
  | "operation_not_created"
  | "operation_missing"
  | "cas_miss";

export type AutoApproveEvalResult =
  | { readonly decision: "approve"; readonly rule: AutoApproveRule }
  | { readonly decision: "fall_through"; readonly reason: AutoApproveFallThroughReason };

export interface AutoApproveSendFacts {
  readonly implementerId: string | null | undefined;
  readonly amountZkz: string;
}

export interface AutoApprovePolicySetMeta {
  readonly actorId: string;
  readonly nodeId: string;
}

export interface AutoApprovePolicyPort {
  getPolicy(): AutoApprovePolicyDocument | Promise<AutoApprovePolicyDocument>;
  /**
   * Persist a new policy document. High-authority: callers must gate with fresh TOTP.
   * Implementations write audit_log. Optional only for pure read ports in tests.
   */
  setPolicy?(
    documentJson: string,
    meta: AutoApprovePolicySetMeta,
  ): void | Promise<void>;
}

// ─── fail-closed parser ────────────────────────────────────────────────────

const RULE_KEYS = new Set([
  "rule_id",
  "implementer_id",
  "per_send_max_zkz",
  "per_send_min_zkz",
  "window_hours",
  "window_cap_zkz",
  "expires_at",
  "enabled",
]);

const TOP_KEYS = new Set(["enabled", "rules"]);

/** RFC3339 with optional fractional seconds, Z-suffix only (policy surface). */
const RFC3339_Z_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

const RULE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseCanonicalPositiveAmount(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  try {
    return parsePositiveZkzAmount(raw);
  } catch {
    return null;
  }
}

function parseOptionalRfc3339(raw: unknown): string | null | undefined {
  if (raw === null) return null;
  if (typeof raw !== "string") return undefined;
  if (!RFC3339_Z_PATTERN.test(raw)) return undefined;
  const ms = Date.parse(raw);
  if (Number.isNaN(ms)) return undefined;
  // Reject calendar values the pattern alone would admit (e.g. month 13).
  // Allow non-ms forms that Date can parse as the same instant.
  const iso = new Date(ms).toISOString();
  if (iso !== raw && iso.replace(".000Z", "Z") !== raw) {
    // Still accept if it is a valid Z-time whose instant is stable.
    if (Date.parse(iso) !== ms) return undefined;
  }
  return raw;
}

function parseRule(raw: unknown): AutoApproveRule | null {
  if (!isPlainObject(raw)) return null;
  for (const key of Object.keys(raw)) {
    if (!RULE_KEYS.has(key)) return null;
  }

  if (typeof raw.rule_id !== "string" || !RULE_ID_PATTERN.test(raw.rule_id)) {
    return null;
  }
  if (typeof raw.implementer_id !== "string" || !UUID_PATTERN.test(raw.implementer_id)) {
    return null;
  }
  // Reject non-canonical UUID casing (parseUuid requires lowercase).
  try {
    parseUuid(raw.implementer_id);
  } catch {
    return null;
  }

  const perSendMax = parseCanonicalPositiveAmount(raw.per_send_max_zkz);
  if (perSendMax === null) return null;

  let perSendMin: string | null = null;
  if (raw.per_send_min_zkz !== undefined && raw.per_send_min_zkz !== null) {
    const min = parseCanonicalPositiveAmount(raw.per_send_min_zkz);
    if (min === null) return null;
    // min must be <= max (inclusive bounds both sides).
    if (compareAmounts(min, perSendMax) > 0) return null;
    perSendMin = min;
  } else if (raw.per_send_min_zkz === null) {
    perSendMin = null;
  } else if (raw.per_send_min_zkz !== undefined) {
    return null;
  }

  if (
    typeof raw.window_hours !== "number" ||
    !Number.isInteger(raw.window_hours) ||
    raw.window_hours < 1 ||
    raw.window_hours > 24 * 365 * 10
  ) {
    return null;
  }

  const windowCap = parseCanonicalPositiveAmount(raw.window_cap_zkz);
  if (windowCap === null) return null;
  // Cap must be at least the per-send max (otherwise every matching send is inert).
  if (compareAmounts(windowCap, perSendMax) < 0) return null;

  let expiresAt: string | null = null;
  if (raw.expires_at !== undefined) {
    const exp = parseOptionalRfc3339(raw.expires_at);
    if (exp === undefined) return null;
    expiresAt = exp;
  }

  if (typeof raw.enabled !== "boolean") return null;

  return {
    rule_id: raw.rule_id,
    implementer_id: raw.implementer_id,
    per_send_max_zkz: perSendMax,
    per_send_min_zkz: perSendMin,
    window_hours: raw.window_hours,
    window_cap_zkz: windowCap,
    expires_at: expiresAt,
    enabled: raw.enabled,
  };
}

/**
 * Strict structural parse. Returns rules + document enabled flag, or a failure
 * reason. Does not collapse enabled:false into a parse failure — storage may
 * park a valid-but-off document.
 */
export function parseAutoApprovePolicyStructure(
  raw: string | null | undefined,
):
  | { readonly ok: true; readonly enabled: boolean; readonly rules: readonly AutoApproveRule[] }
  | { readonly ok: false; readonly reason: AutoApproveDisabledReason } {
  if (raw === null || raw === undefined) {
    return { ok: false, reason: "absent" };
  }
  if (typeof raw !== "string" || raw.length === 0) {
    return { ok: false, reason: "invalid" };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ok: false, reason: "invalid" };
  }

  if (!isPlainObject(parsed)) {
    return { ok: false, reason: "invalid" };
  }
  for (const key of Object.keys(parsed)) {
    if (!TOP_KEYS.has(key)) {
      return { ok: false, reason: "invalid" };
    }
  }
  if (typeof parsed.enabled !== "boolean") {
    return { ok: false, reason: "invalid" };
  }
  if (!Array.isArray(parsed.rules)) {
    return { ok: false, reason: "invalid" };
  }

  const rules: AutoApproveRule[] = [];
  const seenImplementers = new Set<string>();
  for (const entry of parsed.rules) {
    const rule = parseRule(entry);
    if (rule === null) {
      return { ok: false, reason: "invalid" };
    }
    if (seenImplementers.has(rule.implementer_id)) {
      return { ok: false, reason: "invalid" };
    }
    seenImplementers.add(rule.implementer_id);
    rules.push(rule);
  }

  return { ok: true, enabled: parsed.enabled, rules };
}

/**
 * Fail-closed parse of the ops.auto_approve_sends JSON document.
 * Only a fully valid document with enabled:true yields status "enabled".
 * Everything else is DISABLED (safe state — all sends fall through).
 */
export function parseAutoApprovePolicyDocument(
  raw: string | null | undefined,
): AutoApprovePolicyDocument {
  const structured = parseAutoApprovePolicyStructure(raw);
  if (!structured.ok) {
    return { status: "disabled", disabledReason: structured.reason };
  }
  if (!structured.enabled) {
    return { status: "disabled", disabledReason: "off" };
  }
  return { status: "enabled", rules: structured.rules };
}

/**
 * Serialise a validated document back to canonical JSON text for storage.
 */
export function serializeAutoApprovePolicyDocument(
  rules: readonly AutoApproveRule[],
  enabled = true,
): string {
  return JSON.stringify({
    enabled,
    rules: rules.map((r) => ({
      rule_id: r.rule_id,
      implementer_id: r.implementer_id,
      per_send_max_zkz: r.per_send_max_zkz,
      per_send_min_zkz: r.per_send_min_zkz,
      window_hours: r.window_hours,
      window_cap_zkz: r.window_cap_zkz,
      expires_at: r.expires_at,
      enabled: r.enabled,
    })),
  });
}

// ─── pure evaluator ────────────────────────────────────────────────────────

/**
 * Pure rule match + bound check. Does NOT evaluate the window cap — that needs
 * durable spend and belongs in commitAutoApproval / the worker pre-check.
 *
 * `windowSpend` when supplied is checked here too so unit tests and dry-run
 * paths share one predicate; production commit re-checks spend under the
 * implementer-scoped advisory lock (then FOR UPDATE on the send row).
 */
export function evaluateAutoApproveRule(
  policy: AutoApprovePolicyDocument,
  send: AutoApproveSendFacts,
  opts?: {
    readonly nowMs?: number;
    readonly windowSpend?: string;
  },
): AutoApproveEvalResult {
  if (policy.status !== "enabled") {
    return { decision: "fall_through", reason: "disabled" };
  }

  const implementerId = send.implementerId;
  if (
    implementerId === null ||
    implementerId === undefined ||
    implementerId.length === 0
  ) {
    return { decision: "fall_through", reason: "missing_implementer" };
  }

  let amount: string;
  try {
    amount = parsePositiveZkzAmount(send.amountZkz);
  } catch {
    return { decision: "fall_through", reason: "above_max" };
  }

  const rule = policy.rules.find((r) => r.implementer_id === implementerId);
  if (rule === undefined) {
    return { decision: "fall_through", reason: "no_rule" };
  }
  if (!rule.enabled) {
    return { decision: "fall_through", reason: "rule_disabled" };
  }

  const nowMs = opts?.nowMs ?? Date.now();
  if (rule.expires_at !== null) {
    const expMs = Date.parse(rule.expires_at);
    if (!Number.isNaN(expMs) && nowMs >= expMs) {
      return { decision: "fall_through", reason: "expired" };
    }
  }

  if (rule.per_send_min_zkz !== null && compareAmounts(amount, rule.per_send_min_zkz) < 0) {
    return { decision: "fall_through", reason: "below_min" };
  }
  if (compareAmounts(amount, rule.per_send_max_zkz) > 0) {
    return { decision: "fall_through", reason: "above_max" };
  }

  if (opts?.windowSpend !== undefined) {
    let projected: string;
    try {
      projected = addAmounts(opts.windowSpend, amount);
    } catch {
      return { decision: "fall_through", reason: "window_cap" };
    }
    if (compareAmounts(projected, rule.window_cap_zkz) > 0) {
      return { decision: "fall_through", reason: "window_cap" };
    }
  }

  return { decision: "approve", rule };
}

// ─── ports ─────────────────────────────────────────────────────────────────

export function fixedAutoApprovePolicy(
  policy: AutoApprovePolicyDocument,
): AutoApprovePolicyPort {
  return { getPolicy: () => policy };
}

export class InMemoryAutoApprovePolicy implements AutoApprovePolicyPort {
  readonly auditEntries: Array<{
    readonly documentJson: string;
    readonly actorId: string;
    readonly nodeId: string;
  }> = [];

  constructor(
    private policy: AutoApprovePolicyDocument = {
      status: "disabled",
      disabledReason: "absent",
    },
  ) {}

  getPolicy(): AutoApprovePolicyDocument {
    return this.policy;
  }

  setPolicy(documentJson: string, meta: AutoApprovePolicySetMeta): void {
    const structured = parseAutoApprovePolicyStructure(documentJson);
    if (!structured.ok) {
      throw new Error("invalid auto-approve policy document");
    }
    this.policy = structured.enabled
      ? { status: "enabled", rules: structured.rules }
      : { status: "disabled", disabledReason: "off" };
    this.auditEntries.push({
      documentJson,
      actorId: meta.actorId,
      nodeId: meta.nodeId,
    });
  }
}

function detailsSha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function documentSha256(json: string): string {
  return createHash("sha256").update(json, "utf8").digest("hex");
}

/**
 * SQL-backed policy over node_settings + audit_log.
 * Read errors and missing/invalid rows fail closed (DISABLED).
 */
export function createSqlAutoApprovePolicy(
  sql: SqlExecutor,
  opts?: { readonly newId?: () => string },
): AutoApprovePolicyPort {
  const newId = opts?.newId ?? (() => randomUUID());

  async function readRaw(): Promise<
    { readonly ok: true; readonly value: string | null } | { readonly ok: false }
  > {
    try {
      const result = await sql.query<{ setting_value: string }>(
        "SELECT setting_value FROM node_settings WHERE setting_key = $1",
        [AUTO_APPROVE_SETTING_KEY],
      );
      return { ok: true, value: result.rows[0]?.setting_value ?? null };
    } catch {
      return { ok: false };
    }
  }

  return {
    async getPolicy(): Promise<AutoApprovePolicyDocument> {
      const raw = await readRaw();
      if (!raw.ok) {
        return { status: "disabled", disabledReason: "unreadable" };
      }
      return parseAutoApprovePolicyDocument(raw.value);
    },

    async setPolicy(
      documentJson: string,
      meta: AutoApprovePolicySetMeta,
    ): Promise<void> {
      const structured = parseAutoApprovePolicyStructure(documentJson);
      if (!structured.ok) {
        throw new Error("invalid auto-approve policy document");
      }
      // Re-serialise so stored bytes are canonical (no unknown fields / key noise).
      const storedValue = serializeAutoApprovePolicyDocument(
        structured.rules,
        structured.enabled,
      );

      const previous = await readRaw();
      const previousValue = previous.ok && previous.value !== null ? previous.value : "";
      const previousSha = previousValue.length > 0 ? documentSha256(previousValue) : "absent";
      const nextSha = documentSha256(storedValue);

      const details =
        "setting_key=" +
        AUTO_APPROVE_SETTING_KEY +
        ";previous_sha256=" +
        previousSha +
        ";next_sha256=" +
        nextSha;
      const detailsSha = detailsSha256(details);

      // Single statement: settings upsert + audit insert (dual-control pattern).
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
           '${AUTO_APPROVE_POLICY_CHANGED_ACTION}', NULL, NULL,
           $6, $7, now()
         FROM upserted`,
        [
          AUTO_APPROVE_SETTING_KEY,
          storedValue,
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

// ─── window spend ──────────────────────────────────────────────────────────

/**
 * Transaction-scoped advisory lock for one implementer's auto-approve window.
 * Namespaced text key so the bigint does not collide with path_proof / other
 * hashtextextended(uuid) locks. Released automatically on COMMIT or ROLLBACK.
 */
export const LOCK_AUTO_APPROVE_WINDOW_SQL =
  "SELECT pg_advisory_xact_lock(hashtextextended(('auto-approve-window:' || $1::text), 0))";

export const WINDOW_SPEND_SQL =
  "SELECT COALESCE(SUM(o.amount_zkz::numeric), 0)::text AS spend " +
  "FROM operation_approvals a " +
  "JOIN send_operations o ON o.operation_id = a.operation_id " +
  "WHERE a.method = 'AUTO_POLICY' " +
  "  AND o.implementer_id = $1::uuid " +
  "  AND a.consumed_at >= now() - make_interval(hours => $2::int)";

export async function lockAutoApproveWindow(
  sql: SqlExecutor,
  implementerId: string,
): Promise<void> {
  await sql.query(LOCK_AUTO_APPROVE_WINDOW_SQL, [implementerId]);
}

export async function queryWindowSpend(
  sql: SqlExecutor,
  implementerId: string,
  windowHours: number,
): Promise<string> {
  const result = await sql.query<{ spend: string }>(WINDOW_SPEND_SQL, [
    implementerId,
    windowHours,
  ]);
  const raw = (result.rows[0]?.spend ?? "0").trim();
  // PG numeric::text may be "0" / "0.0" / "1.1000". addAmounts re-emits canonical
  // fixed-point text via the contracts emitter.
  if (raw === "" || raw === "0") return "0";
  return addAmounts(raw, "0");
}

// ─── commitAutoApproval ────────────────────────────────────────────────────

export interface CommitAutoApprovalInput {
  readonly operationId: string;
  readonly rule: AutoApproveRule;
}

export type CommitAutoApprovalResult =
  | {
      readonly decision: "approve";
      readonly approvalId: string;
      readonly rowVersion: number;
      readonly windowSpendBefore: string;
    }
  | {
      readonly decision: "fall_through";
      readonly reason: AutoApproveFallThroughReason;
    };

export interface CommitAutoApprovalDeps {
  readonly sql: SqlExecutor;
  /** BEGIN/COMMIT factory. Required — commit is one transactional unit. */
  readonly withTx: SqlTxFn;
  readonly newId?: () => string;
  readonly nowMs?: () => number;
  readonly freshnessMs?: number;
}

interface LockedSendRow {
  readonly operation_id: string;
  readonly implementer_id: string;
  readonly node_id: string;
  readonly status: string;
  readonly row_version: string | number;
  readonly source_wallet_id: string;
  readonly destination_address: string;
  readonly amount_zkz: string;
  readonly references_operation_id: string | null;
  readonly source_pubkey: string;
}

const LOCK_SEND_SQL =
  "SELECT o.operation_id, o.implementer_id, o.node_id, o.status, o.row_version, " +
  "o.source_wallet_id, o.destination_address, o.amount_zkz, o.references_operation_id, " +
  "w.public_key AS source_pubkey " +
  "FROM send_operations o " +
  "JOIN wallets w ON w.id = o.source_wallet_id " +
  "WHERE o.operation_id = $1 " +
  "FOR UPDATE OF o";

const INSERT_AUTO_APPROVAL_SQL =
  "INSERT INTO operation_approvals (" +
  "  id, node_id, operation_id, challenge_id, challenge_status, method, purpose, " +
  "  canonical_version, preimage_text, preimage_sha256, device_key_id, device_signature, " +
  "  totp_timestep, consumed_at" +
  ") VALUES (" +
  "  $1, $2, $3, NULL, 'CONSUMED', 'AUTO_POLICY', $4, " +
  "  $5, $6, $7, NULL, NULL, NULL, $8::timestamptz" +
  ")";

const INSERT_AUTO_AUDIT_SQL =
  "INSERT INTO audit_log (" +
  "  id, node_id, actor_kind, actor_id, action, operation_id, wallet_id, " +
  "  details_text, details_sha256, created_at" +
  ") VALUES (" +
  "  $1::uuid, $2::uuid, 'SYSTEM', $3, $4, $5::uuid, NULL, " +
  "  $6, $7, $8::timestamptz" +
  ")";

/**
 * One-TX auto-approval commit:
 *   implementer advisory lock → FOR UPDATE → bound recheck → window recheck →
 *   build preimage → INSERT AUTO_POLICY → CREATED→APPROVED CAS → SYSTEM audit →
 *   COMMIT (or ROLLBACK on any miss; xact advisory releases with the TX).
 */
export async function commitAutoApproval(
  input: CommitAutoApprovalInput,
  deps: CommitAutoApprovalDeps,
): Promise<CommitAutoApprovalResult> {
  const newId = deps.newId ?? (() => randomUUID());
  const nowMs = deps.nowMs?.() ?? Date.now();
  const freshness = deps.freshnessMs ?? APPROVAL_CHALLENGE_FRESHNESS_MS;
  const rule = input.rule;

  try {
    return await deps.withTx(async (tx): Promise<CommitAutoApprovalResult> => {
    // Serialize same-implementer window spend + AUTO_POLICY insert across writers.
    // Lock the *rule* implementer up front (known before the send row); mismatch
    // with the locked row still falls through via evaluateAutoApproveRule.
    await lockAutoApproveWindow(tx, rule.implementer_id);

    const locked = await tx.query<LockedSendRow>(LOCK_SEND_SQL, [input.operationId]);
    const row = locked.rows[0];
    if (row === undefined) {
      return { decision: "fall_through", reason: "operation_missing" };
    }
    if (row.status !== "CREATED") {
      return { decision: "fall_through", reason: "operation_not_created" };
    }

    // Re-evaluate pure bounds under the locks (amount / implementer may not match rule).
    const bound = evaluateAutoApproveRule(
      { status: "enabled", rules: [rule] },
      { implementerId: row.implementer_id, amountZkz: row.amount_zkz },
      { nowMs },
    );
    if (bound.decision === "fall_through") {
      return bound;
    }

    const spend = await queryWindowSpend(tx, row.implementer_id, rule.window_hours);
    const amount = parsePositiveZkzAmount(row.amount_zkz);
    const projected = addAmounts(spend, amount);
    if (compareAmounts(projected, rule.window_cap_zkz) > 0) {
      return { decision: "fall_through", reason: "window_cap" };
    }

    const nonce = newId();
    const issuedAt = toCanonicalTimestamp(nowMs);
    const expiresAt = toCanonicalTimestamp(nowMs + freshness);
    const built = buildSendExternalApproval({
      node_id: parseUuid(row.node_id),
      operation_id: parseUuid(row.operation_id),
      source_selector: {
        kind: "WALLET_ID",
        wallet_id: parseUuid(row.source_wallet_id),
      },
      source_pubkey: parseWalletPublicKey(row.source_pubkey),
      destination_address: parseWalletPublicKey(row.destination_address),
      amount_zkz: amount,
      references_operation_id:
        row.references_operation_id === null
          ? null
          : parseUuid(row.references_operation_id),
      nonce: parseUuid(nonce),
      issued_at: issuedAt,
      expires_at: expiresAt,
    });

    const approvalId = newId();
    const consumedAt = issuedAt;

    await tx.query(INSERT_AUTO_APPROVAL_SQL, [
      approvalId,
      row.node_id,
      row.operation_id,
      APPROVAL_PURPOSE,
      APPROVAL_CANONICAL_VERSION,
      built.preimageText,
      built.sha256,
      consumedAt,
    ]);

    const expectedRowVersion = Number(row.row_version);
    const cas = await tx.query<{
      operation_id: string;
      status: string;
      row_version: string | number;
    }>(DECISION_STATEMENTS.APPROVE_CREATED, [row.operation_id, expectedRowVersion]);

    if (cas.rows[0] === undefined) {
      // Force rollback of the approval insert by throwing — withTx must ROLLBACK.
      // Returning fall_through alone would COMMIT the orphan approval row.
      throw new AutoApproveCasMissError();
    }

    const details =
      "rule_id=" +
      rule.rule_id +
      ";implementer_id=" +
      rule.implementer_id +
      ";amount_zkz=" +
      amount +
      ";window_spend_before=" +
      spend +
      ";window_cap_zkz=" +
      rule.window_cap_zkz;
    const detailsSha = detailsSha256(details);
    const actorId = "auto_policy:" + rule.rule_id;

    await tx.query(INSERT_AUTO_AUDIT_SQL, [
      newId(),
      row.node_id,
      actorId,
      AUTO_APPROVE_APPLIED_ACTION,
      row.operation_id,
      details,
      detailsSha,
      consumedAt,
    ]);

    return {
      decision: "approve",
      approvalId,
      rowVersion: Number(cas.rows[0].row_version),
      windowSpendBefore: spend,
    };
  });
  } catch (err: unknown) {
    if (err instanceof AutoApproveCasMissError) {
      return { decision: "fall_through", reason: "cas_miss" };
    }
    throw err;
  }
}

/** Internal signal: CAS lost the race; withTx must roll back. */
export class AutoApproveCasMissError extends Error {
  constructor() {
    super("auto-approve CAS miss");
    this.name = "AutoApproveCasMissError";
  }
}

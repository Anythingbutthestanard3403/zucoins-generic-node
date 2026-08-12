// Proposed-rule parser for Route 2 intake. Same amount grammar and window
// bounds as ZTR-1234 auto-approve rules, but implementer_id is absent (the
// identity does not exist until operator approval). ZTR-1239.

import { compareAmounts } from "@zucoins/generic-node-contracts";

import { parsePositiveZkzAmount } from "../protocol/amounts.js";
import type { ProposedIntegrationRule } from "./types.js";

const RULE_KEYS = new Set([
  "rule_id",
  "per_send_max_zkz",
  "per_send_min_zkz",
  "window_hours",
  "window_cap_zkz",
  "expires_at",
]);

const RFC3339_Z_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

const RULE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

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
  const iso = new Date(ms).toISOString();
  if (iso !== raw && iso.replace(".000Z", "Z") !== raw) {
    if (Date.parse(iso) !== ms) return undefined;
  }
  return raw;
}

/**
 * Strict structural parse of a single proposed rule. Returns null on any
 * unknown field, bad type, non-canonical amount, or window/cap inconsistency.
 */
export function parseProposedIntegrationRule(
  raw: unknown,
): ProposedIntegrationRule | null {
  if (!isPlainObject(raw)) return null;
  for (const key of Object.keys(raw)) {
    if (!RULE_KEYS.has(key)) return null;
  }

  let ruleId: string | undefined;
  if (raw.rule_id !== undefined) {
    if (typeof raw.rule_id !== "string" || !RULE_ID_PATTERN.test(raw.rule_id)) {
      return null;
    }
    ruleId = raw.rule_id;
  }

  const perSendMax = parseCanonicalPositiveAmount(raw.per_send_max_zkz);
  if (perSendMax === null) return null;

  let perSendMin: string | null = null;
  if (raw.per_send_min_zkz !== undefined && raw.per_send_min_zkz !== null) {
    const min = parseCanonicalPositiveAmount(raw.per_send_min_zkz);
    if (min === null) return null;
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
  if (compareAmounts(windowCap, perSendMax) < 0) return null;

  let expiresAt: string | null = null;
  if (raw.expires_at !== undefined) {
    const exp = parseOptionalRfc3339(raw.expires_at);
    if (exp === undefined) return null;
    expiresAt = exp;
  }

  const out: ProposedIntegrationRule = {
    per_send_max_zkz: perSendMax,
    per_send_min_zkz: perSendMin,
    window_hours: raw.window_hours,
    window_cap_zkz: windowCap,
    expires_at: expiresAt,
  };
  if (ruleId !== undefined) {
    return { ...out, rule_id: ruleId };
  }
  return out;
}

/** Canonical JSON form stored on insert (stable key sequence). */
export function serializeProposedRule(rule: ProposedIntegrationRule): string {
  const body: Record<string, unknown> = {};
  if (rule.rule_id !== undefined) body.rule_id = rule.rule_id;
  body.per_send_max_zkz = rule.per_send_max_zkz;
  body.per_send_min_zkz = rule.per_send_min_zkz;
  body.window_hours = rule.window_hours;
  body.window_cap_zkz = rule.window_cap_zkz;
  body.expires_at = rule.expires_at;
  return JSON.stringify(body);
}

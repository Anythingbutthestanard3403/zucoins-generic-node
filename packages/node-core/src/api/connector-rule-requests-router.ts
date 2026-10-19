// Spend-rule requests (ZTR-1331).
//
// Public paths stay on this side router. They are not folded into the frozen
// route catalog, so the catalog length pin and the route-policy digest stay
// unchanged. A missing bearer, a missing send:create scope, or a missing
// sends:write label all collapse to the generic 401. Another implementer's
// request is the generic 404. The node does not fetch a hook target.

import { compareAmounts } from "@zucoins/generic-node-contracts";

import type { ConnectorConfigStore } from "../implementer/connector-configs.js";
import {
  ConnectorRuleRequestStoreError,
  type ConnectorRuleRequestRecord,
  type ConnectorRuleRequestStore,
} from "../implementer/connector-rule-requests.js";
import { parsePositiveZkzAmount } from "../protocol/amounts.js";
import { parseUuid } from "../protocol/scalars.js";
import { apiErrorResponse, type ApiErrorCode, type ApiErrorResponse } from "./error-envelope.js";
import { parseStrictJson } from "./strict-json.js";
import { extractImplementerBearer } from "./tenant-middleware.js";

const JSON_CONTENT_TYPE = "application/json; charset=utf-8";
const REQUESTS_PATH = "/v1/connector-rules/requests";
const RULES_PATH = "/v1/connector-rules";

const RULE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const RFC3339_Z_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

const POST_KEYS = new Set([
  "rule_id",
  "label",
  "reserve_wallet_id",
  "total_cap_zkz",
  "per_send_max_zkz",
  "per_send_min_zkz",
  "window_hours",
  "window_cap_zkz",
  "expires_at",
]);

const OVERRIDE_KEYS = new Set([
  "reserve_wallet_id",
  "total_cap_zkz",
  "per_send_max_zkz",
  "window_hours",
  "window_cap_zkz",
  "expires_at",
]);

export interface ConnectorRuleDraft {
  readonly rule_id: string;
  readonly label: string | null;
  readonly implementer_id: string;
  readonly reserve_wallet_id: string | null;
  readonly total_cap_zkz: string | null;
  readonly per_send_max_zkz: string;
  readonly per_send_min_zkz: string | null;
  readonly window_hours: number;
  readonly window_cap_zkz: string;
  readonly expires_at: string | null;
  readonly enabled: boolean;
}

export interface ConnectorRulePolicyRuleView {
  readonly rule_id: string;
  readonly implementer_id: string;
  readonly enabled: boolean;
  readonly label?: string | null;
  readonly reserve_wallet_id?: string | null;
  readonly total_cap_zkz?: string | null;
  readonly per_send_max_zkz: string;
  readonly per_send_min_zkz?: string | null;
  readonly window_hours: number;
  readonly window_cap_zkz: string;
  readonly expires_at?: string | null;
}

export interface ConnectorRulePolicyView {
  readonly status: "enabled" | "disabled";
  readonly rules?: readonly ConnectorRulePolicyRuleView[];
}

export interface ConnectorRulePolicyReader {
  getPolicy(): ConnectorRulePolicyView | Promise<ConnectorRulePolicyView>;
}

export interface ConnectorRuleCredential {
  readonly implementer_id: string;
  readonly scopes: readonly string[];
}

export interface ConnectorRuleRequestRouterDeps {
  readonly store: ConnectorRuleRequestStore;
  readonly connectorConfigStore?: ConnectorConfigStore;
  readonly nodeId: string;
  readonly validateCredential: (rawKey: string) => Promise<ConnectorRuleCredential | null>;
  readonly policyReader?: ConnectorRulePolicyReader;
  readonly newRequestId: () => string;
}

export type ConnectorRuleRequestRouter = (
  method: string,
  rawPath: string,
  rawBody: Uint8Array,
  headers: Record<string, string | undefined>,
) => Promise<{ status: number; body: string; headers: Record<string, string> }>;

export interface ConnectorRuleRequestBody {
  readonly rule_id: string;
  readonly label: string;
  readonly reserve_wallet_id: string | null;
  readonly total_cap_zkz: string | null;
  readonly per_send_max_zkz: string;
  readonly per_send_min_zkz: string | null;
  readonly window_hours: number;
  readonly window_cap_zkz: string;
  readonly expires_at: string | null;
}

export interface ConnectorRuleRequestOverrides {
  readonly reserve_wallet_id?: string | null;
  readonly total_cap_zkz?: string | null;
  readonly per_send_max_zkz?: string;
  readonly window_hours?: number;
  readonly window_cap_zkz?: string;
  readonly expires_at?: string | null;
}

export type ConnectorRuleParseFailure = {
  readonly ok: false;
  readonly code: "unknown_field" | "invalid_scalar";
  readonly message: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function failParse(code: "unknown_field" | "invalid_scalar", message: string): ConnectorRuleParseFailure {
  return { ok: false, code, message };
}

function parseExpires(raw: unknown): string | null | undefined {
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

function parseAmount(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  try {
    return parsePositiveZkzAmount(raw);
  } catch {
    return null;
  }
}

function parseWallet(raw: unknown): string | null | undefined {
  if (raw === null) return null;
  if (typeof raw !== "string") return undefined;
  try {
    return parseUuid(raw);
  } catch {
    return undefined;
  }
}

function parseWindowHours(raw: unknown): number | null {
  if (typeof raw !== "number" || !Number.isInteger(raw) || raw < 1 || raw > 720) return null;
  return raw;
}

function unknownKey(keys: ReadonlySet<string>, raw: Record<string, unknown>): string | null {
  for (const key of Object.keys(raw)) {
    if (!keys.has(key)) return key;
  }
  return null;
}

export function parseConnectorRuleRequestBody(
  raw: unknown,
): { readonly ok: true; readonly value: ConnectorRuleRequestBody } | ConnectorRuleParseFailure {
  if (!isRecord(raw)) return failParse("invalid_scalar", "body must be an object");
  const extra = unknownKey(POST_KEYS, raw);
  if (extra !== null) return failParse("unknown_field", "The request contains an unrecognized field.");
  if (typeof raw.rule_id !== "string" || !RULE_ID_PATTERN.test(raw.rule_id)) {
    return failParse("invalid_scalar", "rule_id is not a canonical id");
  }
  if (typeof raw.label !== "string") return failParse("invalid_scalar", "label is required");
  const label = raw.label.trim();
  if (label.length < 1 || label.length > 120) {
    return failParse("invalid_scalar", "label must be 1 to 120 characters");
  }
  const reserve = raw.reserve_wallet_id === undefined ? null : parseWallet(raw.reserve_wallet_id);
  if (reserve === undefined) return failParse("invalid_scalar", "reserve_wallet_id is not a canonical uuid");
  const perSendMax = parseAmount(raw.per_send_max_zkz);
  if (perSendMax === null) return failParse("invalid_scalar", "per_send_max_zkz is not canonical");
  let totalCap: string | null = null;
  if (raw.total_cap_zkz !== undefined && raw.total_cap_zkz !== null) {
    totalCap = parseAmount(raw.total_cap_zkz);
    if (totalCap === null) return failParse("invalid_scalar", "total_cap_zkz is not canonical");
  }
  let perSendMin: string | null = null;
  if (raw.per_send_min_zkz !== undefined && raw.per_send_min_zkz !== null) {
    perSendMin = parseAmount(raw.per_send_min_zkz);
    if (perSendMin === null) return failParse("invalid_scalar", "per_send_min_zkz is not canonical");
  }
  const windowHours = parseWindowHours(raw.window_hours);
  if (windowHours === null) return failParse("invalid_scalar", "window_hours must be an integer from 1 to 720");
  const windowCap = parseAmount(raw.window_cap_zkz);
  if (windowCap === null) return failParse("invalid_scalar", "window_cap_zkz is not canonical");
  const expires = raw.expires_at === undefined ? null : parseExpires(raw.expires_at);
  if (expires === undefined) return failParse("invalid_scalar", "expires_at must be an RFC3339 Z timestamp");
  const relationship = relationshipFailure({
    perSendMax,
    perSendMin,
    totalCap,
    windowCap,
  });
  if (relationship !== null) return failParse("invalid_scalar", relationship);
  return {
    ok: true,
    value: {
      rule_id: raw.rule_id,
      label,
      reserve_wallet_id: reserve,
      total_cap_zkz: totalCap,
      per_send_max_zkz: perSendMax,
      per_send_min_zkz: perSendMin,
      window_hours: windowHours,
      window_cap_zkz: windowCap,
      expires_at: expires,
    },
  };
}

export function parseConnectorRuleRequestOverrides(
  raw: unknown,
): { readonly ok: true; readonly value: ConnectorRuleRequestOverrides } | ConnectorRuleParseFailure {
  if (!isRecord(raw)) return failParse("invalid_scalar", "body must be an object");
  const extra = unknownKey(OVERRIDE_KEYS, raw);
  if (extra !== null) return failParse("unknown_field", "The request contains an unrecognized field.");
  const value: {
    reserve_wallet_id?: string | null;
    total_cap_zkz?: string | null;
    per_send_max_zkz?: string;
    window_hours?: number;
    window_cap_zkz?: string;
    expires_at?: string | null;
  } = {};
  if (raw.reserve_wallet_id !== undefined) {
    const reserve = parseWallet(raw.reserve_wallet_id);
    if (reserve === undefined) return failParse("invalid_scalar", "reserve_wallet_id is not a canonical uuid");
    value.reserve_wallet_id = reserve;
  }
  if (raw.total_cap_zkz !== undefined) {
    if (raw.total_cap_zkz === null) value.total_cap_zkz = null;
    else {
      const cap = parseAmount(raw.total_cap_zkz);
      if (cap === null) return failParse("invalid_scalar", "total_cap_zkz is not canonical");
      value.total_cap_zkz = cap;
    }
  }
  if (raw.per_send_max_zkz !== undefined) {
    const max = parseAmount(raw.per_send_max_zkz);
    if (max === null) return failParse("invalid_scalar", "per_send_max_zkz is not canonical");
    value.per_send_max_zkz = max;
  }
  if (raw.window_hours !== undefined) {
    const hours = parseWindowHours(raw.window_hours);
    if (hours === null) return failParse("invalid_scalar", "window_hours must be an integer from 1 to 720");
    value.window_hours = hours;
  }
  if (raw.window_cap_zkz !== undefined) {
    const cap = parseAmount(raw.window_cap_zkz);
    if (cap === null) return failParse("invalid_scalar", "window_cap_zkz is not canonical");
    value.window_cap_zkz = cap;
  }
  if (raw.expires_at !== undefined) {
    const expires = parseExpires(raw.expires_at);
    if (expires === undefined) return failParse("invalid_scalar", "expires_at must be an RFC3339 Z timestamp");
    value.expires_at = expires;
  }
  return { ok: true, value };
}

function relationshipFailure(input: {
  readonly perSendMax: string;
  readonly perSendMin: string | null;
  readonly totalCap: string | null;
  readonly windowCap: string;
}): string | null {
  if (compareAmounts(input.windowCap, input.perSendMax) < 0) {
    return "window cap is below the per-send max";
  }
  if (input.totalCap !== null && compareAmounts(input.totalCap, input.perSendMax) < 0) {
    return "total cap is below the per-send max";
  }
  if (input.perSendMin !== null && compareAmounts(input.perSendMin, input.perSendMax) > 0) {
    return "per-send min is above the per-send max";
  }
  return null;
}

export function toAutoApproveRule(record: {
  readonly rule_id: string;
  readonly label: string | null;
  readonly implementer_id: string;
  readonly reserve_wallet_id: string | null;
  readonly total_cap_zkz: string | null;
  readonly per_send_max_zkz: string;
  readonly per_send_min_zkz: string | null;
  readonly window_hours: number;
  readonly window_cap_zkz: string;
  readonly expires_at: string | null;
}): ConnectorRuleDraft {
  return {
    rule_id: record.rule_id,
    label: record.label,
    implementer_id: record.implementer_id,
    reserve_wallet_id: record.reserve_wallet_id,
    total_cap_zkz: record.total_cap_zkz,
    per_send_max_zkz: record.per_send_max_zkz,
    per_send_min_zkz: record.per_send_min_zkz,
    window_hours: record.window_hours,
    window_cap_zkz: record.window_cap_zkz,
    expires_at: record.expires_at,
    enabled: true,
  };
}

export function buildApprovedConnectorRule(
  record: ConnectorRuleRequestRecord,
  overrides: ConnectorRuleRequestOverrides,
): ConnectorRuleDraft {
  const perSendMax = overrides.per_send_max_zkz ?? record.per_send_max_zkz;
  const windowCap = overrides.window_cap_zkz ?? record.window_cap_zkz;
  const totalCap = overrides.total_cap_zkz !== undefined ? overrides.total_cap_zkz : record.total_cap_zkz;
  const windowHours = overrides.window_hours ?? record.window_hours;
  const failure = relationshipFailure({
    perSendMax,
    perSendMin: record.per_send_min_zkz,
    totalCap,
    windowCap,
  });
  if (failure !== null || windowHours < 1 || windowHours > 720) {
    const err = new Error(
      failure ?? "window_hours must be an integer from 1 to 720",
    ) as Error & { code?: string };
    err.code = "INVALID_RULE";
    throw err;
  }
  return toAutoApproveRule({
    rule_id: record.rule_id,
    label: record.label,
    implementer_id: record.implementer_id,
    reserve_wallet_id:
      overrides.reserve_wallet_id !== undefined ? overrides.reserve_wallet_id : record.reserve_wallet_id,
    total_cap_zkz: totalCap,
    per_send_max_zkz: perSendMax,
    per_send_min_zkz: record.per_send_min_zkz,
    window_hours: windowHours,
    window_cap_zkz: windowCap,
    expires_at: overrides.expires_at !== undefined ? overrides.expires_at : record.expires_at,
  });
}

function err(error: ApiErrorResponse) {
  return { status: error.status, body: error.body, headers: { ...error.headers } };
}

function ok(status: number, body: unknown) {
  return {
    status,
    body: JSON.stringify(body),
    headers: { "content-type": JSON_CONTENT_TYPE },
  };
}

function publicRequest(row: ConnectorRuleRequestRecord) {
  return {
    request_id: row.request_id,
    implementer_id: row.implementer_id,
    rule_id: row.rule_id,
    label: row.label,
    reserve_wallet_id: row.reserve_wallet_id,
    total_cap_zkz: row.total_cap_zkz,
    per_send_max_zkz: row.per_send_max_zkz,
    per_send_min_zkz: row.per_send_min_zkz,
    window_hours: row.window_hours,
    window_cap_zkz: row.window_cap_zkz,
    expires_at: row.expires_at,
    status: row.status,
    webhook_enabled: row.webhook_enabled,
    created_at: row.created_at,
    decided_at: row.decided_at,
    decided_by: row.decided_by,
  };
}

function pathnameOf(rawPath: string): string {
  return rawPath.split(/[?#]/, 1)[0] ?? rawPath;
}

export function createConnectorRuleRequestRouter(
  deps: ConnectorRuleRequestRouterDeps,
): ConnectorRuleRequestRouter {
  return async (method, rawPath, rawBody, headers) => {
    const requestId = deps.newRequestId();
    const verb = method.toUpperCase();
    const pathname = pathnameOf(rawPath);
    let credential: ConnectorRuleCredential | null;
    try {
      const bearer = extractImplementerBearer(headers);
      credential = bearer === null ? null : await deps.validateCredential(bearer);
    } catch {
      return err(apiErrorResponse("service_unavailable", requestId));
    }
    if (credential === null || !credential.scopes.includes("send:create")) {
      return err(apiErrorResponse("invalid_api_key", requestId));
    }
    if (deps.connectorConfigStore === undefined) {
      return err(apiErrorResponse("service_unavailable", requestId, "connector configuration is not wired"));
    }
    let connector;
    try {
      connector = await deps.connectorConfigStore.get(credential.implementer_id);
    } catch {
      return err(apiErrorResponse("service_unavailable", requestId));
    }
    if (connector === null || !connector.scopes.includes("sends:write")) {
      return err(apiErrorResponse("invalid_api_key", requestId));
    }

    if (verb === "POST" && pathname === REQUESTS_PATH) {
      const parsedJson = parseStrictJson(rawBody);
      if (!parsedJson.ok) {
        return err(apiErrorResponse(parsedJson.code as ApiErrorCode, requestId));
      }
      const parsed = parseConnectorRuleRequestBody(parsedJson.value);
      if (!parsed.ok) return err(apiErrorResponse(parsed.code, requestId, parsed.message));
      try {
        const saved = await deps.store.create({
          nodeId: deps.nodeId,
          implementerId: credential.implementer_id,
          ruleId: parsed.value.rule_id,
          label: parsed.value.label,
          reserveWalletId: parsed.value.reserve_wallet_id,
          totalCapZkz: parsed.value.total_cap_zkz,
          perSendMaxZkz: parsed.value.per_send_max_zkz,
          perSendMinZkz: parsed.value.per_send_min_zkz,
          windowHours: parsed.value.window_hours,
          windowCapZkz: parsed.value.window_cap_zkz,
          expiresAt: parsed.value.expires_at,
          webhookEnabled: connector.webhook_enabled,
          actorId: credential.implementer_id,
        });
        return ok(201, {
          request_id: saved.request_id,
          implementer_id: saved.implementer_id,
          rule_id: saved.rule_id,
          status: saved.status,
          created_at: saved.created_at,
        });
      } catch (error) {
        if (error instanceof ConnectorRuleRequestStoreError && error.code === "RATE_LIMITED") {
          return err(apiErrorResponse("rate_limited", requestId));
        }
        return err(apiErrorResponse("service_unavailable", requestId));
      }
    }

    if (verb === "GET" && pathname === RULES_PATH) {
      let rules: readonly ConnectorRulePolicyRuleView[] = [];
      if (deps.policyReader !== undefined) {
        try {
          const policy = await deps.policyReader.getPolicy();
          if (policy.status === "enabled") {
            rules = (policy.rules ?? []).filter(
              (rule) => rule.implementer_id === credential.implementer_id && rule.enabled,
            );
          }
        } catch {
          return err(apiErrorResponse("service_unavailable", requestId));
        }
      }
      try {
        const requests = await deps.store.list({
          nodeId: deps.nodeId,
          implementerId: credential.implementer_id,
        });
        return ok(200, {
          rules: rules.map((rule) => ({
            rule_id: rule.rule_id,
            implementer_id: rule.implementer_id,
            label: rule.label ?? null,
            reserve_wallet_id: rule.reserve_wallet_id ?? null,
            total_cap_zkz: rule.total_cap_zkz ?? null,
            per_send_max_zkz: rule.per_send_max_zkz,
            per_send_min_zkz: rule.per_send_min_zkz ?? null,
            window_hours: rule.window_hours,
            window_cap_zkz: rule.window_cap_zkz,
            expires_at: rule.expires_at ?? null,
            enabled: rule.enabled,
          })),
          requests: requests.map(publicRequest),
        });
      } catch {
        return err(apiErrorResponse("service_unavailable", requestId));
      }
    }

    if (verb === "GET" && pathname === REQUESTS_PATH) {
      return err(apiErrorResponse("not_found", requestId));
    }

    const match = /^\/v1\/connector-rules\/requests\/([^/]+)$/.exec(pathname);
    if (verb === "GET" && match) {
      const requestKey = match[1]!;
      try {
        parseUuid(requestKey);
      } catch {
        return err(apiErrorResponse("not_found", requestId));
      }
      try {
        const row = await deps.store.get(requestKey);
        if (
          row === null ||
          row.node_id !== deps.nodeId ||
          row.implementer_id !== credential.implementer_id
        ) {
          return err(apiErrorResponse("not_found", requestId));
        }
        return ok(200, publicRequest(row));
      } catch {
        return err(apiErrorResponse("service_unavailable", requestId));
      }
    }

    return err(apiErrorResponse("not_found", requestId));
  };
}

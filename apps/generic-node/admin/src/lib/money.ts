// SPA money client for the generic-node admin-router routes.
// Mutations always go through `api()` (never apiSoftRead — no fixture "success").
// Reads may use inventory GETs when mounted; absent routes surface as live:false.

import type {
  DestinationInventoryItem,
  OperationInventoryDetail,
  OperationInventoryListItem,
  WalletInventoryItem,
} from "@zucoins/generic-node-contracts/admin-inventory";
import {
  OPERATOR_RECOVERY_ACTIONS,
  RESERVED_RECOVERY_ACTIONS as CONTRACT_RESERVED_RECOVERY_ACTIONS,
} from "@zucoins/generic-node-contracts/operator-halt";
import { api, apiSoftRead, ApiError, type ApiFailureDetail, toApiFailureDetail } from "./api.js";

/** Same shared declaration the node projection compiles against (ZTR-1217). */
export type { WalletInventoryItem };
/** Call-site alias — wire shape is DestinationInventoryItem in contracts. */
export type DestinationItem = DestinationInventoryItem;

export interface ApprovalChallenge {
  operation_id: string;
  row_version: number;
  purpose: string;
  canonical_version: number;
  nonce: string;
  preimage_text: string;
  preimage_sha256: string;
  issued_at: string;
  expires_at: string;
  source_selector: { kind: string; wallet_id: string };
  source_pubkey: string;
  destination_address: string;
  amount_zkz: string;
  references_operation_id: string | null;
}

export interface ApproveSuccess {
  operation_id: string;
  status: "APPROVED";
  row_version: number;
  approval_id: string;
  method: string;
  consumed_at: string;
}

export interface RejectSuccess {
  operation_id: string;
  status: "REJECTED";
  row_version: number;
}

export interface EvidenceManifestItem {
  readonly kind: string;
  readonly id: string | null;
  readonly role: string | null;
  readonly digest_sha256: string | null;
  readonly summary: string;
}

export interface HeldLease {
  readonly wallet_id: string;
  readonly lease_epoch: number;
  readonly role: string;
}

export interface RecoveryDetail {
  operation_id: string;
  operation_type: string;
  status: string;
  attention_required: boolean;
  attention_reason: string | null;
  classification: string;
  classification_rationale: string;
  permitted_actions: readonly string[];
  held_leases: readonly HeldLease[];
  row_version: number;
  lease_epoch: number | null;
  recovery_nonce: string;
  recovery_nonce_issued_at: string;
  recovery_nonce_expires_at: string;
  diagnostics?: unknown;
  evidence_manifest?: readonly EvidenceManifestItem[];
}

export interface RecoveryActionSuccess {
  operation_id: string;
  action: string;
  status: string;
  row_version: number;
  [key: string]: unknown;
}

export interface InventoryListPage<T> {
  object: "list";
  data: readonly T[];
  has_more: boolean;
  next_cursor: string | null;
}

export interface CompleteInventoryResult<T> {
  readonly data: readonly T[];
  readonly live: boolean;
  /** Structured code/message/requestId when a page could not be loaded. */
  readonly error?: ApiFailureDetail;
}

type InventoryQueryValue = string | number | boolean | undefined;

// A corrupt server must neither spin forever nor return a silently truncated success.
const MAX_INVENTORY_PAGES = 10_000;

function inventoryPath(
  path: string,
  filters: object,
  cursor?: string,
): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(filters) as [string, InventoryQueryValue][]) {
    if (value !== undefined) query.set(key, String(value));
  }
  if (cursor !== undefined) query.set("after", cursor);
  const encoded = query.toString();
  return encoded.length === 0 ? path : `${path}?${encoded}`;
}

async function loadCompleteInventory<T>(
  path: string,
  filters: object = {},
): Promise<CompleteInventoryResult<T>> {
  const data: T[] = [];
  const cursors = new Set<string>();
  let cursor: string | undefined;

  for (let pageNumber = 0; pageNumber < MAX_INVENTORY_PAGES; pageNumber += 1) {
    let page: InventoryListPage<T>;
    try {
      page = await api<InventoryListPage<T>>(inventoryPath(path, filters, cursor));
    } catch (error) {
      if (error instanceof ApiError && (error.status === 401 || error.status === 403)) throw error;
      // Never expose a partial inventory as complete. Keep the exact error/request id for callers.
      return { data: [], live: false, error: toApiFailureDetail(error) };
    }

    data.push(...(page.data ?? []));
    if (!page.has_more) return { data, live: true };

    const next = page.next_cursor;
    if (typeof next !== "string" || next.length === 0 || cursors.has(next)) {
      throw new ApiError(502, {
        error: {
          code: "invalid_pagination_cursor",
          message: "Inventory pagination returned a missing or repeated cursor.",
        },
      });
    }
    cursors.add(next);
    cursor = next;
  }

  throw new ApiError(502, {
    error: {
      code: "inventory_page_limit_exceeded",
      message: `Inventory exceeded the ${MAX_INVENTORY_PAGES}-page safety limit.`,
    },
  });
}

/**
 * List row (GET /admin/v1/operations) and point read (GET /admin/v1/operations/:id).
 *
 * Both come from `@zucoins/generic-node-contracts/admin-inventory` — the same declaration the
 * node's projection compiles against — rather than being transcribed here. A hand-copied list
 * type is how `destination_address` came to be read off a summary row the server never sent it
 * on; the shared declaration makes that a build failure instead of a column of dashes.
 */
export type { OperationInventoryDetail };
export type OperationListItem = OperationInventoryListItem;

/**
 * Deep-link path for an operation detail view.
 * Always `/operations/:id` — never gate on type. SEND dual-control stays on
 * `/transfers/:id` and is linked from the detail page toolbar.
 */
export function operationDetailPath(operationId: string, _operationType?: string | null): string {
  void _operationType;
  return `/operations/${encodeURIComponent(operationId)}`;
}

export function isSendOperationType(operationType: string | null | undefined): boolean {
  const kind = (operationType ?? "").toUpperCase();
  return kind === "SEND_EXTERNAL" || kind.includes("SEND");
}

export function newIdempotencyKey(): string {
  // Idempotency keys must be unique per request; unpredictability is not required.
  // crypto.randomUUID is secure-context-only — fall back on plain HTTP (ZTR-1168).
  const c = globalThis.crypto;
  if (c && typeof c.randomUUID === "function") {
    return c.randomUUID();
  }
  if (c && typeof c.getRandomValues === "function") {
    const bytes = new Uint8Array(16);
    c.getRandomValues(bytes);
    bytes[6] = (bytes[6]! & 0x0f) | 0x40;
    bytes[8] = (bytes[8]! & 0x3f) | 0x80;
    const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }
  // Last resort: time + Math.random — unique enough for idempotency, never silent throw.
  return `idem-${Date.now().toString(16)}-${Math.random().toString(16).slice(2, 10)}-${Math.random().toString(16).slice(2, 10)}`;
}


export async function getApprovalChallenge(operationId: string): Promise<ApprovalChallenge> {
  return api<ApprovalChallenge>(
    `/external-sends/${encodeURIComponent(operationId)}/approval-challenge`,
  );
}

export async function postApprove(
  operationId: string,
  body: {
    challenge_nonce: string;
    expected_row_version: number;
    preimage_sha256: string;
    device_key_id: string | null;
    device_signature: string | null;
  },
  totp: string,
): Promise<ApproveSuccess> {
  return api<ApproveSuccess>(`/external-sends/${encodeURIComponent(operationId)}/approve`, {
    method: "POST",
    body: JSON.stringify(body),
    totp,
    idempotencyKey: newIdempotencyKey(),
  });
}

export async function postReject(
  operationId: string,
  body: { expected_row_version: number; reason: string },
  totp: string,
): Promise<RejectSuccess> {
  return api<RejectSuccess>(`/external-sends/${encodeURIComponent(operationId)}/reject`, {
    method: "POST",
    body: JSON.stringify(body),
    totp,
    idempotencyKey: newIdempotencyKey(),
  });
}

export async function getRecovery(operationId: string): Promise<RecoveryDetail> {
  return api<RecoveryDetail>(`/operations/${encodeURIComponent(operationId)}/recovery`);
}

export async function postRecoveryAction(
  operationId: string,
  body: {
    action: string;
    expected_row_version: number;
    recovery_nonce: string;
    proof_id?: string | null;
    operator_note?: string;
  },
  totp: string,
): Promise<RecoveryActionSuccess> {
  return api<RecoveryActionSuccess>(
    `/operations/${encodeURIComponent(operationId)}/recovery-actions`,
    {
      method: "POST",
      body: JSON.stringify(body),
      totp,
      idempotencyKey: newIdempotencyKey(),
    },
  );
}

/**
 * Reserved at launch — admitted in the frozen catalog but not grantable without a
 * positive non-landing oracle. Re-exported from the contract so the SPA cannot drift.
 */
export const RESERVED_RECOVERY_ACTIONS = CONTRACT_RESERVED_RECOVERY_ACTIONS;

/**
 * Live recovery actions the operator console may POST today: the frozen closed catalog
 * minus RESERVED. Derived as a set difference so a tenth action or a promotion out of
 * RESERVED fails the catalog-equality test rather than silently hiding a button.
 */
export const LIVE_RECOVERY_ACTIONS = OPERATOR_RECOVERY_ACTIONS.filter(
  (action) =>
    !(CONTRACT_RESERVED_RECOVERY_ACTIONS as readonly string[]).includes(action),
) as readonly Exclude<
  (typeof OPERATOR_RECOVERY_ACTIONS)[number],
  (typeof CONTRACT_RESERVED_RECOVERY_ACTIONS)[number]
>[];

/** Full frozen catalog — LIVE ∪ RESERVED. Re-exported for equality gates. */
export { OPERATOR_RECOVERY_ACTIONS };

const RECOVERY_ACTION_LABELS: Readonly<Record<string, string>> = {
  RETRY_OBSERVATION: "Retry observation",
  REDELIVER_EXACT_PARTIAL: "Re-send exact transfer code",
  CONTINUE_EXTERNAL_WAIT: "Continue waiting for redemption",
  CLOSE_NEVER_STARTED_EXTERNAL_SEND: "Close never-started send",
  CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED: "Close send (proven not landed)",
  REBUILD_INTERNAL_MOVE: "Rebuild internal transfer",
  RELEASE_EXPIRED_RECEIVE: "Release expired receive",
  QUARANTINE_WALLETS: "Quarantine wallets",
  ACKNOWLEDGE_KEEP_PINNED: "Acknowledge (keep pinned)",
};

export function recoveryActionLabel(action: string): string {
  return RECOVERY_ACTION_LABELS[action] ?? action;
}

export function isLiveRecoveryAction(action: string): boolean {
  return (LIVE_RECOVERY_ACTIONS as readonly string[]).includes(action);
}

export function isReservedRecoveryAction(action: string): boolean {
  return (RESERVED_RECOVERY_ACTIONS as readonly string[]).includes(action);
}

/**
 * Split permitted_actions into live (clickable) vs reserved/unknown (honest disabled).
 * Unknown tokens outside the closed catalog are treated as non-live (fail closed in UI).
 */
export function partitionRecoveryActions(permitted: readonly string[]): {
  readonly live: readonly string[];
  readonly unavailable: readonly { readonly action: string; readonly reason: string }[];
} {
  const live: string[] = [];
  const unavailable: { action: string; reason: string }[] = [];
  for (const action of permitted) {
    if (isLiveRecoveryAction(action)) {
      live.push(action);
    } else if (isReservedRecoveryAction(action)) {
      unavailable.push({
        action,
        reason: "Reserved until positive non-landing proof is available.",
      });
    } else {
      unavailable.push({
        action,
        reason: "Not implemented on this node — action would fail closed.",
      });
    }
  }
  return { live, unavailable };
}

export async function postBless(
  destinationId: string,
  body: {
    nonce: string;
    issued_at: string;
    expires_at: string;
    device_key_id: string;
    device_signature: string;
  },
  totp: string,
): Promise<unknown> {
  return api(`/destinations/${encodeURIComponent(destinationId)}/bless`, {
    method: "POST",
    body: JSON.stringify(body),
    totp,
    idempotencyKey: newIdempotencyKey(),
  });
}

export interface DeviceKeyListItem {
  readonly id: string;
  readonly label: string;
  readonly enrolled_at: string;
}

export async function listDeviceKeys(): Promise<DeviceKeyListItem[]> {
  const response = await api<{ readonly keys: DeviceKeyListItem[] }>("/device-keys");
  return response.keys;
}

export interface EnrollmentChallengeResponse {
  readonly nonce: string;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly purpose: "zp-device-enrol-v1";
  readonly canonical_version: 1;
  readonly node_id: string;
}

export async function postEnrollmentChallenge(): Promise<EnrollmentChallengeResponse> {
  return api<EnrollmentChallengeResponse>("/device-keys/enrollment-challenge", {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export interface GenesisEnrolBody {
  readonly label: string;
  readonly new_device_key_id: string;
  readonly new_device_public_key: string;
  readonly new_device_pop_signature: string;
  readonly challenge_nonce: string;
}

export interface GenesisEnrolResult {
  readonly id: string;
  readonly label: string;
  readonly enrolled_at: string;
}

export async function postGenesisEnrol(
  body: GenesisEnrolBody,
  totp: string,
): Promise<GenesisEnrolResult> {
  return api<GenesisEnrolResult>("/device-keys/enrol", {
    method: "POST",
    body: JSON.stringify(body),
    totp,
    idempotencyKey: newIdempotencyKey(),
  });
}

export async function postRevokeDevice(
  deviceKeyId: string,
  body: {
    readonly authorizing_device_key_id: string;
    readonly authorizing_device_signature: string;
  },
  totp: string,
): Promise<{ readonly id: string; readonly revoked: boolean; readonly revoked_at: string | null }> {
  return api(`/device-keys/${encodeURIComponent(deviceKeyId)}/revoke`, {
    method: "POST",
    body: JSON.stringify(body),
    totp,
    idempotencyKey: newIdempotencyKey(),
  });
}

export async function postRetire(destinationId: string, totp: string): Promise<unknown> {
  // SPA always gates retire with TOTP (fail-closed client); server is session+CSRF.
  return api(`/destinations/${encodeURIComponent(destinationId)}/retire`, {
    method: "POST",
    body: JSON.stringify({}),
    totp,
    idempotencyKey: newIdempotencyKey(),
  });
}

/** Inventory list. Loads every cursor page or returns no partial data. */
export async function listDestinationsInventory(
  filters: { readonly state?: string; readonly limit?: number } = {},
): Promise<CompleteInventoryResult<DestinationItem>> {
  return loadCompleteInventory<DestinationItem>("/destinations", filters);
}

/** Audit rows exposed by the session-gated inventory GET. */
export interface AuditInventoryItem {
  readonly id: string;
  readonly actor_kind: string;
  readonly actor_id: string | null;
  readonly action: string;
  readonly operation_id: string | null;
  readonly wallet_id: string | null;
  readonly details: unknown;
  readonly details_sha256: string;
  readonly created_at: string;
}

export interface WalletInventoryFilters {
  readonly state?: string;
  readonly key_origin?: string;
  readonly recovery_verified?: boolean;
  readonly limit?: number;
}

export function listWalletsInventory(): Promise<CompleteInventoryResult<WalletInventoryItem>>;
export function listWalletsInventory(
  filters: WalletInventoryFilters,
): Promise<CompleteInventoryResult<WalletInventoryItem>>;
export async function listWalletsInventory(
  filters: WalletInventoryFilters = {},
): Promise<CompleteInventoryResult<WalletInventoryItem>> {
  return loadCompleteInventory<WalletInventoryItem>("/wallets", filters);
}

/** Point-read by wallet id or public key. Only a real 404 means absence. */
export async function getWalletInventory(idOrPubkey: string): Promise<WalletInventoryItem | null> {
  try {
    return await api<WalletInventoryItem>(`/wallets/${encodeURIComponent(idOrPubkey)}`);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return null;
    throw error;
  }
}

export interface AuditInventoryFilters {
  readonly actor_kind?: string;
  readonly action?: string;
  readonly created_after?: string;
  readonly created_before?: string;
  readonly limit?: number;
}

/** Audit inventory is complete only after every cursor page succeeds. */
export function listAuditInventory(): Promise<CompleteInventoryResult<AuditInventoryItem>>;
export function listAuditInventory(
  filters: AuditInventoryFilters,
): Promise<CompleteInventoryResult<AuditInventoryItem>>;
export async function listAuditInventory(
  filters: AuditInventoryFilters = {},
): Promise<CompleteInventoryResult<AuditInventoryItem>> {
  return loadCompleteInventory<AuditInventoryItem>("/audit", filters);
}

/**
 * Sum observed_balance_zkz over wallets. Null / unobserved contributes 0.
 * Fixed 4 decimal places for UI — inputs are decimal perkes strings of (ZKZ grammar).
 */
export function sumObservedEquityZkz(wallets: readonly WalletInventoryItem[]): string {
  let micros = 0n;
  for (const w of wallets) {
    const raw = w.observed_balance_zkz;
    if (raw === null || raw === undefined || raw === "") continue;
    const s = String(raw).trim();
    const m = /^([+-]?)(\d+)(?:\.(\d{1,12}))?$/.exec(s);
    if (!m) continue;
    const sign = m[1] === "-" ? -1n : 1n;
    const whole = BigInt(m[2] ?? "0");
    const frac = (m[3] ?? "").padEnd(4, "0").slice(0, 4);
    const unit = whole * 10000n + BigInt(frac || "0");
    micros += sign * unit;
  }
  const neg = micros < 0n;
  const abs = neg ?  -micros : micros;
  const whole = abs / 10000n;
  const frac = (abs % 10000n).toString().padStart(4, "0");
  return `${neg ? "-" : ""}${whole.toString()}.${frac}`;
}

export async function listSendOperationsInventory(
  filters: {
    readonly status?: string;
    readonly attention_required?: boolean;
    readonly limit?: number;
  } = {},
): Promise<CompleteInventoryResult<OperationListItem>> {
  return loadCompleteInventory<OperationListItem>("/operations", {
    kind: "SEND_EXTERNAL",
    ...filters,
  });
}

/** All operation kinds (RECEIVE_EXTERNAL/MOVE_INTERNAL/SEND_EXTERNAL), every page —
 * a single unpaginated read silently truncates counts/exports on any account past
 * page one (1033 rework). */
export function listOperationsInventory(): Promise<CompleteInventoryResult<OperationListItem>>;
export function listOperationsInventory(
  filters: {
    readonly status?: string;
    readonly attention_required?: boolean;
    readonly limit?: number;
  },
): Promise<CompleteInventoryResult<OperationListItem>>;
export async function listOperationsInventory(
  filters: {
    readonly status?: string;
    readonly attention_required?: boolean;
    readonly limit?: number;
  } = {},
): Promise<CompleteInventoryResult<OperationListItem>> {
  return loadCompleteInventory<OperationListItem>("/operations", filters);
}

export async function getOperationInventory(
  operationId: string,
): Promise<OperationInventoryDetail | null> {
  try {
    return await api<OperationInventoryDetail>(`/operations/${encodeURIComponent(operationId)}`);
  } catch (err) {
    // 404 = genuine absence. 503/outage must not look like "no row".
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  }
}

/**
 * After approve: read status only from recovery or inventory.
 * Challenge 404 is never terminal money status (absence ≠ APPROVED).
 */
export async function pollSendState(
  operationId: string,
  opts?: { attempts?: number; delayMs?: number },
): Promise<{ status: string; source: "recovery" | "inventory" | "unknown" }> {
  const attempts = opts?.attempts ?? 8;
  const delayMs = opts?.delayMs ?? 400;
  for (let i = 0; i < attempts; i++) {
    try {
      const rec = await getRecovery(operationId);
      if (rec.status && rec.status !== "CREATED") {
        return { status: rec.status, source: "recovery" };
      }
      if (rec.status === "CREATED" && i === attempts - 1) {
        return { status: rec.status, source: "recovery" };
      }
    } catch {
      /* try inventory */
    }
    try {
      const inv = await getOperationInventory(operationId);
      if (inv?.status && inv.status !== "CREATED") {
        return { status: inv.status, source: "inventory" };
      }
      if (inv?.status === "CREATED" && i === attempts - 1) {
        return { status: inv.status, source: "inventory" };
      }
    } catch {
      /* outage / error — do not invent a terminal status */
    }
    if (i < attempts - 1) {
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
  return { status: "unknown", source: "unknown" };
}

export function formatMoneyError(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    const rid = err.requestId ? ` (${err.requestId})` : "";
    return `${err.message || fallback}${rid}`;
  }
  if (err instanceof Error) return err.message;
  return fallback;
}

export function isCancelled(err: unknown): boolean {
  return (
    err instanceof Error &&
    (err.name === "TotpCancelledError" ||
      err.message === "cancelled" ||
      err.message === "TOTP entry cancelled")
  );
}

/** Wire shape for GET/POST /admin/v1/halt. */
export interface HaltState {
  engaged: boolean;
  reason: string | null;
  updated_at: string | null;
  updated_by: string | null;
}

export async function fetchHaltState(): Promise<HaltState> {
  return api<HaltState>("/halt");
}

export async function postHaltToggle(
  body: { engaged: boolean; reason?: string },
  totp: string,
): Promise<HaltState> {
  return api<HaltState>("/halt", {
    method: "POST",
    body: JSON.stringify(body),
    totp,
    // Server idempotencyGate requires 16–255 visible ASCII (admin_halt).
    idempotencyKey: newIdempotencyKey(),
  });
}

// Implementer API key management. The raw key is
// returned exactly once on issue and is never logged here; the operator copies it
// into their implementer website backend env (never customer browser JS).
export interface ApiKeyListing {
  readonly id: string;
  readonly prefix: string;
  readonly scopes: readonly string[];
  readonly status: string;
  readonly key_version: number;
  readonly issued_at: string;
  readonly expires_at: string | null;
  readonly revoked_at: string | null;
  readonly last_used_at: null;
}

export interface ApiKeyIssueResult {
  readonly id: string;
  readonly raw_key: string;
  readonly prefix: string;
  readonly scopes: readonly string[];
  readonly key_version: number;
  readonly issued_at: string;
  readonly expires_at: string | null;
}

/** Key inventory is empty only after a successful GET; unavailable stays explicit. */
export async function listApiKeys(): Promise<{
  readonly keys: readonly ApiKeyListing[];
  readonly live: boolean;
}> {
  const r = await apiSoftRead<{ readonly keys: readonly ApiKeyListing[] }>("/api-keys", { keys: [] });
  return { keys: r.data.keys ?? [], live: r.live };
}

export async function postIssueApiKey(
  scopes: readonly string[] | undefined,
  totp: string,
): Promise<ApiKeyIssueResult> {
  return api<ApiKeyIssueResult>("/api-keys", {
    method: "POST",
    body: JSON.stringify(scopes === undefined ? {} : { scopes }),
    totp,
    // Server idempotencyGate requires 16–255 visible ASCII (admin_api_keys_issue).
    idempotencyKey: newIdempotencyKey(),
  });
}

export async function postRevokeApiKey(
  credentialId: string,
  totp: string,
): Promise<{ readonly id: string; readonly revoked: boolean }> {
  return api<{ id: string; revoked: boolean }>(`/api-keys/${encodeURIComponent(credentialId)}/revoke`, {
    method: "POST",
    body: JSON.stringify({}),
    totp,
    // Server idempotencyGate requires 16–255 visible ASCII (admin_api_keys_revoke).
    idempotencyKey: newIdempotencyKey(),
  });
}

// Reporting credential management. Issue node-mints the
// credential and returns the raw private seed exactly ONCE; it replaces dependence on
// REPORTING_KEY_OUT (the node no longer has to write the seed to its filesystem). The list
// response type carries NO private field, so no list refetch can resurface the seed. The
// reporting private seed is a verification key, not a wallet signing key — wallet-key custody is not
// implicated.
export interface ReportingKeyListing {
  readonly id: string;
  readonly node_id: string;
  readonly implementer_id: string;
  readonly public_key: string;
  readonly registered_at: string;
  readonly status: string;
}

export interface ReportingKeyIssueResult {
  readonly id: string;
  readonly raw_private_key: string;
  readonly public_key: string;
  readonly key_id: string;
  readonly registered_at: string;
}

/** Reporting inventory is empty only after a successful GET; unavailable stays explicit. */
export async function listReportingKeys(): Promise<{
  readonly keys: readonly ReportingKeyListing[];
  readonly live: boolean;
}> {
  const r = await apiSoftRead<{ readonly keys: readonly ReportingKeyListing[] }>("/reporting-keys", {
    keys: [],
  });
  return { keys: r.data.keys ?? [], live: r.live };
}

export async function postIssueReportingKey(totp: string): Promise<ReportingKeyIssueResult> {
  return api<ReportingKeyIssueResult>("/reporting-keys", {
    method: "POST",
    body: JSON.stringify({}),
    totp,
    idempotencyKey: newIdempotencyKey(),
  });
}

/** Lost-seed recovery — retires current head implementer and mints replacements once. */
export interface ReportingKeyRecoverResult extends ReportingKeyIssueResult {
  readonly object: "reporting_key_recovered";
  readonly superseded_key_id: string;
  readonly implementer_id: string;
  readonly implementer_raw_key: string;
  readonly implementer_key_prefix: string;
}

export async function postRecoverLostReportingKey(
  lostKeyId: string,
  totp: string,
): Promise<ReportingKeyRecoverResult> {
  return api<ReportingKeyRecoverResult>("/reporting-keys/recover-lost", {
    method: "POST",
    body: JSON.stringify({ lost_key_id: lostKeyId }),
    totp,
    idempotencyKey: newIdempotencyKey(),
  });
}

/**
 * Mint the next reporting credential (raw shown once). The node holds a single reporting
 * credential per implementer and derives the lifecycle head itself, so `keyId` names the
 * credential being superseded for the caller's audit/UX — it is not sent on the wire.
 * Superseding an ACTIVE credential is the implementer-signed lifecycle rotation ceremony
 * and is not surfaced here: when a credential is already ACTIVE the node fails closed (409).
 */
export async function postRotateReportingKey(
  keyId: string,
  totp: string,
): Promise<ReportingKeyIssueResult> {
  void keyId;
  return postIssueReportingKey(totp);
}

// --- Home readiness checklist ---

export type ReadinessStatus = "ok" | "blocked" | "optional" | "unknown" | "amber";

export interface ReadinessRow {
  readonly id: string;
  readonly status: ReadinessStatus;
  readonly title: string;
  readonly detail: string;
  readonly href: string;
  readonly blocks_ops?: readonly string[];
}

export interface ReadinessChecklist {
  readonly object: "readiness_checklist";
  readonly generated_at: string;
  readonly rows: readonly ReadinessRow[];
}

export async function fetchReadinessChecklist(): Promise<ReadinessChecklist> {
  return api<ReadinessChecklist>("/readiness");
}

// ── Mode A recovery ceremony ─────────────────────────────────────────────────
// Master key travels only in the POST body for this call. Never put it in the
// path, query, or client storage. Responses are digests/counts only.

export type CeremonyStage =
  | "accepted"
  | "exporting_archive"
  | "restoring_throwaway"
  | "verifying_wallets"
  | "stamping"
  | "summarising"
  | "complete"
  | "failed";

export interface CeremonyProgressEvent {
  readonly stage: CeremonyStage;
  readonly detail: string | null;
  readonly at: string;
}

export interface CeremonyDigestSummary {
  readonly ok: boolean;
  readonly ceremony_id: string;
  readonly export_id: string | null;
  readonly archive_sha256: string | null;
  readonly accepted: boolean;
  readonly stamped: number;
  readonly failed_closed: number;
  readonly skipped: number;
  readonly born_blocked: number;
  readonly abort_reasons: readonly string[];
  readonly instance_destroyed: boolean;
  readonly recovery_verified_on_live: number;
}

export interface CeremonyStatusResponse {
  readonly ceremony_id: string | null;
  readonly status: "idle" | "running" | "complete" | "failed";
  readonly stage: CeremonyStage | null;
  readonly progress: readonly CeremonyProgressEvent[];
  readonly summary: CeremonyDigestSummary | null;
  readonly error: { readonly code: string; readonly message: string } | null;
  readonly started_at: string | null;
  readonly finished_at: string | null;
  readonly in_flight: boolean;
}

export async function postRecoveryCeremonyStart(
  body: {
    readonly vault_master_key: string;
    readonly archive_epoch_master_key?: string;
  },
  totp: string,
): Promise<CeremonyStatusResponse> {
  return api<CeremonyStatusResponse>("/recovery-ceremony/start", {
    method: "POST",
    body: JSON.stringify(body),
    totp,
    idempotencyKey: newIdempotencyKey(),
  });
}

export async function getRecoveryCeremonyStatus(
  ceremonyId?: string,
): Promise<CeremonyStatusResponse> {
  const q =
    ceremonyId !== undefined && ceremonyId.length > 0
      ? `?ceremony_id=${encodeURIComponent(ceremonyId)}`
      : "";
  return api<CeremonyStatusResponse>(`/recovery-ceremony/status${q}`);
}


// --- Recovery pack create/prove ---

export interface RecoveryPackCreateResponse {
  readonly object: "recovery_pack_create";
  readonly format: "zp-node-recovery-pack-v2";
  readonly pack_content_sha256: string;
  /** Digest of the artifact a re-issue replaced — the one to destroy. */
  readonly previous_pack_content_sha256: string | null;
  readonly filename: string;
  readonly pack_file_b64: string;
  readonly content_type: string;
}

export interface RecoveryPackProveResponse {
  readonly object: "recovery_pack_prove";
  readonly accepted: boolean;
  readonly ceremony_id: string;
  readonly recovery_verification_id: string;
  readonly verified_wallet_count: number | null;
  readonly status: string;
  readonly in_flight: boolean;
  /** 1 = a superseded digit-passcode pack was proven; it must be re-issued and destroyed. */
  readonly pack_version?: 1 | 2;
}

/**
 * Crockford base32 — the same 32 symbols the node generates with, chosen so a
 * secret can be transcribed off a screen without I/L/O/U ambiguity. Must stay
 * byte-identical to RECOVERY_PACK_SECRET_ALPHABET on the node (ZTR-1220).
 */
const RECOVERY_SECRET_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/** 26 × log2(32) = 130 bits, over the node's 128-bit creation floor. */
const RECOVERY_SECRET_CHARS = 26;
/** Mirror of node RECOVERY_PACK_MIN_DISTINCT_CHARS — redraw if a draw lands under. */
const RECOVERY_SECRET_MIN_DISTINCT = 10;
/** Mirrors node RECOVERY_PACK_MAX_* structure thresholds (ZTR-1220 Review B/r4). */
const RECOVERY_SECRET_MAX_MONOTONE_RUN = 6;
const RECOVERY_SECRET_MAX_SAME_DELTA_PAIRS = 10;
const RECOVERY_SECRET_MAX_SAME_RUN = 4;
const RECOVERY_SECRET_MAX_PAIRED_DOUBLES = 4;
const RECOVERY_SECRET_MAX_LETTER_RUN = 14;
const RECOVERY_SECRET_MAX_LAG_MATCH_RUN = 6;
const RECOVERY_SECRET_MAX_LAG_MATCH_FRAC = 0.4;
const RECOVERY_SECRET_MAX_REPEATED_SUBSTRING = 4;
const RECOVERY_SECRET_MAX_CLASS_ALTERNATION_RUN = 10;
const RECOVERY_SECRET_MAX_CLASS_PAIR_RUN = 6;
const RECOVERY_SECRET_MAX_KEYBOARD_RUN = 5;
const RECOVERY_SECRET_MAX_STRIDED_MONOTONE_RUN = 6;
/** Mirrors node RECOVERY_PACK_* human-pattern class floor (ZTR-1220 r5). */
const RECOVERY_SECRET_MAX_DIGIT_RUN = 8;
const RECOVERY_SECRET_MAX_LATIN_VOWEL_FRAC = 0.4;
const RECOVERY_SECRET_MIN_LETTERS_FOR_VOWEL_GUARD = 18;
const RECOVERY_SECRET_MAX_ENGLISH_BIGRAM_HITS = 10;
const RECOVERY_SECRET_MAX_ENGLISH_TRIGRAM_HITS = 3;
const RECOVERY_SECRET_MIN_ENGLISH_COVER_LETTERS = 8;
const RECOVERY_SECRET_MIN_ENGLISH_COVER_WITH_VOWEL = 6;
const RECOVERY_SECRET_MIN_VOWEL_FRAC_WITH_COVER = 0.34;
const RECOVERY_SECRET_MIN_MNEMONIC_PAD_LETTERS = 14;
const RECOVERY_SECRET_MIN_MNEMONIC_PAD_LETTER_FRAC = 0.55;
/** Hard redraw ceiling — throw rather than emit a structure-failing secret. */
const RECOVERY_SECRET_MAX_DRAW_ATTEMPTS = 64;

const RECOVERY_SECRET_KEYBOARD_LAYOUT: readonly string[] = [
  "1234567890",
  "QWERTYUIOP",
  "ASDFGHJKL",
  "ZXCVBNM",
];

function buildRecoverySecretKeyboardWalks(): readonly string[] {
  const filterCrock = (s: string): string =>
    [...s].filter((c) => RECOVERY_SECRET_ALPHABET.includes(c)).join("");
  const walks = new Set<string>();
  const add = (raw: string): void => {
    const s = filterCrock(raw);
    if (s.length >= RECOVERY_SECRET_MAX_KEYBOARD_RUN) {
      walks.add(s);
      walks.add([...s].reverse().join(""));
    }
  };
  for (const row of RECOVERY_SECRET_KEYBOARD_LAYOUT) add(row);
  add("QWERTYASDFGHZXCVBN");
  add("0123456789");
  const maxCol = Math.max(...RECOVERY_SECRET_KEYBOARD_LAYOUT.map((r) => r.length));
  const columns: string[] = [];
  for (let c = 0; c < maxCol; c++) {
    let col = "";
    for (const row of RECOVERY_SECRET_KEYBOARD_LAYOUT) {
      if (c < row.length) col += row[c]!;
    }
    columns.push(col);
    add(col);
  }
  const colVariants: readonly (readonly string[])[] = [
    columns,
    columns.map((col) => [...col].reverse().join("")),
  ];
  for (const cols of colVariants) {
    for (let start = 0; start < cols.length; start++) {
      let acc = "";
      for (let end = start; end < cols.length; end++) {
        acc += cols[end]!;
        add(acc);
      }
      let racc = "";
      for (let end = start; end >= 0; end--) {
        racc += cols[end]!;
        add(racc);
      }
    }
  }
  for (let r0 = 0; r0 < RECOVERY_SECRET_KEYBOARD_LAYOUT.length; r0++) {
    for (let c0 = 0; c0 < maxCol; c0++) {
      let dr = "";
      let dl = "";
      for (
        let r = r0, c = c0;
        r < RECOVERY_SECRET_KEYBOARD_LAYOUT.length &&
        c < RECOVERY_SECRET_KEYBOARD_LAYOUT[r]!.length;
        r++, c++
      ) {
        dr += RECOVERY_SECRET_KEYBOARD_LAYOUT[r]![c]!;
      }
      for (
        let r = r0, c = c0;
        r < RECOVERY_SECRET_KEYBOARD_LAYOUT.length &&
        c >= 0 &&
        c < RECOVERY_SECRET_KEYBOARD_LAYOUT[r]!.length;
        r++, c--
      ) {
        dl += RECOVERY_SECRET_KEYBOARD_LAYOUT[r]![c]!;
      }
      add(dr);
      add(dl);
    }
  }
  return [...walks];
}

const RECOVERY_SECRET_KEYBOARD_WALKS: readonly string[] = buildRecoverySecretKeyboardWalks();

const RECOVERY_SECRET_DICT_MIN5: readonly string[] = [
  "CORRECT",
  "HORSE",
  "BATTERY",
  "STAPLE",
  "PLEASE",
  "LETME",
  "WINTER",
  "COMING",
  "NORTH",
  "FORCE",
  "NEVER",
  "GONNA",
  "MASTER",
  "PASSWORD",
  "HUNTER",
  "QWERTY",
  "MAYTHE",
  "SECRET",
  "BACKUP",
  "ADMIN",
  "LOGIN",
  "WELCOME",
  "MONKEY",
  "DRAGON",
  "SHADOW",
  "PRINCESS",
  "FOOTBALL",
  "BASEBALL",
  "SUPPLY",
  "CHAIN",
  "PHRASE",
  "ORANGE",
  "BANANA",
  "COFFEE",
  "TIGER",
  "EAGLE",
  "RIVER",
  "MOUNTAIN",
  "SUNSET",
  "SUMMER",
  "SPRING",
  "AUTUMN",
  "MONEY",
  "TRUST",
  "VAULT",
  "WALLET",
  "CRYPTO",
  "BITCOIN",
  "RECOVERY",
  "CEREMONY",
  "OPERATOR",
  "APPLE",
  "LETMIN",
  "QVICK",
  "BROWN",
  "JUMPS",
  "STRANGER",
  "STRANGE",
  "THINGS",
  "PLANET",
  "HACKTHE",
  "JACKDAW",
  "FROZEN",
  "HEISENBERG",
  "BREAKING",
  "YELLOW",
  "MARINE",
  "SVBMARINE",
  "HEAVEN",
  "STAIRWAY",
  "BOHEMIAN",
  "RHAPSODY",
  "FOOBAR",
  "BELIEVE",
  "BELIEVIN",
  "SHALL",
  "ENTROPY",
  "FLOOR",
  "WORKAND",
  "NOPLAY",
  "LOREM",
  "IPSVM",
  "MORPH",
  "ONCEVPON",
  "VPONATIME",
  "YODASHALL",
  "DONTSTOP",
  "HOWNOW",
  "COWFARM",
];

const RECOVERY_SECRET_DICT_LEN4_CUSTODY: readonly string[] = [
  "CODE",
  "PASS",
  "NODE",
  "PACK",
  "ROOT",
  "LOCK",
  "SAFE",
  "OPEN",
  "TEST",
  "DEMO",
  "KEYS",
  "KEYX",
  "PINX",
];
const RECOVERY_SECRET_DICT_LEN4: readonly string[] = [
  "CODE",
  "PASS",
  "NODE",
  "PACK",
  "THEN",
  "THIS",
  "THAT",
  "HAVE",
  "YOUR",
  "INTO",
  "FROM",
  "LOVE",
  "ROOT",
  "WITH",
  "BACK",
  "LOCK",
  "SAFE",
  "OPEN",
  "TEST",
  "DEMO",
  "USER",
  "HOME",
  "WORK",
  "PLAY",
  "WORD",
  "FISH",
  "BIRD",
  "DARK",
  "BLUE",
  "GOLD",
  "FIRE",
  "WIND",
  "SNOW",
  "RAIN",
  "STAR",
  "MOON",
  "LIFE",
  "TIME",
  "YEAR",
  "WEEK",
  "HAND",
  "HEAD",
  "MIND",
  "SOUL",
  "ONCE",
  "VPON",
  "YODA",
  "DONT",
  "STOP",
  "HACK",
  "JACK",
  "FARM",
  "KEYS",
];

const RECOVERY_SECRET_LEET_FOLD: Readonly<Record<string, string>> = {
  "0": "O",
  "1": "I",
  "3": "E",
  "4": "A",
  "5": "S",
  "7": "T",
};

/**
 * Mirror of node `recoverySecretWeakness` structure floor (post-alphabet).
 * Keep byte-identical rejection class so the SPA never posts a secret the node
 * would answer 400 weak_recovery_secret for.
 */
/** Classic English bigrams — mirror of node OPEN_ENGLISH_BIGRAMS. */
const RECOVERY_SECRET_OPEN_BIGRAMS: ReadonlySet<string> = new Set(
  (
    "TH HE IN ER AN RE ON EN AT ND ED ES NT HA TO OU EA NG AS OR TI IS ET IT AR TE SE HI OF " +
    "DE RO LE SA ME NE CE RA IC NS RI IO WE VE WA TA CA MA BE PE KE YE ST CK WH GH SH CH " +
    "BR CR DR FR GR PR TR WR BL CL FL GL PL SL SM SN SP SW TW SC SK QU"
  ).split(/\s+/),
);

const RECOVERY_SECRET_OPEN_TRIGRAMS: ReadonlySet<string> = new Set(
  (
    "THE AND ING HER HAT HIS THA ERE FOR ENT ION HAS NTH TIO ALL VER TER EST THI CON RES " +
    "PRO ARE OUT PER ECT ONE OUR ITH FRO MEN TED ERS ATH EVE OME COM ATE IVE RED"
  ).split(/\s+/),
);

const RECOVERY_SECRET_OPEN_WORDS_RAW: readonly string[] = (
  "THAT WITH HAVE THIS WILL YOUR FROM THEY KNOW WANT BEEN GOOD MUCH SOME TIME VERY WHEN COME HERE JUST LIKE LONG MAKE MANY MORE ONLY OVER SUCH TAKE THAN THEM WELL WERE " +
  "ABOUT AFTER AGAIN BEING EVERY FIRST GREAT HOUSE LARGE NEVER OTHER PLACE POINT RIGHT SMALL SOUND STILL THEIR THESE THING THINK THREE UNDER WATER WHERE WHICH WORLD WOULD WRITE " +
  "PEOPLE SCHOOL MOTHER FATHER FAMILY FRIEND SECOND NUMBER ALWAYS AROUND BECAUSE BEFORE CHANGE DURING FOLLOW HAPPEN LETTER NATURE PICTURE SHOULD ANIMAL BROTHER SISTER " +
  "APPLE ORANGE BANANA TABLE CHAIR HOUSE WATER CRYSTAL RIVER OCEAN BEACH MOUNTAIN FOREST STORM CLOUD NIGHT LIGHT DREAM " +
  "NORTH SOUTH EAST WEST CENTER KING QUEEN PRINCE KNIGHT CASTLE DRAGON SWORD MAGIC SPELL WIZARD " +
  "MUSIC DANCE SONG MOVIE BOOK STORY POEM PLAY GAME SPORT TEAM BALL GOAL SCORE " +
  "PHONE EMAIL MESSAGE MEDIA VIDEO PHOTO CAMERA SCREEN COMPUTER " +
  "MONEY POWER TRUTH JUSTICE PEACE FREEDOM ACCESS TOKEN SECRET MASTER PASSWORD PRIVATE PUBLIC " +
  "NETWORK SERVER SYSTEM BACKUP RECOVERY CORRECT HORSE BATTERY STAPLE PLEASE WINTER SUMMER " +
  "LONDON PARIS TOKYO BERLIN YORK CITY TOWN COUNTRY EARTH SPACE PLANET " +
  "BLACK WHITE GREEN YELLOW PURPLE BROWN ORANGE ANSWER QUICK BROWN JUMPS OVER LAZY " +
  "EXPRESS TRAIN PLANE CAKE PORTAL STYLE WAND WARS STAR PEPPER SALT SUGAR BREAD " +
  "SPHINX QUARTZ VORTEX CYBER SECURITY RAIN SPAIN FALLS BACK FRONT LEFT RIGHT " +
  "HUMAN HEART SPEAK FORCE NEVER THING HEAVEN " +
  "PART PRESS PORT HAND LAND HARD FIRE WIRE BALL CALL FALL BELL CELL BILL FILL " +
  "BEST REST WEST CASE BASE DARK MARK PARK DATE FATE GATE HATE LATE RATE " +
  "DEAL REAL SEAL DEAR FEAR HEAR NEAR YEAR DEEP KEEP FEED NEED SEED " +
  "FILE MILE TIME FINE LINE MINE NINE FIND KIND MIND FIRM FISH LIST " +
  "FLAG FLAT FLOW SLOW SHOW FOLD GOLD HOLD FOOD GOOD WOOD FOOL POOL FOOT ROOT " +
  "FORM FORT FOUR YOUR FREE TREE FROM FULL GAIN MAIN PAIN RAIN GAME NAME SAME " +
  "GATE GAVE GIFT GIRL GIVE GLAD GLOW GOAL GOLD GONE GOOD GRAB GRAY GREW GROW " +
  "HARD HARM HATE HAVE HEAD LEAD READ HEAL HEAR HEAT MEAT HELD HELP HERE HERO " +
  "HIDE RIDE SIDE WIDE HIGH HIKE LIKE HILL HINT HOLD HOLE HOME HOPE HORN HOST MOST " +
  "HOUR YOUR HUGE HUNT HURT IRON ITEM JOIN JUMP JUST KEEP KIND KING RING SING " +
  "LACK PACK LAKE MAKE TAKE LAND LANE LAST LATE LAZY LEAD LEAF LEAK PEAK WEAK " +
  "LEFT LEND SEND LESS LIFE WIFE LIFT LIKE LIME TIME LINE LINK LIST LIVE LOAD ROAD " +
  "LOCK LONG SONG LOOK TOOK LORD LOSE LOSS LOST LOUD LOVE LUCK MADE MAIL MAIN MAKE " +
  "MALE MANY MARK MASS MATE MATH MEAL MEAN MEAT MEET MELT MENU MESS MILE MILK MILL " +
  "MIND MINE MINT MISS MIST MODE MOOD MOON SOON MORE MOST MOVE MUCH MUST NAME NAVY " +
  "NEAR NEAT NECK NEED NEST NEWS NEXT NICE NINE NODE NONE NOSE ROSE NOTE VOTE ONCE " +
  "ONLY OPEN OVER PACE PACK PAGE PAID PAIN PAIR PALE PARK PART PASS PAST PATH PEAK " +
  "PICK PILE PINE PINK PIPE PLAN PLAY PLOT PLUS POEM POET POLE POND POOL POOR PORT " +
  "POSE POST PRAY PULL PUMP PURE PUSH RACE RACK RAGE RAID RAIL RAIN RANK RARE RATE " +
  "READ REAL REAR REED REEL RENT REST RICE RICH RIDE RING RISE RISK ROAD ROCK ROLE " +
  "ROLL ROOF ROOM ROOT ROPE ROSE RULE RUSH RUST SAFE SAID SAIL SALE SALT SAME SAND " +
  "SAVE SEAL SEAM SEAT SEED SEEK SEEM SEEN SELF SELL SEND SENT SHIP SHOP SHOT SHOW " +
  "SHUT SICK SIDE SIGN SILK SING SINK SITE SIZE SKIN SKIP SLIP SLOW SNOW SOAP SOFT " +
  "SOIL SOLD SOLE SOME SONG SOON SORE SORT SOUL SOUP SOUR SPAN STAR STAY STEM STEP " +
  "STOP SUCH SUIT SURE SURF SWIM TACK TAIL TAKE TALE TALK TALL TAME TANK TAPE TASK " +
  "TEAM TEAR TELL TEND TENT TERM TEST TEXT THAN THAT THEM THEN THEY THIN THIS TICK " +
  "TIDE TILE TILL TIME TIRE TOLD TOLL TONE TOOK TOOL TORN TOSS TOUR TOWN TRAP TRAY " +
  "TREE TRIM TRIP TRUE TUBE TUNE TURN TYPE UNIT UPON URGE USED USER VAIN VARY VASE " +
  "VAST VERY VEST VETO VIEW VINE VOID VOTE WAGE WAIT WAKE WALK WALL WAND WANT WARD " +
  "WARM WARN WASH WAVE WEAK WEAR WEEK WELL WENT WERE WEST WHAT WHEN WHIP WIDE WIFE " +
  "WILD WILL WIND WINE WING WIPE WIRE WISE WISH WITH WOOD WORD WORE WORK WORN WRAP " +
  "YEAR YELL YOUR ZERO ZONE WART PRESS GANG"
).split(/\s+/);

function buildRecoverySecretOpenTokens(): ReadonlySet<string> {
  const out = new Set<string>();
  for (const raw of RECOVERY_SECRET_OPEN_WORDS_RAW) {
    const w = raw.toUpperCase();
    if (w.length >= 4) out.add(w);
    const crock = w.replace(/O/g, "0").replace(/[IL]/g, "1").replace(/U/g, "V");
    let letters = "";
    for (const c of crock) {
      if (c >= "A" && c <= "Z") letters += c;
    }
    if (letters.length >= 4) out.add(letters);
  }
  return out;
}

const RECOVERY_SECRET_OPEN_TOKENS: ReadonlySet<string> = buildRecoverySecretOpenTokens();

const RECOVERY_SECRET_MATH_CONST_DIGITS: readonly string[] = [
  "31415926535897932384626433832795",
  "27182818284590452353602874713526",
  "14142135623730950488016887242096",
];

const RECOVERY_SECRET_ENGLISH_LEET: Readonly<Record<string, string>> = {
  "0": "O",
  "1": "I",
  "2": "Z",
  "3": "E",
  "4": "A",
  "5": "S",
  "6": "G",
  "7": "T",
  "8": "B",
  "9": "G",
};

function recoverySecretLatinSkeleton(secret: string): string {
  let out = "";
  for (const c of secret) {
    if (c >= "A" && c <= "Z") out += c;
    else {
      const folded = RECOVERY_SECRET_ENGLISH_LEET[c];
      if (folded !== undefined) out += folded;
    }
  }
  return out;
}

function recoverySecretEnglishCover(skel: string): number {
  const n = skel.length;
  if (n < 4) return 0;
  const dp = new Array<number>(n + 1).fill(0);
  for (let i = 0; i < n; i++) {
    if (dp[i]! > dp[i + 1]!) dp[i + 1] = dp[i]!;
    for (let len = 4; len <= Math.min(12, n - i); len++) {
      if (RECOVERY_SECRET_OPEN_TOKENS.has(skel.slice(i, i + len))) {
        const next = dp[i]! + len;
        if (next > dp[i + len]!) dp[i + len] = next;
      }
    }
  }
  return dp[n]!;
}

function recoverySecretHumanPatternFail(secret: string): boolean {
  // Digit-constant / long digit-run structure.
  {
    let maxD = 0;
    let run = 0;
    let head = 0;
    for (let i = 0; i < secret.length; i++) {
      const c = secret[i]!;
      if (c >= "0" && c <= "9") {
        run += 1;
        if (run > maxD) maxD = run;
        if (i === head) head += 1;
      } else {
        run = 0;
      }
    }
    if (maxD >= RECOVERY_SECRET_MAX_DIGIT_RUN || head >= RECOVERY_SECRET_MAX_DIGIT_RUN) {
      return true;
    }
    const digits = [...secret].filter((c) => c >= "0" && c <= "9").join("");
    if (digits.length >= 8) {
      for (const prefix of RECOVERY_SECRET_MATH_CONST_DIGITS) {
        for (let len = 8; len <= Math.min(digits.length, prefix.length); len++) {
          for (let i = 0; i <= digits.length - len; i++) {
            if (prefix.includes(digits.slice(i, i + len))) return true;
          }
        }
      }
    }
  }

  const letterSk = [...secret].filter((c) => c >= "A" && c <= "Z").join("");
  const latinSk = recoverySecretLatinSkeleton(secret);
  const skeletons = [letterSk, latinSk];
  if (letterSk.length > 0) skeletons.push([...letterSk].reverse().join(""));
  if (latinSk.length > 0) skeletons.push([...latinSk].reverse().join(""));

  let cover = 0;
  let bigrams = 0;
  let trigrams = 0;
  for (const sk of skeletons) {
    const c = recoverySecretEnglishCover(sk);
    if (c > cover) cover = c;
    let b = 0;
    let t = 0;
    for (let i = 0; i < sk.length - 1; i++) {
      if (RECOVERY_SECRET_OPEN_BIGRAMS.has(sk.slice(i, i + 2))) b += 1;
    }
    for (let i = 0; i < sk.length - 2; i++) {
      if (RECOVERY_SECRET_OPEN_TRIGRAMS.has(sk.slice(i, i + 3))) t += 1;
    }
    if (b > bigrams) bigrams = b;
    if (t > trigrams) trigrams = t;
  }

  const letters = letterSk.length;
  const letterFrac = secret.length === 0 ? 0 : letters / secret.length;
  const vowelOf = (sk: string): number => {
    if (sk.length === 0) return 0;
    let v = 0;
    for (const c of sk) {
      if (c === "A" || c === "E" || c === "I" || c === "O" || c === "U" || c === "Y") v += 1;
    }
    return v / sk.length;
  };
  const vowelFrac = Math.max(vowelOf(letterSk), vowelOf(latinSk));

  if (
    /20[0-2]\d/.test(secret) &&
    /(?:KEY|ABC)/.test(secret) &&
    letters >= RECOVERY_SECRET_MIN_MNEMONIC_PAD_LETTERS &&
    letterFrac >= RECOVERY_SECRET_MIN_MNEMONIC_PAD_LETTER_FRAC
  ) {
    return true;
  }
  if (
    vowelFrac >= RECOVERY_SECRET_MAX_LATIN_VOWEL_FRAC &&
    letters >= RECOVERY_SECRET_MIN_LETTERS_FOR_VOWEL_GUARD
  ) {
    return true;
  }
  if (trigrams >= RECOVERY_SECRET_MAX_ENGLISH_TRIGRAM_HITS) return true;
  if (bigrams >= RECOVERY_SECRET_MAX_ENGLISH_BIGRAM_HITS) return true;
  if (cover >= RECOVERY_SECRET_MIN_ENGLISH_COVER_LETTERS) return true;
  if (
    cover >= RECOVERY_SECRET_MIN_ENGLISH_COVER_WITH_VOWEL &&
    vowelFrac >= RECOVERY_SECRET_MIN_VOWEL_FRAC_WITH_COVER
  ) {
    return true;
  }
  return false;
}

/** @internal exported for parity tests with node recoverySecretWeakness. */
export function recoveryPackSecretStructureOk(secret: string): boolean {
  if (secret.length !== RECOVERY_SECRET_CHARS) return false;
  for (const c of secret) {
    if (!RECOVERY_SECRET_ALPHABET.includes(c)) return false;
  }
  if (new Set(secret).size < RECOVERY_SECRET_MIN_DISTINCT) return false;

  const n = secret.length;
  // Exact tilings + near-period lag runs / match fraction + repeated substring.
  for (let period = 1; period <= Math.floor(n / 2); period++) {
    if (n % period === 0 && secret.slice(0, period).repeat(n / period) === secret) {
      return false;
    }
  }
  for (let period = 1; period <= Math.floor(n / 2); period++) {
    let match = 0;
    let run = 0;
    let maxRun = 0;
    for (let i = period; i < n; i++) {
      if (secret[i] === secret[i - period]) {
        match += 1;
        run += 1;
        if (run > maxRun) maxRun = run;
      } else {
        run = 0;
      }
    }
    if (maxRun >= RECOVERY_SECRET_MAX_LAG_MATCH_RUN) return false;
    if (match / (n - period) >= RECOVERY_SECRET_MAX_LAG_MATCH_FRAC) return false;
  }
  const maxLen = Math.min(RECOVERY_SECRET_MAX_REPEATED_SUBSTRING + 9, Math.floor(n / 2));
  for (let len = RECOVERY_SECRET_MAX_REPEATED_SUBSTRING; len <= maxLen; len++) {
    const seen = new Set<string>();
    for (let i = 0; i <= n - len; i++) {
      const sub = secret.slice(i, i + len);
      if (seen.has(sub)) return false;
      seen.add(sub);
    }
  }

  // Same-symbol run + multi-triple blocks + paired doubles.
  let sameRun = 1;
  let tripleBlocks = 0;
  let blockRun = 1;
  for (let i = 1; i <= n; i++) {
    if (i < n && secret[i] === secret[i - 1]) {
      sameRun += 1;
      blockRun += 1;
      if (sameRun >= RECOVERY_SECRET_MAX_SAME_RUN) return false;
    } else {
      if (blockRun >= 3) tripleBlocks += 1;
      sameRun = 1;
      blockRun = 1;
    }
  }
  if (tripleBlocks >= 2) return false;
  let doubles = 0;
  for (let i = 0; i < n - 1; ) {
    if (secret[i] === secret[i + 1]) {
      doubles += 1;
      if (doubles >= RECOVERY_SECRET_MAX_PAIRED_DOUBLES) return false;
      i += 2;
    } else {
      i += 1;
    }
  }

  // Constant-step (any k ≠ 0) monotone + broken same-delta + strided monotone.
  let stepRun = 1;
  let prevDelta: number | null = null;
  const deltaPairCounts = new Map<number, number>();
  for (let i = 1; i < n; i++) {
    const delta =
      RECOVERY_SECRET_ALPHABET.indexOf(secret[i]!) -
      RECOVERY_SECRET_ALPHABET.indexOf(secret[i - 1]!);
    if (delta !== 0) {
      deltaPairCounts.set(delta, (deltaPairCounts.get(delta) ?? 0) + 1);
    }
    if (delta !== 0 && delta === prevDelta) {
      stepRun += 1;
      if (stepRun >= RECOVERY_SECRET_MAX_MONOTONE_RUN) return false;
    } else {
      stepRun = 1;
      prevDelta = delta === 0 ? null : delta;
    }
  }
  for (const count of deltaPairCounts.values()) {
    if (count >= RECOVERY_SECRET_MAX_SAME_DELTA_PAIRS) return false;
  }
  for (let stride = 2; stride <= 4; stride++) {
    for (let offset = 0; offset < stride; offset++) {
      let strideRun = 1;
      let stridePrev: number | null = null;
      let prevIdx: number | null = null;
      for (let i = offset; i < n; i += stride) {
        const idx = RECOVERY_SECRET_ALPHABET.indexOf(secret[i]!);
        if (prevIdx !== null) {
          const delta = idx - prevIdx;
          if (delta !== 0 && delta === stridePrev) {
            strideRun += 1;
            if (strideRun >= RECOVERY_SECRET_MAX_STRIDED_MONOTONE_RUN) return false;
          } else {
            strideRun = 1;
            stridePrev = delta === 0 ? null : delta;
          }
        }
        prevIdx = idx;
      }
    }
  }

  // Fibonacci digit runs (112358…) — exact or mod-10 recurrence.
  {
    const isFib = (digits: readonly number[]): boolean => {
      if (digits.length < 5) return false;
      let exact = true;
      let mod = true;
      for (let i = 2; i < digits.length; i++) {
        const sum = digits[i - 1]! + digits[i - 2]!;
        if (digits[i] !== sum) exact = false;
        if (digits[i] !== sum % 10) mod = false;
        if (!exact && !mod) return false;
      }
      return exact || mod;
    };
    let run: number[] = [];
    const flush = (): boolean => {
      for (let s = 0; s < run.length; s++) {
        for (let e = s + 5; e <= run.length; e++) {
          if (isFib(run.slice(s, e))) return true;
        }
      }
      run = [];
      return false;
    };
    for (let i = 0; i <= n; i++) {
      const c = secret[i];
      if (c !== undefined && c >= "0" && c <= "9") {
        run.push(Number(c));
      } else if (flush()) {
        return false;
      }
    }
  }

  // Long letter-only run (digits break it) — unbroken dictionary-phrase class.
  let letterRun = 0;
  for (const c of secret) {
    if (c >= "A" && c <= "Z") {
      letterRun += 1;
      if (letterRun >= RECOVERY_SECRET_MAX_LETTER_RUN) return false;
    } else {
      letterRun = 0;
    }
  }

  // Digit↔letter class alternation (0A1B2C… / A1B2C3…).
  let altRun = 1;
  for (let i = 1; i < n; i++) {
    const prevDigit = secret[i - 1]! >= "0" && secret[i - 1]! <= "9";
    const curDigit = secret[i]! >= "0" && secret[i]! <= "9";
    if (prevDigit !== curDigit) {
      altRun += 1;
      if (altRun >= RECOVERY_SECRET_MAX_CLASS_ALTERNATION_RUN) return false;
    } else {
      altRun = 1;
    }
  }

  // Letter+digit / digit+letter pair sequences.
  const isDigit = (c: string): boolean => c >= "0" && c <= "9";
  const isLetter = (c: string): boolean => c >= "A" && c <= "Z";
  for (const offset of [0, 1] as const) {
    for (const kind of ["LD", "DL"] as const) {
      let pairRun = 0;
      let i = offset;
      while (i + 1 < n) {
        const a = secret[i]!;
        const b = secret[i + 1]!;
        const ok =
          (kind === "LD" && isLetter(a) && isDigit(b)) ||
          (kind === "DL" && isDigit(a) && isLetter(b));
        if (ok) {
          pairRun += 1;
          if (pairRun >= RECOVERY_SECRET_MAX_CLASS_PAIR_RUN) return false;
          i += 2;
        } else {
          pairRun = 0;
          i += 1;
        }
      }
    }
  }

  // Keyboard row/column/diagonal walks (raw + letter skeleton).
  const letterSk = [...secret].filter((c) => c >= "A" && c <= "Z").join("");
  for (const walk of RECOVERY_SECRET_KEYBOARD_WALKS) {
    if (walk.length < RECOVERY_SECRET_MAX_KEYBOARD_RUN) continue;
    for (let len = RECOVERY_SECRET_MAX_KEYBOARD_RUN; len <= walk.length; len++) {
      for (let i = 0; i <= walk.length - len; i++) {
        const sub = walk.slice(i, i + len);
        if (secret.includes(sub)) return false;
        if (/^[A-Z]+$/.test(sub) && letterSk.includes(sub)) return false;
      }
    }
  }

  // Dictionary / digit-broken / reversed passphrase skeleton.
  const bases: string[] = [letterSk];
  let leetSk = "";
  for (const c of secret) {
    if (c >= "A" && c <= "Z") leetSk += c;
    else {
      const folded = RECOVERY_SECRET_LEET_FOLD[c];
      if (folded !== undefined) leetSk += folded;
    }
  }
  bases.push(leetSk);
  const skeletons: string[] = [];
  for (const sk of bases) {
    skeletons.push(sk);
    if (sk.length > 0) skeletons.push([...sk].reverse().join(""));
  }
  for (const sk of skeletons) {
    for (const token of RECOVERY_SECRET_DICT_MIN5) {
      if (sk.includes(token)) return false;
      if (sk.includes([...token].reverse().join(""))) return false;
    }
    for (const token of RECOVERY_SECRET_DICT_LEN4_CUSTODY) {
      if (sk.includes(token) || sk.includes([...token].reverse().join(""))) {
        return false;
      }
    }
    let shortHits = 0;
    for (const token of RECOVERY_SECRET_DICT_LEN4) {
      if (sk.includes(token) || sk.includes([...token].reverse().join(""))) {
        shortHits += 1;
        if (shortHits >= 2) return false;
      }
    }
  }

  // Non-list human-pattern class (ZTR-1220 r5) — mirror of node hasHumanPatternClass.
  if (recoverySecretHumanPatternFail(secret)) return false;

  return true;
}

/**
 * Generate the secret a new pack is sealed under. The operator never chooses it:
 * the pack is designed to leave the host, so its seal key has to be beyond
 * offline search. Drawn from the platform CSPRNG, shown once, never stored — the
 * node re-checks the same shape + structure floor at creation (ZTR-1220).
 * Redraws on the rare structure-guard miss; throws rather than last-resort-emit
 * a secret the node would answer 400 weak_recovery_secret for.
 */
export function generateRecoveryPackSecret(): string {
  for (let attempt = 0; attempt < RECOVERY_SECRET_MAX_DRAW_ATTEMPTS; attempt++) {
    const draws = new Uint8Array(RECOVERY_SECRET_CHARS);
    crypto.getRandomValues(draws);
    let out = "";
    for (const d of draws) {
      // 256 % 32 === 0, so the byte-to-symbol fold stays uniform.
      out += RECOVERY_SECRET_ALPHABET[d % RECOVERY_SECRET_ALPHABET.length];
    }
    if (recoveryPackSecretStructureOk(out)) return out;
  }
  throw new Error(
    "recovery pack secret generation failed structure floor — refuse weak emit",
  );
}

export async function postRecoveryPackCreate(
  body: {
    readonly recovery_secret: string;
    readonly vault_master_key?: string;
    /** Re-issue source: the existing pack file, opened server-side. */
    readonly from_pack?: string;
    readonly from_pack_secret?: string;
    readonly allow_legacy_v1?: boolean;
  },
  totp: string,
): Promise<RecoveryPackCreateResponse> {
  return api<RecoveryPackCreateResponse>("/recovery-pack/create", {
    method: "POST",
    body: JSON.stringify(body),
    totp,
    idempotencyKey: newIdempotencyKey(),
  });
}

export async function postRecoveryPackProve(
  body: {
    readonly recovery_secret: string;
    readonly pack_file: string;
    readonly allow_legacy_v1?: boolean;
  },
  totp: string,
): Promise<RecoveryPackProveResponse> {
  return api<RecoveryPackProveResponse>("/recovery-pack/prove", {
    method: "POST",
    body: JSON.stringify(body),
    totp,
    idempotencyKey: newIdempotencyKey(),
  });
}

/** Decode pack create response into a downloadable Blob (application/octet-stream). */
export function recoveryPackFileBlob(res: RecoveryPackCreateResponse): Blob {
  const bin = atob(res.pack_file_b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new Blob([bytes], { type: "application/octet-stream" });
}

// --- Dual-control policy ---

export interface DualControlPolicyResponse {
  readonly mode: "single_operator" | "two_human";
  readonly short: string;
  readonly long: string;
  readonly approve_hint: string;
}

export async function fetchDualControlPolicy(): Promise<DualControlPolicyResponse> {
  return api<DualControlPolicyResponse>("/dual-control-policy");
}

// --- Second-device enrolment ---

export interface SecondDeviceIssueResponse {
  readonly challenge_id: string;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly qr: { readonly challenge_id: string; readonly node_origin: string };
  readonly deep_link_path: string;
  readonly note: string;
}

export async function issueSecondDeviceEnrol(): Promise<SecondDeviceIssueResponse> {
  return api<SecondDeviceIssueResponse>("/device-enrol/issue", {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export async function peekSecondDeviceEnrol(challengeId: string): Promise<unknown> {
  return api(`/device-enrol/${encodeURIComponent(challengeId)}`);
}

export async function bindSecondDeviceEnrol(body: {
  readonly challenge_id: string;
  readonly new_device_public_key: string;
  readonly label: string;
}): Promise<unknown> {
  return api("/device-enrol/bind", { method: "POST", body: JSON.stringify(body) });
}

export async function authorizeSecondDeviceEnrol(
  body: {
    readonly challenge_id: string;
    readonly authorizing_key_id: string;
    readonly authorizing_public_key: string;
    readonly authorizing_signature: string;
  },
  totp: string,
): Promise<unknown> {
  return api("/device-enrol/authorize", {
    method: "POST",
    body: JSON.stringify(body),
    totp,
  });
}

export async function completeSecondDeviceEnrol(body: {
  readonly challenge_id: string;
  readonly new_device_pop_signature: string;
}): Promise<unknown> {
  return api("/device-enrol/complete", { method: "POST", body: JSON.stringify(body) });
}

// --- Operator push — opt-in; separate from wallet push ---

export interface OperatorPushStatus {
  readonly opt_in: boolean;
  readonly wired: boolean;
  readonly note: string;
  /** VAPID application-server public key (base64url), when the node has one. */
  readonly vapid_public_key: string | null;
  readonly subscriptions: readonly {
    readonly id: string;
    readonly endpoint_fingerprint: string;
    readonly created_at: string;
    readonly user_agent: string | null;
  }[];
}

export async function fetchOperatorPushStatus(): Promise<OperatorPushStatus> {
  return api<OperatorPushStatus>("/operator-push/subscriptions");
}

export async function subscribeOperatorPush(body: {
  readonly endpoint: string;
  readonly p256dh: string;
  readonly auth: string;
}): Promise<unknown> {
  return api("/operator-push/subscribe", { method: "POST", body: JSON.stringify(body) });
}

export async function unsubscribeOperatorPush(
  body: { readonly endpoint: string } | { readonly endpoint_fingerprint: string },
): Promise<unknown> {
  return api("/operator-push/unsubscribe", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

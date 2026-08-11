// SPA money client for the generic-node admin-router routes.
// Mutations always go through `api()` (never apiOrDemo — no fixture "success").
// Reads may use inventory GETs when mounted; absent routes surface as live:false.

import type {
  OperationInventoryDetail,
  OperationInventoryListItem,
} from "@zucoins/generic-node-contracts/admin-inventory";
import {
  OPERATOR_RECOVERY_ACTIONS,
  RESERVED_RECOVERY_ACTIONS as CONTRACT_RESERVED_RECOVERY_ACTIONS,
} from "@zucoins/generic-node-contracts/operator-halt";
import { api, apiOrDemo, ApiError, type ApiFailureDetail, toApiFailureDetail } from "./api.js";
import { useAuth } from "../store/auth.js";

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

/**
 * FOLLOW-UP (ZTR-1202): still hand-transcribed, and already known to disagree with the node's
 * `DestinationInventoryItem` (missing `blessed_by_device_key_id` / `blessing_artifact_id`, and
 * marking server-mandatory fields optional). Move it onto the shared
 * `@zucoins/generic-node-contracts` declaration the way the operations shapes above already are
 * — the compiler cannot see the disagreement until it is shared. Same for
 * {@link WalletInventoryItem}.
 */
export interface DestinationItem {
  destination_id: string;
  node_id?: string;
  wallet_id: string;
  wallet_public_key: string;
  state: string;
  label: string;
  blessed_at: string | null;
  retired_at: string | null;
  created_at?: string;
  move_eligible?: boolean;
  ineligibility_reason?: string | null;
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
  if (useAuth.getState().demoMode) return { data: [], live: false };

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

/** Guard: demo mode must never claim a money mutation succeeded. */
export function assertLiveMoneySession(action: string): void {
  if (useAuth.getState().demoMode) {
    throw new ApiError(503, {
      error: {
        code: "service_unavailable",
        message: `Design preview cannot ${action}. Sign in against a live node.`,
      },
    });
  }
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
  assertLiveMoneySession("approve an external send");
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
  assertLiveMoneySession("reject an external send");
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
  assertLiveMoneySession("run a recovery action");
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
  assertLiveMoneySession("bless a destination");
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
  assertLiveMoneySession("issue a device enrollment challenge");
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
  assertLiveMoneySession("enrol a device");
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
  assertLiveMoneySession("revoke a device");
  return api(`/device-keys/${encodeURIComponent(deviceKeyId)}/revoke`, {
    method: "POST",
    body: JSON.stringify(body),
    totp,
    idempotencyKey: newIdempotencyKey(),
  });
}

export async function postRetire(destinationId: string, totp: string): Promise<unknown> {
  assertLiveMoneySession("retire a destination");
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

/** Wallet inventory row. observed_balance_zkz is gateway-observed, null if never seen. */
/**
 * FOLLOW-UP (ZTR-1202): hand-transcribed and known-drifted against the node's
 * `WalletInventoryItem` (which carries the full `WalletCustodyView` — `node_id`, `retired_at`,
 * `quarantine_reason`, `recovery_verified_at`, `recovery_verification_id`). Share the
 * declaration, as {@link OperationListItem} now does, rather than widening it by hand.
 */
export interface WalletInventoryItem {
  readonly wallet_id: string;
  readonly public_key: string;
  readonly state: string;
  readonly key_origin: string;
  readonly recovery_verified: boolean;
  readonly observed_balance_zkz: string | null;
  readonly created_at?: string;
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
  assertLiveMoneySession("toggle operator halt");
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
  const r = await apiOrDemo<{ readonly keys: readonly ApiKeyListing[] }>("/api-keys", { keys: [] });
  return { keys: r.data.keys ?? [], live: r.live };
}

export async function postIssueApiKey(
  scopes: readonly string[] | undefined,
  totp: string,
): Promise<ApiKeyIssueResult> {
  assertLiveMoneySession("issue implementer API key");
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
  assertLiveMoneySession("revoke implementer API key");
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
  const r = await apiOrDemo<{ readonly keys: readonly ReportingKeyListing[] }>("/reporting-keys", {
    keys: [],
  });
  return { keys: r.data.keys ?? [], live: r.live };
}

export async function postIssueReportingKey(totp: string): Promise<ReportingKeyIssueResult> {
  assertLiveMoneySession("issue reporting credential");
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
  assertLiveMoneySession("recover a lost reporting credential");
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
  assertLiveMoneySession("start recovery ceremony");
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
 * secret can be transcribed off a screen without I/L/O/U ambiguity.
 */
const RECOVERY_SECRET_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/** 26 × log2(32) = 130 bits, over the node's 128-bit creation floor. */
const RECOVERY_SECRET_CHARS = 26;

/**
 * Generate the secret a new pack is sealed under. The operator never chooses it:
 * the pack is designed to leave the host, so its seal key has to be beyond
 * offline search. Drawn from the platform CSPRNG, shown once, never stored — the
 * node re-checks the entropy floor at creation regardless of what is sent.
 */
export function generateRecoveryPackSecret(): string {
  const draws = new Uint8Array(RECOVERY_SECRET_CHARS);
  crypto.getRandomValues(draws);
  let out = "";
  for (const d of draws) {
    // 256 % 32 === 0, so the byte-to-symbol fold stays uniform.
    out += RECOVERY_SECRET_ALPHABET[d % RECOVERY_SECRET_ALPHABET.length];
  }
  return out;
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
  assertLiveMoneySession("create recovery pack");
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
  assertLiveMoneySession("prove recovery pack");
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
  assertLiveMoneySession("issue second-device enrolment");
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
  assertLiveMoneySession("bind second-device public key");
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
  assertLiveMoneySession("authorize second-device enrolment");
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
  assertLiveMoneySession("complete second-device enrolment");
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
  assertLiveMoneySession("subscribe operator push");
  return api("/operator-push/subscribe", { method: "POST", body: JSON.stringify(body) });
}

export async function unsubscribeOperatorPush(
  body: { readonly endpoint: string } | { readonly endpoint_fingerprint: string },
): Promise<unknown> {
  assertLiveMoneySession("unsubscribe operator push");
  return api("/operator-push/unsubscribe", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

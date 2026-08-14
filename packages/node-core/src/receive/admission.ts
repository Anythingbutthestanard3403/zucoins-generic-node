// Receive admission — validate a RECEIVE_EXTERNAL request, resolve idempotency, check
// destination eligibility, and create the operation record in CREATED state.
//
// Request admission, idempotency, and the receive pool / receive-eligibility predicate.
// Layer 1 (node-core) only: pure admission logic over a store port — no signing,
// submission, or wallet acquisition happens here, so an idempotent replay can never
// repeat a protocol action (the never-blind-retry rule).
//
// The three invariants this module exists to guarantee are enforced by the DATABASE, not by
// application reads separated from their writes:
// * idempotency — the UNIQUE (implementer_id, http_method, route, idempotency_key)
// constraint on receive_operations decides which of N concurrent first uses wins;
// * the one-in-flight-per-wallet rule — the partial unique index over an unsettled receive's destination
// wallet decides whether a second in-flight receive for one wallet exists at all;
// * RECEIVE_QUEUE_CAP equals POOL_CAP_TOTAL queue cap — `insertQueuedIfCapAllows` takes `pg_advisory_xact_lock` (same key
// as pool-allocator admitReceive), re-reads depth, and inserts only when depth < cap,
// so concurrent first-use admits cannot overshoot. A bare count-then-insert is a TOCTOU
// gap; the sibling allocator already closed it the same way.
// There is deliberately no `hasInFlight`-style read: a check separated from its insert is a
// TOCTOU gap, and against a real store a flag nothing writes is permanently false. The
// frozen DDL and its structural inventory are src/schema/receive-admission.sql and
// receive-admission.contract.ts; the real-PostgreSQL drills are
// test/receive-admission-pg.test.ts.

import { createHash, randomUUID } from "node:crypto";

import type { VerificationMode } from "@zucoins/generic-node-contracts/operations";
import { DEFAULT_VERIFICATION_MODE } from "@zucoins/generic-node-contracts/operations";

import { parsePositiveZkzAmount } from "../protocol/amounts.js";
import {
  admitVerificationMode,
  refuseAllNodeVerifiedPolicy,
  resolveVerificationMode,
  type AllowNodeVerifiedPolicyPort,
} from "../verification/allow-node-verified-policy.js";

// The idempotency scope includes the HTTP method and the canonical
// route, never the key alone. This slice serves exactly one route.
export const RECEIVE_HTTP_METHOD = "POST" as const;
export const RECEIVE_CANONICAL_ROUTE = "/v1/receives" as const;

// Followers of a concurrent first use wait briefly for the
// creator's stored result, then get 409 idempotency_in_progress with Retry-After.
export const IDEMPOTENCY_IN_PROGRESS_RETRY_AFTER_SECONDS = 1;

// Rule 3 / RECEIVE_QUEUE_CAP equals POOL_CAP_TOTAL: the Retry-After stamped on 503 receive_queue_full. The
// frozen pool-policy value (RECEIVE_QUEUE_RETRY_AFTER_SECONDS = RECEIVE_QUEUE_MAX_WAIT_MS /
// 1000) is mirrored rather than imported — @zucoins/generic-node-contracts publishes no
// ./pool-policy subpath — and test/receive-admission-parity.test.ts binds the two together.
export const RECEIVE_QUEUE_FULL_RETRY_AFTER_SECONDS = 30;

// Example default for omitted expires_in_seconds (receive TTL policy default
// until the composition root injects configured RECEIVE_TTL_DEFAULT_SECS).
export const DEFAULT_EXPIRES_IN_SECONDS = 300;

export type ReceiveWalletState = "AVAILABLE" | "PINNED" | "QUARANTINED" | "RETIRED";
export type ReceiveDestinationState = "PENDING" | "BLESSED" | "RETIRED";

export interface ReceiveWalletRecord {
  readonly walletId: string;
  readonly nodeId: string;
  readonly keyOrigin: "node_generated" | "imported";
  readonly state: ReceiveWalletState;
  readonly recoveryVerifiedAt: number | null;
  /**
   * Money capability (ZTR-1268). Required for receive-pool eligibility and for
   * after_landing INTERNAL_MOVE destination parties (allow_internal_move).
   */
  readonly allowExternalReceive: boolean;
  readonly allowInternalMove: boolean;
}

// A destination as the store resolves it: the opaque destination_id joined to the wallet it
// names. Destination selection is by opaque id only — an implementer
// never supplies a raw address.
export interface ReceiveDestinationRecord {
  readonly destinationId: string;
  readonly destinationState: ReceiveDestinationState;
  readonly wallet: ReceiveWalletRecord;
}

// after_landing mirrors the frozen API contract:
// exactly {"kind":"HOLD","destination_id":null} or
// {"kind":"INTERNAL_MOVE","destination_id":"<uuid>"}.
export type AfterLanding =
  | { readonly kind: "HOLD"; readonly destinationId?: null }
  | { readonly kind: "INTERNAL_MOVE"; readonly destinationId: string };

export interface ReceiveRequest {
  readonly implementerId: string;
  readonly nodeId: string;
  readonly amountZkz: string;
  readonly anchor: string;
  readonly ttlMs: number;
  readonly afterLanding: AfterLanding;
  readonly idempotencyKey: string;
  /**
   * Optional admission-time verification mode (ZTR-1301). Omitted → INDEPENDENT.
   * NODE_VERIFIED requires operator policy ops.allow_node_verified for the implementer.
   */
  readonly verificationMode?: VerificationMode;
}

// Full RECEIVE_EXTERNAL external-state vocabulary (parity-bound to RECEIVE_EXTERNAL_STATES).
// Admission only writes CREATED; the assignment sibling stamps READY.
export type ReceiveOperationStatus = "CREATED" | "READY" | "RECEIVE_LANDED" | "EXPIRED";

export interface ReceiveOperation {
  readonly operationId: string;
  readonly implementerId: string;
  readonly nodeId: string;
  readonly kind: "RECEIVE_EXTERNAL";
  readonly status: ReceiveOperationStatus;
  readonly httpMethod: typeof RECEIVE_HTTP_METHOD;
  readonly route: typeof RECEIVE_CANONICAL_ROUTE;
  readonly amountZkz: string;
  readonly anchor: string;
  readonly ttlMs: number;
  readonly afterLanding: AfterLanding;
  readonly idempotencyKey: string;
  readonly requestSha256: string;
  readonly destinationWalletId: string | null;
  readonly walletId: string | null;
  readonly createdAt: number;
  /** Immutable after admission (ZTR-1301 / schema ZTR-1300). */
  readonly verificationMode: VerificationMode;
}

// A row as the store returns it. `responseBody === null` is the in-progress marker: the
// creator has claimed the key but has not yet stored its first completed execution.
export interface StoredReceiveOperation extends ReceiveOperation {
  readonly responseStatus: number | null;
  readonly responseBody: string | null;
  /**
   * Live `operations` facts when the admission row is joined for GET .
   * Absent on pure admission-table reads (create/idempotency). When present, GET
   * overlays state/row_version so verification-complete CAS sees the post-land version
   * rather than the frozen READY response_body (operations.row_version advances on land;
   * receive_operations.status historically lagged at READY).
   */
  readonly liveStatus?: string;
  readonly liveRowVersion?: number;
  readonly liveUpdatedAt?: string;
  readonly liveTerminalAt?: string | null;
  readonly liveVerificationMaterialAvailableUntil?: string | null;
  readonly liveAttentionRequired?: boolean;
  readonly liveAttentionReason?: string | null;
}

export type ReceiveRejectionCode =
  | "missing_idempotency_key"
  | "invalid_amount"
  | "invalid_anchor"
  | "invalid_ttl"
  | "invalid_after_landing"
  | "destination_not_found"
  | "destination_not_eligible"
  | "wallet_in_flight"
  | "idempotency_key_reused"
  | "idempotency_in_progress"
  | "receive_queue_full"
  | "verification_mode_not_allowed";

export type ReceiveAdmissionOutcome =
  | {
      readonly outcome: "ADMITTED";
      readonly operation: ReceiveOperation;
      /** One-time plaintext `sh_…` — return on create response; never persist or log. */
      readonly subscriptionHandlePlaintext: string;
    }
  | {
      readonly outcome: "IDEMPOTENT_REPLAY";
      readonly operation: StoredReceiveOperation;
      readonly responseStatus: number;
      readonly responseBody: string;
    }
  | {
      readonly outcome: "REJECTED";
      readonly code: ReceiveRejectionCode;
      readonly detail?: string;
      readonly retryAfterSeconds?: number;
    };

// Outcome of the arbiter insert. Every branch is decided by the database, not by a prior
// read: INSERTED means this caller won the idempotency constraint, and WALLET_IN_FLIGHT
// means the one-in-flight-per-wallet partial unique index rejected the row.
//
// On INSERTED the store also mints a subscription handle in the same TX and returns the
// plaintext once. Only the hash is durable (subscription_handles.handle_hash).
export type ReceiveInsertOutcome =
  | {
      readonly kind: "INSERTED";
      /** One-time plaintext `sh_…` handle. Never logged; never re-readable from storage. */
      readonly subscriptionHandlePlaintext: string;
    }
  | { readonly kind: "IDEMPOTENCY_CONFLICT" }
  | { readonly kind: "WALLET_IN_FLIGHT"; readonly walletId: string };

// Outcome of the RECEIVE_QUEUE_CAP equals POOL_CAP_TOTAL-gated insert. QUEUE_FULL means the locked depth read observed
// depth >= cap and the INSERT never ran — caller may still resolve an existing idempotency
// row (replay at cap) but must create nothing new.
export type ReceiveQueuedInsertOutcome =
  | ReceiveInsertOutcome
  | { readonly kind: "QUEUE_FULL" };

export interface ReceiveAdmissionStore {
  findDestination(destinationId: string): Promise<ReceiveDestinationRecord | null>;
  // Inserts the operation row and its in-progress idempotency marker in one statement. MUST
  // NOT pre-read to decide the outcome — the constraint decides. Prefer
  // `insertQueuedIfCapAllows` on the admit path so the queue cap cannot race.
  insertInProgress(operation: ReceiveOperation): Promise<ReceiveInsertOutcome>;
  // RECEIVE_QUEUE_CAP equals POOL_CAP_TOTAL hard cap: advisory-lock → count unassigned CREATED → insert only
  // when depth < queueCap. Single statement (or single TX) so concurrent admits cannot
  // overshoot. QUEUE_FULL means create nothing; IDEMPOTENCY_CONFLICT / WALLET_IN_FLIGHT
  // mirror insertInProgress.
  insertQueuedIfCapAllows(
    operation: ReceiveOperation,
    queueCap: number,
  ): Promise<ReceiveQueuedInsertOutcome>;
  findByIdempotency(
    implementerId: string,
    httpMethod: string,
    route: string,
    idempotencyKey: string,
  ): Promise<StoredReceiveOperation | null>;
  // Stores the first completed execution's status and exact response body, closing the
  // in-progress marker. Returns false if the row was already completed.
  completeOperation(operationId: string, responseStatus: number, responseBody: string): Promise<boolean>;
  // Tenant-scoped point read. implementerId is credential-bound — a row
  // owned by another tenant is NOT_FOUND, never a leakage.
  findByOperationId(
    operationId: string,
    implementerId: string,
  ): Promise<StoredReceiveOperation | null>;
  // Depth of this node's unassigned CREATED queue. Observability
  // tests only — admit decisions go through insertQueuedIfCapAllows so the cap is hard.
  countQueuedReceives(nodeId: string): Promise<number>;
}

// Frozen API grammars (api/scalars.ts): anchor ^[A-Za-z0-9_-]{1,96}$,
// idempotency key 16–255 visible ASCII.
const ANCHOR_RE = /^[A-Za-z0-9_-]{1,96}$/;
const IDEMPOTENCY_KEY_RE = /^[\x20-\x7E]{16,255}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MIN_TTL_MS = 1_000;
const MAX_TTL_MS = 86_400_000;

// after_landing arrives as a JSON wire body, so its TypeScript union is erased at runtime
// and cannot be trusted. The canonical field set fixes exactly two legal shapes; anything
// else — an unknown discriminant, a HOLD carrying a destination, a non-UUID destination — is
// rejected here rather than persisted verbatim and silently skipping the destination gate.
export function validateAfterLanding(value: unknown): value is AfterLanding {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort().join(",");
  if (record.kind === "HOLD") {
    return keys === "kind" || (keys === "destinationId,kind" && record.destinationId === null);
  }
  if (record.kind === "INTERNAL_MOVE") {
    return (
      keys === "destinationId,kind" &&
      typeof record.destinationId === "string" &&
      UUID_RE.test(record.destinationId)
    );
  }
  return false;
}

export function validateReceiveRequest(
  request: ReceiveRequest,
): { ok: true } | { ok: false; code: ReceiveRejectionCode; detail?: string } {
  if (!IDEMPOTENCY_KEY_RE.test(request.idempotencyKey)) {
    return { ok: false, code: "missing_idempotency_key" };
  }
  try {
    parsePositiveZkzAmount(request.amountZkz);
  } catch {
    return {
      ok: false,
      code: "invalid_amount",
      detail: "amount_zkz must be a positive canonical decimal, strictly < 100000000",
    };
  }
  if (!ANCHOR_RE.test(request.anchor)) {
    return { ok: false, code: "invalid_anchor" };
  }
  if (!Number.isInteger(request.ttlMs) || request.ttlMs < MIN_TTL_MS || request.ttlMs > MAX_TTL_MS) {
    return { ok: false, code: "invalid_ttl", detail: `ttl_ms must be an integer in [${MIN_TTL_MS}, ${MAX_TTL_MS}]` };
  }
  if (!validateAfterLanding(request.afterLanding)) {
    return {
      ok: false,
      code: "invalid_after_landing",
      detail: 'after_landing must be {"kind":"HOLD","destination_id":null} or {"kind":"INTERNAL_MOVE","destination_id":"<uuid>"}',
    };
  }
  return { ok: true };
}

// A SHA-256 hash of the exact validated canonical request object. The
// field sequence below IS the preimage byte sequence — it is written out literally and is
// never sorted, rearranged, or normalized (the byte-exact signing rule).
export function canonicalRequestSha256(request: ReceiveRequest): string {
  // verification_mode is part of the idempotency fingerprint (ZTR-1301 AC3): a
  // replay with a different mode is idempotency_key_reused, not a silent mode change.
  // Include only when non-default so pre-1301 five-field fingerprints stay stable for
  // omitted / INDEPENDENT creates (Review-B style omit-null upgrade).
  const mode = resolveVerificationMode(request.verificationMode);
  const base = {
    implementer_id: request.implementerId,
    node_id: request.nodeId,
    amount_zkz: request.amountZkz,
    anchor: request.anchor,
    ttl_ms: request.ttlMs,
    after_landing: {
      kind: request.afterLanding.kind,
      destination_id:
        request.afterLanding.kind === "INTERNAL_MOVE" ? request.afterLanding.destinationId : null,
    },
  };
  const canonical =
    mode === DEFAULT_VERIFICATION_MODE
      ? JSON.stringify(base)
      : JSON.stringify({ ...base, verification_mode: mode });
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

// Receive-eligibility predicate: a wallet is receive-eligible iff
// key_origin='node_generated' AND recovery_verified_at IS NOT NULL AND state='AVAILABLE'
// AND allow_external_receive (ZTR-1268 money capability).
// This is the generic core neutrality recovery conjunct MINUS blessing — receivers are never blessed — and it
// gates receive-pool selection, NOT move destinations.
export function isReceiveEligible(wallet: ReceiveWalletRecord): boolean {
  return (
    wallet.keyOrigin === "node_generated" &&
    wallet.state === "AVAILABLE" &&
    wallet.recoveryVerifiedAt !== null &&
    wallet.allowExternalReceive === true
  );
}

// An INTERNAL_MOVE destination requires the receive-standing conjuncts PLUS blessed
// destination (generic core neutrality; B-08) PLUS allow_internal_move (ZTR-1268).
// Applying isReceiveEligible alone would wrongly require allow_external_receive on a
// move sink and miss allow_internal_move.
export function isMoveDestinationEligible(destination: ReceiveDestinationRecord): boolean {
  const wallet = destination.wallet;
  return (
    wallet.keyOrigin === "node_generated" &&
    wallet.state === "AVAILABLE" &&
    wallet.recoveryVerifiedAt !== null &&
    wallet.allowInternalMove === true &&
    destination.destinationState === "BLESSED"
  );
}

export interface ReceiveAdmissionConfig {
  // RECEIVE_QUEUE_CAP (derived as exactly POOL_CAP_TOTAL; never configured). Required,
  // with no default: a cap that defaults to "unbounded" is a backpressure gate that never
  // fires, which is the failure mode exists to prevent.
  readonly queueCap: number;
  readonly generateId?: () => string;
  readonly now?: () => number;
  /**
   * Operator policy gating NODE_VERIFIED (ZTR-1301). When omitted, refuse-all
   * (fail closed) — NODE_VERIFIED is never silently admitted.
   */
  readonly allowNodeVerifiedPolicy?: AllowNodeVerifiedPolicyPort;
}

export async function admitReceiveExternal(
  store: ReceiveAdmissionStore,
  request: ReceiveRequest,
  config: ReceiveAdmissionConfig,
): Promise<ReceiveAdmissionOutcome> {
  const generateId = config.generateId ?? (() => randomUUID());
  const now = config.now ?? (() => Date.now());
  const policy = config.allowNodeVerifiedPolicy ?? refuseAllNodeVerifiedPolicy();

  // Shape, amount, anchor, TTL, explicit after_landing.
  const validation = validateReceiveRequest(request);
  if (!validation.ok) {
    return { outcome: "REJECTED", code: validation.code, detail: validation.detail };
  }

  // Resolve mode. NODE_VERIFIED is fail-closed gated below — never silent-downgrade.
  const verificationMode = resolveVerificationMode(request.verificationMode);
  const requestSha256 = canonicalRequestSha256(request);

  // Gate NODE_VERIFIED before a new insert, but still honour same-hash idempotent
  // replay if a prior admit already persisted the row (policy may have flipped off).
  if (verificationMode === "NODE_VERIFIED") {
    const policyDoc = await policy.getPolicy();
    const modeAdmit = admitVerificationMode(
      verificationMode,
      policyDoc,
      request.implementerId,
    );
    if (!modeAdmit.ok) {
      const existing = await store.findByIdempotency(
        request.implementerId,
        RECEIVE_HTTP_METHOD,
        RECEIVE_CANONICAL_ROUTE,
        request.idempotencyKey,
      );
      if (existing !== null && existing.requestSha256 === requestSha256) {
        return decideAgainstExisting(existing, requestSha256);
      }
      return { outcome: "REJECTED", code: modeAdmit.code };
    }
  }

  // Resolve and gate the INTERNAL_MOVE destination. This is a read; it creates
  // nothing, so idempotency is still resolved (step 4) before anything exists.
  let destinationWalletId: string | null = null;
  if (request.afterLanding.kind === "INTERNAL_MOVE") {
    const destination = await store.findDestination(request.afterLanding.destinationId);
    if (destination === null) {
      return { outcome: "REJECTED", code: "destination_not_found" };
    }
    if (!isMoveDestinationEligible(destination)) {
      return { outcome: "REJECTED", code: "destination_not_eligible" };
    }
    destinationWalletId = destination.wallet.walletId;
  }

  const operation: ReceiveOperation = {
    operationId: generateId(),
    implementerId: request.implementerId,
    nodeId: request.nodeId,
    kind: "RECEIVE_EXTERNAL",
    status: "CREATED",
    httpMethod: RECEIVE_HTTP_METHOD,
    route: RECEIVE_CANONICAL_ROUTE,
    amountZkz: request.amountZkz,
    anchor: request.anchor,
    ttlMs: request.ttlMs,
    afterLanding: request.afterLanding,
    idempotencyKey: request.idempotencyKey,
    requestSha256,
    destinationWalletId,
    // Exit invariant: no receiver exists while an unassigned receive is CREATED.
    walletId: null,
    createdAt: now(),
    verificationMode,
  };

  // Rule 3 / RECEIVE_QUEUE_CAP equals POOL_CAP_TOTAL — lock, measure unassigned depth, and either
  // insert or refuse in one store call. At cap, create NOTHING (hard, not soft). A retry of
  // a key that already has a row is a replay, never a new queue entry, so QUEUE_FULL still
  // resolves through when the row exists — a caller re-sending its own accepted receive
  // is never told the queue is full.
  const insert = await store.insertQueuedIfCapAllows(operation, config.queueCap);
  if (insert.kind === "INSERTED") {
    return {
      outcome: "ADMITTED",
      operation,
      subscriptionHandlePlaintext: insert.subscriptionHandlePlaintext,
    };
  }
  if (insert.kind === "QUEUE_FULL") {
    const existing = await store.findByIdempotency(
      request.implementerId,
      RECEIVE_HTTP_METHOD,
      RECEIVE_CANONICAL_ROUTE,
      request.idempotencyKey,
    );
    if (existing !== null) return decideAgainstExisting(existing, requestSha256);
    return {
      outcome: "REJECTED",
      code: "receive_queue_full",
      retryAfterSeconds: RECEIVE_QUEUE_FULL_RETRY_AFTER_SECONDS,
    };
  }
  if (insert.kind === "WALLET_IN_FLIGHT") {
    // The one-in-flight-per-wallet rule: a second unsettled receive already holds this wallet.
    // Implementers see opaque destination_id only; never the internal wallet UUID.
    return { outcome: "REJECTED", code: "wallet_in_flight" };
  }

  return resolveIdempotencyConflict(store, request, operation.requestSha256);
}

// Rules 1–3, decided against the row the winning inserter created.
async function resolveIdempotencyConflict(
  store: ReceiveAdmissionStore,
  request: ReceiveRequest,
  requestSha256: string,
): Promise<ReceiveAdmissionOutcome> {
  const existing = await store.findByIdempotency(
    request.implementerId,
    RECEIVE_HTTP_METHOD,
    RECEIVE_CANONICAL_ROUTE,
    request.idempotencyKey,
  );
  return decideAgainstExisting(existing, requestSha256);
}

function decideAgainstExisting(
  existing: StoredReceiveOperation | null,
  requestSha256: string,
): ReceiveAdmissionOutcome {
  if (existing === null) {
    // The winner's row is not visible to this reader yet (or was rolled back after claiming
    // the key). Never treat that as "no operation exists" and insert a second one.
    return {
      outcome: "REJECTED",
      code: "idempotency_in_progress",
      retryAfterSeconds: IDEMPOTENCY_IN_PROGRESS_RETRY_AFTER_SECONDS,
    };
  }
  // Same key, different request. Return the conflict; change nothing.
  if (existing.requestSha256 !== requestSha256) {
    return { outcome: "REJECTED", code: "idempotency_key_reused" };
  }
  // The creator has not stored its result yet.
  if (existing.responseBody === null || existing.responseStatus === null) {
    return {
      outcome: "REJECTED",
      code: "idempotency_in_progress",
      retryAfterSeconds: IDEMPOTENCY_IN_PROGRESS_RETRY_AFTER_SECONDS,
    };
  }
  // Replay the first completed execution's exact status and body.
  return {
    outcome: "IDEMPOTENT_REPLAY",
    operation: existing,
    responseStatus: existing.responseStatus,
    responseBody: existing.responseBody,
  };
}

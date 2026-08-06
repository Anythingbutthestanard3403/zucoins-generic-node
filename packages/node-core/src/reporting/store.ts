// the durable-store seam for signed reporting verification. These
// interfaces pin the frozen persistence contract so a durable Postgres adapter drops
// in without a call-site change: the burn is ONE atomic transaction mirroring
// `reporting_lock_and_assert_admission` + the shared nonce insert (
// BURN_TRANSACTION_STEPS in reporting-persistence/decisions.ts):
//
// begin → lock the node's restore-state row → require restore_hold=false →
// lock the (node_id, implementer_id) lifecycle head → require auth_hold=false,
// head.epoch == expectedEpoch, presented key current-or-prior inside the strict overlap,
// key ACTIVE at the latest state version → allocate the node-wide nonce_burn_sequence →
// insert the full evidence row under UNIQUE(node_id, implementer_id, nonce) → commit.
//
// A unique conflict is REPLAY (the earlier burn is retained). Invalid, expired, revoked, or
// badly signed requests insert NOTHING; every post-burn outcome (404/409/500/handler crash)
// retains the committed burn, and the burn is never folded into the handler's mutation
// transaction.
//
// The in-memory reference adapter (in-memory-store.ts) implements these interfaces for the
// single-process posture; its critical sections are await-free so check-then-insert cannot
// interleave under JS run-to-completion. Multi-process deployments require the durable
// adapter (a separately ticketed migration/driver slice).

import {
  FINGERPRINT_GUARDED_ROUTE_IDS,
  priorKeyEligible,
  type ReportingNoncePurpose,
  type ReportingRouteClass,
} from "@zucoins/generic-node-contracts";

// -------- registration / admission (registration layer, consumed read-only here) -------

// The binding: reporting_key_id → (node_id, implementer_id) + the registered public
// key (padded base64url, 32-byte Ed25519). AUTHORIZATION derives from this binding, never from
// request-supplied tenant fields.
export interface ReportingRegistration {
  readonly reportingKeyId: string;
  readonly nodeId: string;
  readonly implementerId: string;
  readonly publicKeyEncoded: string;
}

export type ReportingPresentedKeyState = "ACTIVE" | "RETIRED" | "REVOKED";

// The unlocked pre-burn admission snapshot for one (node, implementer, presented key): the
// restore hold, the lifecycle head, and the presented key's state at its latest epoch. The
// same fields are rechecked under lock inside the burn transaction.
export interface ReportingAdmissionSnapshot {
  readonly restoreHold: boolean;
  readonly epoch: bigint;
  readonly authHold: boolean;
  readonly currentKeyId: string | null;
  readonly priorKeyId: string | null;
  readonly overlapExpiresAtMs: number | null;
  readonly successorCommittedAtMs: number | null;
  readonly presentedKeyState: ReportingPresentedKeyState | null;
  readonly presentedKeyRevokedAtMs: number | null;
}

// Key-status admission for the presented key against one head snapshot. Current slot requires
// ACTIVE; the prior slot requires the strict half-open overlap [successor_commit, commit+24h)
// with the stored expiry equal to the internally derived one (priorKeyEligible; platform holds zero keys). Any
// other arrangement (unknown key, retired, revoked, outside overlap, no active key) fails.
// Shared by the pre-burn snapshot evaluation and the burn-transaction recheck so the two can
// never drift apart.
export function reportingKeyAdmissionEligible(input: {
  readonly presentedKeyId: string;
  readonly currentKeyId: string | null;
  readonly priorKeyId: string | null;
  readonly overlapExpiresAtMs: number | null;
  readonly successorCommittedAtMs: number | null;
  readonly presentedKeyState: ReportingPresentedKeyState | null;
  readonly presentedKeyRevokedAtMs: number | null;
  readonly receivedAtMs: number;
}): boolean {
  if (input.presentedKeyId === input.currentKeyId) {
    return input.presentedKeyState === "ACTIVE";
  }
  if (
    input.presentedKeyId === input.priorKeyId &&
    input.presentedKeyState !== null &&
    input.successorCommittedAtMs !== null &&
    input.overlapExpiresAtMs !== null
  ) {
    return priorKeyEligible({
      isPriorSlot: true,
      keyState: input.presentedKeyState,
      revokedAtMs: input.presentedKeyRevokedAtMs,
      successorCommittedAtMs: input.successorCommittedAtMs,
      storedOverlapExpiresAtMs: input.overlapExpiresAtMs,
      receivedAtMs: input.receivedAtMs,
    });
  }
  return false;
}

// -------- nonce evidence (REPORTING_NONCE_FIELDS, minus the store-allocated id/sequence) -------

export interface ReportingNonceEvidence {
  readonly id: string;
  readonly nodeId: string;
  readonly implementerId: string;
  readonly nonce: string;
  readonly purpose: ReportingNoncePurpose;
  readonly routeId: string;
  readonly requestClass: ReportingRouteClass;
  readonly reportingKeyId: string;
  readonly lifecycleEpoch: bigint;
  readonly nonceBurnSequence: bigint;
  readonly requestPreimageText: string;
  readonly requestPreimageSha256: string;
  readonly requestSignature: string;
  readonly method: string;
  readonly rawTarget: string;
  readonly bodySha256: string;
  readonly logicalFingerprint: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  // The single ingress wall-clock instant and the burn instant; the durable adapter projects
  // these to received_at/consumed_at timestamptz (consumed_at >= received_at by construction).
  readonly receivedAtMs: number;
  readonly consumedAtMs: number;
  readonly retentionClass: string;
}

export type BurnNonceEvidence = Omit<ReportingNonceEvidence, "id" | "nonceBurnSequence">;

export interface BurnNonceRequest {
  readonly expectedEpoch: bigint;
  readonly evidence: BurnNonceEvidence;
}

export type BurnNonceOutcome =
  | { readonly kind: "BURNED"; readonly evidence: ReportingNonceEvidence }
  | { readonly kind: "REPLAY" }
  | { readonly kind: "HOLD" }
  | { readonly kind: "LIFECYCLE_RECHECK_FAILED" };

// -------- completed mutation idempotency (MUTATION_IDEMPOTENCY_FIELDS) -------

export interface CompletedIdempotencyRecord {
  readonly id: string;
  readonly nodeId: string;
  readonly implementerId: string;
  readonly routeId: string;
  readonly idempotencyKey: string;
  readonly reportingNonceId: string;
  readonly childRecordId: string;
  readonly method: string;
  readonly rawTarget: string;
  readonly bodySha256: string;
  readonly logicalFingerprint: string;
  readonly responseStatus: number;
  readonly responseBytes: Uint8Array;
  readonly completedAtMs: number;
}

export type InsertCompletedIdempotencyOutcome =
  | { readonly kind: "INSERTED" }
  | { readonly kind: "CONFLICT" };

// Unit-of-work handle for the guarded child + completed parent pair
// (MUTATION_IDEMPOTENCY_PERSISTENCE.mutationAndCompletedResultAtomic).
// The durable adapter exposes the same `query` fn the burn transaction uses so the child
// INSERT and the completed-idempotency INSERT share ONE Postgres transaction; deferred
// parent/child constraints fire at COMMIT. The in-memory reference adapter exposes
// `stageChildEffect` so child side effects journal and roll back with the parent
// (together-or-neither); UoWs are serialized on that adapter so concurrent handlers cannot
// interleave mid-section.
export interface ReportingMutationTx {
  // Present on the durable adapter; absent on the in-memory reference adapter.
  readonly query?: (
    text: string,
    params?: readonly unknown[],
  ) => Promise<readonly Record<string, unknown>[]>;
  // Present on the in-memory reference adapter. `apply` runs immediately; `rollback` runs
  // if the parent insert CONFLICTs or the unit of work throws — so child side effects never
  // outlive a failed parent.
  readonly stageChildEffect?: (apply: () => void, rollback: () => void) => void;
}

// Completion fields excluding childRecordId — the child id is produced by persistChild
// inside the same unit of work and stitched onto the parent row before commit.
export type CompletedIdempotencyDraft = Omit<CompletedIdempotencyRecord, "childRecordId">;

// Second arg is the completion parent PK (`reporting_mutation_idempotency.id`). Child rows
// MUST set `mutation_idempotency_id = completedIdempotencyId` so the deferred FK and
// `reporting_assert_completed_mutation` correlation hold (receive-arms.sql / verification-proofs.sql).
export type PersistCompletedMutationChild = (
  tx: ReportingMutationTx,
  completedIdempotencyId: string,
) => Promise<string>;

export type CommitMutationWithCompletedIdempotencyOutcome =
  | { readonly kind: "INSERTED"; readonly childRecordId: string }
  | { readonly kind: "CONFLICT" };

export const COMPLETED_IDEMPOTENCY_UNIQUE_FIELDS = [
  "node_id",
  "implementer_id",
  "route_id",
  "idempotency_key",
] as const;

// -------- node event stream verification (operator/auditor-only zp-node-event-v1) -------

export const NODE_EVENT_SIGNING_KEY_PURPOSE = "EVENT_SIGNING" as const;

export interface NodeEventSigningKey {
  readonly keyId: string;
  readonly nodeId: string;
  readonly publicKeyEncoded: string;
  readonly purpose: string;
  readonly activatedAtMs: number;
  readonly retiredAtMs: number | null;
}

export interface NodeEventCursor {
  readonly nodeId: string;
  readonly lastEventHash: string | null;
  readonly lastSeq: bigint;
  readonly lastEventId: string | null;
}

export interface RecordedNodeEvent {
  readonly nodeId: string;
  readonly eventId: string;
  readonly eventHash: string;
  readonly seq: bigint;
}

export type AppendNodeEventsOutcome =
  | { readonly kind: "APPENDED" }
  | { readonly kind: "CURSOR_STALE" };

// -------- the store interfaces -------

export interface ReportingRequestStore {
  findRegistration(nodeId: string, reportingKeyId: string): Promise<ReportingRegistration | null>;
  readAdmissionSnapshot(
    nodeId: string,
    implementerId: string,
    reportingKeyId: string,
  ): Promise<ReportingAdmissionSnapshot | null>;
  // Advisory pre-burn replay peek; the burn's unique insert is the authoritative replay guard.
  peekNonceBurned(nodeId: string, implementerId: string, nonce: string): Promise<boolean>;
  burnNonceAtomically(request: BurnNonceRequest): Promise<BurnNonceOutcome>;
  findCompletedIdempotency(
    nodeId: string,
    implementerId: string,
    routeId: string,
    idempotencyKey: string,
  ): Promise<CompletedIdempotencyRecord | null>;
  // Enforces the frozen completion contract: mandatory completion fields (response_status,
  // response_bytes, completed_at), UNIQUE(node_id, implementer_id, route_id, idempotency_key),
  // the guarded partial uniqueness over the actual (method, raw_target, body_sha256) triple on
  // the two FINGERPRINT_GUARDED_ROUTE_IDS routes, and append-only immutability. A mandate
  // violation is a programming error and surfaces as a rejected promise (never a request
  // outcome); a uniqueness race returns CONFLICT.
  //
  // Prefer commitMutationWithCompletedIdempotency on the request path — a bare completion
  // insert after an already-committed child is the atomicity gap.
  insertCompletedIdempotency(
    record: CompletedIdempotencyRecord,
  ): Promise<InsertCompletedIdempotencyOutcome>;
  // ONE unit of work: persistChild (guarded arm/ack child row, receiving parent PK) then the
  // completed idempotency parent, committed together. A failure after the child write rolls
  // the child back with the parent so a crash cannot leave a durable mutation without a
  // replayable exact response (together-or-neither;
  // MUTATION_IDEMPOTENCY_PERSISTENCE). The nonce burn stays OUTSIDE this transaction
  // (post-burn outcomes retain the burn; the burn is never folded
  // into the handler mutation).
  commitMutationWithCompletedIdempotency(input: {
    readonly persistChild: PersistCompletedMutationChild;
    readonly record: CompletedIdempotencyDraft;
  }): Promise<CommitMutationWithCompletedIdempotencyOutcome>;
}

export interface NodeEventVerificationStore {
  findEventSigningKey(nodeId: string, keyId: string): Promise<NodeEventSigningKey | null>;
  readCursor(nodeId: string): Promise<NodeEventCursor>;
  findRecordedEvent(nodeId: string, eventId: string): Promise<RecordedNodeEvent | null>;
  // Atomically records one verified batch and advances the cursor to its last event;
  // expectedCursor is the optimistic-concurrency guard for the durable adapter.
  appendVerifiedEvents(
    nodeId: string,
    events: readonly RecordedNodeEvent[],
    expectedCursor: NodeEventCursor,
  ): Promise<AppendNodeEventsOutcome>;
}

// Bounded pre-burn rate check. The request path passes the presented reporting key id as the
// principal (the only tenant signal available before the registration lookup; one key id maps
// to exactly one implementer binding, so the cardinality is the per-implementer one).
export interface ReportingRateLimiter {
  consume(nodeId: string, principal: string, atMs: number): boolean | Promise<boolean>;
}

export class ReportingStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReportingStoreError";
  }
}

export function isFingerprintGuardedRouteId(routeId: string): boolean {
  return (FINGERPRINT_GUARDED_ROUTE_IDS as readonly string[]).includes(routeId);
}

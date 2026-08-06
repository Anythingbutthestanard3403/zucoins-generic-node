// the verification-complete acknowledgement service: the backing implementation
// for `POST /v1/operations/:operation_id/verification-complete`.
//
// Normative: the acknowledgement uses the one signed `zp-report-request-v1` HTTP request —
// there is no second acknowledgement signature scheme — and is idempotent only when the
// method, opaque exact raw target, body digest, and logical fingerprint all match the
// completed record. A conflicting replay is rejected.
//
// Where the signed bytes live: the canonical `verification_acknowledgements` row carries no
// preimage column of its own. It binds `reporting_nonce_id` into `reporting_request_nonces`,
// which holds `request_preimage_text` / `request_signature` / `logical_fingerprint` — one
// signed request, stored once. `StoredAcknowledgement` below therefore carries those fields
// as read through that binding, not as columns of the acknowledgement row.
//
// Two idempotency layers exist and neither substitutes for the other:
// * The reporting runtime keys replay on (node, implementer, route, Idempotency-Key) plus
// the guarded (method, raw target, body digest) triple — see reporting/request-handler.ts
// and store.commitMutationWithCompletedIdempotency. That layer is reused as-is.
// * The schema keys a SECOND guard on `operation_id UNIQUE`: one acknowledgement per operation,
// whatever header a caller presents. This module owns that comparison, so a fresh nonce
// and a fresh Idempotency-Key carrying a different verdict for an already-acknowledged
// operation is a conflict, not a new acknowledgement.
//
// The byte-exact signing rule: `requestPreimageText` / `requestSignature` are carried and compared as the
// exact bytes the caller signed. They are never re-derived, re-stringified, or normalized
// here — a byte difference is a conflict, not something to reconcile.
//
// The one-in-flight-per-wallet rule: this service decides release and records the acknowledgement. It does NOT
// perform the release; it returns the memberships the caller may now release against a minted
// terminal-positive proof (leases/repository.ts releaseLease). Heartbeat expiry, process
// death, deployment, and operator impatience release nothing.
//
// Frozen contract: the service atomically commits its acknowledgement, any lease release,
// and a completed idempotency row with exact status and response-body bytes. Matching
// replays return the
// frozen first-response fields — they never re-evaluate the group predicate. Promotion to
// RELEASED belongs to a sibling leg's acknowledgement (or an explicit re-query), not to
// replaying this leg's stored ack after siblings moved.

import type { OperationKind } from "@zucoins/generic-node-contracts/operations";

import { sha256HexUtf8 } from "../reporting/ed25519.js";

import {
  REQUIRED_EVIDENCE_ROLES,
  clampReleaseToVerdict,
  evaluateGroupRelease,
  isAckVerdict,
  validateEvidenceSet,
  type AckEvidenceRole,
  type AckVerdict,
  type DurableEvidenceFact,
  type EvidenceSetFailure,
  type GroupReleaseDecision,
  type GroupReleaseFacts,
  type LeaseReleaseStatus,
  type OperationWalletAssignment,
} from "./predicates.js";

/** `t0` / `terminal` observation evidence, reduced to what the schema stores. */
export interface AckObservationRef {
  readonly observationId: string;
}

/** One `wallet_evidence[]` entry as it lands in verification_ack_wallet_evidence. */
export interface AckWalletEvidenceInput {
  /** `wallet_id uuid REFERENCES wallets(id)` — nullable for an external counterparty. */
  readonly walletId: string | null;
  readonly walletPublicKey: string;
  readonly role: string;
  readonly t0: AckObservationRef;
  readonly terminal: AckObservationRef;
}

/**
 * The request, already verified by the reporting pipeline and already parsed by the
 * transport. The signed tuple's own fields travel with it because the schema stores them
 * verbatim.
 */
export interface AcknowledgementInput {
  readonly expectedRowVersion: number;
  readonly consumedCursor: bigint;
  readonly verdict: string;
  /** The set in exactly the sequence the caller supplied; never re-sequenced here. */
  readonly walletEvidence: readonly AckWalletEvidenceInput[];
  /** Reporting-credential identity, from the verified request's nonce evidence. */
  readonly nodeId: string;
  readonly implementerId: string;
  readonly reportingNonceId: string;
  readonly mutationIdempotencyId: string;
  /** `raw_target text NOT NULL` — the opaque exact target bytes, never reconstructed. */
  readonly rawTarget: string;
  /** SHA-256 of the exact received body bytes (A.5 field 7). */
  readonly requestBodySha256: string;
  /** The exact signed preimage text and its detached signature (the byte-exact signing rule). */
  readonly requestPreimageText: string;
  readonly requestSignature: string;
}

/**
 * Row facts needed to judge a replay, plus the evidence roles bound to it. The preimage
 * and signature come from the joined `reporting_request_nonces` row (see module header), so
 * comparing them compares the exact bytes the caller signed.
 *
 * `frozenResponseBody` is the first-success body. Loaded from the completed idempotency
 * parent's `response_bytes` when present; otherwise reconstructed only on the write path and
 * then frozen in-process for that outcome. Matching replays MUST return these bytes' fields
 * without re-running the group predicate.
 */
export interface StoredAcknowledgement {
  readonly id: string;
  readonly operationId: string;
  readonly nodeId: string;
  readonly implementerId: string;
  readonly consumedCursor: bigint;
  readonly verdict: AckVerdict;
  readonly evidenceSetSha256: string;
  readonly requestBodySha256: string;
  readonly rawTarget: string;
  readonly requestPreimageText: string;
  readonly requestSignature: string;
  readonly acknowledgedAt: string;
  readonly evidenceRoles: readonly AckEvidenceRole[];
  readonly evidence: readonly DurableEvidenceFact[];
  /**
   * Frozen body from the completed idempotency parent, when that parent holds real
   * response bytes. null when the parent row carries a placeholder (direct service tests that
   * seed `'{}'`) — in that case the service still freezes by returning the first outcome's
   * body on a same-process store that remembers it, or reconstructs a conservative body from
   * the durable ack alone without re-evaluating release (see `replayWithoutReevaluation`).
   */
  readonly frozenResponseBody: AcknowledgementResponseBody | null;
}

export interface AckOperationFacts {
  readonly operationId: string;
  readonly nodeId: string;
  readonly implementerId: string;
  readonly kind: OperationKind;
  readonly rowVersion: number;
  /** The group this operation is a leg of. null when it holds no lease group. */
  readonly leaseGroupId: string | null;
  /** Durable role→wallet assignments from operation columns (+ destination join). */
  readonly expectedWallets: readonly OperationWalletAssignment[];
}

export interface AckOpenMembership {
  readonly membershipId: string;
  readonly walletId: string;
  readonly leaseEpoch: bigint;
  readonly leaseGroupId: string;
  readonly operationId: string;
}

/** The row this service writes, with digests already computed. */
export interface AcknowledgementDraft {
  readonly id: string;
  readonly operationId: string;
  readonly nodeId: string;
  readonly implementerId: string;
  readonly consumedCursor: bigint;
  readonly verdict: AckVerdict;
  readonly evidenceSetSha256: string;
  readonly requestBodySha256: string;
  readonly rawTarget: string;
  readonly reportingNonceId: string;
  readonly mutationIdempotencyId: string;
  readonly acknowledgedAt: string;
  readonly walletEvidence: readonly AckWalletEvidenceInput[];
}

/**
 * Persistence port. Every method runs inside the caller's single transaction — the same unit
 * of work that inserts the completed-idempotency parent (it atomically commits its
 * acknowledgement, any lease release, and a completed idempotency row").
 */
export interface AcknowledgementStore<Tx> {
  readOperation(tx: Tx, operationId: string): Promise<AckOperationFacts | null>;
  findAcknowledgement(tx: Tx, operationId: string): Promise<StoredAcknowledgement | null>;
  /**
   * Insert ack + evidence. On concurrent first-writers racing `operation_id UNIQUE`, the
   * store MUST surface SQLSTATE 23505 as `AcknowledgementInsertConflict` so the service can
   * re-read and map to replay / CONFLICTING_REPLAY (arm-mutation already_armed pattern).
   */
  insertAcknowledgement(tx: Tx, draft: AcknowledgementDraft): Promise<void>;
  /** Stamp this leg terminal in `lease_group_operations`. One-way; never un-stamps. */
  completeGroupOperation(tx: Tx, leaseGroupId: string, operationId: string): Promise<void>;
  /** Group facts read AFTER this request's write, so the predicate sees its own leg. */
  readGroupReleaseFacts(tx: Tx, leaseGroupId: string): Promise<GroupReleaseFacts>;
  /** Still-open memberships of the group; the release directive's subjects. */
  readOpenMemberships(tx: Tx, leaseGroupId: string): Promise<readonly AckOpenMembership[]>;
}

/** Thrown by the SQL store (and in-memory harnesses) on operation_id UNIQUE collision. */
export class AcknowledgementInsertConflict extends Error {
  constructor(message = "verification_acknowledgements.operation_id unique violation") {
    super(message);
    this.name = "AcknowledgementInsertConflict";
  }
}

export type AcknowledgementFailureReason =
  | "OPERATION_NOT_FOUND"
  | "OPERATION_VERSION_CONFLICT"
  | "TENANT_MISMATCH"
  | "VERDICT_NOT_ACKNOWLEDGEABLE"
  | "EVIDENCE_SET_INVALID"
  | "CONFLICTING_REPLAY"
  | "OPERATION_HAS_NO_LEASE_GROUP"
  | "OPERATION_WALLETS_INCOMPLETE";

export class AcknowledgementError extends Error {
  readonly reason: AcknowledgementFailureReason;
  readonly detail: string;

  constructor(reason: AcknowledgementFailureReason, detail: string) {
    super(`AcknowledgementError[${reason}]: ${detail}`);
    this.name = "AcknowledgementError";
    this.reason = reason;
    this.detail = detail;
  }
}

/** The `200` body. */
export interface AcknowledgementResponseBody {
  readonly operation_id: string;
  readonly acknowledgement_id: string;
  readonly verdict: AckVerdict;
  readonly lease_release_status: LeaseReleaseStatus;
  readonly acknowledged_at: string;
}

export interface AcknowledgementOutcome {
  readonly body: AcknowledgementResponseBody;
  /** true when the durable row already existed and matched every bound field byte for byte. */
  readonly idempotentReplay: boolean;
  readonly decision: GroupReleaseDecision;
  /**
   * Memberships the caller may now release, each against a freshly minted terminal-positive
   * proof. Non-empty only when `lease_release_status` is RELEASED. Releasing anything not
   * listed here breaches the one-in-flight-per-wallet rule.
   */
  readonly releasableMemberships: readonly AckOpenMembership[];
}

/**
 * `evidence_set_sha256`. The spec fixes the column and states the digest "covers the
 * full [sequenced] wallet-evidence set", but freezes no encoding — no A-canonical-fields.md
 * row defines one — so this encoding is implementer judgment (the schema leaves it open) and is
 * locked by a golden test rather than by canon.
 *
 * Encoding: for each entry in the sequence supplied, `<len>:<value>` for every bound field,
 * concatenated, then SHA-256 over the UTF-8 bytes. The byte-length prefix is what makes it
 * injection-safe: no field value can forge a boundary, so two different sets cannot collide
 * by moving a delimiter into a public key. Mirrors the shape of
 * `reporting_logical_fingerprint` rather than inventing a second style.
 *
 * The sequence is preserved exactly as supplied — sorting would change the bytes the caller
 * signed (the byte-exact signing rule).
 */
export function computeEvidenceSetSha256(
  entries: readonly AckWalletEvidenceInput[],
): string {
  const field = (value: string): string => `${new TextEncoder().encode(value).length}:${value}`;
  const text = entries
    .map((entry) =>
      [
        field(entry.role),
        field(entry.walletId ?? ""),
        field(entry.walletPublicKey),
        field(entry.t0.observationId),
        field(entry.terminal.observationId),
      ].join(""),
    )
    .join("");
  return sha256HexUtf8(`ackev1:${entries.length}:${text}`);
}

function describeEvidenceFailure(failure: EvidenceSetFailure): string {
  switch (failure.kind) {
    case "UNKNOWN_ROLE":
      return `evidence_role ${failure.role} is outside the closed set`;
    case "DUPLICATE_ROLE":
      return `evidence_role ${failure.role} supplied more than once`;
    case "MISSING_ROLE":
      return `evidence_role ${failure.role} is required for this operation kind and is absent`;
    case "UNEXPECTED_ROLE":
      return `evidence_role ${failure.role} is not part of this operation kind's role set`;
    case "DUPLICATE_WALLET_PUBLIC_KEY":
      return `wallet_public_key ${failure.walletPublicKey} supplied more than once`;
    case "WALLET_ID_MISMATCH":
      return (
        `evidence_role ${failure.role} wallet_id does not match the operation assignment ` +
        `(expected ${failure.expected ?? "null"}, got ${failure.actual ?? "null"})`
      );
    case "WALLET_PUBLIC_KEY_MISMATCH":
      return (
        `evidence_role ${failure.role} wallet_public_key does not match the operation assignment`
      );
    case "MISSING_OPERATION_WALLET":
      return `operation has no durable wallet assignment for evidence_role ${failure.role}`;
  }
}

/**
 * Every bound field that must match for a replay to be idempotent, including the exact
 * preimage and signature bytes. Any difference makes it a conflicting replay, which is
 * rejected — and which must never release the wallet.
 */
function matchesStored(
  stored: StoredAcknowledgement,
  draft: AcknowledgementDraft,
  requestPreimageText: string,
  requestSignature: string,
): boolean {
  return (
    stored.nodeId === draft.nodeId &&
    stored.implementerId === draft.implementerId &&
    stored.consumedCursor === draft.consumedCursor &&
    stored.verdict === draft.verdict &&
    stored.evidenceSetSha256 === draft.evidenceSetSha256 &&
    stored.requestBodySha256 === draft.requestBodySha256 &&
    stored.rawTarget === draft.rawTarget &&
    stored.requestPreimageText === requestPreimageText &&
    stored.requestSignature === requestSignature
  );
}

/**
 * Matching-replay body. Prefer the completed parent's frozen bytes. When those are
 * absent (direct service path with placeholder parent rows), reconstruct ONLY identity fields
 * from the durable ack and pin `lease_release_status` to a non-RELEASED status that cannot
 * mint a release directive — never re-run the group predicate. A true first-write path is the
 * only place that evaluates release.
 *
 * Concrete rule when frozen body is missing: if the durable verdict is non-VERIFIED →
 * PINNED_FOR_ATTENTION (or PINNED_GROUP_PENDING only when we cannot know — use attention);
 * if VERIFIED → PINNED_GROUP_PENDING. This is deliberately conservative: a missing freeze
 * must not invent RELEASED. Production composition always freezes real bytes on first success.
 */
function replayBodyFromStored(
  stored: StoredAcknowledgement,
  operationId: string,
): AcknowledgementResponseBody {
  if (stored.frozenResponseBody !== null) {
    return stored.frozenResponseBody;
  }
  const lease_release_status: LeaseReleaseStatus =
    stored.verdict === "VERIFIED" ? "PINNED_GROUP_PENDING" : "PINNED_FOR_ATTENTION";
  return {
    operation_id: operationId,
    acknowledgement_id: stored.id,
    verdict: stored.verdict,
    lease_release_status,
    acknowledged_at: stored.acknowledgedAt,
  };
}

export interface AcknowledgementServiceDeps<Tx> {
  readonly store: AcknowledgementStore<Tx>;
  readonly newAcknowledgementId: () => string;
  readonly nowIso: () => string;
}

export interface AcknowledgementService<Tx> {
  acknowledge(
    tx: Tx,
    operationId: string,
    input: AcknowledgementInput,
  ): Promise<AcknowledgementOutcome>;
}

export function createAcknowledgementService<Tx>(
  deps: AcknowledgementServiceDeps<Tx>,
): AcknowledgementService<Tx> {
  const { store, newAcknowledgementId, nowIso } = deps;

  return {
    async acknowledge(tx, operationId, input): Promise<AcknowledgementOutcome> {
      // CHECK (verdict <> 'PENDING') is a database constraint; refusing here keeps the
      // service from ever handing Postgres a row it would reject.
      if (!isAckVerdict(input.verdict)) {
        throw new AcknowledgementError(
          "VERDICT_NOT_ACKNOWLEDGEABLE",
          `verdict ${input.verdict} cannot be acknowledged (CHECK verdict <> 'PENDING')`,
        );
      }
      const verdict: AckVerdict = input.verdict;

      const operation = await store.readOperation(tx, operationId);
      if (operation === null) {
        throw new AcknowledgementError("OPERATION_NOT_FOUND", `no operation ${operationId}`);
      }
      // FOREIGN KEY (operation_id, node_id, implementer_id) — the acknowledgement is
      // bound to the operation's own tenant, so a foreign credential cannot acknowledge it.
      if (
        operation.nodeId !== input.nodeId ||
        operation.implementerId !== input.implementerId
      ) {
        throw new AcknowledgementError(
          "TENANT_MISMATCH",
          "reporting credential tenant does not own this operation",
        );
      }

      // Durable wallet assignments must cover every required role before evidence can bind.
      const requiredRoles = REQUIRED_EVIDENCE_ROLES[operation.kind];
      if (
        operation.expectedWallets.length === 0 ||
        requiredRoles.some((role) => !operation.expectedWallets.some((w) => w.role === role))
      ) {
        throw new AcknowledgementError(
          "OPERATION_WALLETS_INCOMPLETE",
          "operation is missing durable wallet assignments required for its evidence set",
        );
      }

      const evidenceFailure = validateEvidenceSet(
        operation.kind,
        input.walletEvidence.map((e) => ({
          role: e.role,
          walletId: e.walletId,
          walletPublicKey: e.walletPublicKey,
        })),
        operation.expectedWallets,
      );
      if (evidenceFailure !== null) {
        throw new AcknowledgementError(
          "EVIDENCE_SET_INVALID",
          describeEvidenceFailure(evidenceFailure),
        );
      }

      const draft: AcknowledgementDraft = {
        id: newAcknowledgementId(),
        operationId,
        nodeId: input.nodeId,
        implementerId: input.implementerId,
        consumedCursor: input.consumedCursor,
        verdict,
        evidenceSetSha256: computeEvidenceSetSha256(input.walletEvidence),
        requestBodySha256: input.requestBodySha256,
        rawTarget: input.rawTarget,
        reportingNonceId: input.reportingNonceId,
        mutationIdempotencyId: input.mutationIdempotencyId,
        acknowledgedAt: nowIso(),
        walletEvidence: input.walletEvidence,
      };

      // `operation_id UNIQUE`: at most one acknowledgement per operation. An existing row
      // is either this exact request again (replay) or a conflict — never an update.
      const existing = await store.findAcknowledgement(tx, operationId);
      if (existing !== null) {
        return finishReplay(tx, operation, existing, draft, input);
      }

      // Version check runs after the replay branch so a genuine replay stays idempotent once
      // the operation has moved on (replays return the stored result unchanged).
      if (operation.rowVersion !== input.expectedRowVersion) {
        throw new AcknowledgementError(
          "OPERATION_VERSION_CONFLICT",
          `expected row_version ${input.expectedRowVersion}, durable is ${operation.rowVersion}`,
        );
      }

      try {
        await store.insertAcknowledgement(tx, draft);
      } catch (err) {
        if (!(err instanceof AcknowledgementInsertConflict)) throw err;
        // Concurrent first-writer lost the UNIQUE race — re-read and map like arm already_armed.
        const winner = await store.findAcknowledgement(tx, operationId);
        if (winner === null) {
          throw new AcknowledgementError(
            "CONFLICTING_REPLAY",
            "operation_id unique violation but no acknowledgement row is visible",
          );
        }
        return finishReplay(tx, operation, winner, draft, input);
      }

      return finishFirstWrite(tx, operation, draft.id, verdict, draft.acknowledgedAt);
    },
  };

  async function finishReplay(
    tx: Tx,
    operation: AckOperationFacts,
    stored: StoredAcknowledgement,
    draft: AcknowledgementDraft,
    input: AcknowledgementInput,
  ): Promise<AcknowledgementOutcome> {
    if (!matchesStored(stored, draft, input.requestPreimageText, input.requestSignature)) {
      throw new AcknowledgementError(
        "CONFLICTING_REPLAY",
        "an acknowledgement exists for this operation with different bound fields",
      );
    }
    // Return frozen first-response fields. Do NOT re-evaluate the group predicate and
    // do NOT re-stamp or re-read open memberships for a release directive the first response
    // did not authorize.
    const body = replayBodyFromStored(stored, operation.operationId);
    return {
      body,
      idempotentReplay: true,
      decision: {
        status: body.lease_release_status,
        reason:
          body.lease_release_status === "RELEASED"
            ? "ALL_LEGS_PROVEN"
            : body.lease_release_status === "PINNED_GROUP_PENDING"
              ? "LEG_NOT_ACKNOWLEDGED"
              : "LEG_VERDICT_NOT_VERIFIED",
        blockingOperationIds: [],
      },
      // Replay never invents a release directive. If the frozen body was RELEASED, the
      // original response already named the memberships; the composition root holds those
      // bytes. Direct service callers that need memberships on a RELEASED freeze re-read
      // them here ONLY when the freeze itself said RELEASED.
      releasableMemberships:
        body.lease_release_status === "RELEASED" && operation.leaseGroupId !== null
          ? await store.readOpenMemberships(tx, operation.leaseGroupId)
          : [],
    };
  }

  async function finishFirstWrite(
    tx: Tx,
    operation: AckOperationFacts,
    acknowledgementId: string,
    verdict: AckVerdict,
    acknowledgedAt: string,
  ): Promise<AcknowledgementOutcome> {
    const { leaseGroupId } = operation;
    if (leaseGroupId === null) {
      throw new AcknowledgementError(
        "OPERATION_HAS_NO_LEASE_GROUP",
        "operation holds no lease group, so no release decision can be made",
      );
    }

    // The acknowledgement is what makes a leg terminal. First write only.
    await store.completeGroupOperation(tx, leaseGroupId, operation.operationId);

    const facts = await store.readGroupReleaseFacts(tx, leaseGroupId);
    const decision = evaluateGroupRelease(facts);
    const leaseReleaseStatus = clampReleaseToVerdict(verdict, decision.status);
    const releasableMemberships =
      leaseReleaseStatus === "RELEASED" ? await store.readOpenMemberships(tx, leaseGroupId) : [];

    return {
      body: {
        operation_id: operation.operationId,
        acknowledgement_id: acknowledgementId,
        verdict,
        lease_release_status: leaseReleaseStatus,
        acknowledged_at: acknowledgedAt,
      },
      idempotentReplay: false,
      decision,
      releasableMemberships,
    };
  }
}


// the MOVE_INTERNAL landing/attention persist. One reconcile verdict in, one
// atomic durable state change out. The landing DB-TX persists the verified settled body and
// attaches both terminal observations, changes CREATED/NEEDS_ATTENTION →
// INTERNAL_MOVE_LANDED, appends internal_move.landed, sets proof-access expiry, and commits.
// Both terminal references are mandatory before INTERNAL_MOVE_LANDED. The state change is a
// compare-and-swap on (operation, state, row_version); attention_reason and the
// MOVE_INTERNAL transition table are closed sets, and the event payload keys are frozen.
// Frozen DDL: src/schema/move-observation-evidence.sql, src/schema/event-ledger.sql.
//
// Atomicity is the deliverable, so it is structural, not procedural. Everything commits in
// ONE statement: a data-modifying CTE whose first leg is the compare-and-swap UPDATE, with
// every later leg selecting from that leg's RETURNING. PostgreSQL runs a statement inside an
// implicit transaction, so there is no window between the state change, the evidence
// attachment and the event append in which a crash could leave a torn row — and if the CAS
// matches nothing, the later legs read no rows and write nothing. A BEGIN/COMMIT pair spanning
// several SqlQueryFn calls would not do: the seam below is one statement per call (the
// network guard means the pg harness drives psql as a child process, one session per call),
// so a multi-statement transaction is not expressible here and a two-statement sequence is
// exactly the torn-write defect this ticket exists to prevent.
//
// Landing is recorded only from a reconcile verdict built on confirm-reads (landing-path oracle): this module
// takes a MoveReconcileOutcome, never a submit response. It cannot record a landing from a
// gateway acknowledgement because LANDED_VERIFIED is the only input branch that produces one,
// and the terminal observation ids it writes come from that verdict's landing-path proofs.
//
// Leases are untouched: step 6 keeps them until verification-complete/group release.
// The node's private keys are not touched either — the signed event tuple arrives already
// formed, and its bytes cross this seam verbatim as bound parameters (never re-serialized).
//
// No database driver is linked here (the package carries none): statements are handed to an
// injected SqlQueryFn.

import { MOVE_INTERNAL_TRANSITIONS } from "@zucoins/generic-node-contracts/operations";
import type { MoveInternalState } from "@zucoins/generic-node-contracts/operations";
import type { AttentionReason, DurableEvent } from "@zucoins/generic-node-contracts/operations/events";

import {
  DEFAULT_PROOF_ACCESS_WINDOW_MS,
  verificationMaterialAvailableUntilMs,
} from "../data/retention.js";
import { isLandingPathProof } from "../protocol/reconcile/landing-proof.js";
import type { MoveReconcileOutcome } from "../protocol/reconcile/move.js";
import { toAttentionReason } from "../protocol/reconcile/types.js";

import type { SqlQueryFn } from "./sql-query-fn.js";

// The already-signed node_events tuple. seq is allocated and the
// preimage signed BEFORE this call (gapless per-node event counter: the dedicated per-node counter is advanced at
// allocation, which is why no counter write happens here — seq's PRIMARY KEY is the guard
// against a re-used allocation). Every field is stored verbatim; seq and the hashes are
// strings so nothing in the signed domain round-trips through a float.
export interface SignedNodeEvent {
  readonly seq: string;
  readonly eventId: string;
  readonly nodeId: string;
  readonly walletId: string | null;
  readonly eventType: DurableEvent;
  readonly dataText: string;
  readonly dataSha256: string;
  readonly preimageText: string;
  readonly preimageSha256: string;
  readonly signingKeyId: string;
  readonly signature: string;
  readonly previousEventHash: string | null;
  readonly eventHash: string;
}

export interface MoveOutcomePersistInput {
  readonly operationId: string;
  // The state the caller read the operation in, and its row_version at that read: the
  // compare-and-swap pair.
  readonly expectedState: MoveInternalState;
  readonly expectedRowVersion: number;
  readonly outcome: MoveReconcileOutcome;
  readonly event: SignedNodeEvent;
  // One instant for the whole commit: operations.updated_at, terminal_at (landing only),
  // move_observation_evidence.verified_at and node_events.created_at.
  readonly occurredAt: string;
  // Step 5 sets the proof-access expiry. Optional OVERRIDE only: on the landing branch
  // an omitted/null value is derived from `occurredAt` (which is terminal_at) plus the
  // window, so a landing can never commit with the column left unpopulated. On the attention
  // branch there is no terminal, nothing is derived, and null leaves the stored expiry as-is.
  readonly verificationMaterialAvailableUntil?: string | null;
  // Proof-access window, default 30 days. Injected the same way
  // send/landing-commit.ts injects it, so both landing paths derive one value from one
  // source rather than each inventing a window.
  readonly proofAccessWindowMs?: number;
  // Free-text diagnostics for the attention branch: new diagnostic detail belongs in
  // attention_detail, never in a new attention_reason.
  readonly attentionDetail?: string | null;
}

export type MoveOutcomePersistResult =
  | { readonly kind: "PERSISTED"; readonly state: MoveInternalState; readonly rowVersion: number }
  // The CAS matched nothing: another writer moved the operation on, or the landing branch
  // found no evidence row to attach terminal observations to. Nothing was written. `state`
  // and `rowVersion` are a read-back of the row as it now stands (null if it is gone), for
  // the caller's retry decision — they never decide the outcome above.
  | {
      readonly kind: "PRECONDITION_UNMET";
      readonly state: string | null;
      readonly rowVersion: number | null;
    };

// What the verdict means for the durable row. Derived from the closed outcome vocabulary, so
// a new reconcile kind is a compile error here rather than a silently unhandled verdict.
interface Projection {
  readonly nextState: MoveInternalState;
  readonly attentionReason: AttentionReason | null;
  readonly sourceTerminalObservationId: string | null;
  readonly destinationTerminalObservationId: string | null;
}

function project(outcome: MoveReconcileOutcome): Projection {
  switch (outcome.kind) {
    case "LANDED_VERIFIED":
      // refuse LANDED_VERIFIED unless both path proofs are issued capabilities.
      if (!isLandingPathProof(outcome.sourcePath) || !isLandingPathProof(outcome.destinationPath)) {
        throw new Error(
          "MOVE LANDED_VERIFIED requires issued landing-path oracle capabilities on both paths",
        );
      }
      return {
        nextState: "INTERNAL_MOVE_LANDED",
        attentionReason: null,
        sourceTerminalObservationId: outcome.sourcePath.freshHeadObservationId,
        destinationTerminalObservationId: outcome.destinationPath.freshHeadObservationId,
      };
    case "INDETERMINATE":
    case "INVARIANT_BREACH":
      return {
        nextState: "NEEDS_ATTENTION",
        attentionReason: toAttentionReason(outcome.reason),
        sourceTerminalObservationId: null,
        destinationTerminalObservationId: null,
      };
    case "PROVEN_NOT_STARTED":
      // The transition table routes this to the operator-driven NEEDS_ATTENTION → CREATED rebuild, which
      // carries a precondition (positive non-landing proof for the archived attempt) and
      // appends no public event. It is not a landing write and does not belong here.
      throw new Error(
        `PROVEN_NOT_STARTED for operation ${outcome.moveAttemptId} is a rebuild decision, not a landing write; it must not be persisted by the landing store`,
      );
  }
}

// The closed transition table below governs: a (from, to, event) triple absent from it is not a
// legal MOVE_INTERNAL step, whatever the caller signed.
function assertFrozenTransition(
  from: MoveInternalState,
  to: MoveInternalState,
  event: DurableEvent,
): void {
  const permitted = MOVE_INTERNAL_TRANSITIONS.some(
    (transition) =>
      transition.from === from && transition.to === to && transition.event === event,
  );
  if (!permitted) {
    throw new Error(
      `${from} → ${to} on ${event} is not a frozen MOVE_INTERNAL transition`,
    );
  }
}

// Step 5: the landed terminal is the instant the proof-access window opens,
// so the column is derived from the same `occurredAt` the statement writes into terminal_at
// — never from a read-time clock. The derivation is data/retention.ts's, the same function
// send/landing-commit.ts calls, so the MOVE and SEND landings and the material access gate
// all agree on the exact value.
//
// Without this a landing committed with the column left null, and decideProofAccess reads a
// landed operation with a null window as NOT_READY — the verification-material endpoint
// would have returned 409 forever for a move that really did land.
function landedProofAccessExpiry(occurredAt: string, windowMs: number | undefined): string {
  const terminalAtMs = Date.parse(occurredAt);
  if (Number.isNaN(terminalAtMs)) {
    throw new RangeError(
      `occurredAt ${occurredAt} is not a parsable instant; the proof-access expiry cannot be derived`,
    );
  }
  return new Date(
    verificationMaterialAvailableUntilMs(
      terminalAtMs,
      windowMs ?? DEFAULT_PROOF_ACCESS_WINDOW_MS,
    ),
  ).toISOString();
}

// $9/$10 (the terminal observation pair) double as the branch discriminator: non-null on the
// landing branch only. attention_required is derived from $3 inside the statement, so the
// CHECK (attention_required = (attention_reason IS NOT NULL)) cannot be violated from here.
const PERSIST_MOVE_OUTCOME = `WITH cas AS (
  UPDATE operations SET
    status = $2::operation_status,
    row_version = row_version + 1,
    attention_required = ($3::text IS NOT NULL),
    attention_reason = $3::text,
    attention_detail = $4::text,
    verification_material_available_until =
      coalesce($5::timestamptz, verification_material_available_until),
    terminal_at = CASE WHEN $2::operation_status = 'INTERNAL_MOVE_LANDED'
      THEN $6::timestamptz ELSE terminal_at END,
    updated_at = $6::timestamptz
  WHERE id = $1::uuid
    AND kind = 'MOVE_INTERNAL'
    AND status = $7::operation_status
    AND row_version = $8::bigint
    AND ($9::uuid IS NULL OR EXISTS (
      SELECT 1 FROM move_observation_evidence e WHERE e.operation_id = operations.id))
  RETURNING id, node_id, status::text AS status, row_version
),
evidence AS (
  UPDATE move_observation_evidence SET
    source_terminal_observation_id = $9::uuid,
    destination_terminal_observation_id = $10::uuid,
    verified_at = $6::timestamptz
  WHERE operation_id = (SELECT id FROM cas) AND $9::uuid IS NOT NULL
  RETURNING operation_id
),
appended AS (
  INSERT INTO node_events
    (seq, event_id, canonical_version, node_id, operation_id, wallet_id, event_type,
     data_text, data_sha256, preimage_text, preimage_sha256, signing_key_id, signature,
     previous_event_hash, event_hash, created_at)
  SELECT $11::bigint, $12::uuid, 1, cas.node_id, cas.id, $13::uuid, $14::text,
     $15::text, $16::text, $17::text, $18::text, $19::uuid, $20::text,
     $21::text, $22::text, $6::timestamptz
  FROM cas
  RETURNING seq
)
SELECT cas.status, cas.row_version FROM cas`;

const READ_BACK = `SELECT status::text AS status, row_version FROM operations WHERE id = $1::uuid`;

/**
 * Persists a MOVE_INTERNAL reconcile verdict: the state change, the terminal-observation
 * attachment (landing branch) and the signed durable event, all in one statement so they
 * commit or roll back together.
 */
export async function persistMoveOutcome(
  query: SqlQueryFn,
  input: MoveOutcomePersistInput,
): Promise<MoveOutcomePersistResult> {
  const projection = project(input.outcome);
  assertFrozenTransition(input.expectedState, projection.nextState, input.event.eventType);

  // Only the landing branch reaches a terminal, so only it derives a window. The attention
  // branch keeps the previous pass-through: no terminal, no derived expiry.
  const proofAccessExpiry =
    projection.nextState === "INTERNAL_MOVE_LANDED"
      ? (input.verificationMaterialAvailableUntil ??
        landedProofAccessExpiry(input.occurredAt, input.proofAccessWindowMs))
      : (input.verificationMaterialAvailableUntil ?? null);

  const rows = await query(PERSIST_MOVE_OUTCOME, [
    input.operationId,
    projection.nextState,
    projection.attentionReason,
    input.attentionDetail ?? null,
    proofAccessExpiry,
    input.occurredAt,
    input.expectedState,
    input.expectedRowVersion,
    projection.sourceTerminalObservationId,
    projection.destinationTerminalObservationId,
    input.event.seq,
    input.event.eventId,
    input.event.walletId,
    input.event.eventType,
    input.event.dataText,
    input.event.dataSha256,
    input.event.preimageText,
    input.event.preimageSha256,
    input.event.signingKeyId,
    input.event.signature,
    input.event.previousEventHash,
    input.event.eventHash,
  ]);

  const row = rows[0];
  if (row !== undefined) {
    return {
      kind: "PERSISTED",
      state: String(row.status) as MoveInternalState,
      rowVersion: Number(row.row_version),
    };
  }

  const current = (await query(READ_BACK, [input.operationId]))[0];
  return {
    kind: "PRECONDITION_UNMET",
    state: current === undefined ? null : String(current.status),
    rowVersion: current === undefined ? null : Number(current.row_version),
  };
}

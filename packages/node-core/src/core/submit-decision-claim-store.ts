// Database-arbitrated persistence for the two append-only submit ledgers:
// submit_decisions (the single-shot claim) and gateway_submit_attempts (the transport
// evidence). Frozen DDL: src/schema/submit-attempts.sql. A second transaction attempt,
// submit decision, or submit call for one operation fails; the never-blind-retry rule.
//
// The claim's at-most-once property is the database's UNIQUE (operation_id,
// transaction_attempt_no) on submit_decisions, not application logic: the mint is decided by
// whether the INSERT produced a row, so two concurrent callers are separated by the
// constraint itself. The losing branch's SELECT runs only after the conflict is already
// settled — it reports the winner's claim, it never decides the mint.
//
// No database driver is linked here (the package carries none, and the network guard
// forbids in-process sockets under test): statements are handed to an injected SqlQueryFn.
// Byte columns cross that seam as lowercase hex and are converted by `decode(..., 'hex')`,
// so the seam moves only text, numbers and null regardless of driver.

import { randomUUID } from "node:crypto";

import type {
  GatewaySubmitAttemptRecord,
  SubmitAttemptRecorder,
  SubmitTransportOutcome,
} from "../gateway/records.js";
import type { ReconcileIndeterminateReason } from "../protocol/reconcile/types.js";

import type { MoveSubmitClaim, MoveSubmitClaimMint, MoveSubmitClaimStore } from "./move-submit-claim.js";
import type { SqlQueryFn } from "./sql-query-fn.js";

// The frozen contract fixes the only legal value; the DDL re-checks it (CHECK (decision =
// 'INITIAL_SINGLE_SHOT')), so a drift here is a database rejection, not a silent write.
const INITIAL_SINGLE_SHOT = "INITIAL_SINGLE_SHOT";

// submit_decisions.details is NOT NULL and carries no machine meaning.
const CLAIM_DETAILS = "single-shot submit claim for the one authorized move attempt";

// timestamptz renders per-driver (Date, or a session-formatted string), so every read casts to
// the one ISO-8601 UTC form the rest of the node uses for NowIsoFn values.
const ISO_UTC = `to_char(decided_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')`;

// ON CONFLICT DO NOTHING (no arbiter) catches every unique violation — both the
// intentional UNIQUE (operation_id, transaction_attempt_no) and the primary key on id.
// Concurrent callers for the same authorization share one decision id
// (mintSubmitClaim(authorization.submitDecisionId, ...)); specifying only the composite
// unique as arbiter left a PK race where two simultaneous same-id inserts raised 23505
// instead of minting once and handing the loser the winner's claim via CLAIM_SELECT.
const CLAIM_INSERT = `INSERT INTO submit_decisions
  (id, operation_id, transaction_attempt_no, decision, decided_at, details)
  VALUES ($1, $2, $3, '${INITIAL_SINGLE_SHOT}', $4::timestamptz, $5)
  ON CONFLICT DO NOTHING
  RETURNING id, ${ISO_UTC} AS decided_at`;

const CLAIM_SELECT = `SELECT id, ${ISO_UTC} AS decided_at FROM submit_decisions
  WHERE operation_id = $1 AND transaction_attempt_no = $2`;

const ATTEMPT_INSERT = `INSERT INTO gateway_submit_attempts
  (id, operation_id, attempt_no, transaction_attempt_no, decision_id,
   request_body, request_sha256, response_body, response_sha256,
   transport_outcome, started_at, completed_at)
  VALUES ($1, $2, $3, $4, $5,
   decode($6, 'hex'), $7, decode($8, 'hex'), $9,
   $10, $11::timestamptz, $12::timestamptz)
  RETURNING id`;

const ATTEMPT_SELECT = `SELECT transport_outcome FROM gateway_submit_attempts
  WHERE operation_id = $1 AND transaction_attempt_no = $2`;

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function claimFromRow(row: Record<string, unknown>, claim: MoveSubmitClaim): MoveSubmitClaim {
  return {
    attemptId: String(row.id),
    claimedAt: String(row.decided_at),
    operationId: claim.operationId,
    transactionAttemptNo: claim.transactionAttemptNo,
  };
}

// The SQL-backed MoveSubmitClaimStore. One INSERT decides the mint; the SELECT on the losing
// branch only reads back whichever claim the database kept.
export function makeSubmitDecisionClaimStore(query: SqlQueryFn): MoveSubmitClaimStore {
  return {
    async claimSubmitOnce(claim: MoveSubmitClaim): Promise<MoveSubmitClaimMint> {
      const inserted = await query(CLAIM_INSERT, [
        claim.attemptId,
        claim.operationId,
        claim.transactionAttemptNo,
        claim.claimedAt,
        CLAIM_DETAILS,
      ]);
      const mintedRow = inserted[0];
      if (mintedRow !== undefined) {
        return { claim: claimFromRow(mintedRow, claim), minted: true };
      }

      const existing = await query(CLAIM_SELECT, [claim.operationId, claim.transactionAttemptNo]);
      const existingRow = existing[0];
      if (existingRow === undefined) {
        // The INSERT declined and no row is readable: the claim's durable state is unknown, so
        // reporting either mint verdict would be a guess. Fail closed — a false "minted" is a
        // second submit.
        throw new Error(
          `submit claim for attempt ${claim.transactionAttemptNo} of operation ${claim.operationId} is neither minted nor readable; the claim state is unknown and the attempt must not be submitted`,
        );
      }
      return { claim: claimFromRow(existingRow, claim), minted: false };
    },
  };
}

// The SQL-backed SubmitAttemptRecorder. A second attempt row for the same operation/decision
// violates one of the uniqueness constraints; that rejection propagates, which
// submit.ts converts into the reconcile-only SubmitIndeterminateError (fail closed).
export function makeSubmitAttemptRecorder(query: SqlQueryFn): SubmitAttemptRecorder {
  return {
    async recordSubmitAttempt(record: GatewaySubmitAttemptRecord): Promise<void> {
      await query(ATTEMPT_INSERT, [
        randomUUID(),
        record.operationId,
        record.attemptNo,
        record.transactionAttemptNo,
        record.decisionId,
        toHex(record.requestBytes),
        record.requestSha256,
        record.responseBytes === null ? null : toHex(record.responseBytes),
        record.responseSha256,
        record.transportOutcome,
        record.startedAt,
        record.completedAt,
      ]);
    },
  };
}

// Durable submit-attempt evidence for one (operationId, transactionAttemptNo), read back for
// the recovery classifier. The mutability regime is insert-only, frozen at
// insert (transport_outcome is NOT NULL — there is no partial "in flight" row), so
// "claimed the mint but the gateway exchange never returned" is not a row state; it is the
// ABSENCE of a gateway_submit_attempts row for a submit_decisions row that exists. The three
// states below are exactly that: no claim at all, a claim with no attempt row, and a claim
// with its attempt row.
export type SubmitAttemptEvidenceStatus = "NOT_CLAIMED" | "CLAIMED_UNRETURNED" | "RETURNED";

export interface SubmitAttemptEvidence {
  readonly status: SubmitAttemptEvidenceStatus;
  // Populated only when status is RETURNED — the one column the classifier below needs.
  readonly transportOutcome: SubmitTransportOutcome | null;
}

// Reads the durable evidence for one attempt: two SELECTs, not a JOIN. submit_decisions and
// gateway_submit_attempts are both keyed on (operation_id, transaction_attempt_no);
// the second query runs only once the first establishes a claim exists, since there is
// nothing to correlate beyond that shared key.
export async function readSubmitAttemptEvidence(
  query: SqlQueryFn,
  operationId: string,
  transactionAttemptNo: number,
): Promise<SubmitAttemptEvidence> {
  const claimed = await query(CLAIM_SELECT, [operationId, transactionAttemptNo]);
  if (claimed[0] === undefined) {
    return { status: "NOT_CLAIMED", transportOutcome: null };
  }

  const returned = await query(ATTEMPT_SELECT, [operationId, transactionAttemptNo]);
  const attemptRow = returned[0];
  if (attemptRow === undefined) {
    return { status: "CLAIMED_UNRETURNED", transportOutcome: null };
  }
  return {
    status: "RETURNED",
    transportOutcome: attemptRow.transport_outcome as SubmitTransportOutcome,
  };
}

// Classifies durable evidence into the closed reconcile-indeterminate vocabulary
// (protocol/reconcile/types.ts), or null when the evidence carries no ambiguity. Two states
// are ambiguous: CLAIMED_UNRETURNED (the claim survived a crash, but the gateway exchange it
// authorized never returned — reconcile by receiver observation) and RETURNED with
// an INDETERMINATE transport_outcome (the exchange DID return, but ambiguously — the same
// state move-submit-claim.ts's live/synchronous path already collapses into its own AMBIGUOUS
// status, so a crash-recovered read agrees with what the original caller would have seen).
// NOT_CLAIMED, and RETURNED with a definite ACK/REJECT outcome, are not ambiguous: nothing was
// ever attempted, or a definite transport result already exists.
//
// Return type is deliberately ReconcileIndeterminateReason | null — never a submit-authority
// token. An INDETERMINATE/INVARIANT_BREACH read cannot authorize a new gateway_submit_attempts
// insert at the type level; the database's UNIQUE (operation_id, transaction_attempt_no) makes
// a second insert unrepresentable even if a caller ignored the type (the never-blind-retry rule).
export function classifySubmitAttemptEvidence(
  evidence: SubmitAttemptEvidence,
): ReconcileIndeterminateReason | null {
  if (evidence.status === "CLAIMED_UNRETURNED") {
    return { source: "SUBMIT_OUTCOME_UNKNOWN" };
  }
  if (evidence.status === "RETURNED" && evidence.transportOutcome === "INDETERMINATE") {
    return { source: "SUBMIT_OUTCOME_UNKNOWN" };
  }
  return null;
}


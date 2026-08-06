// Guarded pre-signing decisions on a SEND_EXTERNAL operation: the operator's pre-approval
// reject, and the commit half of approval. Both are the same shape — a compare-and-swap that
// may only fire while the operation is still CREATED — and that shared CAS is what makes the
// two mutually exclusive under contention.
//
// POST /admin/v1/external-sends/:operation_id/reject: the operator may reject CREATED —
// there is no source lease and no SplitChain attempt. CREATED→REJECTED is operator audit
// only, with no public event; it is a guarded mutation resolved by CAS, and the crash
// matrix applies.
//
// The arbiter is the database, never an application read. There is deliberately no
// SELECT-then-UPDATE anywhere below: a read that decides whether the UPDATE may proceed is a
// TOCTOU gap exactly wide enough for a concurrent approve to slip through a reject's guard.
// The single statement carries all three guards — identity, state and row_version — so a
// loser affects zero rows and learns nothing, while the winner's row_version advance makes
// every other in-flight decision stale by construction.
//
// The four economic fields are NOT restated here. src/schema/send-external-create.sql's
// send_operations_immutable_fields_guard trigger rejects any attempt to move source,
// destination, amount or reference, so no decision path — including a future one — can carry
// an economic change through on the back of a state transition.
//
// Scope: this module owns the guarded transition and nothing else. The factors that must
// precede it at the admin HTTP surface — CSRF, X-ZP-TOTP freshness and single-use, the
// approval challenge, request idempotency and the operator audit row — belong to and
// the admin transport, and are recorded as open obligations in
// test/crash-replay-obligations.ts rather than modelled here.

import type { SqlExecutor } from "./sql-store.js";

export const SEND_REJECT_ROUTE = "/admin/v1/external-sends/:operation_id/reject" as const;

// A guarded mutation that did not apply is one 409-class conflict.
// Unknown operation, wrong state and stale row_version are deliberately indistinguishable —
// Forbids an error that reveals which factor failed, and the operator's correct
// response to all three is identical: re-read the operation and observe its current state.
export const SEND_DECISION_CONFLICT_CODE = "operation_conflict" as const;
export const SEND_DECISION_CONFLICT_HTTP_STATUS = 409;

export interface SendDecisionCommand {
  readonly operationId: string;
  readonly expectedRowVersion: number;
}

export type SendDecisionOutcome =
  | { readonly outcome: "APPLIED"; readonly status: "APPROVED" | "REJECTED"; readonly rowVersion: number }
  | {
      readonly outcome: "CONFLICT";
      readonly code: typeof SEND_DECISION_CONFLICT_CODE;
      readonly httpStatus: typeof SEND_DECISION_CONFLICT_HTTP_STATUS;
    };

// One conflict value, constructed once, so no call site can accidentally enrich it with the
// reason it failed.
export const SEND_DECISION_CONFLICT: SendDecisionOutcome = Object.freeze({
  outcome: "CONFLICT",
  code: SEND_DECISION_CONFLICT_CODE,
  httpStatus: SEND_DECISION_CONFLICT_HTTP_STATUS,
});

// Both statements are literal text — no branch, no interpolation, no dynamic status. Each
// guards on operation_id AND status = 'CREATED' AND row_version = $2 and advances
// row_version, so a decision that raced a committed sibling matches zero rows.
//
// REJECT_CREATED leaves formation_state alone: pairs APPROVAL_PENDING with
// CREATED only, and REJECTED is terminal with no formation of its own to record.
// APPROVE_CREATED advances it to APPROVED_UNSIGNED in the same statement, so an APPROVED row
// can never be observed still carrying the pre-approval formation state.
export const DECISION_STATEMENTS = {
  REJECT_CREATED:
    "UPDATE send_operations SET status = 'REJECTED', row_version = row_version + 1 " +
    "WHERE operation_id = $1 AND status = 'CREATED' AND row_version = $2 " +
    "RETURNING operation_id, status, row_version",
  APPROVE_CREATED:
    "UPDATE send_operations SET status = 'APPROVED', formation_state = 'APPROVED_UNSIGNED', " +
    "row_version = row_version + 1 " +
    "WHERE operation_id = $1 AND status = 'CREATED' AND row_version = $2 " +
    "RETURNING operation_id, status, row_version",
} as const;

export interface SendDecisionStore {
  // Applies the CREATED→REJECTED transition. Returns the new row_version, or null when the
  // guard matched no row. MUST NOT pre-read to decide the outcome.
  rejectCreated(command: SendDecisionCommand): Promise<number | null>;
  // Applies the CREATED→APPROVED commit. Same contract; the approval factors that authorize
  // it are verified by the caller before this is reached.
  approveCreated(command: SendDecisionCommand): Promise<number | null>;
}

interface DecisionRow {
  readonly operation_id: string;
  readonly status: string;
  readonly row_version: string | number;
}

export class SqlSendDecisionStore implements SendDecisionStore {
  constructor(private readonly sql: SqlExecutor) {}

  private async apply(statement: string, command: SendDecisionCommand): Promise<number | null> {
    const result = await this.sql.query<DecisionRow>(statement, [
      command.operationId,
      command.expectedRowVersion,
    ]);
    const row = result.rows[0];
    return row === undefined ? null : Number(row.row_version);
  }

  async rejectCreated(command: SendDecisionCommand): Promise<number | null> {
    return this.apply(DECISION_STATEMENTS.REJECT_CREATED, command);
  }

  async approveCreated(command: SendDecisionCommand): Promise<number | null> {
    return this.apply(DECISION_STATEMENTS.APPROVE_CREATED, command);
  }
}

// Reject is available only before any approval, holds no source lease and
// makes no SplitChain attempt. Both properties are structural rather than asserted here — the
// status = 'CREATED' guard is the only way this statement can apply, and acquires no
// lease before approval, so there is nothing for this path to release.
export async function rejectSendOperation(
  command: SendDecisionCommand,
  store: SendDecisionStore,
): Promise<SendDecisionOutcome> {
  const rowVersion = await store.rejectCreated(command);
  if (rowVersion === null) return SEND_DECISION_CONFLICT;
  return { outcome: "APPLIED", status: "REJECTED", rowVersion };
}

// The commit half of approval. It is here, beside reject, because the two share
// one arbiter: whichever of them commits first advances row_version and leaves the other
// matching no row. Splitting them across modules would leave that mutual exclusion implicit.
export async function commitSendApproval(
  command: SendDecisionCommand,
  store: SendDecisionStore,
): Promise<SendDecisionOutcome> {
  const rowVersion = await store.approveCreated(command);
  if (rowVersion === null) return SEND_DECISION_CONFLICT;
  return { outcome: "APPLIED", status: "APPROVED", rowVersion };
}

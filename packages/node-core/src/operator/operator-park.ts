// Operator-initiated park of an operation into attention (OPERATOR_PARKED).
//
// Distinct from attention-retraction (clears a false-positive flag) and from the
// nine recovery-actions (each answers "the flag was real; do X"). Park answers
// "an operator deliberately held this operation pending investigation" and is the
// production setter for OPERATOR_PARKED (ZTR-1147 / Appendix B §4).

import { toAttentionReason } from "../protocol/reconcile/types.js";

/** Closed vocabulary value written for every operator park. */
export const OPERATOR_PARK_ATTENTION_REASON = toAttentionReason({
  source: "OPERATOR_PARKED",
});

export interface OperatorParkInput {
  readonly operationId: string;
  readonly expectedRowVersion: number;
  /** Free-text operator note — stored in attention_detail, never in attention_reason. */
  readonly note: string;
  readonly actorId: string;
  /** Must be the literal true from the operator_session_totp chain. */
  readonly csrfValidated: true;
}

export interface OperatorParkCommitted {
  readonly operationId: string;
  readonly attentionReason: typeof OPERATOR_PARK_ATTENTION_REASON;
  readonly rowVersion: number;
  readonly parkedAt: string;
}

export type OperatorParkOutcome =
  | { readonly status: "ok"; readonly body: OperatorParkCommitted }
  | {
      readonly status: "rejected";
      readonly reason:
        | "csrf_required"
        | "operation_not_found"
        | "conflict"
        | "already_flagged"
        | "note_required";
    };

export interface OperatorParkStore {
  /**
   * CAS: set attention_required + OPERATOR_PARKED when currently unflagged and
   * row_version matches. Append audit_log. Must run under one transaction.
   */
  commitPark(input: {
    readonly operationId: string;
    readonly expectedRowVersion: number;
    readonly note: string;
    readonly actorId: string;
    readonly attentionReason: typeof OPERATOR_PARK_ATTENTION_REASON;
  }): Promise<
    | { readonly kind: "committed"; readonly committed: OperatorParkCommitted }
    | { readonly kind: "not_found" }
    | { readonly kind: "conflict" }
    | { readonly kind: "already_flagged" }
  >;
}

export async function executeOperatorPark(
  store: OperatorParkStore,
  input: OperatorParkInput,
): Promise<OperatorParkOutcome> {
  if (input.csrfValidated !== true) {
    return { status: "rejected", reason: "csrf_required" };
  }
  const note = input.note.trim();
  if (note.length === 0) {
    return { status: "rejected", reason: "note_required" };
  }
  const result = await store.commitPark({
    operationId: input.operationId,
    expectedRowVersion: input.expectedRowVersion,
    note,
    actorId: input.actorId,
    attentionReason: OPERATOR_PARK_ATTENTION_REASON,
  });
  if (result.kind === "committed") {
    return { status: "ok", body: result.committed };
  }
  if (result.kind === "not_found") {
    return { status: "rejected", reason: "operation_not_found" };
  }
  if (result.kind === "already_flagged") {
    return { status: "rejected", reason: "already_flagged" };
  }
  return { status: "rejected", reason: "conflict" };
}

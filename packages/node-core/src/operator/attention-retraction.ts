// audited operator retraction of a false-positive attention_required flag.
//
// attention_required and attention_reason are governed by a co-presence CHECK. A sticky
// NEEDS_ATTENTION raised by a transient flaky read is human-gated: only an operator clears
// it, and the clear is audited.
//
// Retraction is deliberately NOT a 10th entry in the closed OPERATOR_RECOVERY_ACTIONS
// set (recovery-actions.ts): every existing action there answers "the operation
// really did need attention; do X about it." Retraction answers a different question —
// "the classifier that raised this was wrong; the operation never needed attention in
// the first place" — and ACKNOWLEDGE_KEEP_PINNED deliberately never clears
// attention_required (it keeps the wallet pinned because the flag was correct). Folding
// retraction into that switch would blur exactly the distinction requires:
// a retraction record must never read like an acknowledgement of a real problem.
//
// Provenance: the store must copy the pre-retraction attention_reason into the
// audit_log details_text (immutable, append-only per audit-log.sql triggers) before
// clearing it from the operations row, alongside the operator's stated retraction
// reason, actor id and timestamp — the operations row itself is ordinary mutable
// state (attention_reason already clears on ordinary resolution elsewhere, e.g.
// receive/expiry-release.ts SET_RELEASE_STATUS), so the durable "why was this ever
// flagged" record lives in the append-only audit trail, not in a frozen live column.
//
// Boot recovery never calls this path: sql-boot-recovery.ts only ever
// raises attention_required (SET attention_required = true), never clears it, so a
// retraction survives every reboot until an operator explicitly acts again. If the
// same classifier defect resurfaces, the normal raise path re-flags the operation and
// a fresh, separately-audited retraction is required — append-only, not a toggle.

export interface AttentionRetractionRequest {
  readonly operationId: string;
  /** Operator's required, non-empty rationale for why this never needed attention. */
  readonly reason: string;
  /** Optional pointer to the classifier fix that proves the flag was wrong. */
  readonly supersededBy: string | null;
  readonly expectedRowVersion: number;
  /** Operator principal from the session (audit attribution). */
  readonly actorId: string;
  /** CSRF already validated by the admin mutation chain (defence in depth). */
  readonly csrfValidated: true;
}

export type AttentionRetractionRejectReason =
  | "csrf_required"
  | "operation_not_found"
  | "not_flagged"
  | "conflict";

export interface AttentionRetractionSuccessBody {
  readonly operation_id: string;
  readonly row_version: number;
  readonly retracted_at: string;
  readonly prior_attention_reason: string;
}

export type AttentionRetractionOutcome =
  | { readonly status: "ok"; readonly body: AttentionRetractionSuccessBody }
  | {
      readonly status: "rejected";
      readonly reason: AttentionRetractionRejectReason;
      readonly detail?: string;
    };

export type AttentionRetractionCommitResult =
  | {
      readonly ok: true;
      readonly rowVersion: number;
      readonly retractedAt: string;
      readonly priorAttentionReason: string;
    }
  | {
      readonly ok: false;
      readonly reason: Extract<
        AttentionRetractionRejectReason,
        "operation_not_found" | "not_flagged" | "conflict"
      >;
    };

/**
 * Persistence port. The store owns the SQL: lock the row, verify attention is
 * currently raised, CAS-clear attention_required/attention_reason on the expected
 * row_version, and append an audit_log row that preserves the original reason plus
 * the operator's rationale. Handlers never open SQL directly (mirrors
 * RecoveryActionStore's boundary in recovery-actions.ts).
 */
export interface AttentionRetractionStore {
  commit(input: {
    readonly operationId: string;
    readonly reason: string;
    readonly supersededBy: string | null;
    readonly expectedRowVersion: number;
    readonly actorId: string;
  }): Promise<AttentionRetractionCommitResult>;
}

/**
 * Full retraction path: CSRF gate, delegate the CAS + audit to the store, map the
 * result. No effect-planning switch here (ponytail: retraction has exactly one
 * effect, unlike the nine-way recovery-actions catalog, so there is nothing to plan).
 */
export async function executeAttentionRetraction(
  store: AttentionRetractionStore,
  request: AttentionRetractionRequest,
): Promise<AttentionRetractionOutcome> {
  if (request.csrfValidated !== true) {
    return { status: "rejected", reason: "csrf_required" };
  }

  const committed = await store.commit({
    operationId: request.operationId,
    reason: request.reason,
    supersededBy: request.supersededBy,
    expectedRowVersion: request.expectedRowVersion,
    actorId: request.actorId,
  });

  if (!committed.ok) {
    return { status: "rejected", reason: committed.reason };
  }

  return {
    status: "ok",
    body: {
      operation_id: request.operationId,
      row_version: committed.rowVersion,
      retracted_at: committed.retractedAt,
      prior_attention_reason: committed.priorAttentionReason,
    },
  };
}

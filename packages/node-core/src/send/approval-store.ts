// In-memory ApprovalChallengeStore for Layer-1 unit tests, and SQL statement catalogue
// for the durable Postgres adapter (The durable-schema slice composition root).
//
// Mirrors the structural UNIQUE constraints of approval-stores.sql:
// - at most one ISSUED challenge per operation
// - unique challenge nonce
// - at most one approval per operation / per challenge
// - unique (node_id, totp_timestep) ← the TOTP single-use arbiter
//
// Step 7 / step 6: consume + approval insert + CREATED→APPROVED CAS
// are one all-or-nothing unit. The in-memory store snapshots and restores on any
// failure inside the mutation; the SQL catalogue is a single atomic statement (CTE)
// so a CAS miss never leaves CONSUMED/burned/orphan approval durable state.
// Step 8 ("never restore the timestep if signing… later fails") applies only
// AFTER this mutation commits — not to a CAS miss inside the mutation itself.

import {
  ApprovalStoreUniqueViolation,
  type ApprovalChallenge,
  type ApprovalChallengeStore,
  type CommitApprovalMutationResult,
  type OperationApproval,
  type UniqueViolationKind,
} from "./approve.js";
import { DECISION_STATEMENTS } from "./decide.js";

interface OpDecisionState {
  status: string;
  rowVersion: number;
}

interface StoreSnapshot {
  readonly challenges: ReadonlyArray<readonly [string, ApprovalChallenge]>;
  readonly approvals: ReadonlyArray<readonly [string, OperationApproval]>;
  readonly totpTimesteps: readonly string[];
  readonly ops: ReadonlyArray<readonly [string, OpDecisionState]>;
}

export class InMemoryApprovalChallengeStore implements ApprovalChallengeStore {
  private readonly byId = new Map<string, ApprovalChallenge>();
  private readonly byNonce = new Map<string, ApprovalChallenge>();
  private readonly approvalsById = new Map<string, OperationApproval>();
  private readonly approvalsByOperation = new Map<string, OperationApproval>();
  private readonly approvalsByChallenge = new Map<string, OperationApproval>();
  private readonly totpTimesteps = new Set<string>();
  /** Operation status/row_version owned by this store so CAS joins the same unit. */
  private readonly ops = new Map<string, OpDecisionState>();
  /** Serialises commitApprovalMutation to model single-TX isolation under concurrency. */
  private mutationTail: Promise<void> = Promise.resolve();
  /** Test hook: next commitApprovalMutation CAS returns OPERATION_CONFLICT and rolls back. */
  failNextApproveCas = false;

  private totpKey(nodeId: string, timestep: number): string {
    return `${nodeId}:${timestep}`;
  }

  seedOperation(operationId: string, status: string, rowVersion: number): void {
    this.ops.set(operationId, { status, rowVersion });
  }

  getOperationState(operationId: string): OpDecisionState | null {
    const op = this.ops.get(operationId);
    return op === undefined ? null : { status: op.status, rowVersion: op.rowVersion };
  }

  private snapshot(): StoreSnapshot {
    return {
      challenges: [...this.byId.entries()].map(([k, v]) => [k, { ...v }] as const),
      approvals: [...this.approvalsById.entries()].map(([k, v]) => [k, { ...v }] as const),
      totpTimesteps: [...this.totpTimesteps],
      ops: [...this.ops.entries()].map(([k, v]) => [k, { ...v }] as const),
    };
  }

  private restore(snap: StoreSnapshot): void {
    this.byId.clear();
    this.byNonce.clear();
    for (const [, c] of snap.challenges) {
      this.byId.set(c.id, { ...c });
      this.byNonce.set(c.nonce, { ...c });
    }
    this.approvalsById.clear();
    this.approvalsByOperation.clear();
    this.approvalsByChallenge.clear();
    for (const [, a] of snap.approvals) {
      this.approvalsById.set(a.id, { ...a });
      this.approvalsByOperation.set(a.operationId, { ...a });
      this.approvalsByChallenge.set(a.challengeId, { ...a });
    }
    this.totpTimesteps.clear();
    for (const t of snap.totpTimesteps) this.totpTimesteps.add(t);
    this.ops.clear();
    for (const [id, st] of snap.ops) this.ops.set(id, { ...st });
  }

  async findIssuedByOperation(operationId: string): Promise<ApprovalChallenge | null> {
    for (const c of this.byId.values()) {
      if (c.operationId === operationId && c.status === "ISSUED") return c;
    }
    return null;
  }

  async findByNonce(nonce: string): Promise<ApprovalChallenge | null> {
    return this.byNonce.get(nonce) ?? null;
  }

  getApproval(operationId: string): OperationApproval | null {
    return this.approvalsByOperation.get(operationId) ?? null;
  }

  isTimestepBurned(nodeId: string, timestep: number): boolean {
    return this.totpTimesteps.has(this.totpKey(nodeId, timestep));
  }

  async insertIssued(challenge: ApprovalChallenge, supersedeId: string | null): Promise<void> {
    if (this.byId.has(challenge.id)) {
      throw new ApprovalStoreUniqueViolation("unknown");
    }
    if (this.byNonce.has(challenge.nonce)) {
      throw new ApprovalStoreUniqueViolation("challenge_nonce");
    }
    if (supersedeId !== null) {
      const prior = this.byId.get(supersedeId);
      if (prior === undefined) {
        throw new Error(`unknown challenge to supersede: ${supersedeId}`);
      }
      if (prior.status !== "ISSUED" || prior.operationId !== challenge.operationId) {
        throw new Error(`cannot supersede non-ISSUED or foreign challenge: ${supersedeId}`);
      }
      const superseded: ApprovalChallenge = {
        ...prior,
        status: "SUPERSEDED",
        supersededBy: challenge.id,
      };
      this.byId.set(prior.id, superseded);
      this.byNonce.set(prior.nonce, superseded);
    } else {
      const existing = await this.findIssuedByOperation(challenge.operationId);
      if (existing !== null) {
        throw new ApprovalStoreUniqueViolation("challenge_one_issued");
      }
    }
    const stillIssued = await this.findIssuedByOperation(challenge.operationId);
    if (stillIssued !== null) {
      throw new ApprovalStoreUniqueViolation("challenge_one_issued");
    }
    this.byId.set(challenge.id, challenge);
    this.byNonce.set(challenge.nonce, challenge);
  }

  /**
   * All-or-nothing approval mutation (step 6 / step 7):
   * claim TOTP timestep + consume challenge + insert operation_approvals + CREATED→APPROVED CAS.
   * Serialised so concurrent callers observe committed state only.
   */
  async commitApprovalMutation(
    challengeId: string,
    approval: OperationApproval,
    expectedRowVersion: number,
  ): Promise<CommitApprovalMutationResult> {
    const run = this.mutationTail.then(() => this.commitApprovalMutationUnlocked(
      challengeId,
      approval,
      expectedRowVersion,
    ));
    // Keep the chain alive even when the mutation rejects — callers await `run` itself.
    this.mutationTail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  private commitApprovalMutationUnlocked(
    challengeId: string,
    approval: OperationApproval,
    expectedRowVersion: number,
  ): CommitApprovalMutationResult {
    const snap = this.snapshot();

    const challenge = this.byId.get(challengeId);
    if (challenge === undefined || challenge.status !== "ISSUED") {
      return { kind: "CHALLENGE_NOT_ISSUED" };
    }
    if (challenge.operationId !== approval.operationId || challenge.nodeId !== approval.nodeId) {
      return { kind: "CHALLENGE_NOT_ISSUED" };
    }
    if (this.approvalsByOperation.has(approval.operationId)) {
      return { kind: "APPROVAL_EXISTS" };
    }
    if (this.approvalsByChallenge.has(approval.challengeId)) {
      return { kind: "APPROVAL_EXISTS" };
    }
    const tk = this.totpKey(approval.nodeId, approval.totpTimestep);
    if (this.totpTimesteps.has(tk)) {
      return { kind: "TOTP_REPLAY" };
    }

    // Apply mutation into working state; restore snap on any terminal non-APPLIED path
    // that must not leave partial durable evidence.
    this.totpTimesteps.add(tk);

    const consumed: ApprovalChallenge = {
      ...challenge,
      status: "CONSUMED",
      supersededBy: null,
    };
    this.byId.set(challenge.id, consumed);
    this.byNonce.set(challenge.nonce, consumed);
    this.approvalsById.set(approval.id, approval);
    this.approvalsByOperation.set(approval.operationId, approval);
    this.approvalsByChallenge.set(approval.challengeId, approval);

    if (this.failNextApproveCas) {
      this.failNextApproveCas = false;
      this.restore(snap);
      return { kind: "OPERATION_CONFLICT" };
    }

    const op = this.ops.get(approval.operationId);
    if (op === undefined || op.status !== "CREATED" || op.rowVersion !== expectedRowVersion) {
      this.restore(snap);
      return { kind: "OPERATION_CONFLICT" };
    }
    op.status = "APPROVED";
    op.rowVersion += 1;
    return { kind: "APPLIED", rowVersion: op.rowVersion };
  }
}

/**
 * Single-statement atomic approve mutation for Postgres.
 * CAS first (so a miss touches nothing); consume + insert only when the op row advanced.
 * Unique violations on operation_approvals abort the whole statement (timestep not burned).
 *
 * Params:
 * $1 challenge_id
 * $2 approval_id
 * $3 method
 * $4 preimage_text
 * $5 preimage_sha256
 * $6 device_key_id
 * $7 device_signature
 * $8 totp_timestep
 * $9 consumed_at
 * $10 expected row_version
 * $11 operation_id (must match challenge.operation_id; extra guard)
 */
export const APPROVAL_SQL = {
  SELECT_ISSUED_BY_OPERATION:
    "SELECT id, node_id, operation_id, status, purpose, canonical_version, nonce, " +
    "preimage_text, preimage_sha256, issued_at, expires_at, superseded_by " +
    "FROM approval_challenges WHERE operation_id = $1 AND status = 'ISSUED'",

  SELECT_BY_NONCE:
    "SELECT id, node_id, operation_id, status, purpose, canonical_version, nonce, " +
    "preimage_text, preimage_sha256, issued_at, expires_at, superseded_by " +
    "FROM approval_challenges WHERE nonce = $1",

  INSERT_ISSUED_WITH_SUPERSEDE:
    "WITH superseded AS (" +
    "  UPDATE approval_challenges SET status = 'SUPERSEDED', superseded_by = $1 " +
    "  WHERE id = $2 AND status = 'ISSUED' RETURNING id" +
    ") INSERT INTO approval_challenges (" +
    "  id, node_id, operation_id, status, purpose, canonical_version, nonce, " +
    "  preimage_text, preimage_sha256, issued_at, expires_at, superseded_by" +
    ") VALUES (" +
    "  $1, $3, $4, 'ISSUED', 'zp-send-external-approval-v1', 1, $5, " +
    "  $6, $7, $8::timestamptz, $9::timestamptz, NULL" +
    ") RETURNING id",

  INSERT_ISSUED_FRESH:
    "INSERT INTO approval_challenges (" +
    "  id, node_id, operation_id, status, purpose, canonical_version, nonce, " +
    "  preimage_text, preimage_sha256, issued_at, expires_at, superseded_by" +
    ") VALUES (" +
    "  $1, $2, $3, 'ISSUED', 'zp-send-external-approval-v1', 1, $4, " +
    "  $5, $6, $7::timestamptz, $8::timestamptz, NULL" +
    ") RETURNING id",

  /**
   * Atomic step 6–7 / step 6 unit.
   * Empty result set = CAS miss or challenge not ISSUED (caller maps to conflict / not issued).
   * Unique violation on insert → whole statement aborted (no orphan).
   */
  COMMIT_APPROVAL_MUTATION:
    "WITH ch AS (" +
    "  SELECT id, node_id, operation_id FROM approval_challenges " +
    "  WHERE id = $1 AND status = 'ISSUED' AND operation_id = $11 " +
    "  FOR UPDATE" +
    "), approved AS (" +
    "  UPDATE send_operations s SET status = 'APPROVED', " +
    "    formation_state = 'APPROVED_UNSIGNED', row_version = row_version + 1 " +
    "  FROM ch " +
    "  WHERE s.operation_id = ch.operation_id AND s.status = 'CREATED' " +
    "    AND s.row_version = $10 " +
    "  RETURNING s.operation_id, s.row_version, ch.id AS challenge_id, ch.node_id" +
    "), consumed AS (" +
    "  UPDATE approval_challenges c SET status = 'CONSUMED' " +
    "  FROM approved a " +
    "  WHERE c.id = a.challenge_id AND c.status = 'ISSUED' " +
    "  RETURNING c.id, c.node_id, c.operation_id" +
    "), inserted AS (" +
    "  INSERT INTO operation_approvals (" +
    "    id, node_id, operation_id, challenge_id, challenge_status, method, purpose, " +
    "    canonical_version, preimage_text, preimage_sha256, device_key_id, device_signature, " +
    "    totp_timestep, consumed_at" +
    "  ) SELECT " +
    "    $2, c.node_id, c.operation_id, c.id, 'CONSUMED', $3, 'zp-send-external-approval-v1', " +
    "    1, $4, $5, $6, $7, $8, $9::timestamptz " +
    "  FROM consumed c " +
    "  RETURNING id, operation_id" +
    ") SELECT i.id AS approval_id, a.row_version " +
    "FROM inserted i JOIN approved a ON a.operation_id = i.operation_id",

  /** @deprecated Prefer COMMIT_APPROVAL_MUTATION — kept only as a named fragment reference. */
  CONSUME_AND_INSERT_APPROVAL:
    "WITH consumed AS (" +
    "  UPDATE approval_challenges SET status = 'CONSUMED' " +
    "  WHERE id = $1 AND status = 'ISSUED' RETURNING id, node_id, operation_id" +
    ") INSERT INTO operation_approvals (" +
    "  id, node_id, operation_id, challenge_id, challenge_status, method, purpose, " +
    "  canonical_version, preimage_text, preimage_sha256, device_key_id, device_signature, " +
    "  totp_timestep, consumed_at" +
    ") SELECT " +
    "  $2, c.node_id, c.operation_id, c.id, 'CONSUMED', $3, 'zp-send-external-approval-v1', " +
    "  1, $4, $5, $6, $7, $8, $9::timestamptz " +
    "FROM consumed c RETURNING id",

  /** Same CAS text as decide.ts — included so the catalogue is self-contained for adapters. */
  APPROVE_CREATED: DECISION_STATEMENTS.APPROVE_CREATED,
} as const;

export function mapApprovalUniqueViolation(constraint: string | undefined): UniqueViolationKind {
  if (constraint === "approval_challenges_one_issued_per_operation") return "challenge_one_issued";
  if (constraint === "operation_approvals_totp_single_use") return "totp_timestep";
  if (constraint?.includes("nonce")) return "challenge_nonce";
  if (constraint?.includes("totp")) return "totp_timestep";
  if (constraint?.includes("operation_id")) return "approval_operation";
  if (constraint?.includes("challenge_id")) return "approval_challenge";
  return "unknown";
}

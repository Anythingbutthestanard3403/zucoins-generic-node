// fail-closed anomaly quarantine actions (node-action column).
//
// Anomalies authorize no landing, no non-landing, no retry/rebuild/resubmit, and no
// lease/reuse release.
//
// This slice is the side-effecting action layer invoked after the classifier reports an
// anomalous relationship (or after a non-classifier anomaly is detected upstream). It does NOT:
// - write observation_anomalies (the capture transaction owns that append);
// - promote an ordinary head (only SUCCESSOR does);
// - release a lease, delete evidence, rewrite a verdict, or reverse a historic LANDED fact.
//
// Wallet quarantine is structural: wallets.state='QUARANTINED' with quarantine_reason set
// (enforced by a CHECK). Lease acquisition rejects QUARANTINED/RETIRED; this module sets that state.
// An active lease on a wallet that is quarantined mid-operation is preserved (closing
// rule: never free a possible in-flight wallet without a fresh read).

import type { OperationKind } from "@zucoins/generic-node-contracts/operations";
import type { AttentionReason } from "@zucoins/generic-node-contracts/operations/events";
import type { ClassifierOutputRelationship } from "@zucoins/generic-node-contracts/observation";

import { isAnomalousRelationship } from "./classifier.js";

// ── anomaly vocabulary (node-action column) ──────────────────────────

/**
 * Full anomaly kinds this action layer handles. Classifier anomalies are a
 * subset; the remaining rows cover transport/malformed/signature/role/disagreement
 * paths that reach this layer from capture/verify without a relationship.
 */
export const OBS15_ANOMALY_KINDS = [
  "TRANSPORT_READ_FAILURE",
  "MALFORMED_ENVELOPE",
  "INVALID_STEP_SIGNATURE",
  "WALLET_ROLE_INVALID",
  "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
  "SIGNATURE_COLLISION",
  "GENESIS_AFTER_HISTORY",
  "REGRESSION",
  "UNEXPLAINED_JUMP",
  "NODE_PLATFORM_DISAGREEMENT",
  "GATEWAY_ENDPOINT_DISAGREEMENT",
] as const;

export type Obs15AnomalyKind = (typeof OBS15_ANOMALY_KINDS)[number];

/** Classifier outputs that must fire quarantine / NEEDS_ATTENTION (→ this slice). */
export const CLASSIFIER_ANOMALY_KINDS = [
  "SIGNATURE_COLLISION",
  "GENESIS_AFTER_HISTORY",
  "REGRESSION",
  "UNEXPLAINED_JUMP",
] as const satisfies readonly Obs15AnomalyKind[];

export type ClassifierAnomalyKind = (typeof CLASSIFIER_ANOMALY_KINDS)[number];

export type WalletState = "AVAILABLE" | "PINNED" | "QUARANTINED" | "RETIRED";

/** Closed set of operator-facing audit action names appended for every plan application. */
export const QUARANTINE_AUDIT_ACTIONS = [
  "anomaly.bounded_retry_keep_lease",
  "anomaly.retain_raw_alert_no_sign",
  "anomaly.quarantine_candidate_no_cosign",
  "anomaly.refuse_operation_acceptance",
  "anomaly.retain_no_head_promotion",
  "anomaly.quarantine_wallet_halt_signing",
  "anomaly.needs_attention",
  "anomaly.hold_verification_barrier",
  "anomaly.halt_wallet_operation",
  "anomaly.no_op_non_anomalous",
] as const;

export type QuarantineAuditAction = (typeof QUARANTINE_AUDIT_ACTIONS)[number];

// ── Pure plan ────────────────────────────────────────────────────────────────

export interface AnomalyActionInvariants {
  /** Closing rule / landing-path oracle — never free an in-flight wallet without a fresh read. */
  readonly neverReleaseLease: true;
  /** Evidence rows are append-only; this slice never deletes or edits them. */
  readonly neverDeleteEvidence: true;
  /** Prior verification verdicts are immutable. */
  readonly neverRewriteVerdict: true;
  /** Historic terminal (LANDED) operation rows are never mutated by a later anomaly. */
  readonly neverMutateTerminalHistoricOp: true;
  /** Anomalies authorize no landing (landing-path oracle). */
  readonly grantsLandingAuthority: false;
  /** Anomalies authorize no retry/rebuild/resubmit. */
  readonly grantsRetryAuthority: false;
  /** Only SUCCESSOR establishes an ordinary head; anomalies never do. */
  readonly grantsHeadPromotion: false;
}

export const ANOMALY_ACTION_INVARIANTS: AnomalyActionInvariants = {
  neverReleaseLease: true,
  neverDeleteEvidence: true,
  neverRewriteVerdict: true,
  neverMutateTerminalHistoricOp: true,
  grantsLandingAuthority: false,
  grantsRetryAuthority: false,
  grantsHeadPromotion: false,
};

export type WalletPlanEffect =
  | { readonly kind: "none" }
  | {
      readonly kind: "quarantine";
      readonly quarantineReason: string;
      readonly haltSigning: true;
      readonly preserveLease: true;
    }
  | {
      /** Reject this candidate only — wallet stays AVAILABLE/PINNED. */
      readonly kind: "quarantine_candidate";
      readonly quarantineReason: string;
      readonly haltSigning: false;
      readonly preserveLease: true;
    }
  | {
      readonly kind: "halt_signing";
      readonly haltSigning: true;
      readonly preserveLease: true;
    };

export type OperationPlanEffect =
  | { readonly kind: "none" }
  | {
      readonly kind: "needs_attention";
      readonly attentionReason: AttentionReason;
      readonly targetStatus: "NEEDS_ATTENTION";
      readonly emitEvent: "operation.needs_attention";
    }
  | { readonly kind: "keep_verification_pending" }
  | { readonly kind: "refuse_acceptance" }
  | { readonly kind: "hold_verification_barrier" };

export interface AnomalyActionPlan {
  readonly anomaly: Obs15AnomalyKind;
  readonly nodeActionSummary: string;
  readonly wallet: WalletPlanEffect;
  readonly operation: OperationPlanEffect;
  readonly auditAction: QuarantineAuditAction;
  readonly invariants: AnomalyActionInvariants;
  /**
   * True when the plan blocks co-sign/settle for this anomaly episode.
   * Wallet-level halt is only when `wallet.kind` is `quarantine` or `halt_signing`;
   * `refuse_acceptance` / `needs_attention` also set this without flipping wallets.state.
   */
  readonly signingHalted: boolean;
  /** True when the plan requires wallets.state → QUARANTINED (full wallet quarantine only). */
  readonly walletQuarantined: boolean;
}

export interface PlanAnomalyActionInput {
  readonly anomaly: Obs15AnomalyKind;
  /**
   * Optional override for UNEXPLAINED_JUMP attention_reason. Defaults to
   * UNEXPECTED_HEAD_CHANGE (F1.1). LINEAGE_GAP is permitted when the
   * caller has already classified the jump as a gap rather than a head change.
   */
  readonly unexplainedJumpAttentionReason?: Extract<
    AttentionReason,
    "UNEXPECTED_HEAD_CHANGE" | "LINEAGE_GAP"
  >;
}

function quarantineWallet(reason: string): WalletPlanEffect {
  return {
    kind: "quarantine",
    quarantineReason: reason,
    haltSigning: true,
    preserveLease: true,
  };
}

function quarantineCandidate(reason: string): WalletPlanEffect {
  return {
    kind: "quarantine_candidate",
    quarantineReason: reason,
    haltSigning: false,
    preserveLease: true,
  };
}

function needsAttention(reason: AttentionReason): OperationPlanEffect {
  return {
    kind: "needs_attention",
    attentionReason: reason,
    targetStatus: "NEEDS_ATTENTION",
    emitEvent: "operation.needs_attention",
  };
}

/**
 * Pure node-action planner. Total over every anomaly kind. Never grants
 * landing/retry/head-promotion authority. Does not perform I/O.
 */
export function planAnomalyAction(input: PlanAnomalyActionInput): AnomalyActionPlan {
  const jumpReason = input.unexplainedJumpAttentionReason ?? "UNEXPECTED_HEAD_CHANGE";

  switch (input.anomaly) {
    case "TRANSPORT_READ_FAILURE":
      return finalize({
        anomaly: input.anomaly,
        nodeActionSummary: "bounded read-only retry; keep lease",
        wallet: { kind: "none" },
        operation: { kind: "keep_verification_pending" },
        auditAction: "anomaly.bounded_retry_keep_lease",
      });

    case "MALFORMED_ENVELOPE":
      return finalize({
        anomaly: input.anomaly,
        nodeActionSummary: "retain raw bytes; alert; no sign/settle/retry",
        wallet: { kind: "none" },
        operation: { kind: "refuse_acceptance" },
        auditAction: "anomaly.retain_raw_alert_no_sign",
      });

    case "INVALID_STEP_SIGNATURE":
      return finalize({
        anomaly: input.anomaly,
        nodeActionSummary: "quarantine candidate; no co-sign/settle",
        wallet: quarantineCandidate("INVALID_STEP_SIGNATURE"),
        operation: { kind: "refuse_acceptance" },
        auditAction: "anomaly.quarantine_candidate_no_cosign",
      });

    case "WALLET_ROLE_INVALID":
      return finalize({
        anomaly: input.anomaly,
        nodeActionSummary: "no operation acceptance",
        wallet: { kind: "none" },
        operation: { kind: "refuse_acceptance" },
        auditAction: "anomaly.refuse_operation_acceptance",
      });

    case "EQUIVALENT_STATE_DIFFERENT_ENVELOPE":
      return finalize({
        anomaly: input.anomaly,
        nodeActionSummary: "retain, no head promotion",
        wallet: { kind: "none" },
        operation: { kind: "none" },
        auditAction: "anomaly.retain_no_head_promotion",
      });

    case "SIGNATURE_COLLISION":
      // anomaly; quarantine/fail closed. Same wallet halt as regression/genesis.
      return finalize({
        anomaly: input.anomaly,
        nodeActionSummary: "quarantine wallet, preserve lease, halt signing from wallet",
        wallet: quarantineWallet("SIGNATURE_COLLISION"),
        operation: { kind: "none" },
        auditAction: "anomaly.quarantine_wallet_halt_signing",
      });

    case "GENESIS_AFTER_HISTORY":
      return finalize({
        anomaly: input.anomaly,
        nodeActionSummary: "quarantine wallet, preserve lease, halt signing from wallet",
        wallet: quarantineWallet("GENESIS_AFTER_HISTORY"),
        operation: { kind: "none" },
        auditAction: "anomaly.quarantine_wallet_halt_signing",
      });

    case "REGRESSION":
      return finalize({
        anomaly: input.anomaly,
        nodeActionSummary: "quarantine wallet, preserve lease, halt signing from wallet",
        wallet: quarantineWallet("REGRESSION"),
        operation: { kind: "none" },
        auditAction: "anomaly.quarantine_wallet_halt_signing",
      });

    case "UNEXPLAINED_JUMP":
      // NEEDS_ATTENTION; do not infer landing/non-landing. Lease preserved via invariants.
      return finalize({
        anomaly: input.anomaly,
        nodeActionSummary: "NEEDS_ATTENTION; do not infer landing/non-landing",
        wallet: { kind: "none" },
        operation: needsAttention(jumpReason),
        auditAction: "anomaly.needs_attention",
      });

    case "NODE_PLATFORM_DISAGREEMENT":
      return finalize({
        anomaly: input.anomaly,
        nodeActionSummary: "do not release verification barrier automatically",
        wallet: { kind: "none" },
        operation: { kind: "hold_verification_barrier" },
        auditAction: "anomaly.hold_verification_barrier",
      });

    case "GATEWAY_ENDPOINT_DISAGREEMENT":
      return finalize({
        anomaly: input.anomaly,
        nodeActionSummary: "halt affected wallet/operation",
        wallet: {
          kind: "halt_signing",
          haltSigning: true,
          preserveLease: true,
        },
        operation: needsAttention("VERIFICATION_INDETERMINATE"),
        auditAction: "anomaly.halt_wallet_operation",
      });

    default: {
      const _exhaustive: never = input.anomaly;
      throw new Error(`unknown anomaly kind: ${String(_exhaustive)}`);
    }
  }
}

function finalize(
  partial: Omit<AnomalyActionPlan, "invariants" | "signingHalted" | "walletQuarantined">,
): AnomalyActionPlan {
  // Only full wallet quarantine flips wallets.state → QUARANTINED (graded response).
  const walletQuarantined = partial.wallet.kind === "quarantine";
  const signingHalted =
    partial.wallet.kind === "quarantine" ||
    partial.wallet.kind === "halt_signing" ||
    partial.operation.kind === "needs_attention" ||
    partial.operation.kind === "refuse_acceptance";
  return {
    ...partial,
    invariants: ANOMALY_ACTION_INVARIANTS,
    signingHalted,
    walletQuarantined,
  };
}

/**
 * Map a classifier relationship onto an plan. Non-anomalous relationships
 * yield a no-op plan (no wallet/operation mutation) so callers can route every classification
 * through this layer without a separate branch.
 */
export function planActionForRelationship(
  relationship: ClassifierOutputRelationship,
  options?: Pick<PlanAnomalyActionInput, "unexplainedJumpAttentionReason">,
): AnomalyActionPlan {
  if (!isAnomalousRelationship(relationship)) {
    return {
      anomaly: "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
      nodeActionSummary: "no anomaly action (non-anomalous relationship)",
      wallet: { kind: "none" },
      operation: { kind: "none" },
      auditAction: "anomaly.no_op_non_anomalous",
      invariants: ANOMALY_ACTION_INVARIANTS,
      signingHalted: false,
      walletQuarantined: false,
    };
  }
  return planAnomalyAction({
    anomaly: relationship as ClassifierAnomalyKind,
    unexplainedJumpAttentionReason: options?.unexplainedJumpAttentionReason,
  });
}

// ── Apply layer (ports + in-memory store for tests) ──────────────────────────

export interface QuarantineWalletSnapshot {
  readonly walletId: string;
  readonly state: WalletState;
  readonly quarantineReason: string | null;
  /** Active lease id if one is held; null when unleased. Never cleared by this module. */
  readonly activeLeaseId: string | null;
  /** Structural signing halt independent of QUARANTINED (endpoint disagreement). */
  readonly signingHalted: boolean;
}

/**
 * Operation status values this slice reads/writes. Verified-landed / REJECTED
 * members are immutable historic facts. EXPIRED is terminal for the
 * receive protocol machine but attention flags remain mutable.
 */
export type QuarantineTrackedStatus =
  | "CREATED"
  | "READY"
  | "RECEIVE_LANDED"
  | "INTERNAL_MOVE_LANDED"
  | "APPROVED"
  | "AWAITING_REDEMPTION"
  | "EXTERNAL_SEND_LANDED"
  | "NEEDS_ATTENTION"
  | "REJECTED"
  | "EXPIRED";

/**
 * Verified outcome rows that must never be rewritten by an anomaly.
 * EXPIRED is intentionally absent — an expired receive may still raise attention
 * while remaining EXPIRED.
 */
const HISTORIC_TERMINAL_STATUSES: readonly QuarantineTrackedStatus[] = [
  "RECEIVE_LANDED",
  "INTERNAL_MOVE_LANDED",
  "EXTERNAL_SEND_LANDED",
  "REJECTED",
];

function isHistoricTerminalStatus(status: QuarantineTrackedStatus): boolean {
  return (HISTORIC_TERMINAL_STATUSES as readonly string[]).includes(status);
}

/** MOVE_INTERNAL edges that may enter NEEDS_ATTENTION. */
const MOVE_NEEDS_ATTENTION_FROM: ReadonlySet<QuarantineTrackedStatus> = new Set([
  "CREATED",
  "NEEDS_ATTENTION",
]);

/** SEND_EXTERNAL edges that may enter NEEDS_ATTENTION. */
const SEND_NEEDS_ATTENTION_FROM: ReadonlySet<QuarantineTrackedStatus> = new Set([
  "APPROVED",
  "AWAITING_REDEMPTION",
  "NEEDS_ATTENTION",
]);

/**
 * RECEIVE_EXTERNAL statuses that may set attention without changing status
 * (no fifth public receive state).
 */
const RECEIVE_ATTENTION_FROM: ReadonlySet<QuarantineTrackedStatus> = new Set([
  "CREATED",
  "READY",
  "EXPIRED",
]);

/**
 * Resolve the post-attention status for an operation.
 * Returns null when the edge is illegal (caller leaves the row unchanged).
 * Receive never rewrites status; move/send only along edges.
 */
export function resolveAttentionStatus(
  prior: Pick<QuarantineOperationSnapshot, "kind" | "status">,
): QuarantineTrackedStatus | null {
  if (isHistoricTerminalStatus(prior.status)) {
    return null;
  }
  switch (prior.kind) {
    case "RECEIVE_EXTERNAL":
      return RECEIVE_ATTENTION_FROM.has(prior.status) ? prior.status : null;
    case "MOVE_INTERNAL":
      return MOVE_NEEDS_ATTENTION_FROM.has(prior.status) ? "NEEDS_ATTENTION" : null;
    case "SEND_EXTERNAL":
      return SEND_NEEDS_ATTENTION_FROM.has(prior.status) ? "NEEDS_ATTENTION" : null;
    default: {
      const _exhaustive: never = prior.kind;
      throw new Error(`unknown operation kind: ${String(_exhaustive)}`);
    }
  }
}

export interface QuarantineOperationSnapshot {
  readonly operationId: string;
  readonly walletId: string | null;
  /** Discriminates Appendix B attention semantics (receive vs move/send). */
  readonly kind: OperationKind;
  readonly status: QuarantineTrackedStatus;
  readonly attentionRequired: boolean;
  readonly attentionReason: AttentionReason | null;
  readonly attentionEpisode: number;
}

export interface EvidenceRow {
  readonly table: "observation_anomalies" | "gateway_observations";
  readonly id: string;
  readonly payload: Readonly<Record<string, unknown>>;
}

export interface QuarantineAuditEntry {
  readonly action: QuarantineAuditAction;
  readonly anomaly: Obs15AnomalyKind;
  readonly walletId: string | null;
  readonly operationId: string | null;
  readonly detail: string;
  readonly atMs: number;
}

export interface NeedsAttentionEvent {
  readonly event: "operation.needs_attention";
  readonly operationId: string;
  readonly data: {
    readonly current_state: QuarantineTrackedStatus;
    readonly attention_reason: AttentionReason;
    readonly attention_episode: number;
    readonly operator_action_required: true;
  };
}

export interface ApplyAnomalyActionInput {
  readonly plan: AnomalyActionPlan;
  readonly walletId: string | null;
  readonly operationId: string | null;
  /** Optional wall-clock for audit timestamps; defaults to Date.now. */
  readonly nowMs?: number;
}

export interface ApplyAnomalyActionResult {
  readonly plan: AnomalyActionPlan;
  readonly wallet: QuarantineWalletSnapshot | null;
  readonly operation: QuarantineOperationSnapshot | null;
  readonly audit: QuarantineAuditEntry;
  readonly needsAttentionEvent: NeedsAttentionEvent | null;
  /** Always empty — this slice never mutates evidence. Exposed so tests can assert. */
  readonly evidenceMutations: readonly never[];
  readonly leaseReleased: false;
}

/**
 * Persistence port. Implementations must honour the plan invariants: no lease release,
 * no evidence delete/edit, no historic terminal rewrite. The in-memory store below is the
 * reference used by unit tests; SQL wiring is a later integration slice.
 *
 * `runAtomic` is required: multi-effect plans (e.g. GATEWAY halt + NEEDS_ATTENTION + audit)
 * must commit as one unit. Throw ⇒ no durable mutation from that apply call.
 */
export interface AnomalyQuarantineStore {
  getWallet(walletId: string): Promise<QuarantineWalletSnapshot | null>;
  getOperation(operationId: string): Promise<QuarantineOperationSnapshot | null>;
  /**
   * Set wallets.state='QUARANTINED' + quarantine_reason. MUST preserve activeLeaseId.
   * No-op (still success) when wallet is already RETIRED — retirement outranks quarantine
   * for selection, but we still set signingHalted.
   */
  quarantineWallet(
    walletId: string,
    quarantineReason: string,
    opts: { readonly haltSigning: true; readonly preserveLease: true },
  ): Promise<QuarantineWalletSnapshot>;
  /**
   * Record that a transaction candidate is rejected (invalid step signature). MUST NOT
   * transition wallets.state, MUST NOT set signingHalted, MUST preserve activeLeaseId.
   * "quarantine candidate; no co-sign/settle" — graded below wallet quarantine.
   */
  quarantineCandidate(
    walletId: string,
    quarantineReason: string,
    opts: { readonly haltSigning: false; readonly preserveLease: true },
  ): Promise<QuarantineWalletSnapshot>;
  /** Halt signing without forcing QUARANTINED (endpoint disagreement). Preserve lease. */
  haltWalletSigning(walletId: string): Promise<QuarantineWalletSnapshot>;
  /**
   * Raise attention on an operation per Appendix B kind rules:
   * - RECEIVE_EXTERNAL: set attention flags; never rewrite status (incl. EXPIRED).
   * - MOVE_INTERNAL / SEND_EXTERNAL: transition to NEEDS_ATTENTION only on allowed edges.
   * MUST refuse verified historic terminals (LANDED/REJECTED) — returns unchanged +
   * `mutated: false`.
   */
  markNeedsAttention(
    operationId: string,
    attentionReason: AttentionReason,
  ): Promise<{ readonly operation: QuarantineOperationSnapshot; readonly mutated: boolean }>;
  appendAudit(entry: QuarantineAuditEntry): Promise<void>;
  /**
   * Run `fn` as one atomic unit. On throw, every write performed inside `fn` is rolled
   * back (SQL: real transaction; in-memory: snapshot/restore). Nested calls compose.
   */
  runAtomic<T>(fn: () => Promise<T>): Promise<T>;
  /** Read-only evidence access for negative-path assertions. */
  listEvidence(): Promise<readonly EvidenceRow[]>;
}

/**
 * After a wallet mutate that claims preserveLease, refuse success if a prior non-null
 * lease disappeared or changed (closing rule).
 */
function assertLeasePreserved(
  anomaly: Obs15AnomalyKind,
  prior: QuarantineWalletSnapshot,
  next: QuarantineWalletSnapshot,
): void {
  if (prior.activeLeaseId !== null && next.activeLeaseId !== prior.activeLeaseId) {
    throw new Error(
      `anomaly ${anomaly} must preserve active lease ${prior.activeLeaseId}; store returned ${String(next.activeLeaseId)}`,
    );
  }
}

/**
 * Apply a pure plan through the store. Fail-closed:
 * - Preflight resolves every required wallet/operation row before any write; missing
 * ids/rows throw with zero durable mutation.
 * - Wallet + operation + audit effects commit inside `store.runAtomic` so a throw after
 * a partial write rolls back (no orphan signingHalted / attention / audit).
 * - Terminal historic ops are left untouched; leases are never released.
 * - Apply re-reads the prior wallet and throws if a non-null lease is dropped by the store.
 */
export async function applyAnomalyAction(
  store: AnomalyQuarantineStore,
  input: ApplyAnomalyActionInput,
): Promise<ApplyAnomalyActionResult> {
  const { plan } = input;
  const nowMs = input.nowMs ?? Date.now();

  // Invariant guard — the pure planner always stamps these; refuse any forged plan.
  assertInvariants(plan.invariants);

  // ── Preflight (read-only): validate every row the plan will mutate ─────────
  const needsWalletWrite =
    plan.wallet.kind === "quarantine" ||
    plan.wallet.kind === "quarantine_candidate" ||
    plan.wallet.kind === "halt_signing";
  const needsOperationWrite = plan.operation.kind === "needs_attention";

  let priorWallet: QuarantineWalletSnapshot | null = null;
  let priorOperation: QuarantineOperationSnapshot | null = null;

  if (needsWalletWrite) {
    if (input.walletId === null) {
      const verb =
        plan.wallet.kind === "quarantine_candidate"
          ? "for candidate quarantine"
          : plan.wallet.kind === "halt_signing"
            ? "to halt signing"
            : "to quarantine";
      throw new Error(`anomaly ${plan.anomaly} requires walletId ${verb}`);
    }
    priorWallet = await store.getWallet(input.walletId);
    if (priorWallet === null) {
      throw new Error(`wallet ${input.walletId} not found`);
    }
  } else if (input.walletId !== null) {
    priorWallet = await store.getWallet(input.walletId);
  }

  if (needsOperationWrite) {
    if (input.operationId === null) {
      throw new Error(`anomaly ${plan.anomaly} requires operationId for NEEDS_ATTENTION`);
    }
    priorOperation = await store.getOperation(input.operationId);
    if (priorOperation === null) {
      throw new Error(`operation ${input.operationId} not found for NEEDS_ATTENTION`);
    }
  } else if (input.operationId !== null) {
    priorOperation = await store.getOperation(input.operationId);
  }

  // ── Mutate atomically: throw ⇒ store restores pre-apply snapshot ───────────
  return store.runAtomic(async () => {
    let wallet: QuarantineWalletSnapshot | null = priorWallet;
    let operation: QuarantineOperationSnapshot | null = priorOperation;
    let needsAttentionEvent: NeedsAttentionEvent | null = null;

    if (plan.wallet.kind === "quarantine") {
      // preflight guarantees walletId + priorWallet
      wallet = await store.quarantineWallet(
        input.walletId as string,
        plan.wallet.quarantineReason,
        { haltSigning: true, preserveLease: true },
      );
      assertLeasePreserved(plan.anomaly, priorWallet as QuarantineWalletSnapshot, wallet);
    } else if (plan.wallet.kind === "quarantine_candidate") {
      // quarantine candidate only — never wallets.state='QUARANTINED' / wallet halt.
      wallet = await store.quarantineCandidate(
        input.walletId as string,
        plan.wallet.quarantineReason,
        { haltSigning: false, preserveLease: true },
      );
      assertLeasePreserved(plan.anomaly, priorWallet as QuarantineWalletSnapshot, wallet);
      if (wallet.state === "QUARANTINED") {
        throw new Error(
          `anomaly ${plan.anomaly} quarantine_candidate must not set wallets.state=QUARANTINED`,
        );
      }
      if (wallet.signingHalted && !(priorWallet as QuarantineWalletSnapshot).signingHalted) {
        throw new Error(
          `anomaly ${plan.anomaly} quarantine_candidate must not set wallet signingHalted`,
        );
      }
    } else if (plan.wallet.kind === "halt_signing") {
      wallet = await store.haltWalletSigning(input.walletId as string);
      assertLeasePreserved(plan.anomaly, priorWallet as QuarantineWalletSnapshot, wallet);
    }

    if (plan.operation.kind === "needs_attention") {
      // preflight guarantees operationId + priorOperation
      const marked = await store.markNeedsAttention(
        input.operationId as string,
        plan.operation.attentionReason,
      );
      operation = marked.operation;
      if (marked.mutated) {
        // current_state is the actual protocol status after mutation (receive keeps READY/EXPIRED).
        needsAttentionEvent = {
          event: "operation.needs_attention",
          operationId: input.operationId as string,
          data: {
            current_state: operation.status,
            attention_reason: plan.operation.attentionReason,
            attention_episode: operation.attentionEpisode,
            operator_action_required: true,
          },
        };
      }
    }

    const audit: QuarantineAuditEntry = {
      action: plan.auditAction,
      anomaly: plan.anomaly,
      walletId: input.walletId,
      operationId: input.operationId,
      detail: plan.nodeActionSummary,
      atMs: nowMs,
    };
    await store.appendAudit(audit);

    return {
      plan,
      wallet,
      operation,
      audit,
      needsAttentionEvent,
      evidenceMutations: [],
      leaseReleased: false as const,
    };
  });
}

function assertInvariants(inv: AnomalyActionInvariants): void {
  if (
    inv.neverReleaseLease !== true ||
    inv.neverDeleteEvidence !== true ||
    inv.neverRewriteVerdict !== true ||
    inv.neverMutateTerminalHistoricOp !== true ||
    inv.grantsLandingAuthority !== false ||
    inv.grantsRetryAuthority !== false ||
    inv.grantsHeadPromotion !== false
  ) {
    throw new Error("anomaly action plan violates invariants");
  }
}

/**
 * Lease-acquisition gate: AVAILABLE and PINNED may be claimed; QUARANTINED and
 * RETIRED must not. A signing-halted wallet is also refused for new claims even if state
 * has not yet flipped to QUARANTINED (endpoint-disagreement path).
 */
export function canAcquireNewLease(wallet: QuarantineWalletSnapshot): boolean {
  if (wallet.state === "QUARANTINED" || wallet.state === "RETIRED") return false;
  if (wallet.signingHalted) return false;
  // PINNED already has an active operation lease — no second claim.
  if (wallet.state === "PINNED" || wallet.activeLeaseId !== null) return false;
  return wallet.state === "AVAILABLE";
}

/** True when the wallet must not be handed to the signer for any new operation. */
export function isSigningHalted(wallet: QuarantineWalletSnapshot): boolean {
  return (
    wallet.signingHalted ||
    wallet.state === "QUARANTINED" ||
    wallet.state === "RETIRED"
  );
}

// ── In-memory store (test + local reference) ─────────────────────────────────

export class InMemoryAnomalyQuarantineStore implements AnomalyQuarantineStore {
  private readonly wallets = new Map<string, QuarantineWalletSnapshot>();
  private readonly operations = new Map<string, QuarantineOperationSnapshot>();
  private readonly evidence: EvidenceRow[] = [];
  private readonly auditLog: QuarantineAuditEntry[] = [];
  /** Nesting depth for runAtomic — only the outermost frame snapshots/restores. */
  private atomicDepth = 0;

  seedWallet(wallet: QuarantineWalletSnapshot): void {
    this.wallets.set(wallet.walletId, { ...wallet });
  }

  seedOperation(operation: QuarantineOperationSnapshot): void {
    this.operations.set(operation.operationId, { ...operation });
  }

  seedEvidence(row: EvidenceRow): void {
    this.evidence.push({ ...row, payload: { ...row.payload } });
  }

  getAuditLog(): readonly QuarantineAuditEntry[] {
    return this.auditLog.slice();
  }

  async getWallet(walletId: string): Promise<QuarantineWalletSnapshot | null> {
    return this.wallets.get(walletId) ?? null;
  }

  async getOperation(operationId: string): Promise<QuarantineOperationSnapshot | null> {
    return this.operations.get(operationId) ?? null;
  }

  /**
   * Snapshot/restore atomic unit. Outer frame captures maps + audit/evidence lengths;
   * throw restores those snapshots so half-committed multi-effect applies leave zero
   * durable mutation.
   */
  async runAtomic<T>(fn: () => Promise<T>): Promise<T> {
    const isOuter = this.atomicDepth === 0;
    const walletSnap = isOuter
      ? new Map(
          [...this.wallets.entries()].map(([k, v]) => [k, { ...v } as QuarantineWalletSnapshot]),
        )
      : null;
    const opSnap = isOuter
      ? new Map(
          [...this.operations.entries()].map(([k, v]) => [
            k,
            { ...v } as QuarantineOperationSnapshot,
          ]),
        )
      : null;
    const evidenceSnap = isOuter
      ? this.evidence.map((row) => ({ ...row, payload: { ...row.payload } }))
      : null;
    const auditSnap = isOuter ? this.auditLog.slice() : null;

    this.atomicDepth += 1;
    try {
      return await fn();
    } catch (err) {
      if (isOuter && walletSnap && opSnap && evidenceSnap && auditSnap) {
        this.wallets.clear();
        for (const [k, v] of walletSnap) this.wallets.set(k, v);
        this.operations.clear();
        for (const [k, v] of opSnap) this.operations.set(k, v);
        this.evidence.length = 0;
        this.evidence.push(...evidenceSnap);
        this.auditLog.length = 0;
        this.auditLog.push(...auditSnap);
      }
      throw err;
    } finally {
      this.atomicDepth -= 1;
    }
  }

  async quarantineWallet(
    walletId: string,
    quarantineReason: string,
    opts: { readonly haltSigning: true; readonly preserveLease: true },
  ): Promise<QuarantineWalletSnapshot> {
    void opts; // preserveLease is structural — we never touch activeLeaseId below.
    const prior = this.wallets.get(walletId);
    if (prior === undefined) {
      throw new Error(`wallet ${walletId} not found`);
    }
    // RETIRED stays RETIRED (selection already blocked); still halt signing.
    if (prior.state === "RETIRED") {
      const next: QuarantineWalletSnapshot = {
        ...prior,
        signingHalted: true,
        // activeLeaseId deliberately unchanged
      };
      this.wallets.set(walletId, next);
      return next;
    }
    const next: QuarantineWalletSnapshot = {
      walletId: prior.walletId,
      state: "QUARANTINED",
      quarantineReason,
      activeLeaseId: prior.activeLeaseId, // PRESERVE — never release
      signingHalted: true,
    };
    this.wallets.set(walletId, next);
    return next;
  }

  async quarantineCandidate(
    walletId: string,
    quarantineReason: string,
    opts: { readonly haltSigning: false; readonly preserveLease: true },
  ): Promise<QuarantineWalletSnapshot> {
    void quarantineReason;
    void opts;
    const prior = this.wallets.get(walletId);
    if (prior === undefined) {
      throw new Error(`wallet ${walletId} not found`);
    }
    // Candidate rejection only — wallet row unchanged (AVAILABLE/PINNED/lease intact).
    return { ...prior };
  }

  async haltWalletSigning(walletId: string): Promise<QuarantineWalletSnapshot> {
    const prior = this.wallets.get(walletId);
    if (prior === undefined) {
      throw new Error(`wallet ${walletId} not found`);
    }
    const next: QuarantineWalletSnapshot = {
      ...prior,
      signingHalted: true,
      // activeLeaseId deliberately unchanged
    };
    this.wallets.set(walletId, next);
    return next;
  }

  async markNeedsAttention(
    operationId: string,
    attentionReason: AttentionReason,
  ): Promise<{ readonly operation: QuarantineOperationSnapshot; readonly mutated: boolean }> {
    const prior = this.operations.get(operationId);
    if (prior === undefined) {
      throw new Error(`operation ${operationId} not found`);
    }
    // verified LANDED / REJECTED remain durable historic facts (not EXPIRED).
    if (isHistoricTerminalStatus(prior.status)) {
      return { operation: prior, mutated: false };
    }
    // Same attention episode already open — no new event.
    if (prior.attentionRequired && prior.attentionReason === attentionReason) {
      return { operation: prior, mutated: false };
    }

    const nextStatus = resolveAttentionStatus(prior);
    if (nextStatus === null) {
      // Illegal edge for this kind (e.g. send CREATED → NEEDS_ATTENTION is not in).
      return { operation: prior, mutated: false };
    }

    const nextEpisode = prior.attentionRequired
      ? prior.attentionEpisode + 1
      : 1;
    const next: QuarantineOperationSnapshot = {
      operationId: prior.operationId,
      walletId: prior.walletId,
      kind: prior.kind,
      status: nextStatus,
      attentionRequired: true,
      attentionReason,
      attentionEpisode: nextEpisode,
    };
    this.operations.set(operationId, next);
    return { operation: next, mutated: true };
  }

  async appendAudit(entry: QuarantineAuditEntry): Promise<void> {
    this.auditLog.push(entry);
  }

  async listEvidence(): Promise<readonly EvidenceRow[]> {
    // Return defensive copies so callers cannot mutate internal rows.
    return this.evidence.map((row) => ({ ...row, payload: { ...row.payload } }));
  }
}

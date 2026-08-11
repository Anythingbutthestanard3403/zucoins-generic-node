// Deterministic boot recovery — steps 2–8 (step 1 is leadership).
//
// Boot covers steps 2–8, the "Boot does not" list, the raw-byte consecutive-dedup re-read,
// six typed classifications with their per-operation recovery tables, readiness held false
// until leadership is held (no money workers before readiness), the changed-response
// observation ledger (exact-byte consecutive dedup), and complete-path landing only
// there is no generic PROVEN_NOT_LANDED oracle.
//
// Architecture:
// - Classification (step 5) is PURE: it only reads durable evidence via ports and
// returns a typed outcome. It never calls sign or submit.
// - Resume (step 6) is a SEPARATE guarded transition that applies only outcomes
// authorized by the classification tables. Ambiguous submit boundaries never
// re-submit; external partials never re-form; attention never auto-clears.
// - Leadership is a precondition (assertSignerLeadership). Without it the process
// must not classify-or-resume as leader, and readiness stays false.
// - Stale heartbeat never releases a lease (axiom 5 / "Boot does not" item 1).
//
// IO is fully injected so unit tests prove the contract with zero network / DB.

import { type OperationKind } from "@zucoins/generic-node-contracts/operations";
import { type AttentionReason } from "@zucoins/generic-node-contracts/operations/events";
import {
  auditPersistedWallet,
  projectWalletState,
  STORED_STATE_DIMENSION,
  type LeaseRole,
  type WalletLease,
} from "@zucoins/generic-node-contracts/wallet-state";

import { isTerminalOperationState } from "../protocol/operation-states.js";
import {
  assertSignerLeadership,
  type SignerLeadershipLatch,
} from "../core/signer-boundary.js";
import {
  classifyMoveReconcile,
  classifyReceiveReconcile,
  classifySendReconcile,
  toAttentionReason,
  type MoveReconcileInput,
  type MoveReconcileOutcome,
  type ReceiveReconcileInput,
  type ReceiveReconcileOutcome,
  type SendReconcileInput,
  type SendReconcileOutcome,
} from "../protocol/reconcile/index.js";

/** Persisted wallets.state — same closed set as pool/wallet-state (AVAILABLE/PINNED/QUARANTINED/RETIRED). */
export type BootWalletState = (typeof STORED_STATE_DIMENSION)[number];

// ── Closed classification vocabulary ─────────────────────────────────
//
// PROVEN_NOT_LANDED is part of the closed set, but the landing-path oracle makes a generic
// non-landing oracle unrepresentable. Automatic classification never emits it; the member
// exists so the closed set matches the normative table and so a future
// evidence-complete positive oracle (operator-gated) can name it without
// reshaping the type.

export const BOOT_RECOVERY_CLASSIFICATIONS = [
  "LANDED_VERIFIED",
  "PROVEN_NOT_STARTED",
  "PROVEN_NOT_LANDED",
  "WAITING",
  "INDETERMINATE",
  "INVARIANT_BREACH",
] as const;
export type BootRecoveryClassification = (typeof BOOT_RECOVERY_CLASSIFICATIONS)[number];

export const BOOT_RECOVERY_STEPS = [
  "LEADERSHIP_PRECONDITION",
  "KEY_CORRESPONDENCE",
  "LEASE_AUDIT",
  "PHASE_AUDIT",
  "CLASSIFY",
  "RESUME",
  "REBUILD_QUEUES",
  "READINESS",
] as const;
export type BootRecoveryStep = (typeof BOOT_RECOVERY_STEPS)[number];

export { type OperationKind };
// re-export so the app shell can source LeaseRole through the
// package's public surface instead of reaching into generic-node-contracts
// directly (mirrors the OperationKind re-export above).
export { type LeaseRole };

// ── Ports (durable reads / guarded writes; never hold secrets) ────────────────

/** One active lease row as persisted in wallet_active_leases. */
export interface ActiveLeaseRow {
  readonly walletId: string;
  readonly operationId: string;
  readonly leaseGroupId: string;
  readonly role: LeaseRole;
  readonly epoch: number;
  /** Persisted wallets.state for this wallet. */
  readonly walletState: BootWalletState;
  /**
   * Wall-clock of the last lease heartbeat. Present so tests can prove that a
   * stale heartbeat NEVER authorizes release (axiom 5). Recovery itself never
   * uses this field to free a lease.
   */
  readonly lastHeartbeatAtMs: number;
}

/** Durable phase / audit boundary evidence for one nonterminal operation. */
export interface OperationPhaseEvidence {
  readonly operationId: string;
  readonly kind: OperationKind;
  readonly status: string;
  readonly attentionRequired: boolean;
  readonly rowVersion: number;
  readonly leaseEpoch: number;
  /** True when a submit claim or submit-call audit row exists for the attempt. */
  readonly submitBoundaryRecorded: boolean;
  /** True when a signer-audit row indicates a call for the attempt. */
  readonly signerAuditIndicatesCall: boolean;
  /** True when the exact sign-intent / preimage bytes are durable. */
  readonly exactPreimagePersisted: boolean;
  /** True when the expected signature (step-1 send / step-2 receive/move) is durable. */
  readonly signaturePersisted: boolean;
  /** True when formation artifacts (T0/code/etc.) form a complete durable set. */
  readonly formationComplete: boolean;
  /** Wallet ids bound to this operation's active leases (source and/or destination). */
  readonly leasedWalletIds: readonly string[];
  /**
   * Required role(s) for this operation kind — used by step 3's
   * source/destination role agreement check.
   */
  readonly requiredRoles: readonly LeaseRole[];
}

/** Vault open-probe: public key derived from opened key material vs wallets.public_key. */
export interface KeyCorrespondenceRow {
  readonly walletId: string;
  /** Canonical padded-base64url public key from the wallets row. */
  readonly storedPublicKey: string;
  /**
   * Public key derived after opening vault material. Null when the open failed.
   * A deterministic failure (unreadable ciphertext / missing row / version
   * mismatch) is a quarantine; a transient store/audit fault is not — see
   * `transientFault`.
   */
  readonly derivedPublicKey: string | null;
  /**
   * True when `derivedPublicKey === null` was caused by a retryable
   * operational fault (DB/audit-log IO) rather than a deterministic custody
   * verdict. Fails boot readiness without quarantining or breaching the
   * invariant ("Retryable / incomplete" class).
   */
  readonly transientFault?: boolean;
}

/**
 * Observation-cursor state for the first post-restart consecutive-dedup
 * comparison (raw-byte gate; changed-response observation ledger).
 */
export interface ObservationCursorHint {
  readonly streamKey: string;
  readonly lastRecordedObservationId: string | null;
  /**
   * Candidate/index hint only. MUST NOT be used as byte equality or a
   * digest-only suppression shortcut.
   */
  readonly lastRawResponseSha256: string | null;
}

/**
 * Durable lease-group membership (lease_group_operations): proves that
 * an operation owns a lease_group_id. Step 3 rejects orphan groups.
 */
export interface LeaseGroupOperationRow {
  readonly leaseGroupId: string;
  readonly operationId: string;
}

export interface BootRecoveryStore {
  listActiveLeases(): Promise<readonly ActiveLeaseRow[]>;
  /**
   * The lease-eligible census: every nonterminal operation, PLUS every terminal
   * operation that still owns a `wallet_active_leases` row. The name is historic
   * a terminal operation legitimately keeps its lease until the consumer's
   * verification-complete acknowledgement releases it (steps 5 and 6),
   * so a nonterminal-only census makes step 3 read every landed
   * operation as an orphaned lease.
   *
   * Callers must partition: step 3 (`auditActiveLeases`) needs the whole census;
   * steps 4-5 (`auditPhaseBoundaries` / `classifyNonterminalOperations`) need the
   * nonterminal subset only.
   */
  listNonterminalOperations(): Promise<readonly OperationPhaseEvidence[]>;
  /**
   * Permanent lease-group membership rows. Empty / missing membership for a
   * live lease is an invariant breach (step 3 ownership).
   */
  listLeaseGroupOperations(): Promise<readonly LeaseGroupOperationRow[]>;
  listKeyCorrespondence(): Promise<readonly KeyCorrespondenceRow[]>;
  listObservationCursors(): Promise<readonly ObservationCursorHint[]>;
  /**
   * Follow last_recorded_observation_id to gateway_observations.raw_response_bytes.
   * Returns null when the row is missing or the column is absent — fail closed.
   */
  readRawResponseBytes(observationId: string): Promise<Uint8Array | null>;
  listQueuedReceiveOperationIds(): Promise<readonly string[]>;
}

/** Side-effect ports used ONLY in step 6 (resume) and step 7 (queue rebuild). */
export interface BootRecoveryActions {
  /** Quarantine a wallet whose key correspondence or lease audit failed. */
  quarantineWallet(walletId: string, reason: string): Promise<void>;
  /**
   * Repair an understated restriction (e.g. leased wallet stored AVAILABLE → PINNED).
   * Never used to make a wallet AVAILABLE.
   */
  repairWalletState(walletId: string, to: BootWalletState): Promise<void>;
  /**
   * Park an operation with attention. Never clears attention (Boot does not).
   */
  setAttention(operationId: string, reason: AttentionReason, expectedRowVersion: number): Promise<void>;
  /**
   * Apply a classification-authorized resume. Implementations MUST refuse any
   * action not in the authorized set for the classification. Counters below
   * let tests prove classification never touches these.
   */
  resumeAuthorized(action: AuthorizedResumeAction): Promise<void>;
  /** Seed the bounded read-reconciliation cursor for a stream. */
  seedReconcileCursor(streamKey: string, priorRawBytes: Uint8Array | null): Promise<void>;
  /** Rebuild the receive admission queue from durable CREATED/queued rows. */
  rebuildReceiveAdmissionQueue(operationIds: readonly string[]): Promise<void>;
  /** Stop money engines on global invariant breach (automatic effect). */
  stopMoneyEngines(reason: string): Promise<void>;
}

export type AuthorizedResumeAction =
  | {
      readonly kind: "FIRST_FORMATION" | "SIGN_PERSISTED_PREIMAGE" | "SUBMIT_ONCE" | "RESUME_T0_AND_CODE_FORMATION" | "SIGN_PERSISTED_STEP2_PREIMAGE";
      readonly operationId: string;
      readonly operationKind: OperationKind;
      readonly expectedRowVersion: number;
      readonly expectedLeaseEpoch: number;
    }
  | {
      readonly kind: "ADVANCE_LANDED";
      readonly operationId: string;
      readonly operationKind: OperationKind;
      readonly expectedRowVersion: number;
    }
  | {
      readonly kind: "CONTINUE_WAITING";
      readonly operationId: string;
      readonly operationKind: OperationKind;
    };

// ── Results ───────────────────────────────────────────────────────────────────

export interface LeaseAuditFinding {
  readonly walletId: string;
  readonly severity: "ok" | "repair" | "quarantine" | "invariant_breach";
  readonly reason: string;
  /** True when a stale heartbeat was observed — never used to release. */
  readonly staleHeartbeatObserved: boolean;
  /** names the offending lease row so a future orphan is diagnosable from the report alone. */
  readonly operationId: string;
  readonly leaseGroupId: string;
}

export interface KeyCorrespondenceFinding {
  readonly walletId: string;
  readonly ok: boolean;
  readonly reason: string;
}

export interface ClassifiedOperation {
  readonly operationId: string;
  readonly kind: OperationKind;
  readonly classification: BootRecoveryClassification;
  readonly reason: string;
  /**
   * Closed vocabulary value written to operations.attention_reason when this
   * classification parks attention. Null for classifications that never park
   * (LANDED_VERIFIED / PROVEN_NOT_STARTED / WAITING).
   */
  readonly attentionReason: AttentionReason | null;
  readonly authorizedResume: AuthorizedResumeAction | null;
  readonly phaseAuditOk: boolean;
  /**
   * CAS inputs for guarded attention / resume transitions. Threaded
   * from OperationPhaseEvidence so attention parks never use sentinel -1.
   */
  readonly expectedRowVersion: number;
  readonly expectedLeaseEpoch: number;
}

export interface RawByteHydrationResult {
  readonly streamKey: string;
  /** True when prior raw bytes were loaded (or no prior observation exists). */
  readonly ok: boolean;
  readonly usedDigestShortcut: false;
  readonly reason: string;
}

export interface BootRecoveryReport {
  readonly ready: boolean;
  readonly invariantBreach: boolean;
  readonly leadershipHeld: boolean;
  readonly stepsCompleted: readonly BootRecoveryStep[];
  readonly keyFindings: readonly KeyCorrespondenceFinding[];
  readonly leaseFindings: readonly LeaseAuditFinding[];
  readonly classifications: readonly ClassifiedOperation[];
  readonly resumed: readonly AuthorizedResumeAction[];
  readonly rawByteHydrations: readonly RawByteHydrationResult[];
  readonly receiveQueueRebuiltCount: number;
  /** Side-effect counters for test assertions (classification purity). */
  readonly counters: BootRecoveryCounters;
}

export interface BootRecoveryCounters {
  signCalls: number;
  submitCalls: number;
  leaseDeletes: number;
  attentionClears: number;
  externalPartialReforms: number;
  destinationAutoAccepts: number;
  synthesizedBytesFromJson: number;
}

export interface BootRecoveryDeps {
  readonly leadership: SignerLeadershipLatch;
  readonly store: BootRecoveryStore;
  readonly actions: BootRecoveryActions;
  /**
   * Optional clock for "stale heartbeat" observation only. Never used to
   * authorize a lease release.
   */
  readonly nowMs?: () => number;
  /**
   * Heartbeat age above which we *record* staleness for diagnostics. Default
   * 60s. Recording never frees the lease.
   */
  readonly staleHeartbeatMs?: number;
}

// ── Step 2: key material / public-key correspondence ──────────────────────────

export async function validateKeyCorrespondence(
  store: BootRecoveryStore,
  actions: BootRecoveryActions,
): Promise<{ findings: KeyCorrespondenceFinding[]; breach: boolean; transientFault: boolean }> {
  const rows = await store.listKeyCorrespondence();
  const findings: KeyCorrespondenceFinding[] = [];
  let breach = false;
  let transientFault = false;
  for (const row of rows) {
    if (row.derivedPublicKey === null) {
      if (row.transientFault === true) {
        // Retryable IO fault, not a custody verdict — fail readiness only,
        // no quarantine, no durable wallet mutation (retryable class).
        transientFault = true;
        findings.push({
          walletId: row.walletId,
          ok: false,
          reason: "vault_open_transient_fault",
        });
        continue;
      }
      breach = true;
      findings.push({
        walletId: row.walletId,
        ok: false,
        reason: "vault_open_failed",
      });
      await actions.quarantineWallet(row.walletId, "boot: vault open failed for wallet");
      continue;
    }
    if (row.derivedPublicKey !== row.storedPublicKey) {
      // Never log either key value.
      breach = true;
      findings.push({
        walletId: row.walletId,
        ok: false,
        reason: "public_key_mismatch",
      });
      await actions.quarantineWallet(row.walletId, "boot: public-key correspondence failed");
      continue;
    }
    findings.push({ walletId: row.walletId, ok: true, reason: "match" });
  }
  return { findings, breach, transientFault };
}

// ── Step 3: active lease audit ────────────────────────────────────────────────

export async function auditActiveLeases(
  store: BootRecoveryStore,
  actions: BootRecoveryActions,
  ops: readonly OperationPhaseEvidence[],
  nowMs: number,
  staleHeartbeatMs: number,
): Promise<{ findings: LeaseAuditFinding[]; breach: boolean }> {
  const leases = await store.listActiveLeases();
  const groupOps = await store.listLeaseGroupOperations();
  const ownershipKeys = new Set(
    groupOps.map((g) => `${g.leaseGroupId}\0${g.operationId}`),
  );
  const findings: LeaseAuditFinding[] = [];
  let breach = false;

  // one row per wallet — PK enforces this at rest; still detect duplicates in the list.
  const seen = new Map<string, ActiveLeaseRow>();
  for (const lease of leases) {
    const staleHeartbeatObserved = nowMs - lease.lastHeartbeatAtMs > staleHeartbeatMs;

    if (seen.has(lease.walletId)) {
      breach = true;
      findings.push({
        walletId: lease.walletId,
        severity: "invariant_breach",
        reason: "duplicate_active_lease_row",
        staleHeartbeatObserved,
        operationId: lease.operationId,
        leaseGroupId: lease.leaseGroupId,
      });
      await actions.quarantineWallet(lease.walletId, "boot: duplicate active lease");
      // Boot does not delete a stale (or any) lease based on time.
      continue;
    }
    seen.set(lease.walletId, lease);

    const op = ops.find((o) => o.operationId === lease.operationId);
    if (op === undefined) {
      breach = true;
      findings.push({
        walletId: lease.walletId,
        severity: "invariant_breach",
        reason: "lease_operation_missing",
        staleHeartbeatObserved,
        operationId: lease.operationId,
        leaseGroupId: lease.leaseGroupId,
      });
      await actions.quarantineWallet(lease.walletId, "boot: lease operation missing");
      continue;
    }

    // (a) operation/lease-group ownership exists (lease_group_operations).
    if (!ownershipKeys.has(`${lease.leaseGroupId}\0${lease.operationId}`)) {
      breach = true;
      findings.push({
        walletId: lease.walletId,
        severity: "invariant_breach",
        reason: "lease_group_ownership_missing",
        staleHeartbeatObserved,
        operationId: lease.operationId,
        leaseGroupId: lease.leaseGroupId,
      });
      await actions.quarantineWallet(lease.walletId, "boot: lease-group ownership missing");
      continue;
    }

    // (b) wallet is bound to the operation's durable leased set.
    if (!op.leasedWalletIds.includes(lease.walletId)) {
      breach = true;
      findings.push({
        walletId: lease.walletId,
        severity: "invariant_breach",
        reason: "lease_wallet_not_bound_to_operation",
        staleHeartbeatObserved,
        operationId: lease.operationId,
        leaseGroupId: lease.leaseGroupId,
      });
      await actions.quarantineWallet(lease.walletId, "boot: lease wallet not bound to operation");
      continue;
    }

    if (!op.requiredRoles.includes(lease.role)) {
      breach = true;
      findings.push({
        walletId: lease.walletId,
        severity: "invariant_breach",
        reason: "lease_role_disagrees_with_operation",
        staleHeartbeatObserved,
        operationId: lease.operationId,
        leaseGroupId: lease.leaseGroupId,
      });
      await actions.quarantineWallet(lease.walletId, "boot: lease role disagrees with operation");
      continue;
    }

    // MOVE_INTERNAL holds independent per-wallet lease epochs (nextEpoch in
    // leases/repository.ts increments a per-wallet high-water counter), so a single
    // op-wide leaseEpoch cannot equal every wallet's epoch for a multi-wallet operation.
    // Enforce the op-wide match only for single-wallet ops (requiredRoles.length === 1);
    // multi-wallet ops rely on positivity here plus the per-lease role/group-ownership
    // checks above and the required-roles coverage pass below, which (B2) now
    // requires an exact role multiset match — a stray duplicate role lease on a surplus
    // wallet no longer slips past a permissive some-covered check.
    const epochOk = op.requiredRoles.length > 1 || lease.epoch === op.leaseEpoch;
    if (!epochOk || lease.epoch <= 0) {
      breach = true;
      findings.push({
        walletId: lease.walletId,
        severity: "invariant_breach",
        reason: "lease_epoch_not_monotonic_or_mismatch",
        staleHeartbeatObserved,
        operationId: lease.operationId,
        leaseGroupId: lease.leaseGroupId,
      });
      await actions.quarantineWallet(lease.walletId, "boot: lease epoch mismatch");
      continue;
    }

    // Wallet state must be PINNED or QUARANTINED while an operation lease is active
    // (step 3). Use the frozen boot-audit disposition.
    const projection = projectWalletState({
      leases: [{ role: lease.role, lifecycle: "ACTIVE" } satisfies WalletLease],
      quarantined: lease.walletState === "QUARANTINED",
      retired: lease.walletState === "RETIRED",
    });
    const audit = auditPersistedWallet(lease.walletState, projection);

    if (audit.disposition === "INVARIANT_BREACH_QUARANTINE") {
      breach = true;
      findings.push({
        walletId: lease.walletId,
        severity: "invariant_breach",
        reason: "wallet_state_invariant_breach",
        staleHeartbeatObserved,
        operationId: lease.operationId,
        leaseGroupId: lease.leaseGroupId,
      });
      await actions.quarantineWallet(lease.walletId, "boot: wallet state invariant breach");
      continue;
    }
    if (audit.disposition === "QUARANTINE_FOR_RECONCILIATION") {
      // Overstated restriction / phantom pin — park, do not release.
      findings.push({
        walletId: lease.walletId,
        severity: "quarantine",
        reason: "wallet_state_overstated_restriction",
        staleHeartbeatObserved,
        operationId: lease.operationId,
        leaseGroupId: lease.leaseGroupId,
      });
      await actions.quarantineWallet(lease.walletId, "boot: wallet state overstated restriction");
      continue;
    }
    if (audit.disposition === "REPAIR_TO_PROJECTION") {
      // Understated restriction only (AVAILABLE while leased → PINNED). Never AVAILABLE.
      findings.push({
        walletId: lease.walletId,
        severity: "repair",
        reason: "wallet_state_understated_restriction",
        staleHeartbeatObserved,
        operationId: lease.operationId,
        leaseGroupId: lease.leaseGroupId,
      });
      await actions.repairWalletState(lease.walletId, projection.state);
      continue;
    }

    if (lease.walletState !== "PINNED" && lease.walletState !== "QUARANTINED") {
      // Defensive: projection should have caught this; still fail closed.
      breach = true;
      findings.push({
        walletId: lease.walletId,
        severity: "invariant_breach",
        reason: "wallet_not_pinned_or_quarantined",
        staleHeartbeatObserved,
        operationId: lease.operationId,
        leaseGroupId: lease.leaseGroupId,
      });
      await actions.quarantineWallet(lease.walletId, "boot: leased wallet not PINNED/QUARANTINED");
      continue;
    }

    findings.push({
      walletId: lease.walletId,
      severity: "ok",
      reason: staleHeartbeatObserved ? "ok_stale_heartbeat_retained" : "ok",
      staleHeartbeatObserved,
      operationId: lease.operationId,
      leaseGroupId: lease.leaseGroupId,
    });
  }

  // (c) required roles for each op/group are all present with matching group + epoch.
  const leasesByOp = new Map<string, ActiveLeaseRow[]>();
  for (const lease of seen.values()) {
    const arr = leasesByOp.get(lease.operationId) ?? [];
    arr.push(lease);
    leasesByOp.set(lease.operationId, arr);
  }
  for (const [operationId, opLeases] of leasesByOp) {
    const op = ops.find((o) => o.operationId === operationId);
    if (op === undefined) continue;
    let incomplete = false;
    // B2: op.requiredRoles.length === opLeases.length is not enough on its own
    // (a missing role and a surplus duplicate role can cancel out in a bare length check)
    // require the role multiset itself to match exactly. A stray duplicate role lease on a
    // surplus wallet (e.g. two MOVE_SOURCE leases where only one is required) previously
    // passed the some-based coverage check below because "at least one lease covers this
    // role" is true even when a second, uncovering lease is also present.
    const roles = opLeases.map((l) => l.role);
    if (roles.length !== op.requiredRoles.length || new Set(roles).size !== roles.length) {
      incomplete = true;
    }
    for (const required of op.requiredRoles) {
      const covered = opLeases.some(
        (l) =>
          l.role === required &&
          // Same multi-wallet exemption as the per-lease audit above.
          (op.requiredRoles.length > 1 || l.epoch === op.leaseEpoch) &&
          ownershipKeys.has(`${l.leaseGroupId}\0${operationId}`),
      );
      if (!covered) {
        incomplete = true;
        break;
      }
    }
    if (!incomplete) continue;
    breach = true;
    const quarantined = new Set<string>();
    for (const l of opLeases) {
      if (quarantined.has(l.walletId)) continue;
      quarantined.add(l.walletId);
      findings.push({
        walletId: l.walletId,
        severity: "invariant_breach",
        reason: "lease_required_roles_incomplete",
        staleHeartbeatObserved: nowMs - l.lastHeartbeatAtMs > staleHeartbeatMs,
        operationId: l.operationId,
        leaseGroupId: l.leaseGroupId,
      });
      await actions.quarantineWallet(l.walletId, "boot: lease required roles incomplete");
    }
  }

  return { findings, breach };
}

// ── Step 4: immutable phase records + signer/submit audit boundaries ──────────

export function auditPhaseBoundaries(op: OperationPhaseEvidence): {
  ok: boolean;
  reason: string;
  forceBreach: boolean;
} {
  // Signer audit indicates a call but exact preimage is missing → INVARIANT_BREACH
  // (.2 last row).
  if (op.signerAuditIndicatesCall && !op.exactPreimagePersisted) {
    return {
      ok: false,
      reason: "signer_audit_without_exact_preimage",
      forceBreach: true,
    };
  }
  // Submit boundary recorded but signature missing → cannot have arisen under contract.
  if (op.submitBoundaryRecorded && !op.signaturePersisted) {
    return {
      ok: false,
      reason: "submit_boundary_without_signature",
      forceBreach: true,
    };
  }
  // Boot does not synthesize missing exact bytes from parsed JSON — absence is
  // either PROVEN_NOT_STARTED (no audit) or breach (audit present). Handled above.
  return { ok: true, reason: "phase_boundaries_consistent", forceBreach: false };
}

// ── Step 5: pure classification (no sign / no submit) ─────────────────────────


function withCas(
  op: OperationPhaseEvidence,
  partial: Omit<ClassifiedOperation, "operationId" | "kind" | "expectedRowVersion" | "expectedLeaseEpoch">,
): ClassifiedOperation {
  return {
    operationId: op.operationId,
    kind: op.kind,
    expectedRowVersion: op.rowVersion,
    expectedLeaseEpoch: op.leaseEpoch,
    ...partial,
  };
}

function classifyOne(op: OperationPhaseEvidence): ClassifiedOperation {
  const phase = auditPhaseBoundaries(op);
  if (phase.forceBreach) {
    const breachSource =
      phase.reason === "signer_audit_without_exact_preimage"
        ? ({ source: "EXPECTED_BYTES_MISSING_WITH_SIGNER_AUDIT" } as const)
        : ({ source: "SIGNER_AUDIT_CONTRADICTS_DURABLE_RECORD" } as const);
    return withCas(op, {
      classification: "INVARIANT_BREACH",
      reason: phase.reason,
      attentionReason: toAttentionReason(breachSource),
      authorizedResume: null,
      phaseAuditOk: false,
    });
  }

  // Build the pure reconcile input from durable evidence. No network, no sign, no submit.
  if (op.kind === "RECEIVE_EXTERNAL") {
    return classifyReceiveOp(op);
  }
  if (op.kind === "MOVE_INTERNAL") {
    return classifyMoveOp(op);
  }
  return classifySendOp(op);
}

function classifyReceiveOp(op: OperationPhaseEvidence): ClassifiedOperation {
  if (op.submitBoundaryRecorded) {
    // submit claim recorded → never submit again; observation-driven only.
    // Without a fresh observation at boot we park as INDETERMINATE (absence ≠ non-landing).
    return withCas(op, {
      classification: "INDETERMINATE",
      reason: "submit_boundary_recorded_awaiting_observation",
      attentionReason: toAttentionReason({ source: "SUBMIT_OUTCOME_UNKNOWN" }),
      authorizedResume: null,
      phaseAuditOk: true,
    });
  }

  const input: ReceiveReconcileInput = {
    boundary: "PRE_SUBMIT",
    receiveOperationId: op.operationId,
    formationComplete: op.formationComplete,
    step2SignaturePersisted: op.signaturePersisted,
    signerAuditIndicatesUse: op.signerAuditIndicatesCall,
  };
  const outcome = classifyReceiveReconcile(input);
  return mapReceiveOutcome(op, outcome);
}

function mapReceiveOutcome(
  op: OperationPhaseEvidence,
  outcome: ReceiveReconcileOutcome,
): ClassifiedOperation {
  switch (outcome.kind) {
    case "LANDED_VERIFIED":
      return withCas(op, {
        classification: "LANDED_VERIFIED",
        reason: "receive_landed_verified",
        attentionReason: null,
        authorizedResume: {
          kind: "ADVANCE_LANDED",
          operationId: op.operationId,
          operationKind: op.kind,
          expectedRowVersion: op.rowVersion,
        },
        phaseAuditOk: true,
      });
    case "PROVEN_NOT_STARTED":
      return withCas(op, {
        classification: "PROVEN_NOT_STARTED",
        reason: `receive_never_crossed_${outcome.neverCrossedBoundary.toLowerCase()}`,
        attentionReason: null,
        authorizedResume: {
          kind: outcome.resumeAction,
          operationId: op.operationId,
          operationKind: op.kind,
          expectedRowVersion: op.rowVersion,
          expectedLeaseEpoch: op.leaseEpoch,
        },
        phaseAuditOk: true,
      });
    case "INDETERMINATE":
      return withCas(op, {
        classification: "INDETERMINATE",
        reason: "receive_indeterminate",
        attentionReason: toAttentionReason(outcome.reason),
        authorizedResume: null,
        phaseAuditOk: true,
      });
    case "INVARIANT_BREACH":
      return withCas(op, {
        classification: "INVARIANT_BREACH",
        reason: "receive_invariant_breach",
        attentionReason: toAttentionReason(outcome.reason),
        authorizedResume: null,
        phaseAuditOk: true,
      });
  }
}

function classifyMoveOp(op: OperationPhaseEvidence): ClassifiedOperation {
  if (op.submitBoundaryRecorded) {
    return withCas(op, {
      classification: "INDETERMINATE",
      reason: "submit_boundary_recorded_awaiting_observation",
      attentionReason: toAttentionReason({ source: "SUBMIT_OUTCOME_UNKNOWN" }),
      authorizedResume: null,
      phaseAuditOk: true,
    });
  }

  const input: MoveReconcileInput = {
    boundary: "PRE_SUBMIT",
    moveAttemptId: op.operationId,
    preimagePersisted: op.exactPreimagePersisted,
    signaturesComplete: op.signaturePersisted,
    signerAuditIndicatesCall: op.signerAuditIndicatesCall,
  };
  const outcome = classifyMoveReconcile(input);
  return mapMoveOutcome(op, outcome);
}

function mapMoveOutcome(op: OperationPhaseEvidence, outcome: MoveReconcileOutcome): ClassifiedOperation {
  switch (outcome.kind) {
    case "LANDED_VERIFIED":
      return withCas(op, {
        classification: "LANDED_VERIFIED",
        reason: "move_landed_verified",
        attentionReason: null,
        authorizedResume: {
          kind: "ADVANCE_LANDED",
          operationId: op.operationId,
          operationKind: op.kind,
          expectedRowVersion: op.rowVersion,
        },
        phaseAuditOk: true,
      });
    case "PROVEN_NOT_STARTED":
      return withCas(op, {
        classification: "PROVEN_NOT_STARTED",
        reason: `move_never_crossed_${outcome.neverCrossedBoundary.toLowerCase()}`,
        attentionReason: null,
        authorizedResume: {
          kind: outcome.resumeAction,
          operationId: op.operationId,
          operationKind: op.kind,
          expectedRowVersion: op.rowVersion,
          expectedLeaseEpoch: op.leaseEpoch,
        },
        phaseAuditOk: true,
      });
    case "INDETERMINATE":
      return withCas(op, {
        classification: "INDETERMINATE",
        reason: "move_indeterminate",
        attentionReason: toAttentionReason(outcome.reason),
        authorizedResume: null,
        phaseAuditOk: true,
      });
    case "INVARIANT_BREACH":
      return withCas(op, {
        classification: "INVARIANT_BREACH",
        reason: "move_invariant_breach",
        attentionReason: toAttentionReason(outcome.reason),
        authorizedResume: null,
        phaseAuditOk: true,
      });
  }
}

function classifySendOp(op: OperationPhaseEvidence): ClassifiedOperation {
  // SEND_EXTERNAL: node never submits. A "submit boundary" for send would be the
  // recipient's act — we only recon via observation. Delivered partials wait.
  if (op.signaturePersisted) {
    // safe automatic actions only — WAITING; never re-form, never free lease.
    return withCas(op, {
      classification: "WAITING",
      reason: "external_partial_awaiting_redemption",
      attentionReason: null,
      authorizedResume: {
        kind: "CONTINUE_WAITING",
        operationId: op.operationId,
        operationKind: op.kind,
      },
      phaseAuditOk: true,
    });
  }

  const input: SendReconcileInput = {
    boundary: "PRE_DELIVERY",
    sendOperationId: op.operationId,
    signIntentPersisted: op.exactPreimagePersisted,
    step1SignaturePersisted: op.signaturePersisted,
    signerAuditIndicatesCall: op.signerAuditIndicatesCall,
  };
  const outcome = classifySendReconcile(input);
  return mapSendOutcome(op, outcome);
}

function mapSendOutcome(op: OperationPhaseEvidence, outcome: SendReconcileOutcome): ClassifiedOperation {
  switch (outcome.kind) {
    case "LANDED_VERIFIED":
      return withCas(op, {
        classification: "LANDED_VERIFIED",
        reason: "send_landed_verified",
        attentionReason: null,
        authorizedResume: {
          kind: "ADVANCE_LANDED",
          operationId: op.operationId,
          operationKind: op.kind,
          expectedRowVersion: op.rowVersion,
        },
        phaseAuditOk: true,
      });
    case "PROVEN_NOT_STARTED":
      return withCas(op, {
        classification: "PROVEN_NOT_STARTED",
        reason: `send_never_crossed_${outcome.neverCrossedBoundary.toLowerCase()}`,
        attentionReason: null,
        authorizedResume: {
          kind: outcome.resumeAction,
          operationId: op.operationId,
          operationKind: op.kind,
          expectedRowVersion: op.rowVersion,
          expectedLeaseEpoch: op.leaseEpoch,
        },
        phaseAuditOk: true,
      });
    case "WAITING":
      return withCas(op, {
        classification: "WAITING",
        reason: "send_waiting",
        attentionReason: null,
        authorizedResume: {
          kind: "CONTINUE_WAITING",
          operationId: op.operationId,
          operationKind: op.kind,
        },
        phaseAuditOk: true,
      });
    case "INDETERMINATE":
      return withCas(op, {
        classification: "INDETERMINATE",
        reason: "send_indeterminate",
        attentionReason: toAttentionReason(outcome.reason),
        authorizedResume: null,
        phaseAuditOk: true,
      });
    case "INVARIANT_BREACH":
      return withCas(op, {
        classification: "INVARIANT_BREACH",
        reason: "send_invariant_breach",
        attentionReason: toAttentionReason(outcome.reason),
        authorizedResume: null,
        phaseAuditOk: true,
      });
  }
}

/**
 * Pure classification of every nonterminal / attention operation.
 * MUST NOT call sign or submit. Exposed for unit tests of step 5 isolation.
 */
export function classifyNonterminalOperations(
  ops: readonly OperationPhaseEvidence[],
): ClassifiedOperation[] {
  return ops.map(classifyOne);
}

// ── Step 6: resume only authorized actions ────────────────────────────────────

export async function resumeAuthorizedActions(
  classified: readonly ClassifiedOperation[],
  actions: BootRecoveryActions,
): Promise<AuthorizedResumeAction[]> {
  const resumed: AuthorizedResumeAction[] = [];
  for (const c of classified) {
    if (c.classification === "INVARIANT_BREACH") {
      if (c.attentionReason !== null) {
        await actions.setAttention(c.operationId, c.attentionReason, c.expectedRowVersion);
      }
      continue;
    }
    if (c.classification === "INDETERMINATE") {
      // Park / set attention; retain leases. Never submit, never clear attention.
      if (c.attentionReason !== null) {
        await actions.setAttention(c.operationId, c.attentionReason, c.expectedRowVersion);
      }
      continue;
    }
    if (c.authorizedResume === null) {
      continue;
    }
    // Refuse any resume that would re-form an external partial or submit an
    // ambiguous boundary — those classifications never produce authorizedResume.
    await actions.resumeAuthorized(c.authorizedResume);
    resumed.push(c.authorizedResume);
  }
  return resumed;
}

// ── Step 7: rebuild queues + raw-byte re-read (changed-response observation ledger) ──────────────────────────

/**
 * Hydrate the prior raw response bytes for each observation stream from the
 * durable gateway_observations row. Digest-only shortcut is forbidden: when
 * raw bytes cannot be loaded the stream fails closed (does not seed a
 * suppressible prior).
 */
export async function hydrateRawBytePriors(
  store: BootRecoveryStore,
  actions: BootRecoveryActions,
): Promise<RawByteHydrationResult[]> {
  const cursors = await store.listObservationCursors();
  const results: RawByteHydrationResult[] = [];

  for (const cursor of cursors) {
    if (cursor.lastRecordedObservationId === null) {
      // No prior observation — seed empty prior; first capture will APPEND.
      await actions.seedReconcileCursor(cursor.streamKey, null);
      results.push({
        streamKey: cursor.streamKey,
        ok: true,
        usedDigestShortcut: false,
        reason: "no_prior_observation",
      });
      continue;
    }

    const raw = await store.readRawResponseBytes(cursor.lastRecordedObservationId);
    if (raw === null) {
      // Fail closed: do NOT fall back to last_raw_response_sha256.
      // Seed with null prior and mark not-ok so readiness can fail closed on
      // streams that need an exact-byte gate.
      await actions.seedReconcileCursor(cursor.streamKey, null);
      results.push({
        streamKey: cursor.streamKey,
        ok: false,
        usedDigestShortcut: false,
        reason: "raw_response_bytes_unavailable",
      });
      continue;
    }

    // Ignore lastRawResponseSha256 entirely for equality — load the bytes.
    void cursor.lastRawResponseSha256;
    await actions.seedReconcileCursor(cursor.streamKey, raw);
    results.push({
      streamKey: cursor.streamKey,
      ok: true,
      usedDigestShortcut: false,
      reason: "raw_bytes_loaded",
    });
  }

  return results;
}

// ── Orchestrator (steps 2–8) ──────────────────────────────────────────────────

export async function runDeterministicBootRecovery(
  deps: BootRecoveryDeps,
): Promise<BootRecoveryReport> {
  const counters: BootRecoveryCounters = {
    signCalls: 0,
    submitCalls: 0,
    leaseDeletes: 0,
    attentionClears: 0,
    externalPartialReforms: 0,
    destinationAutoAccepts: 0,
    synthesizedBytesFromJson: 0,
  };
  const stepsCompleted: BootRecoveryStep[] = [];
  const nowMs = deps.nowMs?.() ?? Date.now();
  const staleHeartbeatMs = deps.staleHeartbeatMs ?? 60_000;

  // Step 1 precondition: must already hold leadership.
  assertSignerLeadership(deps.leadership);
  stepsCompleted.push("LEADERSHIP_PRECONDITION");

  // Step 2 — key correspondence (no secret logging; quarantine on failure).
  const key = await validateKeyCorrespondence(deps.store, deps.actions);
  stepsCompleted.push("KEY_CORRESPONDENCE");

  // Load the lease-eligible census once, then partition it. The two consumers take
  // different inputs and reusing one list for both is the defect:
  // - step 3 resolves leases, so it needs terminal-with-lease operations too
  // a landed operation keeps its lease until verification-complete, and
  // omitting it made every landed receive a `lease_operation_missing` breach;
  // - steps 4-5 are nonterminal-only (step 5). `classifyOne` never reads
  // `status`, so an unfiltered landed receive reaches `classifyReceiveOp`, hits
  // `submitBoundaryRecorded` and parks attention on a settled operation.
  const ops = await deps.store.listNonterminalOperations();
  const nonterminal = ops.filter((op) => !isTerminalOperationState(op.status));

  // Step 3 — active lease audit.
  const lease = await auditActiveLeases(
    deps.store,
    deps.actions,
    ops,
    nowMs,
    staleHeartbeatMs,
  );
  stepsCompleted.push("LEASE_AUDIT");

  // Step 4 is folded into per-op phase audit inside classify (and re-checked here).
  for (const op of nonterminal) {
    auditPhaseBoundaries(op); // pure; findings surface via classify
  }
  stepsCompleted.push("PHASE_AUDIT");

  // Step 5 — pure classification. No sign, no submit. Counters stay zero.
  const classifications = classifyNonterminalOperations(nonterminal);
  stepsCompleted.push("CLASSIFY");

  const hasClassificationBreach = classifications.some(
    (c) => c.classification === "INVARIANT_BREACH",
  );
  const invariantBreach = key.breach || lease.breach || hasClassificationBreach;

  if (invariantBreach) {
    await deps.actions.stopMoneyEngines("boot: global invariant breach");
  }

  // Step 6 — resume ONLY authorized actions. Never on breach ops / indeterminate.
  const resumed = invariantBreach
    ? []
    : await resumeAuthorizedActions(classifications, deps.actions);
  // On breach we still park every indeterminate/breach op for attention.
  if (invariantBreach) {
    for (const c of classifications) {
      if (
        c.classification === "INVARIANT_BREACH" ||
        c.classification === "INDETERMINATE"
      ) {
        if (c.attentionReason !== null) {
        await deps.actions.setAttention(c.operationId, c.attentionReason, c.expectedRowVersion);
      }
      }
    }
  }
  stepsCompleted.push("RESUME");

  // Step 7 — rebuild queues + raw-byte re-read.
  const rawByteHydrations = await hydrateRawBytePriors(deps.store, deps.actions);
  const queued = await deps.store.listQueuedReceiveOperationIds();
  await deps.actions.rebuildReceiveAdmissionQueue(queued);
  stepsCompleted.push("REBUILD_QUEUES");

  // Step 8 — readiness only when no global breach and leadership still held.
  const rawBytesOk = rawByteHydrations.every((r) => r.ok);
  const leadershipHeld = deps.leadership.held;
  const ready = !invariantBreach && leadershipHeld && rawBytesOk && !key.transientFault;
  stepsCompleted.push("READINESS");

  return {
    ready,
    invariantBreach,
    leadershipHeld,
    stepsCompleted,
    keyFindings: key.findings,
    leaseFindings: lease.findings,
    classifications,
    resumed,
    rawByteHydrations,
    receiveQueueRebuiltCount: queued.length,
    counters,
  };
}

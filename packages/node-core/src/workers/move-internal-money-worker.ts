// MOVE_INTERNAL money-worker pipeline.
//
// Lease → baselines OBSERVE under dual lease → form/sign under lease → single
// settle-safe submit → land INTERNAL_MOVE_LANDED. Ambiguous submit is
// reconcile-first only; never blind-retry.
//
// Pure orchestration over injected ports so offline composition tests and the
// generic-node shell share one step order. No private keys here. // contract-allow:order:frozen structural vocabulary

import type { DualBaselineCapture } from "../protocol/move-baseline.js";
import type { MoveReconcileOutcome } from "../protocol/reconcile/move.js";
import { ONLY_ATTEMPT_NO } from "../core/transaction-material-store.js";
import type { DurableMoveInner } from "../core/move-form-inner.js";
import type { SignedMoveSteps } from "../core/move-form-and-sign.js";
import {
  executeMoveSubmitClaim,
  MoveSubmitAmbiguousError,
  type MoveSubmitExecutionResult,
  type MoveSubmitOutcomeStatus,
} from "../core/move-submit-claim.js";
import type { PersistedExpectedArtifact } from "../core/move-baseline-binding.js";
import type { MoveOutcomePersistResult } from "../core/move-internal-landing-store.js";
import type { SqlQueryFn } from "../core/sql-query-fn.js";

export const MOVE_MONEY_WORKER_STEPS = [
  "LEASE",
  "BASELINE",
  "FORM",
  "SIGN",
  "SUBMIT",
  "LAND",
] as const;

export type MoveMoneyWorkerStep = (typeof MOVE_MONEY_WORKER_STEPS)[number];

/** Durable facts the worker reads to decide the next step (crash-resume). */
export interface MoveWorkerDurableProgress {
  readonly operationId: string;
  readonly operationStatus: "CREATED" | "NEEDS_ATTENTION" | "INTERNAL_MOVE_LANDED" | string;
  readonly rowVersion: number;
  /**
   * True only when MOVE_SOURCE and MOVE_DESTINATION are both ACTIVE for this
   * operation, under the same owner instance, each with a non-zero epoch.
   * count(*)≥2 any rows is NOT enough.
   */
  readonly bothLeasesHeld: boolean;
  readonly baselinesBound: boolean;
  readonly innerPreimagePersisted: boolean;
  readonly signaturesComplete: boolean;
  /** submit_decisions row exists for attempt 1 — never submit again. */
  readonly submitClaimed: boolean;
  /** Gateway attempt recorded with a settled-facing outcome (ACK/REJECT/AMBIGUOUS). */
  readonly submitOutcome: MoveSubmitOutcomeStatus | null;
  /**
   * Dual-path land proof present (both terminal observation ids on
   * move_observation_evidence). Never authorizes DONE/TERMINAL alone.
   */
  readonly landDualPathVerified: boolean;
  /**
   * Convenience mirror of status===INTERNAL_MOVE_LANDED. Never authorizes
   * DONE/TERMINAL alone — require operationStatus === "INTERNAL_MOVE_LANDED"
   * and landDualPathVerified (landed:true + CREATED must not TERMINAL).
   */
  readonly landed: boolean;
}

export interface MoveHeldLeasePair {
  readonly sourceWalletId: string;
  readonly sourceLeaseEpoch: bigint;
  readonly destinationWalletId: string;
  readonly destinationLeaseEpoch: bigint;
}

export interface MoveBaselineBound {
  readonly capture: DualBaselineCapture;
  readonly sourceT0ObservationId: string;
  readonly destinationT0ObservationId: string;
  readonly artifact: PersistedExpectedArtifact;
}

export interface MoveFormedMaterial {
  readonly durable: DurableMoveInner;
}

export interface MoveSignedMaterial {
  readonly signed: SignedMoveSteps;
}

export interface MoveSubmitMaterial {
  readonly result: MoveSubmitExecutionResult;
}

export interface MoveLandMaterial {
  readonly outcome: MoveReconcileOutcome;
  readonly persist: MoveOutcomePersistResult;
}

/**
 * Injected seams. Production binds SQL + gateway + vault; offline tests bind fakes.
 * Each method is a single irreversible boundary ownership (09 axiom: persist before
 * irreversible call; claim-before-submit).
 */
export interface MoveInternalMoneyWorkerPorts {
  readonly loadProgress: (operationId: string) => Promise<MoveWorkerDurableProgress>;

  /**
   * Acquire or re-read dual leases. Must return SOURCE+DEST ACTIVE under this owner
   * with current epochs — never invent epochs from stale process scratch alone.
   */
  readonly acquireDualLeases: (operationId: string) => Promise<
    | { readonly ok: true; readonly leases: MoveHeldLeasePair }
    | { readonly ok: false; readonly reason: string }
  >;

  readonly captureBaselines: (
    operationId: string,
    leases: MoveHeldLeasePair,
  ) => Promise<
    | { readonly ok: true; readonly bound: MoveBaselineBound }
    | { readonly ok: false; readonly reason: string }
  >;

  /**
   * Crash-resume: reload baseline binding from durable rows when process scratch is empty.
   * Returns null only when durable evidence is truly absent (not a permanent FAIL).
   */
  readonly loadBaselineBound: (operationId: string) => Promise<MoveBaselineBound | null>;

  readonly formInner: (
    operationId: string,
    bound: MoveBaselineBound,
  ) => Promise<
    | { readonly ok: true; readonly formed: MoveFormedMaterial }
    | { readonly ok: false; readonly reason: string }
  >;

  readonly signUnderLeases: (
    operationId: string,
    leases: MoveHeldLeasePair,
  ) => Promise<
    | { readonly ok: true; readonly signed: MoveSignedMaterial }
    | { readonly ok: false; readonly reason: string }
  >;

  /**
   * Crash-resume: reload completed signed transaction from durable rows when scratch empty.
   */
  readonly loadSignedMaterial: (operationId: string) => Promise<MoveSignedMaterial | null>;

  /**
   * Claim-and-submit once. Production MUST bind executeMoveSubmitClaim (see
   * bindExecuteMoveSubmitClaimOnce): losing the mint → executed=false → caller
   * reloads durable claim; HOLD_RECONCILE only if claim row exists.
   */
  readonly submitOnce: (
    operationId: string,
    signed: MoveSignedMaterial,
  ) => Promise<
    | { readonly ok: true; readonly submitted: MoveSubmitMaterial }
    | { readonly ok: false; readonly reason: string; readonly ambiguous?: boolean }
  >;

  /**
   * Post-submit / ambiguous path: observe both heads, classifyMoveReconcile,
   * persistMoveOutcome ONLY on LANDED_VERIFIED. Never opens a second submit.
   */
  readonly reconcileAndLand: (
    operationId: string,
    progress: MoveWorkerDurableProgress,
  ) => Promise<
    | { readonly ok: true; readonly land: MoveLandMaterial }
    | { readonly ok: false; readonly reason: string; readonly holdReconcile?: boolean }
  >;
}

export type MoveMoneyWorkerAdvance =
  | {
      readonly kind: "ADVANCED";
      readonly step: MoveMoneyWorkerStep;
      readonly operationId: string;
      readonly detail?: string;
    }
  | {
      readonly kind: "TERMINAL";
      readonly operationId: string;
      readonly status: "INTERNAL_MOVE_LANDED";
    }
  | {
      readonly kind: "HOLD_RECONCILE";
      readonly operationId: string;
      readonly reason: string;
      /** True when a submit claim already exists — resubmit is forbidden. */
      readonly submitClaimed: boolean;
    }
  | {
      readonly kind: "WAITING";
      readonly operationId: string;
      readonly reason: string;
    }
  | {
      readonly kind: "FAILED";
      readonly operationId: string;
      readonly step: MoveMoneyWorkerStep | "LOAD";
      readonly reason: string;
    };

/**
 * Next step from durable progress. Structural: submitClaimed gates submit
 * a crashed worker after claim never re-enters SUBMIT.
 * DONE requires dual-path land proof AND durable operationStatus INTERNAL_MOVE_LANDED.
 * landed:true alone (e.g. with status CREATED) never satisfies DONE (Fake LANDED).
 */
export function nextMoveMoneyWorkerStep(
  progress: MoveWorkerDurableProgress,
): MoveMoneyWorkerStep | "DONE" {
  if (
    progress.landDualPathVerified &&
    progress.operationStatus === "INTERNAL_MOVE_LANDED"
  ) {
    return "DONE";
  }
  // Status pretends landed without dual-path proof → re-enter LAND to re-proof, never DONE.
  // landed:true + dual-path without status LANDED also re-enters LAND (never DONE on flag alone).
  if (
    progress.landDualPathVerified ||
    progress.operationStatus === "INTERNAL_MOVE_LANDED" ||
    progress.landed
  ) {
    return "LAND";
  }
  if (!progress.bothLeasesHeld) return "LEASE";
  if (!progress.baselinesBound) return "BASELINE";
  if (!progress.innerPreimagePersisted) return "FORM";
  if (!progress.signaturesComplete) return "SIGN";
  // Step 9: once claimed, only reconcile/land — never SUBMIT again.
  if (!progress.submitClaimed) return "SUBMIT";
  // Claimed: always land via observation. ACK without landing still needs.
  return "LAND";
}

/** After submitOnce: HOLD_RECONCILE only if durable claim row is true. */
async function holdOrFailAfterSubmit(
  ports: MoveInternalMoneyWorkerPorts,
  operationId: string,
  reason: string,
): Promise<MoveMoneyWorkerAdvance> {
  let durable: MoveWorkerDurableProgress;
  try {
    durable = await ports.loadProgress(operationId);
  } catch (err) {
    return {
      kind: "FAILED",
      operationId,
      step: "SUBMIT",
      reason: `post-submit progress reload failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  if (durable.submitClaimed) {
    return {
      kind: "HOLD_RECONCILE",
      operationId,
      reason,
      submitClaimed: true,
    };
  }
  return {
    kind: "FAILED",
    operationId,
    step: "SUBMIT",
 reason: `${reason} — durable submit claim missing; refuse HOLD without claim`,
  };
}

/**
 * One atomic advance along. Call in a loop until TERMINAL / HOLD /
 * WAITING / FAILED. Reconcile-first is enforced when submitClaimed or after AMBIGUOUS.
 */
export async function advanceMoveInternalMoneyWorker(
  ports: MoveInternalMoneyWorkerPorts,
  operationId: string,
  /** Optional scratch from prior advances in the same process (leases/form material). */
  scratch: MoveWorkerScratch = {},
): Promise<MoveMoneyWorkerAdvance> {
  let progress: MoveWorkerDurableProgress;
  try {
    progress = await ports.loadProgress(operationId);
  } catch (err) {
    return {
      kind: "FAILED",
      operationId,
      step: "LOAD",
      reason: err instanceof Error ? err.message : String(err),
    };
  }

  if (progress.operationId !== operationId) {
    return {
      kind: "FAILED",
      operationId,
      step: "LOAD",
      reason: `progress operationId mismatch: ${progress.operationId}`,
    };
  }

  const step = nextMoveMoneyWorkerStep(progress);
  if (step === "DONE") {
    // Belt: TERMINAL only when dual-path proof AND durable status INTERNAL_MOVE_LANDED.
    // landed convenience flag must not short-circuit a CREATED (or other) durable status.
    if (!progress.landDualPathVerified) {
      return {
        kind: "HOLD_RECONCILE",
        operationId,
        reason: "refusing DONE/TERMINAL without verified dual-path land proof",
        submitClaimed: progress.submitClaimed,
      };
    }
    if (progress.operationStatus !== "INTERNAL_MOVE_LANDED") {
      return {
        kind: "HOLD_RECONCILE",
        operationId,
        reason:
          "refusing DONE/TERMINAL without durable operation status INTERNAL_MOVE_LANDED",
        submitClaimed: progress.submitClaimed,
      };
    }
    return { kind: "TERMINAL", operationId, status: "INTERNAL_MOVE_LANDED" };
  }

  switch (step) {
    case "LEASE": {
      const acquired = await ports.acquireDualLeases(operationId);
      if (!acquired.ok) {
        return {
          kind: "WAITING",
          operationId,
          reason: `lease: ${acquired.reason}`,
        };
      }
      scratch.leases = acquired.leases;
      return { kind: "ADVANCED", step: "LEASE", operationId };
    }
    case "BASELINE": {
      const leases = await ensureLeases(ports, operationId, scratch);
      if (leases === null) {
        return {
          kind: "WAITING",
          operationId,
          reason: "baseline: could not resolve held lease epochs",
        };
      }
      const bound = await ports.captureBaselines(operationId, leases);
      if (!bound.ok) {
        // Missing Observation / Wave residual → WAITING (retry next tick). Ambiguous
        // head under held leases is also non-terminal; caller may escalate separately.
        return {
          kind: "WAITING",
          operationId,
          reason: `baseline: ${bound.reason}`,
        };
      }
      scratch.bound = bound.bound;
      return { kind: "ADVANCED", step: "BASELINE", operationId };
    }
    case "FORM": {
      // Crash-resume: durable baselinesBound + empty scratch → reload, never permanent FAILED.
      let bound = scratch.bound;
      if (bound === undefined) {
        const reloaded = await ports.loadBaselineBound(operationId);
        if (reloaded === null) {
          return {
            kind: "WAITING",
            operationId,
            reason: "form: baselinesBound durable but bound material not yet reloadable",
          };
        }
        bound = reloaded;
        scratch.bound = bound;
      }
      const formed = await ports.formInner(operationId, bound);
      if (!formed.ok) {
        return {
          kind: "FAILED",
          operationId,
          step: "FORM",
          reason: formed.reason,
        };
      }
      scratch.formed = formed.formed;
      return { kind: "ADVANCED", step: "FORM", operationId };
    }
    case "SIGN": {
      const leases = await ensureLeases(ports, operationId, scratch);
      if (leases === null) {
        return {
          kind: "WAITING",
          operationId,
          reason: "sign: could not re-validate held SOURCE+DEST lease epochs",
        };
      }
      const signed = await ports.signUnderLeases(operationId, leases);
      if (!signed.ok) {
        return {
          kind: "FAILED",
          operationId,
          step: "SIGN",
          reason: signed.reason,
        };
      }
      scratch.signed = signed.signed;
      return { kind: "ADVANCED", step: "SIGN", operationId };
    }
    case "SUBMIT": {
      // Defensive double-check: never submit when claim already exists.
      if (progress.submitClaimed) {
        return {
          kind: "HOLD_RECONCILE",
          operationId,
 reason: "submit claimed — reconcile-first, never resubmit",
          submitClaimed: true,
        };
      }
      // Re-validate SOURCE+DEST leases before irreversible submit (stolen → WAITING).
      const submitLeases = await ensureLeases(ports, operationId, scratch);
      if (submitLeases === null) {
        return {
          kind: "WAITING",
          operationId,
          reason: "submit: could not re-validate held SOURCE+DEST lease epochs",
        };
      }
      // Crash-resume: signaturesComplete + empty scratch → reload signed material.
      let signed = scratch.signed;
      if (signed === undefined) {
        const reloaded = await ports.loadSignedMaterial(operationId);
        if (reloaded === null) {
          return {
            kind: "WAITING",
            operationId,
            reason: "submit: signaturesComplete durable but signed material not yet reloadable",
          };
        }
        signed = reloaded;
        scratch.signed = signed;
      }
      const submitted = await ports.submitOnce(operationId, signed);
      // Never trust injectables for claim — reload durable progress after submitOnce.
      if (!submitted.ok) {
        if (submitted.ambiguous === true) {
          return holdOrFailAfterSubmit(ports, operationId, submitted.reason);
        }
        return {
          kind: "FAILED",
          operationId,
          step: "SUBMIT",
          reason: submitted.reason,
        };
      }
      const outcome = submitted.submitted.result.recordedOutcome;
      if (outcome !== null && outcome.status === "AMBIGUOUS") {
        return holdOrFailAfterSubmit(
          ports,
          operationId,
 "submit transport AMBIGUOUS — reconcile-first, never resubmit",
        );
      }
      if (submitted.submitted.result.executed === false) {
        return holdOrFailAfterSubmit(
          ports,
          operationId,
 "submit mint lost — reconcile-first, never resubmit",
        );
      }
      // Successful exchange: still require durable claim before advancing.
      const afterOk = await ports.loadProgress(operationId);
      if (!afterOk.submitClaimed) {
        return {
          kind: "FAILED",
          operationId,
          step: "SUBMIT",
 reason: "submit reported executed but durable submit claim missing",
        };
      }
      scratch.submitted = submitted.submitted;
      return {
        kind: "ADVANCED",
        step: "SUBMIT",
        operationId,
        detail: outcome?.status ?? "executed",
      };
    }
    case "LAND": {
      // Re-validate SOURCE+DEST leases before land/reconcile (stolen → WAITING).
      const landLeases = await ensureLeases(ports, operationId, scratch);
      if (landLeases === null) {
        return {
          kind: "WAITING",
          operationId,
          reason: "land: could not re-validate held SOURCE+DEST lease epochs",
        };
      }
      const land = await ports.reconcileAndLand(operationId, progress);
      if (!land.ok) {
        if (land.holdReconcile === true) {
          return {
            kind: "HOLD_RECONCILE",
            operationId,
            reason: land.reason,
            submitClaimed: progress.submitClaimed,
          };
        }
        return {
          kind: "FAILED",
          operationId,
          step: "LAND",
          reason: land.reason,
        };
      }
      if (land.land.outcome.kind !== "LANDED_VERIFIED") {
        return {
          kind: "HOLD_RECONCILE",
          operationId,
          reason: `reconcile ${land.land.outcome.kind} — hold leases, never resubmit`,
          submitClaimed: progress.submitClaimed,
        };
      }
      // Dual-path LANDED_VERIFIED requires both path proof slots.
      const outcome = land.land.outcome;
      if (
        outcome.kind === "LANDED_VERIFIED" &&
        (outcome.sourcePath === undefined || outcome.destinationPath === undefined)
      ) {
        return {
          kind: "HOLD_RECONCILE",
          operationId,
          reason: "LANDED_VERIFIED missing dual-path proof — refuse TERMINAL",
          submitClaimed: progress.submitClaimed,
        };
      }
      if (land.land.persist.kind !== "PERSISTED") {
        return {
          kind: "HOLD_RECONCILE",
          operationId,
          reason: `land persist ${land.land.persist.kind}`,
          submitClaimed: progress.submitClaimed,
        };
      }
      if (land.land.persist.state !== "INTERNAL_MOVE_LANDED") {
        return {
          kind: "FAILED",
          operationId,
          step: "LAND",
          reason: `unexpected land state ${land.land.persist.state}`,
        };
      }
      // TERMINAL only when dual-path verified AND durable INTERNAL_MOVE_LANDED.
      // landed:true + dual-path with status still CREATED must not emit TERMINAL.
      const afterLand = await ports.loadProgress(operationId);
      if (!afterLand.landDualPathVerified) {
        return {
          kind: "HOLD_RECONCILE",
          operationId,
          reason: "land persist ok but durable dual-path verification not yet visible",
          submitClaimed: afterLand.submitClaimed,
        };
      }
      if (afterLand.operationStatus !== "INTERNAL_MOVE_LANDED") {
        return {
          kind: "HOLD_RECONCILE",
          operationId,
          reason:
            "land persist ok but durable operation status not INTERNAL_MOVE_LANDED — refuse TERMINAL",
          submitClaimed: afterLand.submitClaimed,
        };
      }
      return { kind: "TERMINAL", operationId, status: "INTERNAL_MOVE_LANDED" };
    }
    default: {
      const _exhaustive: never = step;
      return {
        kind: "FAILED",
        operationId,
        step: "LOAD",
        reason: `unknown step ${String(_exhaustive)}`,
      };
    }
  }
}

export interface MoveWorkerScratch {
  leases?: MoveHeldLeasePair;
  bound?: MoveBaselineBound;
  formed?: MoveFormedMaterial;
  signed?: MoveSignedMaterial;
  submitted?: MoveSubmitMaterial;
}

/**
 * Always re-validate via acquireDualLeases (owner+epoch). Scratch is a cache of the last
 * verified pair only — never trusted past expiry/steal without a re-read.
 */
async function ensureLeases(
  ports: MoveInternalMoneyWorkerPorts,
  operationId: string,
  scratch: MoveWorkerScratch,
): Promise<MoveHeldLeasePair | null> {
  const acquired = await ports.acquireDualLeases(operationId);
  if (!acquired.ok) {
    delete scratch.leases;
    return null;
  }
  scratch.leases = acquired.leases;
  return acquired.leases;
}

export interface RunMoveInternalMoneyWorkerOptions {
  readonly maxAdvances?: number;
}

/**
 * Drive one MOVE from CREATED through INTERNAL_MOVE_LANDED (or HOLD/FAIL).
 * Offline composition tests call this with fake ports; production shell calls
 * once per tick per eligible operation.
 */
export async function runMoveInternalMoneyWorker(
  ports: MoveInternalMoneyWorkerPorts,
  operationId: string,
  options: RunMoveInternalMoneyWorkerOptions = {},
): Promise<{
  readonly terminal: MoveMoneyWorkerAdvance;
  readonly trail: readonly MoveMoneyWorkerAdvance[];
  readonly attemptNo: typeof ONLY_ATTEMPT_NO;
}> {
  const maxAdvances = options.maxAdvances ?? 16;
  const trail: MoveMoneyWorkerAdvance[] = [];
  const scratch: MoveWorkerScratch = {};

  for (let i = 0; i < maxAdvances; i += 1) {
    const result = await advanceMoveInternalMoneyWorker(ports, operationId, scratch);
    trail.push(result);
    if (
      result.kind === "TERMINAL" ||
      result.kind === "HOLD_RECONCILE" ||
      result.kind === "WAITING" ||
      result.kind === "FAILED"
    ) {
      return { terminal: result, trail, attemptNo: ONLY_ATTEMPT_NO };
    }
  }

  const overflow: MoveMoneyWorkerAdvance = {
    kind: "FAILED",
    operationId,
    step: "LOAD",
    reason: `exceeded maxAdvances=${maxAdvances}`,
  };
  trail.push(overflow);
  return { terminal: overflow, trail, attemptNo: ONLY_ATTEMPT_NO };
}

export interface CreateSqlMoveWorkerProgressLoaderOptions {
  /** Required for bothLeasesHeld: SOURCE+DEST ACTIVE under this owner with epochs. */
  readonly ownerInstanceId: string;
}

/**
 * Durable progress reader for crash-resume (gates). Lives in node-core so
 * the app shell never names submit ledgers (write-path marker census).
 */
export function createSqlMoveWorkerProgressLoader(
  query: SqlQueryFn,
  options: CreateSqlMoveWorkerProgressLoaderOptions,
): MoveInternalMoneyWorkerPorts["loadProgress"] {
  const ownerInstanceId = options.ownerInstanceId;
  return async (operationId) => {
    const opRows = await query(
      `SELECT status::text AS status, row_version::text AS row_version
         FROM operations WHERE id = $1::uuid AND kind = 'MOVE_INTERNAL'`,
      [operationId],
    );
    const row = opRows[0] as { status: string; row_version: string } | undefined;
    if (row === undefined) {
      throw new Error(`MOVE operation ${operationId} not found`);
    }
    // Both roles + this owner + non-null epoch — not count(*)≥2 any ACTIVE rows.
    const leaseRows = await query(
      `SELECT lease_role::text AS lease_role,
              owner_instance_id::text AS owner_instance_id,
              lease_epoch::text AS lease_epoch
         FROM wallet_active_leases
        WHERE operation_id = $1::uuid
          AND lease_role IN ('MOVE_SOURCE', 'MOVE_DESTINATION')`,
      [operationId],
    );
    const leases = leaseRows as readonly {
      lease_role: string;
      owner_instance_id: string;
      lease_epoch: string;
    }[];
    const epochHeld = (epoch: string | null | undefined): boolean => {
      if (epoch === null || epoch === undefined || epoch === "") return false;
      try {
        return BigInt(epoch) > 0n;
      } catch {
        return false;
      }
    };
    const source = leases.find(
      (r) =>
        r.lease_role === "MOVE_SOURCE" &&
        r.owner_instance_id === ownerInstanceId &&
        epochHeld(r.lease_epoch),
    );
    const destination = leases.find(
      (r) =>
        r.lease_role === "MOVE_DESTINATION" &&
        r.owner_instance_id === ownerInstanceId &&
        epochHeld(r.lease_epoch),
    );
    const bothLeasesHeld = source !== undefined && destination !== undefined;
    const evidenceRows = await query(
      `SELECT source_t0_observation_id::text AS source_t0,
              destination_t0_observation_id::text AS dest_t0,
              source_terminal_observation_id::text AS source_term,
              destination_terminal_observation_id::text AS dest_term
         FROM move_observation_evidence WHERE operation_id = $1::uuid`,
      [operationId],
    );
    const evidence = evidenceRows[0] as
      | {
          source_t0: string | null;
          dest_t0: string | null;
          source_term: string | null;
          dest_term: string | null;
        }
      | undefined;
    const baselinesBound =
      evidence !== undefined &&
      typeof evidence.source_t0 === "string" &&
      evidence.source_t0.length > 0 &&
      typeof evidence.dest_t0 === "string" &&
      evidence.dest_t0.length > 0;
    // Dual-path verified = both terminal observation ids present.
    const landDualPathVerified =
      evidence !== undefined &&
      typeof evidence.source_term === "string" &&
      evidence.source_term.length > 0 &&
      typeof evidence.dest_term === "string" &&
      evidence.dest_term.length > 0;
    const attemptRows = await query(
      `SELECT attempt_phase::text AS attempt_phase, step_2_signature
         FROM operation_transactions
        WHERE operation_id = $1::uuid AND attempt_no = $2`,
      [operationId, ONLY_ATTEMPT_NO],
    );
    const attempt = attemptRows[0] as
      | { attempt_phase: string | null; step_2_signature: string | null }
      | undefined;
    const phase = attempt?.attempt_phase ?? null;
    const sig2 = attempt?.step_2_signature ?? null;
    const claimRows = await query(
      `SELECT 1 AS present FROM submit_decisions
        WHERE operation_id = $1::uuid AND transaction_attempt_no = $2`,
      [operationId, ONLY_ATTEMPT_NO],
    );
    const submitClaimed = claimRows.length > 0;
    let submitOutcome: MoveSubmitOutcomeStatus | null = null;
    if (submitClaimed) {
      const attRows = await query(
        `SELECT transport_outcome::text AS transport_outcome
           FROM gateway_submit_attempts
          WHERE operation_id = $1::uuid AND transaction_attempt_no = $2
          ORDER BY started_at DESC LIMIT 1`, // contract-allow:order:frozen structural vocabulary
        [operationId, ONLY_ATTEMPT_NO],
      );
      const t = (attRows[0] as { transport_outcome: string } | undefined)?.transport_outcome;
      if (t === "ACK" || t === "REJECT") submitOutcome = t;
      else if (t === "INDETERMINATE") submitOutcome = "AMBIGUOUS";
    }
    return {
      operationId,
      operationStatus: row.status,
      rowVersion: Number(row.row_version),
      bothLeasesHeld,
      baselinesBound,
      innerPreimagePersisted:
        phase !== null &&
        [
          "INNER_PREIMAGE_PERSISTED",
          "STEP1_SIGNATURE_PERSISTED",
          "STEP2_PREIMAGE_PERSISTED",
          "STEP2_SIGNATURE_PERSISTED",
          "SETTLED_BODY_PERSISTED",
        ].includes(phase),
      signaturesComplete: typeof sig2 === "string" && sig2.length > 0,
      submitClaimed,
      submitOutcome,
      landDualPathVerified,
      landed: row.status === "INTERNAL_MOVE_LANDED",
    };
  };
}

/**
 * Prefer this binding for submitOnce: run through executeMoveSubmitClaim so the DB mint
 * is the sole second-submit gate.
 */
export function bindExecuteMoveSubmitClaimOnce(deps: {
  readonly claimStore: import("../core/move-submit-claim.js").MoveSubmitClaimStore;
  readonly authorizationFor: (
    operationId: string,
  ) => import("../gateway/submit.js").SubmitAuthorization | Promise<import("../gateway/submit.js").SubmitAuthorization>;
  readonly submitOptions: import("../gateway/submit.js").SubmitGatewayActionOptions;
}): MoveInternalMoneyWorkerPorts["submitOnce"] {
  const { claimStore, authorizationFor, submitOptions } = deps;
  return async (operationId, signed) => {
    const authorization = await authorizationFor(operationId);
    try {
      const result = await executeMoveSubmitClaim({
        authorization,
        signedTransaction: JSON.parse(signed.signed.completedTransactionText) as unknown,
        claimStore,
        submit: submitOptions,
      });
      return { ok: true, submitted: { result } };
    } catch (err) {
      if (err instanceof MoveSubmitAmbiguousError) {
        return {
          ok: false,
          reason: err.message,
          ambiguous: true,
        };
      }
      return {
        ok: false,
        reason: err instanceof Error ? err.message : String(err),
      };
    }
  };
}

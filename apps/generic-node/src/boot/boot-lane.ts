// The boot lane: the startup sequencing that makes this rule true structurally:
//
//   "Boot recovery runs after schema validation and vault unlock but before
//   readiness and before any normal money worker."
//
// Enforced sequence (a manifest or script that reverses any part of this is a
// spec violation, not a style choice):
//
//   0. Configuration validation — runs in main.ts BEFORE this lane is
//      invoked (fail-fast, process exits 1; nothing below ever sees an
//      invalid configuration).
//   1. runMigrations — database migrations, then the post-migration
//      assertions; only after both does the `schema` readiness gate open.
//   2. unlockVault — vault availability; the `vault` gate opens.
//   3. acquireSignerLeadership — the process-wide signer leadership lock;
//      the `leadership` gate opens.
//  4. runBootRecovery — the deterministic boot-recovery walk. Pure
//      classification then authorized resume; readiness stays false on any
//      global invariant breach. Money workers never start after a breach.
//   5. performValidatedGatewayRead — one validated gateway read; the
//      `gateway` gate opens.
// 6. Readiness is the readiness gating conjunction (schema ∧ vault ∧
//      observation; database is live-probed by /health/ready). Signer
//      leadership is acquired in step 3 and stamped for reporting, but
//  does NOT gate the ready verdict. Boot recovery must also
//      report ready. On invariant breach the early return keeps readiness
//      false and retains leadership (quarantine so a second instance cannot
//      sign into a broken inventory). On retryable/incomplete recovery
//      (ready===false AND invariantBreach===false, both explicit) leadership
//  is released so a standby or restart can acquire it; a failed
//      release retains the handle. Missing/undefined breach is fail-closed
//      quarantine. Money workers still start only after leadership is held —
//      the lane never starts them without the handle from step 3.
//
// WIRING POINT: `assertPostMigrationReadiness` is where the composition root
// plugs in `assertPrivilegeReadiness` from `@zucoins/node-core` (
// the schema-role rule). That check verifies the `node_core_app` role exists and
// that DELETE/TRUNCATE revokes hold on public tables, and throws
// PrivilegeReadinessError (fail-closed) when the structural custody-integrity
// guarantee is absent. Wire it immediately after migrations and before any
// money surface. This module stays driver-free: the shell adapts its Pool.
//
// Migration overlap contract (rolling-deploy test depends
// on this): the injected `runMigrations` MUST be safe while an old instance
// is still running — every migration idempotent (IF NOT EXISTS / additive
// only) and backward-compatible with the previous release's code. A
// migration strategy that assumes exactly one live instance is incompatible
// with a zero-downtime rolling deploy.
//
// Every step is injected: this module never touches the network, the
// database, or the vault itself — those surfaces are owned by their own
// tickets. Fail-closed throughout: any step that throws halts the lane,
// leaves readiness false (liveness unaffected), and reports the failed step
// name — never a swallowed error, never a degraded boot.

import { shouldStartMoneyWorkersAfterRecovery } from "@zucoins/node-core";

import type { NodeReadiness } from "./readiness.js";

export interface BootLogger {
  info(message: string): void;
  error(message: string, err?: unknown): void;
}

export interface SignerLeadershipHandle {
  release(): Promise<void> | void;
}

/**
 * Minimal shape of the boot-recovery report the lane consumes.
 * The full `BootRecoveryReport` from `@zucoins/node-core` satisfies this;
 * the lane only needs the readiness / breach bits.
 */
export interface BootRecoveryLaneReport {
  readonly ready: boolean;
  readonly invariantBreach: boolean;
}

export interface BootLaneDeps {
  readonly readiness: NodeReadiness;
  readonly logger: BootLogger;
  readonly runMigrations: () => Promise<void>;
  readonly assertPostMigrationReadiness?: () => Promise<void>;
  readonly unlockVault: () => Promise<void>;
  readonly acquireSignerLeadership: () => Promise<SignerLeadershipHandle>;
  /**
   * Called synchronously with the held handle immediately
   * after acquire and BEFORE boot-recovery / gateway / money-worker awaits.
   * Composition stamps the shutdown registry here so SIGTERM during recovery
   * observes a live handle and a boot-phase inflight token (never an
   * empty-inflight clean flush). May return a wrapped handle; the lane adopts
   * it for all subsequent release paths.
   */
  readonly onLeadershipAcquired?: (
    leadership: SignerLeadershipHandle,
  ) => SignerLeadershipHandle | void;
  /**
   * Settle the boot-phase inflight token opened at stamp.
   * Invoked on every post-stamp exit (ready, breach-hold, failure-before-unlock)
   * so graceful-stop flush can empty only after the lane is done. Optional for
   * harnesses that do not wire the shutdown registry.
   */
  readonly onBootPhaseComplete?: () => void;
  /**
   * The deterministic boot-recovery walk. Required — the lane never
   * fail-opens past leadership without recovery. Harnesses that only exercise
   * leadership/gateway gates must pass an explicit no-op that returns
   * `{ ready: true, invariantBreach: false }` (never omit the dep).
   */
  readonly runBootRecovery: (
    leadership: SignerLeadershipHandle,
  ) => Promise<BootRecoveryLaneReport>;
  readonly performValidatedGatewayRead: () => Promise<void>;
  readonly startMoneyWorkers: (leadership: SignerLeadershipHandle) => Promise<void> | void;
}

export interface BootLaneResult {
  readonly ready: boolean;
  readonly failedStep?: string;
  readonly leadership?: SignerLeadershipHandle;
  readonly bootRecovery?: BootRecoveryLaneReport;
  /**
   * Set when retryable recovery attempted release but `release()` rejected.
   * Handle is retained (fail-closed); main must NOT treat this as a clean unlock.
   */
  readonly leadershipReleaseFailed?: boolean;
}

/**
 * How main should treat an incomplete boot.
 * - quarantine: leadership retained (invariant breach, or release failed) — stay up liveness-only.
 * - exit-for-reacquire: retryable recovery released leadership cleanly — process.exit(1).
 * - liveness-only: other incomplete steps (migrations/vault/…) — stay up, do not crash-loop.
 */
export type BootIncompleteDisposition =
  | "quarantine"
  | "exit-for-reacquire"
  | "liveness-only";

export function dispositionForIncompleteBoot(
  result: BootLaneResult,
): BootIncompleteDisposition {
  if (result.ready) {
    throw new Error("dispositionForIncompleteBoot called on a ready boot result");
  }
  if (result.leadership !== undefined || result.leadershipReleaseFailed === true) {
    return "quarantine";
  }
  // Clean retryable recovery release only — narrow blast radius (not every unwired surface).
  if (
    result.failedStep === "boot-recovery" &&
    result.bootRecovery?.ready === false &&
    result.bootRecovery.invariantBreach === false
  ) {
    return "exit-for-reacquire";
  }
  return "liveness-only";
}

export class BootLaneError extends Error {
  readonly step: string;

  constructor(step: string, cause: unknown) {
    super(
      `boot lane halted at step "${step}": ${cause instanceof Error ? cause.message : String(cause)}`,
    );
    this.name = "BootLaneError";
    this.step = step;
    this.cause = cause;
  }
}

export async function runBootLane(deps: BootLaneDeps): Promise<BootLaneResult> {
  const { readiness, logger } = deps;
  let leadership: SignerLeadershipHandle | undefined;

  try {
    await bootStep("migrations", async () => {
      await deps.runMigrations();
      await deps.assertPostMigrationReadiness?.();
    });
    readiness.markSchemaChecksPassed();
    logger.info("boot: schema checks passed (migrations applied)");

    await bootStep("vault-unlock", () => deps.unlockVault());
    readiness.setVaultAvailable(true);
    logger.info("boot: vault available");

    leadership = await bootStep("signer-leadership", () => deps.acquireSignerLeadership());
    readiness.setSignerLeadershipHeld(true);
    logger.info("boot: signer leadership acquired");
    // Stamp shutdown registry BEFORE any further await (boot-recovery etc.).
    // Adopt a wrapped handle so failure-path release clears the registry too
    // and shares the inflight refuse guard.
    const stamped = deps.onLeadershipAcquired?.(leadership);
    if (stamped !== undefined && stamped !== null) {
      leadership = stamped;
    }
    const heldLeadership = leadership;
    // Boot phase is open from stamp until every exit path below settles it.
    let bootPhaseSettled = false;
    const settleBootPhase = (): void => {
      if (bootPhaseSettled) return;
      bootPhaseSettled = true;
      deps.onBootPhaseComplete?.();
    };

    // Boot recovery. Required after leadership — never skip.
    // On invariant breach we keep leadership (so a second instance cannot
    // sign into a broken inventory) but never open readiness or start money
    // workers.
    if (typeof deps.runBootRecovery !== "function") {
      throw new BootLaneError(
        "boot-recovery",
        new Error("runBootRecovery is required — boot recovery must not be skipped"),
      );
    }
    const bootRecovery = await bootStep("boot-recovery", () =>
      deps.runBootRecovery(heldLeadership),
    );
    if (!bootRecovery.ready) {
      // Two failure classes — fail-CLOSED on the
      // quarantine bit. Release only when BOTH ready===false AND
      // invariantBreach===false are explicit. Missing / undefined / truthy
      // non-boolean breach → quarantine (custody-safe default). A buggy
      // adapter that omits the field must never unlock the SPOF lock.
      const explicitRetryable =
        bootRecovery.ready === false && bootRecovery.invariantBreach === false;
      const explicitBreach = bootRecovery.invariantBreach === true;

      if (explicitBreach || !explicitRetryable) {
        const why = explicitBreach
          ? "invariant breach"
          : "not-ready without explicit invariantBreach===false (fail-closed quarantine)";
        logger.error(
          `boot: recovery reported ${why} — readiness stays false, money workers not started, leadership retained (quarantine)`,
        );
        // Breach/hold: the lane is done, so settle the boot token —
        // a quarantined instance must still stop gracefully. The lock is kept
        // deliberately; graceful-stop releases it only if the money surface is
        // quiesced, and money workers never started here.
        settleBootPhase();
        return Object.freeze({
          ready: false,
          failedStep: "boot-recovery",
          leadership: heldLeadership,
          bootRecovery,
        });
      }

      // Retryable / incomplete (ready:false ∧ invariantBreach:false) → release
      // so a standby or restart can re-run recovery. Leaving the lock held
      // forever here is an operator-only deadlock (node SPOF).
      logger.error(
        "boot: recovery not ready (retryable) — releasing leadership so a replacement can recover",
      );
      // Settle the boot-phase token BEFORE the unlock attempt: the shutdown
      // registry refuses release while any tracked work remains, and the token
      // opened at stamp is still open here. Money workers never started on this
      // path, so no armed money surface is being bypassed.
      settleBootPhase();
      try {
        await Promise.resolve(heldLeadership.release());
      } catch (releaseErr: unknown) {
        // Do NOT clear readiness or drop the handle — a failed unlock must not
        // look like a clean handoff. Prefer retain+page over pretend-unlocked.
        logger.error(
          "boot: leadership release after retryable recovery failure also failed — retaining handle (fail-closed)",
          releaseErr,
        );
        return Object.freeze({
          ready: false,
          failedStep: "boot-recovery",
          leadership: heldLeadership,
          bootRecovery,
          leadershipReleaseFailed: true,
        });
      }
      readiness.setSignerLeadershipHeld(false);
      leadership = undefined;
      return Object.freeze({
        ready: false,
        failedStep: "boot-recovery",
        bootRecovery,
      });
    }
    logger.info("boot: deterministic recovery complete (no invariant breach)");

    await bootStep("gateway-read", () => deps.performValidatedGatewayRead());
    readiness.recordGatewayReadSuccess();
    logger.info("boot: validated gateway read succeeded");

    if (!readiness.snapshot().ready) {
      throw new BootLaneError("readiness", new Error("readiness conjunction incomplete"));
    }

    // Last step: money workers run only on the leadership holder and only when
    // boot recovery explicitly authorizes engine start
    // (shouldStartMoneyWorkersAfterRecovery). Stamp-side
    // readiness may already be true without leadership, but this lane only
    // reaches here with a held handle from step 3.
    if (!shouldStartMoneyWorkersAfterRecovery(bootRecovery)) {
      throw new BootLaneError(
        "money-workers",
        new Error("boot recovery refused money-worker start (ready/invariantBreach gate)"),
      );
    }
    await bootStep("money-workers", async () => {
      await deps.startMoneyWorkers(heldLeadership);
    });
    logger.info("boot: money workers started");
    settleBootPhase();
    return Object.freeze({ ready: true, leadership: heldLeadership, bootRecovery });
  } catch (err) {
    const step = stepThatFailed(err);
    // Fail-closed on partial boot: if leadership was acquired but a later
    // step failed, release it so a successor can run boot recovery. Only clear
    // the readiness bit after a confirmed release — a failed unlock retains
    // the handle (never pretend unlocked).
    // Exception: boot-recovery that returned not-ready already decided its own
    // disposition via the early returns above (quarantine hold or retryable
    // release).
    //
    // Settle the boot-phase token BEFORE unlock so releaseLeadership / the
    // wrapped release are not refused by the still-open boot token.
    // `settleBootPhase` is scoped inside the try, so call the dep directly —
    // `completeBootPhase` is idempotent. If other tracked work remains, or the
    // money surface is armed and not quiesced, release still refuses and we
    // retain the lock (the same hard-fail as graceful-stop's flush timeout)
    // rather than unlock under residual work.
    //
    // Defect C: the readiness leadership bit tracks the real lock. Flip
    // held=false only after a successful unlock; on refuse leave held=true so
    // consumers never observe "dropped" while the advisory lock is still ours.
    if (leadership !== undefined) {
      deps.onBootPhaseComplete?.();
      try {
        await Promise.resolve(leadership.release());
        readiness.setSignerLeadershipHeld(false);
        leadership = undefined;
      } catch (releaseErr: unknown) {
        logger.error(
          "boot: leadership release after lane failure also failed — retaining handle (fail-closed)",
          releaseErr,
        );
        logger.error(`boot: lane halted at step "${step}" — readiness stays false`, err);
        return Object.freeze({
          ready: false,
          failedStep: step,
          leadership,
          leadershipReleaseFailed: true,
        });
      }
    }
    logger.error(`boot: lane halted at step "${step}" — readiness stays false`, err);
    return Object.freeze({ ready: false, failedStep: step });
  }
}

function stepThatFailed(err: unknown): string {
  if (err instanceof BootLaneError) return err.step;
  return "unknown";
}

export async function bootStep<T>(
  step: string,
  run: () => Promise<T>,
): Promise<T> {
  try {
    return await run();
  } catch (cause) {
    throw new BootLaneError(step, cause);
  }
}

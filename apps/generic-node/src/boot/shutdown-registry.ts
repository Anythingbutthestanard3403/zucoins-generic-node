// Process-local the shutdown-sequence contract shutdown composition.
//
// Single shared SignerLeadership latch is (1) the acquire latch, (2) the
// signUnderLease deps.leadership, and (3) the withdraw target.
//
// Flush proof is NOT "opt-in trackInflight remembered by every caller":
//   - stampLeadership opens a boot-phase inflight token (settled by
//     completeBootPhase) so mid-boot empty-flush cannot unlock.
//   - The real signing chokepoint signUnderLease auto-tracks via
//     authority.trackSigningInflight (installed on this registry's latch;
//     tracker is freeze-on-first-install so it cannot be wiped).
//   - armMoneySurface / registerWorkerStop arm DURING boot (boot-lane runs
//     startMoneyWorkers while the boot token is still open). Boot token and
//     armed-surface gate both block unlock; settle does not disarm.
//   - Post-boot async entry also via runUnderLeadership (auto-tracks) after
//     arm. registerWorkerStop arms equivalently (no non-arming back door).
//     armMoneySurface refuses reopen after ENGINE_QUIESCE / authority
//     withdraw for the rest of the process.
//   - unlockLeadership is a single path (hooks + stamped wrapper); the
//     DB unlock target is retained until inner.release() succeeds.
//
// Two states are MONOTONIC for the process, never per-stamp-session (Defects
// D3/D4 — "unlock gate / authority latch is not monotonic across stamp
// transitions"):
//   - moneySurface: unarmed → armed → quiesced. Only registering a stop arms
//     it; only ENGINE_QUIESCE quiesces it. stampLeadership / clearLeadership /
//     unlock never reset it, so no restamp or clear-then-restamp can wipe the
//     armed-surface unlock gate while worker loops are still live.
//   - authority.held: set ONLY by tryAcquireSignerLeadership, which holds the
//     DB advisory lock. stampLeadership records the handle and the boot token;
//     it never mints authority, so a stamp after SIGNER_AUTHORITY_WITHDRAW (or
//     connection loss) cannot resurrect signing without a real acquire.

import { SignerLeadership } from "@zucoins/node-core";

import type { SignerLeadershipHandle } from "./boot-lane.js";

export interface StampedLeadershipHandle extends SignerLeadershipHandle {
  /**
   * Arm the money surface: register the ENGINE_QUIESCE stop and allow
   * {@link runUnderLeadership}. Callable while the boot-phase token is
   * still open (boot-lane invokes startMoneyWorkers before settle) and
   * after settle. Required before any post-boot work under the held lock.
   * Idempotent stop registration (each call pushes).
   */
  armMoneySurface(stop: () => void): void;
  /**
   * Run work under the held leadership lock. Always tracks the promise for
   * flush/release proof — callers never need trackInflight. Refuses
   * when leadership is absent, authority is withdrawn, engines are
   * quiescing, or (post-boot) the money surface is not armed. Mid-boot
   * (token still open) may run without arming for recovery work.
   */
  runUnderLeadership<T>(work: () => Promise<T>): Promise<T>;
}

export interface ShutdownRegistry {
  /** Shared in-process authority latch — acquire, withdraw, and signUnderLease. */
  readonly authority: SignerLeadership;
  /**
   * DB leadership handle. Undefined only when no instance holds the lock in
   * this process. Stamped synchronously on acquire via {@link stampLeadership}.
   */
  leadership: SignerLeadershipHandle | undefined;
  /**
   * Track a promise that must settle before LEADERSHIP_RELEASE. Prefer
   * {@link StampedLeadershipHandle.runUnderLeadership} for money/sign work
   * — that path always tracks without caller memory. This remains for
   * boot-recovery adapters and tests that already hold a bare promise.
   */
  trackInflight<T>(work: Promise<T>): Promise<T>;
  /**
   * ENGINE_QUIESCE callback. Arms the money surface equivalently to
   * {@link armMoneySurface} so a stop-only registration cannot empty-flush
   * unlock while residual sign work is still possible (Defect A2 / D1).
   * Arms while boot phase is still open — mid-boot registerWorkerStop must
   * not leave a permanent non-arming stop-only surface after settle.
   */
  registerWorkerStop(stop: () => void): void;
  /** Extra flush hooks beyond tracked inflight (optional external flushes). */
  registerFlusher(flush: () => Promise<void>): void;
  /**
   * Record the held handle and open a boot-phase inflight token. Call from the
   * acquire seam BEFORE returning to boot-lane (so recovery/signing awaits run
   * only after the registry observes the handle AND flush cannot empty-succeed
   * mid-boot).
   *
   * Records only. It never marks {@link authority} acquired — that belongs to
   * `tryAcquireSignerLeadership`, the one path that holds the DB advisory lock
   * (Defect D4). It also never resets the money-surface lifecycle, so a
   * re-stamp cannot disarm a live surface (Defect D3).
   */
  stampLeadership(handle: SignerLeadershipHandle): StampedLeadershipHandle;
  /**
   * Settle the boot-phase token opened by {@link stampLeadership}. Call when
   * the boot lane finishes under a held handle: ready return, invariant-breach
   * hold return, or failure path about to decide unlock policy. Idempotent.
   * Does not disarm an already-armed money surface (arm-during-boot sticks).
   */
  completeBootPhase(): void;
  /**
   * Arm money/sign surfaces. Registers `stop` for ENGINE_QUIESCE and opens
   * the runUnderLeadership gate. Callable while boot phase is still open
   * (production startMoneyWorkers runs before settle) and after settle.
   * Throws if no leadership is stamped, authority is withdrawn, or engines
   * already quiesced (no reopen after ENGINE_QUIESCE, for the whole process —
   * a re-stamp does not grant a fresh session).
   */
  armMoneySurface(stop: () => void): void;
  /**
   * Chokepoint for work under the held lock. Auto-tracks; see
   * {@link StampedLeadershipHandle.runUnderLeadership}.
   */
  runUnderLeadership<T>(work: () => Promise<T>): Promise<T>;
  /**
   * Clear a stamped handle without unlocking (tests / lost-connection path).
   * Deliberately leaves the money-surface lifecycle alone: losing the DB handle
   * does not stop live worker loops, so the armed-surface unlock gate must
   * survive a clear-then-restamp (Defect D3).
   */
  clearLeadership(): void;
  /** the shutdown-sequence hooks bound to this registry — pass straight to installGracefulStop. */
  hooks(): {
    withdrawSignerAuthority: () => void;
    stopWorkers: () => void;
    flushInFlight: () => Promise<void>;
    releaseLeadership: () => Promise<void>;
  };
  /** Test/inspection: number of unsettled tracked promises. */
  readonly inflightCount: number;
  /** Test/inspection: boot-phase token still open. */
  readonly bootPhaseOpen: boolean;
  /** Test/inspection: post-boot money surface armed (stop registered). */
  readonly moneySurfaceArmed: boolean;
  /** Test/inspection: ENGINE_QUIESCE has run (stopWorkers). */
  readonly enginesQuiesced: boolean;
}

function refuseReleaseMessage(count: number): string {
  return `refuse leadership release: ${count} in-flight work item(s) still tracked`;
}

export function createShutdownRegistry(): ShutdownRegistry {
  const authority = new SignerLeadership();
  /** Public handle slot — always the refuse-guard wrapper when set. */
  let leadership: StampedLeadershipHandle | undefined;
  /** Inner DB unlock target — retained until unlock succeeds (Defect B). */
  let innerHandle: SignerLeadershipHandle | undefined;
  const inflight = new Set<Promise<unknown>>();
  const workerStops: Array<() => void> = [];
  const inflightFlushers: Array<() => Promise<void>> = [];
  /** Resolves the boot-phase token; undefined when no open boot phase. */
  let settleBootPhase: (() => void) | undefined;
  /**
   * Money/sign surface lifecycle for the PROCESS, not for a stamp session:
   * `unarmed` → `armed` (a worker stop is registered) → `quiesced`
   * (ENGINE_QUIESCE ran). Monotonic — nothing but those two events moves it, so
   * stampLeadership / clearLeadership / unlock cannot wipe the armed-surface
   * unlock gate or reopen accept after quiesce (Defect D3 / A3).
   */
  let moneySurface: "unarmed" | "armed" | "quiesced" = "unarmed";

  /**
   * Add `work` to the tracked set and hand back the waitable, so a caller that
   * owns the work's completion (the boot-phase token) can also drop it from the
   * set synchronously. Returning it is the difference between "resolved" and
   * "no longer tracked": the `finally` below runs two microtasks after the
   * underlying promise settles, and a same-tick release check would still see
   * the entry.
   */
  function trackWaitable(work: Promise<unknown>): Promise<unknown> {
    // Waitable settles on fulfill or reject so flush is never stuck on a
    // rejected sign attempt, while still observing the work as in-flight.
    const waitable: Promise<unknown> = Promise.resolve(work).then(
      () => undefined,
      () => undefined,
    );
    inflight.add(waitable);
    void waitable.finally(() => {
      inflight.delete(waitable);
    });
    return waitable;
  }

  function trackInflightInternal<T>(work: Promise<T>): Promise<T> {
    trackWaitable(work);
    return work;
  }

  function assertNoInflight(): void {
    if (inflight.size > 0) {
      throw new Error(refuseReleaseMessage(inflight.size));
    }
  }

  function assertEnginesQuiescedForRelease(): void {
    // Armed money surfaces may still accept work until ENGINE_QUIESCE.
    // Empty inflight is not proof of completion while workers are still live.
    if (moneySurface === "armed") {
      throw new Error(
        "refuse leadership release: money surface armed but engines not quiesced",
      );
    }
  }

  /**
   * Defect A3/D3: shutdown is monotonic for the process. After ENGINE_QUIESCE
   * refuse to arm again, so neither a second arm nor an intervening re-stamp
   * can reopen accept under a still-held lock.
   */
  function assertArmable(): void {
    if (moneySurface === "quiesced") {
      throw new Error(
        "armMoneySurface: engines already quiesced — refuse reopen after ENGINE_QUIESCE",
      );
    }
  }

  /**
   * The only writer of the arm state. Shared by armMoneySurface and
   * registerWorkerStop — a stop that is remembered but does not arm was the
   * PROBE-BOOT-STOP / PRE-STAMP empty-flush hole.
   */
  function armStop(stop: () => void): void {
    assertArmable();
    workerStops.push(stop);
    moneySurface = "armed";
  }

  function armMoneySurfaceInternal(stop: () => void): void {
    if (innerHandle === undefined || leadership === undefined) {
      throw new Error("armMoneySurface: no stamped leadership");
    }
    // Defect D1: arm is reachable while boot phase is still open. Boot-lane
    // runs startMoneyWorkers before settleBootPhase; refusing here made the
    // production composition seam permanently non-arming. Boot token still
    // blocks unlock until completeBootPhase; arm sticks across settle.
    // Quiesce is checked before authority so a post-shutdown reopen attempt
    // reports the monotonicity refusal rather than the withdraw that preceded it.
    assertArmable();
    if (!authority.held) {
      throw new Error(
        `armMoneySurface: signer authority not held${
          authority.reason === undefined ? "" : `: ${authority.reason}`
        }`,
      );
    }
    armStop(stop);
  }

  function runUnderLeadershipInternal<T>(work: () => Promise<T>): Promise<T> {
    // Always return a Promise so callers can uniformly .catch / await —
    // refuse paths reject rather than throw synchronously.
    if (innerHandle === undefined || leadership === undefined) {
      return Promise.reject(new Error("runUnderLeadership: no stamped leadership"));
    }
    if (!authority.held) {
      return Promise.reject(
        new Error(
          `runUnderLeadership: signer authority not held${
            authority.reason === undefined ? "" : `: ${authority.reason}`
          }`,
        ),
      );
    }
    // Post-boot: refuse work unless the money surface armed stop+inflight.
    // Mid-boot (token still open) may run recovery work without arming.
    if (settleBootPhase === undefined && moneySurface === "unarmed") {
      return Promise.reject(
        new Error(
          "runUnderLeadership: money surface not armed — refuse untracked work under leadership",
        ),
      );
    }
    if (moneySurface === "quiesced") {
      return Promise.reject(
        new Error("runUnderLeadership: engines quiesced — refuse new work"),
      );
    }
    // Always track — flush proof does not depend on caller memory.
    const started = Promise.resolve().then(() => work());
    return trackInflightInternal(started);
  }

  /**
   * Single unlock path used by both hooks().releaseLeadership and the
   * stamped wrapper. Refuses while any tracked work (boot token included)
   * remains, or while an armed money surface has not been quiesced.
   * Clears the public/inner slots only AFTER inner.release() succeeds so a
   * throw cannot orphan the DB unlock target (Defect B).
   */
  async function unlockLeadership(): Promise<void> {
    assertNoInflight();
    assertEnginesQuiescedForRelease();
    // The money surface is NOT reset here: unlock only gets past the gate above
    // when the surface is unarmed or already quiesced, and a monotonic state
    // means a post-unlock stamp cannot re-arm (Defect D3).
    const inner = innerHandle;
    if (inner === undefined) {
      // Already unlocked (or never stamped). Keep latch honest.
      if (authority.held) {
        authority.markLost("shutdown: signer leadership released");
      }
      leadership = undefined;
      return;
    }
    // Await DB unlock BEFORE clearing slots — throw leaves targets intact
    // for retry; process death still frees session advisory locks.
    await inner.release();
    leadership = undefined;
    innerHandle = undefined;
    if (authority.held) {
      authority.markLost("shutdown: signer leadership released");
    }
  }

  function buildStampedHandle(): StampedLeadershipHandle {
    return {
      release: () => unlockLeadership(),
      armMoneySurface: (stop) => armMoneySurfaceInternal(stop),
      runUnderLeadership: (work) => runUnderLeadershipInternal(work),
    };
  }

  const registry: ShutdownRegistry = {
    authority,
    get leadership() {
      return leadership;
    },
    set leadership(value: SignerLeadershipHandle | undefined) {
      // Direct assignment is test/lost-connection only. Same as
      // clearLeadership: dropping the handle never disarms a live surface.
      if (value === undefined) {
        leadership = undefined;
        innerHandle = undefined;
        return;
      }
      // Non-undefined direct set is not the stamp path — keep as opaque handle.
      leadership = value as StampedLeadershipHandle;
    },
    get inflightCount() {
      return inflight.size;
    },
    get bootPhaseOpen() {
      return settleBootPhase !== undefined;
    },
    get moneySurfaceArmed() {
      return moneySurface === "armed";
    },
    get enginesQuiesced() {
      return moneySurface !== "armed";
    },
    trackInflight: trackInflightInternal,
    registerWorkerStop(stop: () => void): void {
      // Defect A2/D1: stop-only registration must arm the money surface so
      // unlock refuses while the surface is armed (same gate as armMoneySurface).
      // Arms mid-boot too — silent non-arm after settle was the PROBE-BOOT-STOP
      // empty-flush path.
      if (innerHandle !== undefined && leadership !== undefined) {
        armMoneySurfaceInternal(stop);
        return;
      }
      // No stamp yet: a live stop is a live money surface regardless of call
      // sequence, so arm anyway — recording without arming was the PRE-STAMP
      // empty-flush footgun. Unlock then refuses until ENGINE_QUIESCE.
      armStop(stop);
    },
    registerFlusher(flush: () => Promise<void>): void {
      inflightFlushers.push(flush);
    },
    stampLeadership(handle: SignerLeadershipHandle): StampedLeadershipHandle {
      // Record-only. Deliberately touches NEITHER the money surface nor the
      // authority latch:
      //   - Defect D3: resetting the arm here let a re-stamp (double
      //     onLeadershipAcquired, main.ts defensive late stamp, lost-connection
      //     recovery) wipe the armed-surface unlock gate while worker loops were
      //     still live, so an empty flush read as completion proof.
      //   - Defect D4: markAcquired() here minted `held` with no advisory lock,
      // undoing Shutdown step SIGNER_AUTHORITY_WITHDRAW. Acquire is
      //     tryAcquireSignerLeadership's alone — it flips the latch the instant
      //     the DB grants the lock, before composition ever stamps.
      const wrapped = buildStampedHandle();
      leadership = wrapped;
      innerHandle = handle;
      // Boot-phase token: one open token per stamp session. Re-stamp while
      // still open keeps the existing token (lane is still mid-boot).
      if (settleBootPhase === undefined) {
        let resolveBoot!: () => void;
        const bootToken = new Promise<void>((resolve) => {
          resolveBoot = resolve;
        });
        const bootWaitable = trackWaitable(bootToken);
        // Settle drops the token from the tracked set in the SAME tick, not two
        // microtasks later: boot-lane releases leadership immediately after
        // settling (retryable-recovery path), and a token that is
        // resolved but still tracked would refuse that release and strand the
        // single-holder leadership lock. `bootPhaseOpen` already flips
        // synchronously, so `inflightCount` must too.
        settleBootPhase = () => {
          resolveBoot();
          inflight.delete(bootWaitable);
        };
      }
      return wrapped;
    },
    completeBootPhase(): void {
      if (settleBootPhase === undefined) return;
      const settle = settleBootPhase;
      settleBootPhase = undefined;
      settle();
    },
    armMoneySurface: armMoneySurfaceInternal,
    runUnderLeadership: runUnderLeadershipInternal,
    clearLeadership(): void {
      // Handles only — see the interface note: a lost/cleared DB handle does not
      // stop worker loops, so the arm gate must outlive it (Defect D3).
      leadership = undefined;
      innerHandle = undefined;
    },
    hooks() {
      return {
        withdrawSignerAuthority: (): void => {
          // Shutdown step SIGNER_AUTHORITY_WITHDRAW — sync latch only; lock stays held.
          if (authority.held) {
            authority.markLost("shutdown: signer authority withdrawn");
          }
        },
        stopWorkers: (): void => {
          // ENGINE_QUIESCE — mark before stops so concurrent runUnderLeadership
          // refuses new work once quiesce begins. Unconditional: once shutdown
          // has quiesced, an instance that had no workers must not be able to
          // arm one either (arming after ENGINE_QUIESCE is the A3/D3 reopen).
          moneySurface = "quiesced";
          for (const stop of workerStops) stop();
        },
        flushInFlight: async (): Promise<void> => {
          // Flush proof: wait until the tracked set is empty (includes the
          // boot-phase token until completeBootPhase and every
          // runUnderLeadership promise). New work after withdraw+stop must
          // not start (authority withdrawn + enginesQuiesced).
          for (;;) {
            if (inflight.size === 0) break;
            await Promise.all([...inflight]);
          }
          await Promise.all(inflightFlushers.map((flush) => flush()));
        },
        releaseLeadership: () => unlockLeadership(),
      };
    },
  };

  // Non-opt-in flush tracking for the real signing chokepoint: every signUnderLease body
  // that uses this registry's authority latch is observed in the inflight set
  // without caller runUnderLeadership / trackInflight memory.
  authority.setSigningInflightTracker((work) => {
    trackInflightInternal(work);
  });

  return registry;
}

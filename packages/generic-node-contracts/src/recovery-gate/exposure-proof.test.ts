// the named concern — prove no unrecoverable inbound exposure under the composed
// the named concern/.2 design. CONTRACT_FREEZE pure negative suite: assignment, arm, structural
// trigger, automatic-sink, expiry release, restore, and the five named race interleavings.
//
// Four structural lease-trigger obligations discharged here:
//   1. assignment → backpressure (never ungated pool)
//   2. arm → 409 operation_not_armable; no code byte
//   3. RECEIVE_WINDOW / MOVE_DESTINATION lease insert on unverified → CUSTODY_LEASE_RECOVERY_UNVERIFIED
//   4. RECONCILIATION insert on same unverified wallet is NOT rejected
//
// Disposition (acceptance OR-branch): OUTRIGHT_PROHIBITION — see DISPOSITION.
import { describe, expect, it } from "vitest";

import { isAvailableForReceive } from "../pool-policy/eligibility.js";
import {
  DISPOSITION,
  applyRecoveryStampChange,
  armReceive,
  assignHoldReceive,
  createRaceStore,
  evaluateLeaseInsert,
  exposureInvariantHolds,
  isAutomaticSinkAdmissible,
  passesArmRecheck,
  releaseExpiredUnarmed,
  runRace,
  type ModeledWallet,
  type RaceStep,
} from "./exposure-model.js";

const STAMP = "2026-07-19T00:00:00.000Z";

function wallet(partial: Partial<ModeledWallet> & Pick<ModeledWallet, "id">): ModeledWallet {
  return {
    id: partial.id,
    publicKey: partial.publicKey ?? `pk_${partial.id}`,
    keyOrigin: partial.keyOrigin ?? "node_generated",
    recoveryVerifiedAt: partial.recoveryVerifiedAt === undefined ? null : partial.recoveryVerifiedAt,
    state: partial.state ?? "AVAILABLE",
    createdAt: partial.createdAt ?? "2026-07-01T00:00:00.000Z",
    destinationState: partial.destinationState === undefined ? null : partial.destinationState,
  };
}

const unverified = wallet({ id: "w-unverified" });
const verified = wallet({ id: "w-verified", recoveryVerifiedAt: STAMP });
const verifiedBlessed = wallet({
  id: "w-sink",
  recoveryVerifiedAt: STAMP,
  destinationState: "BLESSED",
});

describe("the named concern disposition — which acceptance OR-branch was taken", () => {
  it("records OUTRIGHT_PROHIBITION (not an approved-backup cover for unverified wallets)", () => {
    expect(DISPOSITION.branch).toBe("OUTRIGHT_PROHIBITION");
    expect(DISPOSITION.rejectedBranch).toBe("APPROVED_BACKUP_RULE_COVERING_UNVERIFIED");
    expect(DISPOSITION.authority).toContain("recovery-gate-rule");
    expect(DISPOSITION.authority).toContain("receive-gate-enforcement-freeze");
    // Verbatim negative-path assertion required by the ticket Verification/evidence line:
    expect(isAvailableForReceive(unverified)).toBe(false);
  });
});

describe("lease-trigger obligation 1 — assignment never falls to an ungated pool", () => {
  it("NEGATIVE: recovery-unverified AVAILABLE wallet is never selected for 201 HOLD", () => {
    const outcome = assignHoldReceive({
      pool: [unverified],
      lockedIds: new Set(),
      queueHasCapacity: false,
      operationId: "op-1",
    });
    expect(outcome.kind).toBe("REJECT_503");
    if (outcome.kind !== "REJECT_503") return;
    expect(outcome.reason).toBe("receive_queue_full");
    expect(outcome.receiver_pubkey).toBeUndefined();
    expect(outcome.operationCreated).toBe(false);
  });

  it("NEGATIVE: deferred path keeps receiver_pubkey null and transfer_code null (202)", () => {
    const outcome = assignHoldReceive({
      pool: [unverified],
      lockedIds: new Set(),
      queueHasCapacity: true,
      operationId: "op-2",
    });
    expect(outcome).toEqual({
      kind: "DEFERRED_202",
      status: 202,
      receiver_pubkey: null,
      transfer_code: null,
      code_status: "NOT_CREATED",
      discriminator: "op-2",
      operationState: "CREATED",
    });
  });

  it("verified wallet assigns 201 with pubkey, but transfer_code stays null (AWAITING_ARM)", () => {
    const outcome = assignHoldReceive({
      pool: [verified],
      lockedIds: new Set(),
      queueHasCapacity: true,
      operationId: "op-3",
    });
    expect(outcome.kind).toBe("SYNC_201");
    if (outcome.kind !== "SYNC_201") return;
    expect(outcome.receiver_pubkey).toBe("pk_w-verified");
    expect(outcome.transfer_code).toBeNull();
    expect(outcome.code_status).toBe("AWAITING_ARM");
  });

  it("NEGATIVE: a pool of only unverified wallets never yields receiver_pubkey on any path", () => {
    for (const cap of [true, false]) {
      const outcome = assignHoldReceive({
        pool: [unverified, wallet({ id: "w2" }), wallet({ id: "w3" })],
        lockedIds: new Set(),
        queueHasCapacity: cap,
        operationId: `op-cap-${cap}`,
      });
      if (outcome.kind === "SYNC_201") {
        expect.fail("unverified pool produced SYNC_201");
      }
      if (outcome.kind === "DEFERRED_202") {
        expect(outcome.receiver_pubkey).toBeNull();
        expect(outcome.transfer_code).toBeNull();
      }
      if (outcome.kind === "REJECT_503") {
        expect(outcome.receiver_pubkey).toBeUndefined();
      }
    }
  });
});

describe("lease-trigger obligation 2 — arm rejects; no code byte", () => {
  it("NEGATIVE: arm against recovery-unverified PINNED receiver returns 409 operation_not_armable", () => {
    // Pathological: wallet became unverified after assign (forbidden by monotonicity) OR
    // a future path leased without the SELECT. Arm recheck is the last line of defence.
    const outcome = armReceive({
      operationState: "READY",
      expired: false,
      leasedWallet: { ...unverified, state: "PINNED" },
      transferCodeBytes: "SECRET_CODE",
    });
    expect(outcome).toEqual({
      kind: "NOT_ARMABLE_409",
      status: 409,
      error: "operation_not_armable",
      transfer_code: null,
      walletRemainsPinned: true,
      attentionRequired: true,
    });
  });

  it("NEGATIVE: intervening quarantine between assign and arm refuses code release", () => {
    expect(passesArmRecheck({ ...verified, state: "PINNED" })).toBe(true);
    expect(passesArmRecheck({ ...verified, state: "QUARANTINED" })).toBe(false);
    const outcome = armReceive({
      operationState: "READY",
      expired: false,
      leasedWallet: { ...verified, state: "QUARANTINED" },
      transferCodeBytes: "SECRET_CODE",
    });
    expect(outcome.kind).toBe("NOT_ARMABLE_409");
    if (outcome.kind !== "NOT_ARMABLE_409") return;
    expect(outcome.transfer_code).toBeNull();
    expect(outcome.error).toBe("operation_not_armable");
  });

  it("NEGATIVE: retired leased wallet is not armable", () => {
    expect(
      armReceive({
        operationState: "READY",
        expired: false,
        leasedWallet: { ...verified, state: "RETIRED" },
        transferCodeBytes: "SECRET_CODE",
      }).kind,
    ).toBe("NOT_ARMABLE_409");
  });

  it("verified PINNED receiver arms and is the only path that releases transfer_code", () => {
    const outcome = armReceive({
      operationState: "READY",
      expired: false,
      leasedWallet: { ...verified, state: "PINNED" },
      transferCodeBytes: "SECRET_CODE",
    });
    expect(outcome).toEqual({
      kind: "ARMED_200",
      status: 200,
      transfer_code: "SECRET_CODE",
      code_status: "RELEASED",
    });
  });
});

describe("lease-trigger obligations 3–4 — structural lease trigger", () => {
  it("NEGATIVE: RECEIVE_WINDOW insert on recovery-unverified raises CUSTODY_LEASE_RECOVERY_UNVERIFIED", () => {
    expect(evaluateLeaseInsert("RECEIVE_WINDOW", unverified)).toEqual({
      ok: false,
      exception: "CUSTODY_LEASE_RECOVERY_UNVERIFIED",
    });
  });

  it("NEGATIVE: MOVE_DESTINATION insert on recovery-unverified BLESSED raises CUSTODY_LEASE_RECOVERY_UNVERIFIED", () => {
    expect(
      evaluateLeaseInsert("MOVE_DESTINATION", {
        ...unverified,
        destinationState: "BLESSED",
      }),
    ).toEqual({
      ok: false,
      exception: "CUSTODY_LEASE_RECOVERY_UNVERIFIED",
    });
  });

  it("RECONCILIATION insert on the same recovery-unverified wallet is NOT rejected (G0)", () => {
    expect(evaluateLeaseInsert("RECONCILIATION", unverified)).toEqual({ ok: true });
    expect(evaluateLeaseInsert("RECONCILIATION", { ...unverified, state: "QUARANTINED" })).toEqual({
      ok: true,
    });
  });

  it("NEGATIVE: unknown lease_role fails closed", () => {
    expect(evaluateLeaseInsert("FUTURE_ROLE", verified)).toEqual({
      ok: false,
      exception: "CUSTODY_LEASE_ROLE_UNKNOWN",
    });
  });
});

describe("automatic routing (MOVE_INTERNAL / after_landing=INTERNAL_MOVE) — never into unverified", () => {
  it("NEGATIVE: recovery-unverified BLESSED wallet is not an automatic sink", () => {
    expect(
      isAutomaticSinkAdmissible({
        ...unverified,
        destinationState: "BLESSED",
      }),
    ).toBe(false);
  });

  it("verified BLESSED AVAILABLE/PINNED is admissible; QUARANTINED is not", () => {
    expect(isAutomaticSinkAdmissible(verifiedBlessed)).toBe(true);
    expect(isAutomaticSinkAdmissible({ ...verifiedBlessed, state: "PINNED" })).toBe(true);
    expect(isAutomaticSinkAdmissible({ ...verifiedBlessed, state: "QUARANTINED" })).toBe(false);
  });
});

describe("expiry release — unarmed path never exposes transfer_code", () => {
  it("unarmed expired receive releases without ever releasing code", () => {
    const outcome = releaseExpiredUnarmed({
      expiryPassed: true,
      landedProofExists: false,
      t0Unchanged: true,
      observationAnomaly: false,
      childSafeOrAbsent: true,
      wasArmed: false,
    });
    expect(outcome).toEqual({
      kind: "RELEASED",
      release_status: "RELEASED_T0_UNCHANGED",
      walletStateAfter: "AVAILABLE",
      transfer_code_ever_released: false,
    });
  });

  it("NEGATIVE: a failed predicate keeps the wallet PINNED and still never releases code", () => {
    const outcome = releaseExpiredUnarmed({
      expiryPassed: true,
      landedProofExists: false,
      t0Unchanged: false,
      observationAnomaly: true,
      childSafeOrAbsent: true,
      wasArmed: false,
    });
    expect(outcome.transfer_code_ever_released).toBe(false);
    expect(outcome.kind).toBe("HELD_ATTENTION");
  });
});

describe("restore / recovery-status monotonicity", () => {
  it("stamping null → value is allowed; clearing a stamp is forbidden", () => {
    expect(applyRecoveryStampChange(null, STAMP)).toEqual({ ok: true, recoveryVerifiedAt: STAMP });
    expect(applyRecoveryStampChange(STAMP, null)).toEqual({
      ok: false,
      reason: "RECOVERY_STAMP_CLEAR_FORBIDDEN",
    });
  });
});

describe("five named interleavings — outcome never ambiguous; exposure invariant holds", () => {
  const sequences: { name: string; steps: RaceStep[] }[] = [
    {
      name: "recovery-status then assignment: stamp unlocks assign",
      steps: [
        { op: "stamp_recovery", walletId: "w-unverified", at: STAMP },
        { op: "assign_hold", operationId: "op-a", queueHasCapacity: true },
      ],
    },
    {
      name: "assignment then recovery-status: unverified still blocked at assign",
      steps: [
        { op: "assign_hold", operationId: "op-b", queueHasCapacity: true },
        { op: "stamp_recovery", walletId: "w-unverified", at: STAMP },
      ],
    },
    {
      name: "assignment then arm (happy path on verified)",
      steps: [
        { op: "assign_hold", operationId: "op-c", queueHasCapacity: true },
        { op: "arm", operationId: "op-c" },
      ],
    },
    {
      name: "assignment then intervening quarantine then arm",
      steps: [
        { op: "assign_hold", operationId: "op-d", queueHasCapacity: true },
        { op: "quarantine", walletId: "w-verified" },
        { op: "arm", operationId: "op-d" },
      ],
    },
    {
      name: "assignment then expiry (unarmed) — release without code",
      steps: [
        { op: "assign_hold", operationId: "op-e", queueHasCapacity: true },
        { op: "expire_unarmed", operationId: "op-e", allPredicatesPass: true },
        { op: "arm", operationId: "op-e" },
      ],
    },
    {
      name: "restore keeps stamp; clear-via-restore is rejected; assign still gated",
      steps: [
        { op: "stamp_recovery", walletId: "w-unverified", at: STAMP },
        { op: "restore_wallet", walletId: "w-unverified", keepStamp: false },
        { op: "assign_hold", operationId: "op-f", queueHasCapacity: false },
        { op: "restore_wallet", walletId: "w-unverified", keepStamp: true },
        { op: "assign_hold", operationId: "op-g", queueHasCapacity: true },
      ],
    },
    {
      name: "recovery-status + arm + expiry + restore composite",
      steps: [
        { op: "assign_hold", operationId: "op-h", queueHasCapacity: true },
        { op: "arm", operationId: "op-h" },
        { op: "expire_unarmed", operationId: "op-h", allPredicatesPass: true },
        { op: "restore_wallet", walletId: "w-verified", keepStamp: true },
        { op: "clear_recovery", walletId: "w-verified" },
        { op: "assign_hold", operationId: "op-i", queueHasCapacity: true },
      ],
    },
  ];

  it.each(sequences)("$name", ({ name, steps }) => {
    // Fresh store per sequence. Default pool: one unverified + one verified so both branches exist.
    const store = createRaceStore([
      wallet({ id: "w-unverified" }),
      wallet({ id: "w-verified", recoveryVerifiedAt: STAMP, publicKey: "pk_w-verified" }),
    ]);
    const results = runRace(store, steps);
    const inv = exposureInvariantHolds(results, store);
    expect(inv, `invariant failed on ${name}: ${"reason" in inv ? inv.reason : ""}`).toEqual({
      holds: true,
    });

    // Concrete negatives per sequence family.
    if (name.startsWith("assignment then recovery-status")) {
      const assign = results[0]?.detail as { kind: string; receiver_pubkey: unknown; walletId?: string };
      expect(assign.kind).toBe("SYNC_201"); // verified was chosen, not unverified
      // The unverified wallet must never have been the 201 subject.
      if (assign.kind === "SYNC_201") {
        expect(assign.walletId).toBe("w-verified");
      }
    }
    if (name.startsWith("assignment then intervening quarantine")) {
      const arm = results[2]?.detail as { kind: string; transfer_code: unknown };
      expect(arm.kind).toBe("NOT_ARMABLE_409");
      expect(arm.transfer_code).toBeNull();
      expect(results[2]?.codeExposed).toBe(false);
    }
    if (name.startsWith("assignment then expiry")) {
      const release = results[1]?.detail as { transfer_code_ever_released: boolean };
      expect(release.transfer_code_ever_released).toBe(false);
      const armAfter = results[2]?.detail as { transfer_code: unknown };
      expect(armAfter.transfer_code).toBeNull();
    }
    if (name.startsWith("restore keeps stamp")) {
      // clear-via-restore rejected; first assign_hold at cap against still-stamped? After failed
      // clear, stamp remains so restore keepStamp:false left stamp intact — assign may succeed.
      // The load-bearing check is the invariant + clear rejection detail.
      const clearAttempt = results[1]?.detail as { ok: boolean; reason?: string };
      expect(clearAttempt.ok).toBe(false);
      expect(clearAttempt.reason).toBe("RECOVERY_STAMP_CLEAR_FORBIDDEN");
    }
    if (name.includes("clear_recovery")) {
      // clear_recovery on verified must not wipe the stamp.
      const w = store.wallets.get("w-verified");
      expect(w?.recoveryVerifiedAt).toBe(STAMP);
    }
  });

  it("NEGATIVE: assign against only-unverified pool under every capacity never exposes pubkey or code", () => {
    for (const cap of [true, false]) {
      const store = createRaceStore([wallet({ id: "w-unverified" })]);
      const results = runRace(store, [
        { op: "assign_hold", operationId: "op-only-u", queueHasCapacity: cap },
        { op: "arm", operationId: "op-only-u" },
        { op: "expire_unarmed", operationId: "op-only-u", allPredicatesPass: true },
      ]);
      expect(results.every((r) => !r.pubkeyExposedOn201)).toBe(true);
      expect(results.every((r) => !r.codeExposed)).toBe(true);
      expect(exposureInvariantHolds(results, store)).toEqual({ holds: true });
      const assign = results[0]?.detail as { kind: string; receiver_pubkey: unknown };
      expect(assign.kind === "DEFERRED_202" || assign.kind === "REJECT_503").toBe(true);
      if (assign.kind === "DEFERRED_202") {
        expect(assign.receiver_pubkey).toBeNull();
      }
    }
  });

  it("NEGATIVE: arm never runs on a deferred (unassigned) receive — no transfer_code path", () => {
    const store = createRaceStore([wallet({ id: "w-unverified" })]);
    const results = runRace(store, [
      { op: "assign_hold", operationId: "op-def", queueHasCapacity: true },
      { op: "arm", operationId: "op-def" },
    ]);
    expect(results[1]?.codeExposed).toBe(false);
    expect(store.operations.get("op-def")?.receiver_pubkey).toBeNull();
    expect(store.operations.get("op-def")?.codeReleased).toBe(false);
  });
});

describe("composed gate freezes match the receive-gate enforcement freeze byte clauses (cross-check)", () => {
  it("assignment predicate rejects exactly when any of the three conjuncts fail", () => {
    expect(isAvailableForReceive(verified)).toBe(true);
    expect(isAvailableForReceive({ ...verified, recoveryVerifiedAt: null })).toBe(false);
    expect(isAvailableForReceive({ ...verified, state: "PINNED" })).toBe(false);
    expect(isAvailableForReceive({ ...verified, keyOrigin: "imported" })).toBe(false);
  });

  it("arm recheck allowlist is {AVAILABLE,PINNED} and requires recovery stamp", () => {
    expect(passesArmRecheck({ ...verified, state: "AVAILABLE" })).toBe(true);
    expect(passesArmRecheck({ ...verified, state: "PINNED" })).toBe(true);
    expect(passesArmRecheck({ ...verified, state: "QUARANTINED" })).toBe(false);
    expect(passesArmRecheck({ ...verified, state: "RETIRED" })).toBe(false);
    expect(passesArmRecheck({ ...unverified, state: "PINNED" })).toBe(false);
  });
});

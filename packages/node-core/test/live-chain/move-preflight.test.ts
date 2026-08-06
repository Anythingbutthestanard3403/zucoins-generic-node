import { describe, expect, it } from "vitest";

import {
  DEFAULT_MOVE_AMOUNT,
  DEFAULT_MOVE_AMOUNT_CEILING,
  MOVE_AMOUNT_HARD_CAP,
  effectiveMoveAmountCeiling,
  evaluateMoveDestinationEligibility,
  evaluateMoveSourceEligibility,
  leaseUuidOrder,
  runMoveInternalPreflight,
} from "./move-preflight.js";
import { createRunnerLock } from "./runner-lock.js";
import {
  SAMPLE_DEST_ID,
  SAMPLE_SOURCE_ID,
  eligibleDestination,
  eligibleSource,
  fakeMoveProbe,
  readyMoveState,
  sampleAuth,
} from "./fakes.js";

const ATTEMPT = "attempt-move-1";

function baseInput(overrides: Record<string, unknown> = {}) {
  return {
    attemptId: ATTEMPT,
    sourceWalletId: SAMPLE_SOURCE_ID,
    destinationWalletId: SAMPLE_DEST_ID,
    amount: DEFAULT_MOVE_AMOUNT,
    authorization: sampleAuth(ATTEMPT),
    runnerLock: createRunnerLock(),
    runnerHolderId: "fixture-1-preflight",
    ...overrides,
  };
}

describe("effectiveMoveAmountCeiling (hard cap)", () => {
  it("defaults to the hard cap", () => {
    expect(effectiveMoveAmountCeiling()).toBe(MOVE_AMOUNT_HARD_CAP);
    expect(effectiveMoveAmountCeiling(undefined)).toBe(DEFAULT_MOVE_AMOUNT_CEILING);
  });

  it("allows a tighter caller ceiling below the hard cap", () => {
    expect(effectiveMoveAmountCeiling("0.001")).toBe("0.001");
  });

  it("clamps a caller ceiling above 0.01 down to the hard cap", () => {
    expect(effectiveMoveAmountCeiling("100")).toBe(MOVE_AMOUNT_HARD_CAP);
    expect(effectiveMoveAmountCeiling("0.02")).toBe(MOVE_AMOUNT_HARD_CAP);
  });
});

describe("leaseUuidOrder", () => {
  it("sorts candidate wallet UUIDs ascending for atomic acquisition", () => {
    const order = leaseUuidOrder(SAMPLE_DEST_ID, SAMPLE_SOURCE_ID);
    expect(order.first).toBe(SAMPLE_SOURCE_ID);
    expect(order.second).toBe(SAMPLE_DEST_ID);
    expect(order.acquireOrder).toEqual([SAMPLE_SOURCE_ID, SAMPLE_DEST_ID]);
  });
});

describe("evaluateMoveSourceEligibility (asymmetric — recovery NOT required)", () => {
  it("accepts node_generated controlled source without recovery_verified_at", () => {
    const result = evaluateMoveSourceEligibility(eligibleSource());
    expect(result.ok).toBe(true);
    expect(result.detail).toMatch(/recovery not required/);
  });

  it("rejects imported or uncontrolled source", () => {
    expect(
      evaluateMoveSourceEligibility(eligibleSource(SAMPLE_SOURCE_ID, { keyOrigin: "imported" }))
        .ok,
    ).toBe(false);
    expect(
      evaluateMoveSourceEligibility(
        eligibleSource(SAMPLE_SOURCE_ID, { nodeControlled: false }),
      ).ok,
    ).toBe(false);
  });

  it("rejects quarantined source", () => {
    expect(
      evaluateMoveSourceEligibility(
        eligibleSource(SAMPLE_SOURCE_ID, { walletState: "QUARANTINED" }),
      ).ok,
    ).toBe(false);
  });
});

describe("evaluateMoveDestinationEligibility (full B1 + recovery)", () => {
  it("accepts BLESSED recovery-verified node_generated destination", () => {
    const result = evaluateMoveDestinationEligibility(eligibleDestination());
    expect(result.ok).toBe(true);
    expect(result.denialReason).toBeNull();
  });

  it("rejects destination lacking recovery_verified_at", () => {
    const result = evaluateMoveDestinationEligibility(
      eligibleDestination(SAMPLE_DEST_ID, { recoveryVerifiedAt: null }),
    );
    expect(result.ok).toBe(false);
    expect(result.denialReason).toBe("INVALID_RECOVERY_VERIFIED_AT");
  });

  it("rejects destination that is not BLESSED", () => {
    const result = evaluateMoveDestinationEligibility(
      eligibleDestination(SAMPLE_DEST_ID, { destinationState: "PENDING" }),
    );
    expect(result.ok).toBe(false);
    expect(result.denialReason).toBe("DESTINATION_NOT_BLESSED");
  });

  it("does NOT accept source-only facts as destination-eligible (negative path)", () => {
    // Source-shaped wallet (no blessing, no recovery) must fail destination predicate.
    const result = evaluateMoveDestinationEligibility(eligibleSource(SAMPLE_DEST_ID));
    expect(result.ok).toBe(false);
  });
});

describe("runMoveInternalPreflight", () => {
  it("reports ready with plan, lease order, abort criteria, and held runner lock", async () => {
    const lock = createRunnerLock();
    const report = await runMoveInternalPreflight(
      fakeMoveProbe(readyMoveState()),
      baseInput({ runnerLock: lock }),
    );

    expect(report.ready).toBe(true);
    expect(report.plan).toEqual({
      kind: "MOVE_INTERNAL",
      attemptId: ATTEMPT,
      sourceWalletId: SAMPLE_SOURCE_ID,
      destinationWalletId: SAMPLE_DEST_ID,
      amount: DEFAULT_MOVE_AMOUNT,
      authorization: sampleAuth(ATTEMPT),
    });
    expect(report.leaseUuidOrder.first).toBe(SAMPLE_SOURCE_ID);
    expect(report.leaseUuidOrder.second).toBe(SAMPLE_DEST_ID);
    expect(report.abortCriteria.blindRetryForbidden).toBe(true);
    expect(report.runnerLockHandle).not.toBeNull();
    expect(lock.held).toBe(true);
    expect(report.checks.every((c) => c.ok)).toBe(true);
    expect(report.checks.map((c) => c.id)).toEqual([
      "dual_control_authorization",
      "source_eligible",
      "destination_eligible",
      "wallets_distinct",
      "amount_fixed_fractional",
      "t0_capture_fresh",
      "backups_present",
      "no_active_lease",
      "lease_uuid_order_reported",
      "abort_criteria_bound",
      "runner_lock_acquired",
    ]);

    report.runnerLockHandle?.release();
    expect(lock.held).toBe(false);
  });

  it("passes when source lacks recovery_verified but destination has it (asymmetric rule)", async () => {
    const state = readyMoveState();
    // Explicit: source recovery is null (already the default) — must still clear.
    state.wallets.set(
      SAMPLE_SOURCE_ID,
      eligibleSource(SAMPLE_SOURCE_ID, { recoveryVerifiedAt: null }),
    );
    const report = await runMoveInternalPreflight(fakeMoveProbe(state), baseInput());
    expect(report.ready).toBe(true);
    expect(report.checks.find((c) => c.id === "source_eligible")?.ok).toBe(true);
    report.runnerLockHandle?.release();
  });

  it("fails when dual-control attestation is bound to a different attempt", async () => {
    const report = await runMoveInternalPreflight(
      fakeMoveProbe(readyMoveState()),
      baseInput({ authorization: sampleAuth("other-attempt") }),
    );
    expect(report.ready).toBe(false);
    expect(report.plan).toBeNull();
    expect(report.checks.find((c) => c.id === "dual_control_authorization")?.ok).toBe(false);
    expect(report.runnerLockHandle).toBeNull();
  });

  it("fails when destination is not recovery-verified", async () => {
    const state = readyMoveState();
    state.wallets.set(
      SAMPLE_DEST_ID,
      eligibleDestination(SAMPLE_DEST_ID, { recoveryVerifiedAt: null }),
    );
    const report = await runMoveInternalPreflight(fakeMoveProbe(state), baseInput());
    expect(report.ready).toBe(false);
    expect(report.checks.find((c) => c.id === "destination_eligible")?.ok).toBe(false);
  });

  it("fails when either wallet has an active lease (the one-in-flight-per-wallet rule)", async () => {
    const state = readyMoveState();
    state.leases.set(SAMPLE_SOURCE_ID, [
      {
        walletId: SAMPLE_SOURCE_ID,
        leaseRole: "RECEIVE_WINDOW",
        operationId: "op-stray-receive",
      },
    ]);
    const report = await runMoveInternalPreflight(fakeMoveProbe(state), baseInput());
    expect(report.ready).toBe(false);
    const check = report.checks.find((c) => c.id === "no_active_lease");
    expect(check?.ok).toBe(false);
    expect(check?.detail).toMatch(/RECEIVE_WINDOW/);
  });

  it("fails when a destination lease is held even if source is clear", async () => {
    const state = readyMoveState();
    state.leases.set(SAMPLE_DEST_ID, [
      {
        walletId: SAMPLE_DEST_ID,
        leaseRole: "SEND_SOURCE",
        operationId: "op-stray-send",
      },
    ]);
    const report = await runMoveInternalPreflight(fakeMoveProbe(state), baseInput());
    expect(report.ready).toBe(false);
    expect(report.checks.find((c) => c.id === "no_active_lease")?.detail).toMatch(
      /SEND_SOURCE/,
    );
  });

  it("fails when T0s would be reused from a prior session", async () => {
    const state = readyMoveState();
    state.freshT0Attempts.clear();
    const report = await runMoveInternalPreflight(fakeMoveProbe(state), baseInput());
    expect(report.ready).toBe(false);
    expect(report.checks.find((c) => c.id === "t0_capture_fresh")?.ok).toBe(false);
  });

  it("fails when backups are missing", async () => {
    const state = readyMoveState();
    state.wallets.set(
      SAMPLE_SOURCE_ID,
      eligibleSource(SAMPLE_SOURCE_ID, { backupPresent: false }),
    );
    const report = await runMoveInternalPreflight(fakeMoveProbe(state), baseInput());
    expect(report.ready).toBe(false);
    expect(report.checks.find((c) => c.id === "backups_present")?.ok).toBe(false);
  });

  it("fails when amount exceeds the acceptance ceiling", async () => {
    const report = await runMoveInternalPreflight(
      fakeMoveProbe(readyMoveState()),
      baseInput({ amount: "0.05" }),
    );
    expect(report.ready).toBe(false);
    const check = report.checks.find((c) => c.id === "amount_fixed_fractional");
    expect(check?.ok).toBe(false);
    expect(check?.detail).toContain(DEFAULT_MOVE_AMOUNT_CEILING);
  });

  it("rejects amountCeiling override above hard cap (amount 50 / ceiling 100)", async () => {
    // D1 clear: caller-supplied amountCeiling must not raise the bound.
    // effectiveCeiling = min(input, HARD_CAP); amount 50 still fails hard cap.
    const lock = createRunnerLock();
    const report = await runMoveInternalPreflight(
      fakeMoveProbe(readyMoveState()),
      baseInput({
        amount: "50",
        amountCeiling: "100",
        runnerLock: lock,
      }),
    );
    expect(report.ready).toBe(false);
    expect(report.plan).toBeNull();
    expect(report.runnerLockHandle).toBeNull();
    expect(lock.held).toBe(false);
    const check = report.checks.find((c) => c.id === "amount_fixed_fractional");
    expect(check?.ok).toBe(false);
    expect(check?.detail).toMatch(new RegExp(MOVE_AMOUNT_HARD_CAP));
    expect(check?.detail).toMatch(/hard cap/i);
  });

  it("fails when plan attemptId is empty (dual-control binding requires identity)", async () => {
    // D2 clear: empty-string equality is not an attempt binding.
    const lock = createRunnerLock();
    const report = await runMoveInternalPreflight(
      fakeMoveProbe(readyMoveState()),
      baseInput({
        attemptId: "",
        authorization: sampleAuth(""),
        runnerLock: lock,
      }),
    );
    expect(report.ready).toBe(false);
    expect(report.plan).toBeNull();
    expect(report.runnerLockHandle).toBeNull();
    expect(lock.held).toBe(false);
    const check = report.checks.find((c) => c.id === "dual_control_authorization");
    expect(check?.ok).toBe(false);
    expect(check?.detail).toMatch(/empty/i);
  });

  it("fails when plan attemptId is whitespace-only", async () => {
    const lock = createRunnerLock();
    const report = await runMoveInternalPreflight(
      fakeMoveProbe(readyMoveState()),
      baseInput({
        attemptId: "   ",
        authorization: sampleAuth("   "),
        runnerLock: lock,
      }),
    );
    expect(report.ready).toBe(false);
    expect(report.plan).toBeNull();
    expect(report.runnerLockHandle).toBeNull();
    expect(lock.held).toBe(false);
    expect(report.checks.find((c) => c.id === "dual_control_authorization")?.ok).toBe(
      false,
    );
  });

  it("fails when source and destination are the same wallet", async () => {
    const state = readyMoveState();
    // Point both ids at the source wallet facts.
    const report = await runMoveInternalPreflight(
      fakeMoveProbe(state),
      baseInput({
        sourceWalletId: SAMPLE_SOURCE_ID,
        destinationWalletId: SAMPLE_SOURCE_ID,
      }),
    );
    expect(report.ready).toBe(false);
    expect(report.checks.find((c) => c.id === "wallets_distinct")?.ok).toBe(false);
  });

  it("refuses the runner lock when another holder already owns it (negative path)", async () => {
    const lock = createRunnerLock();
    const held = lock.tryAcquire("other-runner");
    expect(held).not.toBeNull();

    const report = await runMoveInternalPreflight(
      fakeMoveProbe(readyMoveState()),
      baseInput({ runnerLock: lock, runnerHolderId: "fixture-1-preflight" }),
    );
    expect(report.ready).toBe(false);
    expect(report.checks.find((c) => c.id === "runner_lock_acquired")?.ok).toBe(false);
    expect(report.checks.find((c) => c.id === "runner_lock_acquired")?.detail).toMatch(
      /other-runner/,
    );
    expect(report.runnerLockHandle).toBeNull();
    held?.release();
  });

  it("does not acquire the runner lock when an earlier check fails", async () => {
    const lock = createRunnerLock();
    const state = readyMoveState();
    state.freshT0Attempts.clear();
    const report = await runMoveInternalPreflight(
      fakeMoveProbe(state),
      baseInput({ runnerLock: lock }),
    );
    expect(report.ready).toBe(false);
    expect(lock.held).toBe(false);
    expect(report.checks.find((c) => c.id === "runner_lock_acquired")?.detail).toMatch(
      /not attempted/,
    );
  });

  it("records abort criteria that forbid just-retry on the ready path", async () => {
    const report = await runMoveInternalPreflight(
      fakeMoveProbe(readyMoveState()),
      baseInput(),
    );
    expect(report.ready).toBe(true);
    const ambiguous = report.abortCriteria.rules.find(
      (r) => r.trigger === "SUBMIT_AMBIGUOUS_OR_UNOBSERVED",
    );
    expect(ambiguous?.mayResubmit).toBe(false);
    expect(ambiguous?.action).toBe("HOLD_BOTH_LEASES_AND_RECONCILE");
    report.runnerLockHandle?.release();
  });
});

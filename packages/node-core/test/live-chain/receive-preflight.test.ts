import { describe, expect, it } from "vitest";

import {
  DEFAULT_RECEIVE_AMOUNT,
  DEFAULT_RECEIVE_AMOUNT_CEILING,
  RECEIVE_AMOUNT_HARD_CAP,
  RECEIVE_ELIGIBILITY_SQL,
  RECEIVE_EXPECTED_FIELD_ORDER,
  RECEIVE_EXPECTED_PURPOSE,
  effectiveReceiveAmountCeiling,
  evaluateExternalPayer,
  evaluateReceiveReceiverEligibility,
  runReceiveExternalPreflight,
} from "./receive-preflight.js";
import {
  RECEIVE_ABORT_POLICY_ID,
  RECEIVE_CODE_TTL_DEFAULT_SECS,
  RECEIVE_CODE_TTL_MAX_SECS,
  RECEIVE_CODE_TTL_MIN_SECS,
  receiveAbortActionFor,
  receiveExternalAbortCriteria,
  type ReceiveAbortTrigger,
} from "./receive-abort-criteria.js";
import { createRunnerLock } from "./runner-lock.js";
import {
  SAMPLE_PAYER_KEYHOLDER,
  SAMPLE_RECEIVE_BUILD,
  SAMPLE_RECEIVE_OPERATION_ID,
  SAMPLE_RECEIVE_PAYER_ADDRESS,
  SAMPLE_RECEIVE_RECEIVER_ID,
  SAMPLE_RECEIVE_RECEIVER_PUBKEY,
  eligibleExternalPayer,
  eligibleReceiveReceiver,
  fakeReceiveProbe,
  readyReceiveState,
  readyReceiveStateWithOperation,
  sampleReceiveAuth,
  sampleReceiveOperationRow,
} from "./receive-fakes.js";

const ATTEMPT = "attempt-receive-1";

function baseInput(overrides: Record<string, unknown> = {}) {
  return {
    attemptId: ATTEMPT,
    receiverWalletId: SAMPLE_RECEIVE_RECEIVER_ID,
    externalPayerAddress: SAMPLE_RECEIVE_PAYER_ADDRESS,
    amount: DEFAULT_RECEIVE_AMOUNT,
    authorization: sampleReceiveAuth(ATTEMPT),
    runnerLock: createRunnerLock(),
    runnerHolderId: "fixture-1-preflight",
    ...overrides,
  };
}

describe("effectiveReceiveAmountCeiling (external-amount-cap hard cap)", () => {
  it("defaults to the hard cap", () => {
    expect(effectiveReceiveAmountCeiling()).toBe(RECEIVE_AMOUNT_HARD_CAP);
    expect(effectiveReceiveAmountCeiling(undefined)).toBe(DEFAULT_RECEIVE_AMOUNT_CEILING);
  });

  it("allows a tighter caller ceiling below the hard cap", () => {
    expect(effectiveReceiveAmountCeiling("0.001")).toBe("0.001");
  });

  it("clamps a caller ceiling above 0.01 down to the hard cap", () => {
    expect(effectiveReceiveAmountCeiling("100")).toBe(RECEIVE_AMOUNT_HARD_CAP);
    expect(effectiveReceiveAmountCeiling("0.02")).toBe(RECEIVE_AMOUNT_HARD_CAP);
  });
});

describe("A.3.1 field-order pins + eligibility SQL", () => {
  it("freezes the 14-field zp-receive-expected-v1 order", () => {
    expect([...RECEIVE_EXPECTED_FIELD_ORDER]).toEqual([
      "purpose",
      "canonical_version",
      "node_id",
      "implementer_id",
      "operation_id",
      "receiver_wallet_id",
      "receiver_pubkey",
      "amount_zkz",
      "discriminator",
      "anchor",
      "receiver_t0_fingerprint",
      "expiry_unix_time_secs",
      "after_landing",
      "transfer_code_sha256",
    ]);
    expect(RECEIVE_EXPECTED_FIELD_ORDER).toHaveLength(14);
    expect(RECEIVE_EXPECTED_PURPOSE).toBe("zp-receive-expected-v1");
  });

  it("freezes the assignment-time SQL predicate literally", () => {
    expect(RECEIVE_ELIGIBILITY_SQL).toContain("key_origin = 'node_generated'");
    expect(RECEIVE_ELIGIBILITY_SQL).toContain("recovery_verified_at IS NOT NULL");
    expect(RECEIVE_ELIGIBILITY_SQL).toContain("state = 'AVAILABLE'");
    expect(RECEIVE_ELIGIBILITY_SQL).toContain("FOR UPDATE SKIP LOCKED");
    // Must not widen: no SQL OR disjunct, no PINNED at assignment time.
    // (Avoid bare /OR/i — it matches the "OR" inside "FOR UPDATE".)
    expect(RECEIVE_ELIGIBILITY_SQL).not.toMatch(/\bOR\b/);
    expect(RECEIVE_ELIGIBILITY_SQL).not.toContain("PINNED");
  });
});

describe("evaluateReceiveReceiverEligibility", () => {
  it("accepts node_generated + recovery_verified + AVAILABLE", () => {
    const result = evaluateReceiveReceiverEligibility(eligibleReceiveReceiver());
    expect(result.ok).toBe(true);
    expect(result.detail).toMatch(/receiver-eligible/);
    expect(result.detail).toMatch(/recovery_verified_at=/);
  });

  it("rejects recovery_verified_at IS NULL (core negative)", () => {
    const result = evaluateReceiveReceiverEligibility(
      eligibleReceiveReceiver(SAMPLE_RECEIVE_RECEIVER_ID, {
        recoveryVerifiedAt: null,
      }),
    );
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/recovery_verified_at IS NULL/);
  });

  it("rejects empty recovery_verified_at string", () => {
    expect(
      evaluateReceiveReceiverEligibility(
        eligibleReceiveReceiver(SAMPLE_RECEIVE_RECEIVER_ID, {
          recoveryVerifiedAt: "   ",
        }),
      ).ok,
    ).toBe(false);
  });

  it("rejects imported or uncontrolled receiver", () => {
    expect(
      evaluateReceiveReceiverEligibility(
        eligibleReceiveReceiver(SAMPLE_RECEIVE_RECEIVER_ID, {
          keyOrigin: "imported",
        }),
      ).ok,
    ).toBe(false);
    expect(
      evaluateReceiveReceiverEligibility(
        eligibleReceiveReceiver(SAMPLE_RECEIVE_RECEIVER_ID, {
          nodeControlled: false,
        }),
      ).ok,
    ).toBe(false);
  });

  it("rejects PINNED at assignment time (AVAILABLE only)", () => {
    const result = evaluateReceiveReceiverEligibility(
      eligibleReceiveReceiver(SAMPLE_RECEIVE_RECEIVER_ID, {
        walletState: "PINNED",
      }),
    );
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/AVAILABLE exactly/);
  });

  it("rejects quarantined / retired receiver", () => {
    expect(
      evaluateReceiveReceiverEligibility(
        eligibleReceiveReceiver(SAMPLE_RECEIVE_RECEIVER_ID, {
          walletState: "QUARANTINED",
        }),
      ).ok,
    ).toBe(false);
    expect(
      evaluateReceiveReceiverEligibility(
        eligibleReceiveReceiver(SAMPLE_RECEIVE_RECEIVER_ID, {
          walletState: "RETIRED",
        }),
      ).ok,
    ).toBe(false);
  });
});

describe("evaluateExternalPayer (independent disposable capital)", () => {
  it("accepts a disposable external payer", () => {
    const result = evaluateExternalPayer(eligibleExternalPayer());
    expect(result.ok).toBe(true);
    expect(result.detail).toMatch(SAMPLE_PAYER_KEYHOLDER);
  });

  it("rejects payer that resolves to the node's blessed set", () => {
    const result = evaluateExternalPayer(
      eligibleExternalPayer(SAMPLE_RECEIVE_PAYER_ADDRESS, {
        resolvesToNodeBlessedSet: true,
      }),
    );
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/blessed internal set/);
  });

  it("rejects payer that is a node-controlled wallet", () => {
    const result = evaluateExternalPayer(
      eligibleExternalPayer(SAMPLE_RECEIVE_PAYER_ADDRESS, {
        isNodeControlledWallet: true,
      }),
    );
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/node-controlled/);
  });

  it("rejects undocumented keyholder", () => {
    expect(
      evaluateExternalPayer(
        eligibleExternalPayer(SAMPLE_RECEIVE_PAYER_ADDRESS, { keyholderId: "" }),
      ).ok,
    ).toBe(false);
  });
});

describe("receiveExternalAbortCriteria (TTL + single submit + no blind retry)", () => {
  it("pins code TTL bounds and forbids blind retry / multi-submit", () => {
    const criteria = receiveExternalAbortCriteria();
    expect(criteria.policyId).toBe(RECEIVE_ABORT_POLICY_ID);
    expect(criteria.codeTtlDefaultSecs).toBe(300);
    expect(criteria.codeTtlDefaultSecs).toBe(RECEIVE_CODE_TTL_DEFAULT_SECS);
    expect(criteria.codeTtlMinSecs).toBe(RECEIVE_CODE_TTL_MIN_SECS);
    expect(criteria.codeTtlMaxSecs).toBe(RECEIVE_CODE_TTL_MAX_SECS);
    expect(criteria.blindRetryForbidden).toBe(true);
    expect(criteria.rebuildRequiresPositiveNonLandingOracle).toBe(true);
    expect(criteria.singleSubmitOnly).toBe(true);
  });

  it("never licenses resubmit or rebuild-without-oracle on any rule", () => {
    const criteria = receiveExternalAbortCriteria();
    for (const rule of criteria.rules) {
      expect(rule.mayResubmit).toBe(false);
      expect(rule.mayRebuildWithoutPositiveOracle).toBe(false);
    }
  });

  it("routes operator halt to hold-receiver (never retry)", () => {
    const rule = receiveAbortActionFor("OPERATOR_HALT");
    expect(rule.action).toBe("HOLD_RECEIVER_LEASE_AND_RECONCILE");
    expect(rule.detail).toMatch(/NEEDS_ATTENTION|lease/i);
    expect(rule.detail.toLowerCase()).not.toMatch(/just retry/);
    expect(rule.mayResubmit).toBe(false);
  });

  it("routes code-TTL elapsed to hold-receiver (distinct SEND T2)", () => {
    const rule = receiveAbortActionFor("CODE_TTL_ELAPSED");
    expect(rule.action).toBe("HOLD_RECEIVER_ON_CODE_EXPIRY");
    expect(rule.detail).toMatch(/Payer-code TTL elapsed/);
    expect(rule.detail).toMatch(/never authorizes a second submit/);
    expect(rule.detail).toMatch(/Do not derive this window from the SEND redemption window/);
  });

  it("routes submit ambiguity to hold + reconcile (the never-blind-retry rule)", () => {
    const rule = receiveAbortActionFor("SUBMIT_AMBIGUOUS_OR_UNOBSERVED");
    expect(rule.action).toBe("HOLD_RECEIVER_LEASE_AND_RECONCILE");
    expect(rule.detail).toMatch(/observation/i);
    expect(rule.mayResubmit).toBe(false);
  });

  it("covers every closed trigger", () => {
    const triggers: ReceiveAbortTrigger[] = [
      "SUBMIT_REJECTED",
      "SUBMIT_AMBIGUOUS_OR_UNOBSERVED",
      "INVARIANT_BREACH",
      "LANDED_VERIFIED",
      "OPERATOR_HALT",
      "CODE_TTL_ELAPSED",
    ];
    const criteria = receiveExternalAbortCriteria();
    expect(criteria.rules.map((r) => r.trigger).sort()).toEqual([...triggers].sort());
  });
});

describe("runReceiveExternalPreflight", () => {
  it("reports ready with plan, abort criteria, backup, eligibility SQL, and held runner lock", async () => {
    const lock = createRunnerLock();
    const report = await runReceiveExternalPreflight(
      fakeReceiveProbe(readyReceiveState()),
      baseInput({ runnerLock: lock }),
    );

    expect(report.ready).toBe(true);
    expect(report.eligibilitySql).toBe(RECEIVE_ELIGIBILITY_SQL);
    expect(report.plan).toEqual({
      kind: "RECEIVE_EXTERNAL",
      attemptId: ATTEMPT,
      operationId: null,
      receiverWalletId: SAMPLE_RECEIVE_RECEIVER_ID,
      receiverPubkey: SAMPLE_RECEIVE_RECEIVER_PUBKEY,
      externalPayerAddress: SAMPLE_RECEIVE_PAYER_ADDRESS,
      amount: DEFAULT_RECEIVE_AMOUNT,
      authorization: sampleReceiveAuth(ATTEMPT),
      payerKeyholderId: SAMPLE_PAYER_KEYHOLDER,
      codeTtlDefaultSecs: 300,
      vaultBackupCapturedAt: "2026-07-27T00:00:00.000Z",
      buildVersion: SAMPLE_RECEIVE_BUILD,
      recoveryVerifiedAt: "2026-07-20T12:00:00.000Z",
    });
    expect(report.vaultBackupCapturedAt).toBe("2026-07-27T00:00:00.000Z");
    expect(report.abortCriteria.singleSubmitOnly).toBe(true);
    expect(report.runnerLockHandle).not.toBeNull();
    expect(lock.held).toBe(true);
    expect(report.checks.every((c) => c.ok)).toBe(true);
    expect(report.checks.map((c) => c.id)).toEqual([
      "dual_control_authorization",
      "receiver_eligibility_d917",
      "external_payer_independent",
      "amount_fixed_fractional",
      "no_active_lease",
      "abort_criteria_bound",
      "fresh_vault_backup",
      "expected_artifact_or_clean_start",
      "no_submit_yet",
      "build_version_recorded",
      "runner_lock_acquired",
    ]);

    report.runnerLockHandle?.release();
    expect(lock.held).toBe(false);
  });

  it("reports ready against an admitted CREATED row with A.3.1 artifact", async () => {
    const lock = createRunnerLock();
    const report = await runReceiveExternalPreflight(
      fakeReceiveProbe(readyReceiveStateWithOperation()),
      baseInput({
        runnerLock: lock,
        operationId: SAMPLE_RECEIVE_OPERATION_ID,
      }),
    );
    expect(report.ready).toBe(true);
    expect(report.plan?.operationId).toBe(SAMPLE_RECEIVE_OPERATION_ID);
    expect(
      report.checks.find((c) => c.id === "expected_artifact_or_clean_start")?.detail,
    ).toMatch(/A\.3\.1 14-field order ok/);
    expect(report.checks.find((c) => c.id === "no_submit_yet")?.detail).toMatch(
      /CREATED stage clean/,
    );
    report.runnerLockHandle?.release();
  });

  it("rejects READY status as past preflight stage (Option A stage discipline)", async () => {
    const state = readyReceiveState();
    // Consistent READY facts: PINNED receiver + active RECEIVER lease + snapshot bits.
    state.receivers.set(
      SAMPLE_RECEIVE_RECEIVER_ID,
      eligibleReceiveReceiver(SAMPLE_RECEIVE_RECEIVER_ID, {
        walletState: "PINNED",
      }),
    );
    state.leases.set(SAMPLE_RECEIVE_RECEIVER_ID, [
      {
        walletId: SAMPLE_RECEIVE_RECEIVER_ID,
        leaseRole: "RECEIVER",
        operationId: SAMPLE_RECEIVE_OPERATION_ID,
      },
    ]);
    state.operations.set(
      SAMPLE_RECEIVE_OPERATION_ID,
      sampleReceiveOperationRow(SAMPLE_RECEIVE_OPERATION_ID, {
        status: "READY",
        receiverLeaseHeld: true,
        transferCodeReleased: true,
      }),
    );
    const report = await runReceiveExternalPreflight(
      fakeReceiveProbe(state),
      baseInput({ operationId: SAMPLE_RECEIVE_OPERATION_ID }),
    );
    expect(report.ready).toBe(false);
    expect(
      report.checks.find((c) => c.id === "expected_artifact_or_clean_start")?.ok,
    ).toBe(false);
    expect(
      report.checks.find((c) => c.id === "expected_artifact_or_clean_start")?.detail,
    ).toMatch(/preflight requires CREATED/);
    // Eligibility also fails (AVAILABLE only at assignment) — both gates load-bearing.
    expect(report.checks.find((c) => c.id === "receiver_eligibility_d917")?.ok).toBe(
      false,
    );
    expect(report.checks.find((c) => c.id === "no_active_lease")?.ok).toBe(false);
  });

  it("rejects CREATED row with ornamental receiverLeaseHeld=true (snapshot/probe disagree)", async () => {
    const state = readyReceiveState();
    // Snapshot claims lease held but probe.activeLeases is empty — must fail closed.
    state.operations.set(
      SAMPLE_RECEIVE_OPERATION_ID,
      sampleReceiveOperationRow(SAMPLE_RECEIVE_OPERATION_ID, {
        status: "CREATED",
        receiverLeaseHeld: true,
        transferCodeReleased: false,
        expectedArtifactPresent: true,
      }),
    );
    const report = await runReceiveExternalPreflight(
      fakeReceiveProbe(state),
      baseInput({ operationId: SAMPLE_RECEIVE_OPERATION_ID }),
    );
    expect(report.ready).toBe(false);
    expect(report.checks.find((c) => c.id === "no_submit_yet")?.ok).toBe(false);
    expect(report.checks.find((c) => c.id === "no_submit_yet")?.detail).toMatch(
      /lease evidence disagree/,
    );
  });

  it("rejects CREATED row with transferCodeReleased=true (past preflight pollution)", async () => {
    const state = readyReceiveState();
    state.operations.set(
      SAMPLE_RECEIVE_OPERATION_ID,
      sampleReceiveOperationRow(SAMPLE_RECEIVE_OPERATION_ID, {
        status: "CREATED",
        transferCodeReleased: true,
      }),
    );
    const report = await runReceiveExternalPreflight(
      fakeReceiveProbe(state),
      baseInput({ operationId: SAMPLE_RECEIVE_OPERATION_ID }),
    );
    expect(report.ready).toBe(false);
    expect(report.checks.find((c) => c.id === "no_submit_yet")?.ok).toBe(false);
    expect(report.checks.find((c) => c.id === "no_submit_yet")?.detail).toMatch(
      /CREATED-stage pollution/,
    );
  });

  it("fails when dual-control attestation is bound to a different attempt", async () => {
    const report = await runReceiveExternalPreflight(
      fakeReceiveProbe(readyReceiveState()),
      baseInput({ authorization: sampleReceiveAuth("other-attempt") }),
    );
    expect(report.ready).toBe(false);
    expect(report.plan).toBeNull();
    expect(report.checks.find((c) => c.id === "dual_control_authorization")?.ok).toBe(
      false,
    );
    expect(report.runnerLockHandle).toBeNull();
  });

  it("fails when plan attemptId is empty", async () => {
    const lock = createRunnerLock();
    const report = await runReceiveExternalPreflight(
      fakeReceiveProbe(readyReceiveState()),
      baseInput({
        attemptId: "",
        authorization: sampleReceiveAuth(""),
        runnerLock: lock,
      }),
    );
    expect(report.ready).toBe(false);
    expect(report.plan).toBeNull();
    expect(report.runnerLockHandle).toBeNull();
    expect(lock.held).toBe(false);
    expect(report.checks.find((c) => c.id === "dual_control_authorization")?.detail).toMatch(
      /empty/i,
    );
  });

  it("fails when receiver recovery_verified_at is null (negative)", async () => {
    const state = readyReceiveState();
    state.receivers.set(
      SAMPLE_RECEIVE_RECEIVER_ID,
      eligibleReceiveReceiver(SAMPLE_RECEIVE_RECEIVER_ID, {
        recoveryVerifiedAt: null,
      }),
    );
    const report = await runReceiveExternalPreflight(
      fakeReceiveProbe(state),
      baseInput(),
    );
    expect(report.ready).toBe(false);
    expect(report.checks.find((c) => c.id === "receiver_eligibility_d917")?.ok).toBe(
      false,
    );
    expect(
      report.checks.find((c) => c.id === "receiver_eligibility_d917")?.detail,
    ).toMatch(/recovery_verified_at IS NULL/);
  });

  it("fails when receiver is missing", async () => {
    const state = readyReceiveState();
    state.receivers.clear();
    const report = await runReceiveExternalPreflight(
      fakeReceiveProbe(state),
      baseInput(),
    );
    expect(report.ready).toBe(false);
    expect(report.checks.find((c) => c.id === "receiver_eligibility_d917")?.detail).toMatch(
      /not found/,
    );
  });

  it("fails when external payer is node-controlled", async () => {
    const state = readyReceiveState();
    state.payers.set(
      SAMPLE_RECEIVE_PAYER_ADDRESS,
      eligibleExternalPayer(SAMPLE_RECEIVE_PAYER_ADDRESS, {
        isNodeControlledWallet: true,
      }),
    );
    const report = await runReceiveExternalPreflight(
      fakeReceiveProbe(state),
      baseInput(),
    );
    expect(report.ready).toBe(false);
    expect(
      report.checks.find((c) => c.id === "external_payer_independent")?.ok,
    ).toBe(false);
  });

  it("fails when amount exceeds 0.01 hard cap", async () => {
    const report = await runReceiveExternalPreflight(
      fakeReceiveProbe(readyReceiveState()),
      baseInput({ amount: "0.02" }),
    );
    expect(report.ready).toBe(false);
    expect(report.checks.find((c) => c.id === "amount_fixed_fractional")?.detail).toMatch(
      /0\.01/,
    );
  });

  it("fails when amount is zero or negative", async () => {
    const zero = await runReceiveExternalPreflight(
      fakeReceiveProbe(readyReceiveState()),
      baseInput({ amount: "0" }),
    );
    expect(zero.ready).toBe(false);
    expect(zero.checks.find((c) => c.id === "amount_fixed_fractional")?.ok).toBe(false);

    const neg = await runReceiveExternalPreflight(
      fakeReceiveProbe(readyReceiveState()),
      baseInput({ amount: "-0.000001" }),
    );
    expect(neg.ready).toBe(false);
  });

  it("fails when receiver has an active lease", async () => {
    const state = readyReceiveState();
    state.leases.set(SAMPLE_RECEIVE_RECEIVER_ID, [
      {
        walletId: SAMPLE_RECEIVE_RECEIVER_ID,
        leaseRole: "RECEIVER",
        operationId: "99999999-9999-4999-8999-999999999999",
      },
    ]);
    const report = await runReceiveExternalPreflight(
      fakeReceiveProbe(state),
      baseInput(),
    );
    expect(report.ready).toBe(false);
    expect(report.checks.find((c) => c.id === "no_active_lease")?.ok).toBe(false);
    expect(report.checks.find((c) => c.id === "no_active_lease")?.detail).toMatch(
      /in-flight lease/,
    );
  });

  it("fails when vault backup is missing or stale", async () => {
    const missing = readyReceiveState();
    missing.vaultBackupCapturedAt = null;
    const r1 = await runReceiveExternalPreflight(fakeReceiveProbe(missing), baseInput());
    expect(r1.ready).toBe(false);
    expect(r1.checks.find((c) => c.id === "fresh_vault_backup")?.ok).toBe(false);

    const stale = readyReceiveState();
    stale.vaultBackupCapturedAt = "2026-07-01T00:00:00.000Z";
    const r2 = await runReceiveExternalPreflight(fakeReceiveProbe(stale), baseInput());
    expect(r2.ready).toBe(false);
    expect(r2.checks.find((c) => c.id === "fresh_vault_backup")?.ok).toBe(false);
  });

  it("fails when build/version/config is missing", async () => {
    const state = readyReceiveState();
    state.buildVersion = null;
    const report = await runReceiveExternalPreflight(
      fakeReceiveProbe(state),
      baseInput(),
    );
    expect(report.ready).toBe(false);
    expect(report.checks.find((c) => c.id === "build_version_recorded")?.ok).toBe(false);
  });

  it("fails when operation already has a step_2 submit attempt (the never-blind-retry rule)", async () => {
    const state = readyReceiveStateWithOperation();
    state.operations.set(
      SAMPLE_RECEIVE_OPERATION_ID,
      sampleReceiveOperationRow(SAMPLE_RECEIVE_OPERATION_ID, {
        step2SubmitAttempted: true,
      }),
    );
    const report = await runReceiveExternalPreflight(
      fakeReceiveProbe(state),
      baseInput({ operationId: SAMPLE_RECEIVE_OPERATION_ID }),
    );
    expect(report.ready).toBe(false);
    expect(report.checks.find((c) => c.id === "no_submit_yet")?.ok).toBe(false);
    expect(report.checks.find((c) => c.id === "no_submit_yet")?.detail).toMatch(
      /second ceremony|the never-blind-retry rule/i,
    );
  });

  it("fails when expected-artifact field order diverges from A.3.1", async () => {
    const state = readyReceiveStateWithOperation();
    state.operations.set(
      SAMPLE_RECEIVE_OPERATION_ID,
      sampleReceiveOperationRow(SAMPLE_RECEIVE_OPERATION_ID, {
        expectedArtifactFieldOrder: ["purpose", "amount_zkz"],
      }),
    );
    const report = await runReceiveExternalPreflight(
      fakeReceiveProbe(state),
      baseInput({ operationId: SAMPLE_RECEIVE_OPERATION_ID }),
    );
    expect(report.ready).toBe(false);
    expect(
      report.checks.find((c) => c.id === "expected_artifact_or_clean_start")?.detail,
    ).toMatch(/A\.3\.1/);
  });

  it("does not acquire runner lock when earlier checks fail", async () => {
    const lock = createRunnerLock();
    const prior = lock.tryAcquire("other-holder");
    expect(prior).not.toBeNull();

    const state = readyReceiveState();
    state.receivers.clear();
    const report = await runReceiveExternalPreflight(
      fakeReceiveProbe(state),
      baseInput({ runnerLock: lock }),
    );
    expect(report.ready).toBe(false);
    expect(lock.held).toBe(true);
    expect(lock.holderId).toBe("other-holder");
    expect(report.checks.find((c) => c.id === "runner_lock_acquired")?.detail).toMatch(
      /not attempted/,
    );
    prior?.release();
  });

  it("fails when runner lock is already held and earlier checks are green", async () => {
    const lock = createRunnerLock();
    const prior = lock.tryAcquire("other-holder");
    const report = await runReceiveExternalPreflight(
      fakeReceiveProbe(readyReceiveState()),
      baseInput({ runnerLock: lock }),
    );
    expect(report.ready).toBe(false);
    expect(report.runnerLockHandle).toBeNull();
    expect(report.checks.find((c) => c.id === "runner_lock_acquired")?.detail).toMatch(
      /held by other-holder/,
    );
    prior?.release();
  });

  it("accepts CREATED unassigned row without artifact", async () => {
    const state = readyReceiveState();
    state.operations.set(
      SAMPLE_RECEIVE_OPERATION_ID,
      sampleReceiveOperationRow(SAMPLE_RECEIVE_OPERATION_ID, {
        status: "CREATED",
        receiverWalletId: null,
        expectedArtifactPresent: false,
        expectedArtifactFieldOrder: null,
        receiverLeaseHeld: false,
        transferCodeReleased: false,
      }),
    );
    const report = await runReceiveExternalPreflight(
      fakeReceiveProbe(state),
      baseInput({ operationId: SAMPLE_RECEIVE_OPERATION_ID }),
    );
    expect(report.ready).toBe(true);
    expect(
      report.checks.find((c) => c.id === "expected_artifact_or_clean_start")?.detail,
    ).toMatch(/unassigned/);
    report.runnerLockHandle?.release();
  });

  it("records abort criteria that forbid resubmit and pin TTL", async () => {
    const report = await runReceiveExternalPreflight(
      fakeReceiveProbe(readyReceiveState()),
      baseInput(),
    );
    expect(report.ready).toBe(true);
    expect(report.abortCriteria.codeTtlDefaultSecs).toBe(300);
    const halt = report.abortCriteria.rules.find((r) => r.trigger === "OPERATOR_HALT");
    expect(halt?.mayResubmit).toBe(false);
    expect(halt?.action).toBe("HOLD_RECEIVER_LEASE_AND_RECONCILE");
    report.runnerLockHandle?.release();
  });
});

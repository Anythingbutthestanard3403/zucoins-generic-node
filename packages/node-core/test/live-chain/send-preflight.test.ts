import { describe, expect, it } from "vitest";

import {
  DEFAULT_SEND_AMOUNT,
  DEFAULT_SEND_AMOUNT_CEILING,
  FORBIDDEN_APPROVAL_FIELDS,
  SEND_AMOUNT_HARD_CAP,
  SEND_APPROVAL_FIELD_ORDER,
  SEND_APPROVAL_PURPOSE,
  SEND_EXPECTED_FIELD_ORDER,
  SEND_EXPECTED_PURPOSE,
  effectiveSendAmountCeiling,
  evaluateExternalRecipient,
  evaluateSendSourceEligibility,
  runSendExternalPreflight,
} from "./send-preflight.js";
import {
  SEND_ABORT_POLICY_ID,
  SEND_REDEMPTION_WINDOW_SECS,
  sendAbortActionFor,
  sendExternalAbortCriteria,
  type SendAbortTrigger,
} from "./send-abort-criteria.js";
import { createRunnerLock } from "./runner-lock.js";
import {
  SAMPLE_EXTERNAL_KEYHOLDER,
  SAMPLE_SEND_DEST_ADDRESS,
  SAMPLE_SEND_OPERATION_ID,
  SAMPLE_SEND_SOURCE_ID,
  eligibleExternalRecipient,
  eligibleSendSource,
  fakeSendProbe,
  readySendState,
  sampleApprovalChallenge,
  sampleOperationRow,
  sampleSendAuth,
} from "./send-fakes.js";

const ATTEMPT = "attempt-send-1";

function baseInput(overrides: Record<string, unknown> = {}) {
  return {
    attemptId: ATTEMPT,
    operationId: SAMPLE_SEND_OPERATION_ID,
    sourceWalletId: SAMPLE_SEND_SOURCE_ID,
    destinationAddress: SAMPLE_SEND_DEST_ADDRESS,
    amount: DEFAULT_SEND_AMOUNT,
    authorization: sampleSendAuth(ATTEMPT),
    runnerLock: createRunnerLock(),
    runnerHolderId: "fixture-1-preflight",
    ...overrides,
  };
}

describe("effectiveSendAmountCeiling (external-amount-cap hard cap)", () => {
  it("defaults to the hard cap", () => {
    expect(effectiveSendAmountCeiling()).toBe(SEND_AMOUNT_HARD_CAP);
    expect(effectiveSendAmountCeiling(undefined)).toBe(DEFAULT_SEND_AMOUNT_CEILING);
  });

  it("allows a tighter caller ceiling below the hard cap", () => {
    expect(effectiveSendAmountCeiling("0.001")).toBe("0.001");
  });

  it("clamps a caller ceiling above 0.01 down to the hard cap", () => {
    expect(effectiveSendAmountCeiling("100")).toBe(SEND_AMOUNT_HARD_CAP);
    expect(effectiveSendAmountCeiling("0.02")).toBe(SEND_AMOUNT_HARD_CAP);
  });
});

describe("A.4.1 / A.3.3 field-order pins", () => {
  it("freezes the 12-field approval order (no split_inner_sha256)", () => {
    expect([...SEND_APPROVAL_FIELD_ORDER]).toEqual([
      "purpose",
      "canonical_version",
      "node_id",
      "operation_id",
      "source_selector",
      "source_pubkey",
      "destination_address",
      "amount_zkz",
      "references_operation_id",
      "nonce",
      "issued_at",
      "expires_at",
    ]);
    expect(SEND_APPROVAL_FIELD_ORDER).toHaveLength(12);
    expect(SEND_APPROVAL_PURPOSE).toBe("zp-send-external-approval-v1");
    expect(FORBIDDEN_APPROVAL_FIELDS).toContain("split_inner_sha256");
    expect(SEND_APPROVAL_FIELD_ORDER).not.toContain("split_inner_sha256");
  });

  it("freezes the 10-field expected-artifact order", () => {
    expect([...SEND_EXPECTED_FIELD_ORDER]).toEqual([
      "purpose",
      "canonical_version",
      "node_id",
      "implementer_id",
      "operation_id",
      "source_selector",
      "source_pubkey",
      "destination_address",
      "amount_zkz",
      "references_operation_id",
    ]);
    expect(SEND_EXPECTED_FIELD_ORDER).toHaveLength(10);
    expect(SEND_EXPECTED_PURPOSE).toBe("zp-send-external-expected-v1");
  });
});

describe("evaluateSendSourceEligibility", () => {
  it("accepts node_generated controlled source", () => {
    const result = evaluateSendSourceEligibility(eligibleSendSource());
    expect(result.ok).toBe(true);
  });

  it("rejects imported or uncontrolled source", () => {
    expect(
      evaluateSendSourceEligibility(
        eligibleSendSource(SAMPLE_SEND_SOURCE_ID, { keyOrigin: "imported" }),
      ).ok,
    ).toBe(false);
    expect(
      evaluateSendSourceEligibility(
        eligibleSendSource(SAMPLE_SEND_SOURCE_ID, { nodeControlled: false }),
      ).ok,
    ).toBe(false);
  });

  it("rejects quarantined source", () => {
    expect(
      evaluateSendSourceEligibility(
        eligibleSendSource(SAMPLE_SEND_SOURCE_ID, { walletState: "QUARANTINED" }),
      ).ok,
    ).toBe(false);
  });
});

describe("evaluateExternalRecipient (independent control)", () => {
  it("accepts a disposable external counterparty", () => {
    const result = evaluateExternalRecipient(eligibleExternalRecipient());
    expect(result.ok).toBe(true);
    expect(result.detail).toMatch(SAMPLE_EXTERNAL_KEYHOLDER);
  });

  it("rejects destination that resolves to the node's blessed set (stale/internal)", () => {
    const result = evaluateExternalRecipient(
      eligibleExternalRecipient(SAMPLE_SEND_DEST_ADDRESS, {
        resolvesToNodeBlessedSet: true,
      }),
    );
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/blessed internal set/);
  });

  it("rejects destination that is a node-controlled wallet", () => {
    const result = evaluateExternalRecipient(
      eligibleExternalRecipient(SAMPLE_SEND_DEST_ADDRESS, {
        isNodeControlledWallet: true,
      }),
    );
    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/node-controlled/);
  });

  it("rejects undocumented keyholder", () => {
    expect(
      evaluateExternalRecipient(
        eligibleExternalRecipient(SAMPLE_SEND_DEST_ADDRESS, { keyholderId: "" }),
      ).ok,
    ).toBe(false);
  });
});

describe("sendExternalAbortCriteria (T2 + no node submit)", () => {
  it("pins T2 to SEND_REDEMPTION_WINDOW_SECS=300 and forbids node submit", () => {
    const criteria = sendExternalAbortCriteria();
    expect(criteria.policyId).toBe(SEND_ABORT_POLICY_ID);
    expect(criteria.redemptionWindowSecs).toBe(300);
    expect(criteria.redemptionWindowSecs).toBe(SEND_REDEMPTION_WINDOW_SECS);
    expect(criteria.nodeSubmitForbidden).toBe(true);
    expect(criteria.blindRetryForbidden).toBe(true);
    expect(criteria.rebuildRequiresPositiveNonLandingOracle).toBe(true);
  });

  it("never licenses submit, replacement partial, or approval reconsume", () => {
    const criteria = sendExternalAbortCriteria();
    for (const rule of criteria.rules) {
      expect(rule.maySubmit).toBe(false);
      expect(rule.mayMintReplacementPartial).toBe(false);
      expect(rule.mayReconsumeApproval).toBe(false);
    }
  });

  it("routes redemption-window elapsed to hold-source (never EXPIRED / never release)", () => {
    const rule = sendAbortActionFor("REDEMPTION_WINDOW_ELAPSED");
    expect(rule.action).toBe("HOLD_SOURCE_ON_REDEMPTION_WINDOW");
    expect(rule.detail).toMatch(/never authorizes a replacement partial/);
    // Detail cites the 3600s RECEIVE golden as a negative — the bound timer is 300.
    expect(rule.detail).toMatch(/SEND_REDEMPTION_WINDOW_SECS=300/);
    expect(rule.detail).toMatch(/Do not derive this window from the payer-chosen 3600s/);
    expect(rule.detail.toLowerCase()).not.toMatch(/just retry/);
  });

  it("covers every closed trigger", () => {
    const triggers: SendAbortTrigger[] = [
      "FORMATION_REJECTED",
      "PARTIAL_DELIVERED_UNOBSERVED",
      "INVARIANT_BREACH",
      "LANDED_VERIFIED",
      "OPERATOR_HALT",
      "REDEMPTION_WINDOW_ELAPSED",
    ];
    const criteria = sendExternalAbortCriteria();
    expect(criteria.rules.map((r) => r.trigger).sort()).toEqual([...triggers].sort());
  });
});

describe("runSendExternalPreflight", () => {
  it("reports ready with plan, abort criteria, backup timestamp, and held runner lock", async () => {
    const lock = createRunnerLock();
    const report = await runSendExternalPreflight(
      fakeSendProbe(readySendState()),
      baseInput({ runnerLock: lock }),
    );

    expect(report.ready).toBe(true);
    expect(report.plan).toEqual({
      kind: "SEND_EXTERNAL",
      attemptId: ATTEMPT,
      operationId: SAMPLE_SEND_OPERATION_ID,
      sourceWalletId: SAMPLE_SEND_SOURCE_ID,
      sourcePubkey: "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=",
      destinationAddress: SAMPLE_SEND_DEST_ADDRESS,
      amount: DEFAULT_SEND_AMOUNT,
      authorization: sampleSendAuth(ATTEMPT),
      recipientKeyholderId: SAMPLE_EXTERNAL_KEYHOLDER,
      redemptionWindowSecs: 300,
      vaultBackupCapturedAt: "2026-07-27T00:00:00.000Z",
    });
    expect(report.vaultBackupCapturedAt).toBe("2026-07-27T00:00:00.000Z");
    expect(report.abortCriteria.nodeSubmitForbidden).toBe(true);
    expect(report.runnerLockHandle).not.toBeNull();
    expect(lock.held).toBe(true);
    expect(report.checks.every((c) => c.ok)).toBe(true);
    expect(report.checks.map((c) => c.id)).toEqual([
      "dual_control_authorization",
      "source_identity_and_balance",
      "external_recipient_independent",
      "amount_fixed_fractional",
      "no_active_lease",
      "abort_criteria_bound",
      "fresh_vault_backup",
      "approval_tuple_byte_correct",
      "expected_artifact_present",
      "no_lease_or_preimage_yet",
      "approval_not_consumed",
      "runner_lock_acquired",
    ]);

    report.runnerLockHandle?.release();
    expect(lock.held).toBe(false);
  });

  it("fails when dual-control attestation is bound to a different attempt", async () => {
    const report = await runSendExternalPreflight(
      fakeSendProbe(readySendState()),
      baseInput({ authorization: sampleSendAuth("other-attempt") }),
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
    const report = await runSendExternalPreflight(
      fakeSendProbe(readySendState()),
      baseInput({
        attemptId: "",
        authorization: sampleSendAuth(""),
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

  it("fails when source has an active concurrent lease (the one-in-flight-per-wallet rule)", async () => {
    const state = readySendState();
    state.leases.set(SAMPLE_SEND_SOURCE_ID, [
      {
        walletId: SAMPLE_SEND_SOURCE_ID,
        leaseRole: "SEND_SOURCE",
        operationId: "op-stray-send",
      },
    ]);
    const report = await runSendExternalPreflight(fakeSendProbe(state), baseInput());
    expect(report.ready).toBe(false);
    const check = report.checks.find((c) => c.id === "no_active_lease");
    expect(check?.ok).toBe(false);
    expect(check?.detail).toMatch(/SEND_SOURCE/);
  });

  it("fails when vault backup is missing (negative path)", async () => {
    const state = readySendState();
    state.vaultBackupCapturedAt = null;
    state.sources.set(
      SAMPLE_SEND_SOURCE_ID,
      eligibleSendSource(SAMPLE_SEND_SOURCE_ID, { backupPresent: false }),
    );
    const report = await runSendExternalPreflight(fakeSendProbe(state), baseInput());
    expect(report.ready).toBe(false);
    expect(report.checks.find((c) => c.id === "fresh_vault_backup")?.ok).toBe(false);
  });

  it("fails when amount exceeds the acceptance ceiling / hard cap", async () => {
    const report = await runSendExternalPreflight(
      fakeSendProbe(readySendState()),
      baseInput({ amount: "0.05" }),
    );
    expect(report.ready).toBe(false);
    const check = report.checks.find((c) => c.id === "amount_fixed_fractional");
    expect(check?.ok).toBe(false);
    expect(check?.detail).toMatch(new RegExp(SEND_AMOUNT_HARD_CAP));
  });

  it("rejects amountCeiling override above hard cap", async () => {
    const lock = createRunnerLock();
    const report = await runSendExternalPreflight(
      fakeSendProbe(readySendState()),
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
    expect(check?.detail).toMatch(/hard cap/i);
  });

  it("fails when source balance is insufficient", async () => {
    const state = readySendState();
    state.balances.set(SAMPLE_SEND_SOURCE_ID, "0");
    const report = await runSendExternalPreflight(fakeSendProbe(state), baseInput());
    expect(report.ready).toBe(false);
    expect(report.checks.find((c) => c.id === "amount_fixed_fractional")?.detail).toMatch(
      /balance/,
    );
  });

  it("fails stale/internal destination that resolves to blessed set", async () => {
    const state = readySendState();
    state.recipients.set(
      SAMPLE_SEND_DEST_ADDRESS,
      eligibleExternalRecipient(SAMPLE_SEND_DEST_ADDRESS, {
        resolvesToNodeBlessedSet: true,
      }),
    );
    const report = await runSendExternalPreflight(fakeSendProbe(state), baseInput());
    expect(report.ready).toBe(false);
    const check = report.checks.find((c) => c.id === "external_recipient_independent");
    expect(check?.ok).toBe(false);
    expect(check?.detail).toMatch(/blessed internal set|stale/i);
  });

  it("fails when destination is the node acting as its own counterparty", async () => {
    const state = readySendState();
    state.recipients.set(
      SAMPLE_SEND_DEST_ADDRESS,
      eligibleExternalRecipient(SAMPLE_SEND_DEST_ADDRESS, {
        isNodeControlledWallet: true,
      }),
    );
    const report = await runSendExternalPreflight(fakeSendProbe(state), baseInput());
    expect(report.ready).toBe(false);
    expect(
      report.checks.find((c) => c.id === "external_recipient_independent")?.ok,
    ).toBe(false);
  });

  it("fails when approval field order drifts from A.4.1", async () => {
    const state = readySendState();
    state.challenges.set(
      SAMPLE_SEND_OPERATION_ID,
      sampleApprovalChallenge(SAMPLE_SEND_OPERATION_ID, {
        fieldOrder: [
          "purpose",
          "canonical_version",
          "node_id",
          "operation_id",
          "source_selector",
          "source_pubkey",
          "amount_zkz",
          "destination_address",
          "references_operation_id",
          "nonce",
          "issued_at",
          "expires_at",
        ],
      }),
    );
    const report = await runSendExternalPreflight(fakeSendProbe(state), baseInput());
    expect(report.ready).toBe(false);
    const check = report.checks.find((c) => c.id === "approval_tuple_byte_correct");
    expect(check?.ok).toBe(false);
    expect(check?.detail).toMatch(/field order/);
  });

  it("fails when approval carries forbidden split_inner_sha256", async () => {
    const state = readySendState();
    state.challenges.set(
      SAMPLE_SEND_OPERATION_ID,
      sampleApprovalChallenge(SAMPLE_SEND_OPERATION_ID, {
        carriesSplitInnerSha256: true,
      }),
    );
    const report = await runSendExternalPreflight(fakeSendProbe(state), baseInput());
    expect(report.ready).toBe(false);
    expect(
      report.checks.find((c) => c.id === "approval_tuple_byte_correct")?.detail,
    ).toMatch(/split_inner_sha256/);
  });

  it("fails when approval is already consumed (TOTP not this ticket's job)", async () => {
    const state = readySendState();
    state.operations.set(
      SAMPLE_SEND_OPERATION_ID,
      sampleOperationRow(SAMPLE_SEND_OPERATION_ID, { approvalConsumed: true }),
    );
    state.challenges.set(
      SAMPLE_SEND_OPERATION_ID,
      sampleApprovalChallenge(SAMPLE_SEND_OPERATION_ID, { consumed: true }),
    );
    const report = await runSendExternalPreflight(fakeSendProbe(state), baseInput());
    expect(report.ready).toBe(false);
    expect(report.checks.find((c) => c.id === "approval_not_consumed")?.ok).toBe(false);
  });

  it("fails when CREATED row already holds a source lease or preimage", async () => {
    const state = readySendState();
    state.operations.set(
      SAMPLE_SEND_OPERATION_ID,
      sampleOperationRow(SAMPLE_SEND_OPERATION_ID, {
        sourceLeaseHeld: true,
        splitChainPreimageExists: true,
      }),
    );
    const report = await runSendExternalPreflight(fakeSendProbe(state), baseInput());
    expect(report.ready).toBe(false);
    const check = report.checks.find((c) => c.id === "no_lease_or_preimage_yet");
    expect(check?.ok).toBe(false);
    expect(check?.detail).toMatch(/sourceLeaseHeld=true/);
  });

  it("fails when expected artifact is missing on the CREATED row", async () => {
    const state = readySendState();
    state.operations.set(
      SAMPLE_SEND_OPERATION_ID,
      sampleOperationRow(SAMPLE_SEND_OPERATION_ID, {
        expectedArtifactPresent: false,
        expectedArtifactFieldOrder: null,
      }),
    );
    const report = await runSendExternalPreflight(fakeSendProbe(state), baseInput());
    expect(report.ready).toBe(false);
    expect(report.checks.find((c) => c.id === "expected_artifact_present")?.ok).toBe(
      false,
    );
  });

  it("refuses the runner lock when another holder already owns it", async () => {
    const lock = createRunnerLock();
    const held = lock.tryAcquire("other-runner");
    expect(held).not.toBeNull();

    const report = await runSendExternalPreflight(
      fakeSendProbe(readySendState()),
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
    const state = readySendState();
    state.vaultBackupCapturedAt = null;
    const report = await runSendExternalPreflight(
      fakeSendProbe(state),
      baseInput({ runnerLock: lock }),
    );
    expect(report.ready).toBe(false);
    expect(lock.held).toBe(false);
    expect(report.checks.find((c) => c.id === "runner_lock_acquired")?.detail).toMatch(
      /not attempted/,
    );
  });

  it("records abort criteria that forbid node submit and pin T2=300", async () => {
    const report = await runSendExternalPreflight(
      fakeSendProbe(readySendState()),
      baseInput(),
    );
    expect(report.ready).toBe(true);
    expect(report.abortCriteria.redemptionWindowSecs).toBe(300);
    const elapsed = report.abortCriteria.rules.find(
      (r) => r.trigger === "REDEMPTION_WINDOW_ELAPSED",
    );
    expect(elapsed?.maySubmit).toBe(false);
    expect(elapsed?.mayMintReplacementPartial).toBe(false);
    report.runnerLockHandle?.release();
  });

  it("fails when fresh gateway balance read throws", async () => {
    const state = readySendState();
    state.balanceErrors.set(SAMPLE_SEND_SOURCE_ID, "gateway unavailable");
    const report = await runSendExternalPreflight(fakeSendProbe(state), baseInput());
    expect(report.ready).toBe(false);
    expect(
      report.checks.find((c) => c.id === "source_identity_and_balance")?.detail,
    ).toMatch(/gateway/);
  });
});

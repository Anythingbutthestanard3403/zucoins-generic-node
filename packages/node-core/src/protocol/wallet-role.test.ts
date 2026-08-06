import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import { type SettledSplitChainTransaction, type SplitChainInnerV2 } from "./inner.js";
import { GENESIS_PROJECTION, isWalletObservationRole, projectRoleRelativeState } from "./wallet-role.js";

const SENDER = "sender-pubkey-AAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const RECEIVER = "receiver-pubkey-BBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
const OTHER = "unrelated-pubkey-CCCCCCCCCCCCCCCCCCCCCCCCCCCC=";

function baseInner(overrides: Partial<SplitChainInnerV2> = {}): SplitChainInnerV2 {
  return {
    type: "unique_combinable",
    version: "2",
    unix_time_secs: "1784332700",
    signer_steps: 2,
    step_1_signer: "sender",
    step_2_signer: "receiver",
    step_1_key_public__base64urlsafe: SENDER,
    step_2_key_public__base64urlsafe: RECEIVER,
    step_1_state: { amount: "10" },
    step_2_state: { amount: "5" },
    previous_step_1_state_signature: "prior-sender-sig",
    previous_step_2_state_signature: "prior-receiver-sig",
    ...overrides,
  };
}

function tx(overrides: Partial<SplitChainInnerV2> = {}, stepTwoSig = "tx-step-2-sig"): SettledSplitChainTransaction {
  const inner = baseInner(overrides);
  return { inner, step_1_signature: "tx-step-1-sig", step_2_signature: stepTwoSig };
}

describe("projectRoleRelativeState — sender role", () => {
  it("derives S/P/B from the step-1 fields and a non-null inner digest", () => {
    const result = projectRoleRelativeState(tx(), SENDER);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.projection.role).toBe("sender");
    expect(result.projection.S).toBe("tx-step-2-sig");
    expect(result.projection.P).toBe("prior-sender-sig");
    expect(result.projection.B).toBe("10");
    expect(result.projection.I).not.toBeNull();
  });
});

describe("projectRoleRelativeState — receiver role", () => {
  it("derives S/P/B from the step-2 fields", () => {
    const result = projectRoleRelativeState(tx(), RECEIVER);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.projection.role).toBe("receiver");
    expect(result.projection.S).toBe("tx-step-2-sig");
    expect(result.projection.P).toBe("prior-receiver-sig");
    expect(result.projection.B).toBe("5");
  });
  it("S is identical in either valid role for the same transaction (role table)", () => {
    const t = tx();
    const senderResult = projectRoleRelativeState(t, SENDER);
    const receiverResult = projectRoleRelativeState(t, RECEIVER);
    expect(senderResult.ok && receiverResult.ok).toBe(true);
    if (!senderResult.ok || !receiverResult.ok) return;
    expect(senderResult.projection.S).toBe(receiverResult.projection.S);
  });
  it("never hard-codes the receiver's P for a sender-side observation, or vice versa", () => {
    const t = tx({ previous_step_1_state_signature: "sender-link", previous_step_2_state_signature: "receiver-link" });
    const sender = projectRoleRelativeState(t, SENDER);
    const receiver = projectRoleRelativeState(t, RECEIVER);
    expect(sender.ok && sender.projection.P).toBe("sender-link");
    expect(receiver.ok && receiver.projection.P).toBe("receiver-link");
  });
});

describe("projectRoleRelativeState — NEGATIVE: self-transfer and absent wallet", () => {
  it("rejects a wallet matching both step_1 and step_2 (self-transfer)", () => {
    const result = projectRoleRelativeState(tx({ step_2_key_public__base64urlsafe: SENDER }), SENDER);
    expect(result).toEqual({
      ok: false,
      reason: "wallet_role_invalid",
      detail: "queried wallet is neither or both of the transaction's step_1/step_2 keys",
    });
  });
  it("rejects a wallet matching neither step_1 nor step_2", () => {
    const result = projectRoleRelativeState(tx(), OTHER);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("wallet_role_invalid");
  });
});

describe("GENESIS_PROJECTION — models genesis exactly", () => {
  it("is S=\"\", P=\"\", B=\"0\", I=null with role genesis", () => {
    expect(GENESIS_PROJECTION).toEqual({ role: "genesis", S: "", P: "", B: "0", I: null });
  });
});

describe("projectRoleRelativeState — 32 decimal-place precision (vector 9)", () => {
  it("preserves a 32-decimal-place balance exactly, with no rounding", () => {
    const amount32dp = "1." + "1".repeat(32);
    const result = projectRoleRelativeState(tx({ step_1_state: { amount: amount32dp } }), SENDER);
    expect(result.ok && result.projection.B).toBe(amount32dp);
  });
  it("a one-unit-at-32dp difference produces a different B (mismatch is observable)", () => {
    const a = "1." + "1".repeat(32);
    const b = "1." + "1".repeat(31) + "2";
    const resultA = projectRoleRelativeState(tx({ step_1_state: { amount: a } }), SENDER);
    const resultB = projectRoleRelativeState(tx({ step_1_state: { amount: b } }), SENDER);
    expect(resultA.ok && resultA.projection.B).not.toBe(resultB.ok && resultB.projection.B);
  });
});

describe("inner digest I — exact JSON.stringify(inner) SHA-256", () => {
  it("matches an independently computed SHA-256 of JSON.stringify(inner)", () => {
    const t = tx();
    const expected = createHash("sha256").update(JSON.stringify(t.inner), "utf8").digest("hex");
    const result = projectRoleRelativeState(t, SENDER);
    expect(result.ok && result.projection.I).toBe(expected);
  });
  it("changes when any inner field changes (e.g. unix_time_secs)", () => {
    const a = projectRoleRelativeState(tx({ unix_time_secs: "1" }), SENDER);
    const b = projectRoleRelativeState(tx({ unix_time_secs: "2" }), SENDER);
    expect(a.ok && a.projection.I).not.toBe(b.ok && b.projection.I);
  });
});

describe("isWalletObservationRole", () => {
  it("accepts exactly the frozen role vocabulary and rejects anything else", () => {
    expect(isWalletObservationRole("sender")).toBe(true);
    expect(isWalletObservationRole("receiver")).toBe(true);
    expect(isWalletObservationRole("genesis")).toBe(true);
    expect(isWalletObservationRole("payer")).toBe(false);
  });
});

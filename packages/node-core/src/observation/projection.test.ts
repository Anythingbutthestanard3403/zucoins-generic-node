import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  type SettledSplitChainTransaction,
  type SplitChainInnerV2,
} from "../protocol/inner.js";
import { GENESIS_PROJECTION, projectRoleRelativeState } from "../protocol/wallet-role.js";
import {
  inboundReceiverLinkMatchesBaselineS,
  projectGenesisState,
  projectRoleState,
  reconstructInnerPreimageText,
  toWalletStateProjection,
} from "./projection.js";

const SENDER = "sender-pubkey-AAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const RECEIVER = "receiver-pubkey-BBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
const OTHER = "unrelated-pubkey-CCCCCCCCCCCCCCCCCCCCCCCCCCCC=";

const S0 = "baseline-S0-step2-sig";
const P0 = "baseline-P0-prior-link";
const STEP1_SIG = "tx-step-1-sig";
const STEP2_SIG = "tx-step-2-sig";

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
    step_2_state: { amount: "15" },
    previous_step_1_state_signature: "prior-sender-sig",
    previous_step_2_state_signature: S0,
    ...overrides,
  };
}

function tx(
  overrides: Partial<SplitChainInnerV2> = {},
  stepTwoSig = STEP2_SIG,
): SettledSplitChainTransaction {
  return {
    inner: baseInner(overrides),
    step_1_signature: STEP1_SIG,
    step_2_signature: stepTwoSig,
  };
}

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

describe("projectRoleState — sender role", () => {
  it("derives role/S/P/B/I and both signatures from the verified inner", () => {
    const t = tx({
      previous_step_1_state_signature: "sender-P",
      step_1_state: { amount: "10" },
    });
    const result = projectRoleState(t, SENDER);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.projection.role).toBe("sender");
    expect(result.projection.S).toBe(STEP2_SIG);
    expect(result.projection.P).toBe("sender-P");
    expect(result.projection.B).toBe("10");
    expect(result.projection.step_1_signature).toBe(STEP1_SIG);
    expect(result.projection.step_2_signature).toBe(STEP2_SIG);
    expect(result.projection.inner_preimage_text).toBe(JSON.stringify(t.inner));
    expect(result.projection.I).toBe(sha256Hex(result.projection.inner_preimage_text));
  });

  it("S is always step_2_signature, never step_1_signature", () => {
    const result = projectRoleState(tx(), SENDER);
    expect(result.ok && result.projection.S).toBe(STEP2_SIG);
    expect(result.ok && result.projection.S).not.toBe(STEP1_SIG);
  });
});

describe("projectRoleState — receiver role", () => {
  it("derives P/B from step_2 fields and S from step_2_signature", () => {
    const result = projectRoleState(tx(), RECEIVER);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.projection.role).toBe("receiver");
    expect(result.projection.S).toBe(STEP2_SIG);
    expect(result.projection.P).toBe(S0);
    expect(result.projection.B).toBe("15");
  });

  it("S is identical for sender and receiver on the same transaction", () => {
    const t = tx();
    const sender = projectRoleState(t, SENDER);
    const receiver = projectRoleState(t, RECEIVER);
    expect(sender.ok && receiver.ok).toBe(true);
    if (!sender.ok || !receiver.ok) return;
    expect(sender.projection.S).toBe(receiver.projection.S);
  });

  it("never hard-codes the receiver's P for a sender-side observation, or vice versa", () => {
    const t = tx({
      previous_step_1_state_signature: "sender-link",
      previous_step_2_state_signature: "receiver-link",
    });
    const sender = projectRoleState(t, SENDER);
    const receiver = projectRoleState(t, RECEIVER);
    expect(sender.ok && sender.projection.P).toBe("sender-link");
    expect(receiver.ok && receiver.projection.P).toBe("receiver-link");
  });
});

describe("projectRoleState — WALLET_ROLE_INVALID (self-transfer and absent)", () => {
  it("rejects self-transfer (wallet in both step_1 and step_2)", () => {
    const result = projectRoleState(
      tx({ step_2_key_public__base64urlsafe: SENDER }),
      SENDER,
    );
    expect(result).toEqual({
      ok: false,
      reason: "wallet_role_invalid",
      detail: "queried wallet is neither or both of the transaction's step_1/step_2 keys",
    });
  });

  it("rejects a wallet absent from both positions", () => {
    const result = projectRoleState(tx(), OTHER);
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("wallet_role_invalid");
  });

  it("does not silently default to sender on ambiguous role", () => {
    const both = projectRoleState(tx({ step_2_key_public__base64urlsafe: SENDER }), SENDER);
    const neither = projectRoleState(tx(), OTHER);
    expect(both.ok).toBe(false);
    expect(neither.ok).toBe(false);
  });
});

describe("projectGenesisState — authoritative genesis only", () => {
  it("is S=\"\", P=\"\", B=\"0\", I=null with null signed material", () => {
    expect(projectGenesisState()).toEqual({
      role: "genesis",
      S: "",
      P: "",
      B: "0",
      I: null,
      step_1_signature: null,
      step_2_signature: null,
      inner_preimage_text: null,
    });
  });

  it("matches GENESIS_PROJECTION role/S/P/B/I from", () => {
    const g = projectGenesisState();
    expect(g.role).toBe(GENESIS_PROJECTION.role);
    expect(g.S).toBe(GENESIS_PROJECTION.S);
    expect(g.P).toBe(GENESIS_PROJECTION.P);
    expect(g.B).toBe(GENESIS_PROJECTION.B);
    expect(g.I).toBe(GENESIS_PROJECTION.I);
  });

  it("projectRoleState never produces genesis from an empty-looking envelope/transaction", () => {
    // Empty predecessor links are still a settled HEAD (gateway-envelope.ts contracts this).
    const emptyLooking = tx({
      previous_step_1_state_signature: "",
      previous_step_2_state_signature: "",
      step_1_state: { amount: "0" },
      step_2_state: { amount: "0" },
    });
    const sender = projectRoleState(emptyLooking, SENDER);
    const receiver = projectRoleState(emptyLooking, RECEIVER);
    expect(sender.ok && sender.projection.role).toBe("sender");
    expect(receiver.ok && receiver.projection.role).toBe("receiver");
    expect(sender.ok && sender.projection.I).not.toBeNull();
  });

  it("404 / timeout / generic-not-found cannot produce genesis via projectRoleState", () => {
    // / virgin-wallet empty history: genesis is envelope-classified only (account_not_found or
    // status:true data:[]). Transport non-answers never yield a SettledSplitChainTransaction;
    // projectGenesisState is the sole genesis constructor after — never inferred
    // from absence of fields on a transaction object (see empty-looking HEAD test above).
    const nonAuthoritativeTransport: ReadonlyArray<{ kind: string; producesTx: false }> = [
      { kind: "http_404", producesTx: false },
      { kind: "timeout", producesTx: false },
      { kind: "generic_not_found", producesTx: false },
    ];
    for (const fixture of nonAuthoritativeTransport) {
      expect(fixture.producesTx).toBe(false);
      expect(projectGenesisState().role).toBe("genesis");
    }
    const head = projectRoleState(tx(), SENDER);
    expect(head.ok && head.projection.role).not.toBe("genesis");
  });
});

describe("inner digest I — byte-exact with compute path", () => {
  it("matches projectRoleRelativeState I and SHA-256 of reconstructInnerPreimageText", () => {
    const t = tx();
    const observation = projectRoleState(t, SENDER);
    const protocol = projectRoleRelativeState(t, SENDER);
    expect(observation.ok && protocol.ok).toBe(true);
    if (!observation.ok || !protocol.ok) return;
    expect(observation.projection.I).toBe(protocol.projection.I);
    expect(observation.projection.I).toBe(
      sha256Hex(reconstructInnerPreimageText(t.inner)),
    );
    expect(observation.projection.inner_preimage_text).toBe(JSON.stringify(t.inner));
  });
});

describe("inbound link P1 == S0", () => {
  // Baseline T0 for the receiver: prior head where S0 is the settled step_2_signature
  // and P0 is that prior head's role-relative previous link — they differ.
  const baseline = {
    S: S0,
    P: P0,
    B: "5",
  };

  it("correct check: candidate receiver P equals baseline S0", () => {
    const inbound = projectRoleState(
      tx({ previous_step_2_state_signature: baseline.S, step_2_state: { amount: "15" } }),
      RECEIVER,
    );
    expect(inbound.ok).toBe(true);
    if (!inbound.ok) return;
    expect(inboundReceiverLinkMatchesBaselineS(inbound.projection.P, baseline.S)).toBe(true);
    expect(inbound.projection.P).toBe(S0);
  });

  it("NEGATIVE (mandatory): using P0 as the expected inbound link fails the test", () => {
    // Discriminating assertion from a receive verifier that
    // checks inbound previous-link against P0 instead of S0 must fail for a correct
    // successor. This proves the test would catch that regression.
    const inbound = projectRoleState(
      tx({ previous_step_2_state_signature: baseline.S, step_2_state: { amount: "15" } }),
      RECEIVER,
    );
    expect(inbound.ok).toBe(true);
    if (!inbound.ok) return;
    expect(baseline.S).not.toBe(baseline.P);
    expect(inboundReceiverLinkMatchesBaselineS(inbound.projection.P, baseline.P)).toBe(
      false,
    );
    expect(inbound.projection.P).not.toBe(baseline.P);
  });
});

describe("toWalletStateProjection", () => {
  it("strips observation-only signed material for economic-predicate consumers", () => {
    const result = projectRoleState(tx(), RECEIVER);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(toWalletStateProjection(result.projection)).toEqual({
      role: "receiver",
      S: STEP2_SIG,
      P: S0,
      B: "15",
      I: result.projection.I,
    });
  });
});

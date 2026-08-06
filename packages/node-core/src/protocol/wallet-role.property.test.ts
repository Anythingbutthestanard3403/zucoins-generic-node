import { describe, expect, it } from "vitest";

import { type SplitChainInnerV2 } from "./inner.js";
import { projectRoleRelativeState } from "./wallet-role.js";

// property/invariant coverage for role-relative wallet projection:
// role assignment is total and correct over random wallets, self-transfer is always
// rejected, and an unrelated (wrong) wallet is always rejected. Deterministic seeded PRNG
// (mulberry32), matching the convention in
// packages/generic-node-contracts/src/amounts/property.test.ts — zero new dependencies,
// reproducible, CI-stable.
function mulberry32(seed: number): () => number {
  let s = seed;
  return () => {
    s |= 0;
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function baseInner(overrides: Partial<SplitChainInnerV2> = {}): SplitChainInnerV2 {
  return {
    type: "unique_combinable",
    version: "2",
    unix_time_secs: "1784332700",
    signer_steps: 2,
    step_1_signer: "sender",
    step_2_signer: "receiver",
    step_1_key_public__base64urlsafe: "sender-pubkey",
    step_2_key_public__base64urlsafe: "receiver-pubkey",
    step_1_state: { amount: "10" },
    step_2_state: { amount: "5" },
    previous_step_1_state_signature: "prior-sender-sig",
    previous_step_2_state_signature: "prior-receiver-sig",
    ...overrides,
  };
}

describe("property — role assignment is total and correct over random wallets", () => {
  const rng = mulberry32(0x9e3779b9);
  it("querying the sender key always yields sender; the receiver key always yields receiver; a third (wrong) key is always invalid", () => {
    for (let i = 0; i < 200; i += 1) {
      const senderKey = `pk-sender-${Math.floor(rng() * 1e9)}`;
      const receiverKey = `pk-receiver-${Math.floor(rng() * 1e9)}`;
      const thirdKey = `pk-other-${Math.floor(rng() * 1e9)}`;
      const inner = baseInner({ step_1_key_public__base64urlsafe: senderKey, step_2_key_public__base64urlsafe: receiverKey });
      const t = { inner, step_1_signature: "s1", step_2_signature: "s2" };

      const senderResult = projectRoleRelativeState(t, senderKey);
      const receiverResult = projectRoleRelativeState(t, receiverKey);
      const thirdResult = projectRoleRelativeState(t, thirdKey);

      expect(senderResult.ok && senderResult.projection.role).toBe("sender");
      expect(receiverResult.ok && receiverResult.projection.role).toBe("receiver");
      expect(thirdResult.ok).toBe(false);
    }
  });
});

describe("property — self-transfer is always rejected regardless of the shared key", () => {
  const rng = mulberry32(0xdeadbeef);
  it("a wallet occupying both step_1 and step_2 is always wallet_role_invalid", () => {
    for (let i = 0; i < 200; i += 1) {
      const sharedKey = `pk-shared-${Math.floor(rng() * 1e9)}`;
      const inner = baseInner({ step_1_key_public__base64urlsafe: sharedKey, step_2_key_public__base64urlsafe: sharedKey });
      const t = { inner, step_1_signature: "s1", step_2_signature: "s2" };

      const result = projectRoleRelativeState(t, sharedKey);
      expect(result.ok).toBe(false);
      expect(!result.ok && result.reason).toBe("wallet_role_invalid");
    }
  });
});

describe("property — the inner digest I is a pure, deterministic function of inner", () => {
  const rng = mulberry32(0x1234abcd);
  it("re-projecting the identical transaction twice always yields the identical I", () => {
    for (let i = 0; i < 100; i += 1) {
      const amount = String(1 + Math.floor(rng() * 1e6));
      const inner = baseInner({ step_1_state: { amount } });
      const t = { inner, step_1_signature: "s1", step_2_signature: "s2" };

      const first = projectRoleRelativeState(t, "sender-pubkey");
      const second = projectRoleRelativeState(t, "sender-pubkey");
      expect(first.ok && first.projection.I).toBe(second.ok && second.projection.I);
    }
  });
});

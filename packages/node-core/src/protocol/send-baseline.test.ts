import { describe, expect, it } from "vitest";

import { constructSendInner } from "./send-inner.js";
import { GENESIS_PROJECTION, type WalletStateProjection } from "./wallet-role.js";
import {
  captureSendBaselines,
  type SendBaselineInput,
} from "./send-baseline.js";

const OPERATION_ID = "33333333-3333-4333-8333-333333333333";
const SOURCE_PUBKEY = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
const DESTINATION_ADDRESS = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";

/** Valid padded Ed25519 signature — shared S so role cannot change formed bytes. */
const HEAD_S =
  "IfsGs-NrmBAQ6VWohtlXDcyrd830Agx1IzW8rcHiqYqndeGLoG8b297PjqC-grrIXFrl3GgDcV2qi6xJBlerCQ==";

const NODE_CLOCK_MS = 1_784_332_800_000;

function senderProjection(b: string): WalletStateProjection {
  return { role: "sender", S: "sig-s", P: "sig-p", B: b, I: "digest" };
}

function headProjection(
  role: "sender" | "receiver",
  b: string,
  s: string = HEAD_S,
): WalletStateProjection {
  return { role, S: s, P: s, B: b, I: "digest" };
}

function baseInput(overrides: Partial<SendBaselineInput> = {}): SendBaselineInput {
  return {
    operationId: OPERATION_ID,
    sourceWalletPublicKey: SOURCE_PUBKEY,
    destinationAddress: DESTINATION_ADDRESS,
    sourceLease: { role: "SEND_SOURCE", lifecycle: "ACTIVE" },
    sourceBaseline: senderProjection("10"),
    destinationBaseline: GENESIS_PROJECTION,
    amountZkz: "1",
    capturedAt: 1_700_000_000_000,
    ...overrides,
  };
}

describe("captureSendBaselines — step 5", () => {
  it("accepts verified source + genesis destination under an ACTIVE SEND_SOURCE lease", () => {
    const result = captureSendBaselines(baseInput());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.capture.amountZkz).toBe("1");
    expect(result.capture.sourceBaseline.B).toBe("10");
    expect(result.capture.destinationBaseline).toEqual(GENESIS_PROJECTION);
  });

  it("accepts equal balance (B0 == amount)", () => {
    const result = captureSendBaselines(
      baseInput({ sourceBaseline: senderProjection("1"), amountZkz: "1" }),
    );
    expect(result.ok).toBe(true);
  });

  it("rejects insufficient source balance", () => {
    const result = captureSendBaselines(
      baseInput({ sourceBaseline: senderProjection("0.5"), amountZkz: "1" }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("source_insufficient_balance");
  });

  it("rejects identical source and destination keys", () => {
    const result = captureSendBaselines(
      baseInput({ destinationAddress: SOURCE_PUBKEY }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("same_wallet");
  });

  it("rejects a non-SEND_SOURCE lease role even when ACTIVE", () => {
    const result = captureSendBaselines(
      baseInput({ sourceLease: { role: "MOVE_SOURCE", lifecycle: "ACTIVE" } }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("source_lease_role_invalid");
  });

  it("rejects a RECONCILIATION lease (observation-only, never pins)", () => {
    const result = captureSendBaselines(
      baseInput({ sourceLease: { role: "RECONCILIATION", lifecycle: "ACTIVE" } }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("source_lease_role_invalid");
  });

  it("rejects an inactive source lease", () => {
    const result = captureSendBaselines(
      baseInput({ sourceLease: { role: "SEND_SOURCE", lifecycle: "RELEASED" } }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("source_lease_not_active");
  });

  it("rejects a zero amount", () => {
    const result = captureSendBaselines(baseInput({ amountZkz: "0" }));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("invalid_amount");
  });

  it.each(["sender", "receiver", "genesis"] as const)(
    "accepts a source baseline whose role is %s when balance is sufficient",
    (role) => {
      const sourceBaseline =
        role === "genesis"
          ? { ...GENESIS_PROJECTION, B: "10" }
          : headProjection(role, "10");
      // Genesis structurally requires B="0"/S=""; capture only judges B sufficiency — a
      // non-zero genesis B is accepted here (inner construction rejects it later).
      const result = captureSendBaselines(baseInput({ sourceBaseline }));
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.capture.sourceBaseline.role).toBe(role);
    },
  );

  it.each(["sender", "receiver", "genesis"] as const)(
    "accepts a destination baseline whose role is %s",
    (role) => {
      const destinationBaseline =
        role === "genesis" ? GENESIS_PROJECTION : headProjection(role, "0");
      const result = captureSendBaselines(baseInput({ destinationBaseline }));
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.capture.destinationBaseline.role).toBe(role);
    },
  );

  it("forms a byte-identical inner whether the source head projects sender or receiver", () => {
    // S and B are role-independent inputs to constructSendInner; only GENESIS vs HEAD
    // changes kind. Same S + same B ⇒ same previous_step_1_state_signature + balances.
    const senderCapture = captureSendBaselines(
      baseInput({ sourceBaseline: headProjection("sender", "10") }),
    );
    const receiverCapture = captureSendBaselines(
      baseInput({ sourceBaseline: headProjection("receiver", "10") }),
    );
    expect(senderCapture.ok).toBe(true);
    expect(receiverCapture.ok).toBe(true);
    if (!senderCapture.ok || !receiverCapture.ok) return;

    const senderInner = constructSendInner({
      capture: senderCapture.capture,
      nodeClockMs: NODE_CLOCK_MS,
    });
    const receiverInner = constructSendInner({
      capture: receiverCapture.capture,
      nodeClockMs: NODE_CLOCK_MS,
    });
    expect(receiverInner.innerPreimageText).toBe(senderInner.innerPreimageText);
    expect(receiverInner.innerSha256).toBe(senderInner.innerSha256);
  });

  it("rejects genesis source balance when amount is positive (B0=0 fails sufficiency)", () => {
    // GENESIS_PROJECTION carries B="0"; sufficiency fails independent of role.
    const result = captureSendBaselines(
      baseInput({ sourceBaseline: GENESIS_PROJECTION, amountZkz: "1" }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("source_insufficient_balance");
  });

  it("rejects an unparseable source balance rather than throwing", () => {
    const result = captureSendBaselines(
      baseInput({
        sourceBaseline: { role: "sender", S: "s", P: "p", B: "not-a-number", I: null },
      }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe("source_baseline_balance_invalid");
  });
});

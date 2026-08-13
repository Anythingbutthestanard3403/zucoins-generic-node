// Pure admission eligibility matrix for wallet money capabilities (ZTR-1268).
// Four presets × three verbs (receive assign / send source / move party).
import { describe, expect, it } from "vitest";

import {
  flagsFromMode,
  isEligibleForMoveParty,
  isEligibleForReceiveAssign,
  isEligibleForSendSource,
  WALLET_MONEY_MODES,
  type WalletMoneyMode,
} from "@zucoins/generic-node-contracts/wallet-state";

import {
  isMoveDestinationEligible,
  isMoveSourceEligible,
  type MoveDestinationRecord,
  type MoveSourceWalletRecord,
} from "../src/move/create.js";
import {
  isMoveDestinationEligible as isReceiveAfterLandingMoveDestEligible,
  isReceiveEligible,
  type ReceiveWalletRecord,
} from "../src/receive/admission.js";
import { isArmableWalletStanding } from "../src/receive/arm-mutation.js";
import { isSendSourceEligible, type SendSourceWalletRecord } from "../src/send/create.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const SOURCE_WALLET_ID = "55555555-5555-4555-8555-555555555555";
const DEST_WALLET_ID = "66666666-6666-4666-8666-666666666666";
const DESTINATION_ID = "77777777-7777-4777-8777-777777777777";
const PUB = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";

const VERB_EXPECT: Record<
  WalletMoneyMode,
  { receive: boolean; send: boolean; move: boolean }
> = {
  INTERNAL_ONLY: { receive: false, send: false, move: true },
  SEND_ONLY: { receive: false, send: true, move: true },
  RECEIVE_ONLY: { receive: true, send: false, move: true },
  FULL: { receive: true, send: true, move: true },
};

function sendWallet(mode: WalletMoneyMode): SendSourceWalletRecord {
  const flags = flagsFromMode(mode);
  return {
    walletId: SOURCE_WALLET_ID,
    nodeId: NODE_ID,
    publicKey: PUB,
    keyOrigin: "node_generated",
    state: "AVAILABLE",
    allowExternalSend: flags.allow_external_send,
  };
}

function moveSource(mode: WalletMoneyMode): MoveSourceWalletRecord {
  const flags = flagsFromMode(mode);
  return {
    walletId: SOURCE_WALLET_ID,
    nodeId: NODE_ID,
    publicKey: PUB,
    keyOrigin: "node_generated",
    state: "AVAILABLE",
    allowInternalMove: flags.allow_internal_move,
  };
}

function moveDest(mode: WalletMoneyMode): MoveDestinationRecord {
  const flags = flagsFromMode(mode);
  return {
    destinationId: DESTINATION_ID,
    nodeId: NODE_ID,
    walletId: DEST_WALLET_ID,
    publicKey: PUB,
    keyOrigin: "node_generated",
    walletState: "AVAILABLE",
    destinationState: "BLESSED",
    recoveryVerifiedAt: "2026-07-01T00:00:00.000Z",
    allowInternalMove: flags.allow_internal_move,
  };
}

function receiveWallet(mode: WalletMoneyMode): ReceiveWalletRecord {
  const flags = flagsFromMode(mode);
  return {
    walletId: SOURCE_WALLET_ID,
    nodeId: NODE_ID,
    keyOrigin: "node_generated",
    state: "AVAILABLE",
    recoveryVerifiedAt: 1_700_000_000_000,
    allowExternalReceive: flags.allow_external_receive,
    allowInternalMove: flags.allow_internal_move,
  };
}

describe("wallet money capability admission matrix (ZTR-1268)", () => {
  it.each(WALLET_MONEY_MODES)(
    "contracts helpers match frozen matrix for mode %s",
    (mode) => {
      const flags = flagsFromMode(mode);
      const exp = VERB_EXPECT[mode];
      expect(isEligibleForReceiveAssign(flags)).toBe(exp.receive);
      expect(isEligibleForSendSource(flags)).toBe(exp.send);
      expect(isEligibleForMoveParty(flags)).toBe(exp.move);
    },
  );

  it.each(WALLET_MONEY_MODES)(
    "isSendSourceEligible / isReceiveEligible / move parties for mode %s",
    (mode) => {
      const exp = VERB_EXPECT[mode];
      expect(isSendSourceEligible(sendWallet(mode), NODE_ID)).toBe(exp.send);
      expect(isReceiveEligible(receiveWallet(mode))).toBe(exp.receive);
      expect(isMoveSourceEligible(moveSource(mode), NODE_ID)).toBe(exp.move);
      const dest = isMoveDestinationEligible(moveDest(mode), NODE_ID, SOURCE_WALLET_ID);
      expect(dest.ok).toBe(exp.move);
      expect(
        isReceiveAfterLandingMoveDestEligible({
          destinationId: DESTINATION_ID,
          destinationState: "BLESSED",
          wallet: receiveWallet(mode),
        }),
      ).toBe(exp.move);
      expect(
        isArmableWalletStanding({
          walletId: SOURCE_WALLET_ID,
          state: "PINNED",
          recoveryVerifiedAt: "2026-07-01T00:00:00.000Z",
          allowExternalReceive: flagsFromMode(mode).allow_external_receive,
        }).ok,
      ).toBe(exp.receive);
    },
  );

  it("send rejects with allow_external_send=false detail path via eligibility only", () => {
    const w = sendWallet("RECEIVE_ONLY");
    expect(isSendSourceEligible(w, NODE_ID)).toBe(false);
    expect(w.allowExternalSend).toBe(false);
  });

  it("move dest detail path when allow_internal_move false", () => {
    // All legal presets keep allow_internal_move true; force the flag off for the
    // conjunct unit (illegal triple is structural at rest — admission still fail-closed).
    const dest: MoveDestinationRecord = {
      ...moveDest("FULL"),
      allowInternalMove: false,
    };
    const r = isMoveDestinationEligible(dest, NODE_ID, SOURCE_WALLET_ID);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.detail).toBe("allow_internal_move=false");
    }
  });
});

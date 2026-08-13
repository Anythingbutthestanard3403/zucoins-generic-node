import { describe, expect, it } from "vitest";

import {
  WALLET_MONEY_CAPABILITY_DEFAULT_MODE,
  WALLET_MONEY_MODE_FLAGS,
  WALLET_MONEY_MODES,
  flagsFromMode,
  isEligibleForMoveParty,
  isEligibleForReceiveAssign,
  isEligibleForSendSource,
  isInternalOnlyHub,
  isLegalMoneyCapabilityTriple,
  isWalletMoneyMode,
  modeFromFlags,
} from "./money-capability.js";

describe("wallet money capability matrix (ZTR-1267)", () => {
  it("freezes exactly four presets", () => {
    expect([...WALLET_MONEY_MODES]).toEqual([
      "RECEIVE_ONLY",
      "SEND_ONLY",
      "INTERNAL_ONLY",
      "FULL",
    ]);
  });

  it("default mint/backfill mode is FULL", () => {
    expect(WALLET_MONEY_CAPABILITY_DEFAULT_MODE).toBe("FULL");
    expect(flagsFromMode("FULL")).toEqual({
      allow_external_receive: true,
      allow_external_send: true,
      allow_internal_move: true,
    });
  });

  it("modeFromFlags round-trips every preset", () => {
    for (const mode of WALLET_MONEY_MODES) {
      expect(modeFromFlags(flagsFromMode(mode))).toBe(mode);
      expect(isLegalMoneyCapabilityTriple(flagsFromMode(mode))).toBe(true);
    }
  });

  it("rejects illegal triples including all-false", () => {
    expect(
      modeFromFlags({
        allow_external_receive: false,
        allow_external_send: false,
        allow_internal_move: false,
      }),
    ).toBeNull();
    expect(
      isLegalMoneyCapabilityTriple({
        allow_external_receive: true,
        allow_external_send: true,
        allow_internal_move: false,
      }),
    ).toBe(false);
  });

  it("eligibility helpers match presets", () => {
    expect(isEligibleForReceiveAssign(WALLET_MONEY_MODE_FLAGS.RECEIVE_ONLY)).toBe(true);
    expect(isEligibleForSendSource(WALLET_MONEY_MODE_FLAGS.RECEIVE_ONLY)).toBe(false);
    expect(isEligibleForSendSource(WALLET_MONEY_MODE_FLAGS.SEND_ONLY)).toBe(true);
    expect(isEligibleForReceiveAssign(WALLET_MONEY_MODE_FLAGS.SEND_ONLY)).toBe(false);
    expect(isInternalOnlyHub(WALLET_MONEY_MODE_FLAGS.INTERNAL_ONLY)).toBe(true);
    expect(isEligibleForMoveParty(WALLET_MONEY_MODE_FLAGS.INTERNAL_ONLY)).toBe(true);
    expect(isEligibleForSendSource(WALLET_MONEY_MODE_FLAGS.INTERNAL_ONLY)).toBe(false);
    expect(isEligibleForReceiveAssign(WALLET_MONEY_MODE_FLAGS.FULL)).toBe(true);
    expect(isEligibleForSendSource(WALLET_MONEY_MODE_FLAGS.FULL)).toBe(true);
  });

  it("isWalletMoneyMode is closed", () => {
    expect(isWalletMoneyMode("FULL")).toBe(true);
    expect(isWalletMoneyMode("treasury")).toBe(false);
    expect(isWalletMoneyMode(null)).toBe(false);
  });
});

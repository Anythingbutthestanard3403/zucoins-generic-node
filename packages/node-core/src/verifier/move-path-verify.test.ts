import { describe, expect, it } from "vitest";

import {
  MOVE_PATH_VERIFY_OUTCOMES,
  verifyMoveDualPath,
  type MoveArtifact,
  type MovePathEvidence,
  type PathObservation,
  type PathVerificationFailure,
} from "./move-path-verify.js";

const SOURCE_KEY = "srcWalletKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const DEST_KEY = "dstWalletKeyBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
const OP_ID = "op-move-001";
const AMOUNT = "1.5";

const TS0: PathObservation = {
  walletPublicKey: SOURCE_KEY,
  stateSignature: "ts0-state-sig",
  balance: "10",
  transactionSignature: "ts0-tx-sig",
};

const TS1: PathObservation = {
  walletPublicKey: SOURCE_KEY,
  stateSignature: "ts1-state-sig",
  balance: "8.5",
  transactionSignature: "ts1-tx-sig",
};

const TD0: PathObservation = {
  walletPublicKey: DEST_KEY,
  stateSignature: "td0-state-sig",
  balance: "5",
  transactionSignature: "td0-tx-sig",
};

const TD1: PathObservation = {
  walletPublicKey: DEST_KEY,
  stateSignature: "td1-state-sig",
  balance: "6.5",
  transactionSignature: "td1-tx-sig",
};

const ARTIFACT: MoveArtifact = {
  sourcePublicKey: SOURCE_KEY,
  destinationPublicKey: DEST_KEY,
  amountZkz: AMOUNT,
  operationId: OP_ID,
  step1Signature: "step1-sig",
  step2Signature: "step2-sig",
  previousStep1StateSignature: "ts0-state-sig",
  previousStep2StateSignature: "td0-state-sig",
};

const VALID_SOURCE_EVIDENCE: MovePathEvidence = {
  baselineObservation: TS0,
  settledObservation: TS1,
  operationId: OP_ID,
};

const VALID_DEST_EVIDENCE: MovePathEvidence = {
  baselineObservation: TD0,
  settledObservation: TD1,
  operationId: OP_ID,
};

describe("verifyMoveDualPath", () => {
  it("returns BOTH_PATHS_VERIFIED when source and destination both confirm", () => {
    const verdict = verifyMoveDualPath(VALID_SOURCE_EVIDENCE, VALID_DEST_EVIDENCE, ARTIFACT);
    expect(verdict.outcome).toBe("BOTH_PATHS_VERIFIED");
    expect(verdict.sourceVerified).toBe(true);
    expect(verdict.destinationVerified).toBe(true);
    expect(verdict.failures).toHaveLength(0);
  });

  it("returns SOURCE_ONLY_VERIFIED when destination predecessor mismatches", () => {
    const badDest: MovePathEvidence = {
      baselineObservation: { ...TD0, stateSignature: "wrong-sig" },
      settledObservation: TD1,
      operationId: OP_ID,
    };
    const verdict = verifyMoveDualPath(VALID_SOURCE_EVIDENCE, badDest, ARTIFACT);
    expect(verdict.outcome).toBe("SOURCE_ONLY_VERIFIED");
    expect(verdict.sourceVerified).toBe(true);
    expect(verdict.destinationVerified).toBe(false);
    expect(verdict.failures).toContainEqual({
      path: "destination",
      reason: "DESTINATION_PREDECESSOR_MISMATCH",
    });
  });

  it("returns DESTINATION_ONLY_VERIFIED when source balance delta mismatches", () => {
    const badSource: MovePathEvidence = {
      baselineObservation: TS0,
      settledObservation: { ...TS1, balance: "9" },
      operationId: OP_ID,
    };
    const verdict = verifyMoveDualPath(badSource, VALID_DEST_EVIDENCE, ARTIFACT);
    expect(verdict.outcome).toBe("DESTINATION_ONLY_VERIFIED");
    expect(verdict.sourceVerified).toBe(false);
    expect(verdict.destinationVerified).toBe(true);
    expect(verdict.failures).toContainEqual({
      path: "source",
      reason: "SOURCE_BALANCE_DELTA_MISMATCH",
    });
  });

  it("returns NEITHER_PATH_VERIFIED when both paths fail", () => {
    const badSource: MovePathEvidence = {
      baselineObservation: { ...TS0, walletPublicKey: "wrongKey" },
      settledObservation: TS1,
      operationId: OP_ID,
    };
    const badDest: MovePathEvidence = {
      baselineObservation: TD0,
      settledObservation: { ...TD1, balance: "5.5" },
      operationId: OP_ID,
    };
    const verdict = verifyMoveDualPath(badSource, badDest, ARTIFACT);
    expect(verdict.outcome).toBe("NEITHER_PATH_VERIFIED");
    expect(verdict.sourceVerified).toBe(false);
    expect(verdict.destinationVerified).toBe(false);
    expect(verdict.failures.length).toBeGreaterThanOrEqual(2);
  });

  it("detects operation linkage mismatch on source path", () => {
    const badLinkage: MovePathEvidence = {
      baselineObservation: TS0,
      settledObservation: TS1,
      operationId: "op-different",
    };
    const verdict = verifyMoveDualPath(badLinkage, VALID_DEST_EVIDENCE, ARTIFACT);
    expect(verdict.sourceVerified).toBe(false);
    expect(verdict.failures).toContainEqual({
      path: "source",
      reason: "OPERATION_LINKAGE_MISMATCH",
    });
  });

  it("detects destination key mismatch", () => {
    const badDest: MovePathEvidence = {
      baselineObservation: { ...TD0, walletPublicKey: "wrongDestKey" },
      settledObservation: TD1,
      operationId: OP_ID,
    };
    const verdict = verifyMoveDualPath(VALID_SOURCE_EVIDENCE, badDest, ARTIFACT);
    expect(verdict.destinationVerified).toBe(false);
    expect(verdict.failures).toContainEqual({
      path: "destination",
      reason: "DESTINATION_KEY_MISMATCH",
    });
  });

  it("detects source key mismatch", () => {
    const badSource: MovePathEvidence = {
      baselineObservation: { ...TS0, walletPublicKey: "wrongSrcKey" },
      settledObservation: TS1,
      operationId: OP_ID,
    };
    const verdict = verifyMoveDualPath(badSource, VALID_DEST_EVIDENCE, ARTIFACT);
    expect(verdict.sourceVerified).toBe(false);
    expect(verdict.failures).toContainEqual({
      path: "source",
      reason: "SOURCE_KEY_MISMATCH",
    });
  });

  it("accumulates multiple failures on a single path", () => {
    const badSource: MovePathEvidence = {
      baselineObservation: { ...TS0, walletPublicKey: "wrong", stateSignature: "wrong" },
      settledObservation: { ...TS1, balance: "10" },
      operationId: "wrong-op",
    };
    const verdict = verifyMoveDualPath(badSource, VALID_DEST_EVIDENCE, ARTIFACT);
    expect(verdict.sourceVerified).toBe(false);
    const sourceFailures = verdict.failures.filter(
      (f: PathVerificationFailure) => f.path === "source",
    );
    expect(sourceFailures.length).toBeGreaterThanOrEqual(3);
  });

  it("MOVE_PATH_VERIFY_OUTCOMES is frozen at exactly 4 members", () => {
    expect(MOVE_PATH_VERIFY_OUTCOMES).toHaveLength(4);
    expect(MOVE_PATH_VERIFY_OUTCOMES).toEqual([
      "BOTH_PATHS_VERIFIED",
      "SOURCE_ONLY_VERIFIED",
      "DESTINATION_ONLY_VERIFIED",
      "NEITHER_PATH_VERIFIED",
    ]);
  });
});

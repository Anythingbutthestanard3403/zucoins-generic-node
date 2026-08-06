// Item 2 ("move requires matching transaction signature on
// source/destination observations and exact dual delta") and item 3 ("spawned move requires
// previous_step_1 == parent_receive.step_2_signature and continuous lease group"), plus one
// falsification per frozen predicate.
//
// The named attack: two DIFFERENT dual-signed transactions whose amounts agree. Both verify,
// both name the right wallets in the right roles, and each leg's own arithmetic is exact — the
// only thing wrong is that they are not one transaction. A move policy that checked amounts
// leg-by-leg would call that proven.
import { describe, expect, it } from "vitest";

import type { WalletStateProjection } from "../../protocol/wallet-role.js";
import { verifySettledTransaction } from "../../verifier/transaction-verify.js";
import { MOVE_INTERNAL_POLICY } from "../policies.js";
import type { PredicateId } from "../types.js";
import {
  evaluateMoveProof,
  type MoveDestinationPath,
  type MovePolicyInput,
  type MoveSourcePath,
} from "./move.js";
import { buildTransaction, parseSettled, publicKeyFromSeed, signText } from "./test-transactions.js";

const SOURCE_SEED = 0x10;
const DESTINATION_SEED = 0x11;
const SOURCE = publicKeyFromSeed(SOURCE_SEED);
const DESTINATION = publicKeyFromSeed(DESTINATION_SEED);
const LEASE_GROUP = "lg_5f2c";
const DECOY_SIGNATURE = signText("some other receive", 0x19);

// The source wallet's accepted head: it was credited 10 ZKZ. The destination wallet's: 2 ZKZ.
const SOURCE_PREDECESSOR = buildTransaction({
  senderSeed: 0x12,
  receiverSeed: SOURCE_SEED,
  senderBalanceAfter: "0",
  receiverBalanceAfter: "10",
});
const DESTINATION_PREDECESSOR = buildTransaction({
  senderSeed: 0x13,
  receiverSeed: DESTINATION_SEED,
  senderBalanceAfter: "0",
  receiverBalanceAfter: "2",
});

function baselineOf(built: { settledText: string }, walletPublicKey: string): WalletStateProjection {
  const verdict = verifySettledTransaction(parseSettled(built.settledText), walletPublicKey);
  if (verdict.verdict !== "VERIFIED") throw new Error(`fixture did not verify: ${verdict.verdict}`);
  return verdict.projection;
}

const SOURCE_BASELINE = baselineOf(SOURCE_PREDECESSOR, SOURCE);
const DESTINATION_BASELINE = baselineOf(DESTINATION_PREDECESSOR, DESTINATION);

/** The move M: 3 ZKZ from the source wallet to the destination wallet. */
function buildMove(
  overrides: Partial<Parameters<typeof buildTransaction>[0]> = {},
): ReturnType<typeof buildTransaction> {
  return buildTransaction({
    senderSeed: SOURCE_SEED,
    receiverSeed: DESTINATION_SEED,
    senderBalanceAfter: "7",
    receiverBalanceAfter: "5",
    previousStep1Signature: SOURCE_PREDECESSOR.step2Signature,
    previousStep2Signature: DESTINATION_PREDECESSOR.step2Signature,
    ...overrides,
  });
}

const MOVE = buildMove();

function sourcePath(overrides: Partial<MoveSourcePath> = {}): MoveSourcePath {
  return {
    walletPublicKey: SOURCE,
    baseline: SOURCE_BASELINE,
    // Read independently of the destination path, as the two leases are.
    observation: parseSettled(MOVE.settledText),
    custody: {
      walletId: "wal_src",
      nodeGenerated: true,
      leaseGroupId: LEASE_GROUP,
      continuouslyLeased: true,
    },
    ...overrides,
  };
}

function destinationPath(overrides: Partial<MoveDestinationPath> = {}): MoveDestinationPath {
  return {
    walletPublicKey: DESTINATION,
    baseline: DESTINATION_BASELINE,
    observation: parseSettled(MOVE.settledText),
    custody: {
      walletId: "wal_dst",
      nodeGenerated: true,
      blessedUnderB1: true,
      recoveryVerified: true,
    },
    ...overrides,
  };
}

function baseInput(overrides: Partial<MovePolicyInput> = {}): MovePolicyInput {
  return {
    artifact: {
      amount_zkz: "3",
      source_wallet_id: "wal_src",
      destination_wallet_id: "wal_dst",
      source_pubkey: SOURCE,
      destination_pubkey: DESTINATION,
      spawn_reference: null,
    },
    artifactVerification: { ok: true, purpose: "move-expected-artifact", digest: "a".repeat(64) },
    source: sourcePath(),
    destination: destinationPath(),
    ...overrides,
  };
}

function detailOf(input: MovePolicyInput, predicate: PredicateId): string {
  const found = evaluateMoveProof(input).predicates.find((p) => p.predicate === predicate);
  if (found === undefined) throw new Error(`policy produced no result for ${predicate}`);
  return found.detail;
}

describe("evaluateMoveProof — MOVE_INTERNAL", () => {
  it("verifies one transaction observed from both leased wallets with an exact dual delta", () => {
    const result = evaluateMoveProof(baseInput());
    expect(result.verdict.outcome).toBe("VERIFIED");
    expect(result.verdict.failedPredicates).toEqual([]);
  });

  it("reports every frozen predicate, in policy sequence", () => {
    const result = evaluateMoveProof(baseInput());
    expect(result.predicates.map((p) => p.predicate)).toEqual(
      MOVE_INTERNAL_POLICY.verificationSteps.map((step) => step.predicate),
    );
    expect(result.predicates.every((p) => p.passed && p.determinate)).toBe(true);
  });

  describe("item 2 — one transaction, not two that agree", () => {
    it("rejects two different transactions whose amounts and roles both match", () => {
      // Same wallets, same roles, same backlinks, same balances — a different transaction.
      const twin = buildMove({ unixTimeSecs: "1784332801.500" });
      expect(twin.step2Signature).not.toBe(MOVE.step2Signature);

      const input = baseInput({
        destination: destinationPath({ observation: parseSettled(twin.settledText) }),
      });
      const result = evaluateMoveProof(input);

      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toEqual(["destination_role_verify"]);
      expect(detailOf(input, "destination_role_verify")).toContain("step_2_signature differs");
      // Each leg's arithmetic is individually exact, so the economics must NOT be claimed
      // proven: the delta evaluator stopped at same_transaction_mismatch.
      for (const predicate of ["source_balance_delta", "destination_balance_delta"] as const) {
        expect(result.predicates.find((p) => p.predicate === predicate)).toMatchObject({
          passed: false,
          determinate: false,
        });
      }
    });

    it("rejects a source leg short by one unit at 32dp", () => {
      // The source debits 2.99…99 while the artifact says 3.
      const input = baseInput({
        source: sourcePath({
          observation: parseSettled(buildMove({ senderBalanceAfter: `7.${"0".repeat(31)}1` }).settledText),
        }),
        destination: destinationPath({
          observation: parseSettled(buildMove({ senderBalanceAfter: `7.${"0".repeat(31)}1` }).settledText),
        }),
      });
      const result = evaluateMoveProof(input);
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toEqual(["source_balance_delta"]);
      expect(detailOf(input, "source_balance_delta")).toContain("source B0-B1");
    });

    it("rejects a destination leg short by one unit at 32dp", () => {
      const shorted = buildMove({ receiverBalanceAfter: `4.9${"9".repeat(31)}` });
      const input = baseInput({
        source: sourcePath({ observation: parseSettled(shorted.settledText) }),
        destination: destinationPath({ observation: parseSettled(shorted.settledText) }),
      });
      const result = evaluateMoveProof(input);
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toEqual(["destination_balance_delta"]);
      expect(detailOf(input, "destination_balance_delta")).toContain("destination B1-B0");
    });

    it("pins the two delta labels the leg attribution keys on", () => {
      // MOVE_DELTA_OWNERS tells the legs apart by own labels. If either label is
      // renamed, this fails here rather than silently filing a source fault as a destination one.
      const sourceFault = baseInput({
        source: sourcePath({ observation: parseSettled(buildMove({ senderBalanceAfter: "8" }).settledText) }),
        destination: destinationPath({
          observation: parseSettled(buildMove({ senderBalanceAfter: "8" }).settledText),
        }),
      });
      expect(detailOf(sourceFault, "source_balance_delta")).toMatch(/^source B0-B1: /);

      const destinationFault = baseInput({
        source: sourcePath({ observation: parseSettled(buildMove({ receiverBalanceAfter: "6" }).settledText) }),
        destination: destinationPath({
          observation: parseSettled(buildMove({ receiverBalanceAfter: "6" }).settledText),
        }),
      });
      expect(detailOf(destinationFault, "destination_balance_delta")).toMatch(/^destination B1-B0: /);
    });
  });

  describe("item 3 — spawned move continuity", () => {
    const spawnedInput = (overrides: Partial<MovePolicyInput> = {}): MovePolicyInput =>
      baseInput({
        artifact: { ...baseInput().artifact, spawn_reference: SOURCE_PREDECESSOR.step2Signature },
        spawnedFrom: {
          receiveTransactionStepTwoSignature: SOURCE_PREDECESSOR.step2Signature,
          leaseGroupId: LEASE_GROUP,
        },
        ...overrides,
      });

    it("verifies a move one hop from its parent receive under one lease group", () => {
      const result = evaluateMoveProof(spawnedInput());
      expect(result.verdict.outcome).toBe("VERIFIED");
      expect(detailOf(spawnedInput(), "spawn_continuity")).toContain("one hop from the parent receive");
    });

    it("rejects a move whose previous_step_1 is not the parent receive's step_2_signature", () => {
      // The chain is internally consistent; it just does not descend from the named receive.
      const input = spawnedInput({
        artifact: { ...baseInput().artifact, spawn_reference: DECOY_SIGNATURE },
        spawnedFrom: {
          receiveTransactionStepTwoSignature: DECOY_SIGNATURE,
          leaseGroupId: LEASE_GROUP,
        },
      });
      const result = evaluateMoveProof(input);
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toEqual(["spawn_continuity"]);
      expect(detailOf(input, "source_predecessor_bind")).toBeTruthy();
      expect(
        result.predicates.find((p) => p.predicate === "source_predecessor_bind"),
      ).toMatchObject({ passed: true });
    });

    it("rejects a move that left the parent receive's lease group", () => {
      const input = spawnedInput({
        source: sourcePath({
          custody: { ...sourcePath().custody, leaseGroupId: "lg_other" },
        }),
      });
      const result = evaluateMoveProof(input);
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toEqual(["spawn_continuity"]);
      expect(detailOf(input, "spawn_continuity")).toContain("is not the parent receive's");
    });

    it("rejects an artifact whose spawn_reference is not the parent receive", () => {
      const input = spawnedInput({ artifact: { ...baseInput().artifact, spawn_reference: null } });
      const result = evaluateMoveProof(input);
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toEqual(["send_artifact_verify"]);
    });

    it("holds spawn_continuity vacuously for an ordinary move", () => {
      expect(detailOf(baseInput(), "spawn_continuity")).toContain("not a spawned move");
    });
  });

  describe("chain and key bindings", () => {
    it("rejects a source leg that does not link to the source's accepted head", () => {
      const orphan = buildMove({ previousStep1Signature: DECOY_SIGNATURE });
      const input = baseInput({
        source: sourcePath({ observation: parseSettled(orphan.settledText) }),
        destination: destinationPath({ observation: parseSettled(orphan.settledText) }),
      });
      const result = evaluateMoveProof(input);
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toEqual(["source_predecessor_bind"]);
      // chain_link_mismatch is owned by no delta predicate, so nothing downstream is claimed.
      expect(result.predicates.find((p) => p.predicate === "source_balance_delta")).toMatchObject({
        determinate: false,
      });
    });

    it("rejects a destination leg that does not link to the destination's accepted head", () => {
      const orphan = buildMove({ previousStep2Signature: DECOY_SIGNATURE });
      const input = baseInput({
        source: sourcePath({ observation: parseSettled(orphan.settledText) }),
        destination: destinationPath({ observation: parseSettled(orphan.settledText) }),
      });
      const result = evaluateMoveProof(input);
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toEqual(["destination_predecessor_bind"]);
    });

    it("rejects a transaction whose step-1 key is not the artifact's source_pubkey", () => {
      const input = baseInput({
        artifact: { ...baseInput().artifact, source_pubkey: publicKeyFromSeed(0x1a) },
      });
      const result = evaluateMoveProof(input);
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toEqual(["artifact_key_bindsource"]);
    });

    it("rejects a transaction whose step-2 key is not the artifact's destination_pubkey", () => {
      const input = baseInput({
        artifact: { ...baseInput().artifact, destination_pubkey: publicKeyFromSeed(0x1a) },
      });
      expect(evaluateMoveProof(input).verdict.failedPredicates).toEqual(["artifact_key_bindsource"]);
    });
  });

  describe("roles, custody and the artifact envelope", () => {
    it("rejects a source wallet that is the receiver, not the sender", () => {
      const input = baseInput({ source: sourcePath({ walletPublicKey: DESTINATION }) });
      const result = evaluateMoveProof(input);
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toContain("source_role_verify");
      expect(detailOf(input, "source_role_verify")).toContain("not sender");
    });

    it.each([
      ["nodeGenerated", { nodeGenerated: false }],
      ["continuouslyLeased", { continuouslyLeased: false }],
    ])("rejects a source wallet failing %s", (_label, custody) => {
      const input = baseInput({
        source: sourcePath({ custody: { ...sourcePath().custody, ...custody } }),
      });
      expect(evaluateMoveProof(input).verdict.failedPredicates).toContain("source_role_verify");
    });

    it.each([
      ["nodeGenerated", { nodeGenerated: false }],
      ["blessedUnderB1", { blessedUnderB1: false }],
      ["recoveryVerified", { recoveryVerified: false }],
    ])("rejects a destination wallet failing %s", (_label, custody) => {
      const input = baseInput({
        destination: destinationPath({ custody: { ...destinationPath().custody, ...custody } }),
      });
      expect(evaluateMoveProof(input).verdict.failedPredicates).toContain("destination_role_verify");
    });

    it("rejects a path observation whose signature does not verify", () => {
      const tampered = parseSettled(
        MOVE.settledText.replace(MOVE.step1Signature, signText("other bytes", SOURCE_SEED)),
      );
      const input = baseInput({
        source: sourcePath({ observation: tampered }),
        destination: destinationPath({ observation: tampered }),
      });
      const result = evaluateMoveProof(input);
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toContain("source_role_verify");
      expect(detailOf(input, "source_role_verify")).toContain("step 1 signature did not verify");
      // Nothing after a failed verification is decided.
      for (const predicate of [
        "source_predecessor_bind",
        "destination_predecessor_bind",
        "source_balance_delta",
        "destination_balance_delta",
        "artifact_key_bindsource",
        "spawn_continuity",
      ] as const) {
        expect(result.predicates.find((p) => p.predicate === predicate)).toMatchObject({
          determinate: false,
        });
      }
    });

    it("rejects a rejected artifact envelope", () => {
      const result = evaluateMoveProof(
        baseInput({ artifactVerification: { ok: false, reason: "digest_mismatch" } }),
      );
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toEqual(["send_artifact_verify"]);
    });

    it.each([
      ["source_wallet_id", { source_wallet_id: "wal_other" }],
      ["destination_wallet_id", { destination_wallet_id: "wal_other" }],
    ])("rejects an artifact whose %s is not the leased wallet", (_label, artifactOverride) => {
      const input = baseInput({ artifact: { ...baseInput().artifact, ...artifactOverride } });
      expect(evaluateMoveProof(input).verdict.failedPredicates).toEqual(["send_artifact_verify"]);
    });

    it("rejects an amount that is not a valid ZKZ operation amount", () => {
      const input = baseInput({ artifact: { ...baseInput().artifact, amount_zkz: `0.${"0".repeat(32)}` } });
      const result = evaluateMoveProof(input);
      expect(result.verdict.outcome).toBe("REJECTED");
      expect(result.verdict.failedPredicates).toEqual(["source_balance_delta"]);
    });
  });

  describe("indeterminate, not rejected", () => {
    it("returns INDETERMINATE when the source path was not read", () => {
      const result = evaluateMoveProof(baseInput({ source: null }));
      expect(result.verdict.outcome).toBe("INDETERMINATE");
      expect(result.verdict.missingEvidence).toContain("source_path_confirmation");
    });

    it("returns INDETERMINATE when the destination path was not read", () => {
      const result = evaluateMoveProof(baseInput({ destination: null }));
      expect(result.verdict.outcome).toBe("INDETERMINATE");
      expect(result.verdict.missingEvidence).toContain("destination_path_confirmation");
    });
  });
});

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import {
  FUNDED_SENDER_GENESIS_PREDECESSOR_REJECTION,
  GENESIS_BALANCE,
  GENESIS_CONTRACT_VERSION,
  GENESIS_FINGERPRINT_VALUES,
  GENESIS_OBSERVATION_VOCABULARY_OWNER,
  GENESIS_STATE_SIGNATURE,
  WALLET_CHAIN_LINK_RULE,
  WALLET_HEAD_STATE_KINDS,
} from "./genesis.contract.ts";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** The A.9 #17 preflight check: a funded sender cannot present a genesis predecessor. */
const assertSenderPreflight = (preflightBalance: string, predecessor: string): void => {
  if (preflightBalance !== GENESIS_BALANCE && predecessor === GENESIS_STATE_SIGNATURE) {
    throw new Error(FUNDED_SENDER_GENESIS_PREDECESSOR_REJECTION.rejectionCode);
  }
};

/** The chain-link check (protocol rule 1.5): genesis "" is valid only with no settled history. */
const assertChainLink = (link: string, hasSettledHistory: boolean): void => {
  if (hasSettledHistory && link === GENESIS_STATE_SIGNATURE) {
    throw new Error("genesis link after settled history");
  }
};

describe("genesis census (the fixture-provenance purposes census, protocol rules 1.5,5; A.7,A.9)", () => {
  it("freezes the genesis state signature and balance", () => {
    expect(GENESIS_STATE_SIGNATURE).toBe("");
    expect(GENESIS_BALANCE).toBe("0");
  });

  it("freezes the role-independent chain-link rule", () => {
    expect(WALLET_CHAIN_LINK_RULE.linkField).toBe("step_2_signature");
    expect(WALLET_CHAIN_LINK_RULE.roleIndependent).toBe(true);
    expect(WALLET_CHAIN_LINK_RULE.genesisLink).toBe("");
    expect(WALLET_CHAIN_LINK_RULE.genesisBalance).toBe("0");
  });

  it("freezes the fingerprint state kinds and genesis values (A.7)", () => {
    assertFieldOrder(WALLET_HEAD_STATE_KINDS, ["GENESIS", "HEAD"]);
    expect(GENESIS_FINGERPRINT_VALUES).toEqual({
      stateKind: "GENESIS",
      sSignature: "",
      pSignature: "",
      bAmount: "0",
      innerSha256: null,
      step1Signature: null,
      step2Signature: null,
    });
  });

  it("freezes the funded-sender/genesis-predecessor rejection (A.9 #17)", () => {
    expect(FUNDED_SENDER_GENESIS_PREDECESSOR_REJECTION.rejectionCode).toBe(
      "funded-sender/genesis-predecessor",
    );
    expect(FUNDED_SENDER_GENESIS_PREDECESSOR_REJECTION.stage).toContain("preflight");
    expect(FUNDED_SENDER_GENESIS_PREDECESSOR_REJECTION.emptyPredecessorValidOnlyAtGenesis).toBe(true);
  });

  it("the committed A.9 #17 negative fixture carries the empty genesis predecessor", () => {
    const inner = JSON.parse(
      readFileSync(
        join(
          packageRoot,
          "src/receive-golden/negative-vectors/funded-sender-genesis-predecessor.inner.json",
        ),
        "utf8",
      ),
    ) as { previous_step_1_state_signature: string; step_1_state: { amount: string } };
    expect(inner.previous_step_1_state_signature).toBe(GENESIS_STATE_SIGNATURE);
    // The sender is FUNDED (its preflight is the A.8.1 boundary "10"), so the empty
    // predecessor must be rejected; a genuinely unfunded sender (balance "0") is accepted.
    expectRejects(
      () => inner.previous_step_1_state_signature,
      (predecessor) => assertSenderPreflight("10", predecessor),
    );
    expect(() => assertSenderPreflight("0", inner.previous_step_1_state_signature)).not.toThrow();
  });

  it("rejects a genesis link after settled history (negative path)", () => {
    expectRejects(
      () => GENESIS_STATE_SIGNATURE,
      (link) => assertChainLink(link, true),
    );
    expect(() => assertChainLink(GENESIS_STATE_SIGNATURE, false)).not.toThrow();
  });

  it("points at observation as the genesis role/parse-result vocabulary owner", () => {
    expect(GENESIS_OBSERVATION_VOCABULARY_OWNER).toBe("src/observation/enums.contract.ts");
  });

  it("pins the manifest version", () => {
    expect(GENESIS_CONTRACT_VERSION).toBe(1);
  });
});

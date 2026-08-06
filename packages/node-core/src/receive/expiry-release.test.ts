// Pure release-predicate and frozen-contract parity tests.

import { describe, expect, it } from "vitest";

import { RECEIVE_QUEUE_MAX_WAIT_MS as CONTRACT_QUEUE_MAX_WAIT_MS } from "../../../generic-node-contracts/src/pool-policy/constants.js";
import {
  POST_EXPIRY_RECONCILING as CONTRACT_POST_EXPIRY_RECONCILING,
} from "../../../generic-node-contracts/src/receive-expiry/lifecycle.js";
import {
  SAFE_TERMINAL_RELEASE_STATUS as CONTRACT_SAFE_TERMINAL_RELEASE_STATUS,
} from "../../../generic-node-contracts/src/receive-expiry/consumer.js";

import {
  POST_EXPIRY_RECONCILING,
  RECEIVE_EXPIRY_RELEASE_STATEMENTS,
  RECEIVE_QUEUE_MAX_WAIT_MS,
  SAFE_TERMINAL_RELEASE_STATUS,
  allReceiveReleasePredicatesHold,
  failedReceiveReleasePredicates,
  type ReceiveReleasePredicateName,
  type ReceiveReleasePredicates,
} from "./expiry-release.js";

const PREDICATES = [
  ["expiryPlusSafetyMargin", "EXPIRY_PLUS_SAFETY_MARGIN"],
  ["noLandedProof", "NO_LANDED_PROOF"],
  ["freshVerifiedT0Exact", "FRESH_VERIFIED_T0_EXACT"],
  ["noAnomalyLineageOrSubmit", "NO_ANOMALY_LINEAGE_OR_SUBMIT"],
  ["childAbsentOrSafeTerminal", "CHILD_ABSENT_OR_SAFE_TERMINAL"],
  ["preCodeFormationProvenSafe", "PRE_CODE_FORMATION_PROVEN_SAFE"],
] as const satisfies readonly [
  keyof ReceiveReleasePredicates,
  ReceiveReleasePredicateName,
][];

function vector(mask: number): ReceiveReleasePredicates {
  return Object.fromEntries(
    PREDICATES.map(([key], bit) => [key, (mask & (1 << bit)) !== 0]),
  ) as unknown as ReceiveReleasePredicates;
}

describe("receive expiry/release frozen constants", () => {
  it("matches the package-private pool and attention hold contract sources", () => {
    expect(RECEIVE_QUEUE_MAX_WAIT_MS).toBe(CONTRACT_QUEUE_MAX_WAIT_MS);
    expect(POST_EXPIRY_RECONCILING).toBe(CONTRACT_POST_EXPIRY_RECONCILING);
    expect(SAFE_TERMINAL_RELEASE_STATUS).toBe(
      CONTRACT_SAFE_TERMINAL_RELEASE_STATUS,
    );
  });
});

describe("release predicate mutation matrix", () => {
  it.each(Array.from({ length: 64 }, (_, mask) => mask))(
    "admits only the all-true vector (mask=%i)",
    (mask) => {
      const predicates = vector(mask);
      const expectedFailed = PREDICATES.filter(
        ([key]) => !predicates[key],
      ).map(([, name]) => name);

      expect(failedReceiveReleasePredicates(predicates)).toEqual(expectedFailed);
      expect(allReceiveReleasePredicatesHold(predicates)).toBe(mask === 63);
    },
  );

  it("keeps landing/candidate/submit checks inside the expiry CAS", () => {
    expect(RECEIVE_EXPIRY_RELEASE_STATEMENTS.CAS_TO_EXPIRED).toMatch(
      /NOT EXISTS .*operation_transactions/i,
    );
    expect(RECEIVE_EXPIRY_RELEASE_STATEMENTS.CAS_TO_EXPIRED).toMatch(
      /NOT EXISTS .*gateway_submit_attempts/i,
    );
    expect(RECEIVE_EXPIRY_RELEASE_STATEMENTS.CAS_TO_EXPIRED).toMatch(
      /NOT EXISTS .*receive_landing_proofs/i,
    );
  });

  it("does not infer walletless expiry from the nullable operation projection", () => {
    expect(RECEIVE_EXPIRY_RELEASE_STATEMENTS.CAS_UNASSIGNED_TO_EXPIRED).toMatch(
      /NOT EXISTS .*operation_wallets/i,
    );
    expect(RECEIVE_EXPIRY_RELEASE_STATEMENTS.CAS_UNASSIGNED_TO_EXPIRED).toMatch(
      /NOT EXISTS .*wallet_active_leases/i,
    );
    expect(RECEIVE_EXPIRY_RELEASE_STATEMENTS.CAS_UNASSIGNED_TO_EXPIRED).toMatch(
      /NOT EXISTS .*operation_transactions/i,
    );
    expect(RECEIVE_EXPIRY_RELEASE_STATEMENTS.CAS_UNASSIGNED_TO_EXPIRED).toMatch(
      /NOT EXISTS .*gateway_submit_attempts/i,
    );
    expect(RECEIVE_EXPIRY_RELEASE_STATEMENTS.CAS_UNASSIGNED_TO_EXPIRED).toMatch(
      /NOT EXISTS .*receive_landing_proofs/i,
    );
  });
});

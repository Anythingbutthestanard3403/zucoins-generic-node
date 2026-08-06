/**
 * SOURCE: derived from this concern's frozen contracts (readiness-checks, boot-sequence,
 * degraded-modes, fail-closed) + the readiness-leadership decoupling rule / the wallet-vault envelope freeze. Pure conformance verifiers:
 * they take a candidate and return the frozen violation ids it commits. No I/O, no state.
 */

import { type ReadinessCheck } from "./readiness-checks.contract.ts";
import { WALLET_SEQUENCING_AUTHORITY } from "./fail-closed.contract.ts";
import { NODE_MODES, type NodeModeId } from "./degraded-modes.contract.ts";

/**
 * A candidate readiness-check set conforms only when every check names a non-empty stamping
 * authority, carries a non-empty assertion scope (both asserts and doesNotAssert), and no two
 * checks share a stamping authority. The shared-authority rule is what makes a false value
 * unambiguous: exactly one component can have stamped it. Returns each violation once.
 */
export const verifyReadinessCheckRegistry = (
  checks: readonly ReadinessCheck[],
): readonly string[] => {
  const violations = new Set<string>();
  const seenAuthorities = new Set<string>();
  for (const check of checks) {
    if (check.stampingAuthority.length === 0) {
      violations.add("CHECK_WITHOUT_STAMPING_AUTHORITY");
    } else if (seenAuthorities.has(check.stampingAuthority)) {
      violations.add("DUPLICATE_STAMPING_AUTHORITY");
    }
    seenAuthorities.add(check.stampingAuthority);
    if (check.asserts.length === 0 || check.doesNotAssert.length === 0) {
      violations.add("CHECK_WITHOUT_ASSERTION_SCOPE");
    }
  }
  return [...violations];
};

interface StagePrecedenceConstraint {
  readonly before: string;
  readonly after: string;
  readonly violation: string;
}

/**
 * Shared pure sequence verifier for lifecycle stages (boot, shutdown). Fails closed and
 * short-circuits on a malformed sequence — MISSING_PREREQUISITE_STAGE if any required stage is
 * absent, DUPLICATE_LIFECYCLE_STAGE if any required stage appears more than once (the position of a
 * duplicated stage is undefined) — then returns one violation id per unsatisfied before->after
 * constraint. Occurrence counts scan the whole sequence, never a first-match indexOf, so a
 * duplicated stage cannot hide behind an earlier or later copy.
 */
const verifyStagePrecedence = (
  sequence: readonly string[],
  required: readonly string[],
  constraints: readonly StagePrecedenceConstraint[],
): readonly string[] => {
  const occurrences = (stage: string): number =>
    sequence.reduce((count, current) => (current === stage ? count + 1 : count), 0);
  if (required.some((stage) => occurrences(stage) === 0)) {
    return ["MISSING_PREREQUISITE_STAGE"];
  }
  if (required.some((stage) => occurrences(stage) > 1)) {
    return ["DUPLICATE_LIFECYCLE_STAGE"];
  }
  const violations: string[] = [];
  for (const { before, after, violation } of constraints) {
    if (sequence.indexOf(before) >= sequence.indexOf(after)) violations.push(violation);
  }
  return violations;
};

/**
 * A candidate boot sequence conforms only when schema validation precedes the vault stages, the
 * key-ring load precedes the vault census, and the census precedes the leadership claim. Claiming
 * leadership before the census is the exact NO_LEADERSHIP_WITHOUT_VAULT_CENSUS regression this
 * catches; running a vault stage before SCHEMA_VALIDATE is the boot-sequence regression (the boot-recovery sequence).
 */
export const verifyBootSequence = (sequence: readonly string[]): readonly string[] =>
  verifyStagePrecedence(
    sequence,
    ["SCHEMA_VALIDATE", "VAULT_KEY_RING_LOAD", "VAULT_CENSUS_VERIFY", "LEADERSHIP_ACQUIRE"],
    [
      {
        before: "SCHEMA_VALIDATE",
        after: "VAULT_KEY_RING_LOAD",
        violation: "VAULT_BEFORE_SCHEMA_VALIDATE",
      },
      {
        before: "VAULT_KEY_RING_LOAD",
        after: "VAULT_CENSUS_VERIFY",
        violation: "VAULT_CENSUS_BEFORE_KEY_RING",
      },
      {
        before: "VAULT_CENSUS_VERIFY",
        after: "LEADERSHIP_ACQUIRE",
        violation: "LEADERSHIP_BEFORE_VAULT_CENSUS",
      },
    ],
  );

/**
 * A candidate shutdown sequence conforms only when signer authority is withdrawn before engines
 * quiesce, engines quiesce before in-flight signing completes, and the leadership lock is released
 * last. Releasing the lock while this instance still accepts signing is the exact concurrent-signer
 * regression a handover must never commit (the readiness-leadership decoupling rule).
 */
export const verifyShutdownSequence = (sequence: readonly string[]): readonly string[] =>
  verifyStagePrecedence(
    sequence,
    ["SIGNER_AUTHORITY_WITHDRAW", "ENGINE_QUIESCE", "INFLIGHT_SIGNING_COMPLETE", "LEADERSHIP_RELEASE"],
    [
      {
        before: "SIGNER_AUTHORITY_WITHDRAW",
        after: "ENGINE_QUIESCE",
        violation: "ENGINE_QUIESCE_BEFORE_AUTHORITY_WITHDRAW",
      },
      {
        before: "ENGINE_QUIESCE",
        after: "INFLIGHT_SIGNING_COMPLETE",
        violation: "INFLIGHT_SIGNING_COMPLETE_BEFORE_ENGINE_QUIESCE",
      },
      {
        before: "INFLIGHT_SIGNING_COMPLETE",
        after: "LEADERSHIP_RELEASE",
        violation: "LEADERSHIP_RELEASE_BEFORE_INFLIGHT_SIGNING_COMPLETE",
      },
      {
        before: "SIGNER_AUTHORITY_WITHDRAW",
        after: "LEADERSHIP_RELEASE",
        violation: "LEADERSHIP_RELEASE_BEFORE_AUTHORITY_WITHDRAW",
      },
    ],
  );

/**
 * The wallet sequencing authority must remain the frozen C-02 lease. Any other value is a second
 * sequencing authority and is rejected — readiness and leadership never sequence wallets.
 */
export const verifyWalletSequencingAuthority = (authority: string): readonly string[] =>
  authority === WALLET_SEQUENCING_AUTHORITY ? [] : ["SECOND_WALLET_SEQUENCING_AUTHORITY"];

/** Total classification of the readiness x leadership pair onto exactly one frozen node mode. */
export const classifyMode = (ready: boolean, leader: boolean): NodeModeId => {
  const mode = NODE_MODES.find((candidate) => candidate.ready === ready && candidate.leader === leader);
  if (mode === undefined) {
    throw new Error("UNCLASSIFIED_NODE_MODE");
  }
  return mode.id;
};

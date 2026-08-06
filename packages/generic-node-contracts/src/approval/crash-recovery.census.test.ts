import { describe, expect, it } from "vitest";

import { assertClosedSet, assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import {
  CRASH_DURABLE_STATES,
  RECOVERY_ACTIONS,
  FORBIDDEN_RECOVERY_ACTIONS,
  CRASH_MATRIX,
  CRASH_POINTS,
  DETERMINISTIC_RESIGN,
  INVARIANT_BREACH_PREDICATE,
  APPROVAL_CONSUMED_NO_SIGN_INTENT_GUARD,
  type CrashDurableState,
} from "./crash-recovery.contract.ts";
import { recoveryActionFor, classifyApprovalConsumedNoSignIntent, hasSuiteDomainPrefix } from "./verify.ts";

const EXPECTED_ROWS: ReadonlyArray<[CrashDurableState, string, string]> = [
  ["APPROVAL_PENDING_NO_SIGN_INTENT", "AWAIT_APPROVAL_OR_REJECT_SAFELY", "ACQUIRE_OR_SIGN"],
  ["APPROVAL_CONSUMED_NO_SIGN_INTENT", "ACQUIRE_READ_FRESH_PERSIST_FIRST_SIGN_INTENT", "CREATE_SECOND_SIGN_INTENT"],
  ["SIGNING_CLAIMED_NO_PARTIAL", "REVALIDATE_SAME_PREIMAGE_COMPLETE_FIRST_FORMATION", "CONSTRUCT_DIFFERENT_INNER_OR_CODE"],
  ["PARTIAL_COMMITTED_UNDELIVERED", "DELIVER_EXACT_PERSISTED_CODE", "RE_SIGN_OR_RE_FORM"],
  ["PARTIAL_DELIVERED_HEAD_UNCHANGED", "REDELIVER_EXACT_PERSISTED_CODE", "MINT_REPLACEMENT_PARTIAL"],
  ["PARTIAL_DELIVERED_EXPECTED_AT_HEAD", "MARK_LANDED_FROM_VERIFIED_OBSERVATION", "SUBMIT_OR_DELIVER_NEW_CODE"],
  ["PARTIAL_DELIVERED_HEAD_ANOMALOUS", "NEEDS_ATTENTION_PRESERVE_LEASE_EVIDENCE", "INFER_NON_LANDING_OR_RETRY"],
  ["PARTIAL_EXPIRED", "TERMINALIZE_ON_POSITIVE_EXPIRY_OR_NON_LANDING", "REFRESH_EXPIRY_UNDER_OLD_APPROVAL"],
];

describe("approval crash/replay decision-table census (the approval-tuple freeze)", () => {
  it("freezes the durable-state sequence (table sequence)", () => {
    assertFieldOrder(
      CRASH_DURABLE_STATES,
      EXPECTED_ROWS.map(([state]) => state),
    );
  });

  it("freezes the recovery-action and forbidden-action closed sets", () => {
    assertClosedSet(RECOVERY_ACTIONS, EXPECTED_ROWS.map(([, recovery]) => recovery));
    assertClosedSet(FORBIDDEN_RECOVERY_ACTIONS, EXPECTED_ROWS.map(([, , forbidden]) => forbidden));
  });

  it("freezes every crash-matrix row: state → one recovery, one forbidden action", () => {
    expect(CRASH_MATRIX).toHaveLength(EXPECTED_ROWS.length);
    EXPECTED_ROWS.forEach(([state, recovery, forbidden], i) => {
      expect(CRASH_MATRIX[i].durableState).toBe(state);
      expect(CRASH_MATRIX[i].recovery).toBe(recovery);
      expect(CRASH_MATRIX[i].forbidden).toBe(forbidden);
    });
  });

  it("the recoveryActionFor lookup is total over the closed state set", () => {
    for (const [state, recovery, forbidden] of EXPECTED_ROWS) {
      const row = recoveryActionFor(state);
      expect(row.recovery).toBe(recovery);
      expect(row.forbidden).toBe(forbidden);
    }
  });

  it("maps the four crash points onto exactly the eight durable states with no gap or overlap", () => {
    assertFieldOrder(
      CRASH_POINTS.map((p) => p.point),
      ["BEFORE_SIGN_INTENT_PERSIST", "AFTER_SIGN_INTENT_BEFORE_SIGN", "AFTER_SIGN_BEFORE_DELIVERY", "AFTER_DELIVERY"],
    );
    const covered = CRASH_POINTS.flatMap((p) => p.states);
    assertClosedSet(covered, [...CRASH_DURABLE_STATES]);
    expect(covered).toHaveLength(CRASH_DURABLE_STATES.length); // no state appears under two points
  });

  it("freezes signer determinism as a REQUIREMENT (RFC 8032 pure Ed25519; hedged/randomized forbidden; violation fails closed)", () => {
    expect(DETERMINISTIC_RESIGN.stepOneSignerMustBeDeterministicEd25519Rfc8032).toBe(true);
    expect(DETERMINISTIC_RESIGN.hedgedOrRandomizedEd25519Forbidden).toBe(true);
    expect(DETERMINISTIC_RESIGN.signerRequirementViolationFailsClosed).toBe(true);
  });

  it("freezes the deterministic re-sign fact (same key + message → same signature; completion, not new authorization)", () => {
    expect(DETERMINISTIC_RESIGN.ed25519DeterministicForFixedKeyAndMessage).toBe(true);
    expect(DETERMINISTIC_RESIGN.recoveryReSignsSamePreimage).toBe(true);
    expect(DETERMINISTIC_RESIGN.recoveryYieldsSameSignature).toBe(true);
    expect(DETERMINISTIC_RESIGN.isCompletionNotNewAuthorization).toBe(true);
  });

  it("freezes the pre-delivery byte-compare fact: a re-sign mismatch against prior signer-audit is INVARIANT_BREACH, never delivered", () => {
    expect(DETERMINISTIC_RESIGN.recoveryByteComparesAgainstPriorSignerAuditSignatureBeforeDelivery).toBe(true);
    expect(DETERMINISTIC_RESIGN.mismatchClassification).toBe("INVARIANT_BREACH");
    expect(DETERMINISTIC_RESIGN.mismatchClassification).toBe(INVARIANT_BREACH_PREDICATE.classification);
  });

  // ---- The five mandatory negatives ----

  it("negative: a re-formed preimage after SIGNING_CLAIMED is the forbidden action", () => {
    expect(recoveryActionFor("SIGNING_CLAIMED_NO_PARTIAL").forbidden).toBe("CONSTRUCT_DIFFERENT_INNER_OR_CODE");
    expect(recoveryActionFor("SIGNING_CLAIMED_NO_PARTIAL").recovery).toBe("REVALIDATE_SAME_PREIMAGE_COMPLETE_FIRST_FORMATION");
  });

  it("negative: a refreshed-expiry (relinked) partial under the old approval is the forbidden action", () => {
    expect(recoveryActionFor("PARTIAL_EXPIRED").forbidden).toBe("REFRESH_EXPIRY_UNDER_OLD_APPROVAL");
  });

  it("negative: a replacement/second partial after delivery is the forbidden action", () => {
    expect(recoveryActionFor("PARTIAL_DELIVERED_HEAD_UNCHANGED").forbidden).toBe("MINT_REPLACEMENT_PARTIAL");
    expect(recoveryActionFor("PARTIAL_DELIVERED_EXPECTED_AT_HEAD").forbidden).toBe("SUBMIT_OR_DELIVER_NEW_CODE");
  });

  it("negative: no post-consumption recovery re-runs the guarded mutation (a replayed TOTP cannot mint a partial)", () => {
    // ACQUIRE_OR_SIGN (re-running acquisition/signing under a fresh authorization) is a FORBIDDEN
    // action, never a recovery action — so a replayed TOTP has no recovery path to a new partial.
    expect(RECOVERY_ACTIONS).not.toContain("ACQUIRE_OR_SIGN");
    expect(FORBIDDEN_RECOVERY_ACTIONS).toContain("ACQUIRE_OR_SIGN");
    expectRejects(
      () => "ACQUIRE_OR_SIGN",
      (attempt) => {
        if (!RECOVERY_ACTIONS.includes(attempt as never)) {
          throw new Error("re-authorizing (replayed TOTP → new partial) is not a permitted recovery");
        }
      },
    );
  });

  it("negative: approval and SplitChain preimages occupy disjoint byte spaces (no cross-contamination)", () => {
    const approvalShaped = 'zp-send-external-approval-v1\n{"purpose":"zp-send-external-approval-v1"}';
    const splitchainShaped = '{"type":"unique_combinable","version":"2"}'; // prefix-less native preimage
    expect(hasSuiteDomainPrefix(approvalShaped)).toBe(true);
    expect(hasSuiteDomainPrefix(splitchainShaped)).toBe(false);
  });
});

describe("approval crash-recovery INVARIANT_BREACH classification", () => {
  it("freezes the breach predicate: classification, action, and permitted-actions all false", () => {
    expect(INVARIANT_BREACH_PREDICATE.classification).toBe("INVARIANT_BREACH");
    expect(INVARIANT_BREACH_PREDICATE.action).toBe("NEEDS_ATTENTION_PRESERVE_LEASE_EVIDENCE");
    expect(RECOVERY_ACTIONS).toContain(INVARIANT_BREACH_PREDICATE.action);
    expect(INVARIANT_BREACH_PREDICATE.permitsFirstFormation).toBe(false);
    expect(INVARIANT_BREACH_PREDICATE.permitsReSign).toBe(false);
    expect(INVARIANT_BREACH_PREDICATE.permitsLeaseRelease).toBe(false);
  });

  it("freezes the guard fact on the APPROVAL_CONSUMED_NO_SIGN_INTENT row", () => {
    expect(APPROVAL_CONSUMED_NO_SIGN_INTENT_GUARD.row).toBe("APPROVAL_CONSUMED_NO_SIGN_INTENT");
    expect(APPROVAL_CONSUMED_NO_SIGN_INTENT_GUARD.guard).toBe(
      "first_formation_permitted_only_after_proving_signer_never_called",
    );
    expect(CRASH_DURABLE_STATES).toContain(APPROVAL_CONSUMED_NO_SIGN_INTENT_GUARD.row);
  });

  it("ordinary evidence (no call, preimage available, not contradictory) -> this row's table action", () => {
    expect(
      classifyApprovalConsumedNoSignIntent({
        signerAuditShowsSigningCall: false,
        persistedPreimageRecordAvailable: true,
        persistedPreimageRecordContradictory: false,
      }),
    ).toBe("ACQUIRE_READ_FRESH_PERSIST_FIRST_SIGN_INTENT");
  });

  it("breach-predicate input (signer audit shows a call, no persisted sign intent) -> INVARIANT_BREACH action, never first-sign-intent", () => {
    const action = classifyApprovalConsumedNoSignIntent({
      signerAuditShowsSigningCall: true,
      persistedPreimageRecordAvailable: true,
      persistedPreimageRecordContradictory: false,
    });
    expect(action).toBe("NEEDS_ATTENTION_PRESERVE_LEASE_EVIDENCE");
    expect(action).not.toBe("ACQUIRE_READ_FRESH_PERSIST_FIRST_SIGN_INTENT");
  });

  it("breach-predicate input (preimage record unavailable) -> INVARIANT_BREACH action, never first-sign-intent", () => {
    const action = classifyApprovalConsumedNoSignIntent({
      signerAuditShowsSigningCall: false,
      persistedPreimageRecordAvailable: false,
      persistedPreimageRecordContradictory: false,
    });
    expect(action).toBe("NEEDS_ATTENTION_PRESERVE_LEASE_EVIDENCE");
    expect(action).not.toBe("ACQUIRE_READ_FRESH_PERSIST_FIRST_SIGN_INTENT");
  });

  it("breach-predicate input (preimage record contradictory) -> INVARIANT_BREACH action, never first-sign-intent", () => {
    const action = classifyApprovalConsumedNoSignIntent({
      signerAuditShowsSigningCall: false,
      persistedPreimageRecordAvailable: true,
      persistedPreimageRecordContradictory: true,
    });
    expect(action).toBe("NEEDS_ATTENTION_PRESERVE_LEASE_EVIDENCE");
    expect(action).not.toBe("ACQUIRE_READ_FRESH_PERSIST_FIRST_SIGN_INTENT");
  });
});

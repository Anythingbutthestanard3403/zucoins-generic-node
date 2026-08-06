// the reporting bootstrap enrolment freeze + behavioural matrix for reporting replay and key rotation.
//
// Governing contract: register tuple / event signing; signed reporting; the pull-cursor authority decision. Consumes the reporting-auth register tuple's
// lifecycle rules and the reporting node-event purpose's event-hash goldens. Proves the frozen outcome for every scenario
// across six dimensions, with at least one reject (negative) per dimension.
import { describe, expect, it } from "vitest";

import golden from "./gen/reporting-behavior.json" with { type: "json" };
import {
  ROTATION_MODEL,
  isLegalReportingKeyTransition,
} from "../reporting-auth/index.js";
import {
  NODE_EVENT_A_EVENT_HASH,
  NODE_EVENT_GOLDEN_B,
  eventChainLinks,
} from "../reporting-tuples/index.js";
import { evaluateBootstrapEnrolment } from "./decisions.js";
import { BEHAVIOUR_DIMENSIONS, buildReportingBehaviorManifest } from "./manifest.js";
import { buildReplayMatrix } from "./matrix.js";

const MATRIX = buildReplayMatrix();
const outcome = (dimension: string, scenario: string): string | undefined =>
  MATRIX.find((c) => c.dimension === dimension && c.scenario === scenario)?.outcome;

describe("the reporting bootstrap enrolment reporting-behavior matrix freeze", () => {
  it("serialized manifest matches the committed golden snapshot", () => {
    expect(buildReportingBehaviorManifest()).toEqual(golden);
  });

  it("covers every dimension and each cell is uniquely keyed", () => {
    const keys = MATRIX.map((c) => `${c.dimension}/${c.scenario}`);
    expect(new Set(keys).size).toBe(keys.length);
    for (const dimension of BEHAVIOUR_DIMENSIONS) {
      expect(MATRIX.some((c) => c.dimension === dimension)).toBe(true);
    }
  });
});

describe("the reporting bootstrap enrolment request raw binding / replay / time / body / tenant", () => {
  it("accepts a fresh in-window request and rejects each abuse", () => {
    expect(outcome("request", "fresh")).toBe("ACCEPT");
    expect(outcome("request", "at_issued_boundary")).toBe("ACCEPT");
    expect(outcome("request", "at_expires_boundary")).toBe("ACCEPT");
    expect(outcome("request", "duplicate_nonce")).toBe("REJECT_REPLAY");
    expect(outcome("request", "expired")).toBe("REJECT_EXPIRED");
    expect(outcome("request", "not_yet_valid")).toBe("REJECT_NOT_YET_VALID");
    expect(outcome("request", "zero_length_window")).toBe("REJECT_WINDOW");
    expect(outcome("request", "negative_window")).toBe("REJECT_WINDOW");
    expect(outcome("request", "window_over_60s")).toBe("REJECT_WINDOW");
    expect(outcome("request", "method_mutated")).toBe("REJECT_METHOD_MUTATED");
    expect(outcome("request", "target_mutated")).toBe("REJECT_TARGET_MUTATED");
    expect(outcome("request", "target_mutated_nonce_seen")).toBe("REJECT_TARGET_MUTATED");
    expect(outcome("request", "body_mutated")).toBe("REJECT_BODY_MUTATED");
    expect(outcome("request", "wrong_tenant")).toBe("REJECT_WRONG_TENANT");
  });
});

describe("the reporting bootstrap enrolment rotation / revocation (consumes the reporting-auth register tuple lifecycle)", () => {
  it("accepts current and prior-in-overlap; rejects retired/revoked/unknown", () => {
    expect(outcome("rotation", "current_active")).toBe("ACCEPT_CURRENT");
    expect(outcome("rotation", "prior_overlap")).toBe("ACCEPT_PRIOR_OVERLAP");
    expect(outcome("rotation", "prior_retired_post_cutover")).toBe("REJECT_RETIRED");
    expect(outcome("rotation", "revoked_current")).toBe("REJECT_REVOKED");
    expect(outcome("rotation", "unknown_key")).toBe("REJECT_UNKNOWN");
  });

  it("revoke-to-zero is an ALARMED fail-closed state, consistent with the reporting-auth register tuple", () => {
    expect(outcome("rotation", "revoke_to_zero")).toBe("ALARM_NO_ACTIVE_KEY");
    expect(ROTATION_MODEL.revokeCurrentReactivatesPrior).toBe(false);
    expect(ROTATION_MODEL.revokeToZero).toBe("ALARMED_FAIL_CLOSED_NO_ACTIVE_KEY");
    // The transitions the matrix exercises must be legal per the reporting-auth register tuple state machine.
    expect(isLegalReportingKeyTransition("ACTIVE", "RETIRED")).toBe(true);
    expect(isLegalReportingKeyTransition("ACTIVE", "REVOKED")).toBe(true);
    expect(isLegalReportingKeyTransition("REVOKED", "ACTIVE")).toBe(false);
  });
});

describe("the reporting bootstrap enrolment event stream: sparse seq vs true gap (consumes the reporting node-event purpose chain)", () => {
  it("a skipped seq is not a gap; a lower seq is a reorder/replay", () => {
    expect(outcome("event_stream", "tenant_seq_sparse_jump")).toBe("ACCEPT_ADVANCE");
    expect(outcome("event_stream", "tenant_seq_reorder")).toBe("REJECT_REORDER_OR_REPLAY");
  });

  it("an intact hash-chain link accepts; a break is a hard stop", () => {
    expect(outcome("event_stream", "chain_intact")).toBe("ACCEPT_CHAIN");
    expect(outcome("event_stream", "chain_break")).toBe("HARD_STOP_CHAIN_BREAK");
    // The intact case is exactly the reporting node-event purpose's golden B linking to golden A.
    expect(eventChainLinks(NODE_EVENT_A_EVENT_HASH, NODE_EVENT_GOLDEN_B)).toBe(true);
    expect(NODE_EVENT_GOLDEN_B.previous_event_hash).toBe(NODE_EVENT_A_EVENT_HASH);
  });
});

describe("the reporting bootstrap enrolment restore-from-backup guard", () => {
  it("monotonic epoch + hash-chain hard-stop", () => {
    expect(outcome("restore", "same_epoch_chain_intact")).toBe("ACCEPT");
    expect(outcome("restore", "same_epoch_chain_break")).toBe("HARD_STOP_CHAIN_BREAK");
    expect(outcome("restore", "epoch_regression")).toBe("REJECT_EPOCH_REGRESSION");
    expect(outcome("restore", "post_restore_new_epoch")).toBe("ACCEPT");
  });
});

describe("the reporting bootstrap enrolment cutover sequencing", () => {
  it("activate-before-retire never goes dark; retire-before-activate is invalid", () => {
    expect(outcome("cutover", "activate_before_retire")).toBe("VALID");
    expect(outcome("cutover", "retire_before_activate")).toBe("INVALID");
  });
});

describe("reporting.3 bootstrap enrolment trust-root (permanent, fail-closed)", () => {
  const base = {
    supersedesKeyId: null,
    hasAuthenticatedOnboardingCredential: true,
    implementerIdFromAuthenticatedCaller: true,
    hasNodeOriginOperatorApproval: true,
    proofOfPossessionValid: true,
  };

  it("accepts the permanent root only when ALL THREE requirements are present", () => {
    expect(evaluateBootstrapEnrolment(base)).toBe("ACCEPT_PERMANENT");
  });

  it("fail-closes when any single requirement is missing", () => {
    expect(
      evaluateBootstrapEnrolment({ ...base, hasAuthenticatedOnboardingCredential: false }),
    ).toBe("REJECT_MISSING_ONBOARDING_CREDENTIAL");
    expect(
      evaluateBootstrapEnrolment({ ...base, implementerIdFromAuthenticatedCaller: false }),
    ).toBe("REJECT_IMPLEMENTER_ID_FROM_BODY");
    expect(evaluateBootstrapEnrolment({ ...base, hasNodeOriginOperatorApproval: false })).toBe(
      "REJECT_MISSING_OPERATOR_APPROVAL",
    );
    expect(evaluateBootstrapEnrolment({ ...base, proofOfPossessionValid: false })).toBe(
      "REJECT_MISSING_PROOF_OF_POSSESSION",
    );
  });

  it("does not gate rotation (supersedes_key_id non-null) as a bootstrap", () => {
    expect(
      evaluateBootstrapEnrolment({ ...base, supersedesKeyId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }),
    ).toBe("NOT_BOOTSTRAP");
  });
});

describe("the reporting bootstrap enrolment mandatory negatives (one per dimension)", () => {
  it("each dimension has at least one reject / hard-stop / invalid outcome", () => {
    const isNegative = (o: string): boolean =>
      o.startsWith("REJECT") || o.startsWith("HARD_STOP") || o === "ALARM_NO_ACTIVE_KEY" || o === "INVALID";
    for (const dimension of BEHAVIOUR_DIMENSIONS) {
      const cells = MATRIX.filter((c) => c.dimension === dimension);
      expect(cells.some((c) => isNegative(c.outcome))).toBe(true);
    }
  });
});

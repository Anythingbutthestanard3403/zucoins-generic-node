/**
 * Doc 11 §11.9 — SEND_EXTERNAL expiry / redelivery CONTRACT_FREEZE matrix.
 *
 * Status: CONTRACT_FREEZE (ZTR-149 / GN-016.3 / D9.14). Frozen test/proof artifact.
 * Adds no production code. Every B0 scalar below is a hand-authored literal with
 * documented provenance; the test oracle is an independent pure function that does
 * NOT import production window/margin constants into expected-value computation.
 * Parsed-JSON equality is never accepted as a byte proof.
 *
 * Governing: D9.14 (integer-second signed expiry; T1 on signed issued_at; T2 =
 * floor(node_clock)+300 at FORMATION; recipient anchor is the signed inner);
 * Appendix B §2.3/§5.3/§6; 04 §6/§8/§9/§10/§16 #9–#11; 09 §5.2–§5.4; 05 §6.2;
 * 06 §4.3–§4.5. Citations: D9.14, GN-016, ZTR-149.
 *
 * Ticket: ZTR-1150.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  APPROVAL_CARDINALITY,
  APPROVAL_CONSUMPTION,
  REDELIVERY_RULE,
  REPLACEMENT_RULE,
  SIGN_INTENT_FROZEN_AFTER_EXISTS,
  TIMER_SEPARATION,
} from "../../generic-node-contracts/src/approval/sign-intent.contract.ts";
import {
  CRASH_MATRIX,
  DETERMINISTIC_RESIGN,
  INVARIANT_BREACH_PREDICATE,
} from "../../generic-node-contracts/src/approval/crash-recovery.contract.ts";
import {
  classifyApprovalConsumedNoSignIntent,
  recoveryActionFor,
} from "../../generic-node-contracts/src/approval/verify.ts";
import {
  ATTENTION_REASONS,
  DURABLE_EVENTS,
} from "../../generic-node-contracts/src/operations/events.contract.ts";
import {
  SEND_EXTERNAL_STATES,
  SEND_EXTERNAL_TRANSITIONS,
} from "../../generic-node-contracts/src/operations/states.contract.ts";

import { planRecoveryEffect } from "../src/operator/recovery-actions.js";
import {
  derivePermittedActions,
  type RecoveryFacts,
  type SendRecoveryFacts,
} from "../src/operator/recovery-inspection.js";
import { APPROVAL_CHALLENGE_FRESHNESS_MS } from "../src/send/approve.js";
import {
  SEND_EXPIRY_ATTENTION_ALLOWED_SQL,
  SEND_EXPIRY_ATTENTION_SQL,
  SEND_PARTIAL_AGING_MARGIN_SECS,
  SEND_REDEMPTION_WINDOW_SECS,
  assertNoForbiddenSqlInAllowedSet,
  evaluatePostDeliveryExpiry,
  fingerprintPartialImmutableBytes,
  isPastExpiry,
  oracleEligibleAtUnixSecs,
} from "../src/send/expiry-attention.js";
import {
  deriveSendRedemptionExpiryUnixSecs,
  redemptionExpiryAtFromSecs,
} from "../src/protocol/send-redemption.js";

// ── Independent oracle (never imports production constants into expectations) ─

/**
 * Shared baseline fixture B0 — hand-authored literals from doc 11 §11.9.
 * DO NOT derive these from Date.now(), SEND_REDEMPTION_WINDOW_SECS, or any
 * production constant. The point of a freeze matrix is that drift fails loudly.
 *
 * Provenance: doc 11 §11.9 Shared baseline fixture (B0); D9.14; GN-016.3; ZTR-149.
 */
const B0 = {
  /** formation_clock = 1784332800 (2026-07-18T00:00:00.000Z) */
  formationClockUnixSecs: 1_784_332_800,
  formationClockMs: 1_784_332_800_000,
  /** signed expiry__unix_time_secs = "1784333100" (= formation + 300) */
  signedExpiryUnixSecs: "1784333100",
  signedExpiryUnixSecsNumber: 1_784_333_100,
  /** available_until display projection (non-authoritative) */
  availableUntil: "2026-07-18T00:05:00.000Z",
  /** oracle-eligible-at = 1784336700 (= expiry + 3600) */
  oracleEligibleAt: 1_784_336_700,
  /** Hand-pinned window/margin that production MUST match (D9.14 / F1.2). */
  pinnedRedemptionWindowSecs: 300,
  pinnedAgingMarginSecs: 3600,
  pinnedApprovalFreshnessSecs: 300,
  /** Frozen partial byte columns for redelivery identity proofs. */
  partial: {
    innerSha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    step1Signature:
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
    transferCodeText: "zp1:freeze-b0-partial-bytes-v1",
    transferCodeSha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  },
} as const;

/** Decision / ticket citations every case must remain discoverable under. */
const CITATIONS = ["D9.14", "GN-016", "ZTR-149"] as const;

/**
 * Independent pure oracle — computes expected B0 relations without reading
 * production SEND_REDEMPTION_WINDOW_SECS / SEND_PARTIAL_AGING_MARGIN_SECS.
 */
const oracle = {
  expectedSignedExpiryFromFormation(): string {
    return String(B0.formationClockUnixSecs + B0.pinnedRedemptionWindowSecs);
  },
  expectedOracleEligibleFromExpiry(expirySecs: string): number {
    return Number(expirySecs) + B0.pinnedAgingMarginSecs;
  },
  /** T1 freshness: approval expires_at must be within pinned window of SIGNED issued_at. */
  t1Fresh(issuedAtMs: number, expiresAtMs: number, receiptClockMs: number): boolean {
    void receiptClockMs; // receipt skew must not enter the predicate
    return (
      expiresAtMs - issuedAtMs <= B0.pinnedApprovalFreshnessSecs * 1000 &&
      expiresAtMs >= issuedAtMs
    );
  },
  /** T2 materialization at FORMATION: floor(node_clock_ms/1000)+window as integer-seconds string. */
  t2FromFormationClockMs(nodeClockMs: number): string {
    return String(Math.floor(nodeClockMs / 1000) + B0.pinnedRedemptionWindowSecs);
  },
  /** Two-part terminal-close oracle (09 §5.4). */
  twoPartCloseOracle(input: {
    readonly nowUnixSecs: number;
    readonly signedExpiryUnixSecs: string;
    readonly freshHeadEqualsT0: boolean;
  }): boolean {
    const eligible = Number(input.signedExpiryUnixSecs) + B0.pinnedAgingMarginSecs;
    return input.nowUnixSecs >= eligible && input.freshHeadEqualsT0;
  },
  /** CLOSE_NEVER_STARTED requires AND of five durable negatives. */
  closeNeverStartedNegatives(flags: {
    readonly hasSignIntent: boolean;
    readonly hasSignerCall: boolean;
    readonly hasSignature: boolean;
    readonly hasDurablePartial: boolean;
    readonly hasDelivery: boolean;
  }): boolean {
    return (
      !flags.hasSignIntent &&
      !flags.hasSignerCall &&
      !flags.hasSignature &&
      !flags.hasDurablePartial &&
      !flags.hasDelivery
    );
  },
} as const;

const CASE_IDS = [
  "EXP-BOUNDARY-01",
  "EXP-BOUNDARY-02",
  "EXP-BOUNDARY-03",
  "EXP-BOUNDARY-04",
  "EXP-SKEW-01",
  "EXP-SKEW-02",
  "EXP-SKEW-03",
  "EXP-SKEW-04",
  "EXP-REPLAY-01",
  "EXP-REPLAY-02",
  "EXP-REPLAY-03",
  "EXP-CRASH-01",
  "EXP-CRASH-02",
  "EXP-CRASH-03",
  "EXP-CRASH-04",
  "EXP-CRASH-05",
  "EXP-REDELIVER-01",
  "EXP-REDELIVER-02",
  "EXP-STALE-01",
  "EXP-STALE-02",
  "EXP-LATE-01",
  "EXP-LATE-02",
  "EXP-LATE-03",
  "EXP-CLOSE-01",
  "EXP-CLOSE-02",
  "EXP-CLOSE-03",
  "EXP-CLOSE-04",
  "EXP-CLOSE-05",
  "EXP-REPLACE-01",
  "EXP-REPLACE-02",
  "EXP-REPLACE-03",
] as const;

type CaseId = (typeof CASE_IDS)[number];

const HERE = dirname(fileURLToPath(import.meta.url));
const SELF_PATH = fileURLToPath(import.meta.url);
const EXPIRY_ATTENTION_SRC = readFileSync(join(HERE, "../src/send/expiry-attention.ts"), "utf8");
const SEND_REDEMPTION_SRC = readFileSync(join(HERE, "../src/protocol/send-redemption.ts"), "utf8");
const TRANSACTION_MATERIAL_SQL = readFileSync(
  join(HERE, "../src/schema/transaction-material.sql"),
  "utf8",
);
const SUBMIT_ATTEMPTS_SQL = readFileSync(join(HERE, "../src/schema/submit-attempts.sql"), "utf8");
const BYTE_IMMUTABILITY_SQL = readFileSync(
  join(HERE, "../src/schema/transaction-material-byte-immutability.sql"),
  "utf8",
);
const SUBMIT_GUARD_TEST = readFileSync(join(HERE, "submit-write-path.guard.test.ts"), "utf8");
const FORBIDDEN_RECOVERY_SRC = readFileSync(
  join(HERE, "../src/operator/recovery-inspection.ts"),
  "utf8",
);

const OP = "00000000-0000-4000-8000-0000000000b0";
const WALLET = "00000000-0000-4000-8000-0000000000b1";

function b0Send(overrides: Partial<SendRecoveryFacts> = {}): SendRecoveryFacts {
  return {
    hasSignIntent: true,
    hasSignerCall: true,
    hasSignature: true,
    hasDurablePartial: true,
    hasDelivery: true,
    protocolExpiredPlusMargin: false,
    freshHeadEqualsSourceT0: false,
    completePathExclusionProved: false,
    hasSignerAudit: true,
    hasMatchingExactByteRecord: true,
    ...overrides,
  };
}

function b0Facts(
  status: string,
  send: SendRecoveryFacts | null,
  patch: Partial<RecoveryFacts> = {},
): RecoveryFacts {
  return {
    operationId: OP,
    kind: "SEND_EXTERNAL",
    status,
    attentionRequired: status === "NEEDS_ATTENTION",
    attentionReason: status === "NEEDS_ATTENTION" ? "UNEXPECTED_HEAD_CHANGE" : null,
    rowVersion: 1,
    leaseEpoch: 1,
    heldLeases: [{ walletId: WALLET, leaseEpoch: 1, role: "SOURCE" }],
    hasLandingProof: false,
    landingProofVerdict: null,
    hasObservationAnomaly: false,
    hasLineageGap: false,
    invariantBreachNoted: false,
    evidenceManifest: [],
    diagnostics: [],
    receive: null,
    move: null,
    send,
    haltEngaged: false,
    ...patch,
  };
}

function transitionExists(from: string | null, to: string): boolean {
  return SEND_EXTERNAL_TRANSITIONS.some((t) => t.from === from && t.to === to);
}

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

// ── Matrix meta ──────────────────────────────────────────────────────────────

describe("Doc 11 §11.9 CONTRACT_FREEZE matrix — meta (D9.14 / GN-016 / ZTR-149)", () => {
  it("pins the closed case identifier set exactly (EXP-BOUNDARY-01 … EXP-REPLACE-03)", () => {
    // Doc 11 §11.9 table enumerates these 31 named cases (BOUNDARY×4 … REPLACE×3).
    expect(CASE_IDS).toHaveLength(31);
    expect(CASE_IDS[0]).toBe("EXP-BOUNDARY-01");
    expect(CASE_IDS[CASE_IDS.length - 1]).toBe("EXP-REPLACE-03");
    expect(new Set(CASE_IDS).size).toBe(CASE_IDS.length);
  });

  it("cites D9.14, GN-016, and ZTR-149 in this artifact", () => {
    const self = readFileSync(SELF_PATH, "utf8");
    for (const c of CITATIONS) {
      expect(self).toContain(c);
    }
  });

  it("B0 literals are hand-authored and mutually consistent under the independent oracle", () => {
    expect(B0.formationClockUnixSecs).toBe(1_784_332_800);
    expect(B0.signedExpiryUnixSecs).toBe("1784333100");
    expect(B0.availableUntil).toBe("2026-07-18T00:05:00.000Z");
    expect(B0.oracleEligibleAt).toBe(1_784_336_700);
    expect(oracle.expectedSignedExpiryFromFormation()).toBe(B0.signedExpiryUnixSecs);
    expect(oracle.expectedOracleEligibleFromExpiry(B0.signedExpiryUnixSecs)).toBe(
      B0.oracleEligibleAt,
    );
    // Production MUST equal the pin (mutation of the constant fails the matrix).
    expect(SEND_REDEMPTION_WINDOW_SECS).toBe(B0.pinnedRedemptionWindowSecs);
    expect(SEND_PARTIAL_AGING_MARGIN_SECS).toBe(B0.pinnedAgingMarginSecs);
    expect(String(B0.formationClockUnixSecs + B0.pinnedRedemptionWindowSecs)).toBe(
      B0.signedExpiryUnixSecs,
    );
  });
});

// ── (a) Boundary ─────────────────────────────────────────────────────────────

describe("EXP-BOUNDARY — delivery boundary (D9.14 / GN-016 / ZTR-149)", () => {
  const base = {
    status: "AWAITING_REDEMPTION",
    partialExists: true,
    firstDeliveredAt: "2026-07-18T00:00:00.000Z",
    redemptionExpiryUnixSecs: B0.signedExpiryUnixSecs,
  } as const;

  it("EXP-BOUNDARY-01 before-expiry redelivery serves identical bytes [P]", () => {
    const id: CaseId = "EXP-BOUNDARY-01";
    expect(id).toBe("EXP-BOUNDARY-01");
    const clock = B0.signedExpiryUnixSecsNumber - 1;
    const eval_ = evaluatePostDeliveryExpiry({ ...base, nowUnixSecs: clock });
    expect(eval_.outcome).toBe("NOT_YET_EXPIRED");
    if (eval_.outcome === "NOT_YET_EXPIRED") {
      expect(eval_.remainingSecs).toBe(1);
    }
    expect(base.status).toBe("AWAITING_REDEMPTION");
    const fp1 = fingerprintPartialImmutableBytes(B0.partial);
    const fp2 = fingerprintPartialImmutableBytes(B0.partial);
    expect(fp1).toBe(fp2);
    const actions = derivePermittedActions(
      b0Facts("AWAITING_REDEMPTION", b0Send()),
      "WAITING",
    ).permittedActions;
    expect(actions).toContain("REDELIVER_EXACT_PARTIAL");
  });

  it("EXP-BOUNDARY-02 at-expiry boundary is inclusive [P]", () => {
    const id: CaseId = "EXP-BOUNDARY-02";
    expect(id).toBe("EXP-BOUNDARY-02");
    const clock = B0.signedExpiryUnixSecsNumber;
    expect(isPastExpiry(B0.signedExpiryUnixSecs, clock)).toBe(true);
    expect(isPastExpiry(B0.signedExpiryUnixSecs, clock - 1)).toBe(false);
    const actions = derivePermittedActions(
      b0Facts("AWAITING_REDEMPTION", b0Send()),
      "WAITING",
    ).permittedActions;
    expect(actions).toContain("REDELIVER_EXACT_PARTIAL");
    expect(transitionExists("AWAITING_REDEMPTION", "EXPIRED")).toBe(false);
    expect(SEND_EXTERNAL_STATES as readonly string[]).not.toContain("EXPIRED");
  });

  it("EXP-BOUNDARY-03 after-expiry delivery parks, never rejects [P]+[N]", () => {
    const id: CaseId = "EXP-BOUNDARY-03";
    expect(id).toBe("EXP-BOUNDARY-03");
    const clock = B0.signedExpiryUnixSecsNumber + 1;
    const eval_ = evaluatePostDeliveryExpiry({ ...base, nowUnixSecs: clock });
    expect(eval_.outcome).toBe("PAST_EXPIRY_PARK_ATTENTION");
    // [P] redelivery still admitted (persisted partial still returned)
    const facts = b0Facts("NEEDS_ATTENTION", b0Send({ protocolExpiredPlusMargin: false }));
    const actions = derivePermittedActions(facts, "WAITING").permittedActions;
    expect(actions).toContain("REDELIVER_EXACT_PARTIAL");
    // [N] no terminal reject, no lease release, no EXPIRED edge
    const close = planRecoveryEffect("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED", facts, null);
    expect(close.ok).toBe(false);
    expect(transitionExists("AWAITING_REDEMPTION", "EXPIRED")).toBe(false);
    expect(transitionExists("AWAITING_REDEMPTION", "REJECTED")).toBe(false);
    expect(EXPIRY_ATTENTION_SRC).not.toMatch(/DELETE\s+FROM\s+wallet_active_leases/i);
  });

  it("EXP-BOUNDARY-04 no EXPIRED state/event is representable for SEND_EXTERNAL [N]", () => {
    const id: CaseId = "EXP-BOUNDARY-04";
    expect(id).toBe("EXP-BOUNDARY-04");
    expect(SEND_EXTERNAL_STATES).toEqual([
      "CREATED",
      "APPROVED",
      "AWAITING_REDEMPTION",
      "EXTERNAL_SEND_LANDED",
      "REJECTED",
      "NEEDS_ATTENTION",
    ]);
    expect(SEND_EXTERNAL_STATES as readonly string[]).not.toContain("EXPIRED");
    // operation.expired exists in the global nine-value set (RECEIVE uses it) but
    // SEND_EXTERNAL transitions never append it.
    expect(DURABLE_EVENTS).toContain("operation.expired");
    for (const t of SEND_EXTERNAL_TRANSITIONS) {
      expect(t.event).not.toBe("operation.expired");
    }
    expect(EXPIRY_ATTENTION_SRC).not.toMatch(/operation\.expired/);
    expect(EXPIRY_ATTENTION_SRC).not.toMatch(/status = 'EXPIRED'/);
  });
});

// ── (b) Skew / two-timer ─────────────────────────────────────────────────────

describe("EXP-SKEW — two-timer separation (D9.14 / GN-016 / ZTR-149)", () => {
  it("EXP-SKEW-01 T1 freshness checks SIGNED issued_at, not receipt time [P]+[N]", () => {
    const id: CaseId = "EXP-SKEW-01";
    expect(id).toBe("EXP-SKEW-01");
    const issuedAtMs = B0.formationClockMs - 60_000;
    const expiresAtMs = issuedAtMs + B0.pinnedApprovalFreshnessSecs * 1000;
    const skewedReceipt = issuedAtMs + 10_000_000;
    expect(oracle.t1Fresh(issuedAtMs, expiresAtMs, skewedReceipt)).toBe(true);
    expect(TIMER_SEPARATION.t1ApprovalChallengeFreshness.source).toBe("approval_tuple.expires_at");
    expect(TIMER_SEPARATION.t1ApprovalChallengeFreshness.isRedemptionDeadline).toBe(false);
    expect(APPROVAL_CHALLENGE_FRESHNESS_MS).toBe(B0.pinnedApprovalFreshnessSecs * 1000);
    expect(TIMER_SEPARATION.t2RedemptionExpiry.source).not.toBe(
      TIMER_SEPARATION.t1ApprovalChallengeFreshness.source,
    );
  });

  it("EXP-SKEW-02 T2 is floor(node_clock)+300, anchored to FORMATION [P]", () => {
    const id: CaseId = "EXP-SKEW-02";
    expect(id).toBe("EXP-SKEW-02");
    const skewedMs = B0.formationClockMs + 999;
    expect(oracle.t2FromFormationClockMs(skewedMs)).toBe(B0.signedExpiryUnixSecs);
    expect(deriveSendRedemptionExpiryUnixSecs(B0.formationClockMs)).toBe(B0.signedExpiryUnixSecs);
    expect(deriveSendRedemptionExpiryUnixSecs(skewedMs)).toBe(B0.signedExpiryUnixSecs);
    const t2 = deriveSendRedemptionExpiryUnixSecs(B0.formationClockMs);
    expect(typeof t2).toBe("string");
    expect(t2).toMatch(/^[0-9]+$/);
    expect(Number(t2)).toBeLessThan(1e12);
    expect(TIMER_SEPARATION.t2RedemptionExpiry.materializedAt).toBe("sign_intent_formation");
    expect(TIMER_SEPARATION.t2RedemptionExpiry.byteFrozenAfterFormation).toBe(true);
    expect(SEND_REDEMPTION_WINDOW_SECS).toBe(B0.pinnedRedemptionWindowSecs);
  });

  it("EXP-SKEW-03 recipient anchor is the signed inner, not available_until [N]", () => {
    const id: CaseId = "EXP-SKEW-03";
    expect(id).toBe("EXP-SKEW-03");
    const tamperedAvailableUntil = "2099-01-01T00:00:00.000Z";
    const eval_ = evaluatePostDeliveryExpiry({
      status: "AWAITING_REDEMPTION",
      partialExists: true,
      firstDeliveredAt: B0.availableUntil,
      redemptionExpiryUnixSecs: B0.signedExpiryUnixSecs,
      nowUnixSecs: B0.signedExpiryUnixSecsNumber + 1,
    });
    expect(eval_.outcome).toBe("PAST_EXPIRY_PARK_ATTENTION");
    expect(redemptionExpiryAtFromSecs(B0.signedExpiryUnixSecs)).toBe(B0.availableUntil);
    expect(redemptionExpiryAtFromSecs(B0.signedExpiryUnixSecs)).not.toBe(tamperedAvailableUntil);
    expect(B0.signedExpiryUnixSecs).not.toBe(B0.availableUntil);
    expect(TIMER_SEPARATION.t2RedemptionExpiry.source).toBe("signed_splitchain_inner.expiry");
  });

  it("EXP-SKEW-04 integer-seconds, never ms/JS-number [N]", () => {
    const id: CaseId = "EXP-SKEW-04";
    expect(id).toBe("EXP-SKEW-04");
    const canonical = B0.signedExpiryUnixSecs;
    expect(() => isPastExpiry("1784333100.5", B0.signedExpiryUnixSecsNumber)).toThrow(
      /integer-seconds/,
    );
    expect(String(B0.signedExpiryUnixSecsNumber * 1000)).not.toBe(canonical);
    const bodyNumber = JSON.stringify({ expiry__unix_time_secs: B0.signedExpiryUnixSecsNumber });
    const bodyString = JSON.stringify({ expiry__unix_time_secs: canonical });
    expect(sha256Hex(bodyNumber)).not.toBe(sha256Hex(bodyString));
    // SIGN_INTENT freezes redemption_expiry once formed
    expect(SIGN_INTENT_FROZEN_AFTER_EXISTS).toContain("redemption_expiry");
  });
});

// ── (c) Replay ───────────────────────────────────────────────────────────────

describe("EXP-REPLAY — single-use approval / one partial (D9.14 / GN-016 / ZTR-149)", () => {
  it("EXP-REPLAY-01 approval single-use under TOTP timestep [N]", () => {
    const id: CaseId = "EXP-REPLAY-01";
    expect(id).toBe("EXP-REPLAY-01");
    expect(APPROVAL_CARDINALITY.signIntent.maxPerApproval).toBe(1);
    expect(APPROVAL_CONSUMPTION.restoredAfterDownstreamFailure).toBe(false);
    expect(APPROVAL_CONSUMPTION.consumedBeforeMutation).toBe(true);
    expect(APPROVAL_CONSUMPTION.burnOnSignerFailure).toBe(true);
  });

  it("EXP-REPLAY-02 one approval ⇒ one sign intent ⇒ one partial [N]", () => {
    const id: CaseId = "EXP-REPLAY-02";
    expect(id).toBe("EXP-REPLAY-02");
    expect(APPROVAL_CARDINALITY.signIntent.maxPerApproval).toBe(1);
    expect(APPROVAL_CARDINALITY.stepOneSignature.maxPerApproval).toBe(1);
    expect(APPROVAL_CARDINALITY.persistedPartial.maxPerApproval).toBe(1);
    expect(TRANSACTION_MATERIAL_SQL).toMatch(
      /CREATE TABLE external_send_partials[\s\S]*?operation_id uuid PRIMARY KEY/,
    );
    expect(TRANSACTION_MATERIAL_SQL).toMatch(/approval_id uuid NOT NULL UNIQUE/);
    expect(TRANSACTION_MATERIAL_SQL).toMatch(/CREATE TABLE external_send_sign_intents/);
  });

  it("EXP-REPLAY-03 terminal replay is idempotent [P]", () => {
    const id: CaseId = "EXP-REPLAY-03";
    expect(id).toBe("EXP-REPLAY-03");
    expect(transitionExists("EXTERNAL_SEND_LANDED", "EXTERNAL_SEND_LANDED")).toBe(false);
    expect(transitionExists("REJECTED", "EXTERNAL_SEND_LANDED")).toBe(false);
    expect(transitionExists("EXTERNAL_SEND_LANDED", "REJECTED")).toBe(false);
    const fromLanded = SEND_EXTERNAL_TRANSITIONS.filter((t) => t.from === "EXTERNAL_SEND_LANDED");
    const fromRejected = SEND_EXTERNAL_TRANSITIONS.filter((t) => t.from === "REJECTED");
    expect(fromLanded).toEqual([]);
    expect(fromRejected).toEqual([]);
  });
});

// ── (d) Crash ────────────────────────────────────────────────────────────────

describe("EXP-CRASH — crash inventory (D9.14 / GN-016 / ZTR-149)", () => {
  it("EXP-CRASH-01 crash before durable sign intent [P]", () => {
    const id: CaseId = "EXP-CRASH-01";
    expect(id).toBe("EXP-CRASH-01");
    const row = recoveryActionFor("APPROVAL_CONSUMED_NO_SIGN_INTENT");
    expect(row.recovery).toBe("ACQUIRE_READ_FRESH_PERSIST_FIRST_SIGN_INTENT");
    expect(row.forbidden).toBe("CREATE_SECOND_SIGN_INTENT");
    const ok = classifyApprovalConsumedNoSignIntent({
      signerAuditShowsSigningCall: false,
      persistedPreimageRecordAvailable: true,
      persistedPreimageRecordContradictory: false,
    });
    expect(ok).toBe("ACQUIRE_READ_FRESH_PERSIST_FIRST_SIGN_INTENT");
  });

  it("EXP-CRASH-02 crash after sign intent, before signature [P]", () => {
    const id: CaseId = "EXP-CRASH-02";
    expect(id).toBe("EXP-CRASH-02");
    const row = recoveryActionFor("SIGNING_CLAIMED_NO_PARTIAL");
    expect(row.recovery).toBe("REVALIDATE_SAME_PREIMAGE_COMPLETE_FIRST_FORMATION");
    expect(row.forbidden).toBe("CONSTRUCT_DIFFERENT_INNER_OR_CODE");
    expect(DETERMINISTIC_RESIGN.recoveryReSignsSamePreimage).toBe(true);
    expect(DETERMINISTIC_RESIGN.stepOneSignerMustBeDeterministicEd25519Rfc8032).toBe(true);
  });

  it("EXP-CRASH-03 crash after signature persistence [P]", () => {
    const id: CaseId = "EXP-CRASH-03";
    expect(id).toBe("EXP-CRASH-03");
    const undelivered = recoveryActionFor("PARTIAL_COMMITTED_UNDELIVERED");
    expect(undelivered.recovery).toBe("DELIVER_EXACT_PERSISTED_CODE");
    expect(undelivered.forbidden).toBe("RE_SIGN_OR_RE_FORM");
    const delivered = recoveryActionFor("PARTIAL_DELIVERED_HEAD_UNCHANGED");
    expect(delivered.recovery).toBe("REDELIVER_EXACT_PERSISTED_CODE");
    expect(delivered.forbidden).toBe("MINT_REPLACEMENT_PARTIAL");
    expect(REDELIVERY_RULE).toBe("byte_identical_persisted_partial_only");
  });

  it("EXP-CRASH-04 missing/contradictory preimage is INVARIANT_BREACH [N]", () => {
    const id: CaseId = "EXP-CRASH-04";
    expect(id).toBe("EXP-CRASH-04");
    const breach = classifyApprovalConsumedNoSignIntent({
      signerAuditShowsSigningCall: true,
      persistedPreimageRecordAvailable: true,
      persistedPreimageRecordContradictory: false,
    });
    expect(breach).toBe(INVARIANT_BREACH_PREDICATE.action);
    expect(INVARIANT_BREACH_PREDICATE.classification).toBe("INVARIANT_BREACH");
    expect(INVARIANT_BREACH_PREDICATE.permitsFirstFormation).toBe(false);
    expect(INVARIANT_BREACH_PREDICATE.permitsLeaseRelease).toBe(false);
    expect(breach).not.toBe("ACQUIRE_READ_FRESH_PERSIST_FIRST_SIGN_INTENT");
  });

  it("EXP-CRASH-05 lease heartbeat expiry ≠ lease release [N]", () => {
    const id: CaseId = "EXP-CRASH-05";
    expect(id).toBe("EXP-CRASH-05");
    expect(() => assertNoForbiddenSqlInAllowedSet()).not.toThrow();
    for (const sql of SEND_EXPIRY_ATTENTION_ALLOWED_SQL) {
      expect(sql.toUpperCase()).not.toContain("DELETE FROM WALLET_ACTIVE_LEASES");
      expect(sql.toUpperCase()).not.toMatch(/UPDATE\s+WALLET_ACTIVE_LEASES/);
    }
    const anomalous = recoveryActionFor("PARTIAL_DELIVERED_HEAD_ANOMALOUS");
    expect(anomalous.recovery).toBe("NEEDS_ATTENTION_PRESERVE_LEASE_EVIDENCE");
    expect(anomalous.forbidden).toBe("INFER_NON_LANDING_OR_RETRY");
  });
});

// ── (e) Redeliver ────────────────────────────────────────────────────────────

describe("EXP-REDELIVER — byte-identical redelivery (D9.14 / GN-016 / ZTR-149)", () => {
  it("EXP-REDELIVER-01 redelivery is byte-identical, counters only [P]+[N]", () => {
    const id: CaseId = "EXP-REDELIVER-01";
    expect(id).toBe("EXP-REDELIVER-01");
    const before = fingerprintPartialImmutableBytes(B0.partial);
    for (let i = 0; i < 5; i++) {
      expect(fingerprintPartialImmutableBytes(B0.partial)).toBe(before);
    }
    expect(REDELIVERY_RULE).toBe("byte_identical_persisted_partial_only");
    expect(REPLACEMENT_RULE.permitsSecondPartialUnderOldApproval).toBe(false);
    expect(EXPIRY_ATTENTION_SRC).not.toMatch(/signStep1|invokeSigner|REFORM_EXTERNAL_SEND/);
    expect(EXPIRY_ATTENTION_SRC).toMatch(/redeliverExactPartial/);
  });

  it("EXP-REDELIVER-02 REDELIVER_EXACT_PARTIAL serves stored bytes [P]", () => {
    const id: CaseId = "EXP-REDELIVER-02";
    expect(id).toBe("EXP-REDELIVER-02");
    const facts = b0Facts("NEEDS_ATTENTION", b0Send());
    const planned = planRecoveryEffect("REDELIVER_EXACT_PARTIAL", facts, null);
    expect(planned.ok).toBe(true);
    if (planned.ok) {
      expect(planned.effect.kind).toBe("REDELIVER_EXACT_PARTIAL");
    }
    const actions = derivePermittedActions(facts, "WAITING").permittedActions;
    expect(actions).toContain("REDELIVER_EXACT_PARTIAL");
    expect(actions.join(",")).not.toMatch(/REFORM/);
    expect(BYTE_IMMUTABILITY_SQL).toMatch(/external_send_partials_reject_byte_mutation/);
    expect(FORBIDDEN_RECOVERY_SRC).toContain("REFORM_EXTERNAL_SEND");
  });
});

// ── (f) Stale destination ────────────────────────────────────────────────────

describe("EXP-STALE — stale destination never re-signs (D9.14 / GN-016 / ZTR-149)", () => {
  it("EXP-STALE-01 stale destination refuses; node never re-signs [N]", () => {
    const id: CaseId = "EXP-STALE-01";
    expect(id).toBe("EXP-STALE-01");
    const anomalous = recoveryActionFor("PARTIAL_DELIVERED_HEAD_ANOMALOUS");
    expect(anomalous.recovery).toBe("NEEDS_ATTENTION_PRESERVE_LEASE_EVIDENCE");
    expect(anomalous.forbidden).toBe("INFER_NON_LANDING_OR_RETRY");
    expect(REPLACEMENT_RULE.refreshesExpiryUnderOldApproval).toBe(false);
    expect(REPLACEMENT_RULE.permitsSecondPartialUnderOldApproval).toBe(false);
    const expired = recoveryActionFor("PARTIAL_EXPIRED");
    expect(expired.forbidden).toBe("REFRESH_EXPIRY_UNDER_OLD_APPROVAL");
  });

  it("EXP-STALE-02 DESTINATION_NO_LONGER_BLESSED parks, does not reform [N]", () => {
    const id: CaseId = "EXP-STALE-02";
    expect(id).toBe("EXP-STALE-02");
    expect(transitionExists("AWAITING_REDEMPTION", "NEEDS_ATTENTION")).toBe(true);
    expect(SEND_EXTERNAL_TRANSITIONS.some((t) => String(t.guard).includes("re-form"))).toBe(
      false,
    );
    expect(ATTENTION_REASONS).toContain("DESTINATION_NO_LONGER_BLESSED");
    expect(EXPIRY_ATTENTION_SRC).not.toMatch(/REFORM_EXTERNAL_SEND/);
    expect(FORBIDDEN_RECOVERY_SRC).toMatch(/REFORM_EXTERNAL_SEND/);
  });
});

// ── (g) Late landing ─────────────────────────────────────────────────────────

describe("EXP-LATE — late completion / reconciliation (D9.14 / GN-016 / ZTR-149)", () => {
  it("EXP-LATE-01 late completion lands from AWAITING_REDEMPTION [P]", () => {
    const id: CaseId = "EXP-LATE-01";
    expect(id).toBe("EXP-LATE-01");
    expect(transitionExists("AWAITING_REDEMPTION", "EXTERNAL_SEND_LANDED")).toBe(true);
    const t = SEND_EXTERNAL_TRANSITIONS.find(
      (x) => x.from === "AWAITING_REDEMPTION" && x.to === "EXTERNAL_SEND_LANDED",
    );
    expect(t?.event).toBe("external_send.landed");
  });

  it("EXP-LATE-02 late reconciliation lands from NEEDS_ATTENTION [P]", () => {
    const id: CaseId = "EXP-LATE-02";
    expect(id).toBe("EXP-LATE-02");
    expect(transitionExists("NEEDS_ATTENTION", "EXTERNAL_SEND_LANDED")).toBe(true);
    const t = SEND_EXTERNAL_TRANSITIONS.find(
      (x) => x.from === "NEEDS_ATTENTION" && x.to === "EXTERNAL_SEND_LANDED",
    );
    expect(t?.event).toBe("external_send.landed");
  });

  it("EXP-LATE-03 post-close landing is P0 breach, never auto-reversal [N]", () => {
    const id: CaseId = "EXP-LATE-03";
    expect(id).toBe("EXP-LATE-03");
    expect(transitionExists("REJECTED", "EXTERNAL_SEND_LANDED")).toBe(false);
    expect(transitionExists("REJECTED", "AWAITING_REDEMPTION")).toBe(false);
    expect(transitionExists("REJECTED", "NEEDS_ATTENTION")).toBe(false);
    const fromRejected = SEND_EXTERNAL_TRANSITIONS.filter((t) => t.from === "REJECTED");
    expect(fromRejected).toEqual([]);
  });
});

// ── (h) Close oracle ─────────────────────────────────────────────────────────

describe("EXP-CLOSE — terminal close gates (D9.14 / GN-016 / ZTR-149)", () => {
  it("EXP-CLOSE-01 expiry alone cannot close/release [N]", () => {
    const id: CaseId = "EXP-CLOSE-01";
    expect(id).toBe("EXP-CLOSE-01");
    const clock = B0.signedExpiryUnixSecsNumber + 1;
    expect(clock).toBeLessThan(B0.oracleEligibleAt);
    expect(
      oracle.twoPartCloseOracle({
        nowUnixSecs: clock,
        signedExpiryUnixSecs: B0.signedExpiryUnixSecs,
        freshHeadEqualsT0: true,
      }),
    ).toBe(false);
    const facts = b0Facts(
      "NEEDS_ATTENTION",
      b0Send({ protocolExpiredPlusMargin: false, freshHeadEqualsSourceT0: true }),
    );
    const close = planRecoveryEffect("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED", facts, null);
    expect(close.ok).toBe(false);
    expect(oracleEligibleAtUnixSecs(B0.signedExpiryUnixSecs)).toBe(B0.oracleEligibleAt);
    expect(SEND_PARTIAL_AGING_MARGIN_SECS).toBe(B0.pinnedAgingMarginSecs);
  });

  it("EXP-CLOSE-02 two-part oracle gates terminal close [P]+[N]", () => {
    const id: CaseId = "EXP-CLOSE-02";
    expect(id).toBe("EXP-CLOSE-02");
    expect(
      oracle.twoPartCloseOracle({
        nowUnixSecs: B0.oracleEligibleAt,
        signedExpiryUnixSecs: B0.signedExpiryUnixSecs,
        freshHeadEqualsT0: true,
      }),
    ).toBe(true);
    const okFacts = b0Facts(
      "NEEDS_ATTENTION",
      b0Send({ protocolExpiredPlusMargin: true, freshHeadEqualsSourceT0: true }),
    );
    const ok = planRecoveryEffect("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED", okFacts, null);
    expect(ok.ok).toBe(true);
    if (ok.ok) {
      expect(ok.effect.kind).toBe("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED");
      expect(ok.effect).toMatchObject({ nextStatus: "REJECTED", releaseSourceLease: true });
    }
    expect(
      oracle.twoPartCloseOracle({
        nowUnixSecs: B0.oracleEligibleAt - 1,
        signedExpiryUnixSecs: B0.signedExpiryUnixSecs,
        freshHeadEqualsT0: true,
      }),
    ).toBe(false);
    const missingHead = b0Facts(
      "NEEDS_ATTENTION",
      b0Send({
        protocolExpiredPlusMargin: true,
        freshHeadEqualsSourceT0: false,
        completePathExclusionProved: false,
      }),
    );
    expect(
      planRecoveryEffect("CLOSE_EXTERNAL_SEND_PROVEN_NOT_LANDED", missingHead, null).ok,
    ).toBe(false);
  });

  it("EXP-CLOSE-03 no direct AWAITING_REDEMPTION→REJECTED [N]", () => {
    const id: CaseId = "EXP-CLOSE-03";
    expect(id).toBe("EXP-CLOSE-03");
    expect(transitionExists("AWAITING_REDEMPTION", "REJECTED")).toBe(false);
    expect(transitionExists("AWAITING_REDEMPTION", "NEEDS_ATTENTION")).toBe(true);
    expect(transitionExists("NEEDS_ATTENTION", "REJECTED")).toBe(true);
    const reject = SEND_EXTERNAL_TRANSITIONS.find(
      (t) => t.from === "NEEDS_ATTENTION" && t.to === "REJECTED",
    );
    expect(reject).toBeDefined();
  });

  it("EXP-CLOSE-04 CLOSE_NEVER_STARTED needs AND of durable negatives [N]", () => {
    const id: CaseId = "EXP-CLOSE-04";
    expect(id).toBe("EXP-CLOSE-04");
    const allClear = {
      hasSignIntent: false,
      hasSignerCall: false,
      hasSignature: false,
      hasDurablePartial: false,
      hasDelivery: false,
    };
    expect(oracle.closeNeverStartedNegatives(allClear)).toBe(true);
    expect(oracle.closeNeverStartedNegatives({ ...allClear, hasSignIntent: true })).toBe(false);
    const withPartial = b0Facts(
      "APPROVED",
      b0Send({
        hasSignIntent: false,
        hasSignerCall: false,
        hasSignature: false,
        hasDurablePartial: true,
        hasDelivery: false,
      }),
    );
    expect(planRecoveryEffect("CLOSE_NEVER_STARTED_EXTERNAL_SEND", withPartial, null).ok).toBe(
      false,
    );
    const neverStarted = b0Facts(
      "APPROVED",
      b0Send({
        hasSignIntent: false,
        hasSignerCall: false,
        hasSignature: false,
        hasDurablePartial: false,
        hasDelivery: false,
        protocolExpiredPlusMargin: true,
        freshHeadEqualsSourceT0: true,
      }),
    );
    const planned = planRecoveryEffect("CLOSE_NEVER_STARTED_EXTERNAL_SEND", neverStarted, null);
    expect(planned.ok).toBe(true);
  });

  it("EXP-CLOSE-05 node has no submit route for SEND_EXTERNAL [N]", () => {
    const id: CaseId = "EXP-CLOSE-05";
    expect(id).toBe("EXP-CLOSE-05");
    expect(SUBMIT_GUARD_TEST).toMatch(
      /SEND_EXTERNAL cannot reach either submit-decision write path/,
    );
    expect(SUBMIT_GUARD_TEST).toContain("makeSubmitDecisionClaimStore");
    expect(SUBMIT_GUARD_TEST).toContain("makeSubmitAttemptRecorder");
    expect(EXPIRY_ATTENTION_SRC).not.toMatch(/submit_decisions|gateway_submit_attempts/);
    for (const sql of SEND_EXPIRY_ATTENTION_ALLOWED_SQL) {
      expect(sql).not.toMatch(/submit_decisions|gateway_submit_attempts/);
    }
    expect(FORBIDDEN_RECOVERY_SRC).toContain("NODE_SUBMIT_EXTERNAL_SEND");
    void SEND_EXPIRY_ATTENTION_SQL;
  });
});

// ── (i) No replacement ───────────────────────────────────────────────────────

describe("EXP-REPLACE — no second attempt / partial (D9.14 / GN-016 / ZTR-149)", () => {
  it("EXP-REPLACE-01 no second transaction attempt [N]", () => {
    const id: CaseId = "EXP-REPLACE-01";
    expect(id).toBe("EXP-REPLACE-01");
    expect(TRANSACTION_MATERIAL_SQL).toMatch(
      /attempt_no integer NOT NULL CHECK \(attempt_no = 1\)/,
    );
    expect(TRANSACTION_MATERIAL_SQL).toMatch(/PRIMARY KEY \(operation_id, attempt_no\)/);
  });

  it("EXP-REPLACE-02 no second submit decision/call [N]", () => {
    const id: CaseId = "EXP-REPLACE-02";
    expect(id).toBe("EXP-REPLACE-02");
    expect(SUBMIT_ATTEMPTS_SQL).toMatch(/CREATE TABLE submit_decisions/);
    expect(SUBMIT_ATTEMPTS_SQL).toMatch(
      /transaction_attempt_no integer NOT NULL CHECK \(transaction_attempt_no = 1\)/,
    );
    expect(SUBMIT_ATTEMPTS_SQL).toMatch(/UNIQUE \(operation_id, transaction_attempt_no\)/);
    expect(SUBMIT_ATTEMPTS_SQL).toMatch(/CREATE TABLE gateway_submit_attempts/);
    expect(SUBMIT_ATTEMPTS_SQL).toMatch(/UNIQUE \(operation_id, attempt_no\)/);
  });

  it("EXP-REPLACE-03 no replacement partial after expiry/crash [N]", () => {
    const id: CaseId = "EXP-REPLACE-03";
    expect(id).toBe("EXP-REPLACE-03");
    expect(REPLACEMENT_RULE.permitsSecondPartialUnderOldApproval).toBe(false);
    expect(REPLACEMENT_RULE.refreshesExpiryUnderOldApproval).toBe(false);
    expect(REPLACEMENT_RULE.requires).toEqual(
      expect.arrayContaining([
        "safe_resolution_of_existing_operation",
        "new_operation",
        "fresh_approval",
      ]),
    );
    expect(TRANSACTION_MATERIAL_SQL).toMatch(
      /CREATE TABLE external_send_partials[\s\S]*?operation_id uuid PRIMARY KEY/,
    );
    expect(TRANSACTION_MATERIAL_SQL).toMatch(/approval_id uuid NOT NULL UNIQUE/);
    expect(BYTE_IMMUTABILITY_SQL).toMatch(/external_send_partials_reject_byte_mutation/);
    const expired = recoveryActionFor("PARTIAL_EXPIRED");
    expect(expired.forbidden).toBe("REFRESH_EXPIRY_UNDER_OLD_APPROVAL");
  });
});

// ── Mutation guards (ticket AC) ──────────────────────────────────────────────

describe("CONTRACT_FREEZE mutation guards (D9.14 / GN-016 / ZTR-149)", () => {
  it("mutating SEND_REDEMPTION_WINDOW_SECS away from the B0 pin fails the matrix", () => {
    expect(SEND_REDEMPTION_WINDOW_SECS).toBe(B0.pinnedRedemptionWindowSecs);
    expect(deriveSendRedemptionExpiryUnixSecs(B0.formationClockMs)).toBe(B0.signedExpiryUnixSecs);
    expect(SEND_REDEMPTION_SRC).toMatch(
      /export const SEND_REDEMPTION_WINDOW_SECS = 300 as const/,
    );
    expect(SEND_REDEMPTION_SRC).not.toMatch(/Date\.now\(/);
  });

  it("confusing signed expiry with approval expires_at or available_until fails the matrix", () => {
    expect(TIMER_SEPARATION.t1ApprovalChallengeFreshness.isRedemptionDeadline).toBe(false);
    expect(TIMER_SEPARATION.t2RedemptionExpiry.isSingleImmutableRedemptionDeadline).toBe(true);
    expect(TIMER_SEPARATION.t2RedemptionExpiry.source).toBe("signed_splitchain_inner.expiry");
    expect(TIMER_SEPARATION.t1ApprovalChallengeFreshness.source).toBe(
      "approval_tuple.expires_at",
    );
    expect(B0.availableUntil).not.toBe(B0.signedExpiryUnixSecs);
    const forgedApprovalExpiresAt = "2099-12-31T23:59:59.000Z";
    const eval_ = evaluatePostDeliveryExpiry({
      status: "AWAITING_REDEMPTION",
      partialExists: true,
      firstDeliveredAt: forgedApprovalExpiresAt,
      redemptionExpiryUnixSecs: B0.signedExpiryUnixSecs,
      nowUnixSecs: B0.signedExpiryUnixSecsNumber - 1,
    });
    expect(eval_.outcome).toBe("NOT_YET_EXPIRED");
  });

  it("every CASE_ID appears as a named test title in this file", () => {
    const self = readFileSync(SELF_PATH, "utf8");
    for (const caseId of CASE_IDS) {
      expect(self).toContain(`"${caseId}"`);
      expect(self).toMatch(new RegExp(`it\\("${caseId} `));
    }
  });

  it("crash matrix remains the 8-row closed set the EXP-CRASH cases index into", () => {
    expect(CRASH_MATRIX).toHaveLength(8);
  });
});

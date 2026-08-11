// pure unit coverage for SEND expiry evaluation + SQL catalogue
// invariants. DB-backed transitions live in test/send-expiry-attention.pg.test.ts.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  OPERATION_NEEDS_ATTENTION_EVENT,
  SEND_EXPIRY_ATTENTION_ALLOWED_SQL,
  SEND_EXPIRY_ATTENTION_REASON,
  SEND_EXPIRY_ATTENTION_SQL,
  SEND_PARTIAL_AGING_MARGIN_SECS,
  SEND_REDEMPTION_WINDOW_SECS,
  assertNoForbiddenSqlInAllowedSet,
  classifySendDeliveryBoundary,
  evaluatePostDeliveryExpiry,
  extractSignedExpiryUnixSecs,
  fingerprintPartialImmutableBytes,
  isPastExpiry,
  oracleEligibleAtUnixSecs,
} from "./expiry-attention.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const SOURCE = readFileSync(join(HERE, "expiry-attention.ts"), "utf8");

describe("send expiry attention — constants (SEND_EXTERNAL expiry single-source)", () => {
  it("SEND_REDEMPTION_WINDOW_SECS is 300", () => {
    expect(SEND_REDEMPTION_WINDOW_SECS).toBe(300);
  });

  it("SEND_PARTIAL_AGING_MARGIN_SECS is 3600", () => {
    expect(SEND_PARTIAL_AGING_MARGIN_SECS).toBe(3600);
  });

  it("parks with a closed attention reason (F1.1 UNEXPECTED_HEAD_CHANGE)", () => {
    expect(SEND_EXPIRY_ATTENTION_REASON).toBe("UNEXPECTED_HEAD_CHANGE");
  });

  it("emits the closed durable event operation.needs_attention", () => {
    expect(OPERATION_NEEDS_ATTENTION_EVENT).toBe("operation.needs_attention");
  });
});

describe("classifySendDeliveryBoundary", () => {
  it("AWAITING_REDEMPTION + partial → POST_DELIVERY_AWAITING", () => {
    expect(
      classifySendDeliveryBoundary({
        status: "AWAITING_REDEMPTION",
        partialExists: true,
        firstDeliveredAt: "2026-07-01T00:00:00.000Z",
      }),
    ).toBe("POST_DELIVERY_AWAITING");
  });

  it("NEEDS_ATTENTION + partial → POST_DELIVERY_ATTENTION", () => {
    expect(
      classifySendDeliveryBoundary({
        status: "NEEDS_ATTENTION",
        partialExists: true,
        firstDeliveredAt: null,
      }),
    ).toBe("POST_DELIVERY_ATTENTION");
  });

  it("APPROVED without partial → PRE_DELIVERY", () => {
    expect(
      classifySendDeliveryBoundary({
        status: "APPROVED",
        partialExists: false,
        firstDeliveredAt: null,
      }),
    ).toBe("PRE_DELIVERY");
  });

  it("EXTERNAL_SEND_LANDED / REJECTED → TERMINAL", () => {
    expect(
      classifySendDeliveryBoundary({
        status: "EXTERNAL_SEND_LANDED",
        partialExists: true,
        firstDeliveredAt: "x",
      }),
    ).toBe("TERMINAL");
    expect(
      classifySendDeliveryBoundary({
        status: "REJECTED",
        partialExists: false,
        firstDeliveredAt: null,
      }),
    ).toBe("TERMINAL");
  });
});

describe("evaluatePostDeliveryExpiry", () => {
  const base = {
    status: "AWAITING_REDEMPTION",
    partialExists: true,
    firstDeliveredAt: "2026-07-01T00:00:00.000Z",
    redemptionExpiryUnixSecs: "1784333100",
  };

  it("NOT_YET_EXPIRED while clock is before T2", () => {
    const r = evaluatePostDeliveryExpiry({ ...base, nowUnixSecs: 1784333099 });
    expect(r.outcome).toBe("NOT_YET_EXPIRED");
    if (r.outcome !== "NOT_YET_EXPIRED") return;
    expect(r.remainingSecs).toBe(1);
  });

  it("NOT_YET_EXPIRED at exact T2 boundary (doc §11.9 window includes equality)", () => {
    const r = evaluatePostDeliveryExpiry({ ...base, nowUnixSecs: 1784333100 });
    expect(r.outcome).toBe("NOT_YET_EXPIRED");
    if (r.outcome !== "NOT_YET_EXPIRED") return;
    expect(r.remainingSecs).toBe(0);
  });

  it("PAST_EXPIRY_PARK_ATTENTION well past T2 (still no terminal)", () => {
    const r = evaluatePostDeliveryExpiry({
      ...base,
      nowUnixSecs: 1784333100 + SEND_PARTIAL_AGING_MARGIN_SECS + 1,
    });
    expect(r.outcome).toBe("PAST_EXPIRY_PARK_ATTENTION");
  });

  it("ALREADY_ATTENTION is a no-repark", () => {
    const r = evaluatePostDeliveryExpiry({
      ...base,
      status: "NEEDS_ATTENTION",
      nowUnixSecs: 1784339999,
    });
    expect(r.outcome).toBe("ALREADY_ATTENTION");
  });

  it("TERMINAL_NOOP for landed / rejected", () => {
    expect(
      evaluatePostDeliveryExpiry({
        ...base,
        status: "EXTERNAL_SEND_LANDED",
        nowUnixSecs: 1784339999,
      }).outcome,
    ).toBe("TERMINAL_NOOP");
    expect(
      evaluatePostDeliveryExpiry({
        ...base,
        status: "REJECTED",
        nowUnixSecs: 1784339999,
      }).outcome,
    ).toBe("TERMINAL_NOOP");
  });

  it("PRE_DELIVERY_GATE_ONLY never authorizes lease release or terminal reject", () => {
    const r = evaluatePostDeliveryExpiry({
      status: "APPROVED",
      partialExists: false,
      firstDeliveredAt: null,
      redemptionExpiryUnixSecs: "100",
      nowUnixSecs: 999,
    });
    expect(r.outcome).toBe("PRE_DELIVERY_GATE_ONLY");
    if (r.outcome !== "PRE_DELIVERY_GATE_ONLY") return;
    expect(r.leaseReleaseAuthorized).toBe(false);
    expect(r.terminalRejectAuthorized).toBe(false);
    expect(r.pastT2).toBe(true);
  });
});

describe("isPastExpiry / oracleEligibleAtUnixSecs", () => {
  it("equality is still inside the window (doc §11.9 BOUNDARY-02)", () => {
    expect(isPastExpiry("100", 100)).toBe(false);
    expect(isPastExpiry("100", 99)).toBe(false);
    expect(isPastExpiry("100", 101)).toBe(true);
  });

  it("oracle eligibility = T2 + aging margin (F1.2 fixture)", () => {
    // Expiry="1784333100"; oracle-eligible-at = 1784336700
    expect(oracleEligibleAtUnixSecs("1784333100")).toBe(1784336700);
  });

  it("rejects non-integer-seconds strings", () => {
    expect(() => isPastExpiry("1.5", 2)).toThrow(/integer-seconds/);
    expect(() => oracleEligibleAtUnixSecs("abc")).toThrow(/integer-seconds/);
  });
});

describe("extractSignedExpiryUnixSecs", () => {
  it("reads top-level expiry__unix_time_secs", () => {
    expect(
      extractSignedExpiryUnixSecs(
        JSON.stringify({ expiry__unix_time_secs: "1784333100", amount: "1" }),
      ),
    ).toBe("1784333100");
  });

  it("reads nested inner.expiry__unix_time_secs", () => {
    expect(
      extractSignedExpiryUnixSecs(
        JSON.stringify({
          inner: { expiry__unix_time_secs: "1784333100" },
          step_1_signature: "x",
        }),
      ),
    ).toBe("1784333100");
  });

  it("rejects missing / non-string expiry", () => {
    expect(() => extractSignedExpiryUnixSecs("{}")).toThrow(/missing/);
    expect(() =>
      extractSignedExpiryUnixSecs(JSON.stringify({ expiry__unix_time_secs: 1784333100 })),
    ).toThrow(/missing/);
  });
});

describe("fingerprintPartialImmutableBytes", () => {
  it("is stable and ordering-sensitive on the four immutable fields", () => {
    const a = fingerprintPartialImmutableBytes({
      innerSha256: "aa",
      step1Signature: "s1",
      transferCodeText: "code",
      transferCodeSha256: "bb",
    });
    const b = fingerprintPartialImmutableBytes({
      innerSha256: "aa",
      step1Signature: "s1",
      transferCodeText: "code",
      transferCodeSha256: "bb",
    });
    const c = fingerprintPartialImmutableBytes({
      innerSha256: "aa",
      step1Signature: "s1",
      transferCodeText: "CODE",
      transferCodeSha256: "bb",
    });
    expect(a).toBe(b);
    expect(a).not.toBe(c);
  });
});

describe("SQL catalogue safety (negative paths)", () => {
  it("allowed set has no lease DELETE, EXPIRED, AWAITING→REJECTED, or second partial", () => {
    expect(() => assertNoForbiddenSqlInAllowedSet()).not.toThrow();
  });

  it("CAS_AWAITING_TO_NEEDS_ATTENTION only matches AWAITING_REDEMPTION + partial", () => {
    const sql = SEND_EXPIRY_ATTENTION_SQL.CAS_AWAITING_TO_NEEDS_ATTENTION;
    expect(sql).toMatch(/status = 'AWAITING_REDEMPTION'/);
    expect(sql).toMatch(/status = 'NEEDS_ATTENTION'/);
    expect(sql).toMatch(/EXISTS \(SELECT 1 FROM external_send_partials/);
    expect(sql).not.toMatch(/wallet_active_leases/);
    expect(sql).not.toMatch(/EXPIRED/);
    expect(sql).not.toMatch(/REJECTED/);
  });

  it("CAS_AWAITING_TO_NEEDS_ATTENTION co-commits attention event in one statement (D3)", () => {
    const sql = SEND_EXPIRY_ATTENTION_SQL.CAS_AWAITING_TO_NEEDS_ATTENTION;
    expect(sql).toMatch(/^WITH cas AS \(/);
    expect(sql).toMatch(/INSERT INTO external_send_attention_events/);
    expect(sql).toMatch(/json_build_object/);
    // Standalone APPEND must not be issued by parkPastExpiryAwaitingRedemption.
    const source = SOURCE;
    const parkFn = source.slice(
      source.indexOf("export async function parkPastExpiryAwaitingRedemption"),
      source.indexOf("export async function continueExternalWait"),
    );
    expect(parkFn).not.toMatch(/APPEND_NEEDS_ATTENTION_EVENT/);
    expect(parkFn).toMatch(/CAS_AWAITING_TO_NEEDS_ATTENTION/);
  });

  it("CAS_CONTINUE_EXTERNAL_WAIT returns AWAITING_REDEMPTION and clears attention", () => {
    const sql = SEND_EXPIRY_ATTENTION_SQL.CAS_CONTINUE_EXTERNAL_WAIT;
    expect(sql).toMatch(/status = 'AWAITING_REDEMPTION'/);
    expect(sql).toMatch(/attention_required = false/);
    expect(sql).toMatch(/attention_reason = NULL/);
    expect(sql).toMatch(/status = 'NEEDS_ATTENTION'/);
    expect(sql).not.toMatch(/wallet_active_leases/);
  });

  it("source never calls the signer or inserts a second partial / sign intent", () => {
    expect(SOURCE).not.toMatch(/signStep1|invokeSigner|createSignIntent|insertSignIntent|insertPartial\(/);
    expect(SOURCE).not.toMatch(/INSERT\s+INTO\s+external_send_partials/i);
    expect(SOURCE).not.toMatch(/INSERT\s+INTO\s+external_send_sign_intents/i);
  });

  it("allowed SQL never DELETEs or UPDATEs a lease row (SELECT presence only)", () => {
    for (const sql of SEND_EXPIRY_ATTENTION_ALLOWED_SQL) {
      expect(sql.toUpperCase()).not.toContain("DELETE");
      // Lease table may appear in SELECT/EXISTS presence checks only.
      if (/wallet_active_leases/i.test(sql)) {
        expect(sql.toUpperCase()).toMatch(/SELECT|EXISTS/);
        expect(sql.toUpperCase()).not.toMatch(/UPDATE\s+wallet_active_leases/);
        expect(sql.toUpperCase()).not.toMatch(/DELETE\s+FROM/);
      }
    }
  });

  it("FORBIDDEN_* tokens document closed edges and are absent from allowed SQL", () => {
    expect(SEND_EXPIRY_ATTENTION_SQL.FORBIDDEN_AWAITING_TO_EXPIRED_STATUS).toBe("EXPIRED");
    expect(SEND_EXPIRY_ATTENTION_SQL.FORBIDDEN_AWAITING_TO_REJECTED_STATUS).toBe("REJECTED");
    expect(SEND_EXPIRY_ATTENTION_SQL.FORBIDDEN_LEASE_VERB).toBe("DELETE");
    expect(SEND_EXPIRY_ATTENTION_SQL.FORBIDDEN_LEASE_TABLE).toBe("wallet_active_leases");
    for (const sql of SEND_EXPIRY_ATTENTION_ALLOWED_SQL) {
      expect(sql).not.toMatch(/EXPIRED/);
      expect(sql).not.toMatch(/status\s*=\s*'REJECTED'/);
      expect(sql).not.toMatch(/DELETE/i);
    }
  });

  it("formation_state is never rewritten on the park CAS (stays PARTIAL_*)", () => {
    expect(SEND_EXPIRY_ATTENTION_SQL.CAS_AWAITING_TO_NEEDS_ATTENTION).not.toMatch(
      /formation_state\s*=/,
    );
  });
});

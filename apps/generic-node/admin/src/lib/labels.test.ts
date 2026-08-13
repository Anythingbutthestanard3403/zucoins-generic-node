import { describe, expect, it } from "vitest";
import {
  APPROVE_SUCCESS_NOTE,
  credentialPrefixKind,
  implementerDisplayName,
  isNoEligibleWallet,
  OPERATION_KIND_LABELS,
  operationKindDisplay,
  operationKindLabel,
  operationKindWire,
  parseAttentionDetail,
  predicateLabel,
  severityLabel,
  severityShort,
  statusLabel,
} from "./labels.js";

describe("operation kind labels", () => {
  it("maps the three protocol ops to plain language", () => {
    expect(OPERATION_KIND_LABELS.RECEIVE_EXTERNAL).toBe("Incoming");
    expect(OPERATION_KIND_LABELS.MOVE_INTERNAL).toBe("Internal transfer");
    expect(OPERATION_KIND_LABELS.SEND_EXTERNAL).toBe("Outgoing (needs approval)");
    expect(operationKindLabel("RECEIVE_EXTERNAL")).toBe("Incoming");
    expect(operationKindLabel("MOVE_INTERNAL")).toBe("Internal transfer");
    expect(operationKindLabel("SEND_EXTERNAL")).toBe("Outgoing (needs approval)");
  });

  it("keeps wire enums unchanged for secondary/support text", () => {
    expect(operationKindWire("RECEIVE_EXTERNAL")).toBe("RECEIVE_EXTERNAL");
    expect(operationKindWire("move_internal")).toBe("MOVE_INTERNAL");
  });

  it("does not invent a fourth money verb", () => {
    const retiredRefund = "RE" + "FUND"; // contract-allow:refund:negative-fourth-verb-citation
    const retiredCheckout = "CHECK" + "OUT"; // contract-allow:checkout:negative-fourth-verb-citation
    expect(operationKindLabel(retiredRefund)).toBe(retiredRefund);
    expect(operationKindDisplay(retiredCheckout)).toBe(retiredCheckout);
  });
});

describe("status labels", () => {
  it("maps formation and send statuses to operator text", () => {
    expect(statusLabel("NO_ELIGIBLE_WALLET")).toBe(
      "Wallets not recovery-verified — continue setup",
    );
    expect(statusLabel("AWAITING_REDEMPTION")).toBe("Waiting for recipient to finish");
    expect(statusLabel("APPROVED")).toMatch(/recipient must finish/i);
  });

  it("detects NO_ELIGIBLE_WALLET class in composite reasons", () => {
    expect(isNoEligibleWallet("NO_ELIGIBLE_WALLET")).toBe(true);
    expect(isNoEligibleWallet("formation:NO_ELIGIBLE_WALLET")).toBe(true);
    expect(isNoEligibleWallet("CREATED")).toBe(false);
  });

  it("never claims approval alone is settlement or paid", () => {
    expect(APPROVE_SUCCESS_NOTE.toLowerCase()).not.toMatch(/\bpaid\b/);
    expect(APPROVE_SUCCESS_NOTE).toMatch(/recipient must finish/i);
    expect(APPROVE_SUCCESS_NOTE.toLowerCase()).toMatch(/not settlement|observe-land/);
  });
});

describe("credential prefix labels", () => {
  it("labels ik_/sh_ families without echoing full secrets", () => {
    expect(credentialPrefixKind("ik_abcdef12")).toBe("Server API key");
    expect(credentialPrefixKind("sh_xyz")).toBe("Status subscription secret");
  });
});

describe("severity and implementer display", () => {
  it("severity labels carry meaning", () => {
    expect(severityLabel("P0")).toMatch(/act now/i);
    expect(severityShort("P1")).toMatch(/shift/i);
  });

  it("implementerDisplayName prefers name with id fallback", () => {
    expect(
      implementerDisplayName("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", [
        { id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", name: "rewards-bot" },
      ]),
    ).toBe("rewards-bot");
    expect(implementerDisplayName("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", [])).toMatch(
      /^bbbbbbbb/,
    );
  });

  it("EXPIRED and formation states are labelled", () => {
    expect(statusLabel("EXPIRED")).toBe("Expired");
    expect(statusLabel("APPROVAL_PENDING")).toMatch(/Approval pending/i);
    expect(statusLabel("UNEXPECTED_HEAD_CHANGE")).toMatch(/Unexpected head/i);
  });
});

describe("parseAttentionDetail (ZTR-1279)", () => {
  it("renders per-predicate causes and fresh-read summary from structured JSON", () => {
    const detail = JSON.stringify({
      failed_predicates: ["FRESH_VERIFIED_T0_EXACT"],
      predicate_causes: [
        {
          predicate: "FRESH_VERIFIED_T0_EXACT",
          cause:
            "fresh verified head does not match T0 exactly; post-expiry confirm-read was skipped: wallet_row_undefined",
        },
      ],
      fresh_read: {
        kind: "skipped",
        reason: "wallet_row_undefined",
        summary: "skipped:wallet_row_undefined",
      },
    });
    const parsed = parseAttentionDetail(detail);
    expect(parsed?.failedPredicates).toEqual(["FRESH_VERIFIED_T0_EXACT"]);
    expect(parsed?.predicateCauses[0]?.cause).toMatch(/wallet_row_undefined/);
    expect(parsed?.freshReadSummary).toBe("skipped:wallet_row_undefined");
    expect(predicateLabel("FRESH_VERIFIED_T0_EXACT")).toMatch(/Fresh head matches T0/i);
  });

  it("falls back to raw text for free-form attention notes", () => {
    const parsed = parseAttentionDetail("operator note: holding for review");
    expect(parsed?.rawText).toBe("operator note: holding for review");
    expect(parsed?.failedPredicates).toEqual([]);
  });
});

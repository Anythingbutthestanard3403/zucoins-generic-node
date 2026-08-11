import { describe, expect, it } from "vitest";
import {
  APPROVE_SUCCESS_NOTE,
  credentialPrefixKind,
  isNoEligibleWallet,
  OPERATION_KIND_LABELS,
  operationKindDisplay,
  operationKindLabel,
  operationKindWire,
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

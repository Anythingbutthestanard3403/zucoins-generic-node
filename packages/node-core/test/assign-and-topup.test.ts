// Unit tests for external-send assign + multi-hub top-up pure helpers (ZTR-1270).
import { describe, expect, it } from "vitest";

import {
  decideWorkerFunding,
  evaluateTopUpReadiness,
  isTopUpHubEligible,
  SELECT_SEND_WORKER_SQL,
  SELECT_TOPUP_HUB_SQL,
  SELECT_SEND_TOPUP_READY_SQL,
  SEND_ASSIGN_SQL,
} from "../src/assign-and-topup.js";
import { WALLET_MONEY_MODE_FLAGS } from "@zucoins/generic-node-contracts/wallet-state";

describe("decideWorkerFunding", () => {
  it("funded path when observed balance ≥ amount", () => {
    expect(decideWorkerFunding("2", "5")).toEqual({
      kind: "funded",
      balanceZkz: "5",
    });
    expect(decideWorkerFunding("2", "2")).toEqual({
      kind: "funded",
      balanceZkz: "2",
    });
  });

  it("exact shortfall when underfunded (not full N)", () => {
    expect(decideWorkerFunding("5", "2")).toEqual({
      kind: "needs_topup",
      balanceZkz: "2",
      shortfallZkz: "3",
    });
  });

  it("null observation treats balance as 0 (full-N shortfall)", () => {
    expect(decideWorkerFunding("2", null)).toEqual({
      kind: "needs_topup",
      balanceZkz: "0",
      shortfallZkz: "2",
    });
  });
});

describe("isTopUpHubEligible", () => {
  it("only INTERNAL_ONLY hubs", () => {
    expect(isTopUpHubEligible(WALLET_MONEY_MODE_FLAGS.INTERNAL_ONLY)).toBe(true);
    expect(isTopUpHubEligible(WALLET_MONEY_MODE_FLAGS.SEND_ONLY)).toBe(false);
    expect(isTopUpHubEligible(WALLET_MONEY_MODE_FLAGS.RECEIVE_ONLY)).toBe(false);
    expect(isTopUpHubEligible(WALLET_MONEY_MODE_FLAGS.FULL)).toBe(false);
  });
});

describe("evaluateTopUpReadiness", () => {
  it("ready without reference (funded path)", () => {
    expect(
      evaluateTopUpReadiness({ referencesOperationId: null, referenced: null }),
    ).toEqual({ ready: true, reason: "no_reference" });
  });

  it("ready when move INTERNAL_MOVE_LANDED", () => {
    expect(
      evaluateTopUpReadiness({
        referencesOperationId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        referenced: { kind: "MOVE_INTERNAL", status: "INTERNAL_MOVE_LANDED" },
      }),
    ).toEqual({ ready: true, reason: "move_landed" });
  });

  it("parks on pending / attention / missing", () => {
    expect(
      evaluateTopUpReadiness({
        referencesOperationId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        referenced: { kind: "MOVE_INTERNAL", status: "CREATED" },
      }),
    ).toMatchObject({ ready: false, reason: "move_pending" });

    expect(
      evaluateTopUpReadiness({
        referencesOperationId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        referenced: { kind: "MOVE_INTERNAL", status: "NEEDS_ATTENTION" },
      }),
    ).toMatchObject({ ready: false, reason: "move_attention" });

    expect(
      evaluateTopUpReadiness({
        referencesOperationId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        referenced: null,
      }),
    ).toMatchObject({ ready: false, reason: "move_missing" });
  });
});

describe("frozen selection SQL", () => {
  it("worker select pins capability, SKIP LOCKED, funded-first preference", () => {
    expect(SELECT_SEND_WORKER_SQL).toContain("allow_external_send IS TRUE");
    expect(SELECT_SEND_WORKER_SQL).toContain("FOR UPDATE OF w SKIP LOCKED");
    expect(SELECT_SEND_WORKER_SQL).toContain("gateway_observations");
    expect(SELECT_SEND_WORKER_SQL).not.toContain("INTERNAL_ONLY");
    // Funded tier before underfunded
    expect(SELECT_SEND_WORKER_SQL).toMatch(/CASE[\s\S]*THEN 0[\s\S]*ELSE 1/);
  });

  it("hub select pins INTERNAL_ONLY and never allow_external_send", () => {
    expect(SELECT_TOPUP_HUB_SQL).toContain("money_mode = 'INTERNAL_ONLY'");
    expect(SELECT_TOPUP_HUB_SQL).toContain("allow_external_send IS FALSE");
    expect(SELECT_TOPUP_HUB_SQL).toContain("FOR UPDATE OF w SKIP LOCKED");
    expect(SELECT_TOPUP_HUB_SQL).toContain("ORDER BY w.id ASC");
  });

  it("top-up ready probe requires INTERNAL_MOVE_LANDED", () => {
    expect(SELECT_SEND_TOPUP_READY_SQL).toContain("INTERNAL_MOVE_LANDED");
    expect(SELECT_SEND_TOPUP_READY_SQL).toContain("references_operation_id");
  });

  it("SEND_ASSIGN_SQL catalogue is complete", () => {
    expect(Object.keys(SEND_ASSIGN_SQL).sort()).toEqual(
      [
        "SELECT_BLESSED_DESTINATION_FOR_WALLET",
        "SELECT_SEND_BY_TOPUP_MOVE",
        "SELECT_SEND_TOPUP_READY",
        "SELECT_SEND_WORKER",
        "SELECT_TOPUP_HUB",
      ].sort(),
    );
  });
});

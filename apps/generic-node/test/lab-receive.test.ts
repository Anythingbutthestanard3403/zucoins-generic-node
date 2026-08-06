import { describe, expect, it, vi } from "vitest";

import {
  assertLabReceiveAmount,
  assertLabPayloadSecretFree,
  checklistLinksFromRows,
  LAB_RECEIVE_MAX_ZKZ,
  receiveBlockingRows,
  runLabReceive,
  type LabReceivePorts,
} from "../src/lab-receive.js";
import { buildReadinessChecklist } from "../src/admin-readiness.js";

describe("assertLabReceiveAmount", () => {
  it("accepts amounts at and below 0.01 ZKZ", () => {
    expect(assertLabReceiveAmount("0.01").ok).toBe(true);
    expect(assertLabReceiveAmount("0.001").ok).toBe(true);
    // trailing zeros are non-canonical PositiveZkz — rejected as invalid, not cap
    expect(assertLabReceiveAmount("0.0100").ok).toBe(false);
  });

  it("rejects above cap server-side", () => {
    const r = assertLabReceiveAmount("0.0100001");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("lab_amount_exceeds_cap");
  });

  it("rejects invalid amounts", () => {
    const r = assertLabReceiveAmount("not-a-number");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe("lab_amount_invalid");
  });

  it("exports the external-amount cap constant", () => {
    expect(LAB_RECEIVE_MAX_ZKZ).toBe("0.01");
  });
});

describe("receiveBlockingRows / checklist links", () => {
  it("surfaces recovery + reporting blockers with deep links", () => {
    const checklist = buildReadinessChecklist({
      nodeStatus: "ready",
      totpEnrolled: true,
      deviceEnrolled: true,
      recoveryVerifiedEligibleCount: 0,
      reportingKeyActive: false,
      implementerKeyPresent: true,
      backup: null,
    });
    const blocked = receiveBlockingRows(checklist);
    expect(blocked.map((r) => r.id)).toEqual(
      expect.arrayContaining(["recovery_verified_wallet", "reporting_key_active"]),
    );
    const links = checklistLinksFromRows(blocked);
    expect(links.some((l) => l.href === "/recovery-ceremony")).toBe(true);
    expect(links.some((l) => l.href === "/reporting-keys")).toBe(true);
  });

  it("allows when receive gates green", () => {
    const checklist = buildReadinessChecklist({
      nodeStatus: "ready",
      totpEnrolled: true,
      deviceEnrolled: true,
      recoveryVerifiedEligibleCount: 1,
      reportingKeyActive: true,
      implementerKeyPresent: true,
      backup: {
        enabled: true,
        rpoBreached: false,
        lastSuccessAt: new Date().toISOString(),
        consecutiveFailures: 0,
      },
    });
    expect(receiveBlockingRows(checklist)).toHaveLength(0);
  });
});

describe("assertLabPayloadSecretFree", () => {
  it("accepts the lab success shape", () => {
    expect(() =>
      assertLabPayloadSecretFree({
        object: "lab_receive",
        lab: true,
        transfer_code: "abc",
        amount_zkz: "0.01",
      }),
    ).not.toThrow();
  });

  it("rejects ik_ material", () => {
    expect(() =>
      assertLabPayloadSecretFree({ leak: "ik_abcdefghijklmnopqrst" }),
    ).toThrow(/ik_/);
  });
});

describe("runLabReceive gate enforcement", () => {
  it("refuses when checklist blocks RECEIVE without calling create", async () => {
    const createReceive = vi.fn();
    const ports: LabReceivePorts = {
      nodeId: "00000000-0000-4000-8000-000000000001",
      resolveImplementerId: async () => "00000000-0000-4000-8000-000000000002",
      operationStore: { createReceive, getReceive: vi.fn() } as never,
      reportingHandle: vi.fn(),
      collectSignals: async () => ({
        nodeStatus: "ready",
        totpEnrolled: true,
        recoveryVerifiedEligibleCount: 0,
        reportingKeyActive: true,
        implementerKeyPresent: true,
      }),
      nowMs: () => Date.now(),
    };
    const result = await runLabReceive(ports, {
      amount_zkz: "0.01",
      reporting_key_id: "00000000-0000-4000-8000-000000000003",
      reporting_private_seed_hex: "aa".repeat(32),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe("lab_gates_blocked");
      expect(result.checklist_links?.some((l) => l.href.includes("recovery"))).toBe(true);
    }
    expect(createReceive).not.toHaveBeenCalled();
  });

  it("refuses over-cap before gates", async () => {
    const createReceive = vi.fn();
    const ports: LabReceivePorts = {
      nodeId: "00000000-0000-4000-8000-000000000001",
      resolveImplementerId: async () => null,
      operationStore: { createReceive, getReceive: vi.fn() } as never,
      reportingHandle: vi.fn(),
      collectSignals: async () => ({}),
      nowMs: () => Date.now(),
    };
    const result = await runLabReceive(ports, {
      amount_zkz: "1",
      reporting_key_id: "00000000-0000-4000-8000-000000000003",
      reporting_private_seed_hex: "bb".repeat(32),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("lab_amount_exceeds_cap");
    expect(createReceive).not.toHaveBeenCalled();
  });
});

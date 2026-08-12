import { describe, expect, it } from "vitest";
import {
  isOperationTerminal,
  isTerminalStatus,
  operationLifecycleBucket,
  TERMINAL_OPERATION_STATUSES,
} from "./money.js";

/** Every Layer-1 state from the operations states contract. */
const CONTRACT_STATES: readonly { kind: string; status: string }[] = [
  ...["CREATED", "READY", "RECEIVE_LANDED", "EXPIRED"].map((status) => ({
    kind: "RECEIVE_EXTERNAL",
    status,
  })),
  ...["CREATED", "INTERNAL_MOVE_LANDED", "NEEDS_ATTENTION"].map((status) => ({
    kind: "MOVE_INTERNAL",
    status,
  })),
  ...[
    "CREATED",
    "APPROVED",
    "AWAITING_REDEMPTION",
    "EXTERNAL_SEND_LANDED",
    "REJECTED",
    "NEEDS_ATTENTION",
  ].map((status) => ({ kind: "SEND_EXTERNAL", status })),
];

describe("operationLifecycleBucket (ZTR-1254)", () => {
  it("covers every contract state without throwing", () => {
    for (const row of CONTRACT_STATES) {
      const bucket = operationLifecycleBucket({
        status: row.status,
        operation_type: row.kind,
        terminal_at: null,
      });
      expect(["in_flight", "landed", "expired", "rejected"]).toContain(bucket);
    }
  });

  it("EXPIRED with null terminal_at is expired, never in_flight", () => {
    expect(
      operationLifecycleBucket({
        status: "EXPIRED",
        operation_type: "RECEIVE_EXTERNAL",
        terminal_at: null,
      }),
    ).toBe("expired");
    expect(
      isOperationTerminal({
        status: "EXPIRED",
        terminal_at: null,
      }),
    ).toBe(true);
  });

  it("REJECTED is rejected terminal", () => {
    expect(
      operationLifecycleBucket({ status: "REJECTED", terminal_at: null }),
    ).toBe("rejected");
  });

  it("landed statuses are landed regardless of terminal_at", () => {
    for (const status of [
      "RECEIVE_LANDED",
      "INTERNAL_MOVE_LANDED",
      "EXTERNAL_SEND_LANDED",
    ] as const) {
      expect(operationLifecycleBucket({ status, terminal_at: null })).toBe("landed");
      expect(operationLifecycleBucket({ status, terminal_at: "2026-01-01T00:00:00Z" })).toBe(
        "landed",
      );
    }
  });

  it("open statuses stay in_flight even if terminal_at is wrongly set", () => {
    for (const status of ["CREATED", "READY", "APPROVED", "AWAITING_REDEMPTION", "NEEDS_ATTENTION"]) {
      // Status wins: open states are in_flight; terminal_at alone must not settle them.
      expect(
        operationLifecycleBucket({
          status,
          terminal_at: "2026-01-01T00:00:00Z",
        }),
      ).toBe("in_flight");
    }
  });

  it("isTerminalStatus matches TERMINAL_OPERATION_STATUSES set", () => {
    for (const s of TERMINAL_OPERATION_STATUSES) {
      expect(isTerminalStatus("RECEIVE_EXTERNAL", s)).toBe(true);
    }
    expect(isTerminalStatus("SEND_EXTERNAL", "APPROVED")).toBe(false);
    expect(isTerminalStatus(null, null)).toBe(false);
  });
});

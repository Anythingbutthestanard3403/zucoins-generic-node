import { describe, expect, it, vi } from "vitest";

import {
  executeOperatorPark,
  OPERATOR_PARK_ATTENTION_REASON,
  type OperatorParkStore,
} from "./operator-park.js";
import { toAttentionReason } from "../protocol/reconcile/types.js";

describe("operator-park (ZTR-1147)", () => {
  it("OPERATOR_PARK_ATTENTION_REASON is the frozen vocabulary value via toAttentionReason", () => {
    expect(OPERATOR_PARK_ATTENTION_REASON).toBe("OPERATOR_PARKED");
    expect(toAttentionReason({ source: "OPERATOR_PARKED" })).toBe("OPERATOR_PARKED");
  });

  it("refuses empty note and missing csrf", async () => {
    const store: OperatorParkStore = {
      commitPark: vi.fn(),
    };
    await expect(
      executeOperatorPark(store, {
        operationId: "op",
        expectedRowVersion: 1,
        note: "   ",
        actorId: "actor",
        csrfValidated: true,
      }),
    ).resolves.toEqual({ status: "rejected", reason: "note_required" });
    expect(store.commitPark).not.toHaveBeenCalled();
  });

  it("commits OPERATOR_PARKED through the store", async () => {
    const store: OperatorParkStore = {
      commitPark: vi.fn(async (input) => ({
        kind: "committed" as const,
        committed: {
          operationId: input.operationId,
          attentionReason: input.attentionReason,
          rowVersion: input.expectedRowVersion + 1,
          parkedAt: "2026-08-11T00:00:00.000Z",
        },
      })),
    };
    const outcome = await executeOperatorPark(store, {
      operationId: "op-1",
      expectedRowVersion: 3,
      note: "investigating gateway lag",
      actorId: "op-user",
      csrfValidated: true,
    });
    expect(outcome).toEqual({
      status: "ok",
      body: {
        operationId: "op-1",
        attentionReason: "OPERATOR_PARKED",
        rowVersion: 4,
        parkedAt: "2026-08-11T00:00:00.000Z",
      },
    });
    expect(store.commitPark).toHaveBeenCalledWith(
      expect.objectContaining({
        attentionReason: "OPERATOR_PARKED",
        note: "investigating gateway lag",
      }),
    );
  });
});

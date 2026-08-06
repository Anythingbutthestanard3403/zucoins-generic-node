import { describe, expect, it } from "vitest";

import {
  executeAttentionRetraction,
  type AttentionRetractionCommitResult,
  type AttentionRetractionRequest,
  type AttentionRetractionStore,
} from "./index.js";

const BASE_REQUEST: AttentionRetractionRequest = {
  operationId: "e9570a2e-6f76-4221-897e-2d1efd2937f4",
  reason: "classifier fixed; this row never needed attention",
  supersededBy: "attention-classifier-fix",
  expectedRowVersion: 3,
  actorId: "operator-1",
  csrfValidated: true,
};

class FakeStore implements AttentionRetractionStore {
  calls: Parameters<AttentionRetractionStore["commit"]>[0][] = [];
  constructor(private readonly result: AttentionRetractionCommitResult) {}

  async commit(
    input: Parameters<AttentionRetractionStore["commit"]>[0],
  ): Promise<AttentionRetractionCommitResult> {
    this.calls.push(input);
    return this.result;
  }
}

describe("executeAttentionRetraction", () => {
  it("rejects before touching the store when CSRF was not validated", async () => {
    const store = new FakeStore({ ok: false, reason: "conflict" });
    const outcome = await executeAttentionRetraction(store, {
      ...BASE_REQUEST,
      csrfValidated: false as unknown as true,
    });
    expect(outcome).toEqual({ status: "rejected", reason: "csrf_required" });
    expect(store.calls).toHaveLength(0);
  });

  it("commits and returns the prior attention_reason for provenance", async () => {
    const store = new FakeStore({
      ok: true,
      rowVersion: 4,
      retractedAt: "2026-08-01T00:00:00.000Z",
      priorAttentionReason: "signer_audit_without_exact_preimage",
    });
    const outcome = await executeAttentionRetraction(store, BASE_REQUEST);
    expect(outcome).toEqual({
      status: "ok",
      body: {
        operation_id: BASE_REQUEST.operationId,
        row_version: 4,
        retracted_at: "2026-08-01T00:00:00.000Z",
        prior_attention_reason: "signer_audit_without_exact_preimage",
      },
    });
    expect(store.calls).toEqual([
      {
        operationId: BASE_REQUEST.operationId,
        reason: BASE_REQUEST.reason,
        supersededBy: BASE_REQUEST.supersededBy,
        expectedRowVersion: BASE_REQUEST.expectedRowVersion,
        actorId: BASE_REQUEST.actorId,
      },
    ]);
  });

  it("propagates a row_version conflict as a rejected outcome, never silently overwriting", async () => {
    const store = new FakeStore({ ok: false, reason: "conflict" });
    const outcome = await executeAttentionRetraction(store, BASE_REQUEST);
    expect(outcome).toEqual({ status: "rejected", reason: "conflict" });
  });

  it("rejects a row that was never flagged, so retraction cannot fabricate provenance", async () => {
    const store = new FakeStore({ ok: false, reason: "not_flagged" });
    const outcome = await executeAttentionRetraction(store, BASE_REQUEST);
    expect(outcome).toEqual({ status: "rejected", reason: "not_flagged" });
  });

  it("rejects an unknown operation id", async () => {
    const store = new FakeStore({ ok: false, reason: "operation_not_found" });
    const outcome = await executeAttentionRetraction(store, BASE_REQUEST);
    expect(outcome).toEqual({ status: "rejected", reason: "operation_not_found" });
  });
});

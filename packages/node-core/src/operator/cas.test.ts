import { describe, expect, it } from "vitest";

import {
  CasConflictError,
  applyCasTransition,
  createInMemoryOperationStateStore,
  type CasTransitionRequest,
} from "./index.js";

describe("CAS state transition service", () => {
  it("applies a transition when status and version match", async () => {
    const store = createInMemoryOperationStateStore();
    store.seed({ operationId: "op-1", status: "CREATED", rowVersion: 1 });
    const result = await store.compareAndSwap("op-1", "CREATED", 1, "READY");
    expect(result).toEqual({ ok: true, operationId: "op-1", newStatus: "READY", newRowVersion: 2 });
  });

  it("rejects when row version does not match", async () => {
    const store = createInMemoryOperationStateStore();
    store.seed({ operationId: "op-1", status: "CREATED", rowVersion: 3 });
    const result = await store.compareAndSwap("op-1", "CREATED", 1, "READY");
    expect(result).toEqual({ ok: false, operationId: "op-1", actualStatus: "CREATED", actualRowVersion: 3 });
  });

  it("rejects when status does not match", async () => {
    const store = createInMemoryOperationStateStore();
    store.seed({ operationId: "op-1", status: "READY", rowVersion: 2 });
    const result = await store.compareAndSwap("op-1", "CREATED", 2, "SUBMITTED");
    expect(result).toEqual({ ok: false, operationId: "op-1", actualStatus: "READY", actualRowVersion: 2 });
  });

  it("rejects when operation does not exist", async () => {
    const store = createInMemoryOperationStateStore();
    const result = await store.compareAndSwap("missing", "CREATED", 1, "READY");
    expect(result.ok).toBe(false);
  });

  it("increments row version monotonically on successive transitions", async () => {
    const store = createInMemoryOperationStateStore();
    store.seed({ operationId: "op-1", status: "CREATED", rowVersion: 1 });
    const r1 = await store.compareAndSwap("op-1", "CREATED", 1, "READY");
    expect(r1.ok).toBe(true);
    if (!r1.ok) return;
    expect(r1.newRowVersion).toBe(2);
    const r2 = await store.compareAndSwap("op-1", "READY", 2, "SUBMITTED");
    expect(r2.ok).toBe(true);
    if (!r2.ok) return;
    expect(r2.newRowVersion).toBe(3);
    const record = await store.read("op-1");
    expect(record).toEqual({ operationId: "op-1", status: "SUBMITTED", rowVersion: 3 });
  });

  it("prevents lost updates under concurrent conflicting transitions", async () => {
    const store = createInMemoryOperationStateStore();
    store.seed({ operationId: "op-1", status: "CREATED", rowVersion: 1 });
    const [r1, r2] = await Promise.all([
      store.compareAndSwap("op-1", "CREATED", 1, "READY"),
      store.compareAndSwap("op-1", "CREATED", 1, "EXPIRED"),
    ]);
    const successes = [r1, r2].filter((r) => r.ok);
    const conflicts = [r1, r2].filter((r) => !r.ok);
    expect(successes).toHaveLength(1);
    expect(conflicts).toHaveLength(1);
  });

  it("read returns null for missing operations", async () => {
    const store = createInMemoryOperationStateStore();
    expect(await store.read("nonexistent")).toBeNull();
  });
});

describe("applyCasTransition", () => {
  it("returns success on valid transition", async () => {
    const store = createInMemoryOperationStateStore();
    store.seed({ operationId: "op-1", status: "CREATED", rowVersion: 1 });
    const request: CasTransitionRequest = {
      operationId: "op-1", expectedStatus: "CREATED", expectedRowVersion: 1, newStatus: "READY",
    };
    const result = await applyCasTransition(store, request);
    expect(result.ok).toBe(true);
    expect(result.newStatus).toBe("READY");
    expect(result.newRowVersion).toBe(2);
  });

  it("throws CasConflictError on version mismatch", async () => {
    const store = createInMemoryOperationStateStore();
    store.seed({ operationId: "op-1", status: "CREATED", rowVersion: 5 });
    const request: CasTransitionRequest = {
      operationId: "op-1", expectedStatus: "CREATED", expectedRowVersion: 1, newStatus: "READY",
    };
    await expect(applyCasTransition(store, request)).rejects.toThrow(CasConflictError);
  });

  it("CasConflictError carries actual state", async () => {
    const store = createInMemoryOperationStateStore();
    store.seed({ operationId: "op-1", status: "SUBMITTED", rowVersion: 7 });
    const request: CasTransitionRequest = {
      operationId: "op-1", expectedStatus: "CREATED", expectedRowVersion: 3, newStatus: "READY",
    };
    try {
      await applyCasTransition(store, request);
      expect.unreachable("should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(CasConflictError);
      const casError = error as CasConflictError;
      expect(casError.operationId).toBe("op-1");
      expect(casError.actualStatus).toBe("SUBMITTED");
      expect(casError.actualRowVersion).toBe(7);
    }
  });
});

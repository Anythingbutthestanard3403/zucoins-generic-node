import { describe, expect, it } from "vitest";

import {
  createIdempotencyService,
  createInMemoryIdempotencyStore,
  type IdempotencyKey,
} from "./index.js";

const KEY: IdempotencyKey = {
  implementerId: "impl-1",
  method: "POST",
  route: "/v1/operations",
  idempotencyKey: "idem-abc-123",
};

const RESPONSE_BYTES = new TextEncoder().encode('{"id":"op-1"}');

describe("idempotency service", () => {
  it("executes handler on first request and stores result", async () => {
    const store = createInMemoryIdempotencyStore();
    const service = createIdempotencyService(store, { ttlMs: 60_000 }, () => 1000);
    let handlerCalls = 0;
    const outcome = await service.execute(KEY, async () => {
      handlerCalls += 1;
      return { statusCode: 201, responseBytes: RESPONSE_BYTES, childRecordId: "child-1" };
    });
    expect(outcome.type).toBe("executed");
    expect(handlerCalls).toBe(1);
    if (outcome.type === "executed") {
      expect(outcome.record.statusCode).toBe(201);
      expect(outcome.record.responseBytes).toEqual(RESPONSE_BYTES);
      expect(outcome.record.childRecordId).toBe("child-1");
      expect(outcome.record.createdAt).toBe(1000);
      expect(outcome.record.expiresAt).toBe(61_000);
    }
  });

  it("replays stored result on duplicate request without re-executing", async () => {
    const store = createInMemoryIdempotencyStore();
    const service = createIdempotencyService(store, { ttlMs: 60_000 }, () => 1000);
    let handlerCalls = 0;
    const handler = async () => {
      handlerCalls += 1;
      return { statusCode: 201, responseBytes: RESPONSE_BYTES };
    };
    await service.execute(KEY, handler);
    const replay = await service.execute(KEY, handler);
    expect(handlerCalls).toBe(1);
    expect(replay.type).toBe("replayed");
    if (replay.type === "replayed") {
      expect(replay.record.statusCode).toBe(201);
      expect(replay.record.responseBytes).toEqual(RESPONSE_BYTES);
    }
  });

  it("scopes idempotency by composite key", async () => {
    const store = createInMemoryIdempotencyStore();
    const service = createIdempotencyService(store, { ttlMs: 60_000 }, () => 1000);
    let calls = 0;
    const handler = async () => {
      calls += 1;
      return { statusCode: 200, responseBytes: RESPONSE_BYTES };
    };
    await service.execute(KEY, handler);
    expect((await service.execute({ ...KEY, idempotencyKey: "different-key" }, handler)).type).toBe("executed");
    expect(calls).toBe(2);
    expect((await service.execute({ ...KEY, method: "PUT" }, handler)).type).toBe("executed");
    expect(calls).toBe(3);
    expect((await service.execute({ ...KEY, route: "/v1/other" }, handler)).type).toBe("executed");
    expect(calls).toBe(4);
    expect((await service.execute({ ...KEY, implementerId: "impl-2" }, handler)).type).toBe("executed");
    expect(calls).toBe(5);
  });

  it("allows re-execution after TTL expiry", async () => {
    const store = createInMemoryIdempotencyStore();
    let now = 1000;
    const service = createIdempotencyService(store, { ttlMs: 5000 }, () => now);
    let calls = 0;
    const handler = async () => {
      calls += 1;
      return { statusCode: 200, responseBytes: RESPONSE_BYTES };
    };
    await service.execute(KEY, handler);
    expect(calls).toBe(1);
    now = 5999;
    expect((await service.execute(KEY, handler)).type).toBe("replayed");
    expect(calls).toBe(1);
    now = 6001;
    expect((await service.execute(KEY, handler)).type).toBe("executed");
    expect(calls).toBe(2);
  });

  it("purges expired records", async () => {
    const store = createInMemoryIdempotencyStore();
    let now = 1000;
    const service = createIdempotencyService(store, { ttlMs: 5000 }, () => now);
    await service.execute(KEY, async () => ({ statusCode: 200, responseBytes: RESPONSE_BYTES }));
    const key2: IdempotencyKey = { ...KEY, idempotencyKey: "key-2" };
    now = 3000;
    await service.execute(key2, async () => ({ statusCode: 200, responseBytes: RESPONSE_BYTES }));
    now = 7000;
    const purged = await service.purgeExpired();
    expect(purged).toBe(1);
    expect(store.records.size).toBe(1);
  });

  it("uses default 24h TTL when not configured", async () => {
    const store = createInMemoryIdempotencyStore();
    const service = createIdempotencyService(store, {}, () => 0);
    const outcome = await service.execute(KEY, async () => ({
      statusCode: 200, responseBytes: RESPONSE_BYTES,
    }));
    if (outcome.type === "executed") {
      expect(outcome.record.expiresAt).toBe(24 * 60 * 60 * 1000);
    }
  });

  it("stores null childRecordId when not provided", async () => {
    const store = createInMemoryIdempotencyStore();
    const service = createIdempotencyService(store, { ttlMs: 60_000 }, () => 1000);
    const outcome = await service.execute(KEY, async () => ({
      statusCode: 200, responseBytes: RESPONSE_BYTES,
    }));
    if (outcome.type === "executed") {
      expect(outcome.record.childRecordId).toBeNull();
    }
  });
});

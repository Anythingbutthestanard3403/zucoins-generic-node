// CursorManager unit tests.
import { describe, expect, it } from "vitest";

import { CursorManager, InMemoryEventStore } from "../src/event-log/index.ts";

const NODE_ID = "11111111-1111-4111-8111-111111111111";

function manager(store = new InMemoryEventStore()): CursorManager {
  return new CursorManager(store, { nodeId: NODE_ID });
}

describe("CursorManager", () => {
  it("fresh cursor reads at position 0 version 0", async () => {
    const mgr = manager();
    const state = await mgr.read("reporting");
    expect(state).toMatchObject({
      nodeId: NODE_ID,
      name: "reporting",
      position: 0n,
      version: 0n,
    });
  });

  it("three named cursors advance independently", async () => {
    const store = new InMemoryEventStore();
    const mgr = manager(store);
    await mgr.advance("reporting", 5n);
    await mgr.advance("observation", 2n);
    await mgr.advance("sse", 9n);
    expect((await mgr.read("reporting")).position).toBe(5n);
    expect((await mgr.read("observation")).position).toBe(2n);
    expect((await mgr.read("sse")).position).toBe(9n);
  });

  it("advance is idempotent at the same position", async () => {
    const mgr = manager();
    const first = await mgr.advance("reporting", 3n);
    const second = await mgr.advance("reporting", 3n);
    expect(first.position).toBe(3n);
    expect(second.position).toBe(3n);
    expect(second.version).toBe(first.version);
  });

  it("never rolls back a higher position", async () => {
    const mgr = manager();
    await mgr.advance("reporting", 10n);
    const after = await mgr.advance("reporting", 4n);
    expect(after.position).toBe(10n);
  });

  it("concurrent advances converge to the max position", async () => {
    const store = new InMemoryEventStore();
    const mgr = manager(store);
    await Promise.all([
      mgr.advance("reporting", 3n),
      mgr.advance("reporting", 7n),
      mgr.advance("reporting", 5n),
      mgr.advance("reporting", 7n),
    ]);
    expect((await mgr.read("reporting")).position).toBe(7n);
  });

  it("optimistic version guard returns STALE_VERSION on the store seam", async () => {
    const store = new InMemoryEventStore();
    const first = await store.advanceCursor(NODE_ID, "reporting", 1n, 0n);
    expect(first.kind).toBe("ADVANCED");
    const stale = await store.advanceCursor(NODE_ID, "reporting", 2n, 0n);
    expect(stale).toEqual({ kind: "STALE_VERSION" });
  });
});

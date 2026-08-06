import { describe, expect, it } from "vitest";

import { createRunnerLock } from "./runner-lock.js";

describe("createRunnerLock", () => {
  it("acquires for the first holder and refuses a second concurrent holder", () => {
    const lock = createRunnerLock();
    const first = lock.tryAcquire("runner-A", () => new Date("2026-07-27T01:00:00.000Z"));
    expect(first).not.toBeNull();
    expect(lock.held).toBe(true);
    expect(lock.holderId).toBe("runner-A");
    expect(first?.acquiredAt).toBe("2026-07-27T01:00:00.000Z");

    const second = lock.tryAcquire("runner-B");
    expect(second).toBeNull();
    expect(lock.holderId).toBe("runner-A");
  });

  it("allows a new holder only after release", () => {
    const lock = createRunnerLock();
    const first = lock.tryAcquire("runner-A");
    first?.release();
    expect(lock.held).toBe(false);

    const second = lock.tryAcquire("runner-B");
    expect(second).not.toBeNull();
    expect(lock.holderId).toBe("runner-B");
  });

  it("ignores release from a stale handle after a later re-acquire cycle", () => {
    const lock = createRunnerLock();
    const first = lock.tryAcquire("runner-A");
    first?.release();
    const second = lock.tryAcquire("runner-B");
    // Stale release must not clear the new holder.
    first?.release();
    expect(lock.held).toBe(true);
    expect(lock.holderId).toBe("runner-B");
    second?.release();
    expect(lock.held).toBe(false);
  });

  it("rejects an empty holder id", () => {
    const lock = createRunnerLock();
    expect(() => lock.tryAcquire("")).toThrow(/non-empty/);
  });
});

// Prove lockout unit tests.

import { describe, expect, it } from "vitest";

import {
  clearProveFailures,
  createMemoryRecoveryPackLockoutStore,
  isProveLocked,
  recordProveFailure,
} from "./recovery-pack-lockout.js";
import {
  RECOVERY_PACK_PROVE_FAIL_THRESHOLD,
  RECOVERY_PACK_PROVE_LOCKOUT_MS,
} from "./recovery-pack.js";

const NODE = "11111111-1111-4111-8111-111111111111";
const OP = "op-a";

describe("recovery-pack prove lockout", () => {
  it("locks after 5 failures within window", async () => {
    const store = createMemoryRecoveryPackLockoutStore();
    const t0 = 1_700_000_000_000;
    for (let i = 0; i < RECOVERY_PACK_PROVE_FAIL_THRESHOLD - 1; i++) {
      const r = await recordProveFailure(store, NODE, OP, t0 + i);
      expect(r.locked).toBe(false);
    }
    const lockAt = t0 + RECOVERY_PACK_PROVE_FAIL_THRESHOLD;
    const last = await recordProveFailure(store, NODE, OP, lockAt);
    expect(last.locked).toBe(true);
    expect(last.failCount).toBe(RECOVERY_PACK_PROVE_FAIL_THRESHOLD);

    const snap = await store.load(NODE, OP);
    expect(isProveLocked(snap, lockAt + 1000)).toBe(true);
    // Lock starts at lockAt, so expiry is lockAt + LOCKOUT_MS (not t0 + LOCKOUT_MS).
    expect(isProveLocked(snap, lockAt + RECOVERY_PACK_PROVE_LOCKOUT_MS + 1)).toBe(false);
  });

  it("clears on success", async () => {
    const store = createMemoryRecoveryPackLockoutStore();
    const t0 = 1_700_000_000_000;
    await recordProveFailure(store, NODE, OP, t0);
    await recordProveFailure(store, NODE, OP, t0 + 1);
    await clearProveFailures(store, NODE, OP, t0 + 2);
    const snap = await store.load(NODE, OP);
    expect(snap?.failCount).toBe(0);
    expect(isProveLocked(snap, t0 + 2)).toBe(false);
  });

  it("is per-operator", async () => {
    const store = createMemoryRecoveryPackLockoutStore();
    const t0 = 1_700_000_000_000;
    for (let i = 0; i < RECOVERY_PACK_PROVE_FAIL_THRESHOLD; i++) {
      await recordProveFailure(store, NODE, "op-a", t0 + i);
    }
    expect(isProveLocked(await store.load(NODE, "op-a"), t0 + 10)).toBe(true);
    expect(isProveLocked(await store.load(NODE, "op-b"), t0 + 10)).toBe(false);
  });
});

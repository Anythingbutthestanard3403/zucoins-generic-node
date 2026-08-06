import { describe, expect, it, beforeEach } from "vitest";

import {
  InMemoryClaimStore,
  acquireClaim,
  heartbeatClaim,
  releaseClaim,
} from "./claim.js";
import { DEFAULT_POOL_CONFIG, type WorkerPoolConfig } from "./types.js";

const CONFIG: WorkerPoolConfig = {
  ...DEFAULT_POOL_CONFIG,
  claimTtlMs: 1000,
  heartbeatIntervalMs: 300,
  stealGraceMs: 200,
};

describe("worker claim ownership", () => {
  let store: InMemoryClaimStore;

  beforeEach(() => {
    store = new InMemoryClaimStore();
  });

  it("acquires a claim on an unheld wallet", () => {
    const result = acquireClaim(store, "worker-1", "wallet-A", 1000, CONFIG);
    expect(result.outcome).toBe("ACQUIRED");
    if (result.outcome === "ACQUIRED") {
      expect(result.claim.workerId).toBe("worker-1");
      expect(result.claim.walletId).toBe("wallet-A");
      expect(result.claim.generation).toBe(1);
      expect(result.claim.expiresAt).toBe(2000);
    }
  });

  it("rejects a second worker while claim is active", () => {
    acquireClaim(store, "worker-1", "wallet-A", 1000, CONFIG);
    const result = acquireClaim(store, "worker-2", "wallet-A", 1500, CONFIG);
    expect(result.outcome).toBe("HELD_BY_OTHER");
    if (result.outcome === "HELD_BY_OTHER") {
      expect(result.holder).toBe("worker-1");
    }
  });

  it("two workers racing for the same claim — only one wins", () => {
    const r1 = acquireClaim(store, "worker-1", "wallet-A", 1000, CONFIG);
    const r2 = acquireClaim(store, "worker-2", "wallet-A", 1000, CONFIG);

    const winners = [r1, r2].filter((r) => r.outcome === "ACQUIRED");
    expect(winners).toHaveLength(1);
  });

  it("does not steal before TTL + grace expires", () => {
    acquireClaim(store, "worker-1", "wallet-A", 1000, CONFIG);
    // TTL=1000, grace=200, so steal not allowed until 2200
    const result = acquireClaim(store, "worker-2", "wallet-A", 2100, CONFIG);
    expect(result.outcome).toBe("CAS_CONFLICT");
  });

  it("steals an expired claim after grace period", () => {
    acquireClaim(store, "worker-1", "wallet-A", 1000, CONFIG);
    // TTL=1000, grace=200 → stealable at 2200+
    const result = acquireClaim(store, "worker-2", "wallet-A", 2300, CONFIG);
    expect(result.outcome).toBe("ACQUIRED");
    if (result.outcome === "ACQUIRED") {
      expect(result.claim.workerId).toBe("worker-2");
      expect(result.claim.generation).toBe(2);
    }
  });

  it("heartbeat renews the claim TTL", () => {
    acquireClaim(store, "worker-1", "wallet-A", 1000, CONFIG);
    const hb = heartbeatClaim(store, "wallet-A", "worker-1", 1500, CONFIG);
    expect(hb.outcome).toBe("RENEWED");
    if (hb.outcome === "RENEWED") {
      expect(hb.claim.expiresAt).toBe(2500);
      expect(hb.claim.heartbeatAt).toBe(1500);
    }
  });

  it("heartbeat from non-owner is rejected", () => {
    acquireClaim(store, "worker-1", "wallet-A", 1000, CONFIG);
    const hb = heartbeatClaim(store, "wallet-A", "worker-2", 1500, CONFIG);
    expect(hb.outcome).toBe("NOT_OWNER");
  });

  it("release removes the claim so another worker can acquire", () => {
    acquireClaim(store, "worker-1", "wallet-A", 1000, CONFIG);
    const rel = releaseClaim(store, "wallet-A", "worker-1");
    expect(rel.outcome).toBe("RELEASED");

    const r2 = acquireClaim(store, "worker-2", "wallet-A", 1100, CONFIG);
    expect(r2.outcome).toBe("ACQUIRED");
  });

  it("release by non-owner is rejected", () => {
    acquireClaim(store, "worker-1", "wallet-A", 1000, CONFIG);
    const rel = releaseClaim(store, "wallet-A", "worker-2");
    expect(rel.outcome).toBe("NOT_OWNER");
  });

  it("stale claim recovery increments generation", () => {
    acquireClaim(store, "worker-1", "wallet-A", 1000, CONFIG);
    const stolen = acquireClaim(store, "worker-2", "wallet-A", 2300, CONFIG);
    expect(stolen.outcome).toBe("ACQUIRED");
    if (stolen.outcome === "ACQUIRED") {
      expect(stolen.claim.generation).toBe(2);
    }

    // Third steal after second expires
    const stolen2 = acquireClaim(store, "worker-3", "wallet-A", 4600, CONFIG);
    expect(stolen2.outcome).toBe("ACQUIRED");
    if (stolen2.outcome === "ACQUIRED") {
      expect(stolen2.claim.generation).toBe(3);
    }
  });
});

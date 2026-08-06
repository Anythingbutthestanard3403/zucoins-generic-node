import {
  type WorkerClaim,
  type ClaimAcquireResult,
  type ClaimStealResult,
  type WorkerPoolConfig,
  DEFAULT_POOL_CONFIG,
} from "./types.js";

export interface ClaimStore {
  getActiveClaim(walletId: string): WorkerClaim | null;
  insertClaim(claim: WorkerClaim): boolean;
  compareAndSwapClaim(
    walletId: string,
    expectedGeneration: number,
    newClaim: WorkerClaim,
  ): boolean;
  removeClaim(walletId: string, expectedGeneration: number): boolean;
}

export class InMemoryClaimStore implements ClaimStore {
  private readonly claims = new Map<string, WorkerClaim>();

  getActiveClaim(walletId: string): WorkerClaim | null {
    return this.claims.get(walletId) ?? null;
  }

  insertClaim(claim: WorkerClaim): boolean {
    if (this.claims.has(claim.walletId)) return false;
    this.claims.set(claim.walletId, claim);
    return true;
  }

  compareAndSwapClaim(
    walletId: string,
    expectedGeneration: number,
    newClaim: WorkerClaim,
  ): boolean {
    const existing = this.claims.get(walletId);
    if (!existing) return false;
    if (existing.generation !== expectedGeneration) return false;
    this.claims.set(walletId, newClaim);
    return true;
  }

  removeClaim(walletId: string, expectedGeneration: number): boolean {
    const existing = this.claims.get(walletId);
    if (!existing) return false;
    if (existing.generation !== expectedGeneration) return false;
    this.claims.delete(walletId);
    return true;
  }

  clear(): void {
    this.claims.clear();
  }
}

let claimCounter = 0;

export function mintClaimId(): string {
  return `claim_${++claimCounter}_${Date.now().toString(36)}`;
}

export function acquireClaim(
  store: ClaimStore,
  workerId: string,
  walletId: string,
  now: number,
  config: WorkerPoolConfig = DEFAULT_POOL_CONFIG,
): ClaimAcquireResult {
  const existing = store.getActiveClaim(walletId);

  if (existing !== null) {
    if (existing.expiresAt > now) {
      return { outcome: "HELD_BY_OTHER", holder: existing.workerId, expiresAt: existing.expiresAt };
    }
    // Expired — attempt CAS steal
    const stolen = tryStealExpired(store, existing, workerId, walletId, now, config);
    if (stolen.outcome === "STOLEN") {
      return { outcome: "ACQUIRED", claim: stolen.claim };
    }
    return { outcome: "CAS_CONFLICT" };
  }

  const claim: WorkerClaim = {
    claimId: mintClaimId(),
    workerId,
    walletId,
    acquiredAt: now,
    expiresAt: now + config.claimTtlMs,
    heartbeatAt: now,
    generation: 1,
  };

  const inserted = store.insertClaim(claim);
  if (!inserted) return { outcome: "CAS_CONFLICT" };
  return { outcome: "ACQUIRED", claim };
}

export function tryStealExpired(
  store: ClaimStore,
  expired: WorkerClaim,
  workerId: string,
  walletId: string,
  now: number,
  config: WorkerPoolConfig = DEFAULT_POOL_CONFIG,
): ClaimStealResult {
  if (expired.expiresAt + config.stealGraceMs > now) {
    return { outcome: "NOT_EXPIRED", expiresAt: expired.expiresAt + config.stealGraceMs };
  }

  const newClaim: WorkerClaim = {
    claimId: mintClaimId(),
    workerId,
    walletId,
    acquiredAt: now,
    expiresAt: now + config.claimTtlMs,
    heartbeatAt: now,
    generation: expired.generation + 1,
  };

  const swapped = store.compareAndSwapClaim(walletId, expired.generation, newClaim);
  if (!swapped) return { outcome: "CAS_CONFLICT" };
  return { outcome: "STOLEN", claim: newClaim };
}

export function heartbeatClaim(
  store: ClaimStore,
  walletId: string,
  workerId: string,
  now: number,
  config: WorkerPoolConfig = DEFAULT_POOL_CONFIG,
): { outcome: "RENEWED"; readonly claim: WorkerClaim } | { outcome: "NOT_OWNER" } | { outcome: "EXPIRED" } {
  const existing = store.getActiveClaim(walletId);
  if (!existing) return { outcome: "EXPIRED" };
  if (existing.workerId !== workerId) return { outcome: "NOT_OWNER" };
  if (existing.expiresAt <= now) return { outcome: "EXPIRED" };

  const renewed: WorkerClaim = {
    ...existing,
    heartbeatAt: now,
    expiresAt: now + config.claimTtlMs,
  };

  const swapped = store.compareAndSwapClaim(walletId, existing.generation, renewed);
  if (!swapped) return { outcome: "NOT_OWNER" };
  return { outcome: "RENEWED", claim: renewed };
}

export function releaseClaim(
  store: ClaimStore,
  walletId: string,
  workerId: string,
): { outcome: "RELEASED" } | { outcome: "NOT_OWNER" } {
  const existing = store.getActiveClaim(walletId);
  if (!existing) return { outcome: "NOT_OWNER" };
  if (existing.workerId !== workerId) return { outcome: "NOT_OWNER" };

  const removed = store.removeClaim(walletId, existing.generation);
  if (!removed) return { outcome: "NOT_OWNER" };
  return { outcome: "RELEASED" };
}

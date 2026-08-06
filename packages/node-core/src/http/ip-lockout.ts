// Per-(IP, username) login-failure lockout — the DoS-resistant primary lock
// (admin lockout model).
//
// Relocated into node-core re-verify-and-relocate so
// GN gates no longer import frozen apps/node. Semantics match the documented
// flat 5-failure / 15-min window model: in-memory only, no DB stamp, silent
// lockout (callers answer with the same generic 401).

export const IP_LOCK_THRESHOLD = 5;
export const IP_LOCK_WINDOW_MS = 15 * 60 * 1000;
export const IP_LOCK_DURATION_MS = IP_LOCK_WINDOW_MS;

const PRUNE_THRESHOLD = 10_000;
const ENTRY_TTL_MS = IP_LOCK_WINDOW_MS + IP_LOCK_DURATION_MS + 60 * 60 * 1000;

interface WindowEntry {
  count: number;
  windowStartMs: number;
  lockedUntilMs: number | null;
  lastFailureMs: number;
}

const windows = new Map<string, WindowEntry>();

function windowKey(ip: string | null, username: string): string {
  return `${ip ?? "unknown"}|${username.toLowerCase()}`;
}

function prune(now: number): void {
  if (windows.size < PRUNE_THRESHOLD) return;
  for (const [key, entry] of windows) {
    if (now - entry.lastFailureMs > ENTRY_TTL_MS) windows.delete(key);
  }
}

export interface IpFailureResult {
  tripped: boolean;
  count: number;
}

export function isIpPairLocked(ip: string | null, username: string): boolean {
  const entry = windows.get(windowKey(ip, username));
  return entry?.lockedUntilMs != null && entry.lockedUntilMs > Date.now();
}

export function registerIpFailure(ip: string | null, username: string): IpFailureResult {
  const now = Date.now();
  prune(now);

  const key = windowKey(ip, username);
  const entry = windows.get(key);

  if (entry?.lockedUntilMs != null && entry.lockedUntilMs > now) {
    entry.lastFailureMs = now;
    return { tripped: true, count: entry.count };
  }

  if (!entry || now - entry.windowStartMs >= IP_LOCK_WINDOW_MS) {
    const tripped = IP_LOCK_THRESHOLD <= 1;
    const fresh: WindowEntry = {
      count: 1,
      windowStartMs: now,
      lockedUntilMs: tripped ? now + IP_LOCK_DURATION_MS : null,
      lastFailureMs: now,
    };
    windows.set(key, fresh);
    return { tripped, count: 1 };
  }

  entry.count += 1;
  entry.lastFailureMs = now;
  const tripped = entry.count >= IP_LOCK_THRESHOLD;
  if (tripped && entry.lockedUntilMs == null) {
    entry.lockedUntilMs = now + IP_LOCK_DURATION_MS;
  }
  return { tripped, count: entry.count };
}

export function clearIpFailures(ip: string | null, username: string): void {
  windows.delete(windowKey(ip, username));
}

/** Test helper — forget all per-IP window state. Not for production call sites. */
export function _resetIpLockoutForTests(): void {
  windows.clear();
}

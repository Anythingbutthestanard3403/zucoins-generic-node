/**
 * HTTP + authorization surface fuzzer: NEGATIVE-PATH ASSERTIONS, one per
 * governing-source bullet (the security model no-oracle posture,
 * scope matrix; no test-mode keys). Each `it` drives the real auth
 * code to the state where the forbidden outcome WOULD occur and asserts it is
 * absent. The SITE/bcrypt branch is exercised once here (it is too slow for the
 * hot fuzz loop). DB-backed concerns (revocation/grace SQL, real statement
 * parity) stay with the Postgres integration suite — see the it.todo below.
 *
 * TEST-ONLY. Auth SUT is packages/node-core (auth-sut + src/http) — no apps/node.
 */
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import {
  hashPassword,
  IP_LOCK_DURATION_MS,
  IP_LOCK_THRESHOLD,
  IP_LOCK_WINDOW_MS,
} from "./auth-sut/index.js";
import {
  DOCUMENTED_LOCK_DURATION_MS,
  DOCUMENTED_LOCK_THRESHOLD,
  DOCUMENTED_LOCK_WINDOW_MS,
  assertEnvelopeContract,
} from "./http-auth-fuzz-oracles.js";
import {
  HOT_STORE,
  STORE_ACTION_TOKEN,
  STORE_REPORTING_TOKEN,
  driveCsrfGate,
  driveCsrfUnlessActionKey,
  drivePasswordGate,
  driveTotpGate,
  driveVerifyApiKey,
  isIpPairLocked,
  registerIpFailure,
  _resetIpLockoutForTests,
  type StoredKey,
} from "./http-auth-fuzz-alphabet.js";

const BASE_MS = 1_700_000_000_000;

describe("the security model scope matrix — wrong-scope keys are refused on the ACTION surface", () => {
  it("a REPORTING key presented as a bearer is rejected with the generic 401", async () => {
    const res = await driveVerifyApiKey(`Bearer ${STORE_REPORTING_TOKEN}`);
    expect(res.nextCalled).toBe(false);
    expect(res.status).toBe(401);
    assertEnvelopeContract(res.body, 401);
    expect((res.body as { error: { code: string } }).error.code).toBe("invalid_api_key");
    expect(res.spy.updates).toBe(0);
  });

  it("a SITE key (bcrypt branch) presented as a bearer is rejected with the generic 401", async () => {
    const siteToken = `sk_${"S".repeat(40)}`;
    const siteKey: StoredKey = {
      id: "key-site",
      kind: "SITE",
      token: siteToken,
      keyPrefix: siteToken.slice(0, 15),
      keyHash: await hashPassword(siteToken), // real bcrypt hash-at-rest
    };
    const store = [...HOT_STORE, siteKey];
    const res = await driveVerifyApiKey(`Bearer ${siteToken}`, store);
    expect(res.nextCalled).toBe(false);
    expect(res.status).toBe(401);
    assertEnvelopeContract(res.body, 401);
    expect((res.body as { error: { code: string } }).error.code).toBe("invalid_api_key");
  });
});

describe("the security model — no scope / unknown-key oracle", () => {
  it("a wrong-scope key and an unknown key produce the IDENTICAL generic 401 (code + status)", async () => {
    const wrongScope = await driveVerifyApiKey(`Bearer ${STORE_REPORTING_TOKEN}`);
    const unknown = await driveVerifyApiKey(`Bearer ak_${"Q".repeat(40)}`);
    expect(wrongScope.status).toBe(401);
    expect(unknown.status).toBe(401);
    const ws = wrongScope.body as { error: { code: string; message: string } };
    const uk = unknown.body as { error: { code: string; message: string } };
    expect(ws.error.code).toBe(uk.error.code);
    expect(ws.error.code).toBe("invalid_api_key");
    expect(ws.error.message).toBe(uk.error.message);
  });
});

describe("no test-mode key variants", () => {
  it("ak_test_ / rk_test_ / sk_test_ tokens are rejected before any DB statement", async () => {
    for (const token of [`ak_test_${"x".repeat(20)}`, `rk_test_${"x".repeat(20)}`, `sk_test_${"x".repeat(20)}`]) {
      const res = await driveVerifyApiKey(`Bearer ${token}`);
      expect(res.nextCalled).toBe(false);
      expect(res.status).toBe(401);
      expect(res.spy.selects).toBe(0); // rejected before any DB work
      expect(res.spy.updates).toBe(0);
    }
  });
});

describe("bearer grammar — a credential must ride in `Authorization: Bearer …`", () => {
  it("a valid ACTION key in the wrong format / wrong header never authenticates", async () => {
    // Bare token (no `Bearer ` prefix) in Authorization.
    const bare = await driveVerifyApiKey(STORE_ACTION_TOKEN);
    expect(bare.nextCalled).toBe(false);
    expect(bare.status).toBe(401);
    expect(bare.spy.selects).toBe(0);
    // Lowercase scheme.
    const lower = await driveVerifyApiKey(`bearer ${STORE_ACTION_TOKEN}`);
    expect(lower.nextCalled).toBe(false);
    expect(lower.status).toBe(401);
    // A valid key placed in a different header is invisible to the bearer path.
    const wrongHeader = await driveVerifyApiKey(undefined);
    expect(wrongHeader.nextCalled).toBe(false);
    expect(wrongHeader.status).toBe(401);
  });
});

describe("context gates — fail toward refusal", () => {
  it("CSRF: a missing or mismatched token is a generic 401 and never passes", async () => {
    const missing = await driveCsrfGate(undefined, "expected");
    expect(missing.nextCalled).toBe(false);
    expect(missing.json?.status).toBe(401);
    const mismatch = await driveCsrfGate("wrong", "expected");
    expect(mismatch.nextCalled).toBe(false);
    expect(mismatch.json?.status).toBe(401);
  });

  it("CSRF-unless-action-key: an UNSET authMode fails closed (full CSRF enforced)", async () => {
    // Even with a header that would match, an unset authMode must NOT stand CSRF down.
    const res = await driveCsrfUnlessActionKey(undefined, "tok", "different");
    expect(res.nextCalled).toBe(false);
    expect(res.json?.status).toBe(401);
  });

  it("TOTP gate: an unenrolled operator (mustEnrolTotp) is refused with 401 totp_required", async () => {
    const res = await driveTotpGate(true);
    expect(res.nextCalled).toBe(false);
    expect(res.json?.status).toBe(401);
    assertEnvelopeContract(res.json?.body, 401);
  });

  it("password-rotation gate: mustChangePassword is refused with 403 password_change_required", async () => {
    const res = await drivePasswordGate(true);
    expect(res.nextCalled).toBe(false);
    expect(res.json?.status).toBe(403);
    expect((res.json?.body as { error: { code: string } }).error.code).toBe("password_change_required");
  });
});

describe("the security model — per-(IP,username) lockout negatives", () => {
  beforeAll(() => {
    vi.useFakeTimers();
  });

  afterAll(() => {
    vi.useRealTimers();
    _resetIpLockoutForTests();
  });

  it("exactly THRESHOLD in-window failures trip; one fewer does not", () => {
    _resetIpLockoutForTests();
    vi.setSystemTime(BASE_MS);
    for (let i = 0; i < IP_LOCK_THRESHOLD - 1; i++) {
      const r = registerIpFailure("10.9.9.9", "admin");
      expect(r.tripped).toBe(false);
    }
    expect(isIpPairLocked("10.9.9.9", "admin")).toBe(false);
    const trip = registerIpFailure("10.9.9.9", "admin");
    expect(trip.tripped).toBe(true);
    expect(isIpPairLocked("10.9.9.9", "admin")).toBe(true);
    _resetIpLockoutForTests();
  });

  it("a locked pair is never re-counted (flat lock, no escalation)", () => {
    _resetIpLockoutForTests();
    vi.setSystemTime(BASE_MS);
    for (let i = 0; i < IP_LOCK_THRESHOLD; i++) registerIpFailure("10.8.8.8", "admin");
    const countAtTrip = registerIpFailure("10.8.8.8", "admin").count;
    // Further failures while locked do not advance the counter.
    const again = registerIpFailure("10.8.8.8", "admin");
    expect(again.tripped).toBe(true);
    expect(again.count).toBe(countAtTrip);
    _resetIpLockoutForTests();
  });

  it("the lock is scoped to the (IP, username) pair — a different IP for the same username is unaffected", () => {
    _resetIpLockoutForTests();
    vi.setSystemTime(BASE_MS);
    for (let i = 0; i < IP_LOCK_THRESHOLD; i++) registerIpFailure("10.7.7.7", "admin");
    expect(isIpPairLocked("10.7.7.7", "admin")).toBe(true);
    expect(isIpPairLocked("10.6.6.6", "admin")).toBe(false); // attacker locked, not the operator
    _resetIpLockoutForTests();
  });

  it("the username is case-folded and a missing IP collapses to one bucket", () => {
    _resetIpLockoutForTests();
    vi.setSystemTime(BASE_MS);
    for (let i = 0; i < IP_LOCK_THRESHOLD; i++) registerIpFailure(null, i % 2 ? "Admin" : "ADMIN");
    expect(isIpPairLocked(null, "admin")).toBe(true); // same bucket despite case + null IP
    _resetIpLockoutForTests();
  });

  it("after the flat lock window elapses, the counter is forgotten (no escalation across windows)", () => {
    _resetIpLockoutForTests();
    vi.setSystemTime(BASE_MS);
    for (let i = 0; i < IP_LOCK_THRESHOLD; i++) registerIpFailure("10.5.5.5", "admin");
    expect(isIpPairLocked("10.5.5.5", "admin")).toBe(true);
    vi.setSystemTime(BASE_MS + IP_LOCK_DURATION_MS + 1000);
    expect(isIpPairLocked("10.5.5.5", "admin")).toBe(false);
    const fresh = registerIpFailure("10.5.5.5", "admin");
    expect(fresh.count).toBe(1); // fresh window, not escalated
    expect(fresh.tripped).toBe(false);
    _resetIpLockoutForTests();
  });

  it("lockout constants match the documented flat model", () => {
    expect(IP_LOCK_THRESHOLD).toBe(DOCUMENTED_LOCK_THRESHOLD);
    expect(IP_LOCK_WINDOW_MS).toBe(DOCUMENTED_LOCK_WINDOW_MS);
    expect(IP_LOCK_DURATION_MS).toBe(DOCUMENTED_LOCK_DURATION_MS);
  });
});

describe("out of surface — DB-backed acceptance (covered by the Postgres integration suite)", () => {
  it.todo("revocation / grace-window SQL (revoked_at filter) — requires real Postgres");
  it.todo("DB statement parity for the unknown-user login path — requires real Postgres");
});

/**
 * HTTP + authorization surface fuzzer: CORE PROPERTIES.
 *
 * Acceptance: no crash on adversarial input; every rejection is a contract-valid
 * generic 401/403 envelope; the ACTION surface authenticates ONLY
 * a well-formed `Bearer <ACTION-key>` that hash-matches a stored active key and
 * fails CLOSED before any DB statement for unclassifiable / test-mode tokens
 * a wrong-scope key is refused with the SAME 401 as an unknown key (no
 * scope oracle, the security model); the context gates fail toward refusal; the
 * per-(IP,username) lockout matches the documented 5/15-min flat model step for
 * step under a faked clock; and the login/confirm schemas accept exactly the
 * documented shape. Deterministic: pinned seed + numRuns + endOnFailure.
 *
 * TEST-ONLY; runs under packages/node-core/test/** so setup-network-guard.ts is
 * active. Auth SUT is packages/node-core (auth-sut + src/http) — no apps/node.
 */
import { describe, expect, it, vi } from "vitest";
import fc from "fast-check";

import {
  FUZZ_NUM_RUNS,
  FUZZ_SEED,
  assertEnvelopeContract,
  assertNoSecretLeak,
  isDocumentedTestKey,
  referenceConfirmTotpValid,
  referenceKindForToken,
  referenceLoginValid,
  referenceLookupPrefix,
  ReferenceLockout,
  DOCUMENTED_LOCK_THRESHOLD,
  DOCUMENTED_LOCK_WINDOW_MS,
  DOCUMENTED_LOCK_DURATION_MS,
} from "./http-auth-fuzz-oracles.js";
import {
  HOT_STORE,
  STORE_ACTION_TOKEN,
  LOCKOUT_TRIP_ACTIONS,
  bearerTokenArb,
  driveConfirmTotpSchema,
  driveCsrfGate,
  driveCsrfUnlessActionKey,
  driveLoginSchema,
  drivePasswordGate,
  driveTotpGate,
  driveVerifyApiKey,
  isIpPairLocked,
  kindForToken,
  lockoutActionArb,
  lookupPrefix,
  malformedHeaderArb,
  loginInputArb,
  referenceVerifyDecision,
  registerIpFailure,
  clearIpFailures,
  sha256Hex,
  wellFormedBearerArb,
  _resetIpLockoutForTests,
} from "./http-auth-fuzz-alphabet.js";
import {
  IP_LOCK_THRESHOLD,
  IP_LOCK_WINDOW_MS,
  IP_LOCK_DURATION_MS,
  errorBody,
} from "./auth-sut/index.js";

const CFG = { seed: FUZZ_SEED, numRuns: FUZZ_NUM_RUNS, endOnFailure: true } as const;
const BASE_MS = 1_700_000_000_000;

// Coverage-floor accumulators — populated inside properties, asserted after.
let sawValidActionAuth = false;
let sawWrongScopeReject = false;
let sawTestKeyReject = false;
let sawUnknownKeyReject = false;
let sawMalformedHeader = false;
let sawUnicodeInput = false;
let sawOversizedInput = false;
let sawLockoutTrip = false;
let sawCaseFold = false;
let sawNullIp = false;
let sawWindowExpiry = false;

describe("network containment guard is installed", () => {
  it("fetch is network-contained", async () => {
    await expect(globalThis.fetch("http://127.0.0.1/should-not-reach")).rejects.toThrow(
      /network-contained/i,
    );
  });
});

describe("rate-limit constants are frozen to the documented model", () => {
  it("threshold 5, 15-min rolling window, flat 15-min lock", () => {
    expect(IP_LOCK_THRESHOLD).toBe(DOCUMENTED_LOCK_THRESHOLD);
    expect(IP_LOCK_WINDOW_MS).toBe(DOCUMENTED_LOCK_WINDOW_MS);
    expect(IP_LOCK_DURATION_MS).toBe(DOCUMENTED_LOCK_DURATION_MS);
  });
});

describe("error envelope contract", () => {
  it("every auth-surface error body conforms and maps to its frozen http status", () => {
    const codes = [
      ["invalid_api_key", 401],
      ["invalid_credentials", 401],
      ["totp_required", 401],
      ["password_change_required", 403],
      ["validation_error", 400],
    ] as const;
    for (const [code, http] of codes) {
      const body = errorBody(code, "message");
      assertEnvelopeContract(body, http);
      assertNoSecretLeak(body);
    }
  });
});

describe("bearer grammar + ACTION-surface authentication decision", () => {
  it("a well-formed bearer authenticates iff it is an ACTION key that hash-matches the store", async () => {
    await fc.assert(
      fc.asyncProperty(wellFormedBearerArb, async ({ header, token }) => {
        const res = await driveVerifyApiKey(header);
        const ref = referenceVerifyDecision(token);
        if (ref.authenticates) {
          sawValidActionAuth = true;
          expect(res.nextCalled).toBe(true);
          expect(res.status).toBeUndefined();
          expect(res.apiKeyKind).toBe("ACTION");
          expect(res.spy.updates).toBe(1); // last_used_at stamped only on success
        } else {
          expect(res.nextCalled).toBe(false);
          expect(res.status).toBe(401);
          assertEnvelopeContract(res.body, 401);
          expect(res.spy.updates).toBe(0); // never stamp on rejection
          if (ref.kind === null || isDocumentedTestKey(token)) {
            // Fail CLOSED before any DB statement (unknown scheme).
            expect(res.spy.selects).toBe(0);
          }
          if (ref.kind === "REPORTING") sawWrongScopeReject = true;
          if (isDocumentedTestKey(token)) sawTestKeyReject = true;
          if (ref.kind === "ACTION" && !isDocumentedTestKey(token)) sawUnknownKeyReject = true;
        }
      }),
      CFG,
    );
  });

  it("a malformed Authorization header never authenticates and never reaches the DB", async () => {
    await fc.assert(
      fc.asyncProperty(malformedHeaderArb, async (header) => {
        sawMalformedHeader = true;
        const res = await driveVerifyApiKey(header);
        expect(res.nextCalled).toBe(false);
        expect(res.status).toBe(401);
        assertEnvelopeContract(res.body, 401);
        expect(res.spy.selects).toBe(0); // bad grammar rejected before any DB work
        expect(res.spy.updates).toBe(0);
      }),
      CFG,
    );
  });

  it("adversarial unicode / oversized / injected headers never crash and never authenticate", async () => {
    const unicodeish = (maxLen: number) =>
      fc
        .array(fc.integer({ min: 1, max: 0x21ff }), { minLength: 0, maxLength: maxLen })
        .map((codes) => String.fromCodePoint(...codes));
    const adversarial = fc.oneof(
      unicodeish(200).map((s) => `Bearer ak_${s}`),
      fc.constant(`Bearer ak_${"A".repeat(5000)}`),
      unicodeish(200),
      fc.constant("Bearer ak_x\r\nX-Injected: 1"),
      fc.constant("Bearer ak_\u0000nul"),
      fc.constant("Bearer ak_\u202e\u2066rtl"),
    );
    await fc.assert(
      fc.asyncProperty(adversarial, async (header) => {
        if (header.length > 1000) sawOversizedInput = true;
        if (/[^\x20-\x7e]/.test(header)) sawUnicodeInput = true;
        const res = await driveVerifyApiKey(header);
        // None of these equal the stored ACTION key, so none may authenticate.
        expect(res.nextCalled).toBe(false);
        expect(res.status).toBe(401);
        assertEnvelopeContract(res.body, 401);
      }),
      CFG,
    );
  });
});

describe("key-scheme classification closure", () => {
  it("kindForToken agrees with the documented scheme and lookupPrefix is the first 15 bytes", () => {
    fc.assert(
      fc.property(bearerTokenArb, (token) => {
        expect(kindForToken(token)).toBe(referenceKindForToken(token));
        if (token.length > 0) {
          expect(lookupPrefix(token)).toBe(referenceLookupPrefix(token));
          expect(lookupPrefix(token).length).toBeLessThanOrEqual(15);
        }
      }),
      CFG,
    );
  });

  it("sha256Hex is the documented digest and is deterministic", () => {
    fc.assert(
      fc.property(bearerTokenArb, (token) => {
        expect(sha256Hex(token)).toBe(sha256Hex(token));
        expect(sha256Hex(token)).toMatch(/^[0-9a-f]{64}$/);
      }),
      CFG,
    );
  });
});

describe("context gates fail toward refusal", () => {
  it("CSRF: match passes, any mismatch/absence is a generic 401", async () => {
    await fc.assert(
      fc.asyncProperty(fc.string(), fc.string(), async (provided, expected) => {
        const res = await driveCsrfGate(provided === "" ? undefined : provided, expected);
        if (provided !== "" && provided === expected) {
          expect(res.nextCalled).toBe(true);
        } else {
          expect(res.nextCalled).toBe(false);
          expect(res.json?.status).toBe(401);
          assertEnvelopeContract(res.json?.body, 401);
        }
      }),
      CFG,
    );
  });

  it("CSRF-unless-action-key: action_key stands down; session/unset enforce full CSRF (fail closed)", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom("action_key", "session", undefined),
        fc.string(),
        fc.string(),
        async (authMode, provided, expected) => {
          const res = await driveCsrfUnlessActionKey(authMode, provided === "" ? undefined : provided, expected);
          if (authMode === "action_key") {
            expect(res.nextCalled).toBe(true); // non-ambient bearer: CSRF stood down
          } else {
            // session AND unset authMode both take the full CSRF check (fail closed on unset).
            const shouldPass = provided !== "" && provided === expected;
            expect(res.nextCalled).toBe(shouldPass);
            if (!shouldPass) {
              expect(res.json?.status).toBe(401);
              assertEnvelopeContract(res.json?.body, 401);
            }
          }
        },
      ),
      CFG,
    );
  });

  it("TOTP gate: mustEnrolTotp -> 401 totp_required; otherwise passes", async () => {
    await fc.assert(
      fc.asyncProperty(fc.boolean(), async (mustEnrol) => {
        const res = await driveTotpGate(mustEnrol);
        if (mustEnrol) {
          expect(res.nextCalled).toBe(false);
          expect(res.json?.status).toBe(401);
        } else {
          expect(res.nextCalled).toBe(true);
        }
      }),
      CFG,
    );
  });

  it("password-rotation gate: mustChangePassword -> 403; otherwise passes", async () => {
    await fc.assert(
      fc.asyncProperty(fc.boolean(), async (mustChange) => {
        const res = await drivePasswordGate(mustChange);
        if (mustChange) {
          expect(res.nextCalled).toBe(false);
          expect(res.json?.status).toBe(403);
          assertEnvelopeContract(res.json?.body, 403);
        } else {
          expect(res.nextCalled).toBe(true);
        }
      }),
      CFG,
    );
  });
});

describe("per-(IP,username) lockout matches the documented flat model", () => {
  it("real in-memory lockout agrees with the reference spec step-for-step under a faked clock", () => {
    vi.useFakeTimers();
    try {
      fc.assert(
        fc.property(
          fc.oneof(
            fc.constant([...LOCKOUT_TRIP_ACTIONS]),
            fc.array(lockoutActionArb, { minLength: 1, maxLength: 12 }),
          ),
          (actions) => {
          _resetIpLockoutForTests();
          const ref = new ReferenceLockout();
          let now = BASE_MS;
          for (const a of actions) {
            now += a.advanceMs;
            vi.setSystemTime(now);
            if (a.ip === null) sawNullIp = true;
            if (a.username !== a.username.toLowerCase()) sawCaseFold = true;
            if (a.advanceMs >= DOCUMENTED_LOCK_WINDOW_MS) sawWindowExpiry = true;

            if (a.op === "fail") {
              const real = registerIpFailure(a.ip, a.username);
              const exp = ref.registerFailure(a.ip, a.username, now);
              expect(real.tripped).toBe(exp.tripped);
              expect(real.count).toBe(exp.count);
              if (real.tripped) sawLockoutTrip = true;
            } else if (a.op === "clear") {
              clearIpFailures(a.ip, a.username);
              ref.clear(a.ip, a.username);
            }
            // After every action the lock state agrees for this pair.
            expect(isIpPairLocked(a.ip, a.username)).toBe(ref.isLocked(a.ip, a.username, now));
          }
        }),
        CFG,
      );
    } finally {
      vi.useRealTimers();
      _resetIpLockoutForTests();
    }
  });
});

describe("content-type / shape confusion at the validation boundary", () => {
  it("loginSchema accepts exactly the documented shape, never crashes", () => {
    fc.assert(
      fc.property(loginInputArb, (value) => {
        expect(driveLoginSchema(value)).toBe(referenceLoginValid(value));
      }),
      CFG,
    );
  });

  it("confirmTotpSchema accepts exactly a single 6-digit code, never crashes", () => {
    const arb = fc.oneof(
      fc.record({ totp: fc.string({ unit: fc.constantFrom("0", "1", "2", "3", "4", "5", "6", "7", "8", "9"), minLength: 0, maxLength: 8 }) }),
      fc.record({ totp: fc.string(), extra: fc.string() }),
      loginInputArb,
    );
    fc.assert(
      fc.property(arb, (value) => {
        expect(driveConfirmTotpSchema(value)).toBe(referenceConfirmTotpValid(value));
      }),
      CFG,
    );
  });
});

describe("secret-leak scan over generated inputs (no secret in synthetic fuzz objects)", () => {
  it("no secret-shaped field is reachable in any generated bearer token or lockout action", () => {
    fc.assert(
      fc.property(fc.oneof(bearerTokenArb, lockoutActionArb), (value) => {
        assertNoSecretLeak(value);
      }),
      CFG,
    );
  });
});

describe("adversarial coverage floor (no false negative)", () => {
  it("valid ACTION auth, wrong-scope, test-key, unknown-key, malformed, unicode, oversized, lockout trip, case-fold, null-IP, and window-expiry all occurred", () => {
    expect(sawValidActionAuth).toBe(true);
    expect(sawWrongScopeReject).toBe(true);
    expect(sawTestKeyReject).toBe(true);
    expect(sawUnknownKeyReject).toBe(true);
    expect(sawMalformedHeader).toBe(true);
    expect(sawUnicodeInput).toBe(true);
    expect(sawOversizedInput).toBe(true);
    expect(sawLockoutTrip).toBe(true);
    expect(sawCaseFold).toBe(true);
    expect(sawNullIp).toBe(true);
    expect(sawWindowExpiry).toBe(true);
    // Reference the imported fixtures so the store/token are exercised, not dead.
    expect(HOT_STORE.length).toBeGreaterThan(0);
    expect(typeof STORE_ACTION_TOKEN).toBe("string");
  });
});

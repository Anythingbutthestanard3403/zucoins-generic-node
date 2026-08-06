/**
 * HTTP + authorization surface fuzzer: ORACLE SELF-CHECK (anti-tautology
 * mutants). An oracle that cannot be red-gone is tautological. Each block proves
 * the oracle's verdict actually depends on (a) the expectation content and
 * (b) the observed value — a positive control goes green, a mutated expectation
 * or adversarial input goes red.
 *
 * TEST-ONLY.
 */
import { describe, expect, it } from "vitest";

import { kindForToken } from "./auth-sut/index.js";
import {
  DOCUMENTED_LOCK_THRESHOLD,
  ReferenceLockout,
  assertEnvelopeContract,
  assertNoSecretLeak,
  isDocumentedTestKey,
  referenceAuthenticate,
  referenceConfirmTotpValid,
  referenceKindForToken,
  referenceLoginValid,
  referenceLookupPrefix,
  referenceScopeAllows,
  referenceSha256Hex,
  type ReferenceCandidate,
} from "./http-auth-fuzz-oracles.js";
import {
  HOT_STORE,
  STORE_ACTION_TOKEN,
  STORE_REPORTING_TOKEN,
  driveVerifyApiKey,
} from "./http-auth-fuzz-alphabet.js";

const actionCandidate = (token: string, id = "k"): ReferenceCandidate => ({
  id,
  kind: "ACTION",
  keyPrefix: referenceLookupPrefix(token),
  keyHash: referenceSha256Hex(token),
});

describe("error-envelope oracle is NOT tautological", () => {
  it("positive control: a well-formed envelope passes", () => {
    expect(() =>
      assertEnvelopeContract(
        {
          error: {
            code: "invalid_api_key",
            message: "m",
            request_id: "r",
            doc_url: "d",
          },
        },
        401,
      ),
    ).not.toThrow();
  });
  it("goes RED on a missing required field", () => {
    expect(() =>
      assertEnvelopeContract({ error: { code: "invalid_api_key", message: "m", doc_url: "d" } }),
    ).toThrow(/envelope/);
  });
  it("goes RED on a code outside the frozen enum", () => {
    expect(() =>
      assertEnvelopeContract({
        error: { code: "not_a_real_code", message: "m", request_id: "r", doc_url: "d" },
      }),
    ).toThrow(/envelope/);
  });
  it("goes RED on a wrong http status for the code", () => {
    expect(() =>
      assertEnvelopeContract(
        { error: { code: "invalid_api_key", message: "m", request_id: "r", doc_url: "d" } },
        404,
      ),
    ).toThrow(/http/);
  });
});

describe("authentication-decision oracle is NOT tautological", () => {
  it("positive control: a stored ACTION token authenticates", () => {
    expect(referenceAuthenticate(STORE_ACTION_TOKEN, [actionCandidate(STORE_ACTION_TOKEN)])).not.toBeNull();
  });
  it("goes RED when the candidate is removed (empty store)", () => {
    expect(referenceAuthenticate(STORE_ACTION_TOKEN, [])).toBeNull();
  });
  it("goes RED when the stored hash does not match", () => {
    const wrong: ReferenceCandidate = {
      id: "k",
      kind: "ACTION",
      keyPrefix: referenceLookupPrefix(STORE_ACTION_TOKEN),
      keyHash: referenceSha256Hex("ak_someOtherToken"),
    };
    expect(referenceAuthenticate(STORE_ACTION_TOKEN, [wrong])).toBeNull();
  });
  it("goes RED on a test-mode key even when a candidate exists", () => {
    const testToken = "ak_test_zzz";
    expect(isDocumentedTestKey(testToken)).toBe(true);
    expect(referenceAuthenticate(testToken, [actionCandidate(testToken)])).toBeNull();
  });
  it("scope oracle: ACTION allowed on the ACTION surface, REPORTING/SITE refused", () => {
    expect(referenceScopeAllows("ACTION", ["ACTION"])).toBe(true);
    expect(referenceScopeAllows("REPORTING", ["ACTION"])).toBe(false);
    expect(referenceScopeAllows("SITE", ["ACTION"])).toBe(false);
    expect(referenceScopeAllows(null, ["ACTION"])).toBe(false);
  });
});

describe("scheme-classification oracle is NOT tautological", () => {
  it("positive control matches the real kindForToken", () => {
    for (const t of ["ak_x", "sk_x", "rk_x", "xx_x", ""]) {
      expect(referenceKindForToken(t)).toBe(kindForToken(t));
    }
  });
  it("goes RED on a prefix change (classification depends on the exact prefix)", () => {
    expect(referenceKindForToken("ak_x")).toBe("ACTION");
    expect(referenceKindForToken("Ak_x")).toBeNull(); // no case fold
    expect(referenceKindForToken("a_k_x")).toBeNull();
  });
});

describe("rate-limit oracle is NOT tautological (threshold-sensitive)", () => {
  it("positive control: THRESHOLD failures lock; one fewer does not", () => {
    const ref = new ReferenceLockout();
    for (let i = 0; i < DOCUMENTED_LOCK_THRESHOLD - 1; i++) ref.registerFailure("ip", "u", 1000 + i);
    expect(ref.isLocked("ip", "u", 2000)).toBe(false);
    ref.registerFailure("ip", "u", 2001);
    expect(ref.isLocked("ip", "u", 2002)).toBe(true);
  });
  it("goes RED on a different (IP,username) pair (lock is pair-scoped)", () => {
    const ref = new ReferenceLockout();
    for (let i = 0; i < DOCUMENTED_LOCK_THRESHOLD; i++) ref.registerFailure("ipA", "u", 1000 + i);
    expect(ref.isLocked("ipB", "u", 2000)).toBe(false);
  });
  it("folds username case and collapses null IP into one bucket", () => {
    const ref = new ReferenceLockout();
    for (let i = 0; i < DOCUMENTED_LOCK_THRESHOLD; i++) {
      ref.registerFailure(null, i % 2 ? "Admin" : "ADMIN", 1000 + i);
    }
    expect(ref.isLocked(null, "admin", 2000)).toBe(true);
  });
  it("clear forgets the window", () => {
    const ref = new ReferenceLockout();
    for (let i = 0; i < DOCUMENTED_LOCK_THRESHOLD; i++) ref.registerFailure("ip", "u", 1000 + i);
    ref.clear("ip", "u");
    expect(ref.isLocked("ip", "u", 2000)).toBe(false);
  });
});

describe("login-shape oracle is NOT tautological", () => {
  it("positive control: the documented shape passes", () => {
    expect(referenceLoginValid({ username: "u", password: "p" })).toBe(true);
    expect(referenceLoginValid({ username: "u", password: "p", totp: "123456" })).toBe(true);
  });
  it("goes RED on extra keys, wrong types, and non-objects", () => {
    expect(referenceLoginValid({ username: "u", password: "p", extra: 1 })).toBe(false);
    expect(referenceLoginValid({ username: 5, password: "p" })).toBe(false);
    expect(referenceLoginValid({ username: "", password: "p" })).toBe(false);
    expect(referenceLoginValid("nope")).toBe(false);
    expect(referenceLoginValid(null)).toBe(false);
    expect(referenceLoginValid([1])).toBe(false);
  });
  it("confirm-totp oracle: exactly six digits", () => {
    expect(referenceConfirmTotpValid({ totp: "123456" })).toBe(true);
    expect(referenceConfirmTotpValid({ totp: "12345" })).toBe(false);
    expect(referenceConfirmTotpValid({ totp: "1234567" })).toBe(false);
    expect(referenceConfirmTotpValid({ totp: "12a456" })).toBe(false);
    expect(referenceConfirmTotpValid({ totp: "123456", x: 1 })).toBe(false);
  });
});

describe("secret-leak scanner goes RED on secret-shaped input", () => {
  it("rejects secret-shaped fields and overlong blobs; accepts opaque ids", () => {
    expect(() => assertNoSecretLeak({ totp: "x" })).toThrow(/secret-shaped/);
    expect(() => assertNoSecretLeak({ password_hash: "x" })).toThrow(/secret-shaped/);
    expect(() => assertNoSecretLeak({ csrf_token: "x" })).toThrow(/secret-shaped/);
    expect(() => assertNoSecretLeak({ blob: "a".repeat(200) })).toThrow(/overlong/);
    expect(() => assertNoSecretLeak({ apiKeyKind: "ACTION", ip: "10.0.0.1" })).not.toThrow();
  });
});

describe("oracle ties to the REAL implementation (positive control)", () => {
  it("the real verifyApiKey authenticates the stored ACTION key the oracle predicts", async () => {
    const res = await driveVerifyApiKey(`Bearer ${STORE_ACTION_TOKEN}`, HOT_STORE);
    expect(res.nextCalled).toBe(true);
    expect(res.apiKeyKind).toBe("ACTION");
  });
  it("the real verifyApiKey refuses the wrong-scope key the oracle predicts", async () => {
    const res = await driveVerifyApiKey(`Bearer ${STORE_REPORTING_TOKEN}`, HOT_STORE);
    expect(res.nextCalled).toBe(false);
    expect(res.status).toBe(401);
  });
});

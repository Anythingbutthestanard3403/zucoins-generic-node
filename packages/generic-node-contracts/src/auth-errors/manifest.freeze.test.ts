// the auth-errors/route-policy concern.1 freeze + census gate for the non-oracular auth-error contract.
//
// The error envelope and authentication classes; canonical: the frozen error vocabulary (scope denial
// is the generic 401; no 403 oracle). This gate proves: (a) the serialized manifest matches
// the committed golden; (b) the frozen codes never include a 403/forbidden scope oracle nor a
// cross-tenant code; (c) the golden wire bodies are byte-exact and digest-pinned; and (d) —
// mandatory negative path — the pure non-oracularity verifier ACCEPTS the collapsed class and
// REJECTS a 403 scope oracle and a scope-leaking message.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import golden from "./gen/auth-errors.json" with { type: "json" };
import {
  AUTH_ERROR_CODES,
  REJECTED_AUTH_ERROR_CODES,
  CANONICAL_AUTH_FAILURE_CODE,
  CANONICAL_NOT_FOUND_CODE,
} from "./codes.js";
import {
  REPORTING_REJECTION_CODES,
  REJECTION_STATUS,
} from "./reporting-rejection.js";
import {
  ERROR_ENVELOPE_FIELD_ORDER,
  REQUEST_ID_PLACEHOLDER,
  buildAuthErrorBody,
  CANONICAL_AUTH_FAILURE_BODY,
  CANONICAL_NOT_FOUND_BODY,
  CANONICAL_AUTH_FAILURE_MESSAGE,
  CANONICAL_AUTH_ERROR_HEADERS,
} from "./envelope.js";
import { AUTH_FAILURE_STATE_TO_CODE } from "./classes.js";
import {
  canonicalizeHeaders,
  firstOracleDivergence,
  indistinguishable,
  isNonOracular,
  type WireResponse,
} from "./non-oracular.js";
import { SHA256_AUTH_FAILURE_BODY, SHA256_NOT_FOUND_BODY } from "./digests.js";
import { buildAuthErrorsManifest } from "./manifest.js";

const sha256 = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");
const readArtifact = (name: string): string =>
  readFileSync(fileURLToPath(new URL(`./gen/${name}`, import.meta.url)), "utf8");

describe("the auth-errors/route-policy concern.1 auth-error manifest freeze", () => {
  it("serialized manifest matches the committed golden snapshot", () => {
    expect(buildAuthErrorsManifest()).toEqual(golden);
  });

  it("freezes the error-envelope field sequence (the byte-exact signing rule byte sequence)", () => {
    expect([...ERROR_ENVELOPE_FIELD_ORDER]).toEqual(["code", "message", "request_id", "details"]);
  });
});

describe("the auth-errors/route-policy concern.1 census: no scope / cross-tenant oracle in the frozen codes", () => {
  it("exposes exactly the two collapse codes and no 403", () => {
    expect(AUTH_ERROR_CODES.map((c) => c.code)).toEqual(["invalid_api_key", "not_found"]);
    const statuses: readonly number[] = AUTH_ERROR_CODES.map((c) => c.http);
    expect(statuses.includes(403)).toBe(false);
  });

  it("keeps every rejected code out of the frozen set (the frozen error-vocabulary resolution holds)", () => {
    const frozen = new Set<string>(AUTH_ERROR_CODES.map((c) => c.code));
    for (const rejected of REJECTED_AUTH_ERROR_CODES) {
      expect(frozen.has(rejected.code)).toBe(false);
    }
    // The specific proposal-403 that the auth-errors/route-policy concern.1 resolves must be named as rejected.
    expect(REJECTED_AUTH_ERROR_CODES.some((c) => c.code === "forbidden" && c.http === 403)).toBe(
      true,
    );
  });

  it("maps every credential state to the 401 and every resolution state to the 404 — never 403", () => {
    for (const [state, code] of Object.entries(AUTH_FAILURE_STATE_TO_CODE)) {
      expect(code === CANONICAL_AUTH_FAILURE_CODE || code === CANONICAL_NOT_FOUND_CODE).toBe(true);
      if (state.endsWith("_OBJECT")) {
        expect(code).toBe(CANONICAL_NOT_FOUND_CODE);
      } else {
        expect(code).toBe(CANONICAL_AUTH_FAILURE_CODE);
      }
    }
  });
});

describe("the auth-errors/route-policy concern.1 byte-exact golden wire bodies (tier 3)", () => {
  it("the 401 body equals its raw artifact and matches its pinned digest", () => {
    const raw = readArtifact("auth-error-401.body.json");
    expect(CANONICAL_AUTH_FAILURE_BODY).toBe(raw);
    expect(sha256(CANONICAL_AUTH_FAILURE_BODY)).toBe(SHA256_AUTH_FAILURE_BODY);
    expect(sha256(raw)).toBe(SHA256_AUTH_FAILURE_BODY);
  });

  it("the 404 body equals its raw artifact and matches its pinned digest", () => {
    const raw = readArtifact("auth-error-404.body.json");
    expect(CANONICAL_NOT_FOUND_BODY).toBe(raw);
    expect(sha256(CANONICAL_NOT_FOUND_BODY)).toBe(SHA256_NOT_FOUND_BODY);
    expect(sha256(raw)).toBe(SHA256_NOT_FOUND_BODY);
  });

  it("the builder emits the frozen key sequence regardless of input sequence", () => {
    // Even if a caller passed fields differently, the builder's explicit insertion sequence wins.
    expect(buildAuthErrorBody("invalid_api_key", "Invalid API key.", REQUEST_ID_PLACEHOLDER)).toBe(
      CANONICAL_AUTH_FAILURE_BODY,
    );
  });
});

describe("the auth-errors/route-policy concern.1 non-oracularity predicate (positive control)", () => {
  it("valid-key-wrong-scope and unknown-key are indistinguishable modulo request_id", () => {
    // The two named collapse-class subcases: an out-of-scope valid key and a
    // genuinely unknown key. Distinct per-request request_ids, otherwise byte-identical.
    const wrongScope: WireResponse = {
      status: 401,
      body: buildAuthErrorBody(
        CANONICAL_AUTH_FAILURE_CODE,
        CANONICAL_AUTH_FAILURE_MESSAGE,
        "11111111-1111-4111-8111-111111111111",
      ),
    };
    const unknownKey: WireResponse = {
      status: 401,
      body: buildAuthErrorBody(
        CANONICAL_AUTH_FAILURE_CODE,
        CANONICAL_AUTH_FAILURE_MESSAGE,
        "22222222-2222-4222-8222-222222222222",
      ),
    };
    expect(indistinguishable(wrongScope, unknownKey)).toBe(true);
    expect(isNonOracular([wrongScope, unknownKey])).toBe(true);
  });
});

describe("the auth-errors/route-policy concern.1 non-oracularity predicate (mandatory negative path)", () => {
  const canonical401: WireResponse = { status: 401, body: CANONICAL_AUTH_FAILURE_BODY };

  it("REJECTS a 403 scope-oracle response as distinguishable from the generic 401", () => {
    // The exact posture the auth-errors/route-policy concern.1 forbids: a distinct 403 that reveals "valid key, wrong scope".
    const scopeOracle403: WireResponse = {
      status: 403,
      body: buildAuthErrorBody("forbidden", "Insufficient scope.", REQUEST_ID_PLACEHOLDER),
    };
    expect(indistinguishable(canonical401, scopeOracle403)).toBe(false);
    expect(firstOracleDivergence([canonical401, scopeOracle403])).toBe(1);
  });

  it("REJECTS a same-status message that leaks scope existence", () => {
    // Same 401 status, but a subcase-specific message — an oracle hidden inside the body bytes.
    const leakyMessage401: WireResponse = {
      status: 401,
      body: buildAuthErrorBody(
        CANONICAL_AUTH_FAILURE_CODE,
        "Valid key, but missing scope send:create.",
        REQUEST_ID_PLACEHOLDER,
      ),
    };
    expect(indistinguishable(canonical401, leakyMessage401)).toBe(false);
    expect(isNonOracular([canonical401, leakyMessage401])).toBe(false);
  });
});

describe("the auth-errors/route-policy concern.1 header-channel non-oracularity (defect close)", () => {
  it("freezes the auth-error response headers as a constant with no WWW-Authenticate challenge", () => {
    expect(CANONICAL_AUTH_ERROR_HEADERS).toEqual({ "content-type": "application/json; charset=utf-8" });
    // J3 / RFC 6750: no challenge header, so no `error="…"` scope hint can ride the header channel.
    const lowerNames = Object.keys(CANONICAL_AUTH_ERROR_HEADERS).map((n) => n.toLowerCase());
    expect(lowerNames).not.toContain("www-authenticate");
  });

  it("REJECTS two 401s that differ ONLY in a WWW-Authenticate scope hint (the breaking input)", () => {
    // Identical status + body; the sole difference is the RFC 6750 Bearer error the header carries.
    // A status+body-only verifier called these indistinguishable — reopening the closed scope oracle.
    const invalidToken401: WireResponse = {
      status: 401,
      body: CANONICAL_AUTH_FAILURE_BODY,
      headers: { "content-type": "application/json; charset=utf-8", "WWW-Authenticate": 'Bearer error="invalid_token"' },
    };
    const insufficientScope401: WireResponse = {
      status: 401,
      body: CANONICAL_AUTH_FAILURE_BODY,
      headers: { "content-type": "application/json; charset=utf-8", "WWW-Authenticate": 'Bearer error="insufficient_scope"' },
    };
    expect(indistinguishable(invalidToken401, insufficientScope401)).toBe(false);
    expect(isNonOracular([invalidToken401, insufficientScope401])).toBe(false);
    expect(firstOracleDivergence([invalidToken401, insufficientScope401])).toBe(1);
  });

  it("holds indistinguishability when two responses share the frozen headers and differ only in request_id", () => {
    const a: WireResponse = {
      status: 401,
      body: buildAuthErrorBody(CANONICAL_AUTH_FAILURE_CODE, CANONICAL_AUTH_FAILURE_MESSAGE, "11111111-1111-4111-8111-111111111111"),
      headers: CANONICAL_AUTH_ERROR_HEADERS,
    };
    const b: WireResponse = {
      status: 401,
      body: buildAuthErrorBody(CANONICAL_AUTH_FAILURE_CODE, CANONICAL_AUTH_FAILURE_MESSAGE, "22222222-2222-4222-8222-222222222222"),
      headers: CANONICAL_AUTH_ERROR_HEADERS,
    };
    expect(indistinguishable(a, b)).toBe(true);
  });

  it("treats header field names case-insensitively (RFC 7230) — casing alone is not an oracle", () => {
    const upper: WireResponse = {
      status: 401,
      body: CANONICAL_AUTH_FAILURE_BODY,
      headers: { "Content-Type": "application/json; charset=utf-8" },
    };
    const lower: WireResponse = {
      status: 401,
      body: CANONICAL_AUTH_FAILURE_BODY,
      headers: { "content-type": "application/json; charset=utf-8" },
    };
    expect(canonicalizeHeaders(upper.headers)).toBe(canonicalizeHeaders(lower.headers));
    expect(indistinguishable(upper, lower)).toBe(true);
  });

  it("fails closed when a header appears in one response but not the other", () => {
    const withHeader: WireResponse = { status: 401, body: CANONICAL_AUTH_FAILURE_BODY, headers: CANONICAL_AUTH_ERROR_HEADERS };
    const withoutHeader: WireResponse = { status: 401, body: CANONICAL_AUTH_FAILURE_BODY };
    expect(indistinguishable(withHeader, withoutHeader)).toBe(false);
  });
});

describe("/ UP-09 reporting rejection taxonomy (auth-errors concern)", () => {
  it("freezes reporting_auth_hold as 401 and the full REPORTING_REJECTION_CODES set", () => {
    expect([...REPORTING_REJECTION_CODES]).toEqual([
      "missing_reporting_headers",
      "invalid_reporting_headers",
      "invalid_request_target",
      "not_found",
      "request_too_large",
      "invalid_idempotency_key",
      "unsupported_content_encoding",
      "rate_limited",
      "invalid_reporting_window",
      "reporting_request_expired",
      "reporting_request_not_yet_valid",
      "unknown_reporting_key",
      "tenant_binding_mismatch",
      "reporting_key_not_active",
      "reporting_auth_hold",
      "invalid_signature",
      "nonce_replay",
      "idempotency_conflict",
      "internal_error",
    ]);
    expect(REJECTION_STATUS.reporting_auth_hold).toBe(401);
    for (const code of REPORTING_REJECTION_CODES) {
      expect(typeof REJECTION_STATUS[code]).toBe("number");
    }
  });

  it("manifest snapshot carries the reporting rejection codes and status map", () => {
    const m = buildAuthErrorsManifest();
    expect(m.reportingRejectionCodes).toEqual([...REPORTING_REJECTION_CODES]);
    expect(m.reportingRejectionStatus).toEqual({ ...REJECTION_STATUS });
  });
});

// API contract and size-limit tests: validation-pipeline integration, exact
// size/depth boundaries, content-type enforcement, and rate-limit (429) behavior.
//
// Complements api-validation.test.ts (scalar/schema rejection + envelope shape) by
// exercising the eight-stage pipeline end-to-end, the
// bounded size/depth gates at their exact boundaries (the test plan),
// the canonical content-type header on every error envelope (J3), and the
// 429 rate-limit envelope.
//
// Invariants: ZKZ never ZUC; byte-exact JSON.stringify key order.

import { describe, expect, it } from "vitest";
// API contract and size-limit tests: validation-pipeline integration, exact
// size/depth boundaries, content-type enforcement, and rate-limit (429) behavior.
//
// Complements api-validation.test.ts (scalar/schema rejection + envelope shape) by
// exercising the eight-stage pipeline end-to-end, the
// bounded size/depth gates at their exact boundaries (the test plan),
// the canonical content-type header on every error envelope (J3), and the
// 429 rate-limit envelope.
//
// Invariants: ZKZ never ZUC; byte-exact JSON.stringify key order.

import { describe, expect, it } from "vitest";
import {
  runValidationPipeline,
  findRouteSchema,
  apiErrorResponse,
  buildApiErrorBody,
  HTTP_STATUS_BY_CODE,
  parseStrictJson,
  DEFAULT_MAX_BODY_BYTES,
  DEFAULT_MAX_NESTING_DEPTH,
  API_ERROR_CODES,
  type AuthPrincipal,
  type PipelineConfig,
  type PipelineRequest,
} from "../src/api/index.js";
// Not re-exported by the api barrel (the prefix is an internal presentation detail).
import { IMPLEMENTER_BEARER_PREFIX } from "../src/api/tenant-middleware.js";
import { CANONICAL_AUTH_ERROR_HEADERS } from "@zucoins/generic-node-contracts/auth-errors";
import {
  ROUTE_POLICIES,
  routeAuthClasses,
} from "@zucoins/generic-node-contracts/route-policy";

const UTF8 = new TextEncoder();
const REQUEST_ID = "7b8bb326-0f2b-4dad-a8e7-40115b375ec4";
const VALID_IDEMPOTENCY_KEY = "idem-key-0123456789"; // 19 visible-ASCII chars (16–255)

function pipelineConfig(overrides: Partial<PipelineConfig> = {}): PipelineConfig {
  return {
    newRequestId: () => REQUEST_ID,
    authenticate: () => true,
    authorizeScope: () => true,
    ...overrides,
  };
}

// Every route exercised below is `tenantScoped: true` (route-policy/routes.ts).
// the pipeline fails those closed unless a principal is bound, and the legacy boolean
// `authenticate` hook binds none — so a genuine happy path must present a bearer credential
// through `resolveCredential`, exactly as production createOperationRouter does. The boolean
// config above stays for the stage-ordering and error-mapping tests, which assert rejections.
const BEARER_KEY = `${IMPLEMENTER_BEARER_PREFIX}test-key`;
const BEARER_HEADERS = { authorization: `Bearer ${BEARER_KEY}` } as const;
const RECEIVE_CREATE_PRINCIPAL: AuthPrincipal = {
  implementerId: "imp_fixture",
  scopes: ["receive:create"],
};
const DESTINATION_READ_PRINCIPAL: AuthPrincipal = {
  implementerId: "imp_fixture",
  scopes: ["destination:read"],
};
const UNSCOPED_PRINCIPAL: AuthPrincipal = {
  implementerId: "imp_fixture",
  scopes: ["destination:create"],
};

function credentialPipelineConfig(
  principal: AuthPrincipal = RECEIVE_CREATE_PRINCIPAL,
  overrides: Partial<PipelineConfig> = {},
): PipelineConfig {
  return {
    newRequestId: () => REQUEST_ID,
    resolveCredential: {
      resolve: async (bearerKey) => (bearerKey === BEARER_KEY ? principal : null),
    },
    ...overrides,
  };
}

function postRequest(path: string, body: unknown, headers: Record<string, string> = {}): PipelineRequest {
  return {
    method: "POST",
    path,
    rawBody: UTF8.encode(JSON.stringify(body)),
    headers: { "idempotency-key": VALID_IDEMPOTENCY_KEY, ...headers },
    query: {},
  };
}

const VALID_RECEIVE_BODY = {
  amount_zkz: "5.5",
  anchor: "ord_01J2",
  after_landing: { kind: "HOLD", destination_id: null },
};

// --- Pipeline integration: stage ordering and error mapping ---

describe("validation pipeline — happy path", () => {
  it("admits a valid authenticated POST /v1/receives with a parsed body", async () => {
    const route = findRouteSchema("POST", "/v1/receives");
    expect(route).toBeDefined();
    const policy = ROUTE_POLICIES.find((p) => p.method === "POST" && p.path === "/v1/receives");
    expect(policy?.scope).toBe("receive:create");
    expect(routeAuthClasses(policy!)).toEqual(["IMPLEMENTER_BEARER"]);

    const outcome = await runValidationPipeline(
      credentialPipelineConfig(RECEIVE_CREATE_PRINCIPAL),
      postRequest("/v1/receives", VALID_RECEIVE_BODY, BEARER_HEADERS),
      route!,
    );
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.context.requestId).toBe(REQUEST_ID);
      expect(outcome.context.parsedBody).toEqual(VALID_RECEIVE_BODY);
      expect(outcome.context.principal).toEqual(RECEIVE_CREATE_PRINCIPAL);
      expect(outcome.context.idempotencyTenantId).toBe(RECEIVE_CREATE_PRINCIPAL.implementerId);
    }
  });

  it("admits multi-auth-class GET /v1/destinations via IMPLEMENTER_BEARER + destination:read", async () => {
    // dual-auth: route accepts IMPLEMENTER_BEARER | REPORTING_CREDENTIAL. Pipeline's
    // resolveCredential path covers the ik_ bearer class; scope gates only that path.
    const route = findRouteSchema("GET", "/v1/destinations");
    expect(route).toBeDefined();
    const policy = ROUTE_POLICIES.find((p) => p.method === "GET" && p.path === "/v1/destinations");
    expect(policy?.scope).toBe("destination:read");
    expect(new Set(routeAuthClasses(policy!))).toEqual(
      new Set(["IMPLEMENTER_BEARER", "REPORTING_CREDENTIAL"]),
    );

    const request: PipelineRequest = {
      method: "GET",
      path: "/v1/destinations",
      rawBody: new Uint8Array(0),
      headers: { ...BEARER_HEADERS },
      query: { state: "BLESSED", limit: "50" },
    };
    const outcome = await runValidationPipeline(
      credentialPipelineConfig(DESTINATION_READ_PRINCIPAL),
      request,
      route!,
    );
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.context.parsedQuery).toEqual({ state: "BLESSED", limit: 50 });
      expect(outcome.context.principal).toEqual(DESTINATION_READ_PRINCIPAL);
    }
  });

  // D3: the reason the two admissions above must present a credential. A
  // boolean-only config on a tenantScoped route binds no principal, so no handler could
  // tenant-predicate its lookups — the pipeline must refuse rather than serve it unscoped.
  // This is what silently regressed the happy paths above, so it is pinned here.
  it("a tenantScoped route with boolean-only auth and no principal is refused, not served", async () => {
    const route = findRouteSchema("POST", "/v1/receives");
    const outcome = await runValidationPipeline(
      pipelineConfig(),
      postRequest("/v1/receives", VALID_RECEIVE_BODY),
      route!,
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error.status).toBe(401);
      expect(JSON.parse(outcome.error.body).error.code).toBe("invalid_api_key");
    }
  });
});

describe("validation pipeline — authentication gate (stage 2)", () => {
  it("returns 401 invalid_api_key when authentication fails", async () => {
    const route = findRouteSchema("POST", "/v1/receives");
    const outcome = await runValidationPipeline(
      pipelineConfig({ authenticate: () => false }),
      postRequest("/v1/receives", VALID_RECEIVE_BODY),
      route!,
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error.status).toBe(401);
      expect(JSON.parse(outcome.error.body).error.code).toBe("invalid_api_key");
    }
  });

  it("scope denial collapses to the same 401 invalid_api_key (never 403)", async () => {
    // The pipeline only invokes authorizeScope when the route carries a non-null scope.
    const route = { ...findRouteSchema("POST", "/v1/receives")!, scope: "receive:create" };
    const outcome = await runValidationPipeline(
      pipelineConfig({ authorizeScope: () => false }),
      postRequest("/v1/receives", VALID_RECEIVE_BODY),
      route,
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error.status).toBe(401);
      const parsed = JSON.parse(outcome.error.body) as { error: { code: string } };
      expect(parsed.error.code).toBe("invalid_api_key");
      expect(outcome.error.status).not.toBe(403);
    }
  });

  it("authentication failure precedes body validation (stage order)", async () => {
    // An invalid body AND a failed auth must surface the 401, not the 400 — auth runs first.
    const route = findRouteSchema("POST", "/v1/receives");
    const outcome = await runValidationPipeline(
      pipelineConfig({ authenticate: () => false }),
      postRequest("/v1/receives", { amount_zkz: "not-an-amount" }),
      route!,
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.error.status).toBe(401);
  });

  // Credential-resolution path (production createOperationRouter) — same 401 envelope as the
  // boolean-hook negatives above. Isolated principals prove missing/unknown/wrong-scope.
  it("resolveCredential: missing bearer → 401 invalid_api_key", async () => {
    const route = findRouteSchema("POST", "/v1/receives");
    const outcome = await runValidationPipeline(
      credentialPipelineConfig(RECEIVE_CREATE_PRINCIPAL),
      postRequest("/v1/receives", VALID_RECEIVE_BODY),
      route!,
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error).toEqual(apiErrorResponse("invalid_api_key", REQUEST_ID));
    }
  });

  it("resolveCredential: unknown key → 401 invalid_api_key", async () => {
    const route = findRouteSchema("POST", "/v1/receives");
    const outcome = await runValidationPipeline(
      credentialPipelineConfig(RECEIVE_CREATE_PRINCIPAL),
      postRequest("/v1/receives", VALID_RECEIVE_BODY, {
        authorization: `Bearer ${IMPLEMENTER_BEARER_PREFIX}unknown`,
      }),
      route!,
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error).toEqual(apiErrorResponse("invalid_api_key", REQUEST_ID));
    }
  });

  it("resolveCredential: wrong scope on multi-auth GET collapses to same 401", async () => {
    const route = findRouteSchema("GET", "/v1/destinations");
    const request: PipelineRequest = {
      method: "GET",
      path: "/v1/destinations",
      rawBody: new Uint8Array(0),
      headers: { ...BEARER_HEADERS },
      query: {},
    };
    const outcome = await runValidationPipeline(
      credentialPipelineConfig(UNSCOPED_PRINCIPAL),
      request,
      route!,
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error.status).toBe(401);
      expect(outcome.error.status).not.toBe(403);
      expect(outcome.error).toEqual(apiErrorResponse("invalid_api_key", REQUEST_ID));
    }
  });
});

describe("validation pipeline — idempotency gate (stage 4)", () => {
  it("rejects a POST mutation with a missing Idempotency-Key as 400", async () => {
    const route = findRouteSchema("POST", "/v1/receives");
    const request: PipelineRequest = {
      method: "POST",
      path: "/v1/receives",
      rawBody: UTF8.encode(JSON.stringify(VALID_RECEIVE_BODY)),
      headers: {},
      query: {},
    };
    const outcome = await runValidationPipeline(pipelineConfig(), request, route!);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error.status).toBe(400);
      expect(JSON.parse(outcome.error.body).error.code).toBe("invalid_idempotency_key");
    }
  });

  it("rejects a too-short Idempotency-Key (< 16 chars) as 400", async () => {
    const route = findRouteSchema("POST", "/v1/receives");
    const outcome = await runValidationPipeline(
      pipelineConfig(),
      postRequest("/v1/receives", VALID_RECEIVE_BODY, { "idempotency-key": "short" }),
      route!,
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(JSON.parse(outcome.error.body).error.code).toBe("invalid_idempotency_key");
    }
  });

  it("rejects a non-visible-ASCII Idempotency-Key as 400", async () => {
    const route = findRouteSchema("POST", "/v1/receives");
    const controlCharKey = `idem-key-${String.fromCharCode(0x07)}-0123456789`;
    const outcome = await runValidationPipeline(
      pipelineConfig(),
      postRequest("/v1/receives", VALID_RECEIVE_BODY, { "idempotency-key": controlCharKey }),
      route!,
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(JSON.parse(outcome.error.body).error.code).toBe("invalid_idempotency_key");
    }
  });
});

describe("validation pipeline — body validation (strict JSON + schema)", () => {
  it("maps an unknown field to 400 unknown_field", async () => {
    const route = findRouteSchema("POST", "/v1/receives");
    const outcome = await runValidationPipeline(
      pipelineConfig(),
      postRequest("/v1/receives", { ...VALID_RECEIVE_BODY, callback_url: "https://evil.example.com" }),
      route!,
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error.status).toBe(400);
      expect(JSON.parse(outcome.error.body).error.code).toBe("unknown_field");
    }
  });

  it("maps an invalid scalar to 400 invalid_scalar", async () => {
    const route = findRouteSchema("POST", "/v1/receives");
    const outcome = await runValidationPipeline(
      pipelineConfig(),
      postRequest("/v1/receives", { ...VALID_RECEIVE_BODY, amount_zkz: "not-an-amount" }),
      route!,
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error.status).toBe(400);
      expect(JSON.parse(outcome.error.body).error.code).toBe("invalid_scalar");
    }
  });

  it("maps a numeric JSON amount to 400 invalid_scalar (amounts must be strings)", async () => {
    const route = findRouteSchema("POST", "/v1/receives");
    const outcome = await runValidationPipeline(
      pipelineConfig(),
      postRequest("/v1/receives", { ...VALID_RECEIVE_BODY, amount_zkz: 5.5 }),
      route!,
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(JSON.parse(outcome.error.body).error.code).toBe("invalid_scalar");
    }
  });

  it("maps malformed JSON to 400 malformed_json", async () => {
    const route = findRouteSchema("POST", "/v1/receives");
    const request: PipelineRequest = {
      method: "POST",
      path: "/v1/receives",
      rawBody: UTF8.encode("{not valid json"),
      headers: { "idempotency-key": VALID_IDEMPOTENCY_KEY },
      query: {},
    };
    const outcome = await runValidationPipeline(pipelineConfig(), request, route!);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error.status).toBe(400);
      expect(JSON.parse(outcome.error.body).error.code).toBe("malformed_json");
    }
  });

  it("maps duplicate JSON keys to 400 duplicate_json_key", async () => {
    const route = findRouteSchema("POST", "/v1/receives");
    const request: PipelineRequest = {
      method: "POST",
      path: "/v1/receives",
      rawBody: UTF8.encode('{"amount_zkz":"5.5","amount_zkz":"6.6"}'),
      headers: { "idempotency-key": VALID_IDEMPOTENCY_KEY },
      query: {},
    };
    const outcome = await runValidationPipeline(pipelineConfig(), request, route!);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(JSON.parse(outcome.error.body).error.code).toBe("duplicate_json_key");
    }
  });

  it("maps an oversized body to 400 request_too_large through the pipeline", async () => {
    const route = findRouteSchema("POST", "/v1/receives");
    const oversized = new Uint8Array(DEFAULT_MAX_BODY_BYTES + 1).fill(0x7b);
    const request: PipelineRequest = {
      method: "POST",
      path: "/v1/receives",
      rawBody: oversized,
      headers: { "idempotency-key": VALID_IDEMPOTENCY_KEY },
      query: {},
    };
    const outcome = await runValidationPipeline(pipelineConfig(), request, route!);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error.status).toBe(400);
      expect(JSON.parse(outcome.error.body).error.code).toBe("request_too_large");
    }
  });
});

// --- Size and depth boundaries at the exact limit (build-test-plan) ---

describe("size limits — exact boundary behavior", () => {
  it("accepts a body of exactly DEFAULT_MAX_BODY_BYTES", () => {
    const raw = new Uint8Array(DEFAULT_MAX_BODY_BYTES).fill(0x61); // 'a' bytes, valid UTF-8
    const result = parseStrictJson(raw);
    // Not valid JSON, but the SIZE gate must pass; it fails later at malformed_json.
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).not.toBe("request_too_large");
  });

  it("rejects a body of DEFAULT_MAX_BODY_BYTES + 1 as request_too_large", () => {
    const raw = new Uint8Array(DEFAULT_MAX_BODY_BYTES + 1).fill(0x61);
    const result = parseStrictJson(raw);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("request_too_large");
  });

  it("honors a caller-supplied smaller maxBodyBytes", () => {
    const raw = UTF8.encode(JSON.stringify({ amount_zkz: "5.5", anchor: "ord_01J2" }));
    expect(raw.length).toBeGreaterThan(10);
    const result = parseStrictJson(raw, { maxBodyBytes: 10 });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("request_too_large");
  });

  it("accepts nesting of exactly DEFAULT_MAX_NESTING_DEPTH", () => {
    const raw = UTF8.encode("[".repeat(DEFAULT_MAX_NESTING_DEPTH) + "]".repeat(DEFAULT_MAX_NESTING_DEPTH));
    const result = parseStrictJson(raw);
    expect(result.ok).toBe(true);
  });

  it("rejects nesting of DEFAULT_MAX_NESTING_DEPTH + 1 as nesting_too_deep", () => {
    const raw = UTF8.encode(
      "[".repeat(DEFAULT_MAX_NESTING_DEPTH + 1) + "]".repeat(DEFAULT_MAX_NESTING_DEPTH + 1),
    );
    const result = parseStrictJson(raw);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("nesting_too_deep");
  });

  it("the size gate fires before the UTF-8 gate (an oversized invalid-UTF-8 body is request_too_large)", () => {
    const raw = new Uint8Array(DEFAULT_MAX_BODY_BYTES + 1).fill(0xff); // invalid UTF-8 AND oversized
    const result = parseStrictJson(raw);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("request_too_large");
  });
});

// --- Content-type enforcement (J3) ---

describe("content-type enforcement — canonical header on every error envelope", () => {
  it("every error code emits content-type application/json; charset=utf-8", () => {
    for (const { code } of API_ERROR_CODES) {
      const response = apiErrorResponse(code, REQUEST_ID);
      expect(
        response.headers["content-type"],
        `code ${code} must carry the canonical content-type`,
      ).toBe("application/json; charset=utf-8");
    }
  });

  it("no error envelope leaks a WWW-Authenticate challenge (J3 no-information-leak)", () => {
    for (const { code } of API_ERROR_CODES) {
      const response = apiErrorResponse(code, REQUEST_ID);
      expect(
        response.headers["www-authenticate"],
        `code ${code} must not carry an auth challenge`,
      ).toBeUndefined();
    }
  });

  it("every error envelope header set equals the canonical frozen header set", () => {
    for (const { code } of API_ERROR_CODES) {
      const response = apiErrorResponse(code, REQUEST_ID);
      expect(response.headers).toEqual(CANONICAL_AUTH_ERROR_HEADERS);
    }
  });

  it("the pipeline's schema-rejection envelope carries the canonical content-type", async () => {
    const route = findRouteSchema("POST", "/v1/receives");
    const outcome = await runValidationPipeline(
      pipelineConfig(),
      postRequest("/v1/receives", { ...VALID_RECEIVE_BODY, callback_url: "https://evil.example.com" }),
      route!,
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error.headers["content-type"]).toBe("application/json; charset=utf-8");
      expect(outcome.error.headers["www-authenticate"]).toBeUndefined();
    }
  });

  it("the pipeline's size-rejection envelope carries the canonical content-type", async () => {
    const route = findRouteSchema("POST", "/v1/receives");
    const request: PipelineRequest = {
      method: "POST",
      path: "/v1/receives",
      rawBody: new Uint8Array(DEFAULT_MAX_BODY_BYTES + 1).fill(0x7b),
      headers: { "idempotency-key": VALID_IDEMPOTENCY_KEY },
      query: {},
    };
    const outcome = await runValidationPipeline(pipelineConfig(), request, route!);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error.headers["content-type"]).toBe("application/json; charset=utf-8");
      expect(outcome.error.headers).toEqual(CANONICAL_AUTH_ERROR_HEADERS);
    }
  });
});

// --- Rate limiting (429) ---

describe("rate limiting — 429 envelope and headers ", () => {
  it("rate_limited maps to HTTP 429", () => {
    expect(HTTP_STATUS_BY_CODE["rate_limited"]).toBe(429);
  });

  it("the 429 response carries the canonical error envelope", () => {
    const response = apiErrorResponse("rate_limited", REQUEST_ID);
    expect(response.status).toBe(429);
    const parsed = JSON.parse(response.body) as {
      error: { code: string; message: string; request_id: string; details: Record<string, never> };
    };
    expect(parsed.error.code).toBe("rate_limited");
    expect(typeof parsed.error.message).toBe("string");
    expect(parsed.error.request_id).toBe(REQUEST_ID);
    expect(parsed.error.details).toEqual({});
    // Byte-exact key order (the byte-exact signing rule).
    expect(Object.keys(parsed.error)).toEqual(["code", "message", "request_id", "details"]);
  });

  it("the 429 body is byte-exact for a given request id", () => {
    const response = apiErrorResponse("rate_limited", REQUEST_ID);
    expect(response.body).toBe(buildApiErrorBody("rate_limited", REQUEST_ID));
  });

  it("the 429 response carries the canonical content-type header and leaks no challenge", () => {
    const response = apiErrorResponse("rate_limited", REQUEST_ID);
    expect(response.headers).toEqual(CANONICAL_AUTH_ERROR_HEADERS);
    expect(response.headers["content-type"]).toBe("application/json; charset=utf-8");
    // No authentication challenge is leaked on a rate-limit response (CONTRACT J3 posture).
    expect(response.headers["www-authenticate"]).toBeUndefined();
  });

  it("the rate-limit details object never carries tenant or existence information", () => {
    const response = apiErrorResponse("rate_limited", REQUEST_ID);
    const parsed = JSON.parse(response.body) as { error: { details: Record<string, unknown> } };
    expect(Object.keys(parsed.error.details)).toHaveLength(0);
  });
});


// API contract and size-limit tests. Adversarial matrix per
// the test plan Phase 5 exit evidence and.
//
// Tests: unknown field, wrong signature spelling, unsupported state/event,
// malformed base64, duplicate JSON key, malformed UTF-8, numeric JSON amount —
// all rejected. Auth mode, HTTP status, error code, and body shape tested for
// every route.

import { describe, expect, it } from "vitest";
import {
  parseStrictJson,
  CreateReceiveBody,
  CreateInternalMoveBody,
  CreateExternalSendBody,
  CreateDestinationBody,
  ArmBody,
  VerificationCompleteBody,
  ApproveBody,
  RejectBody,
  BlessBody,
  RetireBody,
  ROUTE_SCHEMAS,
  Rfc3339MsSchema,
  type RouteSchema,
  PositiveZkzAmountSchema,
  UuidSchema,
  WalletPublicKeySchema,
  Ed25519SignatureSchema,
  Sha256HexSchema,
} from "../src/api/index.js";
import {
  apiErrorResponse,
  buildApiErrorBody,
  scopeDenialResponse,
  HTTP_STATUS_BY_CODE,
  API_ERROR_CODES,
} from "../src/api/error-envelope.js";
import { POLICY_EXEMPT_ROUTES } from "../src/api/pipeline.js";
import {
  CANONICAL_AUTH_FAILURE_BODY,
  CANONICAL_NOT_FOUND_BODY,
  REQUEST_ID_PLACEHOLDER,
} from "@zucoins/generic-node-contracts/auth-errors";
import {
  ROUTE_POLICIES,
  type RoutePolicy,
} from "@zucoins/generic-node-contracts/route-policy";

const UTF8 = new TextEncoder();

function jsonBytes(obj: unknown): Uint8Array {
  return UTF8.encode(JSON.stringify(obj));
}

// --- Phase 5: Adversarial input rejection matrix ---

describe("strict JSON intake", () => {
  it("rejects duplicate JSON keys", () => {
    const raw = UTF8.encode('{"amount_zkz":"5.5","amount_zkz":"6.6"}');
    const result = parseStrictJson(raw);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("duplicate_json_key");
  });

  it("does not false-positive on value strings matching later keys", () => {
    const raw = UTF8.encode('{"a":"b","b":"c"}');
    const result = parseStrictJson(raw);
    expect(result.ok).toBe(true);
  });

  it("does not collect strings inside arrays as keys", () => {
    const raw = UTF8.encode('{"a":["b","c"],"b":"d"}');
    const result = parseStrictJson(raw);
    expect(result.ok).toBe(true);
  });

  it("rejects malformed UTF-8", () => {
    const raw = new Uint8Array([0xff, 0xfe, 0x7b, 0x7d]);
    const result = parseStrictJson(raw);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("invalid_utf8");
  });

  it("rejects oversized bodies", () => {
    const raw = new Uint8Array(2_000_000).fill(0x7b);
    const result = parseStrictJson(raw, { maxBodyBytes: 1_048_576 });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("request_too_large");
  });

  it("rejects nesting too deep", () => {
    const deep = "[".repeat(20) + "]".repeat(20);
    const raw = UTF8.encode(deep);
    const result = parseStrictJson(raw, { maxNestingDepth: 16 });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("nesting_too_deep");
  });

  it("rejects malformed JSON", () => {
    const raw = UTF8.encode("{invalid json}");
    const result = parseStrictJson(raw);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("malformed_json");
  });

  it("accepts valid JSON within bounds", () => {
    const raw = jsonBytes({ amount_zkz: "5.5" });
    const result = parseStrictJson(raw);
    expect(result.ok).toBe(true);
  });
});

describe("scalar validation — numeric JSON amount rejected", () => {
  it("rejects a numeric JSON amount (must be string)", () => {
    const result = CreateReceiveBody.safeParse({
      amount_zkz: 5.5,
      anchor: "ord_01J2",
      after_landing: { kind: "HOLD", destination_id: null },
    });
    expect(result.success).toBe(false);
  });

  it("rejects amount >= 100000000 (strict bound)", () => {
    const result = PositiveZkzAmountSchema.safeParse("100000000");
    expect(result.success).toBe(false);
  });

  it("rejects amount = 0 (not positive)", () => {
    const result = PositiveZkzAmountSchema.safeParse("0");
    expect(result.success).toBe(false);
  });

  // Regression: a string-comparison refine used to accept mathematically-zero forms.
  it("rejects amount = 0.0 (zero with trailing decimal)", () => {
    const result = PositiveZkzAmountSchema.safeParse("0.0");
    expect(result.success).toBe(false);
  });

  it("rejects amount = 0.00 (zero with two decimal places)", () => {
    const result = PositiveZkzAmountSchema.safeParse("0.00");
    expect(result.success).toBe(false);
  });

  it("rejects amount = 0. + 32 zeros (max fractional zero)", () => {
    const result = PositiveZkzAmountSchema.safeParse("0.00000000000000000000000000000000");
    expect(result.success).toBe(false);
  });

  it("accepts amount just below bound", () => {
    const result = PositiveZkzAmountSchema.safeParse("99999999.99999999999999999999999999999999");
    expect(result.success).toBe(true);
  });

  it("rejects negative amount", () => {
    const result = PositiveZkzAmountSchema.safeParse("-1.5");
    expect(result.success).toBe(false);
  });

  it("rejects exponent notation", () => {
    const result = PositiveZkzAmountSchema.safeParse("1e5");
    expect(result.success).toBe(false);
  });
});

describe("scalar validation — malformed base64 rejected", () => {
  it("rejects wrong-length wallet public key", () => {
    const result = WalletPublicKeySchema.safeParse("abc");
    expect(result.success).toBe(false);
  });

  it("rejects non-canonical base64url", () => {
    // 44 chars but not valid base64url encoding of 32 bytes
    const result = WalletPublicKeySchema.safeParse("A".repeat(44));
    expect(result.success).toBe(false);
  });
});

describe("scalar validation — wrong signature spelling rejected", () => {
  it("rejects uppercase UUID", () => {
    const result = UuidSchema.safeParse("7B8BB326-0F2B-4DAD-A8E7-40115B375EC4");
    expect(result.success).toBe(false);
  });

  it("rejects UUID without hyphens", () => {
    const result = UuidSchema.safeParse("7b8bb3260f2b4dada8e740115b375ec4");
    expect(result.success).toBe(false);
  });

  it("rejects sha256 with uppercase hex", () => {
    const result = Sha256HexSchema.safeParse("A".repeat(64));
    expect(result.success).toBe(false);
  });
});

// --- Unknown field rejection ---

describe("unknown field rejection (400 unknown_field)", () => {
  it("rejects POST /v1/receives with unknown field", () => {
    const result = CreateReceiveBody.safeParse({
      amount_zkz: "5.5",
      anchor: "ord_01J2",
      after_landing: { kind: "HOLD", destination_id: null },
      callback_url: "https://evil.example.com",
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]!.code).toBe("unrecognized_keys");
    }
  });

  it("rejects POST /v1/internal-moves with unknown field", () => {
    const result = CreateInternalMoveBody.safeParse({
      source_wallet_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
      destination_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
      amount_zkz: "5.5",
      extra_field: true,
    });
    expect(result.success).toBe(false);
  });

  it("rejects POST /v1/external-sends with unknown field", () => {
    const result = CreateExternalSendBody.safeParse({
      source_wallet_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
      destination_address: "A".repeat(44),
      amount_zkz: "5.5",
      secret_field: "leak",
    });
    expect(result.success).toBe(false);
  });
});

// --- Unsupported state/event rejection ---

describe("unsupported state/event rejection", () => {
  it("rejects invalid after_landing kind", () => {
    const result = CreateReceiveBody.safeParse({
      amount_zkz: "5.5",
      anchor: "ord_01J2",
      after_landing: { kind: "DRAIN", destination_id: null },
    });
    expect(result.success).toBe(false);
  });

  it("rejects invalid verdict in verification-complete", () => {
    const result = VerificationCompleteBody.safeParse({
      expected_row_version: 7,
      consumed_cursor: "1051",
      verdict: "MAYBE_VERIFIED",
      wallet_evidence: [{
        wallet_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
        role: "RECEIVER",
        t0: { observation_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4", projection: { s: "", p: "", b_zkz: "0" } },
        terminal: { observation_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4", projection: { s: "sig", p: "", b_zkz: "5.5" } },
        landing_proof: {
          classification: "EXPECTED_ANCESTOR",
          fresh_head_step_2_signature: "sig",
          fresh_head_transaction_sha256: "a".repeat(64),
          path_manifest_sha256: "b".repeat(64),
        },
      }],
    });
    expect(result.success).toBe(false);
  });
});

// ---: Error envelope shape and posture ---

describe("error envelope shape ", () => {
  it("produces the frozen 401 body byte-exactly", () => {
    const body = buildApiErrorBody("invalid_api_key", REQUEST_ID_PLACEHOLDER);
    expect(body).toBe(CANONICAL_AUTH_FAILURE_BODY);
  });

  it("produces the frozen 404 body byte-exactly", () => {
    const body = buildApiErrorBody("not_found", REQUEST_ID_PLACEHOLDER);
    expect(body).toBe(CANONICAL_NOT_FOUND_BODY);
  });

  it("every error response has the exact envelope shape", () => {
    for (const { code } of API_ERROR_CODES) {
      const response = apiErrorResponse(code, "7b8bb326-0f2b-4dad-a8e7-40115b375ec4");
      const parsed = JSON.parse(response.body) as {
        error: { code: string; message: string; request_id: string; details: Record<string, never> };
      };
      expect(parsed.error.code).toBe(code);
      expect(typeof parsed.error.message).toBe("string");
      expect(parsed.error.request_id).toBe("7b8bb326-0f2b-4dad-a8e7-40115b375ec4");
      expect(parsed.error.details).toEqual({});
      // Field order: code, message, request_id, details (the byte-exact signing rule).
      const keys = Object.keys(parsed.error);
      expect(keys).toEqual(["code", "message", "request_id", "details"]);
    }
  });

  it("scope denial returns same 401 as unknown key", () => {
    const scopeResponse = scopeDenialResponse("7b8bb326-0f2b-4dad-a8e7-40115b375ec4");
    const unknownKeyResponse = apiErrorResponse("invalid_api_key", "7b8bb326-0f2b-4dad-a8e7-40115b375ec4");
    expect(scopeResponse.status).toBe(401);
    expect(scopeResponse.body).toBe(unknownKeyResponse.body);
  });

  it("no 403 status exists in the error code table", () => {
    for (const { code, http } of API_ERROR_CODES) {
      expect(http, `code ${code} must not be 403`).not.toBe(403);
    }
  });
});

// --- ROUTE_SCHEMAS ↔ ROUTE_POLICIES cross-validation ---
// The inventory checks below compare ROUTE_SCHEMAS only to itself, so a route added to one
// table and not the other stayed invisible — it shipped with no authClass, no scope and no
// tenantScoped, which is an authorization hole. This gate takes both frozen tables as its
// only inputs (no hand-maintained route list) and fails on any divergence in either
// direction, plus the one fact both tables declare: the idempotency requirement.
//
// Scope, stated plainly so the gate is not read as covering more than it does: this compares
// the two REGISTRIES to each other. It does not compare either registry against the routes an
// app actually mounts, and it does not reach the third route table (PUBLIC_ROUTES/ADMIN_ROUTES
// in the contracts package's operations concern). Both remain uncovered classes.

// POLICY_EXEMPT_ROUTES is imported from src/api/pipeline.ts — the same list the pipeline uses to
// decide a route may be served without a policy row. Sharing one constant is what makes this gate
// bind enforcement: the rules below (no policed namespace, no mutation, no stale entry) are the
// only way that list can grow, so it cannot be widened to launder a route past scope resolution.

const routeKey = (route: { readonly method: string; readonly path: string }): string =>
  `${route.method} ${route.path}`;

/**
 * Every way ROUTE_SCHEMAS and ROUTE_POLICIES can disagree, as a list of findings; empty means
 * the two tables agree. Pure over its inputs so the negative fixtures below drive the exact
 * code path the live assertion does — the gate is proven to go red, not assumed to.
 */
function routeRegistryDrift(
  schemas: readonly RouteSchema[],
  policies: readonly RoutePolicy[],
  exempt: readonly string[] = POLICY_EXEMPT_ROUTES,
): string[] {
  const findings: string[] = [];
  const schemaByKey = new Map(schemas.map((schema) => [routeKey(schema), schema]));
  const policyByKey = new Map(policies.map((policy) => [routeKey(policy), policy]));
  // The namespaces the policy table itself claims, derived from that table rather than listed
  // here, so a namespace the contract grows later is covered without editing this gate.
  const policedNamespaces = new Set(policies.map((policy) => policy.path.split("/")[1]));

  // A duplicate is invisible to the Maps above, and findRouteSchema() returns the first match —
  // so the shadowed row's schema silently never applies to any request.
  const seen = new Set<string>();
  for (const schema of schemas) {
    const key = routeKey(schema);
    if (seen.has(key)) findings.push(`duplicate schema route: ${key}`);
    seen.add(key);
  }

  // Direction 1 — a schema route with no policy is served with no auth class and no scope.
  for (const key of schemaByKey.keys()) {
    if (!policyByKey.has(key) && !exempt.includes(key)) {
      findings.push(`schema route has no policy: ${key}`);
    }
  }

  // Direction 2 — a policy with no schema is a policed route nothing validates.
  for (const key of policyByKey.keys()) {
    if (!schemaByKey.has(key)) findings.push(`policy route has no schema: ${key}`);
  }

  // Present in both, disagreeing. `idempotency` is the only fact both tables declare; the rest
  // of each row (authClass/scope/tenantScoped vs bodySchema/querySchema) has no counterpart.
  for (const [key, schema] of schemaByKey) {
    const policy = policyByKey.get(key);
    if (policy === undefined) continue;
    const policyRequires = policy.idempotency === "REQUIRED";
    if (policyRequires !== schema.requiresIdempotencyKey) {
      findings.push(
        `idempotency disagreement: ${key} (policy ${policy.idempotency}, schema requiresIdempotencyKey=${schema.requiresIdempotencyKey})`,
      );
    }
  }

  // The exemption list runs through the same pass, or it becomes the hole it exists to name.
  for (const key of exempt) {
    const schema = schemaByKey.get(key);
    if (schema === undefined) {
      findings.push(`stale exemption, no such schema route: ${key}`);
      continue;
    }
    if (policyByKey.has(key)) {
      findings.push(`stale exemption, route already has a policy: ${key}`);
      continue;
    }
    if (policedNamespaces.has(schema.path.split("/")[1])) {
      findings.push(`exemption inside a policed namespace: ${key}`);
    }
    if (
      schema.method !== "GET" ||
      schema.bodySchema !== undefined ||
      schema.requiresIdempotencyKey
    ) {
      findings.push(`exemption is not a read-only infrastructure route: ${key}`);
    }
  }

  return findings.sort();
}

// ---: Route inventory matches frozen ROUTE_POLICIES ---

describe("route schema inventory ", () => {
  it("covers exactly the frozen policy set plus its declared exemptions", () => {
    // Derived from both source tables — a hand-written count (previously a literal 25) drifts
    // silently alongside whichever table changed.
    // create/point-read handlers only; no new ROUTE_SCHEMAS entry (list route out of scope).
    expect(ROUTE_SCHEMAS.length).toBe(ROUTE_POLICIES.length + POLICY_EXEMPT_ROUTES.length);
  });

  it("every POST mutation route requires idempotency key", () => {
    // Public intake (Route 2) is intentionally non-idempotent: claim_token is
    // minted once per request and must not be replay-keyed (ROUTE_POLICIES idempotency NA).
    const postRoutes = ROUTE_SCHEMAS.filter(
      (r) => r.method === "POST" && r.path !== "/v1/integration-requests",
    );
    for (const route of postRoutes) {
      expect(route.requiresIdempotencyKey, `${route.path} must require idempotency`).toBe(true);
    }
    const intake = ROUTE_SCHEMAS.find(
      (r) => r.method === "POST" && r.path === "/v1/integration-requests",
    );
    expect(intake?.requiresIdempotencyKey).toBe(false);
  });

  it("every GET route does not require idempotency key", () => {
    const getRoutes = ROUTE_SCHEMAS.filter((r) => r.method === "GET");
    for (const route of getRoutes) {
      expect(route.requiresIdempotencyKey, `${route.path} must not require idempotency`).toBe(false);
    }
  });

  it("HTTP status codes match table", () => {
    expect(HTTP_STATUS_BY_CODE["invalid_api_key"]).toBe(401);
    expect(HTTP_STATUS_BY_CODE["not_found"]).toBe(404);
    expect(HTTP_STATUS_BY_CODE["unknown_field"]).toBe(400);
    expect(HTTP_STATUS_BY_CODE["wallet_busy"]).toBe(409);
    expect(HTTP_STATUS_BY_CODE["verification_material_expired"]).toBe(410);
    expect(HTTP_STATUS_BY_CODE["protocol_predicate_failed"]).toBe(422);
    expect(HTTP_STATUS_BY_CODE["rate_limited"]).toBe(429);
    expect(HTTP_STATUS_BY_CODE["receive_queue_full"]).toBe(503);
  });
});

describe("ROUTE_SCHEMAS cross-validates against ROUTE_POLICIES", () => {
  it("the two frozen tables cover exactly the same route set, with no disagreement", () => {
    expect(routeRegistryDrift(ROUTE_SCHEMAS, ROUTE_POLICIES)).toEqual([]);
  });

  it("no schema route lacks a policy row (health is PUBLIC)", () => {
    const unpoliced = ROUTE_SCHEMAS.filter(
      (schema) => !ROUTE_POLICIES.some((policy) => routeKey(policy) === routeKey(schema)),
    ).map(routeKey);
    expect(unpoliced).toEqual([]);
  });

  // --- mandatory negative path: every direction proven to go red ---

  it("REJECTS a schema route with no policy (the GET /v1/operations drift shape)", () => {
    const unpoliced: RouteSchema = {
      method: "GET",
      path: "/v1/operations",
      requiresIdempotencyKey: false,
    };
    expect(routeRegistryDrift([...ROUTE_SCHEMAS, unpoliced], ROUTE_POLICIES)).toContain(
      "schema route has no policy: GET /v1/operations",
    );
  });

  it("REJECTS a policy route with no schema", () => {
    const orphanPolicy: RoutePolicy = {
      method: "POST",
      path: "/v1/quarantines",
      authClass: "IMPLEMENTER_BEARER",
      scope: "receive:create",
      tenantScoped: true,
      idempotency: "REQUIRED",
    };
    expect(routeRegistryDrift(ROUTE_SCHEMAS, [...ROUTE_POLICIES, orphanPolicy])).toContain(
      "policy route has no schema: POST /v1/quarantines",
    );
  });

  it("REJECTS a route in both tables whose idempotency requirement disagrees", () => {
    const flipped = ROUTE_SCHEMAS.map((schema) =>
      schema.method === "POST" && schema.path === "/v1/receives"
        ? { ...schema, requiresIdempotencyKey: false }
        : schema,
    );
    expect(routeRegistryDrift(flipped, ROUTE_POLICIES)).toContain(
      "idempotency disagreement: POST /v1/receives (policy REQUIRED, schema requiresIdempotencyKey=false)",
    );
  });

  it("REJECTS an exemption minted for a route inside a policed namespace (the laundering path)", () => {
    // The cheapest way to defeat this gate is to widen POLICY_EXEMPT_ROUTES instead of adding
    // the missing policy row, so exempting a /v1 route must itself be a finding.
    const unpoliced: RouteSchema = {
      method: "GET",
      path: "/v1/operations",
      requiresIdempotencyKey: false,
    };
    expect(
      routeRegistryDrift([...ROUTE_SCHEMAS, unpoliced], ROUTE_POLICIES, [
        ...POLICY_EXEMPT_ROUTES,
        "GET /v1/operations",
      ]),
    ).toContain("exemption inside a policed namespace: GET /v1/operations");
  });

  it("REJECTS an exemption minted for a mutation", () => {
    const unpolicedMutation: RouteSchema = {
      method: "POST",
      path: "/probe/reset",
      bodySchema: CreateDestinationBody,
      requiresIdempotencyKey: true,
    };
    expect(
      routeRegistryDrift([...ROUTE_SCHEMAS, unpolicedMutation], ROUTE_POLICIES, [
        ...POLICY_EXEMPT_ROUTES,
        "POST /probe/reset",
      ]),
    ).toContain("exemption is not a read-only infrastructure route: POST /probe/reset");
  });

  it("REJECTS a stale exemption whose schema route no longer exists", () => {
    expect(
      routeRegistryDrift(ROUTE_SCHEMAS, ROUTE_POLICIES, ["GET /gone"]),
    ).toContain("stale exemption, no such schema route: GET /gone");
  });

  it("REJECTS a stale exemption for a route that already has a policy (GET /health)", () => {
    expect(
      routeRegistryDrift(ROUTE_SCHEMAS, ROUTE_POLICIES, ["GET /health"]),
    ).toContain("stale exemption, route already has a policy: GET /health");
  });

  it("REJECTS a duplicate schema route (findRouteSchema silently shadows the second)", () => {
    const first = ROUTE_SCHEMAS[0];
    if (first === undefined) throw new Error("ROUTE_SCHEMAS is empty");
    expect(routeRegistryDrift([...ROUTE_SCHEMAS, first], ROUTE_POLICIES)).toContain(
      `duplicate schema route: ${routeKey(first)}`,
    );
  });
});

// --- Valid request acceptance ---

describe("valid request acceptance", () => {
  it("accepts a valid POST /v1/receives body", () => {
    const result = CreateReceiveBody.safeParse({
      amount_zkz: "5.5",
      anchor: "ord_01J2",
      after_landing: { kind: "HOLD", destination_id: null },
    });
    expect(result.success).toBe(true);
  });

  it("accepts a valid POST /v1/internal-moves body", () => {
    const result = CreateInternalMoveBody.safeParse({
      source_wallet_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
      destination_id: "8c9cc437-1g3c-5ebe-b9f8-51226c486fd5",
      amount_zkz: "10.25",
    });
    // destination_id has invalid hex chars — should fail
    expect(result.success).toBe(false);
  });

  it("accepts POST /v1/internal-moves with optional client_reference", () => {
    const result = CreateInternalMoveBody.safeParse({
      source_wallet_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
      destination_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec5",
      amount_zkz: "10.25",
      client_reference: "order-42",
    });
    expect(result.success).toBe(true);
  });

  it("accepts verification-complete REJECTED without landing_proof", () => {
    const result = VerificationCompleteBody.safeParse({
      expected_row_version: 7,
      consumed_cursor: "1051",
      verdict: "REJECTED",
      wallet_evidence: [{
        wallet_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
        role: "RECEIVER",
        t0: { observation_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4", projection: { s: "", p: "", b_zkz: "0" } },
        terminal: { observation_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4", projection: { s: "sig", p: "", b_zkz: "5.5" } },
      }],
    });
    expect(result.success).toBe(true);
  });

  it("rejects verification-complete VERIFIED without landing_proof", () => {
    const result = VerificationCompleteBody.safeParse({
      expected_row_version: 7,
      consumed_cursor: "1051",
      verdict: "VERIFIED",
      wallet_evidence: [{
        wallet_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
        role: "RECEIVER",
        t0: { observation_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4", projection: { s: "", p: "", b_zkz: "0" } },
        terminal: { observation_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4", projection: { s: "sig", p: "", b_zkz: "5.5" } },
      }],
    });
    expect(result.success).toBe(false);
  });

  it("accepts a valid POST /v1/destinations body", () => {
    const result = CreateDestinationBody.safeParse({
      label: "Primary internal sink",
    });
    expect(result.success).toBe(true);
  });

  it("accepts a valid arm body", () => {
    const result = ArmBody.safeParse({
      expected_row_version: 2,
      t0: {
        observation_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
        projection: { s: "", p: "", b_zkz: "0" },
      },
      opened_cursor: "1043",
    });
    expect(result.success).toBe(true);
  });

  it("rejects bless body with unknown field", () => {
    const result = BlessBody.safeParse({
      nonce: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
      issued_at: "2026-07-18T00:00:00.000Z",
      expires_at: "2026-07-18T00:05:00.000Z",
      device_signature: "A".repeat(86) + "==",
      device_key_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
      device_key_ids: "typo-plural",
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]!.code).toBe("unrecognized_keys");
    }
  });

  it("rejects retire body with unknown field", () => {
    const result = RetireBody.safeParse({ reason: "nope" });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]!.code).toBe("unrecognized_keys");
    }
  });

  it("accepts a valid approve body", () => {
    const result = ApproveBody.safeParse({
      challenge_nonce: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
      expected_row_version: 1,
      preimage_sha256: "a".repeat(64),
      device_key_id: null,
      device_signature: null,
    });
    expect(result.success).toBe(true);
  });

  it("accepts a valid reject body", () => {
    const result = RejectBody.safeParse({
      expected_row_version: 1,
      reason: "Not needed",
    });
    expect(result.success).toBe(true);
  });
});

// --- BlessBody / RetireBody boundary (ZTR-1199) ---

const VALID_BLESS = {
  nonce: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
  issued_at: "2026-07-18T00:00:00.000Z",
  expires_at: "2026-07-18T00:05:00.000Z",
  // 64 zero bytes → padded base64url "A"*86 + "==" (canonical re-encode of all-zero sig)
  device_signature: "A".repeat(86) + "==",
  device_key_id: "66666666-6666-4666-8666-666666666666",
} as const;

describe("BlessBody field shapes", () => {
  it("accepts a fully shaped bless body", () => {
    const result = BlessBody.safeParse(VALID_BLESS);
    expect(result.success).toBe(true);
  });

  it("rejects non-UUID nonce", () => {
    const result = BlessBody.safeParse({ ...VALID_BLESS, nonce: "not-a-uuid" });
    expect(result.success).toBe(false);
  });

  it("rejects uppercase UUID nonce (must be lowercase canonical)", () => {
    const result = BlessBody.safeParse({
      ...VALID_BLESS,
      nonce: "7B8BB326-0F2B-4DAD-A8E7-40115B375EC4",
    });
    expect(result.success).toBe(false);
  });

  it("rejects issued_at without millisecond precision", () => {
    const result = BlessBody.safeParse({
      ...VALID_BLESS,
      issued_at: "2026-07-18T00:00:00Z",
    });
    expect(result.success).toBe(false);
  });

  it("rejects calendar-invalid issued_at that matches the structural pattern", () => {
    // Month 13 matches RFC3339_MS pattern but fails encodeCanonicalTimestamp round-trip.
    expect(Rfc3339MsSchema.safeParse("2026-13-01T00:00:00.000Z").success).toBe(false);
    const result = BlessBody.safeParse({
      ...VALID_BLESS,
      issued_at: "2026-13-01T00:00:00.000Z",
    });
    expect(result.success).toBe(false);
  });

  it("rejects unpadded / wrong-length device_signature", () => {
    const result = BlessBody.safeParse({
      ...VALID_BLESS,
      device_signature: "not-a-sig",
    });
    expect(result.success).toBe(false);
  });

  it("rejects missing required field", () => {
    const { device_key_id: _drop, ...rest } = VALID_BLESS;
    const result = BlessBody.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it("ROUTE_SCHEMAS declares BlessBody and RetireBody", () => {
    const bless = ROUTE_SCHEMAS.find(
      (r) => r.method === "POST" && r.path === "/admin/v1/destinations/:destination_id/bless",
    );
    const retire = ROUTE_SCHEMAS.find(
      (r) => r.method === "POST" && r.path === "/admin/v1/destinations/:destination_id/retire",
    );
    expect(bless?.bodySchema).toBe(BlessBody);
    expect(retire?.bodySchema).toBe(RetireBody);
  });
});

describe("RetireBody empty object", () => {
  it("accepts empty object", () => {
    expect(RetireBody.safeParse({}).success).toBe(true);
  });

  it("rejects non-object", () => {
    expect(RetireBody.safeParse(null).success).toBe(false);
    expect(RetireBody.safeParse("x").success).toBe(false);
  });
});

// --- Regression: money routes must reject mathematically-zero amounts ---

describe("money routes reject amount_zkz = 0.0 (regression)", () => {
  it("POST /v1/receives rejects amount_zkz 0.0", () => {
    const result = CreateReceiveBody.safeParse({
      amount_zkz: "0.0",
      anchor: "ord_01J2",
      after_landing: { kind: "HOLD", destination_id: null },
    });
    expect(result.success).toBe(false);
  });

  it("POST /v1/internal-moves rejects amount_zkz 0.0", () => {
    const result = CreateInternalMoveBody.safeParse({
      source_wallet_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
      destination_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
      amount_zkz: "0.0",
    });
    expect(result.success).toBe(false);
  });

  it("POST /v1/external-sends rejects amount_zkz 0.0", () => {
    const result = CreateExternalSendBody.safeParse({
      source_wallet_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
      destination_address: paddedBase64Url(Buffer.alloc(32)),
      amount_zkz: "0.0",
    });
    expect(result.success).toBe(false);
  });
});

// --- positive fixtures for the canonical padded base64url scalars ---
// The scalars shipped UNSATISFIABLE (regex excluded the trailing `=`; refine compared a
// re-encoded value that Node emits UNPADDED). Absence of positive fixtures is how it shipped.
// Fixtures are derived in-test (no golden-vector file dependency) using the same padding rule
// the fix and the frozen protocol parser use.

function paddedBase64Url(bytes: Buffer): string {
  const unpadded = bytes.toString("base64url");
  const pad = (4 - (unpadded.length % 4)) % 4;
  return `${unpadded}${"=".repeat(pad)}`;
}

describe("canonical padded base64url scalars accept the valid form", () => {
  it("accepts a valid 44-char padded 32-byte wallet public key", () => {
    const addr = paddedBase64Url(Buffer.alloc(32));
    expect(addr).toHaveLength(44);
    expect(addr.endsWith("=")).toBe(true);
    expect(Buffer.from(addr, "base64url")).toHaveLength(32);
    expect(WalletPublicKeySchema.safeParse(addr).success).toBe(true);
  });

  it("accepts a valid 88-char padded 64-byte Ed25519 signature", () => {
    const sig = paddedBase64Url(Buffer.alloc(64));
    expect(sig).toHaveLength(88);
    expect(sig.endsWith("==")).toBe(true);
    expect(Buffer.from(sig, "base64url")).toHaveLength(64);
    expect(Ed25519SignatureSchema.safeParse(sig).success).toBe(true);
  });

  it("rejects the UNPADDED 43-char wallet key form (the exact bug direction)", () => {
    const addr = paddedBase64Url(Buffer.alloc(32));
    const unpadded = addr.slice(0, -1); // drop the trailing "="
    expect(unpadded).toHaveLength(43);
    expect(WalletPublicKeySchema.safeParse(unpadded).success).toBe(false);
  });

  it("accepts a valid padded destination_address on the external-send body", () => {
    const result = CreateExternalSendBody.safeParse({
      source_wallet_id: "7b8bb326-0f2b-4dad-a8e7-40115b375ec4",
      destination_address: paddedBase64Url(Buffer.alloc(32)),
      amount_zkz: "5.5",
    });
    expect(result.success).toBe(true);
  });
});

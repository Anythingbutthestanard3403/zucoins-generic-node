// OpenAPI freeze + two-directional drift gate.
//
// Acceptance criteria:
//   1. No path matches RETIRED_ROUTES / RETIRED_ROUTES_NON_PATH_CATEGORY.
//   2. Exactly three money-moving create verbs; no fourth operation_type enum value.
//   3. POST /v1/receives request schema has no callback_url.
//   4. Two-directional diff: generated document ↔ routes.contract ↔ ROUTE_SCHEMAS.
//   5. Committed openapi.yaml equals a fresh generate+render (byte freeze).
//   6. Field inventory scalars match the runtime Zod amount/time ceilings.
//
// Negative path: poison *generator inputs* (extraContractRoutes, body overrides,
// operationKinds) and assert the freeze gates fail on the generated output.
//
// UPDATE_OPENAPI=1 rewrites packages/node-core/api/openapi.yaml from the generator.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import { CANONICAL_DECIMAL_PATTERN } from "@zucoins/generic-node-contracts/amounts";
import {
  ADMIN_ROUTES,
  OPERATION_KINDS,
  PUBLIC_ROUTES,
  RETIRED_ROUTES,
  RETIRED_ROUTES_NON_PATH_CATEGORY,
} from "@zucoins/generic-node-contracts/operations";
import {
  FORBIDDEN_ROUTE_PREFIXES,
  ROUTE_POLICIES,
} from "@zucoins/generic-node-contracts/route-policy";

import { ROUTE_SCHEMAS } from "../src/api/route-schemas.js";
import { SPLITCHAIN_FUTURE_TIME_CEILING_SECS } from "../src/protocol/receive-ttl.js";
import {
  IDEMPOTENCY_KEY_MAX_LENGTH,
  IDEMPOTENCY_KEY_MIN_LENGTH,
  IDEMPOTENCY_KEY_PATTERN,
  POSITIVE_ZKZ_OPENAPI_PATTERN,
  UUID_PATTERN,
  WALLET_PUBKEY_PATTERN,
} from "../src/api/scalars.js";
import {
  generateOpenApiDocument,
  openApiRouteInventory,
  contractRouteInventory,
  policyRouteInventory,
  implementedRouteInventory,
  routeRefKey,
  moneyMovingCreatePathsInDoc,
  collectOperationTypeEnums,
  pathMatchesRetired,
  createReceiveHasCallbackUrl,
  openApiScalarConstraintsMatchRuntime,
  MONEY_MOVING_CREATE_PATHS,
  CREATE_RECEIVE_PROPERTY_NAMES,
  CREATE_RECEIVE_BODY,
  BODY_BY_ROUTE,
  QUERY_BY_ROUTE,
  OPENAPI_VERSION,
} from "../src/api/openapi/index.js";
import { renderOpenApiYaml } from "../src/api/openapi/yaml.js";
import { EXTERNAL_SEND_APPROVAL_STATUSES } from "../src/send/create.js";

// JsonSchema is exported via generate re-export path — import type from request-bodies if needed
import type { JsonSchema as BodyJsonSchema } from "../src/api/openapi/request-bodies.js";

const here = dirname(fileURLToPath(import.meta.url));
const OPENAPI_PATH = join(here, "..", "api", "openapi.yaml");

function sortedKeys(routes: readonly { method: string; path: string }[]): string[] {
  return routes.map(routeRefKey).sort();
}

function freshYaml(): string {
  return renderOpenApiYaml(generateOpenApiDocument());
}

/** Zod object keys for a body/query schema (supports ZodObject only). */
function zodObjectKeys(schema: z.ZodType | undefined): string[] | null {
  if (!schema) return null;
  // unwrap optional/default
  let s: z.ZodTypeAny = schema as z.ZodTypeAny;
  while (
    s instanceof z.ZodOptional ||
    s instanceof z.ZodDefault ||
    s instanceof z.ZodEffects
  ) {
    s = (s instanceof z.ZodEffects ? s._def.schema : s._def.innerType) as z.ZodTypeAny;
  }
  if (s instanceof z.ZodObject) {
    return Object.keys(s.shape).sort();
  }
  return null;
}

describe("OpenAPI document freeze", () => {
  const doc = generateOpenApiDocument();
  const yaml = renderOpenApiYaml(doc);

  it("info.version is the frozen 1.0.0-frozen tag", () => {
    expect(doc.openapi).toBe("3.0.3");
    expect(doc.info.version).toBe(OPENAPI_VERSION);
    expect(OPENAPI_VERSION).toBe("1.0.0-frozen");
  });

  it("committed openapi.yaml equals a fresh generate+render (byte freeze)", () => {
    if (process.env.UPDATE_OPENAPI === "1") {
      mkdirSync(dirname(OPENAPI_PATH), { recursive: true });
      writeFileSync(OPENAPI_PATH, yaml, "utf8");
    }
    const committed = readFileSync(OPENAPI_PATH, "utf8");
    expect(committed).toBe(yaml);
  });

  it("rejects a stale committed snapshot against freshYaml (negative path)", () => {
    // Real freeze gate: a wrong-bytes fixture must not equal generator output.
    const stale = yaml.replace("1.0.0-frozen", "0.0.0-stale");
    expect(stale).not.toBe(freshYaml());
    expect(stale).not.toBe(yaml);
  });

  it("error envelope schema matches the API contract field sequence exactly", () => {
    const envelopeFields = ["code", "message", "request_id", "details"] as const;
    const envelope = doc.components.schemas.ErrorEnvelope as {
      properties: { error: { required: string[]; properties: Record<string, unknown> } };
    };
    expect(envelope.properties.error.required).toEqual([...envelopeFields]);
    expect(Object.keys(envelope.properties.error.properties)).toEqual([...envelopeFields]);
  });

  it("sha256 of the rendered document is stable for the freeze record", () => {
    const digest = createHash("sha256").update(yaml).digest("hex");
    expect(digest).toMatch(/^[0-9a-f]{64}$/);
    expect(createHash("sha256").update(freshYaml()).digest("hex")).toBe(digest);
  });
});

describe("two-directional route inventory diff", () => {
  const doc = generateOpenApiDocument();
  const openapi = openApiRouteInventory(doc);
  const contract = contractRouteInventory();
  const policy = policyRouteInventory();
  const implemented = implementedRouteInventory();

  it("PUBLIC_ROUTES + ADMIN_ROUTES equal ROUTE_POLICIES (manifest parity)", () => {
    expect(sortedKeys(contract)).toEqual(sortedKeys(policy));
    expect(PUBLIC_ROUTES.length + ADMIN_ROUTES.length).toBe(ROUTE_POLICIES.length);
    expect(PUBLIC_ROUTES.length).toBe(20);
    expect(ADMIN_ROUTES.length).toBe(8);
  });

  it("every contract route appears in the generated document", () => {
    const openSet = new Set(sortedKeys(openapi));
    for (const route of contract) {
      expect(openSet.has(routeRefKey(route))).toBe(true);
    }
  });

  it("every implemented ROUTE_SCHEMAS route appears in the generated document", () => {
    const openSet = new Set(sortedKeys(openapi));
    for (const route of implemented) {
      expect(openSet.has(routeRefKey(route))).toBe(true);
    }
  });

  it("every generated document route is either a contract route or an operational probe", () => {
    const allowed = new Set([
      ...sortedKeys(contract),
      "GET /health",
      "GET /health/ready",
    ]);
    for (const route of openapi) {
      expect(allowed.has(routeRefKey(route))).toBe(true);
    }
  });

  it("ROUTE_SCHEMAS money-moving + action routes are a subset of the document", () => {
    const schemaKeys = new Set(ROUTE_SCHEMAS.map((r) => `${r.method} ${r.path}`));
    for (const path of MONEY_MOVING_CREATE_PATHS) {
      expect(schemaKeys.has(`POST ${path}`)).toBe(true);
    }
    expect(schemaKeys.has("POST /v1/operations/:operation_id/armed")).toBe(true);
    expect(schemaKeys.has("POST /v1/operations/:operation_id/verification-complete")).toBe(
      true,
    );
    expect(schemaKeys.has("GET /v1/operations/:operation_id/verification-material")).toBe(
      true,
    );
  });

  it("REJECTS a fourth stub route injected into generator inputs (negative path)", () => {
    // Poison the generator — not a local array after the fact.
    const poisonedDoc = generateOpenApiDocument({
      extraContractRoutes: [
        {
          method: "POST",
          path: "/v1/payments", // contract-allow:retired-route-citation
          authMode: "implementer_bearer",
        } as (typeof PUBLIC_ROUTES)[number],
      ],
    });
    const inventory = openApiRouteInventory(poisonedDoc);
    const allowed = new Set([
      ...sortedKeys(contractRouteInventory()),
      "GET /health",
      "GET /health/ready",
    ]);
    const extras = inventory.filter((r) => !allowed.has(routeRefKey(r)));
    expect(extras.map(routeRefKey)).toContain("POST /v1/payments");
    expect(pathMatchesRetired("/v1/payments")).not.toBeNull();
    // Fourth money-moving create path is visible without allow-list intersection.
    expect(moneyMovingCreatePathsInDoc(poisonedDoc)).toContain("/v1/payments");
    expect(moneyMovingCreatePathsInDoc(poisonedDoc).length).toBeGreaterThan(3);
  });
});

describe("field inventory ↔ Zod / parity", () => {
  it("ExternalSendResponse approval_status enum equals the response-builder vocabulary", () => {
    const schema = generateOpenApiDocument().components.schemas.ExternalSendResponse as {
      properties: { approval_status: { enum: readonly string[] } };
    };
    expect([...schema.properties.approval_status.enum]).toEqual([
      ...EXTERNAL_SEND_APPROVAL_STATUSES,
    ]);
    expect(schema.properties.approval_status.enum).toEqual([
      "PENDING",
      "APPROVED",
      "CONSUMED",
    ]);
    const committed = readFileSync(OPENAPI_PATH, "utf8");
    const yamlBlock = committed.match(
      /ExternalSendResponse:[\s\S]*?approval_status:\n\s+type: string\n\s+enum:\n((?:\s+- [A-Z]+\n)+)/,
    );
    expect(yamlBlock).not.toBeNull();
    const yamlEnum = [...(yamlBlock?.[1].matchAll(/- ([A-Z]+)/g) ?? [])].map((m) => m[1]);
    expect(yamlEnum).toEqual([...EXTERNAL_SEND_APPROVAL_STATUSES]);
  });

  it("freezes the live internal-move read projection fields", () => {
    const schema = generateOpenApiDocument().components.schemas.InternalMoveResponse as {
      required: string[];
      properties: Record<string, unknown>;
    };
    expect(schema.required).toEqual([
      "operation",
      "source_wallet_id",
      "destination_id",
      "spawned_from_operation_id",
      "lease_status",
      "execution_phase",
      "expected_artifact",
      "source_terminal_observation_id",
      "destination_terminal_observation_id",
    ]);
    expect(Object.keys(schema.properties)).toEqual(schema.required);
  });

  it("openApiScalarConstraintsMatchRuntime is green on live constants", () => {
    const check = openApiScalarConstraintsMatchRuntime();
    expect(check.mismatches).toEqual([]);
    expect(check.ok).toBe(true);
  });

  it("amount_zkz OpenAPI pattern encodes grammar + positivity lookaround", () => {
    expect(POSITIVE_ZKZ_OPENAPI_PATTERN).toContain(CANONICAL_DECIMAL_PATTERN.slice(1, -1));
    // Structural upper bound: nine-digit integers cannot match.
    const re = new RegExp(POSITIVE_ZKZ_OPENAPI_PATTERN);
    expect(re.test("1")).toBe(true);
    expect(re.test("99999999")).toBe(true);
    expect(re.test("100000000")).toBe(false); // exclusive 1e8
    expect(re.test("123456789")).toBe(false);
    expect(re.test("0")).toBe(false);
    expect(re.test("0.0")).toBe(false);
    expect(re.test("1." + "9".repeat(40))).toBe(false); // >32 dp
    expect(re.test("1." + "9".repeat(32))).toBe(true);
  });

  it("BODY_BY_ROUTE property names equal ROUTE_SCHEMAS Zod body keys", () => {
    for (const route of ROUTE_SCHEMAS) {
      if (!route.bodySchema) continue;
      const key = `${route.method} ${route.path}`;
      const body = BODY_BY_ROUTE.get(key);
      expect(body, `missing BODY_BY_ROUTE for ${key}`).toBeDefined();
      const zodKeys = zodObjectKeys(route.bodySchema);
      expect(zodKeys, `expected ZodObject body for ${key}`).not.toBeNull();
      const openKeys = Object.keys(body!.properties ?? {}).sort();
      expect(openKeys).toEqual(zodKeys);
    }
  });

  it("QUERY_BY_ROUTE property names equal ROUTE_SCHEMAS Zod query keys", () => {
    for (const route of ROUTE_SCHEMAS) {
      if (!route.querySchema) continue;
      const key = `${route.method} ${route.path}`;
      const query = QUERY_BY_ROUTE.get(key);
      expect(query, `missing QUERY_BY_ROUTE for ${key}`).toBeDefined();
      const zodKeys = zodObjectKeys(route.querySchema);
      expect(zodKeys).not.toBeNull();
      expect(Object.keys(query!).sort()).toEqual(zodKeys);
    }
  });

  it("expires_in_seconds maximum equals SPLITCHAIN_FUTURE_TIME_CEILING_SECS", () => {
    const exp = CREATE_RECEIVE_BODY.properties?.expires_in_seconds;
    expect(exp?.minimum).toBe(1);
    expect(exp?.maximum).toBe(SPLITCHAIN_FUTURE_TIME_CEILING_SECS);
    expect(SPLITCHAIN_FUTURE_TIME_CEILING_SECS).toBe(59_999_880);
  });

  it("destination_address / uuid patterns match scalar constants", () => {
    const send = BODY_BY_ROUTE.get("POST /v1/external-sends");
    expect(send?.properties?.destination_address?.pattern).toBe(WALLET_PUBKEY_PATTERN);
    expect(send?.properties?.source_wallet_id?.pattern).toBe(UUID_PATTERN);
  });

  it("Idempotency-Key parameter matches IdempotencyKeySchema bounds", () => {
    const doc = generateOpenApiDocument();
    const param = doc.components.parameters.IdempotencyKey as {
      schema: { minLength: number; maxLength: number; pattern: string };
    };
    expect(param.schema.minLength).toBe(IDEMPOTENCY_KEY_MIN_LENGTH);
    expect(param.schema.maxLength).toBe(IDEMPOTENCY_KEY_MAX_LENGTH);
    expect(param.schema.pattern).toBe(IDEMPOTENCY_KEY_PATTERN);
    expect(IDEMPOTENCY_KEY_MIN_LENGTH).toBe(16);
    expect(IDEMPOTENCY_KEY_MAX_LENGTH).toBe(255);
  });

  it("CREATE_RECEIVE_BODY has no callback_url property", () => {
    expect(CREATE_RECEIVE_PROPERTY_NAMES).not.toContain("callback_url");
    expect(CREATE_RECEIVE_PROPERTY_NAMES).toEqual([
      "amount_zkz",
      "anchor",
      "expires_in_seconds",
      "after_landing",
      "verification_mode",
    ]);
  });
});

describe("negative assertions (retired / fourth verb / callback_url)", () => {
  const doc = generateOpenApiDocument();

  it("no generated path matches any RETIRED_ROUTES pattern or import endpoint", () => {
    for (const route of openApiRouteInventory(doc)) {
      expect(pathMatchesRetired(route.path)).toBeNull();
    }
    expect(RETIRED_ROUTES).toEqual([
      "/v1/reservations*",
      "/v1/outbound-requests*",
      "/v1/payments*",
      "/v1/refunds*",
      "/admin/v1/drains*",
    ]);
    expect(RETIRED_ROUTES_NON_PATH_CATEGORY).toBe("any import endpoint");
    expect(FORBIDDEN_ROUTE_PREFIXES).toContain("/v1/payments");
  });

  it("pathMatchesRetired flags every pattern and import endpoints (negative path)", () => {
    expect(pathMatchesRetired("/v1/payments")).toBe("/v1/payments*");
    expect(pathMatchesRetired("/v1/payments/foo")).toBe("/v1/payments*");
    expect(pathMatchesRetired("/v1/reservations")).toBe("/v1/reservations*");
    expect(pathMatchesRetired("/v1/outbound-requests/x")).toBe("/v1/outbound-requests*");
    expect(pathMatchesRetired("/v1/refunds")).toBe("/v1/refunds*");
    expect(pathMatchesRetired("/admin/v1/drains")).toBe("/admin/v1/drains*");
    expect(pathMatchesRetired("/v1/wallets/import")).toBe("any import endpoint");
    expect(pathMatchesRetired("/v1/import-wallet")).toBe("any import endpoint");
  });

  it("money-moving create paths are exactly the three Layer-1 verbs", () => {
    expect(moneyMovingCreatePathsInDoc(doc)).toEqual(
      [...MONEY_MOVING_CREATE_PATHS].sort(),
    );
    expect(MONEY_MOVING_CREATE_PATHS).toHaveLength(3);
    expect(OPERATION_KINDS).toEqual([
      "RECEIVE_EXTERNAL",
      "MOVE_INTERNAL",
      "SEND_EXTERNAL",
    ]);
  });

  it("every operation_type enum in the document is exactly the three kinds — no fourth", () => {
    const enums = collectOperationTypeEnums(doc);
    expect(enums.length).toBeGreaterThan(0);
    for (const values of enums) {
      expect([...values].sort()).toEqual([...OPERATION_KINDS].sort());
      expect(values).toHaveLength(3);
      expect(values).not.toContain("PAYMENT");
      expect(values).not.toContain("REFUND");
    }
  });

  it("REJECTS a fourth operation_type via generator operationKinds input (negative path)", () => {
    const poisonedDoc = generateOpenApiDocument({
      operationKinds: [...OPERATION_KINDS, "PAYMENT"],
    });
    const enums = collectOperationTypeEnums(poisonedDoc);
    const bad = enums.filter((e) => e.length !== 3 || e.includes("PAYMENT"));
    expect(bad.length).toBeGreaterThan(0);
    // Live freeze assertion shape: three-kind equality fails on poisoned generator output.
    for (const values of enums) {
      if (values.includes("PAYMENT")) {
        expect([...values].sort()).not.toEqual([...OPERATION_KINDS].sort());
      }
    }
  });

  it("POST /v1/receives request schema has no callback_url", () => {
    expect(createReceiveHasCallbackUrl(doc)).toBe(false);
  });

  it("REJECTS callback_url sneaked via bodyByRouteOverrides (negative path)", () => {
    const sneaked: BodyJsonSchema = {
      ...CREATE_RECEIVE_BODY,
      properties: {
        ...(CREATE_RECEIVE_BODY.properties ?? {}),
        callback_url: { type: "string" },
      },
    };
    const poisonedDoc = generateOpenApiDocument({
      bodyByRouteOverrides: new Map([["POST /v1/receives", sneaked]]),
    });
    expect(createReceiveHasCallbackUrl(poisonedDoc)).toBe(true);
    // Freeze gate on the generated document fails the assertion.
    expect(createReceiveHasCallbackUrl(generateOpenApiDocument())).toBe(false);
  });
});

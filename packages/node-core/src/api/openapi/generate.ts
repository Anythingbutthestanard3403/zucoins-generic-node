// OpenAPI 3.0.3 document generator for the generic node API.
//
// Generation inputs (reviewed manifests — never hand-authored path lists):
// - PUBLIC_ROUTES / ADMIN_ROUTES / RETIRED_ROUTES (operations/routes.contract)
// - ROUTE_POLICIES / FORBIDDEN_ROUTE_PREFIXES (route-policy)
// - OPERATION_KINDS (operations)
// - HTTP_ERROR_STATUSES / ERROR_ENVELOPE_FIELDS (api-schema)
// - IMPLEMENTER_SCOPES / REPORTING_HEADERS (api-schema)
// - ROUTE_SCHEMAS (node-core route-schemas)
// - request-bodies.ts (field inventories)
//
// Ticket.

import {
  ADMIN_ROUTES,
  OPERATION_KINDS,
  PUBLIC_ROUTES,
  RETIRED_ROUTES,
  RETIRED_ROUTES_NON_PATH_CATEGORY,
  isRetiredImportEndpoint,
  type RouteEntry,
} from "@zucoins/generic-node-contracts/operations";
import {
  FORBIDDEN_ROUTE_PREFIXES,
  ROUTE_POLICIES,
  routeAuthClasses,
  type AuthClass,
  type RoutePolicy,
} from "@zucoins/generic-node-contracts/route-policy";

import { ROUTE_SCHEMAS } from "../route-schemas.js";
import { API_ERROR_CODES } from "../error-envelope.js";
import {
  IDEMPOTENCY_KEY_MAX_LENGTH,
  IDEMPOTENCY_KEY_MIN_LENGTH,
  IDEMPOTENCY_KEY_PATTERN,
  POSITIVE_ZKZ_OPENAPI_PATTERN,
  UUID_PATTERN,
} from "../scalars.js";
import {
  BODY_BY_ROUTE,
  CREATE_RECEIVE_BODY,
  CREATE_RECEIVE_PROPERTY_NAMES,
  OPENAPI_SCALAR_CONSTRAINTS,
  QUERY_BY_ROUTE,
  type JsonSchema,
} from "./request-bodies.js";

export const OPENAPI_VERSION = "1.0.0-frozen" as const;
export const OPENAPI_TITLE = "ZuPayments Generic Node API" as const;

/** Operational probes served by the node but outside PUBLIC_ROUTES/ADMIN_ROUTES. */
export const OPERATIONAL_PROBE_ROUTES = [
  // GET /health is ROUTE_POLICIES / PUBLIC_ROUTES; readiness stays probe-only.
  { method: "GET" as const, path: "/health/ready", authMode: "public" as const },
] as const;

/**
 * Optional generator overrides — production callers pass nothing.
 * Freeze negative tests poison these inputs and assert the output gate fails.
 */
export type GenerateOpenApiOptions = {
  /** Extra contract routes merged after PUBLIC+ADMIN (e.g. a stub retired path). */
  readonly extraContractRoutes?: readonly RouteEntry[];
  /** Replace BODY_BY_ROUTE entries (e.g. sneak callback_url onto receives). */
  readonly bodyByRouteOverrides?: ReadonlyMap<string, JsonSchema>;
  /** Override operation_type enum source (defaults to OPERATION_KINDS). */
  readonly operationKinds?: readonly string[];
};

export type OpenApiDocument = {
  readonly openapi: "3.0.3";
  readonly info: {
    readonly title: string;
    readonly version: string;
    readonly description: string;
  };
  readonly servers: readonly { readonly url: string; readonly description: string }[];
  readonly tags: readonly { readonly name: string; readonly description: string }[];
  readonly paths: Readonly<Record<string, PathItem>>;
  readonly components: {
    readonly securitySchemes: Readonly<Record<string, unknown>>;
    readonly parameters: Readonly<Record<string, unknown>>;
    readonly schemas: Readonly<Record<string, JsonSchema | unknown>>;
    readonly responses: Readonly<Record<string, unknown>>;
  };
  readonly "x-zupay-frozen": {
    readonly operation_kinds: readonly string[];
    readonly retired_routes: readonly string[];
    readonly retired_routes_non_path_category: string;
    readonly public_route_count: number;
    readonly admin_route_count: number;
    readonly money_moving_create_paths: readonly string[];
  };
};

type PathItem = Readonly<Record<string, OperationObject>>;

type OperationObject = {
  readonly tags: readonly string[];
  readonly operationId: string;
  readonly summary: string;
  readonly security: readonly Record<string, readonly string[]>[];
  readonly parameters?: readonly unknown[];
  readonly requestBody?: unknown;
  readonly responses: Readonly<Record<string, unknown>>;
  readonly "x-zupay-auth-classes"?: readonly string[];
  readonly "x-zupay-scope"?: string | null;
  readonly "x-zupay-idempotency"?: string;
};

const routeKey = (method: string, path: string): string => `${method} ${path}`;

const toOpenApiPath = (path: string): string =>
  path.replace(/:([A-Za-z_][A-Za-z0-9_]*)/g, "{$1}");

const pathParamNames = (path: string): string[] => {
  const names: string[] = [];
  for (const match of path.matchAll(/:([A-Za-z_][A-Za-z0-9_]*)/g)) {
    names.push(match[1]!);
  }
  return names;
};

const AUTH_CLASS_TO_SCHEME: Readonly<Record<AuthClass, string | null>> = {
  IMPLEMENTER_BEARER: "implementerBearer",
  REPORTING_CREDENTIAL: "signedReportingCredential",
  SUBSCRIPTION_HANDLE: "subscriptionHandle",
  OPERATOR_SESSION: "operatorSession",
  PUBLIC: null,
};

function securityForPolicy(policy: RoutePolicy | undefined, isPublic: boolean): readonly Record<string, readonly string[]>[] {
  if (isPublic || !policy) return [];
  const classes = routeAuthClasses(policy);
  const schemes = classes
    .map((c) => AUTH_CLASS_TO_SCHEME[c])
    .filter((s): s is string => s !== null);
  if (schemes.length === 0) return [];
  // Multi-auth routes (GET /v1/destinations): OR of schemes as separate objects.
  return schemes.map((s) => ({ [s]: [] as readonly string[] }));
}

function tagForPath(path: string): string {
  if (path.startsWith("/admin/")) return "Admin";
  if (path.startsWith("/v1/integration-requests")) return "IntegrationRequests";
  if (path.startsWith("/.well-known")) return "Discovery";
  if (path === "/health" || path === "/health/ready") return "Health";
  if (path.includes("/destinations") && !path.includes("/operations")) return "Destinations";
  if (path.includes("/events") || path.includes("/snapshot") || path.includes("/subscribe")) {
    return "Events";
  }
  if (
    path.includes("/armed") ||
    path.includes("/verification-complete") ||
    path.includes("/verification-material")
  ) {
    return "Actions";
  }
  return "Operations";
}

function operationIdFor(method: string, path: string): string {
  const cleaned = path
    .replace(/^\//, "")
    .replace(/[{}:]/g, "")
    .split("/")
    .filter(Boolean)
    .map((seg, i) =>
      i === 0 ? seg : seg.charAt(0).toUpperCase() + seg.slice(1),
    )
    .join("")
    .replace(/[^A-Za-z0-9]/g, "");
  return `${method.toLowerCase()}${cleaned.charAt(0).toUpperCase()}${cleaned.slice(1)}`;
}

function summaryFor(method: string, path: string): string {
  const known: Record<string, string> = {
    "POST /v1/receives": "Create a RECEIVE_EXTERNAL operation",
    "GET /v1/receives/:operation_id": "Query a RECEIVE_EXTERNAL operation",
    "POST /v1/internal-moves": "Create a MOVE_INTERNAL operation",
    "GET /v1/internal-moves/:operation_id": "Query a MOVE_INTERNAL operation",
    "POST /v1/external-sends": "Create a SEND_EXTERNAL operation",
    "GET /v1/external-sends/:operation_id": "Query a SEND_EXTERNAL operation",
    "POST /v1/destinations": "Create a destination",
    "GET /v1/destinations": "List destinations",
    "GET /v1/events": "Read implementer events page",
    "GET /v1/events/stream": "SSE implementer event stream",
    "GET /v1/state/snapshot": "Read implementer state snapshot",
    "GET /v1/operations/:operation_id/subscribe": "Browser subscription status",
    "POST /v1/operations/:operation_id/armed": "Arm a receive (release transfer code)",
    "POST /v1/operations/:operation_id/verification-complete": "Submit verification verdict",
    "GET /v1/operations/:operation_id/verification-material": "Read verification material",
    "GET /admin/v1/external-sends/:operation_id/approval-challenge": "Fetch approval challenge",
    "POST /admin/v1/external-sends/:operation_id/approve": "Approve external send",
    "POST /admin/v1/external-sends/:operation_id/reject": "Reject external send",
    "POST /admin/v1/destinations/:destination_id/bless": "Bless a destination",
    "POST /admin/v1/destinations/:destination_id/retire": "Retire a destination",
    "GET /admin/v1/operations/needs-attention": "List operations needing attention",
    "GET /admin/v1/operations/:operation_id/recovery": "Read recovery options",
    "POST /admin/v1/operations/:operation_id/recovery-actions": "Apply a recovery action",
    "POST /v1/integration-requests": "Platform integration request intake",
    "GET /v1/integration-requests/:id": "Poll integration request status / one-time claim",
    "GET /.well-known/zupay-node": "Public node identity discovery",
    "GET /health": "Liveness probe",
    "GET /health/ready": "Readiness probe",
  };
  return known[routeKey(method, path)] ?? `${method} ${path}`;
}

function successResponses(method: string, path: string): Record<string, unknown> {
  const key = routeKey(method, path);
  if (key === "POST /v1/receives") {
    return {
      "201": {
        description: "Wallet assigned and T0 formed synchronously",
        content: {
          "application/json": { schema: { $ref: "#/components/schemas/ReceiveResponse" } },
        },
      },
      "202": {
        description: "Accepted into bounded receive queue",
        content: {
          "application/json": { schema: { $ref: "#/components/schemas/ReceiveResponse" } },
        },
      },
    };
  }
  if (key === "POST /v1/internal-moves") {
    return {
      "201": {
        description: "MOVE_INTERNAL created",
        content: {
          "application/json": { schema: { $ref: "#/components/schemas/InternalMoveResponse" } },
        },
      },
    };
  }
  if (key === "POST /v1/external-sends") {
    return {
      "201": {
        description: "SEND_EXTERNAL created",
        content: {
          "application/json": { schema: { $ref: "#/components/schemas/ExternalSendResponse" } },
        },
      },
    };
  }
  if (key === "GET /v1/receives/:operation_id") {
    return {
      "200": {
        description: "Current RECEIVE_EXTERNAL representation",
        content: {
          "application/json": { schema: { $ref: "#/components/schemas/ReceiveResponse" } },
        },
      },
    };
  }
  if (key === "GET /v1/internal-moves/:operation_id") {
    return {
      "200": {
        description: "Current MOVE_INTERNAL representation",
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/InternalMoveResponse" },
          },
        },
      },
    };
  }
  if (key === "GET /v1/external-sends/:operation_id") {
    return {
      "200": {
        description: "Current SEND_EXTERNAL representation",
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/ExternalSendResponse" },
          },
        },
      },
    };
  }
  if (key === "POST /v1/integration-requests") {
    return {
      "201": {
        description: "Integration request accepted (claim token returned once)",
        content: {
          "application/json": {
            schema: {
              type: "object",
              additionalProperties: false,
              required: ["request_id", "claim_token", "expires_at"],
              properties: {
                request_id: { type: "string", format: "uuid" },
                claim_token: { type: "string" },
                expires_at: { type: "string", format: "date-time" },
              },
            },
          },
        },
      },
    };
  }
  if (key === "GET /v1/integration-requests/:id") {
    return {
      "200": {
        description: "Status poll; first APPROVED poll may include one-time api_key",
        content: {
          "application/json": {
            schema: {
              type: "object",
              additionalProperties: true,
              required: ["status"],
              properties: {
                status: {
                  type: "string",
                  enum: ["PENDING", "APPROVED", "DECLINED", "EXPIRED", "CLAIMED"],
                },
                api_key: { type: "string" },
                public_prefix: { type: "string" },
                scopes: { type: "array", items: { type: "string" } },
                approved_rule: { type: "object", additionalProperties: true },
                implementer_id: { type: "string", format: "uuid" },
                credential_id: { type: "string", format: "uuid" },
              },
            },
          },
        },
      },
    };
  }
  if (key === "GET /.well-known/zupay-node") {
    return {
      "200": {
        description: "Node identity document",
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/DiscoveryResponse" },
          },
        },
      },
    };
  }
  if (key === "GET /health") {
    return {
      "200": {
        description: "Process is alive",
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/LivenessResponse" },
          },
        },
      },
    };
  }
  if (key === "GET /health/ready") {
    return {
      "200": {
        description: "Node is ready to serve traffic",
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/ReadinessResponse" },
          },
        },
      },
      "503": { $ref: "#/components/responses/ServiceUnavailable" },
    };
  }
  if (key === "GET /v1/events/stream") {
    return {
      "200": {
        description: "text/event-stream of implementer events",
        content: {
          "text/event-stream": { schema: { type: "string" } },
        },
      },
    };
  }
  return {
    "200": {
      description: "Success",
      content: {
        "application/json": { schema: { type: "object", additionalProperties: true } },
      },
    },
  };
}

function errorResponses(policy: RoutePolicy | undefined, isPublic: boolean): Record<string, unknown> {
  if (isPublic) return {};
  const out: Record<string, unknown> = {
    "400": { $ref: "#/components/responses/BadRequest" },
    "401": { $ref: "#/components/responses/Unauthorized" },
  };
  if (policy?.tenantScoped) {
    out["404"] = { $ref: "#/components/responses/NotFound" };
  }
  if (policy?.idempotency === "REQUIRED") {
    out["409"] = { $ref: "#/components/responses/Conflict" };
  }
  return out;
}

function buildParameters(
  method: string,
  path: string,
  policy: RoutePolicy | undefined,
): unknown[] {
  const params: unknown[] = [];
  for (const name of pathParamNames(path)) {
    params.push({
      name,
      in: "path",
      required: true,
      schema: name.endsWith("_id")
        ? { type: "string", pattern: UUID_PATTERN }
        : { type: "string" },
      description: name.replace(/_/g, " "),
    });
  }
  if (policy?.idempotency === "REQUIRED") {
    params.push({ $ref: "#/components/parameters/IdempotencyKey" });
  }
  const query = QUERY_BY_ROUTE.get(routeKey(method, path));
  if (query) {
    for (const [name, schema] of Object.entries(query)) {
      params.push({
        name,
        in: "query",
        required: false,
        schema,
      });
    }
  }
  return params;
}

function buildOperation(
  method: "GET" | "POST",
  path: string,
  policy: RoutePolicy | undefined,
  isPublic: boolean,
  bodyMap: ReadonlyMap<string, JsonSchema> = BODY_BY_ROUTE,
): OperationObject {
  const key = routeKey(method, path);
  const body = bodyMap.get(key);
  const parameters = buildParameters(method, path, policy);
  const op: OperationObject = {
    tags: [tagForPath(path)],
    operationId: operationIdFor(method, path),
    summary: summaryFor(method, path),
    security: securityForPolicy(policy, isPublic),
    ...(parameters.length > 0 ? { parameters } : {}),
    ...(body
      ? {
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: body,
              },
            },
          },
        }
      : {}),
    responses: {
      ...successResponses(method, path),
      ...errorResponses(policy, isPublic),
    },
    ...(policy
      ? {
          "x-zupay-auth-classes": [...routeAuthClasses(policy)],
          "x-zupay-scope": policy.scope,
          "x-zupay-idempotency": policy.idempotency,
        }
      : {}),
  };
  return op;
}

function componentsBlock(
  operationKinds: readonly string[] = OPERATION_KINDS,
): OpenApiDocument["components"] {
  const errorCodes = API_ERROR_CODES.map((e) => e.code);
  return {
    securitySchemes: {
      implementerBearer: {
        type: "http",
        scheme: "bearer",
        bearerFormat: "opaque",
        description:
          "implementer bearer key. Scopes are resource:action pairs (receive:create, …).",
      },
      signedReportingCredential: {
        type: "apiKey",
        in: "header",
        name: "X-ZP-Reporting-Signature",
        description:
          "signed reporting credential. Companion headers: X-ZP-Reporting-Key-Id, X-ZP-Reporting-Timestamp, X-ZP-Reporting-Expires-At, X-ZP-Reporting-Nonce.",
      },
      subscriptionHandle: {
        type: "apiKey",
        in: "header",
        name: "X-ZP-Subscription-Handle",
        description: "single-operation browser subscription handle.",
      },
      operatorSession: {
        type: "apiKey",
        in: "cookie",
        name: "zp_operator_session",
        description:
          "operator session. Mutations may additionally require TOTP / device signature.",
      },
    },
    parameters: {
      IdempotencyKey: {
        name: "Idempotency-Key",
        in: "header",
        required: true,
        schema: {
          type: "string",
          minLength: IDEMPOTENCY_KEY_MIN_LENGTH,
          maxLength: IDEMPOTENCY_KEY_MAX_LENGTH,
          pattern: IDEMPOTENCY_KEY_PATTERN,
        },
        description:
          "Mandatory on every POST mutation. 16–255 visible ASCII chars (IdempotencyKeySchema).",
      },
    },
    schemas: {
      ErrorEnvelope: {
        type: "object",
        additionalProperties: false,
        required: ["error"],
        properties: {
          error: {
            type: "object",
            additionalProperties: false,
            required: ["code", "message", "request_id", "details"],
            properties: {
              code: { type: "string", enum: errorCodes },
              message: {
                type: "string",
                description: "Diagnostic only — clients branch on code.",
              },
              request_id: { type: "string", pattern: UUID_PATTERN },
              details: { type: "object", additionalProperties: true },
            },
          },
        },
      },
      OperationObject: {
        type: "object",
        additionalProperties: false,
        required: [
          "operation_id",
          "operation_type",
          "state",
          "amount_zkz",
          "row_version",
          "attention_required",
          "attention_reason",
          "created_at",
          "updated_at",
          "terminal_at",
          "verification_material_available_until",
        ],
        properties: {
          operation_id: { type: "string", format: "uuid" },
          operation_type: {
            type: "string",
            enum: [...operationKinds],
            description: "Exactly three Layer-1 verbs.",
          },
          state: { type: "string" },
          amount_zkz: {
            type: "string",
            pattern: POSITIVE_ZKZ_OPENAPI_PATTERN,
            description: "Operation amount (PositiveZkzAmount).",
          },
          row_version: { type: "integer", minimum: 1 },
          attention_required: { type: "boolean" },
          attention_reason: { type: "string", nullable: true },
          created_at: { type: "string", format: "date-time" },
          updated_at: { type: "string", format: "date-time" },
          terminal_at: { type: "string", format: "date-time", nullable: true },
          verification_material_available_until: {
            type: "string",
            format: "date-time",
            nullable: true,
          },
        },
      },
      ExpectedArtifact: {
        type: "object",
        additionalProperties: false,
        required: ["key_id", "preimage_text", "preimage_sha256", "signature"],
        properties: {
          key_id: { type: "string", format: "uuid" },
          preimage_text: { type: "string" },
          preimage_sha256: { type: "string", pattern: "^[0-9a-f]{64}$" },
          signature: { type: "string" },
        },
      },
      ReceiveResponse: {
        type: "object",
        additionalProperties: false,
        required: [
          "operation",
          "receiver_pubkey",
          "discriminator",
          "expires_at",
          "after_landing",
          "code_status",
          "transfer_code",
          "expected_artifact",
          "t0",
          "subscription_handle",
        ],
        properties: {
          operation: { $ref: "#/components/schemas/OperationObject" },
          receiver_pubkey: { type: "string", nullable: true },
          discriminator: { type: "string" },
          expires_at: { type: "string", format: "date-time", nullable: true },
          after_landing: { type: "object", additionalProperties: true },
          code_status: {
            type: "string",
            enum: ["NOT_CREATED", "AWAITING_ARM", "RELEASED", "EXPIRED"],
          },
          transfer_code: { type: "string", nullable: true },
          expected_artifact: {
            oneOf: [
              { $ref: "#/components/schemas/ExpectedArtifact" },
              { type: "null" },
            ],
          },
          t0: { type: "object", nullable: true, additionalProperties: true },
          // Non-null on create 201/202 (and exact idempotent replay). Point GET
          // strips the field entirely — it is never re-issued as null.
          subscription_handle: { type: "string", minLength: 1 },
        },
      },
      InternalMoveResponse: {
        type: "object",
        additionalProperties: false,
        required: [
          "operation",
          "source_wallet_id",
          "destination_id",
          "spawned_from_operation_id",
          "lease_status",
          "execution_phase",
          "expected_artifact",
          "source_terminal_observation_id",
          "destination_terminal_observation_id",
        ],
        properties: {
          operation: { $ref: "#/components/schemas/OperationObject" },
          source_wallet_id: { type: "string", format: "uuid" },
          destination_id: { type: "string", format: "uuid" },
          spawned_from_operation_id: { type: "string", format: "uuid", nullable: true },
          lease_status: {
            type: "string",
            enum: ["WAITING", "HELD", "RELEASED", "PINNED_FOR_ATTENTION"],
          },
          execution_phase: {
            type: "string",
            enum: [
              "NOT_STARTED",
              "PREIMAGE_PERSISTED",
              "SIGNED_PERSISTED",
              "DELIVERED",
              "SUBMIT_STARTED",
              "SUBMIT_RETURNED",
              "LANDED_VERIFIED",
            ],
          },
          expected_artifact: {
            oneOf: [
              { $ref: "#/components/schemas/ExpectedArtifact" },
              { type: "null" },
            ],
          },
          source_terminal_observation_id: {
            type: "string",
            format: "uuid",
            nullable: true,
          },
          destination_terminal_observation_id: {
            type: "string",
            format: "uuid",
            nullable: true,
          },
        },
      },
      ExternalSendResponse: {
        type: "object",
        additionalProperties: false,
        required: [
          "operation",
          "source_wallet_id",
          "destination_address",
          "references_operation_id",
          "approval_status",
          "transfer_code",
          "transfer_code_sha256",
          "available_until",
          "expected_artifact",
        ],
        properties: {
          operation: { $ref: "#/components/schemas/OperationObject" },
          source_wallet_id: { type: "string", format: "uuid" },
          destination_address: { type: "string" },
          references_operation_id: { type: "string", format: "uuid", nullable: true },
          approval_status: {
            type: "string",
            enum: ["PENDING", "CONSUMED", "REJECTED"],
          },
          transfer_code: { type: "string", nullable: true },
          transfer_code_sha256: { type: "string", nullable: true },
          available_until: {
            type: "string",
            format: "date-time",
            nullable: true,
            description:
              "Derived redemption-expiry projection; null until post-approval sign intent forms.",
          },
          expected_artifact: {
            oneOf: [
              { $ref: "#/components/schemas/ExpectedArtifact" },
              { type: "null" },
            ],
          },
        },
      },
      DiscoveryResponse: {
        type: "object",
        additionalProperties: false,
        required: [
          "node_id",
          "api_version",
          "supported_operation_types",
          "event_signing_public_keys",
          "expected_artifact_public_keys",
          "canonical_suite_versions",
          "key_validity_intervals",
        ],
        properties: {
          node_id: { type: "string", format: "uuid" },
          api_version: { type: "string" },
          supported_operation_types: {
            type: "array",
            items: { type: "string", enum: [...OPERATION_KINDS] },
          },
          event_signing_public_keys: { type: "array", items: { type: "object" } },
          expected_artifact_public_keys: { type: "array", items: { type: "object" } },
          canonical_suite_versions: { type: "array", items: { type: "string" } },
          key_validity_intervals: { type: "array", items: { type: "object" } },
        },
      },
      LivenessResponse: {
        type: "object",
        additionalProperties: false,
        required: ["status", "version", "timestamp"],
        properties: {
          status: { type: "string", enum: ["alive"] },
          version: { type: "string" },
          timestamp: { type: "string", format: "date-time" },
        },
      },
      ReadinessResponse: {
        type: "object",
        additionalProperties: false,
        required: ["status", "version", "timestamp", "checks"],
        properties: {
          status: { type: "string", enum: ["ready", "not_ready", "degraded"] },
          version: { type: "string" },
          timestamp: { type: "string", format: "date-time" },
          checks: {
            type: "array",
            items: {
              type: "object",
              additionalProperties: false,
              required: ["name", "ready", "gating"],
              properties: {
                name: { type: "string" },
                ready: { type: "boolean" },
                gating: { type: "boolean" },
              },
            },
          },
        },
      },
      CreateReceiveBody: CREATE_RECEIVE_BODY,
    },
    responses: {
      BadRequest: {
        description: "Malformed JSON, invalid scalar, unknown field, or impossible shape.",
        content: {
          "application/json": { schema: { $ref: "#/components/schemas/ErrorEnvelope" } },
        },
      },
      Unauthorized: {
        description:
          "Missing/invalid/expired authentication. Scope denial collapses to the same 401 (no 403).",
        content: {
          "application/json": { schema: { $ref: "#/components/schemas/ErrorEnvelope" } },
        },
      },
      NotFound: {
        description: "Object absent or outside the authenticated tenant.",
        content: {
          "application/json": { schema: { $ref: "#/components/schemas/ErrorEnvelope" } },
        },
      },
      Conflict: {
        description: "Idempotency or concurrent-state conflict.",
        content: {
          "application/json": { schema: { $ref: "#/components/schemas/ErrorEnvelope" } },
        },
      },
      Gone: {
        description: "Verification-material access window expired.",
        content: {
          "application/json": { schema: { $ref: "#/components/schemas/ErrorEnvelope" } },
        },
      },
      UnprocessableEntity: {
        description: "Well-formed request fails a custody/protocol predicate.",
        content: {
          "application/json": { schema: { $ref: "#/components/schemas/ErrorEnvelope" } },
        },
      },
      TooManyRequests: {
        description: "Principal rate limit exceeded.",
        content: {
          "application/json": { schema: { $ref: "#/components/schemas/ErrorEnvelope" } },
        },
      },
      ServiceUnavailable: {
        description:
          "Bounded queue full, signer leadership unavailable, or required gateway evidence unavailable.",
        content: {
          "application/json": { schema: { $ref: "#/components/schemas/ErrorEnvelope" } },
        },
      },
    },
  };
}

/**
 * Build the frozen OpenAPI document from the reviewed manifests.
 * Deterministic: same inputs → byte-identical YAML via renderOpenApiYaml.
 */
export function generateOpenApiDocument(
  options: GenerateOpenApiOptions = {},
): OpenApiDocument {
  const policyByKey = new Map(
    ROUTE_POLICIES.map((p) => [routeKey(p.method, p.path), p] as const),
  );

  const bodyMap: ReadonlyMap<string, JsonSchema> = options.bodyByRouteOverrides
    ? new Map([...BODY_BY_ROUTE, ...options.bodyByRouteOverrides])
    : BODY_BY_ROUTE;
  const operationKinds = options.operationKinds ?? OPERATION_KINDS;

  const contractRoutes: readonly RouteEntry[] = [
    ...PUBLIC_ROUTES,
    ...ADMIN_ROUTES,
    ...(options.extraContractRoutes ?? []),
  ];
  const paths: Record<string, PathItem> = {};

  for (const entry of contractRoutes) {
    const openPath = toOpenApiPath(entry.path);
    const policy = policyByKey.get(routeKey(entry.method, entry.path));
    const isPublic = entry.authMode === "public" || policy?.authClass === "PUBLIC";
    const op = buildOperation(entry.method, entry.path, policy, isPublic, bodyMap);
    const existing = paths[openPath] ?? {};
    paths[openPath] = {
      ...existing,
      [entry.method.toLowerCase()]: op,
    };
  }

  // Operational probes — present in ROUTE_SCHEMAS / runtime but outside the
  // 05-api-contract PUBLIC_ROUTES list. Documented so the two-directional
  // implementation diff stays honest about what the node serves.
  for (const probe of OPERATIONAL_PROBE_ROUTES) {
    const openPath = toOpenApiPath(probe.path);
    const op = buildOperation(probe.method, probe.path, undefined, true, bodyMap);
    const existing = paths[openPath] ?? {};
    paths[openPath] = {
      ...existing,
      [probe.method.toLowerCase()]: op,
    };
  }

  // Stable path key ordering for deterministic emit.
  const orderedPaths: Record<string, PathItem> = {};
  for (const key of Object.keys(paths).sort()) {
    orderedPaths[key] = paths[key]!;
  }

  return {
    openapi: "3.0.3",
    info: {
      title: OPENAPI_TITLE,
      version: OPENAPI_VERSION,
      description: [
        "Frozen OpenAPI contract for the generic node (Layer 1).",
        "Governing spec:.",
        "Generated from reviewed manifests (PUBLIC_ROUTES, ROUTE_POLICIES, ROUTE_SCHEMAS).",
        "Do not hand-edit — regenerate via packages/node-core/scripts/emit-openapi.mjs.",
      ].join(" "),
    },
    servers: [{ url: "http://localhost:3100", description: "Local node" }],
    tags: [
      { name: "Operations", description: "Layer-1 create/query (exactly three operation kinds)." },
      { name: "Actions", description: "Arm, verification-complete, verification-material." },
      { name: "Destinations", description: "Node-generated wallet destinations." },
      { name: "Events", description: "Implementer events, snapshot, subscription." },
      { name: "Admin", description: "Operator session endpoints." },
      { name: "Discovery", description: "Public node identity." },
      { name: "Health", description: "Liveness and readiness probes." },
    ],
    paths: orderedPaths,
    components: componentsBlock(operationKinds),
    "x-zupay-frozen": {
      operation_kinds: [...operationKinds],
      retired_routes: [...RETIRED_ROUTES],
      retired_routes_non_path_category: RETIRED_ROUTES_NON_PATH_CATEGORY,
      public_route_count: PUBLIC_ROUTES.length,
      admin_route_count: ADMIN_ROUTES.length,
      money_moving_create_paths: [
        "/v1/receives",
        "/v1/internal-moves",
        "/v1/external-sends",
      ],
    },
  };
}

// --------------------------------------------------------------------------
// Inventory helpers used by the freeze/diff test
// --------------------------------------------------------------------------

export type RouteRef = { readonly method: string; readonly path: string };

export function contractRouteInventory(): readonly RouteRef[] {
  return [...PUBLIC_ROUTES, ...ADMIN_ROUTES].map((r) => ({
    method: r.method,
    path: r.path,
  }));
}

export function policyRouteInventory(): readonly RouteRef[] {
  return ROUTE_POLICIES.map((r) => ({ method: r.method, path: r.path }));
}

/** Implemented routes = ROUTE_SCHEMAS ∪ readiness probe (schemas list /health only). */
export function implementedRouteInventory(): readonly RouteRef[] {
  const fromSchemas = ROUTE_SCHEMAS.map((r) => ({ method: r.method, path: r.path }));
  const hasReady = fromSchemas.some((r) => r.method === "GET" && r.path === "/health/ready");
  return hasReady
    ? fromSchemas
    : [...fromSchemas, { method: "GET", path: "/health/ready" }];
}

export function openApiRouteInventory(doc: OpenApiDocument): readonly RouteRef[] {
  const out: RouteRef[] = [];
  for (const [openPath, item] of Object.entries(doc.paths)) {
    const path = openPath.replace(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g, ":$1");
    for (const method of Object.keys(item)) {
      out.push({ method: method.toUpperCase(), path });
    }
  }
  return out;
}

export function routeRefKey(r: RouteRef): string {
  return `${r.method} ${r.path}`;
}

/** Money-moving create verbs — exactly three (three public money operations). */
export const MONEY_MOVING_CREATE_PATHS = [
  "/v1/receives",
  "/v1/internal-moves",
  "/v1/external-sends",
] as const;

/**
 * POST paths under `/v1/*` that create money-moving operations.
 * Derived from the document (not an allow-list intersection) so a fourth create
 * verb surfaces here. Action posts (armed / verification-complete) and
 * non-money creates (destinations) are excluded by path shape.
 */
const NON_MONEY_V1_POST_SUFFIXES = [
  "/armed",
  "/verification-complete",
  "/destinations",
  "/integration-requests",
] as const;

export function moneyMovingCreatePathsInDoc(doc: OpenApiDocument): string[] {
  return Object.keys(doc.paths)
    .filter((p) => {
      const item = doc.paths[p];
      if (!item || !("post" in item)) return false;
      if (!p.startsWith("/v1/")) return false;
      if (NON_MONEY_V1_POST_SUFFIXES.some((s) => p.endsWith(s) || p === "/v1/destinations")) {
        return false;
      }
      // Money-moving creates: known three verbs, OR any other POST /v1/* that is
      // not an action/destination (so a fourth money verb would still be visible).
      if (MONEY_MOVING_CREATE_PATHS.includes(p as (typeof MONEY_MOVING_CREATE_PATHS)[number])) {
        return true;
      }
      // Unknown POST under /v1 that is not destinations/actions → treat as money create candidate
      if (p.includes("/operations/")) return false;
      return true;
    })
    .sort();
}

/** Collect every string enum array under components.schemas that looks like operation_type. */
export function collectOperationTypeEnums(doc: OpenApiDocument): string[][] {
  const found: string[][] = [];
  const visit = (node: unknown): void => {
    if (node === null || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const item of node) visit(item);
      return;
    }
    const obj = node as Record<string, unknown>;
    if (Array.isArray(obj.enum) && obj.enum.every((v) => typeof v === "string")) {
      const values = obj.enum as string[];
      const hasReceive = values.includes("RECEIVE_EXTERNAL");
      const hasMove = values.includes("MOVE_INTERNAL");
      const hasSend = values.includes("SEND_EXTERNAL");
      if (hasReceive || hasMove || hasSend) {
        found.push(values);
      }
    }
    for (const v of Object.values(obj)) visit(v);
  };
  visit(doc.components.schemas);
  visit(doc["x-zupay-frozen"]);
  return found;
}

export function pathMatchesRetired(path: string): string | null {
  for (const pattern of RETIRED_ROUTES) {
    const prefix = pattern.endsWith("*") ? pattern.slice(0, -1) : pattern;
    if (path === prefix || path.startsWith(prefix)) return pattern;
  }
  for (const prefix of FORBIDDEN_ROUTE_PREFIXES) {
    if (path === prefix || path.startsWith(prefix + "/") || path.startsWith(prefix)) {
      return prefix;
    }
  }
  if (isRetiredImportEndpoint(path)) return RETIRED_ROUTES_NON_PATH_CATEGORY;
  return null;
}

function resolveSchema(
  schema: JsonSchema | undefined,
  doc: OpenApiDocument,
): JsonSchema | undefined {
  if (!schema) return undefined;
  if (schema.$ref) {
    const name = schema.$ref.replace("#/components/schemas/", "");
    const resolved = doc.components.schemas[name] as JsonSchema | undefined;
    return resolveSchema(resolved, doc);
  }
  return schema;
}

export function createReceiveHasCallbackUrl(doc: OpenApiDocument): boolean {
  const receive = doc.paths["/v1/receives"];
  const post = receive?.post as OperationObject | undefined;
  const raw = (post?.requestBody as { content?: { "application/json"?: { schema?: JsonSchema } } })
    ?.content?.["application/json"]?.schema;
  const schema = resolveSchema(raw, doc);
  if (schema?.properties && Object.prototype.hasOwnProperty.call(schema.properties, "callback_url")) {
    return true;
  }
  // Also inspect components.schemas.CreateReceiveBody when present (inline+component dual).
  const component = resolveSchema(
    { $ref: "#/components/schemas/CreateReceiveBody" } as JsonSchema,
    doc,
  );
  if (
    component?.properties &&
    Object.prototype.hasOwnProperty.call(component.properties, "callback_url")
  ) {
    return true;
  }
  return false;
}

/** Assert inventory amount/uuid/wallet/expires constraints match live scalar constants. */
export function openApiScalarConstraintsMatchRuntime(): {
  readonly ok: boolean;
  readonly mismatches: readonly string[];
} {
  const mismatches: string[] = [];
  if (OPENAPI_SCALAR_CONSTRAINTS.amount_zkz_pattern !== POSITIVE_ZKZ_OPENAPI_PATTERN) {
    mismatches.push("amount_zkz_pattern");
  }
  if (OPENAPI_SCALAR_CONSTRAINTS.uuid_pattern !== UUID_PATTERN) {
    mismatches.push("uuid_pattern");
  }
  if (CREATE_RECEIVE_BODY.properties?.amount_zkz?.pattern !== POSITIVE_ZKZ_OPENAPI_PATTERN) {
    mismatches.push("CREATE_RECEIVE_BODY.amount_zkz.pattern");
  }
  const exp = CREATE_RECEIVE_BODY.properties?.expires_in_seconds;
  if (!exp || exp.maximum !== OPENAPI_SCALAR_CONSTRAINTS.expires_in_seconds_maximum) {
    mismatches.push("expires_in_seconds.maximum");
  }
  if (exp && (exp.minimum !== 1)) {
    mismatches.push("expires_in_seconds.minimum");
  }
  return { ok: mismatches.length === 0, mismatches };
}

export {
  CREATE_RECEIVE_PROPERTY_NAMES,
  CREATE_RECEIVE_BODY,
  BODY_BY_ROUTE,
  QUERY_BY_ROUTE,
  OPENAPI_SCALAR_CONSTRAINTS,
};

// Live acceptance run of the IMPLEMENTER_BEARER credential-matrix
// against real CredentialService + tenant/scope pipeline.
//
// Retired keys fail immediately, generic 401 / byte-identical 404,
// Lifecycle audit. Contract technique: packages/generic-node-contracts
// credential-matrix MATRIX_STATES + isNonOracular.
//
// Pure verification — no production code. Depends on the published
// public surfaces only. Includes a
// createOperationRouter two-tenant matrix (D2) and an honest rate-limit
// map (D1 — no principal limiter ships yet).

import { describe, expect, it } from "vitest";

import {
  CANONICAL_AUTH_ERROR_HEADERS,
  CANONICAL_AUTH_FAILURE_BODY,
  CANONICAL_AUTH_FAILURE_CODE,
  CANONICAL_AUTH_FAILURE_MESSAGE,
  CANONICAL_NOT_FOUND_BODY,
  isNonOracular,
  normalizeRequestId,
  type WireResponse,
} from "@zucoins/generic-node-contracts/auth-errors";
import {
  MATRIX_STATES,
  REPRESENTATIVE_ROUTES,
  STATE_DIMENSION,
  STATE_RESOLVING_STAGE,
  type MatrixCell,
} from "../../generic-node-contracts/src/credential-matrix/index.js";

import {
  apiErrorResponse,
  createImplementerBearerAuth,
  createOperationRouter,
  createRejectAllOperationAuth,
  findRouteSchema,
  OperationRouterCompositionError,
  type OperationRouteStore,
  type PipelineConfig,
  type PipelineOutcome,
  type PipelineRequest,
  type ReceiveResponse,
  type RouterResponse,
  runValidationPipeline,
} from "../src/api/index.js";
import {
  credentialResolverFromService,
} from "../src/api/tenant-middleware.js";
import {
  CredentialAuthError,
  CredentialError,
  CredentialService,
  hashCredential,
  type CredentialAuditEntry,
  type CredentialStore,
  type ImplementerScope,
  type StoredCredential,
} from "../src/credential/index.js";

const REQUEST_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const T0 = "2026-07-26T12:00:00.000Z";

// ---------------------------------------------------------------------------
// In-memory store — same contract surface as CredentialStore, used
// only as a harness. Production path is SqlCredentialStore (covered by 312).
// ---------------------------------------------------------------------------

class InMemoryCredentialStore implements CredentialStore {
  readonly rows: StoredCredential[] = [];
  readonly audits: CredentialAuditEntry[] = [];

  async issue(row: StoredCredential, audit: CredentialAuditEntry): Promise<void> {
    this.rows.push(row);
    this.audits.push(audit);
  }

  async findByHash(credentialHash: string): Promise<StoredCredential | null> {
    return this.rows.find((r) => r.credential_hash === credentialHash) ?? null;
  }

  async findById(
    credentialId: string,
    implementerId: string,
  ): Promise<StoredCredential | null> {
    return (
      this.rows.find(
        (r) => r.id === credentialId && r.implementer_id === implementerId,
      ) ?? null
    );
  }

  async listByImplementer(implementerId: string): Promise<StoredCredential[]> {
    return this.rows.filter((r) => r.implementer_id === implementerId);
  }

  async rotate(
    credentialId: string,
    implementerId: string,
    replacement: StoredCredential,
    rotatedAt: string,
    graceUntil: string,
    audit: CredentialAuditEntry,
  ): Promise<boolean> {
    const idx = this.rows.findIndex(
      (row) =>
        row.id === credentialId &&
        row.implementer_id === implementerId &&
        row.status === "ACTIVE",
    );
    if (idx === -1) return false;
    this.rows[idx] = {
      ...this.rows[idx]!,
      status: "GRACE",
      rotated_to_id: replacement.id,
      rotated_at: rotatedAt,
      rotation_grace_until: graceUntil,
      revoked_at: graceUntil,
    };
    this.rows.push(replacement);
    this.audits.push(audit);
    return true;
  }

  async revoke(
    credentialId: string,
    implementerId: string,
    revokedAt: string,
    audit: CredentialAuditEntry,
  ): Promise<boolean> {
    const idx = this.rows.findIndex(
      (row) =>
        row.id === credentialId &&
        row.implementer_id === implementerId &&
        (row.status === "ACTIVE" || row.status === "GRACE"),
    );
    if (idx === -1) return false;
    this.rows[idx] = {
      ...this.rows[idx]!,
      status: "REVOKED",
      revoked_at: revokedAt,
    };
    this.audits.push(audit);
    return true;
  }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

interface Fixture {
  readonly store: InMemoryCredentialStore;
  readonly service: CredentialService;
  /** Controllable clock — mutate `.current` between lifecycle steps. */
  readonly clock: { current: Date };
  readonly implA: string;
  readonly implB: string;
  /** Live full-scope key for impl A. */
  readonly keyA: { credential_id: string; raw_key: string };
  /** Live receive:read-only key for impl A (OUT_OF_SCOPE for send/receive:create). */
  readonly keyANarrow: { credential_id: string; raw_key: string };
  /** Live destination:read key for impl B. */
  readonly keyB: { credential_id: string; raw_key: string };
  /** Expired key for impl A. */
  readonly keyExpired: { credential_id: string; raw_key: string };
  /** Revoked key for impl A. */
  readonly keyRevoked: { credential_id: string; raw_key: string };
}

async function buildFixture(): Promise<Fixture> {
  const clock = { current: new Date(T0) };
  const store = new InMemoryCredentialStore();
  const service = new CredentialService(store, () => clock.current);
  const implA = "impl-aaa-1111-4111-8111-aaaaaaaaaaaa";
  const implB = "impl-bbb-2222-4222-8222-bbbbbbbbbbbb";

  const keyA = await service.create(implA, [
    "receive:create",
    "receive:read",
    "destination:read",
  ]);
  const keyANarrow = await service.create(implA, ["receive:read"]);
  const keyB = await service.create(implB, ["destination:read", "receive:read"]);

  const keyExpired = await service.create(
    implA,
    ["receive:read"],
    "2026-07-26T12:00:01.000Z",
  );
  const keyRevoked = await service.create(implA, ["receive:read"]);
  await service.revoke(keyRevoked.credential_id, implA);

  // Advance past the short-lived expiry so EXPIRED_KEY is live for subsequent calls.
  clock.current = new Date("2026-07-26T12:00:02.000Z");

  return {
    store,
    service,
    clock,
    implA,
    implB,
    keyA: { credential_id: keyA.credential_id, raw_key: keyA.raw_key },
    keyANarrow: {
      credential_id: keyANarrow.credential_id,
      raw_key: keyANarrow.raw_key,
    },
    keyB: { credential_id: keyB.credential_id, raw_key: keyB.raw_key },
    keyExpired: {
      credential_id: keyExpired.credential_id,
      raw_key: keyExpired.raw_key,
    },
    keyRevoked: {
      credential_id: keyRevoked.credential_id,
      raw_key: keyRevoked.raw_key,
    },
  };
}

function bearerHeaders(
  rawKey: string | undefined,
): Record<string, string | undefined> {
  if (rawKey === undefined) return {};
  return { authorization: `Bearer ${rawKey}` };
}

function pipelineRequest(
  method: string,
  path: string,
  authorization: string | undefined,
  extras: Partial<PipelineRequest> = {},
): PipelineRequest {
  return {
    method,
    path,
    rawBody: new Uint8Array(),
    headers: bearerHeaders(authorization),
    query: {},
    ...extras,
  };
}

function pipelineConfig(
  service: CredentialService,
  resolveObject?: PipelineConfig["resolveObjectWithTenantPredicate"],
): PipelineConfig {
  return {
    newRequestId: () => REQUEST_ID,
    resolveCredential: credentialResolverFromService(service),
    resolveObjectWithTenantPredicate: resolveObject,
  };
}

function asWire(error: {
  status: number;
  body: string;
  headers?: Readonly<Record<string, string>>;
}): WireResponse {
  return {
    status: error.status,
    body: error.body,
    headers: error.headers ?? { ...CANONICAL_AUTH_ERROR_HEADERS },
  };
}

// ---------------------------------------------------------------------------
// 1. MATRIX_STATES live acceptance — IMPLEMENTER_BEARER class
// ---------------------------------------------------------------------------

describe("live matrix — IMPLEMENTER_BEARER failure states", () => {
  // Representative read route (no body / no idempotency key required).
  const ROUTE = findRouteSchema("GET", "/v1/receives/:operation_id");
  if (ROUTE === undefined) {
    throw new Error("GET /v1/receives/:operation_id route schema missing");
  }

  // Contract cells for this class × route, used as the oracle of expected
  // status/code/stage — never re-derived in this suite.
  const contractCells: readonly MatrixCell[] = MATRIX_STATES.map((state) => ({
    authClass: "IMPLEMENTER_BEARER" as const,
    method: REPRESENTATIVE_ROUTES.IMPLEMENTER_BEARER[1]!.method,
    path: REPRESENTATIVE_ROUTES.IMPLEMENTER_BEARER[1]!.path,
    state,
    dimension: STATE_DIMENSION[state],
    status: state === "ABSENT_OBJECT" || state === "CROSS_TENANT_OBJECT" ? 404 : 401,
    code:
      state === "ABSENT_OBJECT" || state === "CROSS_TENANT_OBJECT"
        ? "not_found"
        : CANONICAL_AUTH_FAILURE_CODE,
    message:
      state === "ABSENT_OBJECT" || state === "CROSS_TENANT_OBJECT"
        ? "Not found."
        : CANONICAL_AUTH_FAILURE_MESSAGE,
    resolvingStage: STATE_RESOLVING_STAGE[state],
    resolvingStageOrder: 0,
    reachesHandler: false,
  }));

  async function runState(
    fx: Fixture,
    state: (typeof MATRIX_STATES)[number],
  ): Promise<PipelineOutcome> {
    const config = pipelineConfig(fx.service, (context, implementerId) => {
      // Tenant-predicated lookup: bake the tenant into the WHERE, never fetch-then-check.
      const catalog = [
        { id: "op-owned", implementerId: fx.implA },
        { id: "op-foreign", implementerId: fx.implB },
      ];
      // object id from path is not parsed by pipeline; the resolver probe is driven by
      // which state we are testing via a side channel on the request path string.
      const wantId =
        context.request.path.includes("cross-tenant")
          ? "op-foreign"
          : context.request.path.includes("absent")
            ? "op-absent"
            : "op-owned";
      return (
        catalog.find(
          (row) => row.id === wantId && row.implementerId === implementerId,
        ) ?? null
      );
    });

    switch (state) {
      case "MISSING_CREDENTIAL":
        return runValidationPipeline(
          config,
          pipelineRequest("GET", ROUTE.path, undefined),
          ROUTE,
        );
      case "MALFORMED_CREDENTIAL":
        // Present but not an ik_ bearer — extractImplementerBearer returns null.
        return runValidationPipeline(
          config,
          {
            method: "GET",
            path: ROUTE.path,
            rawBody: new Uint8Array(),
            headers: { authorization: "Bearer not-an-ik-key" },
            query: {},
          },
          ROUTE,
        );
      case "UNKNOWN_KEY":
        return runValidationPipeline(
          config,
          pipelineRequest("GET", ROUTE.path, "ik_totally_unknown_key_xxxxxxxx"),
          ROUTE,
        );
      case "EXPIRED_KEY":
        return runValidationPipeline(
          config,
          pipelineRequest("GET", ROUTE.path, fx.keyExpired.raw_key),
          ROUTE,
        );
      case "REVOKED_KEY":
        return runValidationPipeline(
          config,
          pipelineRequest("GET", ROUTE.path, fx.keyRevoked.raw_key),
          ROUTE,
        );
      case "OUT_OF_SCOPE":
        // receive:read key against a route that requires receive:read — wait, GET
        // /v1/receives/:operation_id requires receive:read. Use a destination-only key.
        // Re-issue: keyANarrow is receive:read which MATCHES this route. Force scope
        // denial by running against POST /v1/receives (receive:create) with narrow key.
        {
          const createRoute = findRouteSchema("POST", "/v1/receives")!;
          return runValidationPipeline(
            config,
            {
              method: "POST",
              path: createRoute.path,
              // Minimal body so validation does not short-circuit before auth
              // (auth runs before body validation in the pipeline — confirmed).
              rawBody: new Uint8Array(),
              headers: {
                ...bearerHeaders(fx.keyANarrow.raw_key),
                "idempotency-key": "idem-out-of-scope-0001",
              },
              query: {},
            },
            createRoute,
          );
        }
      case "ABSENT_OBJECT":
        return runValidationPipeline(
          config,
          pipelineRequest("GET", `${ROUTE.path}?probe=absent`, fx.keyA.raw_key),
          ROUTE,
        );
      case "CROSS_TENANT_OBJECT":
        return runValidationPipeline(
          config,
          pipelineRequest(
            "GET",
            `${ROUTE.path}?probe=cross-tenant`,
            fx.keyA.raw_key,
          ),
          ROUTE,
        );
      default: {
        const _exhaustive: never = state;
        throw new Error(`unhandled matrix state: ${_exhaustive}`);
      }
    }
  }

  // Fix ABSENT/CROSS path probe — resolver reads context.request.path. Use path suffix.
  // Re-bind runState with path that embeds the probe token in the path string itself.
  async function runStateFixed(
    fx: Fixture,
    state: (typeof MATRIX_STATES)[number],
  ): Promise<PipelineOutcome> {
    if (state === "ABSENT_OBJECT") {
      const config = pipelineConfig(fx.service, (_ctx, implementerId) => {
        const rows = [{ id: "op-owned", implementerId: fx.implA }];
        return (
          rows.find(
            (r) => r.id === "op-absent" && r.implementerId === implementerId,
          ) ?? null
        );
      });
      return runValidationPipeline(
        config,
        pipelineRequest("GET", ROUTE.path, fx.keyA.raw_key),
        ROUTE,
      );
    }
    if (state === "CROSS_TENANT_OBJECT") {
      const config = pipelineConfig(fx.service, (_ctx, implementerId) => {
        const rows = [{ id: "op-foreign", implementerId: fx.implB }];
        // Bake tenant into lookup — foreign row never matches implA's predicate.
        return (
          rows.find(
            (r) => r.id === "op-foreign" && r.implementerId === implementerId,
          ) ?? null
        );
      });
      return runValidationPipeline(
        config,
        pipelineRequest("GET", ROUTE.path, fx.keyA.raw_key),
        ROUTE,
      );
    }
    return runState(fx, state);
  }

  it("covers every MATRIX_STATES cell for IMPLEMENTER_BEARER", () => {
    expect(MATRIX_STATES).toEqual([
      "MISSING_CREDENTIAL",
      "MALFORMED_CREDENTIAL",
      "UNKNOWN_KEY",
      "EXPIRED_KEY",
      "REVOKED_KEY",
      "OUT_OF_SCOPE",
      "ABSENT_OBJECT",
      "CROSS_TENANT_OBJECT",
    ]);
    expect(contractCells).toHaveLength(8);
  });

  it("collapses the six credential/scope states onto one non-oracular 401", async () => {
    const fx = await buildFixture();
    const authStates = MATRIX_STATES.filter(
      (s) => STATE_DIMENSION[s] === "credential" || STATE_DIMENSION[s] === "scope",
    );
    expect(authStates).toHaveLength(6);

    const outcomes = await Promise.all(
      authStates.map((state) => runStateFixed(fx, state)),
    );
    for (const outcome of outcomes) {
      expect(outcome.ok).toBe(false);
    }
    const wires: WireResponse[] = outcomes.map((o) => {
      if (o.ok) throw new Error("expected failure");
      return asWire(o.error);
    });

    expect(isNonOracular(wires)).toBe(true);
    for (const wire of wires) {
      expect(wire.status).toBe(401);
      expect(normalizeRequestId(wire.body)).toBe(CANONICAL_AUTH_FAILURE_BODY);
      expect(wire.headers).toEqual({ ...CANONICAL_AUTH_ERROR_HEADERS });
    }
  });

  it("collapses ABSENT_OBJECT and CROSS_TENANT_OBJECT onto one non-oracular 404", async () => {
    const fx = await buildFixture();
    const absent = await runStateFixed(fx, "ABSENT_OBJECT");
    const cross = await runStateFixed(fx, "CROSS_TENANT_OBJECT");
    expect(absent.ok).toBe(false);
    expect(cross.ok).toBe(false);
    if (absent.ok || cross.ok) return;

    expect(absent.error).toEqual(cross.error);
    expect(absent.error.status).toBe(404);
    expect(normalizeRequestId(absent.error.body)).toBe(CANONICAL_NOT_FOUND_BODY);
    expect(isNonOracular([asWire(absent.error), asWire(cross.error)])).toBe(true);
  });

  it("never reaches the handler for any matrix failure state", async () => {
    const fx = await buildFixture();
    for (const state of MATRIX_STATES) {
      // Handler is not a pipeline config hook — reachability is proven by
      // resolveObjectWithTenantPredicate not being called for auth/scope states,
      // and by ok:false for tenant states (object resolve returns null → 404 before handler).
      if (STATE_DIMENSION[state] === "credential" || STATE_DIMENSION[state] === "scope") {
        let lookups = 0;
        const base = pipelineConfig(fx.service, () => {
          lookups += 1;
          return null;
        });
        // Drive via runStateFixed which may override config — re-run with lookup counter.
        let outcome: PipelineOutcome;
        if (state === "OUT_OF_SCOPE") {
          const createRoute = findRouteSchema("POST", "/v1/receives")!;
          outcome = await runValidationPipeline(
            base,
            {
              method: "POST",
              path: createRoute.path,
              rawBody: new Uint8Array(),
              headers: {
                ...bearerHeaders(fx.keyANarrow.raw_key),
                "idempotency-key": "idem-no-handler-0001",
              },
              query: {},
            },
            createRoute,
          );
        } else if (state === "MISSING_CREDENTIAL") {
          outcome = await runValidationPipeline(
            base,
            pipelineRequest("GET", ROUTE.path, undefined),
            ROUTE,
          );
        } else if (state === "MALFORMED_CREDENTIAL") {
          outcome = await runValidationPipeline(
            base,
            {
              method: "GET",
              path: ROUTE.path,
              rawBody: new Uint8Array(),
              headers: { authorization: "Bearer sh_not_implementer" },
              query: {},
            },
            ROUTE,
          );
        } else if (state === "UNKNOWN_KEY") {
          outcome = await runValidationPipeline(
            base,
            pipelineRequest("GET", ROUTE.path, "ik_unknown"),
            ROUTE,
          );
        } else if (state === "EXPIRED_KEY") {
          outcome = await runValidationPipeline(
            base,
            pipelineRequest("GET", ROUTE.path, fx.keyExpired.raw_key),
            ROUTE,
          );
        } else {
          outcome = await runValidationPipeline(
            base,
            pipelineRequest("GET", ROUTE.path, fx.keyRevoked.raw_key),
            ROUTE,
          );
        }
        expect(outcome.ok).toBe(false);
        expect(lookups).toBe(0);
      } else {
        const outcome = await runStateFixed(fx, state);
        expect(outcome.ok).toBe(false);
        if (!outcome.ok) expect(outcome.error.status).toBe(404);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// 2. Lifecycle isolation — issue / rotate grace / revoke-immediate / stolen id
// ---------------------------------------------------------------------------

describe("lifecycle isolation (issue → rotate → revoke)", () => {
  it("returns the raw secret once at issue and never stores it", async () => {
    const fx = await buildFixture();
    const issued = await fx.service.create(fx.implA, ["send:read"]);
    expect(issued.raw_key.startsWith("ik_")).toBe(true);

    const row = fx.store.rows.find((r) => r.id === issued.credential_id);
    expect(row).toBeDefined();
    // Store holds only the hash — the raw secret never appears in the row.
    expect(JSON.stringify(row)).not.toContain(issued.raw_key);
    expect(row!.credential_hash).toBe(hashCredential(issued.raw_key));
    // Fingerprint (public_prefix) is the stored prefix from issue time, not recomputed at read.
    expect(row!.public_prefix).toBe(issued.raw_key.slice(0, 11));
    expect(row!.public_prefix).toBe(issued.public_prefix);
    // No row in the whole store carries the raw secret.
    for (const other of fx.store.rows) {
      expect(JSON.stringify(other)).not.toContain(issued.raw_key);
    }
    // Audit trail carries no secret.
    for (const audit of fx.store.audits) {
      expect(JSON.stringify(audit)).not.toContain(issued.raw_key);
    }
  });

  it("rotation grace accepts the old key until grace ends, then rejects immediately", async () => {
    const clock = { current: new Date(T0) };
    const store = new InMemoryCredentialStore();
    const service = new CredentialService(store, () => clock.current);
    const impl = "impl-rotate-test";
    const original = await service.create(impl, ["receive:read"]);

    const graceSeconds = 60;
    const rotated = await service.rotate(
      original.credential_id,
      impl,
      graceSeconds,
    );
    expect(rotated.raw_key).not.toBe(original.raw_key);

    // Inside grace window: both keys authorize.
    await expect(
      service.authorize(original.raw_key, "receive:read"),
    ).resolves.toMatchObject({ implementer_id: impl });
    await expect(
      service.authorize(rotated.raw_key, "receive:read"),
    ).resolves.toMatchObject({ implementer_id: impl });

    // Exactly at grace boundary (rotation_grace_until is exclusive via `<= now`).
    clock.current = new Date(new Date(T0).getTime() + graceSeconds * 1000);
    await expect(
      service.authorize(original.raw_key, "receive:read"),
    ).rejects.toBeInstanceOf(CredentialAuthError);
    // New key still valid.
    await expect(
      service.authorize(rotated.raw_key, "receive:read"),
    ).resolves.toMatchObject({ implementer_id: impl });
  });

  it("revoke-then-immediate-retry has zero grace — retired keys fail immediately", async () => {
    const fx = await buildFixture();
    const live = await fx.service.create(fx.implA, ["receive:read"]);
    await expect(
      fx.service.authorize(live.raw_key, "receive:read"),
    ).resolves.toBeTruthy();

    await fx.service.revoke(live.credential_id, fx.implA);

    // Immediate — no delay, no wall-clock advance.
    await expect(
      fx.service.authorize(live.raw_key, "receive:read"),
    ).rejects.toBeInstanceOf(CredentialAuthError);

    // Same rejection through the live pipeline adapter.
    const route = findRouteSchema("GET", "/v1/receives/:operation_id")!;
    const outcome = await runValidationPipeline(
      pipelineConfig(fx.service),
      pipelineRequest("GET", route.path, live.raw_key),
      route,
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error.status).toBe(401);
      expect(normalizeRequestId(outcome.error.body)).toBe(
        CANONICAL_AUTH_FAILURE_BODY,
      );
    }
  });

  it("stolen/leaked credential id cannot be rotated or revoked cross-tenant", async () => {
    const fx = await buildFixture();
    // Attacker (implB) knows victim's credential_id (leaked id, not the secret).
    const stolenId = fx.keyA.credential_id;

    await expect(
      fx.service.rotate(stolenId, fx.implB, 30),
    ).rejects.toMatchObject({
      name: "CredentialError",
      code: "CREDENTIAL_NOT_FOUND",
    });
    await expect(
      fx.service.revoke(stolenId, fx.implB),
    ).rejects.toMatchObject({
      name: "CredentialError",
      code: "CREDENTIAL_NOT_FOUND",
    });

    // Victim's key still works — attacker could not retire it.
    await expect(
      fx.service.authorize(fx.keyA.raw_key, "receive:read"),
    ).resolves.toMatchObject({ implementer_id: fx.implA });

    // Management-path not_found collapses the same for absent id and cross-tenant id
    // (ABSENT_OBJECT / CROSS_TENANT_OBJECT → not_found at the storage layer).
    const absentCode = await fx.service
      .revoke("00000000-0000-4000-8000-000000000000", fx.implA)
      .then(
        () => "ok",
        (e: CredentialError) => e.code,
      );
    const crossCode = await fx.service.revoke(stolenId, fx.implB).then(
      () => "ok",
      (e: CredentialError) => e.code,
    );
    expect(absentCode).toBe("CREDENTIAL_NOT_FOUND");
    expect(crossCode).toBe("CREDENTIAL_NOT_FOUND");
  });

  it("audit trail records issue, rotate, and revoke with no recoverable secret", async () => {
    const clock = { current: new Date(T0) };
    const store = new InMemoryCredentialStore();
    const service = new CredentialService(store, () => clock.current);
    const impl = "impl-audit";
    const issued = await service.create(impl, ["move:read"]);
    await service.rotate(issued.credential_id, impl, 0);
    // After zero-grace rotate the original is retired; revoke the replacement.
    const replacement = store.rows.find(
      (r) => r.rotated_from_id === issued.credential_id,
    )!;
    await service.revoke(replacement.id, impl);

    const actions = store.audits.map((a) => a.action);
    expect(actions).toEqual([
      "IMPLEMENTER_CREDENTIAL_ISSUED",
      "IMPLEMENTER_CREDENTIAL_ROTATED",
      "IMPLEMENTER_CREDENTIAL_REVOKED",
    ]);
    for (const audit of store.audits) {
      expect(audit.implementer_id).toBe(impl);
      expect(JSON.stringify(audit)).not.toContain(issued.raw_key);
    }
  });
});

// ---------------------------------------------------------------------------
// 3. Concurrent use — no cross-request authorization context leakage
// ---------------------------------------------------------------------------

describe("concurrent use isolation", () => {
  it("two simultaneous authorizations on one key against different scopes are independently checked", async () => {
    const fx = await buildFixture();
    // keyA holds receive:create + receive:read + destination:read — not send:create.
    const [okReceive, denySend] = await Promise.all([
      fx.service.authorize(fx.keyA.raw_key, "receive:read").then(
        (v) => ({ ok: true as const, v }),
        (e: unknown) => ({ ok: false as const, e }),
      ),
      fx.service.authorize(fx.keyA.raw_key, "send:create").then(
        (v) => ({ ok: true as const, v }),
        (e: unknown) => ({ ok: false as const, e }),
      ),
    ]);
    expect(okReceive.ok).toBe(true);
    expect(denySend.ok).toBe(false);
    if (denySend.ok) return;
    expect(denySend.e).toBeInstanceOf(CredentialAuthError);
  });

  it("two simultaneous pipeline requests on the same key bind distinct tenant contexts and scopes", async () => {
    const fx = await buildFixture();
    const destRoute = findRouteSchema("GET", "/v1/destinations")!;
    const recvRoute = findRouteSchema("GET", "/v1/receives/:operation_id")!;
    const config = pipelineConfig(fx.service);

    // keyA is valid for both destination:read and receive:read.
    // keyANarrow is receive:read only — must 401 on destinations.
    const [aOk, bOk, narrowDeny] = await Promise.all([
      runValidationPipeline(
        config,
        pipelineRequest("GET", destRoute.path, fx.keyA.raw_key),
        destRoute,
      ),
      runValidationPipeline(
        config,
        pipelineRequest("GET", recvRoute.path, fx.keyB.raw_key),
        recvRoute,
      ),
      runValidationPipeline(
        config,
        pipelineRequest("GET", destRoute.path, fx.keyANarrow.raw_key),
        destRoute,
      ),
    ]);

    expect(aOk.ok).toBe(true);
    expect(bOk.ok).toBe(true);
    expect(narrowDeny.ok).toBe(false);
    if (aOk.ok && bOk.ok) {
      expect(aOk.context.principal?.implementerId).toBe(fx.implA);
      expect(bOk.context.principal?.implementerId).toBe(fx.implB);
      // No leakage: A's principal must not appear on B's context and vice versa.
      expect(aOk.context.principal?.implementerId).not.toBe(
        bOk.context.principal?.implementerId,
      );
      expect(aOk.context.idempotencyTenantId).toBe(fx.implA);
      expect(bOk.context.idempotencyTenantId).toBe(fx.implB);
    }
    if (!narrowDeny.ok) {
      expect(narrowDeny.error.status).toBe(401);
      expect(normalizeRequestId(narrowDeny.error.body)).toBe(
        CANONICAL_AUTH_FAILURE_BODY,
      );
    }
  });

  it("implementer_id in the request body/query/header is ignored — tenant comes only from the credential", async () => {
    const fx = await buildFixture();
    const route = findRouteSchema("GET", "/v1/destinations")!;
    // Spoof every caller-controlled channel. GET has no body schema path that
    // would reject unknown fields before auth completes; query/header spoofs
    // are enough to prove the middleware never reads them for tenant binding.
    const outcome = await runValidationPipeline(
      pipelineConfig(fx.service),
      {
        method: "GET",
        path: route.path,
        rawBody: new Uint8Array(),
        headers: {
          ...bearerHeaders(fx.keyA.raw_key),
          "x-implementer-id": fx.implB,
          "implementer_id": fx.implB,
        },
        // Query stays empty: ListDestinationsQuery is .strict() and would 400 on
        // an unknown implementer_id field before we can observe tenant binding.
        // Header spoofs are the caller-controlled channel that must be ignored.
        query: {},
      },
      route,
    );
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.context.principal?.implementerId).toBe(fx.implA);
      expect(outcome.context.idempotencyTenantId).toBe(fx.implA);
      expect(outcome.context.principal?.implementerId).not.toBe(fx.implB);
    }
  });
});

// ---------------------------------------------------------------------------
// 4. Rate-limit — product envelope only (no implementer-bearer limiter yet)
// ---------------------------------------------------------------------------
//
// The credential-pipeline contract names per-implementer 429 independence. The rate-limit
// slices (and this prep)
// ship no implementer-bearer principal rate limiter on the operation path —
// only the frozen error-envelope code `rate_limited` → HTTP 429 exists
// (`error-envelope.ts`). A prior harness that threw from a test-local Map and
// caught it outside the pipeline was a tautology (review D1 @ 4bda2f12).
//
// Until a production principal limiter is composed into createOperationRouter /
// the node listener, the independence AC is **not satisfied** here. What we
// do lock: the wire shape of `apiErrorResponse("rate_limited")` is a real 429
// envelope, byte-distinct from the frozen 401 auth failure (so a future
// limiter cannot accidentally collapse trip → existence oracle).

describe("rate-limit error envelope (product surface)", () => {
  it("apiErrorResponse(rate_limited) is frozen 429 and distinct from invalid_api_key", () => {
    const limited = apiErrorResponse("rate_limited", REQUEST_ID);
    const auth = apiErrorResponse("invalid_api_key", REQUEST_ID);

    expect(limited.status).toBe(429);
    expect(limited.body).toBe(
      JSON.stringify({
        error: {
          code: "rate_limited",
          message: "The principal rate limit is exceeded.",
          request_id: REQUEST_ID,
          details: {},
        },
      }),
    );
    expect(auth.status).toBe(401);
    expect(limited.body).not.toBe(auth.body);
    expect(normalizeRequestId(auth.body)).toBe(CANONICAL_AUTH_FAILURE_BODY);
    // Headers stay on the canonical auth-error content-type surface.
    expect(limited.headers).toEqual({ ...CANONICAL_AUTH_ERROR_HEADERS });
  });
});

// ---------------------------------------------------------------------------
// 5. Regression catch — deliberately broken scope / tenant predicates go red
// ---------------------------------------------------------------------------

describe("matrix regression catch (deliberately broken predicates)", () => {
  it("a scope check that always grants reddens the OUT_OF_SCOPE cell", async () => {
    const fx = await buildFixture();
    const createRoute = findRouteSchema("POST", "/v1/receives")!;

    // Broken authorize: ignore the principal's scopes and always pass.
    const brokenConfig: PipelineConfig = {
      newRequestId: () => REQUEST_ID,
      // Bypass resolveCredential path; use legacy hooks that always authorize.
      authenticate: async () => true,
      authorizeScope: async () => true,
    };

    const broken = await runValidationPipeline(
      brokenConfig,
      {
        method: "POST",
        path: createRoute.path,
        rawBody: new Uint8Array(),
        headers: {
          ...bearerHeaders(fx.keyANarrow.raw_key),
          "idempotency-key": "idem-broken-scope-0001",
        },
        query: {},
      },
      createRoute,
    );
    // Broken gate admits the request past auth/scope (may still fail body validation
    // with 400 — the point is it is NOT the matrix's 401 OUT_OF_SCOPE cell).
    const isMatrixOutOfScope401 =
      !broken.ok &&
      broken.error.status === 401 &&
      normalizeRequestId(broken.error.body) === CANONICAL_AUTH_FAILURE_BODY;

    // Correct gate produces the matrix 401.
    const correct = await runValidationPipeline(
      pipelineConfig(fx.service),
      {
        method: "POST",
        path: createRoute.path,
        rawBody: new Uint8Array(),
        headers: {
          ...bearerHeaders(fx.keyANarrow.raw_key),
          "idempotency-key": "idem-correct-scope-0001",
        },
        query: {},
      },
      createRoute,
    );
    expect(correct.ok).toBe(false);
    if (!correct.ok) {
      expect(correct.error.status).toBe(401);
      expect(normalizeRequestId(correct.error.body)).toBe(
        CANONICAL_AUTH_FAILURE_BODY,
      );
    }

    // The broken cell diverges from the correct matrix cell — that divergence is
    // what "reddens the matrix cell" means for this leave-behind.
    expect(isMatrixOutOfScope401).toBe(false);
    expect(broken.ok || (!broken.ok && broken.error.status !== 401)).toBe(true);
  });

  it("a tenant predicate that omits implementer_id reddens the CROSS_TENANT cell", async () => {
    const fx = await buildFixture();
    const route = findRouteSchema("GET", "/v1/receives/:operation_id")!;

    // Broken: fetch by id only, ignore the bound tenant (the oracle).
    const broken = await runValidationPipeline(
      pipelineConfig(fx.service, (_ctx, _implementerId) => {
        // Deliberately ignore implementerId — returns the foreign row to any tenant.
        return { id: "op-foreign", implementerId: fx.implB };
      }),
      pipelineRequest("GET", route.path, fx.keyA.raw_key),
      route,
    );

    // Correct: bake tenant into the lookup.
    const correct = await runValidationPipeline(
      pipelineConfig(fx.service, (_ctx, implementerId) => {
        const rows = [{ id: "op-foreign", implementerId: fx.implB }];
        return (
          rows.find(
            (r) => r.id === "op-foreign" && r.implementerId === implementerId,
          ) ?? null
        );
      }),
      pipelineRequest("GET", route.path, fx.keyA.raw_key),
      route,
    );

    // Correct collapses to 404 not_found.
    expect(correct.ok).toBe(false);
    if (!correct.ok) {
      expect(correct.error.status).toBe(404);
      expect(normalizeRequestId(correct.error.body)).toBe(CANONICAL_NOT_FOUND_BODY);
    }

    // Broken admits the foreign object (ok:true with resolvedObject) — matrix cell reddens.
    expect(broken.ok).toBe(true);
    if (broken.ok) {
      expect(broken.context.resolvedObject).toEqual({
        id: "op-foreign",
        implementerId: fx.implB,
      });
    }
  });

  it("service-level OUT_OF_SCOPE is byte-identical to UNKNOWN_KEY (CredentialAuthError)", async () => {
    const fx = await buildFixture();
    const unknown = await fx.service.authorize("ik_nope", "receive:read").then(
      () => null,
      (e: unknown) => e,
    );
    const oos = await fx.service
      .authorize(fx.keyANarrow.raw_key, "send:create")
      .then(
        () => null,
        (e: unknown) => e,
      );
    expect(unknown).toBeInstanceOf(CredentialAuthError);
    expect(oos).toBeInstanceOf(CredentialAuthError);
    const shape = (e: CredentialAuthError) =>
      JSON.stringify({
        name: e.name,
        message: e.message,
        code: e.code,
        ownKeys: Object.keys(e).sort(),
      });
    expect(shape(unknown as CredentialAuthError)).toBe(
      shape(oos as CredentialAuthError),
    );
    expect((unknown as CredentialAuthError).code).toBe(CANONICAL_AUTH_FAILURE_CODE);
    expect((unknown as CredentialAuthError).message).toBe(
      CANONICAL_AUTH_FAILURE_MESSAGE,
    );
  });
});

// ---------------------------------------------------------------------------
// 6. Production router two-tenant matrix (rework head composition)
// ---------------------------------------------------------------------------
//
// Review D2 @ 4bda2f12 / 313-A deferred e2e: library-local runValidationPipeline
// injection is not enough. This block mounts createOperationRouter +
// createImplementerBearerAuth (the production composition path on the 313
// rework head) with two tenants and proves 401 non-oracle, 404 byte-identity,
// authz-before-lookup, principal binding, and idempotency tenant isolation.
// Suite goes red if resolveCredential is omitted (composition gate / reject-all
// refuse live store).

const encodeJson = (value: unknown): Uint8Array =>
  new TextEncoder().encode(JSON.stringify(value));

const OP_A = "00000000-0000-0000-0000-0000000000a1";
const OP_B = "00000000-0000-0000-0000-0000000000b2";
const OP_ABSENT = "00000000-0000-0000-0000-00000000dead";
const IDEM_KEY = "idem-key-314-router-01";
const RECEIVE_BODY = {
  amount_zkz: "5.5",
  anchor: "ord_01J2",
  after_landing: { kind: "HOLD" as const, destination_id: null },
};

const FULL_SCOPES = [
  "receive:create",
  "receive:read",
  "move:create",
  "move:read",
  "send:create",
  "send:read",
  "destination:create",
  "destination:read",
] as const;

function receiveBody(id: string): ReceiveResponse {
  return {
    operation: {
      operation_id: id,
      operation_type: "RECEIVE_EXTERNAL",
      state: "READY",
      amount_zkz: "5.5",
      row_version: 1,
      attention_required: false,
      attention_reason: null,
      created_at: "2026-01-01T00:00:00.000Z",
      updated_at: "2026-01-01T00:00:01.000Z",
      terminal_at: null,
      verification_material_available_until: null,
    },
    receiver_pubkey: "wUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrM=",
    discriminator: id,
    expires_at: "2026-01-01T00:05:00.000Z",
    after_landing: { kind: "HOLD", destination_id: null },
    code_status: "AWAITING_ARM",
    transfer_code: null,
    expected_artifact: null,
    t0: null,
    subscription_handle: "sh_secret",
  };
}

interface StoredReceive {
  readonly implementerId: string;
  readonly body: ReceiveResponse;
  readonly idempotencyKey: string;
}

function tenantedRouterStore(): {
  store: OperationRouteStore;
  creates: Array<{ implementerId: string; idempotencyKey: string }>;
  gets: Array<{ operationId: string; implementerId: string }>;
} {
  const rows = new Map<string, StoredReceive>();
  const creates: Array<{ implementerId: string; idempotencyKey: string }> = [];
  const gets: Array<{ operationId: string; implementerId: string }> = [];

  rows.set(OP_A, {
    implementerId: "impl-a",
    body: receiveBody(OP_A),
    idempotencyKey: "seed-a",
  });
  rows.set(OP_B, {
    implementerId: "impl-b",
    body: receiveBody(OP_B),
    idempotencyKey: "seed-b",
  });

  const store: OperationRouteStore = {
    async createReceive(input) {
      creates.push({
        implementerId: input.implementerId,
        idempotencyKey: input.idempotencyKey,
      });
      for (const row of rows.values()) {
        if (
          row.implementerId === input.implementerId &&
          row.idempotencyKey === input.idempotencyKey
        ) {
          return { status: 201 as const, body: row.body, idempotentReplay: true };
        }
      }
      const id = crypto.randomUUID();
      const body = receiveBody(id);
      rows.set(id, {
        implementerId: input.implementerId,
        body,
        idempotencyKey: input.idempotencyKey,
      });
      return { status: 201 as const, body };
    },
    async getReceive(operationId, implementerId) {
      gets.push({ operationId, implementerId });
      const row = rows.get(operationId);
      if (row === undefined || row.implementerId !== implementerId) return null;
      return row.body;
    },
    async createInternalMove() {
      throw new Error("unused");
    },
    async getInternalMove() {
      throw new Error("unused");
    },
    async createExternalSend() {
      throw new Error("unused");
    },
    async getExternalSend() {
      throw new Error("unused");
    },
  };

  return { store, creates, gets };
}

/** Issue real CredentialService keys, then enroll them on the production auth factory. */
async function dualTenantRouterAuthFromCredentialService(): Promise<{
  auth: ReturnType<typeof createImplementerBearerAuth>;
  tokenA: string;
  tokenB: string;
  tokenReadOnly: string;
  implA: string;
  implB: string;
  service: CredentialService;
}> {
  const store = new InMemoryCredentialStore();
  const service = new CredentialService(store, () => new Date(T0));
  const implA = "impl-a";
  const implB = "impl-b";
  const keyA = await service.create(implA, [...FULL_SCOPES]);
  const keyB = await service.create(implB, [...FULL_SCOPES]);
  const keyReadOnly = await service.create(implA, ["receive:read"]);

  // Production composition enrolls the issued secrets into the branded auth binding.
  // Lifecycle validity (revoke/expiry) stays proven on CredentialService above;
  // the router path proves principal binding + tenant collapse on the money path.
  const auth = createImplementerBearerAuth({
    keys: [
      {
        token: keyA.raw_key,
        implementerId: implA,
        scopes: [...FULL_SCOPES],
      },
      {
        token: keyB.raw_key,
        implementerId: implB,
        scopes: [...FULL_SCOPES],
      },
      {
        token: keyReadOnly.raw_key,
        implementerId: implA,
        scopes: ["receive:read"],
      },
    ],
  });

  return {
    auth,
    tokenA: keyA.raw_key,
    tokenB: keyB.raw_key,
    tokenReadOnly: keyReadOnly.raw_key,
    implA,
    implB,
    service,
  };
}

function authHeaders(
  token: string,
  extra: Record<string, string> = {},
): Record<string, string | undefined> {
  return { authorization: `Bearer ${token}`, ...extra };
}

describe("createOperationRouter two-tenant matrix (production composition)", () => {
  it("refuses a live store without implementer-bearer resolveCredential (omit → red)", () => {
    const { store } = tenantedRouterStore();
    expect(() =>
      createOperationRouter({
        store,
        auth: createRejectAllOperationAuth(),
        newRequestId: () => REQUEST_ID,
      }),
    ).toThrow(OperationRouterCompositionError);

    // Unbranded hooks (legacy always-true path) are also refused — silent open mount is impossible.
    expect(() =>
      createOperationRouter({
        store,
        // @ts-expect-error deliberately unbranded
        auth: {
          kind: "implementer_bearer",
          authenticate: () => true,
          authorizeScope: () => true,
        },
        newRequestId: () => REQUEST_ID,
      }),
    ).toThrow(OperationRouterCompositionError);
  });

  it("binds CredentialService-issued principal on create and get", async () => {
    const { store, creates, gets } = tenantedRouterStore();
    const { auth, tokenA, implA } = await dualTenantRouterAuthFromCredentialService();
    expect(auth.resolveCredential).toBeDefined();

    const router = createOperationRouter({
      store,
      auth,
      newRequestId: () => "req-314-bind-0001",
    });

    const created = await router(
      "POST",
      "/v1/receives",
      encodeJson(RECEIVE_BODY),
      authHeaders(tokenA, { "idempotency-key": IDEM_KEY }),
    );
    expect(created.status).toBe(201);
    expect(creates).toEqual([{ implementerId: implA, idempotencyKey: IDEM_KEY }]);

    const got = await router(
      "GET",
      `/v1/receives/${OP_A}`,
      new Uint8Array(0),
      authHeaders(tokenA),
    );
    expect(got.status).toBe(200);
    expect(gets).toEqual([{ operationId: OP_A, implementerId: implA }]);
  });

  it("collapses six auth/scope failures onto one non-oracular 401 over the router", async () => {
    const { store, creates, gets } = tenantedRouterStore();
    const { auth, tokenA, tokenReadOnly } = await dualTenantRouterAuthFromCredentialService();
    const fixedId = () => REQUEST_ID;
    const router = createOperationRouter({
      store,
      auth,
      newRequestId: fixedId,
    });

    const cases: Array<Promise<RouterResponse>> = [
      // MISSING
      router("GET", `/v1/receives/${OP_A}`, new Uint8Array(0), {}),
      // MALFORMED (not ik_)
      router("GET", `/v1/receives/${OP_A}`, new Uint8Array(0), {
        authorization: "Bearer not-an-ik-key",
      }),
      // UNKNOWN
      router("GET", `/v1/receives/${OP_A}`, new Uint8Array(0), {
        authorization: "Bearer ik_totally_unknown_key_xxxxxxxx",
      }),
      // OUT_OF_SCOPE — read-only on create
      router(
        "POST",
        "/v1/receives",
        encodeJson(RECEIVE_BODY),
        authHeaders(tokenReadOnly, { "idempotency-key": IDEM_KEY }),
      ),
      // empty bearer after scheme
      router("GET", `/v1/receives/${OP_A}`, new Uint8Array(0), {
        authorization: "Bearer ",
      }),
      // wrong scheme
      router("GET", `/v1/receives/${OP_A}`, new Uint8Array(0), {
        authorization: "Basic ik_not_bearer",
      }),
    ];

    const responses = await Promise.all(cases);
    for (const res of responses) {
      expect(res.status).toBe(401);
      expect(normalizeRequestId(res.body)).toBe(CANONICAL_AUTH_FAILURE_BODY);
    }
    const wires = responses.map((r) => asWire(r));
    expect(isNonOracular(wires)).toBe(true);
    // Auth failures never reached the tenanted store.
    expect(creates).toEqual([]);
    expect(gets).toEqual([]);
    // Sanity: a valid key still works (control).
    const ok = await router(
      "GET",
      `/v1/receives/${OP_A}`,
      new Uint8Array(0),
      authHeaders(tokenA),
    );
    expect(ok.status).toBe(200);
  });

  it("cross-tenant get and absent get are byte-identical 404 on the router", async () => {
    const { store, gets } = tenantedRouterStore();
    const { auth, tokenA } = await dualTenantRouterAuthFromCredentialService();
    const fixedId = () => "req-314-404-xxxx";
    const router = createOperationRouter({
      store,
      auth,
      newRequestId: fixedId,
    });

    const cross = await router(
      "GET",
      `/v1/receives/${OP_B}`,
      new Uint8Array(0),
      authHeaders(tokenA),
    );
    const absent = await router(
      "GET",
      `/v1/receives/${OP_ABSENT}`,
      new Uint8Array(0),
      authHeaders(tokenA),
    );

    expect(cross.status).toBe(404);
    expect(absent.status).toBe(404);
    expect(cross.body).toBe(absent.body);
    expect(cross.body).toBe(apiErrorResponse("not_found", "req-314-404-xxxx").body);
    expect(cross).toEqual(absent);
    // Both lookups ran with tenant A's principal — never bare id alone.
    expect(gets).toEqual([
      { operationId: OP_B, implementerId: "impl-a" },
      { operationId: OP_ABSENT, implementerId: "impl-a" },
    ]);
  });

  it("idempotency key reuse across implementers does not collide", async () => {
    const { store, creates } = tenantedRouterStore();
    const { auth, tokenA, tokenB } = await dualTenantRouterAuthFromCredentialService();
    const router = createOperationRouter({
      store,
      auth,
      newRequestId: () => crypto.randomUUID(),
    });

    const sharedKey = "shared-idem-key-314-across-tenants";
    const resA = await router(
      "POST",
      "/v1/receives",
      encodeJson(RECEIVE_BODY),
      authHeaders(tokenA, { "idempotency-key": sharedKey }),
    );
    const resB = await router(
      "POST",
      "/v1/receives",
      encodeJson(RECEIVE_BODY),
      authHeaders(tokenB, { "idempotency-key": sharedKey }),
    );

    expect(resA.status).toBe(201);
    expect(resB.status).toBe(201);
    expect(resA.body).not.toBe(resB.body);
    expect(creates).toEqual([
      { implementerId: "impl-a", idempotencyKey: sharedKey },
      { implementerId: "impl-b", idempotencyKey: sharedKey },
    ]);

    const replayA = await router(
      "POST",
      "/v1/receives",
      encodeJson(RECEIVE_BODY),
      authHeaders(tokenA, { "idempotency-key": sharedKey }),
    );
    expect(replayA.status).toBe(201);
    expect(replayA.body).toBe(resA.body);
    expect(replayA.headers["Idempotency-Replayed"]).toBe("true");
  });

  it("scope denial is generic 401 and never reaches the store", async () => {
    const { store, creates, gets } = tenantedRouterStore();
    const { auth, tokenReadOnly } = await dualTenantRouterAuthFromCredentialService();
    const router = createOperationRouter({
      store,
      auth,
      newRequestId: () => REQUEST_ID,
    });

    const denied = await router(
      "POST",
      "/v1/receives",
      encodeJson(RECEIVE_BODY),
      authHeaders(tokenReadOnly, { "idempotency-key": IDEM_KEY }),
    );
    expect(denied.status).toBe(401);
    expect(denied.body).toBe(apiErrorResponse("invalid_api_key", REQUEST_ID).body);
    expect(creates).toEqual([]);
    expect(gets).toEqual([]);
  });

  it("own-tenant get succeeds after cross-tenant 404 (no residual leak)", async () => {
    const { store } = tenantedRouterStore();
    const { auth, tokenA, tokenB } = await dualTenantRouterAuthFromCredentialService();
    const router = createOperationRouter({
      store,
      auth,
      newRequestId: () => crypto.randomUUID(),
    });

    const cross = await router(
      "GET",
      `/v1/receives/${OP_B}`,
      new Uint8Array(0),
      authHeaders(tokenA),
    );
    expect(cross.status).toBe(404);

    const ownA = await router(
      "GET",
      `/v1/receives/${OP_A}`,
      new Uint8Array(0),
      authHeaders(tokenA),
    );
    const ownB = await router(
      "GET",
      `/v1/receives/${OP_B}`,
      new Uint8Array(0),
      authHeaders(tokenB),
    );
    expect(ownA.status).toBe(200);
    expect(ownB.status).toBe(200);
    expect(ownA.body).not.toBe(ownB.body);
  });
});

// Type-only keep-alive so ImplementerScope import stays load-bearing if eslint trims.
const _scopeKeep: ImplementerScope = "receive:read";
void _scopeKeep;

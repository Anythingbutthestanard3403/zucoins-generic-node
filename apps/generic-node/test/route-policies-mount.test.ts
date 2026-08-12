// Production ROUTE_POLICIES census + halt deferral honesty.

import { describe, expect, it } from "vitest";
import { ROUTE_POLICIES } from "@zucoins/generic-node-contracts/route-policy";
import { ADMIN_ROUTES } from "@zucoins/generic-node-contracts/operations";

import {
  DEFERRED_HALT_ROUTE,
  requiredProductionRouteKeys,
  routeKeyOf,
  routeManifestParityFindings,
  routePolicyKeys,
} from "@zucoins/node-core";

import {
  runtimeMountedRouteKeys,
} from "../src/runtime-listener.js";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  createProductionRouteSurface,
  DEFERRED_ADMIN_MONEY_ENGINES,
  DURABLE_REPORTING_STORE,
  DurableReportingRequestStore,
} from "../src/full-http-mount.js";
import type {
  ProofBodyStore,
  ReportingRateLimiter,
  VaultAccessAuditLog,
} from "@zucoins/node-core";
import type { SqlVerificationAccessStore } from "../src/reporting/durable-security-ports.js";


/** Non-zero 32-byte test vault root for SqlAdminUserStore composition (ZTR-1134 B3). */
const ZTR_1134_TEST_VAULT_ROOT = Buffer.alloc(32, 0xa7);


// createProductionRouteSurface production hard-stops on missing durable security
// ports. Mirrors the lightweight fakes in reporting/durable-security-ports.pg.test.ts — this
// test never exercises rate-limiting/proof-body/verification-material/vault-audit behavior.
const fakeRateLimiter: ReportingRateLimiter = { consume: async () => true };
const fakeProofBodyStore = { findByPathProof: async () => [] } as unknown as ProofBodyStore;
const fakeVerificationAccessStore = {} as SqlVerificationAccessStore;
const fakeVaultAccessAuditLog: VaultAccessAuditLog = { record: async () => {} };

describe("production ROUTE_POLICIES census (AC1–AC2, AC7–AC8)", () => {
  it("ROUTE_POLICIES has 25 frozen entries", () => {
    expect(ROUTE_POLICIES).toHaveLength(25);
  });

  it("manifest parity: PUBLIC∪ADMIN === ROUTE_POLICIES (OpenAPI honesty AC6)", () => {
    expect(routeManifestParityFindings()).toEqual([]);
  });

  it("required production keys = ROUTE_POLICIES ∪ health probes", () => {
    const keys = new Set(requiredProductionRouteKeys());
    for (const policy of ROUTE_POLICIES) {
      expect(keys.has(routeKeyOf(policy.method, policy.path))).toBe(true);
    }
    expect(keys.has("GET /health")).toBe(true);
    expect(keys.has("GET /health/ready")).toBe(true);
    expect(keys.has("GET /metrics")).toBe(false);
  });

  it("runtime full mount keys equal requiredProductionRouteKeys (AC2)", () => {
    const mounted = new Set(
      runtimeMountedRouteKeys({ metricsMounted: false, fullRoutePolicies: true }),
    );
    const required = new Set(requiredProductionRouteKeys());
    expect([...mounted].sort()).toEqual([...required].sort());
  });

  it("optional /metrics appears only when metricsMounted", () => {
    const withMetrics = runtimeMountedRouteKeys({
      metricsMounted: true,
      fullRoutePolicies: true,
    });
    expect(withMetrics).toContain("GET /metrics");
  });

  it("AC7: /admin/v1/halt is live on admin router but stays out of ROUTE_POLICIES", () => {
    expect(DEFERRED_HALT_ROUTE.path).toBe("/admin/v1/halt");
    expect(DEFERRED_HALT_ROUTE.live).toBe(true);
    expect(routePolicyKeys()).not.toContain(
      routeKeyOf(DEFERRED_HALT_ROUTE.method, DEFERRED_HALT_ROUTE.path),
    );
    // Not part of implementer_bearer mount set — operator SPA admin extension.
    const mounted = runtimeMountedRouteKeys({
      metricsMounted: true,
      fullRoutePolicies: true,
    });
    expect(mounted).not.toContain(
      routeKeyOf(DEFERRED_HALT_ROUTE.method, DEFERRED_HALT_ROUTE.path),
    );
  });

  it("AC8: recovery admin path templates match ADMIN_ROUTES", () => {
    const admin = ADMIN_ROUTES.map((r) => routeKeyOf(r.method, r.path));
    expect(admin).toContain("GET /admin/v1/operations/needs-attention");
    expect(admin).toContain("GET /admin/v1/operations/:operation_id/recovery");
    expect(admin).toContain("POST /admin/v1/operations/:operation_id/recovery-actions");
    const mounted = runtimeMountedRouteKeys({
      metricsMounted: false,
      fullRoutePolicies: true,
    });
    for (const key of admin) {
      expect(mounted).toContain(key);
    }
  });

  it("production surface exposes mount keys + live halt", async () => {
    const surface = createProductionRouteSurface({
    dualControlMode: "single_operator",
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      nodeId: "11111111-1111-4111-8111-111111111111",
      pool: { query: async () => ({ rows: [] }) } as never,
      rateLimiter: fakeRateLimiter,
      proofBodyStore: fakeProofBodyStore,
      verificationAccessStore: fakeVerificationAccessStore,
      vaultAccessAuditLog: fakeVaultAccessAuditLog,
    });
    expect(surface.mountedRouteKeys).toEqual(requiredProductionRouteKeys());
    expect(surface.deferredHalt.path).toBe("/admin/v1/halt");
    expect(surface.deferredHalt.live).toBe(true);
    expect(surface.liveHaltRoutes.map((r) => `${r.method} ${r.path}`)).toEqual([
      "GET /admin/v1/halt",
      "POST /admin/v1/halt",
    ]);
    expect(
      surface.liveAttentionRetractionRoutes.map((r) => `${r.method} ${r.path}`),
    ).toEqual(["POST /admin/v1/operations/:operation_id/attention-retraction"]);
    expect(
      surface.liveOperatorParkRoutes.map((r) => `${r.method} ${r.path}`),
    ).toEqual(["POST /admin/v1/operations/:operation_id/operator-park"]);
    expect(surface.liveImplementerRoutes.map((r) => `${r.method} ${r.path}`)).toEqual([
      "GET /admin/v1/implementers",
      "POST /admin/v1/implementers",
      "POST /admin/v1/implementers/:id/retire",
      "GET /admin/v1/api-keys",
      "POST /admin/v1/api-keys",
      "POST /admin/v1/api-keys/:id/revoke",
    ]);
    expect(surface.liveAutoApprovePolicyRoutes.map((r) => `${r.method} ${r.path}`)).toEqual([
      "GET /admin/v1/auto-approve-policy",
      "POST /admin/v1/auto-approve-policy",
    ]);
    expect(surface.liveIntegrationRequestRoutes.map((r) => `${r.method} ${r.path}`)).toEqual([
      "GET /admin/v1/integration-requests",
      "POST /admin/v1/integration-requests/:id/approve",
      "POST /admin/v1/integration-requests/:id/decline",
    ]);
    expect(surface.adminRouteDeps.integrationRequestStore).toBeDefined();
    expect(surface.adminRouteDeps.halt).toBeDefined();
    expect(surface.adminRouteDeps.implementerRegistry).toBeDefined();
    expect(surface.adminRouteDeps.adminIdempotencyStore).toBeDefined();
    expect(surface.adminRouteDeps.atomicAdminMutation).toBeDefined();
    expect((await surface.discoveryDocument()).node_id).toBe(
      "11111111-1111-4111-8111-111111111111",
    );
    expect(typeof surface.reportingListener).toBe("function");
    expect(surface.adminRouteDeps.nodeId).toBe("11111111-1111-4111-8111-111111111111");
  });

  it("admin money challenge+send+recovery-action+attention-retraction all live", () => {
    const surface = createProductionRouteSurface({
    dualControlMode: "single_operator",
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      nodeId: "11111111-1111-4111-8111-111111111111",
      pool: { query: async () => ({ rows: [] }) } as never,
      env: {},
      rateLimiter: fakeRateLimiter,
      proofBodyStore: fakeProofBodyStore,
      verificationAccessStore: fakeVerificationAccessStore,
      vaultAccessAuditLog: fakeVaultAccessAuditLog,
    });
    expect(surface.adminMoneyLive).toBe(true);
    expect(surface.adminTotpLabBound).toBe(false);
    expect(surface.deferredAdminMoney).toBe(DEFERRED_ADMIN_MONEY_ENGINES);
    expect(surface.deferredAdminMoney.ticket).toMatch(/challenge \+ send-decision live/);
    expect(surface.deferredAdminMoney.challengeStore).toMatch(/live/i);
    expect(surface.deferredAdminMoney.sendDecisionStore).toMatch(/live/i);
    expect(surface.deferredAdminMoney.recoveryActionStore).toMatch(/live/i);
    expect(surface.deferredAdminMoney.attentionRetractionStore).toMatch(/live/i);
    expect(surface.deferredAdminMoney.operatorParkStore).toMatch(/live/i);
  });

  it("operator-park is live on admin router but stays out of ROUTE_POLICIES", () => {
    const policy = routePolicyKeys();
    expect(policy).not.toContain(
      "POST /admin/v1/operations/:operation_id/operator-park",
    );
    const surface = createProductionRouteSurface({
    dualControlMode: "single_operator",
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      nodeId: "11111111-1111-4111-8111-111111111111",
      pool: { query: async () => ({ rows: [] }) } as never,
    });
    expect(surface.deferredAdminMoney.operatorParkStore).toMatch(/live/i);
    expect(surface.deferredAdminMoney.operatorParkStore).toMatch(/createSqlOperatorParkStore/);
  });

  it("attention-retraction is live on admin router but stays out of ROUTE_POLICIES", () => {
    const policy = routePolicyKeys();
    expect(policy).not.toContain(
      "POST /admin/v1/operations/:operation_id/attention-retraction",
    );
    const surface = createProductionRouteSurface({
    dualControlMode: "single_operator",
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      nodeId: "11111111-1111-4111-8111-111111111111",
      pool: { query: async () => ({ rows: [] }) } as never,
    });
    expect(surface.deferredAdminMoney.attentionRetractionStore).toMatch(/live/i);
    expect(surface.deferredAdminMoney.attentionRetractionStore).toMatch(/createSqlAttentionRetractionStore/);
  });

  it("ADMIN_TOTP_SECRET alone does not lab-bind (explicit flag required)", () => {
    const secretHex = Buffer.alloc(20, 7).toString("hex");
    const surface = createProductionRouteSurface({
    dualControlMode: "single_operator",
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      nodeId: "11111111-1111-4111-8111-111111111111",
      pool: { query: async () => ({ rows: [] }) } as never,
      env: { ADMIN_TOTP_SECRET: secretHex },
      rateLimiter: fakeRateLimiter,
      proofBodyStore: fakeProofBodyStore,
      verificationAccessStore: fakeVerificationAccessStore,
      vaultAccessAuditLog: fakeVaultAccessAuditLog,
    });
    expect(surface.adminMoneyLive).toBe(true);
    expect(surface.adminTotpLabBound).toBe(false);
  });

  it("lab mode + secret arms process TOTP (undurable)", () => {
    const secretHex = Buffer.alloc(20, 7).toString("hex");
    const surface = createProductionRouteSurface({
    dualControlMode: "single_operator",
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      nodeId: "11111111-1111-4111-8111-111111111111",
      pool: { query: async () => ({ rows: [] }) } as never,
      env: { ADMIN_TOTP_LAB_MODE: "1", ADMIN_TOTP_SECRET: secretHex },
      rateLimiter: fakeRateLimiter,
      proofBodyStore: fakeProofBodyStore,
      verificationAccessStore: fakeVerificationAccessStore,
      vaultAccessAuditLog: fakeVaultAccessAuditLog,
    });
    expect(surface.adminMoneyLive).toBe(true);
    expect(surface.adminTotpLabBound).toBe(true);
  });

  it("Review B r2: production NODE_ENV hard-stops lab even with flags", async () => {
    const { isAdminTotpLabMode, resolveLabTotp, applyLabTotpBinding } = await import(
      "../src/full-http-mount.js"
    );
    const secretHex = Buffer.alloc(20, 7).toString("hex");
    const prodEnv = {
      NODE_ENV: "production",
      ADMIN_TOTP_LAB_MODE: "1",
      ADMIN_TOTP_SECRET: secretHex,
    };
    expect(isAdminTotpLabMode(prodEnv)).toBe(false);
    expect(resolveLabTotp({ env: prodEnv })).toBeNull();
    expect(resolveLabTotp({ env: prodEnv, labTotpMode: true, totp: {
      secret: Buffer.alloc(20, 7),
      windowSteps: 1,
    } })).toBeNull();

    const surface = createProductionRouteSurface({
    dualControlMode: "single_operator",
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      nodeId: "11111111-1111-4111-8111-111111111111",
      pool: { query: async () => ({ rows: [] }) } as never,
      env: prodEnv,
      rateLimiter: fakeRateLimiter,
      proofBodyStore: fakeProofBodyStore,
      verificationAccessStore: fakeVerificationAccessStore,
      vaultAccessAuditLog: fakeVaultAccessAuditLog,
    });
    expect(surface.adminTotpLabBound).toBe(false);

    const { InMemoryAdminUserStore, bootstrapInitialAdmin } = await import("@zucoins/node-core");
    const users = new InMemoryAdminUserStore();
    await bootstrapInitialAdmin(users, { INITIAL_ADMIN_PASSWORD: "correct-horse-battery-staple" });
    const lab = resolveLabTotp({
      env: { ADMIN_TOTP_LAB_MODE: "1", ADMIN_TOTP_SECRET: secretHex, NODE_ENV: "development" },
    });
    expect(lab).not.toBeNull();
    const bound = await applyLabTotpBinding(users, lab, {
      ADMIN_TOTP_LAB_MODE: "1",
      NODE_ENV: "development",
    });
    expect(bound.bound).toBe(true);
    expect(bound.durable).toBe(false);
    const admin = await users.findByUsername("admin");
    expect(admin!.mustEnrolTotp).toBe(true);
    const factor = await users.getTotpFactor(admin!.id);
    expect(factor.status).toBe("none");
  });

  it("PUBLIC_BASE_URL origin is always in CSRF allowlist (same-origin SPA)", async () => {
    const { resolveAdminCsrfOrigins } = await import("../src/full-http-mount.js");
    expect(
      resolveAdminCsrfOrigins({
        publicBaseUrl: "https://node.merchant.example/ops",
        extraOrigins: ["http://localhost:5174"],
      }),
    ).toEqual(["https://node.merchant.example", "http://localhost:5174"]);

    const surface = createProductionRouteSurface({
    dualControlMode: "single_operator",
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      nodeId: "11111111-1111-4111-8111-111111111111",
      pool: { query: async () => ({ rows: [] }) } as never,
      publicBaseUrl: "https://node.merchant.example/",
      adminAllowedOrigins: ["http://localhost:5174"],
      rateLimiter: fakeRateLimiter,
      proofBodyStore: fakeProofBodyStore,
      verificationAccessStore: fakeVerificationAccessStore,
      vaultAccessAuditLog: fakeVaultAccessAuditLog,
    });
    expect(surface.adminCsrfAllowedOrigins).toEqual([
      "https://node.merchant.example",
      "http://localhost:5174",
    ]);
    expect(surface.adminRouteDeps.csrf.allowedOrigins).toEqual(
      surface.adminCsrfAllowedOrigins,
    );
  });
  it("production binds SqlAdminSessionStore (not InMemory) for cookie PG verify", () => {
    const srcPath = fileURLToPath(
      new URL("../src/full-http-mount.ts", import.meta.url),
    );
    const src = readFileSync(srcPath, "utf8");
    expect(src).not.toMatch(/new InMemoryAdminSessionStore/);
    expect(src).toMatch(/SqlAdminSessionStore/);
    expect(src).toMatch(/createPoolAdminSessionExecutor/);

    const surface = createProductionRouteSurface({
    dualControlMode: "single_operator",
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      nodeId: "11111111-1111-4111-8111-111111111111",
      pool: { query: async () => ({ rows: [] }) } as never,
      env: {},
      rateLimiter: fakeRateLimiter,
      proofBodyStore: fakeProofBodyStore,
      verificationAccessStore: fakeVerificationAccessStore,
      vaultAccessAuditLog: fakeVaultAccessAuditLog,
    });
    expect(surface.adminSessionStore.constructor.name).toBe("SqlAdminSessionStore");
  });
});

describe("durable reporting PG store on custody production surface", () => {
  // Unit-test-only InMemoryReportingStore sites live under packages/node-core
  // reporting tests and apps/generic-node/test/http-adapter.test.ts — never here.
  it("AC1 source census: full-http-mount production factory never constructs InMemoryReportingStore", () => {
    const srcPath = fileURLToPath(
      new URL("../src/full-http-mount.ts", import.meta.url),
    );
    const src = readFileSync(srcPath, "utf8");
    expect(src).not.toMatch(/InMemoryReportingStore/);
    expect(src).toMatch(/DurableReportingRequestStore/);
    expect(src).toMatch(/createPoolReportingClient/);
  });

  it("AC1/AC2: composition binds DurableReportingRequestStore (durable-pg kind)", () => {
    const surface = createProductionRouteSurface({
    dualControlMode: "single_operator",
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      nodeId: "11111111-1111-4111-8111-111111111111",
      pool: { query: async () => ({ rows: [] }), connect: async () => ({}) } as never,
      env: {},
      rateLimiter: fakeRateLimiter,
      proofBodyStore: fakeProofBodyStore,
      verificationAccessStore: fakeVerificationAccessStore,
      vaultAccessAuditLog: fakeVaultAccessAuditLog,
    });
    expect(surface.reportingStoreKind).toBe(DURABLE_REPORTING_STORE);
    expect(surface.reportingStoreKind.kind).toBe("durable-pg");
    expect(surface.reportingStore).toBeInstanceOf(DurableReportingRequestStore);
  });

  it("AC4: stage1-main zero-custody entry does not admit money reporting", () => {
    const stage1Path = fileURLToPath(
      new URL("../src/stage1-main.ts", import.meta.url),
    );
    const stage1 = readFileSync(stage1Path, "utf8");
    expect(stage1).not.toMatch(/createProductionRouteSurface/);
    expect(stage1).not.toMatch(/InMemoryReportingStore|DurableReportingRequestStore/);
    expect(stage1).not.toMatch(/createReportingRequestVerifier|reportingListener/);
  });
});

describe("B2 source census: main.ts wires only durable security ports", () => {
  it("production entry constructs the Sql* ports and never an InMemory* port", () => {
    const mainPath = fileURLToPath(new URL("../src/main.ts", import.meta.url));
    const src = readFileSync(mainPath, "utf8");
    expect(src).toMatch(/new SqlReportingRateLimiter/);
    expect(src).toMatch(/new SqlVaultAccessAuditLog/);
    expect(src).toMatch(/new SqlProofBodyStore/);
    expect(src).toMatch(/new SqlVerificationAccessStore/);
    expect(src).not.toMatch(
      /InMemory(ReportingRateLimiter|VaultAccessAuditLog|ProofBodyStore|VerificationAccessStore)/,
    );
  });
});

describe("ZTR-1134 B3 vaultRootKey composition", () => {
  it("throws when defaulting SqlAdminUserStore without vaultRootKey", () => {
    expect(() =>
      createProductionRouteSurface({
    dualControlMode: "single_operator",
        nodeId: "11111111-1111-4111-8111-111111111111",
        pool: { query: async () => ({ rows: [] }) } as never,
      }),
    ).toThrow(/vaultRootKey required/);
  });

  it("throws on all-zero vaultRootKey", () => {
    expect(() =>
      createProductionRouteSurface({
    dualControlMode: "single_operator",
        nodeId: "11111111-1111-4111-8111-111111111111",
        pool: { query: async () => ({ rows: [] }) } as never,
        vaultRootKey: Buffer.alloc(32, 0),
      }),
    ).toThrow(/all-zero/);
  });
});

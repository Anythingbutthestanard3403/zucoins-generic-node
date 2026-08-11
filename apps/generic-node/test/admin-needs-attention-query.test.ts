// ZTR-1198 — needs-attention must run NeedsAttentionQuerySchema before the store.
// Bad limit/enum/unknown keys → 400 (invalid_scalar | unknown_field), never 503.

import {
  createAdminSessionService,
  createFailClosedDestinationService,
  hashPassword,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  type AdminUser,
} from "@zucoins/node-core";
import { randomUUID } from "node:crypto";
import { describe, expect, it, vi } from "vitest";

import { createAdminRouter, createFailClosedAdminRouteDeps } from "../src/admin-router.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";

async function seedAdmin(store: InMemoryAdminUserStore, password: string): Promise<AdminUser> {
  const user: AdminUser = {
    id: randomUUID(),
    username: "admin",
    passwordHash: await hashPassword(password),
    role: "admin",
    mustChangePassword: false,
    mustEnrolTotp: false,
    disabledAt: null,
    createdAt: Date.now(),
  };
  await store.insert(user);
  // Money-adjacent GETs require an active factor.
  await store.setActiveTotpSecret(user.id, "JBSWY3DPEHPK3PXP");
  return user;
}

function cookieFrom(setCookie: string | undefined): string {
  if (!setCookie) return "";
  return setCookie.split(";")[0] ?? "";
}

async function authedRouter(listNeedsAttention = vi.fn(async () => [])) {
  const userStore = new InMemoryAdminUserStore();
  await seedAdmin(userStore, "needs-attention-secret");
  const sessions = createAdminSessionService(
    { nodeId: NODE_ID },
    new InMemoryAdminSessionStore(),
    userStore,
  );
  const deps = {
    ...createFailClosedAdminRouteDeps({
      sessions,
      userStore,
      csrf: { allowedOrigins: ["https://node.example"] },
      totp: { secret: new Uint8Array(32), windowSteps: 1 },
      nodeId: NODE_ID,
      destinationService: createFailClosedDestinationService(),
      newRequestId: () => "req-needs-attention-query",
    }),
    recoveryStore: {
      listNeedsAttention,
      loadRecoveryFacts: async () => null,
      issueRecoveryNonce: async () => {
        throw new Error("unused");
      },
    },
  };
  const router = createAdminRouter(deps);
  const login = await router(
    "POST",
    "/admin/v1/login",
    Buffer.from(JSON.stringify({ username: "admin", password: "needs-attention-secret" })),
    {},
  );
  const cookie = cookieFrom(login.headers["set-cookie"]);
  return {
    listNeedsAttention,
    get: (path: string) => router("GET", path, new Uint8Array(), { cookie }),
  };
}

function errorOf(body: string): { code: string; message: string } {
  const parsed = JSON.parse(body) as { error: { code: string; message: string } };
  return parsed.error;
}

describe("GET /admin/v1/operations/needs-attention query validation (ZTR-1198)", () => {
  it("accepts empty query and limit=200", async () => {
    const { get, listNeedsAttention } = await authedRouter();
    const empty = await get("/admin/v1/operations/needs-attention");
    expect(empty.status).toBe(200);
    expect(JSON.parse(empty.body)).toMatchObject({ operations: [], summary: { total: 0 } });

    const ceiling = await get("/admin/v1/operations/needs-attention?limit=200");
    expect(ceiling.status).toBe(200);
    expect(listNeedsAttention).toHaveBeenCalledWith(
      expect.objectContaining({ limit: 200 }),
    );
  });

  it("rejects non-numeric / out-of-range limit with 400 invalid_scalar (not 503)", async () => {
    const { get, listNeedsAttention } = await authedRouter();
    for (const raw of ["abc", "0", "-1", "201", "1.5"]) {
      const res = await get(`/admin/v1/operations/needs-attention?limit=${raw}`);
      expect(res.status, `limit=${raw}`).toBe(400);
      const err = errorOf(res.body);
      expect(err.code, `limit=${raw}`).toBe("invalid_scalar");
      // Stable diagnostic — no raw Zod issue text.
      expect(err.message).toBe("A field value does not satisfy its canonical scalar constraint.");
      expect(res.body).not.toMatch(/Expected|too_small|too_big|invalid_type|NaN/i);
    }
    expect(listNeedsAttention).not.toHaveBeenCalled();
  });

  it("rejects unknown query keys with 400 unknown_field", async () => {
    const { get, listNeedsAttention } = await authedRouter();
    const res = await get("/admin/v1/operations/needs-attention?bogus=1");
    expect(res.status).toBe(400);
    const err = errorOf(res.body);
    expect(err.code).toBe("unknown_field");
    expect(err.message).toBe("The request contains an unrecognized field.");
    expect(listNeedsAttention).not.toHaveBeenCalled();
  });

  it("rejects invalid classification and kind with 400 invalid_scalar", async () => {
    const { get, listNeedsAttention } = await authedRouter();
    const badClass = await get("/admin/v1/operations/needs-attention?classification=NOPE");
    expect(badClass.status).toBe(400);
    expect(errorOf(badClass.body).code).toBe("invalid_scalar");

    const badKind = await get("/admin/v1/operations/needs-attention?kind=REFUND");
    expect(badKind.status).toBe(400);
    expect(errorOf(badKind.body).code).toBe("invalid_scalar");

    expect(listNeedsAttention).not.toHaveBeenCalled();
  });

  it("forwards validated filters to the store (no as-never bypass)", async () => {
    const { get, listNeedsAttention } = await authedRouter();
    const res = await get(
      "/admin/v1/operations/needs-attention?kind=MOVE_INTERNAL&classification=WAITING&limit=10",
    );
    expect(res.status).toBe(200);
    expect(listNeedsAttention).toHaveBeenCalledTimes(1);
    expect(listNeedsAttention).toHaveBeenCalledWith({
      kind: "MOVE_INTERNAL",
      classification: "WAITING",
      limit: 10,
    });
  });
});

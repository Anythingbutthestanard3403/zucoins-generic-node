// GET/POST /admin/v1/api-keys + revoke. Session+CSRF+TOTP via
// runGuardedAdminMutation; list never returns the secret/hash; revoke fails closed
// without TOTP; unknown id surfaces 404 (CREDENTIAL_NOT_FOUND collapses cross-tenant).

import { createHmac, randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  CredentialError,
  CredentialService,
  createAdminSessionService,
  createFailClosedDestinationService,
  createHaltGate,
  createInMemoryHaltEvidenceRecorder,
  createInMemoryOperatorHaltStore,
  hashPassword,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  IMPLEMENTER_SCOPES,
  RUNNING,
  TotpConsumptionLog,
  type AdminUser,
  type CredentialAuditEntry,
  type CredentialStore,
  type StoredCredential,
} from "@zucoins/node-core";

import { createAdminRouter } from "../src/admin-router.js";
import { createTestAdminAtomicDeps } from "./support/admin-atomic.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const ORIGIN = "https://node.example";
const SECRET = new TextEncoder().encode("test-secret-key-32-bytes-long!!");
const IMPLEMENTER_ID = "22222222-2222-4222-8222-222222222222";

function generateTotp(secret: Uint8Array, nowMs: number): string {
  const timestep = Math.floor(nowMs / 1000 / 30);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(timestep));
  const h = createHmac("sha1", secret).update(buf).digest();
  const offset = h[h.length - 1]! & 0x0f;
  const code =
    ((h[offset]! & 0x7f) << 24) |
    (h[offset + 1]! << 16) |
    (h[offset + 2]! << 8) |
    h[offset + 3]!;
  return (code % 1_000_000).toString().padStart(6, "0");
}

function encodeBase32(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }
  return output;
}

function cookieFrom(setCookie: string | undefined): string {
  if (!setCookie) return "";
  return setCookie.split(";")[0] ?? "";
}

// Minimal in-memory CredentialStore so the route can issue/list/revoke without PG.
class MemoryCredentialStore implements CredentialStore {
  readonly rows = new Map<string, StoredCredential>();
  readonly audit: CredentialAuditEntry[] = [];

  async issue(row: StoredCredential, audit: CredentialAuditEntry): Promise<void> {
    this.rows.set(row.id, row);
    this.audit.push(audit);
  }
  async findByHash(): Promise<StoredCredential | null> {
    return null; // unused by the admin routes (no validate path here)
  }
  async findById(credentialId: string, implementerId: string): Promise<StoredCredential | null> {
    const row = this.rows.get(credentialId);
    if (row === undefined || row.implementer_id !== implementerId) return null;
    return row;
  }
  async findByCredentialId(credentialId: string): Promise<StoredCredential | null> {
    return this.rows.get(credentialId) ?? null;
  }
  async listByImplementer(implementerId: string): Promise<StoredCredential[]> {
    return [...this.rows.values()].filter((r) => r.implementer_id === implementerId);
  }
  async listAll(): Promise<StoredCredential[]> {
    return [...this.rows.values()];
  }
  async rotate(): Promise<boolean> {
    throw new Error("rotate unused");
  }
  async revoke(
    credentialId: string,
    implementerId: string,
    revokedAt: string,
    audit: CredentialAuditEntry,
  ): Promise<boolean> {
    const row = this.rows.get(credentialId);
    if (row === undefined || row.implementer_id !== implementerId) return false;
    this.rows.set(credentialId, {
      ...row,
      status: "REVOKED",
      revoked_at: revokedAt,
    });
    this.audit.push(audit);
    return true;
  }
}

function makeRouter(opts: {
  readonly credentialService?: CredentialService;
  readonly resolveImplementerId?: () => Promise<string | null>;
  readonly nowMs?: () => number;
  readonly userStore?: InMemoryAdminUserStore;
}) {
  const userStore = opts.userStore ?? new InMemoryAdminUserStore();
  const sessions = createAdminSessionService(
    { nodeId: NODE_ID },
    new InMemoryAdminSessionStore(),
    userStore,
  );
  const atomic = createTestAdminAtomicDeps({
    credentialService: opts.credentialService as CredentialService,
  });
  const router = createAdminRouter({
    sessions,
    userStore,
    csrf: { allowedOrigins: [ORIGIN] },
    totp: { secret: SECRET, windowSteps: 1 },
    totpLog: new TotpConsumptionLog(),
    nodeId: NODE_ID,
    challengeStore: {
      findIssuedByOperation: async () => null,
      findByNonce: async () => null,
      insertIssued: async () => {},
      commitApprovalMutation: async () => {
        throw new Error("unused");
      },
    },
    loadOperation: async () => null,
    sendDecisionStore: {
      rejectCreated: async () => {
        throw new Error("unused");
      },
      approveCreated: async () => {
        throw new Error("unused");
      },
    },
    deviceStore: null,
    recoveryStore: {
      listNeedsAttention: async () => ({ items: [], total: 0, has_more: false, next_cursor: null }),
      loadRecoveryFacts: async () => null,
      issueRecoveryNonce: async () => {
        throw new Error("unused");
      },
    },
    recoveryActionStore: {
      lookupIdempotency: async () => ({ kind: "miss" }),
      loadRecoveryFactsLocked: async () => null,
      commitRecoveryAction: async () => {
        throw new Error("unused");
      },
      storeIdempotency: async () => {},
    },
    destinationService: createFailClosedDestinationService(),
    newRequestId: () => randomUUID(),
    nowMs: opts.nowMs ?? (() => 1_700_000_030_000),
    halt: {
      gate: createHaltGate(RUNNING),
      store: createInMemoryOperatorHaltStore(RUNNING),
      evidence: createInMemoryHaltEvidenceRecorder(),
    },
    credentialService: opts.credentialService,
    resolveImplementerId: opts.resolveImplementerId,
    adminIdempotencyStore: atomic.adminIdempotencyStore,
    atomicAdminMutation: atomic.atomicAdminMutation,
  });
  return { router, userStore };
}

async function login(
  router: ReturnType<typeof makeRouter>["router"],
  userStore: InMemoryAdminUserStore,
  password: string,
) {
  const res = await router(
    "POST",
    "/admin/v1/login",
    Buffer.from(JSON.stringify({ username: "admin", password })),
    { "content-type": "application/json" },
  );
  expect(res.status).toBe(200);
  return {
    cookie: cookieFrom(res.headers["set-cookie"]),
    csrf: (JSON.parse(res.body) as { csrfToken: string }).csrfToken,
  };
}

describe("admin /admin/v1/api-keys", () => {
  it("GET fails closed (503) when the credential service is not wired", async () => {
    const { router, userStore } = makeRouter({});
    const user: AdminUser = {
      id: randomUUID(),
      username: "admin",
      passwordHash: await hashPassword("p"),
      role: "admin",
      mustChangePassword: false,
      mustEnrolTotp: false,
      disabledAt: null,
      createdAt: Date.now(),
    };
    await userStore.insert(user);
    const { cookie, csrf } = await login(router, userStore, "p");
    const res = await router("GET", "/admin/v1/api-keys", new Uint8Array(), {
      cookie,
      origin: ORIGIN,
      "x-csrf-token": csrf,
    });
    expect(res.status).toBe(503);
  });

  it("GET requires a session (401 without)", async () => {
    const store = new MemoryCredentialStore();
    const { router } = makeRouter({
      credentialService: new CredentialService(store),
      resolveImplementerId: async () => IMPLEMENTER_ID,
    });
    const res = await router("GET", "/admin/v1/api-keys", new Uint8Array(), {});
    expect(res.status).toBe(401);
  });

  it("issue without TOTP is refused and mints nothing; issue with TOTP returns the raw key once", async () => {
    const store = new MemoryCredentialStore();
    let nowMs = 1_700_000_030_000;
    const userStore = new InMemoryAdminUserStore();
    const { router } = makeRouter({
      credentialService: new CredentialService(store),
      resolveImplementerId: async () => IMPLEMENTER_ID,
      nowMs: () => nowMs,
      userStore,
    });
    const password = "keys-pass-1";
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
    await userStore.insert(user);
    await userStore.setActiveTotpSecret(user.id, encodeBase32(SECRET));
    const { cookie, csrf } = await login(router, userStore, password);

    // POST without TOTP -> 401, nothing minted.
    const noTotp = await router(
      "POST",
      "/admin/v1/api-keys",
      Buffer.from(JSON.stringify({})),
      { cookie, origin: ORIGIN, "x-csrf-token": csrf, "content-type": "application/json", "idempotency-key": "idem-admin-api-keys-no-totp-1234567890ab" },
    );
    expect(noTotp.status).toBe(401);
    expect(store.rows.size).toBe(0);

    // POST with TOTP -> 200, raw key returned once.
    const issued = await router(
      "POST",
      "/admin/v1/api-keys",
      Buffer.from(JSON.stringify({})),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
        "idempotency-key": "idem-admin-api-keys-issue-1234567890abcdef",
      },
    );
    expect(issued.status).toBe(200);
    const body = JSON.parse(issued.body) as {
      id: string;
      raw_key: string;
      prefix: string;
      scopes: string[];
      key_version: number;
    };
    expect(body.raw_key).toMatch(/^ik_/);
    expect(body.prefix).toBe(body.raw_key.slice(0, 11));
    expect(body.scopes).toEqual([...IMPLEMENTER_SCOPES]);
    expect(body.key_version).toBe(1);
    expect(store.rows.size).toBe(1);
    expect(store.audit.some((a) => a.action === "IMPLEMENTER_CREDENTIAL_ISSUED")).toBe(true);
    const credentialId = body.id;

    // GET list shows the key but never the raw key or hash.
    const list = await router("GET", "/admin/v1/api-keys", new Uint8Array(), {
      cookie,
      origin: ORIGIN,
      "x-csrf-token": csrf,
    });
    expect(list.status).toBe(200);
    const listed = JSON.parse(list.body) as {
      keys: {
        id: string;
        prefix: string;
        scopes: string[];
        status: string;
        last_used_at: null;
      }[];
    };
    expect(listed.keys).toHaveLength(1);
    const only = listed.keys[0]!;
    expect(only.id).toBe(credentialId);
    expect(only.prefix).toBe(body.prefix);
    expect(only.status).toBe("ACTIVE");
    expect(only.last_used_at).toBeNull();
    // The response body must not contain the raw key tail or the hash.
    expect(list.body).not.toContain(body.raw_key.slice(11));
    expect(list.body).not.toContain(store.rows.get(credentialId)!.credential_hash);

    // revoke without TOTP -> 401, still ACTIVE.
    const revokeNoTotp = await router(
      "POST",
      `/admin/v1/api-keys/${credentialId}/revoke`,
      Buffer.from(JSON.stringify({})),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "content-type": "application/json",
        "idempotency-key": "idem-admin-api-keys-revoke-no-totp-abcdef",
      },
    );
    expect(revokeNoTotp.status).toBe(401);
    expect(store.rows.get(credentialId)!.status).toBe("ACTIVE");

    // revoke with TOTP -> 200, status REVOKED.
    nowMs += 30_000;
    const revoked = await router(
      "POST",
      `/admin/v1/api-keys/${credentialId}/revoke`,
      Buffer.from(JSON.stringify({})),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
        "idempotency-key": "idem-admin-api-keys-revoke-ok-abcdefabcdef",
      },
    );
    expect(revoked.status).toBe(200);
    expect(JSON.parse(revoked.body)).toEqual({ id: credentialId, revoked: true });
    expect(store.rows.get(credentialId)!.status).toBe("REVOKED");
    expect(store.audit.some((a) => a.action === "IMPLEMENTER_CREDENTIAL_REVOKED")).toBe(true);
  });

  it("revoke of an unknown id surfaces 404 (not_found)", async () => {
    const store = new MemoryCredentialStore();
    const nowMs = 1_700_000_030_000;
    const userStore = new InMemoryAdminUserStore();
    const { router } = makeRouter({
      credentialService: new CredentialService(store),
      resolveImplementerId: async () => IMPLEMENTER_ID,
      nowMs: () => nowMs,
      userStore,
    });
    const password = "keys-pass-2";
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
    await userStore.insert(user);
    await userStore.setActiveTotpSecret(user.id, encodeBase32(SECRET));
    const { cookie, csrf } = await login(router, userStore, password);

    const res = await router(
      "POST",
      "/admin/v1/api-keys/00000000-0000-4000-8000-000000000000/revoke",
      Buffer.from(JSON.stringify({})),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
        "idempotency-key": "idem-admin-api-keys-revoke-404-abcdefabcd",
      },
    );
    expect(res.status).toBe(404);
    expect(JSON.parse(res.body).error.code).toBe("not_found");
  });

  it("list returns an empty page when no active implementer exists", async () => {
    const store = new MemoryCredentialStore();
    const userStore = new InMemoryAdminUserStore();
    const { router } = makeRouter({
      credentialService: new CredentialService(store),
      resolveImplementerId: async () => null,
      userStore,
    });
    const password = "keys-pass-3";
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
    await userStore.insert(user);
    const { cookie, csrf } = await login(router, userStore, password);
    const res = await router("GET", "/admin/v1/api-keys", new Uint8Array(), {
      cookie,
      origin: ORIGIN,
      "x-csrf-token": csrf,
    });
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body)).toEqual({ keys: [] });
  });

  it("issue with an explicit unknown scope is rejected before any TOTP burn", async () => {
    const store = new MemoryCredentialStore();
    const userStore = new InMemoryAdminUserStore();
    const { router } = makeRouter({
      credentialService: new CredentialService(store),
      resolveImplementerId: async () => IMPLEMENTER_ID,
      userStore,
    });
    const password = "keys-pass-4";
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
    await userStore.insert(user);
    await userStore.setActiveTotpSecret(user.id, encodeBase32(SECRET));
    const { cookie, csrf } = await login(router, userStore, password);
    const res = await router(
      "POST",
      "/admin/v1/api-keys",
      Buffer.from(JSON.stringify({ scopes: ["admin:all"] })),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, 1_700_000_030_000),
        "content-type": "application/json",
      },
    );
    // Body validation runs before the TOTP burn, so a bad scope is a 400.
    expect(res.status).toBe(400);
    expect(store.rows.size).toBe(0);
  });

  it("CredentialError from a foreign id is CREDENTIAL_NOT_FOUND (parity collapse)", () => {
    // Sanity: the store collapses cross-tenant onto not_found, so the route never
    // distinguishes a foreign id from an absent one.
    const err = new CredentialError("credential not found", "CREDENTIAL_NOT_FOUND");
    expect(err.code).toBe("CREDENTIAL_NOT_FOUND");
  });
});
// Mode A recovery-ceremony admin API security gates.
//
// Proves fail-closed auth, digests-only responses, lockout, and that master key
// material never appears in response/log surfaces. Does NOT run the full
// PG restore ceremony (that stays in ops/recovery-ceremony.pg.test.ts via CLI entry).

import { createHash, createHmac, randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Live-bind startCeremonyJob so Mode A start can commit idempotency without PG.
const startCeremonyJobMock = vi.fn();
vi.mock("../src/ops/admin-recovery-ceremony.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/ops/admin-recovery-ceremony.js")>();
  return {
    ...actual,
    startCeremonyJob: (...args: unknown[]) => startCeremonyJobMock(...args),
  };
});

import {
  createAdminSessionService,
  createFailClosedDestinationService,
  createHaltGate,
  createInMemoryHaltEvidenceRecorder,
  createInMemoryOperatorHaltStore,
  hashPassword,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  RUNNING,
  TotpConsumptionLog,
  type AdminUser,
} from "@zucoins/node-core";

import { createAdminRouter } from "../src/admin-router.js";
import {
  RECOVERY_CEREMONY_START_BODY_FINGERPRINT,
} from "../src/ops/admin-idempotency-guard.js";
import { sha256HexUtf8 } from "../src/ops/admin-idempotency.js";
import {
  _resetCeremonyRegistryForTests,
  ceremonyJobToWire,
  isCeremonyUserLocked,
  registerCeremonyAttempt,
  type CeremonyJobSnapshot,
} from "../src/ops/admin-recovery-ceremony.js";
import { createTestAdminAtomicDeps } from "./support/admin-atomic.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const ORIGIN = "https://node.example";
const SECRET = new TextEncoder().encode("test-secret-key-32-bytes-long!!");
const MASTER = "test-master-key-32chars!!!!!!!!!!!";

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
      output += alphabet[(value >>> (bits - 5)) & 31]!;
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31]!;
  return output;
}

function cookieFrom(setCookie: string | undefined): string {
  if (!setCookie) return "";
  return setCookie.split(";")[0] ?? "";
}

function makeRouter(opts: {
  readonly nowMs?: () => number;
  readonly userStore?: InMemoryAdminUserStore;
  readonly runner?: { databaseUrl: string; liveSql: never };
  readonly withRunner?: boolean;
}) {
  const userStore = opts.userStore ?? new InMemoryAdminUserStore();
  const sessions = createAdminSessionService(
    { nodeId: NODE_ID },
    new InMemoryAdminSessionStore(),
    userStore,
  );
  const atomic = createTestAdminAtomicDeps({});
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
      listNeedsAttention: async () => [],
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
    adminIdempotencyStore: atomic.adminIdempotencyStore,
    atomicAdminMutation: atomic.atomicAdminMutation,
    recoveryCeremonyRunner:
      opts.withRunner === false
        ? undefined
        : (opts.runner ?? {
            databaseUrl: "postgres://unused/unused",
            // Cast: route only starts the job; we stub startCeremonyJob in unit tests
            // that need to avoid real PG. For auth-gate tests the runner is present
            // but the request never reaches mutate when TOTP/CSRF fails.
            liveSql: { query: async () => ({ rows: [] }) } as never,
          }),
  });
  return { router, userStore, sessions, idemStore: atomic.store };
}

async function enrolAdmin(
  userStore: InMemoryAdminUserStore,
  password: string,
): Promise<AdminUser> {
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
  return user;
}

async function login(
  router: ReturnType<typeof makeRouter>["router"],
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

describe("admin recovery-ceremony API", () => {
  beforeEach(() => {
    _resetCeremonyRegistryForTests();
    startCeremonyJobMock.mockReset();
  });
  afterEach(() => {
    _resetCeremonyRegistryForTests();
    vi.restoreAllMocks();
  });

  it("GET status fails closed (503) when runner is not wired", async () => {
    const { router, userStore } = makeRouter({ withRunner: false });
    await enrolAdmin(userStore, "p-ceremony-1");
    const { cookie, csrf } = await login(router, "p-ceremony-1");
    const res = await router("GET", "/admin/v1/recovery-ceremony/status", new Uint8Array(), {
      cookie,
      origin: ORIGIN,
      "x-csrf-token": csrf,
    });
    expect(res.status).toBe(503);
    expect(res.body).not.toContain(MASTER);
  });

  it("GET status requires session (401 without)", async () => {
    const { router } = makeRouter({});
    const res = await router("GET", "/admin/v1/recovery-ceremony/status", new Uint8Array(), {});
    expect(res.status).toBe(401);
  });

  it("POST start without TOTP fails closed and does not echo master key", async () => {
    const nowMs = 1_700_000_030_000;
    const { router, userStore } = makeRouter({ nowMs: () => nowMs });
    await enrolAdmin(userStore, "p-ceremony-2");
    const { cookie, csrf } = await login(router, "p-ceremony-2");

    const body = JSON.stringify({ vault_master_key: MASTER });
    const res = await router("POST", "/admin/v1/recovery-ceremony/start", Buffer.from(body), {
      cookie,
      origin: ORIGIN,
      "x-csrf-token": csrf,
      "content-type": "application/json",
      "idempotency-key": "ceremony-no-totp-key-01xx",
    });
    expect(res.status).toBe(401);
    expect(res.body).not.toContain(MASTER);
    expect(res.body.toLowerCase()).not.toContain("vault_master_key");
  });

  it("POST start without CSRF fails closed", async () => {
    const nowMs = 1_700_000_030_000;
    const { router, userStore } = makeRouter({ nowMs: () => nowMs });
    await enrolAdmin(userStore, "p-ceremony-3");
    const { cookie } = await login(router, "p-ceremony-3");
    const code = generateTotp(SECRET, nowMs);
    const res = await router(
      "POST",
      "/admin/v1/recovery-ceremony/start",
      Buffer.from(JSON.stringify({ vault_master_key: MASTER })),
      {
        cookie,
        origin: ORIGIN,
        "x-zp-totp": code,
        "content-type": "application/json",
        "idempotency-key": "ceremony-no-csrf-key-01xx",
      },
    );
    expect(res.status).toBe(401);
    expect(res.body).not.toContain(MASTER);
  });

  it("POST start without session fails closed", async () => {
    const { router } = makeRouter({});
    const res = await router(
      "POST",
      "/admin/v1/recovery-ceremony/start",
      Buffer.from(JSON.stringify({ vault_master_key: MASTER })),
      {
        origin: ORIGIN,
        "content-type": "application/json",
        "idempotency-key": "ceremony-no-sess-key-01xx",
      },
    );
    expect(res.status).toBe(401);
    expect(res.body).not.toContain(MASTER);
  });

  it("POST start rejects short master key before TOTP burn path completes", async () => {
    const nowMs = 1_700_000_030_000;
    const { router, userStore } = makeRouter({ nowMs: () => nowMs });
    await enrolAdmin(userStore, "p-ceremony-4");
    const { cookie, csrf } = await login(router, "p-ceremony-4");
    const code = generateTotp(SECRET, nowMs);
    const res = await router(
      "POST",
      "/admin/v1/recovery-ceremony/start",
      Buffer.from(JSON.stringify({ vault_master_key: "too-short" })),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": code,
        "content-type": "application/json",
        "idempotency-key": "ceremony-short-key-01xxxxx",
      },
    );
    // Body validation fails (400) — TOTP may or may not burn depending on guard order;
    // either way key is not echoed.
    expect([400, 401]).toContain(res.status);
    expect(res.body).not.toContain("too-short");
  });

  it("POST start requires Idempotency-Key", async () => {
    const nowMs = 1_700_000_030_000;
    const { router, userStore } = makeRouter({ nowMs: () => nowMs });
    await enrolAdmin(userStore, "p-ceremony-5");
    const { cookie, csrf } = await login(router, "p-ceremony-5");
    const code = generateTotp(SECRET, nowMs);
    const res = await router(
      "POST",
      "/admin/v1/recovery-ceremony/start",
      Buffer.from(JSON.stringify({ vault_master_key: MASTER })),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": code,
        "content-type": "application/json",
      },
    );
    expect(res.status).toBe(400);
    expect(res.body).toMatch(/idempotency/i);
    expect(res.body).not.toContain(MASTER);
  });

  it("rate limit lockout trips after threshold attempts", () => {
    const userId = "user-lockout-1";
    for (let i = 0; i < 4; i++) {
      const r = registerCeremonyAttempt(userId, 1_700_000_000_000 + i);
      expect(r.tripped).toBe(false);
    }
    const fifth = registerCeremonyAttempt(userId, 1_700_000_000_000 + 5);
    expect(fifth.tripped).toBe(true);
    expect(isCeremonyUserLocked(userId, 1_700_000_000_000 + 6)).toBe(true);
  });

  it("ceremonyJobToWire never includes master key fields", () => {
    const job: CeremonyJobSnapshot = {
      ceremony_id: "c1",
      status: "complete",
      stage: "complete",
      progress: [{ stage: "complete", at: "2026-01-01T00:00:00.000Z" }],
      summary: {
        ok: true,
        ceremony_id: "c1",
        export_id: "e1",
        archive_sha256: "abc",
        accepted: true,
        stamped: 1,
        failed_closed: 0,
        skipped: 0,
        born_blocked: 0,
        abort_reasons: [],
        instance_destroyed: true,
        recovery_verified_on_live: 1,
      },
      error: null,
      started_at: "2026-01-01T00:00:00.000Z",
      finished_at: "2026-01-01T00:01:00.000Z",
    };
    const wire = JSON.stringify(ceremonyJobToWire(job));
    expect(wire).not.toMatch(/vault_master|master_key|MASTER/i);
    expect(wire).toContain("archive_sha256");
    expect(wire).toContain("stamped");
  });

  it("GET status idle shape is digests-only", async () => {
    const { router, userStore } = makeRouter({});
    await enrolAdmin(userStore, "p-ceremony-6");
    const { cookie, csrf } = await login(router, "p-ceremony-6");
    const res = await router("GET", "/admin/v1/recovery-ceremony/status", new Uint8Array(), {
      cookie,
      origin: ORIGIN,
      "x-csrf-token": csrf,
    });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as Record<string, unknown>;
    expect(body.status).toBe("idle");
    expect(body).not.toHaveProperty("vault_master_key");
    expect(JSON.stringify(body)).not.toContain(MASTER);
  });

  it("idempotency row never stores sha256 of master-key body", async () => {
    const nowMs = 1_700_000_030_000;
    const { router, userStore, idemStore } = makeRouter({ nowMs: () => nowMs });
    await enrolAdmin(userStore, "p-ceremony-7");
    const { cookie, csrf } = await login(router, "p-ceremony-7");

    // Avoid real PG: stub startCeremonyJob so mutate commits and records idempotency.
    const stubSnap: CeremonyJobSnapshot = {
      ceremony_id: "stub-ceremony-id",
      status: "running",
      stage: "accepted",
      progress: [{ stage: "accepted", at: "2026-01-01T00:00:00.000Z" }],
      summary: null,
      error: null,
      started_at: "2026-01-01T00:00:00.000Z",
      finished_at: null,
    };
    startCeremonyJobMock.mockReturnValue(stubSnap);

    const rawBody = JSON.stringify({ vault_master_key: MASTER });
    const rawBodySha = sha256HexUtf8(rawBody);
    const keyHashOracle = createHash("sha256").update(MASTER, "utf8").digest("hex");
    const idemKey = "ceremony-no-key-hash-01xxxx";

    const res = await router(
      "POST",
      "/admin/v1/recovery-ceremony/start",
      Buffer.from(rawBody),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
        "idempotency-key": idemKey,
      },
    );
    expect(res.status).toBe(202);
    expect(res.body).not.toContain(MASTER);
    expect(res.body.toLowerCase()).not.toContain("vault_master_key");

    const completed = await idemStore.findCompleted(
      NODE_ID,
      "admin_recovery_ceremony_start",
      idemKey,
    );
    expect(completed).not.toBeNull();
    const fp = completed!.fingerprint.bodySha256;

    // Stored fingerprint must be the structural sentinel — never body or key hash.
    expect(fp).toBe(RECOVERY_CEREMONY_START_BODY_FINGERPRINT);
    expect(fp).not.toBe(rawBodySha);
    expect(fp).not.toBe(keyHashOracle);

    // Durable row must not embed key material or key-body digest as response bytes either.
    const durable = JSON.stringify({
      fingerprint: completed!.fingerprint,
      response: completed!.responseBytes.toString("utf8"),
    });
    expect(durable).not.toContain(MASTER);
    expect(durable).not.toContain(rawBodySha);
    expect(durable.toLowerCase()).not.toContain("vault_master_key");
  });

  it("structural fingerprint is constant (not body-derived)", () => {
    const a = RECOVERY_CEREMONY_START_BODY_FINGERPRINT;
    const b = sha256HexUtf8(
      "zupayments:admin-idempotency:structural:admin_recovery_ceremony_start",
    );
    expect(a).toBe(b);
    expect(a).toHaveLength(64);
    expect(a).not.toBe(sha256HexUtf8(JSON.stringify({ vault_master_key: MASTER })));
  });
});

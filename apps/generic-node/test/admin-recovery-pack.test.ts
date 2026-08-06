// Recovery pack create/prove admin API gates.

import { createHmac, randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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
  _resetCeremonyRegistryForTests,
  type CeremonyJobSnapshot,
} from "../src/ops/admin-recovery-ceremony.js";
import { createMemoryRecoveryPackLockoutStore } from "../src/ops/recovery-pack-lockout.js";
import { createRecoveryPack, RECOVERY_PACK_FORMAT } from "../src/ops/recovery-pack.js";
import { createTestAdminAtomicDeps } from "./support/admin-atomic.js";
import {
  createVirginVaultMasterState,
  generateShowOnce,
} from "../src/setup-vault-master.js";

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
  readonly vaultBootstrap?: ReturnType<typeof createVirginVaultMasterState>;
  readonly lockout?: ReturnType<typeof createMemoryRecoveryPackLockoutStore>;
  readonly audit?: (e: unknown) => void;
  readonly withRunner?: boolean;
}) {
  const userStore = new InMemoryAdminUserStore();
  const sessions = createAdminSessionService(
    { nodeId: NODE_ID },
    new InMemoryAdminSessionStore(),
    userStore,
  );
  const atomic = createTestAdminAtomicDeps({});
  const vaultMasterBootstrap = opts.vaultBootstrap ?? createVirginVaultMasterState();
  const auditEvents: unknown[] = [];
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
    vaultMasterBootstrap,
    recoveryPackLockoutStore: opts.lockout ?? createMemoryRecoveryPackLockoutStore(),
    recoveryPackAudit: (e) => {
      auditEvents.push(e);
      opts.audit?.(e);
    },
    recoveryCeremonyRunner:
      opts.withRunner === false
        ? undefined
        : {
            databaseUrl: "postgres://unused/unused",
            liveSql: { query: async () => ({ rows: [] }) } as never,
          },
  });
  return { router, userStore, sessions, vaultMasterBootstrap, auditEvents };
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

function authHeaders(
  cookie: string,
  csrf: string,
  nowMs: number,
  extra: Record<string, string> = {},
): Record<string, string> {
  return {
    cookie,
    origin: ORIGIN,
    "content-type": "application/json",
    "x-csrf-token": csrf,
    "x-zp-totp": generateTotp(SECRET, nowMs),
    "idempotency-key": `idem-${randomUUID().replace(/-/g, "").slice(0, 20)}`,
    ...extra,
  };
}

describe("admin recovery-pack create", () => {
  const nowMs = 1_700_000_030_000;

  beforeEach(() => {
    _resetCeremonyRegistryForTests();
    startCeremonyJobMock.mockReset();
  });

  afterEach(() => {
    _resetCeremonyRegistryForTests();
  });

  it("refuses without session", async () => {
    const { router } = makeRouter({});
    const res = await router(
      "POST",
      "/admin/v1/recovery-pack/create",
      Buffer.from(JSON.stringify({ passcode: "123456", vault_master_key: MASTER })),
      { "content-type": "application/json", origin: ORIGIN },
    );
    expect(res.status).toBe(401);
  });

  it("refuses without TOTP", async () => {
    const { router, userStore } = makeRouter({});
    await enrolAdmin(userStore, "pw-good-enough-12");
    const { cookie, csrf } = await login(router, "pw-good-enough-12");
    const res = await router(
      "POST",
      "/admin/v1/recovery-pack/create",
      Buffer.from(JSON.stringify({ passcode: "123456", vault_master_key: MASTER })),
      {
        cookie,
        origin: ORIGIN,
        "content-type": "application/json",
        "x-csrf-token": csrf,
        "idempotency-key": `idem-${randomUUID().replace(/-/g, "").slice(0, 20)}`,
      },
    );
    expect([401, 403]).toContain(res.status);
    expect(res.body).not.toContain(MASTER);
  });

  it("creates pack from body vault_master_key; audits digest only", async () => {
    const { router, userStore, auditEvents } = makeRouter({});
    await enrolAdmin(userStore, "pw-good-enough-12");
    const { cookie, csrf } = await login(router, "pw-good-enough-12");
    const res = await router(
      "POST",
      "/admin/v1/recovery-pack/create",
      Buffer.from(JSON.stringify({ passcode: "424242", vault_master_key: MASTER })),
      authHeaders(cookie, csrf, nowMs),
    );
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as {
      object: string;
      format: string;
      pack_content_sha256: string;
      pack_file_b64: string;
      content_type: string;
    };
    expect(body.object).toBe("recovery_pack_create");
    expect(body.format).toBe(RECOVERY_PACK_FORMAT);
    expect(body.content_type).toBe("application/octet-stream");
    expect(body.pack_content_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(res.body).not.toContain(MASTER);
    expect(res.body).not.toContain("424242");

    const fileUtf8 = Buffer.from(body.pack_file_b64, "base64").toString("utf8");
    expect(fileUtf8).not.toContain(MASTER);
    const env = JSON.parse(fileUtf8) as { format: string };
    expect(env.format).toBe(RECOVERY_PACK_FORMAT);

    expect(auditEvents).toHaveLength(1);
    const audit = auditEvents[0] as {
      kind: string;
      pack_content_sha256: string;
      operator_id: string;
    };
    expect(audit.kind).toBe("pack_create");
    expect(audit.pack_content_sha256).toBe(body.pack_content_sha256);
    expect(JSON.stringify(audit)).not.toContain(MASTER);
  });

  it("creates pack from pending show-once plaintext without body master", async () => {
    const bootstrap = createVirginVaultMasterState();
    generateShowOnce(bootstrap);
    expect(bootstrap.pendingPlaintext).not.toBeNull();
    const pending = bootstrap.pendingPlaintext!;

    const { router, userStore } = makeRouter({ vaultBootstrap: bootstrap });
    await enrolAdmin(userStore, "pw-good-enough-12");
    const { cookie, csrf } = await login(router, "pw-good-enough-12");
    const res = await router(
      "POST",
      "/admin/v1/recovery-pack/create",
      Buffer.from(JSON.stringify({ passcode: "999999" })),
      authHeaders(cookie, csrf, nowMs),
    );
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as { pack_file_b64: string };
    expect(res.body).not.toContain(pending);
    // Round-trip decrypt offline proves correct seal
    const { openRecoveryPack } = await import("../src/ops/recovery-pack.js");
    const opened = openRecoveryPack({
      fileBytes: Buffer.from(body.pack_file_b64, "base64"),
      passcode: "999999",
    });
    expect(opened.vault_master_key).toBe(pending);
  });

  it("rejects non-digit passcode", async () => {
    const { router, userStore } = makeRouter({});
    await enrolAdmin(userStore, "pw-good-enough-12");
    const { cookie, csrf } = await login(router, "pw-good-enough-12");
    const res = await router(
      "POST",
      "/admin/v1/recovery-pack/create",
      Buffer.from(JSON.stringify({ passcode: "abcd", vault_master_key: MASTER })),
      authHeaders(cookie, csrf, nowMs),
    );
    expect(res.status).toBe(400);
  });
});

describe("admin recovery-pack prove", () => {
  const nowMs = 1_700_000_030_000;

  beforeEach(() => {
    _resetCeremonyRegistryForTests();
    startCeremonyJobMock.mockReset();
    const job: CeremonyJobSnapshot = {
      ceremony_id: "cer-pack-1",
      status: "running",
      stage: "accepted",
      progress: [],
      summary: null,
      error: null,
      started_at: new Date(nowMs).toISOString(),
      finished_at: null,
    };
    startCeremonyJobMock.mockReturnValue(job);
  });

  afterEach(() => {
    _resetCeremonyRegistryForTests();
  });

  it("decrypts pack and starts ceremony with master (engine sole writer)", async () => {
    const { fileBytes } = createRecoveryPack({
      vaultMasterKey: MASTER,
      passcode: "135790",
    });
    const { router, userStore, auditEvents } = makeRouter({});
    await enrolAdmin(userStore, "pw-good-enough-12");
    const { cookie, csrf } = await login(router, "pw-good-enough-12");

    const res = await router(
      "POST",
      "/admin/v1/recovery-pack/prove",
      Buffer.from(
        JSON.stringify({
          passcode: "135790",
          pack_file: fileBytes.toString("utf8"),
        }),
      ),
      authHeaders(cookie, csrf, nowMs),
    );
    expect(res.status).toBe(202);
    const body = JSON.parse(res.body) as {
      object: string;
      ceremony_id: string;
      recovery_verification_id: string;
      verified_wallet_count: null;
    };
    expect(body.object).toBe("recovery_pack_prove");
    expect(body.ceremony_id).toBe("cer-pack-1");
    expect(body.recovery_verification_id).toBe("cer-pack-1");
    expect(body.verified_wallet_count).toBeNull();
    expect(res.body).not.toContain(MASTER);
    expect(res.body).not.toContain("135790");

    expect(startCeremonyJobMock).toHaveBeenCalledTimes(1);
    const arg = startCeremonyJobMock.mock.calls[0]![0] as {
      vaultMasterKey: string;
      verifierIdentity: string;
    };
    expect(arg.vaultMasterKey).toBe(MASTER);
    expect(arg.verifierIdentity).toContain("recovery-pack");

    const okAudit = auditEvents.find(
      (e) => (e as { kind: string }).kind === "pack_prove_ok",
    ) as { pack_content_sha256: string };
    expect(okAudit).toBeDefined();
    expect(JSON.stringify(okAudit)).not.toContain(MASTER);
  });

  it("wrong passcode does not start ceremony; generic error", async () => {
    const { fileBytes } = createRecoveryPack({
      vaultMasterKey: MASTER,
      passcode: "111111",
    });
    const { router, userStore } = makeRouter({});
    await enrolAdmin(userStore, "pw-good-enough-12");
    const { cookie, csrf } = await login(router, "pw-good-enough-12");

    const res = await router(
      "POST",
      "/admin/v1/recovery-pack/prove",
      Buffer.from(
        JSON.stringify({
          passcode: "000000",
          pack_file: fileBytes.toString("utf8"),
        }),
      ),
      authHeaders(cookie, csrf, nowMs),
    );
    expect(res.status).toBe(400);
    const err = JSON.parse(res.body) as { error: { code: string; message: string } };
    expect(err.error.code).toBe("prove_failed");
    expect(err.error.message).not.toContain(MASTER);
    expect(startCeremonyJobMock).not.toHaveBeenCalled();
  });

  it("locks after 5 failed proves", async () => {
    const lockout = createMemoryRecoveryPackLockoutStore();
    let clock = nowMs;
    const { router, userStore } = makeRouter({
      lockout,
      nowMs: () => clock,
    });
    await enrolAdmin(userStore, "pw-good-enough-12");
    const { cookie, csrf } = await login(router, "pw-good-enough-12");
    const { fileBytes } = createRecoveryPack({
      vaultMasterKey: MASTER,
      passcode: "222222",
    });

    for (let i = 0; i < 5; i++) {
      clock = nowMs + i * 1000;
      // Fresh TOTP window: advance enough that each code burns a distinct step
      // but stay in same lockout window. Use windowSteps=1 — bump clock by 30s each.
      clock = nowMs + i * 30_000;
      const res = await router(
        "POST",
        "/admin/v1/recovery-pack/prove",
        Buffer.from(
          JSON.stringify({
            passcode: "999999",
            pack_file: fileBytes.toString("utf8"),
          }),
        ),
        authHeaders(cookie, csrf, clock),
      );
      if (i < 4) {
        expect(res.status).toBe(400);
      } else {
        // 5th fail trips lock — may return 400 with rate_limited or 429
        expect([400, 429]).toContain(res.status);
      }
    }

    clock = nowMs + 5 * 30_000;
    const locked = await router(
      "POST",
      "/admin/v1/recovery-pack/prove",
      Buffer.from(
        JSON.stringify({
          passcode: "222222",
          pack_file: fileBytes.toString("utf8"),
        }),
      ),
      authHeaders(cookie, csrf, clock),
    );
    expect(locked.status).toBe(429);
    expect(startCeremonyJobMock).not.toHaveBeenCalled();
  });

  it("503 when ceremony runner not wired", async () => {
    const { router, userStore } = makeRouter({ withRunner: false });
    await enrolAdmin(userStore, "pw-good-enough-12");
    const { cookie, csrf } = await login(router, "pw-good-enough-12");
    const { fileBytes } = createRecoveryPack({
      vaultMasterKey: MASTER,
      passcode: "333333",
    });
    const res = await router(
      "POST",
      "/admin/v1/recovery-pack/prove",
      Buffer.from(
        JSON.stringify({
          passcode: "333333",
          pack_file: fileBytes.toString("utf8"),
        }),
      ),
      authHeaders(cookie, csrf, nowMs),
    );
    expect(res.status).toBe(503);
  });
});

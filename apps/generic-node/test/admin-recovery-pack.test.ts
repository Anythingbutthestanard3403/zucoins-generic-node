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
/** Generated-grade pack secrets — the create path refuses anything under the floor. */
const PACK_SECRET = "9F3KQ2XW7HB4TMZ0RCJ8PNVA5D";
const PACK_SECRET_ALT = "8HZ4PQ2WKX7NRB0MJ5TVDC93FA";

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
      Buffer.from(JSON.stringify({ recovery_secret: PACK_SECRET, vault_master_key: MASTER })),
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
      Buffer.from(JSON.stringify({ recovery_secret: PACK_SECRET, vault_master_key: MASTER })),
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
      Buffer.from(JSON.stringify({ recovery_secret: PACK_SECRET, vault_master_key: MASTER })),
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
    expect(res.body).not.toContain(PACK_SECRET);

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
      Buffer.from(JSON.stringify({ recovery_secret: PACK_SECRET })),
      authHeaders(cookie, csrf, nowMs),
    );
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as { pack_file_b64: string };
    expect(res.body).not.toContain(pending);
    // Round-trip decrypt offline proves correct seal
    const { openRecoveryPack } = await import("../src/ops/recovery-pack.js");
    const opened = openRecoveryPack({
      fileBytes: Buffer.from(body.pack_file_b64, "base64"),
      secret: PACK_SECRET,
    });
    expect(opened.vault_master_key).toBe(pending);
  });

  // The entropy floor is a creation-time gate. It owes nothing to
  // RECOVERY_PACK_PROVE_FAIL_THRESHOLD: no pack exists yet, so no lockout counter
  // is consulted and none is burned. Once the artifact is written the seal is
  // fixed, and an online limiter cannot help a file that has left the host.
  it("refuses a digit passcode at creation — no artifact is ever produced", async () => {
    const { router, userStore } = makeRouter({});
    await enrolAdmin(userStore, "pw-good-enough-12");
    const { cookie, csrf } = await login(router, "pw-good-enough-12");
    const res = await router(
      "POST",
      "/admin/v1/recovery-pack/create",
      Buffer.from(JSON.stringify({ recovery_secret: "482913", vault_master_key: MASTER })),
      authHeaders(cookie, csrf, nowMs),
    );
    expect(res.status).toBe(400);
    const err = JSON.parse(res.body) as { error: { code: string; message: string } };
    expect(err.error.code).toBe("weak_recovery_secret");
    // Non-oracular: names the rule that failed, never the master, the secret or a pack.
    expect(err.error.message).toMatch(/digits only/);
    expect(res.body).not.toContain(MASTER);
    expect(res.body).not.toContain("482913");
    expect(res.body).not.toContain("pack_file_b64");
  });

  it("refuses a non-shape / low-entropy secret at creation (ZTR-1220)", async () => {
    const { router, userStore } = makeRouter({});
    await enrolAdmin(userStore, "pw-good-enough-12");
    const { cookie, csrf } = await login(router, "pw-good-enough-12");
    // Free-form phrase previously cleared the charset×length proxy.
    const res = await router(
      "POST",
      "/admin/v1/recovery-pack/create",
      Buffer.from(JSON.stringify({ recovery_secret: "Tr0ub4dor&3", vault_master_key: MASTER })),
      authHeaders(cookie, csrf, nowMs),
    );
    expect(res.status).toBe(400);
    const err = JSON.parse(res.body) as { error: { code: string; message: string } };
    expect(err.error.code).toBe("weak_recovery_secret");
    expect(err.error.message).toMatch(/Crockford base32 alphabet|128 bits of entropy/);
    expect(res.body).not.toContain("pack_file_b64");

    // Ticket false-accept: repeated substring with ≥10 distinct under old proxy.
    const tiled = await router(
      "POST",
      "/admin/v1/recovery-pack/create",
      Buffer.from(
        JSON.stringify({
          recovery_secret: "abcdefghij".repeat(3),
          vault_master_key: MASTER,
        }),
      ),
      authHeaders(cookie, csrf, nowMs + 30_000),
    );
    expect(tiled.status).toBe(400);
    expect(JSON.parse(tiled.body).error.code).toBe("weak_recovery_secret");

    // Review B residual: Crockford×26 near-tile / dictionary / step-k still 400.
    const residuals = [
      "C0RRECTH0RSEBATTERYSTAP1E0",
      "1ETME1N1ETME1N1ETME1NABCD0",
      "AAABBBCCCDDDEEEFFFGGGHHHJK",
      "02468ACEGJMPRTWY02468ACEGJ",
      "PACKSECRETPACKSECRETPACK01",
      // Review B r2 residual: digit-broken dict / keyboard / alternation.
      "C0RRECTH0RSEBATTERY0STAP1E",
      "C0RRECTH0RSEBATT3RYSTAP1E0",
      "C001R2R3E4C5T6H708R9S0E1B2",
      "P1EASE1ETME1NT0THEN0DE2024",
      "QWERTYASD1FGHZXCVBN12345AB",
      "0A1B2C3D4E5F6G7H8J9KMNPRST",
      "A1B2C3D4E5F6G7H8J9K0M1N2P3",
      "MANC0DE7P1NGETP1NPASS4N0DE",
      // Review B r3 residual: columns / media / reverse-dict / broken-step.
      "1QAZ2WSX3EDC4RFV5TGB6YHN0P",
      "ZAQ1XSW2CDE3VFR4BGT5NHY6MJ",
      "THEQV1CKBR0WNFXJVMPS2024AX",
      "STR4NGERTH1NGS2024KEYABCXX",
      "HACKTHEP1ANET2024KEYM0RPHX",
      "TCERR0CESR0HYRETTABE1PATS2",
      "BP1CQ2DR3ES4FT5GV6HW7JX8KY",
      "AA1BB2CC3DD4EE5FF6GG7HH8JJ",
      // Review B r4 residual: off-list English/media/geo/π human-pattern class.
      "THECAKE1SA11EP0RTA12024XXA",
      "H0GWARTSEXPRESS2024KEYABXA",
      "GANGNAMSTY1E2024KEYABCDEXA",
      "HARRYP0TTERWAND2024KEYABXA",
      "STARWARSJED1K1GHT2024ABXAB",
      "GAME0FTHR0NES2024KEYABCXXA",
      "314159265358979323846ABCDA",
      "TAB1ECHA1RH0VSEWATER2024XA",
      "NEWY0RKC1TY2024KEYABCDEXAB",
      "SPH1NX0FB1ACKQVARTZ2024XXA",
    ];
    for (let i = 0; i < residuals.length; i++) {
      const resR = await router(
        "POST",
        "/admin/v1/recovery-pack/create",
        Buffer.from(
          JSON.stringify({
            recovery_secret: residuals[i],
            vault_master_key: MASTER,
          }),
        ),
        authHeaders(cookie, csrf, nowMs + 60_000 + i * 30_000),
      );
      expect(resR.status).toBe(400);
      expect(JSON.parse(resR.body).error.code).toBe("weak_recovery_secret");
      expect(resR.body).not.toContain("pack_file_b64");
    }
  });

  it("re-issues a pack from an existing one without the operator handling the master", async () => {
    const { fileBytes } = createRecoveryPack({ vaultMasterKey: MASTER, secret: PACK_SECRET });
    const { router, userStore, auditEvents } = makeRouter({});
    await enrolAdmin(userStore, "pw-good-enough-12");
    const { cookie, csrf } = await login(router, "pw-good-enough-12");
    const res = await router(
      "POST",
      "/admin/v1/recovery-pack/create",
      Buffer.from(
        JSON.stringify({
          recovery_secret: PACK_SECRET_ALT,
          from_pack: fileBytes.toString("utf8"),
          from_pack_secret: PACK_SECRET,
        }),
      ),
      authHeaders(cookie, csrf, nowMs),
    );
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as {
      pack_file_b64: string;
      pack_content_sha256: string;
      previous_pack_content_sha256: string | null;
    };
    const { openRecoveryPack, peekPackContentSha256 } = await import(
      "../src/ops/recovery-pack.js"
    );
    // The replacement carries the same master under the new secret only.
    expect(body.previous_pack_content_sha256).toBe(peekPackContentSha256(fileBytes));
    expect(body.pack_content_sha256).not.toBe(body.previous_pack_content_sha256);
    expect(
      openRecoveryPack({
        fileBytes: Buffer.from(body.pack_file_b64, "base64"),
        secret: PACK_SECRET_ALT,
      }).vault_master_key,
    ).toBe(MASTER);
    expect(res.body).not.toContain(MASTER);
    expect(res.body).not.toContain(PACK_SECRET_ALT);
    // Destruction trail: the audit names the artifact that must now be destroyed.
    expect(
      (auditEvents as { previous_pack_content_sha256?: string }[]).some(
        (e) => e.previous_pack_content_sha256 === body.previous_pack_content_sha256,
      ),
    ).toBe(true);
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
      secret: PACK_SECRET,
    });
    const { router, userStore, auditEvents } = makeRouter({});
    await enrolAdmin(userStore, "pw-good-enough-12");
    const { cookie, csrf } = await login(router, "pw-good-enough-12");

    const res = await router(
      "POST",
      "/admin/v1/recovery-pack/prove",
      Buffer.from(
        JSON.stringify({
          recovery_secret: PACK_SECRET,
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
    expect(res.body).not.toContain(PACK_SECRET);

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

  it("wrong pack secret does not start ceremony; generic error", async () => {
    const { fileBytes } = createRecoveryPack({
      vaultMasterKey: MASTER,
      secret: PACK_SECRET,
    });
    const { router, userStore } = makeRouter({});
    await enrolAdmin(userStore, "pw-good-enough-12");
    const { cookie, csrf } = await login(router, "pw-good-enough-12");

    const res = await router(
      "POST",
      "/admin/v1/recovery-pack/prove",
      Buffer.from(
        JSON.stringify({
          recovery_secret: PACK_SECRET_ALT,
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
      secret: PACK_SECRET,
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
            recovery_secret: PACK_SECRET_ALT,
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
          recovery_secret: PACK_SECRET,
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
      secret: PACK_SECRET,
    });
    const res = await router(
      "POST",
      "/admin/v1/recovery-pack/prove",
      Buffer.from(
        JSON.stringify({
          recovery_secret: PACK_SECRET,
          pack_file: fileBytes.toString("utf8"),
        }),
      ),
      authHeaders(cookie, csrf, nowMs),
    );
    expect(res.status).toBe(503);
  });
});

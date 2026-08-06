// GET/POST /admin/v1/reporting-keys. Session+CSRF+TOTP via runGuardedAdminMutation
// (parity with api-keys). POST node-mints the reporting credential and returns the raw
// private seed exactly once; the list response is public-only (never the seed); a POST that
// finds a credential already ACTIVE fails closed with 409 (superseding is the implementer-signed
// lifecycle rotation, not surfaced here). The route is a thin gate over the SQL service — the
// real persist-public-only + byte-equals-ceremony proof lives in reporting-credential-service.pg.test.ts.

import { createHmac, randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

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
import { ReportingCredentialAlreadyActiveError } from "../src/bootstrap/reporting-key-enrol.js";
import type {
  ReportingCredentialService,
  ReportingKeyListing,
} from "../src/reporting-credential-service.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const ORIGIN = "https://node.example";
const SECRET = new TextEncoder().encode("test-secret-key-32-bytes-long!!");
const IMPLEMENTER_ID = "22222222-2222-4222-8222-222222222222";
const SEED_HEX = "51".repeat(32);
const PUBLIC_KEY = "cHVibGljLXJlcG9ydGluZy1rZXktYjY0dXJs";

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

// In-memory reporting credential service: node-mints the first credential (raw once) and
// fails closed once ACTIVE. Persists public material only — the returned seed is never stored.
const RK1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const RK2 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

class FakeReportingService implements ReportingCredentialService {
  active = false;
  issued = 0;
  recovered = 0;
  currentId = RK1;
  async list(): Promise<readonly ReportingKeyListing[]> {
    if (!this.active) return [];
    return [
      {
        id: this.currentId,
        node_id: NODE_ID,
        implementer_id: IMPLEMENTER_ID,
        public_key: PUBLIC_KEY,
        registered_at: "2026-07-30T00:00:00.000Z",
        status: "ACTIVE",
      },
    ];
  }
  async issue(operatorSessionId: string) {
    if (this.active) throw new ReportingCredentialAlreadyActiveError(this.currentId);
    if (operatorSessionId.length === 0) throw new Error("missing operator session");
    this.active = true;
    this.issued += 1;
    return {
      id: RK1,
      key_id: RK1,
      public_key: PUBLIC_KEY,
      raw_private_key: SEED_HEX,
      registered_at: "2026-07-30T00:00:00.000Z",
    };
  }
  async recoverLost(operatorSessionId: string, lostKeyId: string) {
    if (operatorSessionId.length === 0) throw new Error("missing operator session");
    if (!this.active || lostKeyId !== this.currentId) {
      const err = new Error("not current") as Error & { code: string };
      err.code = "reporting_key_not_current";
      throw err;
    }
    this.recovered += 1;
    this.currentId = RK2;
    this.active = true;
    return {
      object: "reporting_key_recovered" as const,
      id: RK2,
      key_id: RK2,
      public_key: PUBLIC_KEY,
      raw_private_key: "52".repeat(32),
      registered_at: "2026-08-03T00:00:00.000Z",
      superseded_key_id: lostKeyId,
      implementer_id: "33333333-3333-4333-8333-333333333333",
      implementer_raw_key: "ik_recovered_test_key_xxxxxxxxxxxx",
      implementer_key_prefix: "ik_recove",
    };
  }
}

function makeRouter(opts: {
  readonly reportingCredentialService?: ReportingCredentialService;
  readonly nowMs?: () => number;
  readonly userStore?: InMemoryAdminUserStore;
}) {
  const userStore = opts.userStore ?? new InMemoryAdminUserStore();
  const sessions = createAdminSessionService(
    { nodeId: NODE_ID },
    new InMemoryAdminSessionStore(),
    userStore,
  );
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
    reportingCredentialService: opts.reportingCredentialService,
  });
  return { router, userStore };
}

async function makeOperator(userStore: InMemoryAdminUserStore, password: string, withTotp: boolean) {
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
  if (withTotp) await userStore.setActiveTotpSecret(user.id, encodeBase32(SECRET));
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

describe("admin /admin/v1/reporting-keys", () => {
  it("POST fails closed (503) when the reporting service is not wired", async () => {
    const { router } = makeRouter({});
    const res = await router(
      "POST",
      "/admin/v1/reporting-keys",
      Buffer.from(JSON.stringify({})),
      { origin: ORIGIN, "content-type": "application/json", "idempotency-key": "idem-admin-reporting-keys-unwired-0001" },
    );
    expect(res.status).toBe(503);
  });

  it("GET requires a session (401 without)", async () => {
    const { router } = makeRouter({ reportingCredentialService: new FakeReportingService() });
    const res = await router("GET", "/admin/v1/reporting-keys", new Uint8Array(), {});
    expect(res.status).toBe(401);
  });

  it("issue without TOTP is refused and mints nothing; with TOTP returns the raw seed once and the list never shows it", async () => {
    const service = new FakeReportingService();
    let nowMs = 1_700_000_030_000;
    const userStore = new InMemoryAdminUserStore();
    const { router } = makeRouter({ reportingCredentialService: service, nowMs: () => nowMs, userStore });
    await makeOperator(userStore, "reporting-pass-1", true);
    const { cookie, csrf } = await login(router, "reporting-pass-1");

    // POST without TOTP -> 401, nothing minted.
    const noTotp = await router(
      "POST",
      "/admin/v1/reporting-keys",
      Buffer.from(JSON.stringify({})),
      { cookie, origin: ORIGIN, "x-csrf-token": csrf, "content-type": "application/json", "idempotency-key": "idem-admin-reporting-keys-no-totp-000001" },
    );
    expect(noTotp.status).toBe(401);
    expect(service.issued).toBe(0);
    expect(service.active).toBe(false);

    // POST with TOTP -> 200, raw seed returned once.
    const issued = await router(
      "POST",
      "/admin/v1/reporting-keys",
      Buffer.from(JSON.stringify({})),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
        "idempotency-key": "idem-admin-reporting-keys-issue-0000001",
      },
    );
    expect(issued.status).toBe(200);
    const body = JSON.parse(issued.body) as {
      id: string;
      key_id: string;
      public_key: string;
      raw_private_key: string;
      registered_at: string;
    };
    expect(body.raw_private_key).toBe(SEED_HEX);
    expect(body.public_key).toBe(PUBLIC_KEY);
    expect(service.issued).toBe(1);

    // GET list shows the credential public-only — never the raw seed.
    const list = await router("GET", "/admin/v1/reporting-keys", new Uint8Array(), {
      cookie,
      origin: ORIGIN,
      "x-csrf-token": csrf,
    });
    expect(list.status).toBe(200);
    const listed = JSON.parse(list.body) as { keys: { id: string; public_key: string; status: string }[] };
    expect(listed.keys).toHaveLength(1);
    expect(listed.keys[0]!.public_key).toBe(PUBLIC_KEY);
    expect(listed.keys[0]!.status).toBe("ACTIVE");
    expect(list.body).not.toContain(SEED_HEX);

    // A second issue finds the credential already ACTIVE -> 409 (superseding is the lifecycle ceremony).
    nowMs += 30_000;
    const again = await router(
      "POST",
      "/admin/v1/reporting-keys",
      Buffer.from(JSON.stringify({})),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
        "idempotency-key": "idem-admin-reporting-keys-issue-0000002",
      },
    );
    expect(again.status).toBe(409);
    expect(JSON.parse(again.body).error.code).toBe("reporting_key_already_active");
    expect(service.issued).toBe(1);
  });

  it("issue with a non-empty body is rejected before any TOTP burn", async () => {
    const service = new FakeReportingService();
    const userStore = new InMemoryAdminUserStore();
    const { router } = makeRouter({ reportingCredentialService: service, userStore });
    await makeOperator(userStore, "reporting-pass-2", true);
    const { cookie, csrf } = await login(router, "reporting-pass-2");
    const res = await router(
      "POST",
      "/admin/v1/reporting-keys",
      Buffer.from(JSON.stringify({ rogue: true })),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, 1_700_000_030_000),
        "content-type": "application/json",
        "idempotency-key": "idem-admin-reporting-keys-badbody-00001",
      },
    );
    expect(res.status).toBe(400);
    expect(service.issued).toBe(0);
  });

  it("recover-lost mints replacement secrets with TOTP (lost-seed UX)", async () => {
    const service = new FakeReportingService();
    service.active = true;
    let nowMs = 1_700_000_100_000;
    const userStore = new InMemoryAdminUserStore();
    const { router } = makeRouter({
      reportingCredentialService: service,
      userStore,
      nowMs: () => nowMs,
    });
    await makeOperator(userStore, "reporting-pass-3", true);
    const { cookie, csrf } = await login(router, "reporting-pass-3");
    const res = await router(
      "POST",
      "/admin/v1/reporting-keys/recover-lost",
      Buffer.from(JSON.stringify({ lost_key_id: RK1 })),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
        "idempotency-key": "idem-recover-lost-00000001",
      },
    );
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as {
      object: string;
      raw_private_key: string;
      implementer_raw_key: string;
      superseded_key_id: string;
    };
    expect(body.object).toBe("reporting_key_recovered");
    expect(body.superseded_key_id).toBe(RK1);
    expect(body.raw_private_key).toMatch(/^[0-9a-f]{64}$/);
    expect(body.implementer_raw_key.startsWith("ik_")).toBe(true);
    expect(service.recovered).toBe(1);

    nowMs += 30_000;
    const wrong = await router(
      "POST",
      "/admin/v1/reporting-keys/recover-lost",
      Buffer.from(JSON.stringify({ lost_key_id: "00000000-0000-4000-8000-000000000000" })),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "x-zp-totp": generateTotp(SECRET, nowMs),
        "content-type": "application/json",
        "idempotency-key": "idem-recover-lost-00000002",
      },
    );
    // Current head is now RK2 — wrong uuid → 409
    expect(wrong.status).toBe(409);
  });
});

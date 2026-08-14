// PATCH /admin/v1/wallets/:id/money-capability — TOTP + CAS + audit (ZTR-1269).

import { createHmac, randomUUID } from "node:crypto";

import { describe, expect, it } from "vitest";

import { flagsFromMode } from "@zucoins/generic-node-contracts/wallet-state";
import {
  createAdminSessionService,
  createFailClosedDestinationService,
  createHaltGate,
  createInMemoryHaltEvidenceRecorder,
  createInMemoryOperatorHaltStore,
  hashPassword,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  InMemoryWalletMoneyCapabilityStore,
  RUNNING,
  TotpConsumptionLog,
  type AdminUser,
} from "@zucoins/node-core";

import { createAdminRouter } from "../src/admin-router.js";
import { createTestAdminAtomicDeps } from "./support/admin-atomic.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const ORIGIN = "https://node.example";
const WALLET_A = "22222222-2222-4222-8222-222222222222";
const WALLET_B = "33333333-3333-4333-8333-333333333333";
const TOTP_SECRET = new TextEncoder().encode("test-secret-key-32-bytes-long!!");

function cookieFrom(setCookie: string | undefined): string {
  return setCookie?.split(";")[0] ?? "";
}

function totpNow(nowMs: number = Date.now()): string {
  const step = Math.floor(nowMs / 1000 / 30);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const hmac = createHmac("sha1", TOTP_SECRET).update(msg).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const code =
    ((hmac[offset]! & 0x7f) << 24) |
    ((hmac[offset + 1]! & 0xff) << 16) |
    ((hmac[offset + 2]! & 0xff) << 8) |
    (hmac[offset + 3]! & 0xff);
  return String(code % 1_000_000).padStart(6, "0");
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
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31]!;
  }
  return output;
}

function makeRouter(capabilityStore: InMemoryWalletMoneyCapabilityStore) {
  const userStore = new InMemoryAdminUserStore();
  const sessions = createAdminSessionService(
    { nodeId: NODE_ID },
    new InMemoryAdminSessionStore(),
    userStore,
  );

  const router = createAdminRouter({
    sessions,
    userStore,
    csrf: { allowedOrigins: [ORIGIN] },
    totp: {
      secret: TOTP_SECRET,
      windowSteps: 1,
    },
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
    ...createTestAdminAtomicDeps({
      walletMoneyCapabilityStore: capabilityStore,
    }),
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
    halt: {
      gate: createHaltGate(RUNNING),
      store: createInMemoryOperatorHaltStore(RUNNING),
      evidence: createInMemoryHaltEvidenceRecorder(),
    },
  });

  return { router, userStore, capabilityStore };
}

async function login(
  router: ReturnType<typeof makeRouter>["router"],
  userStore: InMemoryAdminUserStore,
) {
  const password = "correct-horse-battery-staple";
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
  await userStore.setActiveTotpSecret(user.id, encodeBase32(TOTP_SECRET));
  const response = await router(
    "POST",
    "/admin/v1/login",
    Buffer.from(JSON.stringify({ username: user.username, password })),
    { "content-type": "application/json" },
  );
  expect(response.status).toBe(200);
  return {
    cookie: cookieFrom(response.headers["set-cookie"]),
    csrf: (JSON.parse(response.body) as { csrfToken: string }).csrfToken,
    userId: user.id,
  };
}

function seedFull(store: InMemoryWalletMoneyCapabilityStore, walletId: string, rowVersion = 1) {
  store.seed({
    wallet_id: walletId,
    node_id: NODE_ID,
    money_mode: "FULL",
    ...flagsFromMode("FULL"),
    row_version: rowVersion,
  });
}

describe("PATCH /admin/v1/wallets/:id/money-capability (ZTR-1269)", () => {
  it("TOTP-gated PATCH sets mode via flagsFromMode and audits before→after", async () => {
    const capabilityStore = new InMemoryWalletMoneyCapabilityStore();
    seedFull(capabilityStore, WALLET_A);
    const { router, userStore } = makeRouter(capabilityStore);
    const auth = await login(router, userStore);

    const res = await router(
      "PATCH",
      `/admin/v1/wallets/${WALLET_A}/money-capability`,
      Buffer.from(JSON.stringify({ mode: "SEND_ONLY", expected_row_version: 1 })),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "content-type": "application/json",
        "x-csrf-token": auth.csrf,
        "x-zp-totp": totpNow(),
        "idempotency-key": `idem-money-cap-${randomUUID()}`,
      },
    );
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as {
      money_mode: string;
      allow_external_receive: boolean;
      allow_external_send: boolean;
      allow_internal_move: boolean;
      row_version: number;
      previous_mode: string;
      previous_flags: { allow_external_send: boolean };
    };
    expect(body.money_mode).toBe("SEND_ONLY");
    expect(body).toMatchObject(flagsFromMode("SEND_ONLY"));
    expect(body.row_version).toBe(2);
    expect(body.previous_mode).toBe("FULL");
    expect(body.previous_flags.allow_external_send).toBe(true);
    expect(capabilityStore.auditEntries).toHaveLength(1);
    expect(capabilityStore.auditEntries[0]!.details).toContain("previous_mode=FULL");
    expect(capabilityStore.auditEntries[0]!.details).toContain("next_mode=SEND_ONLY");
  });

  it("row_version CAS prevents lost updates (409 conflict)", async () => {
    const capabilityStore = new InMemoryWalletMoneyCapabilityStore();
    seedFull(capabilityStore, WALLET_A, 4);
    const { router, userStore } = makeRouter(capabilityStore);
    const auth = await login(router, userStore);

    const res = await router(
      "PATCH",
      `/admin/v1/wallets/${WALLET_A}/money-capability`,
      Buffer.from(JSON.stringify({ mode: "INTERNAL_ONLY", expected_row_version: 1 })),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "content-type": "application/json",
        "x-csrf-token": auth.csrf,
        "x-zp-totp": totpNow(),
        "idempotency-key": `idem-money-cas-${randomUUID()}`,
      },
    );
    expect(res.status).toBe(409);
    expect(capabilityStore.auditEntries).toHaveLength(0);
    expect(capabilityStore.rows.get(WALLET_A)!.money_mode).toBe("FULL");
  });

  it("rejects missing TOTP", async () => {
    const capabilityStore = new InMemoryWalletMoneyCapabilityStore();
    seedFull(capabilityStore, WALLET_A);
    const { router, userStore } = makeRouter(capabilityStore);
    const auth = await login(router, userStore);

    const res = await router(
      "PATCH",
      `/admin/v1/wallets/${WALLET_A}/money-capability`,
      Buffer.from(JSON.stringify({ mode: "FULL", expected_row_version: 1 })),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "content-type": "application/json",
        "x-csrf-token": auth.csrf,
        "idempotency-key": `idem-money-nototp-${randomUUID()}`,
      },
    );
    expect(res.status).toBe(401);
    expect(capabilityStore.auditEntries).toHaveLength(0);
  });

  it("allows multiple INTERNAL_ONLY wallets and surfaces fleet warnings", async () => {
    const capabilityStore = new InMemoryWalletMoneyCapabilityStore();
    seedFull(capabilityStore, WALLET_A);
    seedFull(capabilityStore, WALLET_B);
    const { router, userStore } = makeRouter(capabilityStore);
    const auth = await login(router, userStore);

    const first = await router(
      "PATCH",
      `/admin/v1/wallets/${WALLET_A}/money-capability`,
      Buffer.from(JSON.stringify({ mode: "INTERNAL_ONLY", expected_row_version: 1 })),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "content-type": "application/json",
        "x-csrf-token": auth.csrf,
        "x-zp-totp": totpNow(),
        "idempotency-key": `idem-money-hub-a-${randomUUID()}`,
      },
    );
    expect(first.status).toBe(200);
    const firstBody = JSON.parse(first.body) as {
      warnings: { zero_send_capable: boolean; zero_receive_capable: boolean };
    };
    expect(firstBody.warnings.zero_send_capable).toBe(false);

    // Burned timestep: advance clock by one step for second TOTP.
    const later = Date.now() + 31_000;
    const second = await router(
      "PATCH",
      `/admin/v1/wallets/${WALLET_B}/money-capability`,
      Buffer.from(JSON.stringify({ mode: "INTERNAL_ONLY", expected_row_version: 1 })),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "content-type": "application/json",
        "x-csrf-token": auth.csrf,
        "x-zp-totp": totpNow(later),
        "idempotency-key": `idem-money-hub-b-${randomUUID()}`,
      },
    );
    expect(second.status).toBe(200);
    const secondBody = JSON.parse(second.body) as {
      money_mode: string;
      warnings: { zero_send_capable: boolean; zero_receive_capable: boolean };
    };
    expect(secondBody.money_mode).toBe("INTERNAL_ONLY");
    expect(secondBody.warnings.zero_send_capable).toBe(true);
    expect(secondBody.warnings.zero_receive_capable).toBe(true);
    expect(capabilityStore.rows.get(WALLET_A)!.money_mode).toBe("INTERNAL_ONLY");
    expect(capabilityStore.rows.get(WALLET_B)!.money_mode).toBe("INTERNAL_ONLY");
  });

  it("validates mode and expected_row_version", async () => {
    const capabilityStore = new InMemoryWalletMoneyCapabilityStore();
    seedFull(capabilityStore, WALLET_A);
    const { router, userStore } = makeRouter(capabilityStore);
    const auth = await login(router, userStore);

    const badMode = await router(
      "PATCH",
      `/admin/v1/wallets/${WALLET_A}/money-capability`,
      Buffer.from(JSON.stringify({ mode: "NOT_A_MODE", expected_row_version: 1 })),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "content-type": "application/json",
        "x-csrf-token": auth.csrf,
        "x-zp-totp": totpNow(),
        "idempotency-key": `idem-money-badmode-${randomUUID()}`,
      },
    );
    expect(badMode.status).toBe(400);

    const badRv = await router(
      "PATCH",
      `/admin/v1/wallets/${WALLET_A}/money-capability`,
      Buffer.from(JSON.stringify({ mode: "FULL" })),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "content-type": "application/json",
        "x-csrf-token": auth.csrf,
        "x-zp-totp": totpNow(Date.now() + 31_000),
        "idempotency-key": `idem-money-badrv-${randomUUID()}`,
      },
    );
    expect(badRv.status).toBe(400);
  });

  it("requires Idempotency-Key (16–255 visible ASCII)", async () => {
    const capabilityStore = new InMemoryWalletMoneyCapabilityStore();
    seedFull(capabilityStore, WALLET_A);
    const { router, userStore } = makeRouter(capabilityStore);
    const auth = await login(router, userStore);

    const res = await router(
      "PATCH",
      `/admin/v1/wallets/${WALLET_A}/money-capability`,
      Buffer.from(JSON.stringify({ mode: "FULL", expected_row_version: 1 })),
      {
        cookie: auth.cookie,
        origin: ORIGIN,
        "content-type": "application/json",
        "x-csrf-token": auth.csrf,
        "x-zp-totp": totpNow(),
      },
    );
    expect(res.status).toBe(400);
    expect(JSON.parse(res.body)).toMatchObject({
      error: { code: "invalid_idempotency_key" },
    });
  });
});

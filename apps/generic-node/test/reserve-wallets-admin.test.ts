// POST /admin/v1/reserve-wallets. Session+CSRF+TOTP. The route is a thin gate:
// omitted dep fails closed, a cap error is a 409, and a successful mint returns
// the named INTERNAL_ONLY wallet. The real row proof is the pg suite.

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
  ReservePoolCapError,
  RUNNING,
  TotpConsumptionLog,
  type AdminUser,
} from "@zucoins/node-core";

import { createAdminRouter } from "../src/admin-router.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const ORIGIN = "https://node.example";
const SECRET = new TextEncoder().encode("test-secret-key-32-bytes-long!!");

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
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function cookieFrom(setCookie: string | undefined): string {
  if (!setCookie) return "";
  return setCookie.split(";")[0] ?? "";
}

function makeRouter(mint?: (input: { readonly displayLabel: string }) => Promise<{
  readonly walletId: string;
  readonly moneyMode: "INTERNAL_ONLY";
  readonly displayLabel: string;
  readonly destinationState: "BLESSED";
}>) {
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
    nowMs: () => 1_700_000_030_000,
    halt: {
      gate: createHaltGate(RUNNING),
      store: createInMemoryOperatorHaltStore(RUNNING),
      evidence: createInMemoryHaltEvidenceRecorder(),
    },
    mintNamedReserveWallet: mint,
  });
  return { router, userStore };
}

async function makeOperator(userStore: InMemoryAdminUserStore, password: string) {
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
}

async function login(router: ReturnType<typeof makeRouter>["router"], password: string) {
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

describe("admin /admin/v1/reserve-wallets", () => {
  it("fails closed when the mint is not wired", async () => {
    const { router } = makeRouter();
    const res = await router(
      "POST",
      "/admin/v1/reserve-wallets",
      Buffer.from(JSON.stringify({ label: "Client Holding A" })),
      { origin: ORIGIN, "content-type": "application/json" },
    );
    expect(res.status).toBe(503);
  });

  it("refuses a session without TOTP and returns the minted wallet with TOTP", async () => {
    const seen: string[] = [];
    const { router, userStore } = makeRouter(async (input) => {
      seen.push(input.displayLabel);
      return {
        walletId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        moneyMode: "INTERNAL_ONLY",
        displayLabel: input.displayLabel,
        destinationState: "BLESSED",
      };
    });
    await makeOperator(userStore, "reserve-pass-1");
    const { cookie, csrf } = await login(router, "reserve-pass-1");
    const body = Buffer.from(JSON.stringify({ label: "Client Holding A" }));
    const headers = {
      cookie,
      origin: ORIGIN,
      "x-csrf-token": csrf,
      "content-type": "application/json",
      "idempotency-key": "idem-reserve-wallets-no-totp-0001",
    };
    const noTotp = await router("POST", "/admin/v1/reserve-wallets", body, headers);
    expect(noTotp.status).toBe(401);
    expect(seen).toEqual([]);

    const minted = await router("POST", "/admin/v1/reserve-wallets", body, {
      ...headers,
      "idempotency-key": "idem-reserve-wallets-with-totp-001",
      "x-zp-totp": generateTotp(SECRET, 1_700_000_030_000),
    });
    expect(minted.status).toBe(201);
    expect(JSON.parse(minted.body)).toEqual({
      wallet_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      money_mode: "INTERNAL_ONLY",
      display_label: "Client Holding A",
      destination_state: "BLESSED",
    });
    expect(seen).toEqual(["Client Holding A"]);
  });

  it("maps a cap error to 409", async () => {
    const { router, userStore } = makeRouter(async () => {
      throw new ReservePoolCapError();
    });
    await makeOperator(userStore, "reserve-pass-2");
    const { cookie, csrf } = await login(router, "reserve-pass-2");
    const res = await router(
      "POST",
      "/admin/v1/reserve-wallets",
      Buffer.from(JSON.stringify({ label: "Client Holding A" })),
      {
        cookie,
        origin: ORIGIN,
        "x-csrf-token": csrf,
        "content-type": "application/json",
        "idempotency-key": "idem-reserve-wallets-cap-0000001",
        "x-zp-totp": generateTotp(SECRET, 1_700_000_030_000),
      },
    );
    expect(res.status).toBe(409);
  });
});

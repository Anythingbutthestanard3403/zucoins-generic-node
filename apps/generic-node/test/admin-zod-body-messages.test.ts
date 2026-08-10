// ZTR-1200: approve / reject / recovery-actions must never put Zod's serialized
// issue array (expected/received/path dumps) into 400 bodies.

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
import { createTestAdminAtomicDeps } from "./support/admin-atomic.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const ORIGIN = "https://node.example";
const SECRET = new TextEncoder().encode("test-secret-key-32-bytes-long!!");
const FIXED_NOW_MS = 1_700_000_030_000;
const OP_ID = "22222222-2222-4222-8222-222222222222";

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

/** Zod-dump fingerprints that must never appear in a client-facing 400 body. */
function assertNoZodDump(raw: string): void {
  expect(raw).not.toMatch(/"expected"\s*:/);
  expect(raw).not.toMatch(/"received"\s*:/);
  expect(raw).not.toContain("invalid_type");
  expect(raw).not.toContain("invalid_enum_value");
  expect(raw).not.toContain("Required");
  expect(raw).not.toContain("challenge_nonce");
  expect(raw).not.toContain("expected_row_version");
  expect(raw).not.toContain("recovery_nonce");
}

async function makeAuthedRouter() {
  const userStore = new InMemoryAdminUserStore();
  const password = "zod-body-pass-12";
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
    nowMs: () => FIXED_NOW_MS,
    halt: {
      gate: createHaltGate(RUNNING),
      store: createInMemoryOperatorHaltStore(RUNNING),
      evidence: createInMemoryHaltEvidenceRecorder(),
    },
    adminIdempotencyStore: atomic.adminIdempotencyStore,
    atomicAdminMutation: atomic.atomicAdminMutation,
  });

  const login = await router(
    "POST",
    "/admin/v1/login",
    Buffer.from(JSON.stringify({ username: "admin", password })),
    { "content-type": "application/json" },
  );
  expect(login.status).toBe(200);
  const cookie = cookieFrom(login.headers["set-cookie"]);
  const csrf = (JSON.parse(login.body) as { csrfToken: string }).csrfToken;
  return {
    router,
    headers: {
      cookie,
      origin: ORIGIN,
      "x-csrf-token": csrf,
      "content-type": "application/json",
      "x-zp-totp": generateTotp(SECRET, FIXED_NOW_MS),
    },
  };
}

describe("admin Zod body parse — non-oracular 400 messages (ZTR-1200)", () => {
  const cases = [
    {
      name: "approve",
      path: `/admin/v1/external-sends/${OP_ID}/approve`,
      body: {},
      needsIdem: true,
    },
    {
      name: "reject",
      path: `/admin/v1/external-sends/${OP_ID}/reject`,
      body: { expected_row_version: "not-an-int", reason: 12 },
      needsIdem: true,
    },
    {
      name: "recovery-actions",
      path: `/admin/v1/operations/${OP_ID}/recovery-actions`,
      body: { action: "NOT_A_REAL_ACTION" },
      needsIdem: true,
    },
  ] as const;

  for (const c of cases) {
    it(`${c.name}: 400 invalid_scalar with stable message, no Zod dump`, async () => {
      const { router, headers } = await makeAuthedRouter();
      const res = await router(
        "POST",
        c.path,
        Buffer.from(JSON.stringify(c.body)),
        {
          ...headers,
          ...(c.needsIdem
            ? { "idempotency-key": `idem-zod-${c.name}-${randomUUID().slice(0, 8)}` }
            : {}),
        },
      );
      expect(res.status).toBe(400);
      const parsed = JSON.parse(res.body) as {
        error: { code: string; message: string };
      };
      expect(parsed.error.code).toBe("invalid_scalar");
      expect(parsed.error.message).toBe("request body failed validation");
      assertNoZodDump(res.body);
    });
  }
});

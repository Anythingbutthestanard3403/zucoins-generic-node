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
  type OperationRecord,
  type OperationRouteStore,
} from "@zucoins/node-core";

import {
  createEmptyAdminInventoryStore,
  type AdminInventoryStore,
  type AdminWalletDetail,
} from "../src/admin-inventory/index.js";
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
  return user;
}

async function loginOperator(router: ReturnType<typeof createAdminRouter>, password: string) {
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

describe("GN-404 reserve-first wallets & direct operator actions", () => {
  it("lists reserve wallets and worker pool summary separately, and supports direct operator receive, send, and move", async () => {
    let now = 1_700_000_030_000;
    const userStore = new InMemoryAdminUserStore();
    const sessions = createAdminSessionService(
      { nodeId: NODE_ID },
      new InMemoryAdminSessionStore(),
      userStore,
    );

    const wallets: AdminWalletDetail[] = [
      {
        wallet_id: "w-reserve-main",
        address: "0xReserveMain",
        state: "AVAILABLE",
        key_origin: "node_generated",
        money_mode: "INTERNAL_ONLY",
        display_label: "Main Reserve",
        spendable_balance_zkz: "500.00",
        pending_balance_zkz: "0",
        assigned_operation_id: null,
        recovery_verified: true,
        recovery_verified_at: "2026-01-01T00:00:00.000Z",
        created_at: "2026-01-01T00:00:00.000Z",
      },
      {
        wallet_id: "w-reserve-savings",
        address: "0xReserveSavings",
        state: "AVAILABLE",
        key_origin: "node_generated",
        money_mode: "INTERNAL_ONLY",
        display_label: "Savings Vault",
        spendable_balance_zkz: "200.00",
        pending_balance_zkz: "0",
        assigned_operation_id: null,
        recovery_verified: true,
        recovery_verified_at: "2026-01-01T00:00:00.000Z",
        created_at: "2026-01-01T00:00:00.000Z",
      },
      {
        wallet_id: "w-recv-1",
        address: "0xRecvWorker1",
        state: "AVAILABLE",
        key_origin: "node_generated",
        money_mode: "RECEIVE_ONLY",
        display_label: null,
        spendable_balance_zkz: "0",
        pending_balance_zkz: "0",
        assigned_operation_id: null,
        recovery_verified: true,
        recovery_verified_at: "2026-01-01T00:00:00.000Z",
        created_at: "2026-01-01T00:00:00.000Z",
      },
      {
        wallet_id: "w-send-1",
        address: "0xSendWorker1",
        state: "AVAILABLE",
        key_origin: "node_generated",
        money_mode: "SEND_ONLY",
        display_label: null,
        spendable_balance_zkz: "0",
        pending_balance_zkz: "0",
        assigned_operation_id: null,
        recovery_verified: true,
        recovery_verified_at: "2026-01-01T00:00:00.000Z",
        created_at: "2026-01-01T00:00:00.000Z",
      },
    ];

    const inventoryStore: AdminInventoryStore = {
      ...createEmptyAdminInventoryStore(),
      listWallets: async () => ({
        data: wallets,
        has_more: false,
        next_cursor: null,
      }),
      getWallet: async (_nodeId, walletId) => wallets.find((w) => w.wallet_id === walletId) ?? null,
    };

    const records = new Map<string, OperationRecord>();
    const opStore: OperationRouteStore = {
      getById: async ({ operationId }) => records.get(operationId) ?? null,
      createReceive: async (input) => {
        const record: OperationRecord = {
          object: "operation",
          operation_id: "op-recv-test-1",
          node_id: input.nodeId,
          implementer_id: input.implementerId,
          kind: "RECEIVE_EXTERNAL",
          status: "CREATED",
          recipient_wallet_address: "0xRecvWorker1",
          expected_amount_zkz: input.expectedAmountZkz,
          amount_zkz: null,
          observed_amount_zkz: null,
          transfer_code: "TC-TEST-001",
          expires_at: input.expiresAt,
          destination_wallet_id: null,
          target_reserve_wallet_id: input.targetReserveWalletId ?? "w-reserve-main",
          source_reserve_wallet_id: null,
          attention_required: false,
          attention_reason: null,
          terminal_reason: null,
          created_at: new Date(now).toISOString(),
          updated_at: new Date(now).toISOString(),
        };
        records.set(record.operation_id, record);
        return { ok: true, replayed: false, record };
      },
      armReceive: async ({ operationId }) => {
        const existing = records.get(operationId)!;
        const armed: OperationRecord = { ...existing, status: "ARMED" };
        records.set(operationId, armed);
        return { ok: true, record: armed };
      },
      createInternalTransfer: async (input) => {
        const record: OperationRecord = {
          object: "operation",
          operation_id: "op-move-test-1",
          node_id: input.nodeId,
          implementer_id: input.implementerId,
          kind: "MOVE_INTERNAL",
          status: "CREATED",
          recipient_wallet_address: input.recipientAddress,
          expected_amount_zkz: null,
          amount_zkz: input.amountZkz,
          observed_amount_zkz: null,
          transfer_code: null,
          expires_at: null,
          destination_wallet_id: input.destinationWalletId,
          target_reserve_wallet_id: null,
          source_reserve_wallet_id: null,
          attention_required: false,
          attention_reason: null,
          terminal_reason: null,
          created_at: new Date(now).toISOString(),
          updated_at: new Date(now).toISOString(),
        };
        records.set(record.operation_id, record);
        return { ok: true, replayed: false, record };
      },
      createExternalSend: async (input) => {
        const record: OperationRecord = {
          object: "operation",
          operation_id: "op-send-test-1",
          node_id: input.nodeId,
          implementer_id: input.implementerId,
          kind: "SEND_EXTERNAL",
          status: "CREATED",
          recipient_wallet_address: input.recipientAddress,
          expected_amount_zkz: null,
          amount_zkz: input.amountZkz,
          observed_amount_zkz: null,
          transfer_code: null,
          expires_at: null,
          destination_wallet_id: null,
          target_reserve_wallet_id: null,
          source_reserve_wallet_id: input.sourceReserveWalletId ?? "w-reserve-main",
          attention_required: false,
          attention_reason: null,
          terminal_reason: null,
          created_at: new Date(now).toISOString(),
          updated_at: new Date(now).toISOString(),
        };
        records.set(record.operation_id, record);
        return { ok: true, replayed: false, record };
      },
      evaluateSendAutoApproval: async () => ({ autoApproved: false }),
    };

    const approvedOpIds: string[] = [];

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
        approveCreated: async ({ operationId }) => {
          approvedOpIds.push(operationId);
          return {
            ok: true,
            operationId,
            status: "APPROVED",
            approvedAt: new Date(now).toISOString(),
            approvedByUserId: "admin",
            approvalEventId: randomUUID(),
            replayed: false,
          };
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
      inventoryStore,
      operatorOperationStore: opStore,
      mintNamedReserveWallet: async ({ displayLabel }) => ({
        walletId: "w-reserve-new",
        moneyMode: "INTERNAL_ONLY",
        displayLabel,
        destinationState: "BLESSED",
      }),
      newRequestId: () => randomUUID(),
      nowMs: () => now,
      halt: {
        gate: createHaltGate(RUNNING),
        store: createInMemoryOperatorHaltStore(RUNNING),
        evidence: createInMemoryHaltEvidenceRecorder(),
      },
    });

    await makeOperator(userStore, "correct-horse-battery-staple");
    const { cookie, csrf } = await loginOperator(router, "correct-horse-battery-staple");

    // 1. GET /admin/v1/wallets/reserves returns only INTERNAL_ONLY reserve wallets
    const reservesRes = await router(
      "GET",
      "/admin/v1/wallets/reserves",
      Buffer.alloc(0),
      { cookie },
    );
    expect(reservesRes.status).toBe(200);
    const reservesBody = JSON.parse(reservesRes.body);
    expect(reservesBody.data).toHaveLength(2);
    expect(reservesBody.data.map((w: { wallet_id: string }) => w.wallet_id)).toEqual([
      "w-reserve-main",
      "w-reserve-savings",
    ]);

    // 2. GET /admin/v1/wallets/worker-pool returns only RECEIVE_ONLY / SEND_ONLY worker summary
    const poolRes = await router(
      "GET",
      "/admin/v1/wallets/worker-pool",
      Buffer.alloc(0),
      { cookie },
    );
    expect(poolRes.status).toBe(200);
    const poolBody = JSON.parse(poolRes.body);
    expect(poolBody.receive_workers).toEqual({ total: 1, available: 1, assigned: 0 });
    expect(poolBody.send_workers).toEqual({ total: 1, available: 1, assigned: 0 });

    // 3. POST /admin/v1/wallets/reserves accepts display_name or label
    const mintRes = await router(
      "POST",
      "/admin/v1/wallets/reserves",
      Buffer.from(JSON.stringify({ display_name: "Payroll Reserve" })),
      {
        origin: ORIGIN,
        cookie,
        "x-csrf-token": csrf,
        "idempotency-key": "idem-reserve-mint-0001",
        "content-type": "application/json",
        "x-zp-totp": generateTotp(SECRET, now),
      },
    );
    expect(mintRes.status).toBe(201);
    expect(JSON.parse(mintRes.body).display_label).toBe("Payroll Reserve");

    // Advance TOTP window step
    now += 30_000;

    // 4. POST /admin/v1/operations/receives creates and arms a receive
    const recvRes = await router(
      "POST",
      "/admin/v1/operations/receives",
      Buffer.from(
        JSON.stringify({
          expected_amount_zkz: "25.50",
          target_reserve_wallet_id: "w-reserve-savings",
        }),
      ),
      {
        origin: ORIGIN,
        cookie,
        "x-csrf-token": csrf,
        "idempotency-key": "idem-operator-recv-0001",
        "content-type": "application/json",
        "x-zp-totp": generateTotp(SECRET, now),
      },
    );
    expect(recvRes.status).toBe(201);
    const recvBody = JSON.parse(recvRes.body);
    expect(recvBody.status).toBe("ARMED");
    expect(recvBody.expected_amount_zkz).toBe("25.50");
    expect(recvBody.recipient_wallet_address).toBe("0xRecvWorker1");
    expect(recvBody.pay_url).toBe(`/pay/${recvBody.operation_id}`);

    // Advance TOTP window step
    now += 30_000;

    // 5. POST /admin/v1/operations/sends creates and immediately approves an external send
    const sendRes = await router(
      "POST",
      "/admin/v1/operations/sends",
      Buffer.from(
        JSON.stringify({
          source_reserve_wallet_id: "w-reserve-main",
          recipient_wallet_address: "0xExternalRecipient999",
          amount_zkz: "15.00",
        }),
      ),
      {
        origin: ORIGIN,
        cookie,
        "x-csrf-token": csrf,
        "idempotency-key": "idem-operator-send-0001",
        "content-type": "application/json",
        "x-zp-totp": generateTotp(SECRET, now),
      },
    );
    expect(sendRes.status).toBe(201);
    const sendBody = JSON.parse(sendRes.body);
    expect(sendBody.status).toBe("APPROVED");
    expect(approvedOpIds).toContain(sendBody.operation_id);

    // Advance TOTP window step
    now += 30_000;

    // 6. POST /admin/v1/operations/moves creates an internal transfer between two Reserve Wallets
    const moveRes = await router(
      "POST",
      "/admin/v1/operations/moves",
      Buffer.from(
        JSON.stringify({
          source_reserve_wallet_id: "w-reserve-main",
          destination_reserve_wallet_id: "w-reserve-savings",
          amount_zkz: "40.00",
        }),
      ),
      {
        origin: ORIGIN,
        cookie,
        "x-csrf-token": csrf,
        "idempotency-key": "idem-operator-move-0001",
        "content-type": "application/json",
        "x-zp-totp": generateTotp(SECRET, now),
      },
    );
    expect(moveRes.status).toBe(201);
    const moveBody = JSON.parse(moveRes.body);
    expect(moveBody.destination_reserve_wallet_id).toBe("w-reserve-savings");
    expect(moveBody.recipient_wallet_address).toBe("0xReserveSavings");
    expect(moveBody.amount_zkz).toBe("40.00");
  });
});

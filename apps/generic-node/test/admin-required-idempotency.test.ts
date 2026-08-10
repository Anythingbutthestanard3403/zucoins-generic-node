import { randomUUID } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  createAdminSessionService,
  createFailClosedDestinationService,
  createHaltGate,
  createInMemoryHaltEvidenceRecorder,
  createInMemoryOperatorHaltStore,
  InMemoryAdminSessionStore,
  InMemoryAdminUserStore,
  RUNNING,
} from "@zucoins/node-core";

import {
  createAdminRouter,
  createFailClosedAdminRouteDeps,
} from "../src/admin-router.js";
import { sha256HexUtf8 } from "../src/ops/admin-idempotency.js";
import {
  createTestAdminAtomicDeps,
  MemoryAdminIdempotencyStore,
} from "./support/admin-atomic.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";

/**
 * The frozen REQUIRED-idempotency admin surface: family, request target, and the route id the
 * completed row is keyed under. Every row routes through the same
 * idempotencyGate -> runRequiredAdminMutation pair, so the gate outcomes below are asserted as
 * one shared table rather than per route (ZTR-1197: recovery-actions was the one REQUIRED
 * route with its own `length > 0` check, no completed-row lookup, and no replay header).
 */
const REQUIRED_ROUTES = [
  ["approve", `/admin/v1/external-sends/${randomUUID()}/approve`, "admin_external_send_approve"],
  ["reject", `/admin/v1/external-sends/${randomUUID()}/reject`, "admin_external_send_reject"],
  ["bless", `/admin/v1/destinations/${randomUUID()}/bless`, "admin_destination_bless"],
  ["retire", `/admin/v1/destinations/${randomUUID()}/retire`, "admin_destination_retire"],
  [
    "recovery-actions",
    `/admin/v1/operations/${randomUUID()}/recovery-actions`,
    "admin_operation_recovery_actions",
  ],
] as const;

const BODY = "{}";

function baseDeps() {
  const users = new InMemoryAdminUserStore();
  const sessions = createAdminSessionService(
    { nodeId: NODE_ID },
    new InMemoryAdminSessionStore(),
    users,
  );
  return {
    sessions,
    userStore: users,
    csrf: { allowedOrigins: ["https://node.example"] },
    totp: { secret: new Uint8Array(32), windowSteps: 1 },
    nodeId: NODE_ID,
    destinationService: createFailClosedDestinationService(),
    newRequestId: () => randomUUID(),
    halt: {
      gate: createHaltGate(RUNNING),
      store: createInMemoryOperatorHaltStore(RUNNING),
      evidence: createInMemoryHaltEvidenceRecorder(),
    },
  };
}

function post(
  deps: Parameters<typeof createAdminRouter>[0],
  path: string,
  idemKey: string,
  body = BODY,
) {
  return createAdminRouter(deps)("POST", path, Buffer.from(body), {
    "content-type": "application/json",
    "idempotency-key": idemKey,
  });
}

describe("frozen REQUIRED admin routes fail closed without the atomic executor", () => {
  for (const [family, path] of REQUIRED_ROUTES) {
    it(`${family} cannot reach authentication/TOTP or its child effect without atomic wiring`, async () => {
      const deps = createFailClosedAdminRouteDeps({
        ...baseDeps(),
        adminIdempotencyStore: new MemoryAdminIdempotencyStore(),
        // Deliberately omit atomicAdminMutation: production must return 503, never continue.
      });
      const response = await post(deps, path, `atomic-admin-mutation-${family}-required-atomic`);
      expect(response.status).toBe(503);
      expect(JSON.parse(response.body)).toMatchObject({
        error: { code: "idempotency_unavailable" },
      });
    });
  }
});

describe("frozen REQUIRED admin routes share one Idempotency-Key gate", () => {
  function wired() {
    const atomic = createTestAdminAtomicDeps();
    return { store: atomic.store, deps: createFailClosedAdminRouteDeps({ ...baseDeps(), ...atomic }) };
  }

  for (const [family, path, routeId] of REQUIRED_ROUTES) {
    // The key grammar is the DB CHECK on operations.idempotency_key (^[!-~]{16,255}$)
    // enforced at the HTTP boundary: a malformed key is a 400 from validation, never a
    // constraint violation surfaced from a write.
    it.each([
      ["too short", "x"],
      ["empty", ""],
      ["space-bearing", `not visible ascii only ${family}`],
    ])(
      `${family} rejects a %s Idempotency-Key with 400 before any store write`,
      async (_label, idemKey) => {
        const { deps, store } = wired();
        const response = await post(deps, path, idemKey);
        expect(response.status).toBe(400);
        expect(JSON.parse(response.body)).toMatchObject({
          error: { code: "invalid_idempotency_key" },
        });
        expect(store.rows.size).toBe(0);
      },
    );

    it(`${family} replays the completed row with idempotency-replayed: true`, async () => {
      const { deps, store } = wired();
      const idemKey = `zupayments-shared-gate-replay-${family}`;
      const responseBytes = Buffer.from(`{"replayed_family":"${family}"}`, "utf8");
      await store.recordCompleted({
        nodeId: NODE_ID,
        routeId,
        idempotencyKey: idemKey,
        fingerprint: { method: "POST", rawTarget: path, bodySha256: sha256HexUtf8(BODY) },
        responseStatus: 200,
        responseBytes,
      });
      const response = await post(deps, path, idemKey);
      expect(response.status).toBe(200);
      expect(response.body).toBe(responseBytes.toString("utf8"));
      expect(response.headers["idempotency-replayed"]).toBe("true");
    });

    it(`${family} answers 409 when the key is reused with a different body`, async () => {
      const { deps, store } = wired();
      const idemKey = `zupayments-shared-gate-conflict-${family}`;
      await store.recordCompleted({
        nodeId: NODE_ID,
        routeId,
        idempotencyKey: idemKey,
        fingerprint: {
          method: "POST",
          rawTarget: path,
          bodySha256: sha256HexUtf8('{"different":"body"}'),
        },
        responseStatus: 200,
        responseBytes: Buffer.from(BODY, "utf8"),
      });
      const response = await post(deps, path, idemKey);
      expect(response.status).toBe(409);
      expect(JSON.parse(response.body)).toMatchObject({
        error: { code: "idempotency_conflict" },
      });
    });
  }
});

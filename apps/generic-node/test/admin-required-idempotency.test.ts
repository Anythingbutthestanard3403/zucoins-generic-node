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
import { MemoryAdminIdempotencyStore } from "./support/admin-atomic.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";

describe("frozen REQUIRED admin routes fail closed without the atomic executor", () => {
  const cases = [
    ["approve", `/admin/v1/external-sends/${randomUUID()}/approve`],
    ["reject", `/admin/v1/external-sends/${randomUUID()}/reject`],
    ["bless", `/admin/v1/destinations/${randomUUID()}/bless`],
    ["retire", `/admin/v1/destinations/${randomUUID()}/retire`],
  ] as const;

  for (const [family, path] of cases) {
    it(`${family} cannot reach authentication/TOTP or its child effect without atomic wiring`, async () => {
      const users = new InMemoryAdminUserStore();
      const sessions = createAdminSessionService(
        { nodeId: NODE_ID },
        new InMemoryAdminSessionStore(),
        users,
      );
      const deps = createFailClosedAdminRouteDeps({
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
        adminIdempotencyStore: new MemoryAdminIdempotencyStore(),
        // Deliberately omit atomicAdminMutation: production must return 503, never continue.
      });
      const response = await createAdminRouter(deps)(
        "POST",
        path,
        Buffer.from("{}"),
        {
          "content-type": "application/json",
          "idempotency-key": `atomic-admin-mutation-${family}-required-atomic`,
        },
      );
      expect(response.status).toBe(503);
      expect(JSON.parse(response.body)).toMatchObject({
        error: { code: "idempotency_unavailable" },
      });
    });
  }
});
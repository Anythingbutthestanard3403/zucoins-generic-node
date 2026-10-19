import { createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";

import { describe, expect, it } from "vitest";

import { webhookEventPreimage } from "@zucoins/generic-node-contracts/implementer-events";

import {
  InMemoryWebhookDeliveryStore,
  delayAfterFailedAttempt,
  type WebhookDeliveryPorts,
  type WebhookPostRequest,
} from "./webhook-dispatcher.js";

const NODE = "11111111-1111-4111-8111-111111111111";
const IMPL = "22222222-2222-4222-8222-222222222222";
const OP = "33333333-3333-4333-8333-333333333333";
const TARGET = "https://hooks.example/promo";

function signerFrom(privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"]) {
  return {
    sign(preimage: Uint8Array): string {
      return sign(null, Buffer.from(preimage), privateKey).toString("base64url");
    },
  };
}

describe("webhook dispatcher", () => {
  it("posts a signed receive.settled body that the consumer verifier accepts", async () => {
    const keys = generateKeyPairSync("ed25519");
    const store = new InMemoryWebhookDeliveryStore();
    const received: WebhookPostRequest[] = [];
    const saved = await store.enqueue(
      {
        nodeId: NODE,
        implementerId: IMPL,
        eventType: "receive.settled",
        operationId: OP,
        externalRef: null,
        occurredAt: "2026-10-19T09:00:00.000Z",
        data: { amount: "15" },
        sourceKind: "DURABLE_EVENT",
        sourceId: OP,
      },
      signerFrom(keys.privateKey),
    );
    expect(saved).not.toBeNull();
    const ports = portsWith(keys, received, () => ({ status: 200 }));
    expect(await store.deliverDue(NODE, ports)).toBe(1);
    expect(received).toHaveLength(1);
    expect(received[0]?.url).toBe(TARGET);
    expect(received[0]?.headers["x-generic-node-signature"]).toBe(saved?.signature_text);
    const body = received[0]!.body;
    const signature = Buffer.from(received[0]!.headers["x-generic-node-signature"]!, "base64url");
    const pem = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(
      verify(null, Buffer.from(webhookEventPreimage(body)), createPublicKey(pem), signature),
    ).toBe(true);
    const parsed = JSON.parse(body) as { event_type: string; operation_id: string };
    expect(parsed.event_type).toBe("receive.settled");
    expect(parsed.operation_id).toBe(OP);
    expect(store.rows.get(saved!.delivery_id)?.status).toBe("DELIVERED");
  });

  it("backs off twice and marks the third success delivered", async () => {
    const keys = generateKeyPairSync("ed25519");
    const store = new InMemoryWebhookDeliveryStore();
    const saved = await store.enqueue(
      {
        nodeId: NODE,
        implementerId: IMPL,
        eventType: "connector.rule.approved",
        operationId: null,
        externalRef: null,
        occurredAt: "2026-10-19T09:00:00.000Z",
        data: { request_id: "44444444-4444-4444-8444-444444444444" },
        sourceKind: "RULE_REQUEST",
        sourceId: "44444444-4444-4444-8444-444444444444",
      },
      signerFrom(keys.privateKey),
    );
    const codes = [503, 503, 200];
    let clock = Date.parse("2026-10-19T09:00:00.000Z");
    const ports: WebhookDeliveryPorts = {
      now: () => new Date(clock),
      signer: () => signerFrom(keys.privateKey),
      targetFor: async () => ({ url: TARGET }),
      validateTarget: async () => undefined,
      post: async () => ({ status: codes.shift() ?? 500 }),
    };
    await store.deliverDue(NODE, ports);
    let row = store.rows.get(saved!.delivery_id)!;
    expect(row.attempt_count).toBe(1);
    expect(row.status).toBe("PENDING");
    expect(Date.parse(row.next_attempt_at) - clock).toBe(delayAfterFailedAttempt(1));
    clock = Date.parse(row.next_attempt_at);
    await store.deliverDue(NODE, ports);
    row = store.rows.get(saved!.delivery_id)!;
    expect(row.attempt_count).toBe(2);
    clock = Date.parse(row.next_attempt_at);
    await store.deliverDue(NODE, ports);
    row = store.rows.get(saved!.delivery_id)!;
    expect(row.attempt_count).toBe(3);
    expect(row.status).toBe("DELIVERED");
  });
});

function portsWith(
  keys: ReturnType<typeof generateKeyPairSync>,
  received: WebhookPostRequest[],
  respond: () => { status: number },
): WebhookDeliveryPorts {
  return {
    now: () => new Date("2026-10-19T09:00:00.000Z"),
    signer: () => signerFrom(keys.privateKey),
    targetFor: async () => ({ url: TARGET }),
    validateTarget: async () => undefined,
    post: async (request) => {
      received.push(request);
      return respond();
    },
  };
}

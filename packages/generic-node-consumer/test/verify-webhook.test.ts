import { generateKeyPairSync, sign } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  canonicalWebhookEventJson,
  webhookEventPreimage,
  type WebhookEventPayloadV1,
} from "@zucoins/generic-node-contracts/implementer-events";

import { SignatureVerificationError, verifyWebhookEvent } from "../src/signing/verify-webhook.js";

const payload: WebhookEventPayloadV1 = {
  v: 1,
  delivery_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  node_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  implementer_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
  event_type: "receive.settled",
  occurred_at: "2026-10-19T09:00:00.000Z",
  operation_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
  external_ref: null,
  data: { amount: "15" },
};

function pair() {
  return generateKeyPairSync("ed25519");
}

describe("verifyWebhookEvent", () => {
  it("accepts a body signed by the matching key", () => {
    const keys = pair();
    const body = canonicalWebhookEventJson(payload);
    const signature = sign(null, Buffer.from(webhookEventPreimage(body)), keys.privateKey).toString("base64url");
    const pem = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(verifyWebhookEvent(body, signature, pem).event_type).toBe("receive.settled");
  });

  it("rejects a body changed by one byte and a different public key", () => {
    const keys = pair();
    const other = pair();
    const body = canonicalWebhookEventJson(payload);
    const signature = sign(null, Buffer.from(webhookEventPreimage(body)), keys.privateKey).toString("base64url");
    const pem = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
    const otherPem = other.publicKey.export({ type: "spki", format: "pem" }).toString();
    const tampered = body.replace("15", "16");
    expect(() => verifyWebhookEvent(tampered, signature, pem)).toThrow(SignatureVerificationError);
    expect(() => verifyWebhookEvent(body, signature, otherPem)).toThrow(SignatureVerificationError);
  });
});

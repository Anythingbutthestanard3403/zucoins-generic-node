/**
 * Verify a node-signed hook body (ZTR-1333).
 *
 * The signature covers `zp-webhook-event-v1` plus a newline plus the exact body
 * bytes. A changed byte or a different public key fails closed.
 */

import { createPublicKey, verify } from "node:crypto";

import {
  WEBHOOK_EVENT_TYPES,
  canonicalWebhookEventJson,
  isWebhookEventType,
  webhookEventPreimage,
  type WebhookEventPayloadV1,
} from "@zucoins/generic-node-contracts/implementer-events";

export class SignatureVerificationError extends Error {
  readonly code = "signature_verification_failed" as const;

  constructor(message: string) {
    super(message);
    this.name = "SignatureVerificationError";
  }
}

export function verifyWebhookEvent(
  rawBody: string | Uint8Array,
  signatureBase64Url: string,
  nodePublicKeyPem: string,
): WebhookEventPayloadV1 {
  const bodyText = typeof rawBody === "string" ? rawBody : new TextDecoder().decode(rawBody);
  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    throw new SignatureVerificationError("body is not json");
  }
  const payload = asPayload(parsed);
  if (canonicalWebhookEventJson(payload) !== bodyText) {
    throw new SignatureVerificationError("body is not the canonical payload");
  }
  let signature: Buffer;
  try {
    signature = Buffer.from(signatureBase64Url, "base64url");
  } catch {
    throw new SignatureVerificationError("signature is not base64url");
  }
  let ok = false;
  try {
    ok = verify(null, Buffer.from(webhookEventPreimage(bodyText)), createPublicKey(nodePublicKeyPem), signature);
  } catch {
    ok = false;
  }
  if (!ok) throw new SignatureVerificationError("signature does not match the node public key");
  return payload;
}

function asPayload(value: unknown): WebhookEventPayloadV1 {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new SignatureVerificationError("body is not a payload object");
  }
  const row = value as Record<string, unknown>;
  if (row.v !== 1) throw new SignatureVerificationError("payload version is not 1");
  if (typeof row.delivery_id !== "string" || typeof row.node_id !== "string") {
    throw new SignatureVerificationError("payload ids are not strings");
  }
  if (typeof row.implementer_id !== "string" || typeof row.occurred_at !== "string") {
    throw new SignatureVerificationError("payload identity fields are not strings");
  }
  if (typeof row.event_type !== "string" || !isWebhookEventType(row.event_type)) {
    throw new SignatureVerificationError("payload event type is not in the closed set");
  }
  if (!nullableString(row.operation_id) || !nullableString(row.external_ref)) {
    throw new SignatureVerificationError("payload nullable fields are not strings or null");
  }
  if (row.data === null || typeof row.data !== "object" || Array.isArray(row.data)) {
    throw new SignatureVerificationError("payload data is not an object");
  }
  return {
    v: 1,
    delivery_id: row.delivery_id,
    node_id: row.node_id,
    implementer_id: row.implementer_id,
    event_type: row.event_type,
    occurred_at: row.occurred_at,
    operation_id: row.operation_id as string | null,
    external_ref: row.external_ref as string | null,
    data: row.data as Record<string, unknown>,
  };
}

function nullableString(value: unknown): boolean {
  return value === null || typeof value === "string";
}

export const WEBHOOK_EVENT_TYPE_COUNT = WEBHOOK_EVENT_TYPES.length;

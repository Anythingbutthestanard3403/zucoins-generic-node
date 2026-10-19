/**
 * Signed hook-event payload (ZTR-1333).
 *
 * The domain line plus the canonical JSON is what the node identity key signs.
 * Nested `data` keys are sorted. The top-level fields stay in one fixed sequence.
 */

export const WEBHOOK_EVENT_DOMAIN = "zp-webhook-event-v1" as const;

export const WEBHOOK_EVENT_TYPES = [
  "receive.ready",
  "receive.observed",
  "receive.settled",
  "receive.expired",
  "receive.failed",
  "send.created",
  "send.approved",
  "send.settled",
  "send.cancelled",
  "send.failed",
  "connector.rule.approved",
  "connector.rule.rejected",
] as const;

export type WebhookEventType = (typeof WEBHOOK_EVENT_TYPES)[number];

export interface WebhookEventPayloadV1 {
  readonly v: 1;
  readonly delivery_id: string;
  readonly node_id: string;
  readonly implementer_id: string;
  readonly event_type: WebhookEventType;
  readonly occurred_at: string;
  readonly operation_id: string | null;
  readonly external_ref: string | null;
  readonly data: Record<string, unknown>;
}

/** Durable public event name to the hook vocabulary. Unmapped names stay on the pull stream. */
export const DURABLE_EVENT_TO_WEBHOOK: Readonly<Record<string, WebhookEventType>> = {
  "receive.ready": "receive.ready",
  "receive.landed": "receive.settled",
  "operation.expired": "receive.expired",
  "external_send.created": "send.created",
  "external_send.landed": "send.settled",
};

const EVENT_TYPE_SET: ReadonlySet<string> = new Set(WEBHOOK_EVENT_TYPES);

export function isWebhookEventType(value: string): value is WebhookEventType {
  return EVENT_TYPE_SET.has(value);
}

export function canonicalWebhookEventJson(payload: WebhookEventPayloadV1): string {
  return (
    "{" +
    [
      `"v":${canonicalValue(payload.v)}`,
      `"delivery_id":${canonicalValue(payload.delivery_id)}`,
      `"node_id":${canonicalValue(payload.node_id)}`,
      `"implementer_id":${canonicalValue(payload.implementer_id)}`,
      `"event_type":${canonicalValue(payload.event_type)}`,
      `"occurred_at":${canonicalValue(payload.occurred_at)}`,
      `"operation_id":${canonicalValue(payload.operation_id)}`,
      `"external_ref":${canonicalValue(payload.external_ref)}`,
      `"data":${canonicalValue(payload.data)}`,
    ].join(",") +
    "}"
  );
}

export function webhookEventPreimage(canonicalJson: string): Uint8Array {
  return new TextEncoder().encode(`${WEBHOOK_EVENT_DOMAIN}\n${canonicalJson}`);
}

function canonicalValue(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("hook payload number is not finite");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonicalValue(item)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalValue(record[key])}`).join(",")}}`;
  }
  throw new Error("hook payload value is not serializable");
}

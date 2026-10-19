/**
 * Signed hook delivery (ZTR-1333).
 *
 * The ledger transition stays on its own transaction. This module signs a
 * payload with an injected node-identity signer and posts it later.
 * node-core never holds a private key.
 */

import { randomUUID } from "node:crypto";

import {
  DURABLE_EVENT_TO_WEBHOOK,
  canonicalWebhookEventJson,
  isWebhookEventType,
  webhookEventPreimage,
  type WebhookEventPayloadV1,
  type WebhookEventType,
} from "@zucoins/generic-node-contracts/implementer-events";

import { assertUrlSafe } from "../net/ssrf-guard.js";

export const WEBHOOK_DELIVERY_INTERVAL_MS = 2_000;
export const WEBHOOK_DELIVERY_TIMEOUT_MS = 5_000;
/** Delay after failed attempt 1, 2, 3, and 4. Attempt 5 is permanent. */
export const WEBHOOK_DELIVERY_BACKOFF_MS = [5_000, 30_000, 120_000, 600_000] as const;

export type WebhookDeliveryStatus = "PENDING" | "DELIVERED" | "FAILED_PERMANENT";
export type WebhookSourceKind = "DURABLE_EVENT" | "RULE_REQUEST";

export interface WebhookSigner {
  sign(preimageBytes: Uint8Array): Promise<string> | string;
}

export interface WebhookDeliveryRecord {
  readonly delivery_id: string;
  readonly node_id: string;
  readonly implementer_id: string;
  readonly event_type: WebhookEventType;
  readonly operation_id: string | null;
  readonly payload_text: string;
  readonly signature_text: string;
  readonly status: WebhookDeliveryStatus;
  readonly attempt_count: number;
  readonly next_attempt_at: string;
  readonly last_status_code: number | null;
  readonly last_error: string | null;
  readonly created_at: string;
  readonly delivered_at: string | null;
  readonly source_kind: WebhookSourceKind;
  readonly source_id: string;
}

export interface WebhookEnqueueInput {
  readonly nodeId: string;
  readonly implementerId: string;
  readonly eventType: WebhookEventType;
  readonly operationId: string | null;
  readonly externalRef: string | null;
  readonly occurredAt: string;
  readonly data: Record<string, unknown>;
  readonly sourceKind: WebhookSourceKind;
  readonly sourceId: string;
}

export interface WebhookDeliverySql {
  query<T extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ rows: T[] }>;
}

export interface WebhookPostRequest {
  readonly url: string;
  readonly body: string;
  readonly headers: Readonly<Record<string, string>>;
}

export interface WebhookDeliveryPorts {
  readonly now: () => Date;
  readonly signer: () => WebhookSigner | null;
  readonly targetFor: (
    implementerId: string,
  ) => Promise<{ readonly url: string } | null>;
  readonly validateTarget: (url: string) => Promise<void>;
  readonly post: (request: WebhookPostRequest) => Promise<{ readonly status: number }>;
}

export interface WebhookDeliveryStore {
  enqueue(input: WebhookEnqueueInput, signer: WebhookSigner): Promise<WebhookDeliveryRecord | null>;
  deliverDue(nodeId: string, ports: WebhookDeliveryPorts, limit?: number): Promise<number>;
  requeue(input: {
    readonly nodeId: string;
    readonly implementerId: string;
    readonly deliveryId: string;
    readonly now: Date;
  }): Promise<WebhookDeliveryRecord | null>;
  get(deliveryId: string): Promise<WebhookDeliveryRecord | null>;
}

export function delayAfterFailedAttempt(attemptCount: number): number | null {
  if (attemptCount >= 5) return null;
  return WEBHOOK_DELIVERY_BACKOFF_MS[attemptCount - 1] ?? null;
}

export function webhookHeaders(record: Pick<WebhookDeliveryRecord, "node_id" | "delivery_id" | "signature_text">): Record<string, string> {
  return {
    "content-type": "application/json",
    "x-generic-node-id": record.node_id,
    "x-generic-node-delivery-id": record.delivery_id,
    "x-generic-node-signature": record.signature_text,
  };
}

export async function signWebhookPayload(
  payload: WebhookEventPayloadV1,
  signer: WebhookSigner,
): Promise<{ readonly body: string; readonly signature: string }> {
  const body = canonicalWebhookEventJson(payload);
  const signature = await signer.sign(webhookEventPreimage(body));
  return { body, signature };
}

export function productionValidateTarget(url: string): Promise<void> {
  return assertUrlSafe(url).then(() => undefined);
}

export async function postWebhookJson(
  request: WebhookPostRequest,
  fetchImpl: typeof fetch = fetch,
): Promise<{ readonly status: number }> {
  const timer = AbortSignal.timeout(WEBHOOK_DELIVERY_TIMEOUT_MS);
  try {
    const response = await fetchImpl(request.url, {
      method: "POST",
      headers: request.headers,
      body: request.body,
      redirect: "error",
      signal: timer,
    });
    return { status: response.status };
  } catch (error) {
    if (error instanceof Error && error.name === "TimeoutError") {
      return { status: 0 };
    }
    if (error instanceof Error && error.name === "AbortError") {
      return { status: 0 };
    }
    throw error;
  }
}

interface DurableSourceRow extends Record<string, unknown> {
  readonly event_id: string;
  readonly implementer_id: string;
  readonly event_type: string;
  readonly created_at: Date | string;
  readonly proof_representation: string;
}

interface RuleSourceRow extends Record<string, unknown> {
  readonly request_id: string;
  readonly implementer_id: string;
  readonly status: string;
  readonly decided_at: Date | string | null;
}

const CATCH_UP_EVENTS = `SELECT e.event_id::text AS event_id,
       e.implementer_id::text AS implementer_id,
       e.event_type,
       e.created_at,
       e.proof_representation
  FROM implementer_events e
  JOIN connector_configs c ON c.implementer_id = e.implementer_id
 WHERE e.node_id = $1::uuid
   AND c.webhook_enabled = true
   AND c.webhook_url IS NOT NULL
   AND NOT EXISTS (
     SELECT 1 FROM webhook_deliveries d
      WHERE d.source_kind = 'DURABLE_EVENT'
        AND d.source_id = e.event_id
   )
 LIMIT 50`;

const CATCH_UP_RULES = `SELECT r.request_id::text AS request_id,
       r.implementer_id::text AS implementer_id,
       r.status,
       r.decided_at
  FROM connector_rule_requests r
  JOIN connector_configs c ON c.implementer_id = r.implementer_id
 WHERE r.node_id = $1::uuid
   AND r.status IN ('APPROVED', 'REJECTED')
   AND c.webhook_enabled = true
   AND c.webhook_url IS NOT NULL
   AND NOT EXISTS (
     SELECT 1 FROM webhook_deliveries d
      WHERE d.source_kind = 'RULE_REQUEST'
        AND d.source_id = r.request_id
   )
 LIMIT 50`;

const TARGET_SQL = `SELECT webhook_url
  FROM connector_configs
 WHERE implementer_id = $1::uuid
   AND webhook_enabled = true
   AND webhook_url IS NOT NULL`;

export function operationIdFromProof(proofRepresentation: string): string | null {
  try {
    const envelope = JSON.parse(proofRepresentation) as { preimage_text?: unknown };
    if (typeof envelope.preimage_text !== "string") return null;
    const splitAt = envelope.preimage_text.indexOf("\n");
    if (splitAt < 0) return null;
    const body = JSON.parse(envelope.preimage_text.slice(splitAt + 1)) as { operation_id?: unknown };
    return typeof body.operation_id === "string" ? body.operation_id : null;
  } catch {
    return null;
  }
}

export async function catchUpWebhookDeliveries(
  store: WebhookDeliveryStore,
  sql: WebhookDeliverySql,
  nodeId: string,
  signer: WebhookSigner,
): Promise<number> {
  let queued = 0;
  const events = await sql.query<DurableSourceRow>(CATCH_UP_EVENTS, [nodeId]);
  for (const row of events.rows) {
    const eventType = DURABLE_EVENT_TO_WEBHOOK[row.event_type];
    if (eventType === undefined) continue;
    const saved = await store.enqueue(
      {
        nodeId,
        implementerId: row.implementer_id,
        eventType,
        operationId: operationIdFromProof(row.proof_representation),
        externalRef: null,
        occurredAt: asIso(row.created_at),
        data: { durable_event: row.event_type },
        sourceKind: "DURABLE_EVENT",
        sourceId: row.event_id,
      },
      signer,
    );
    if (saved !== null) queued += 1;
  }
  const rules = await sql.query<RuleSourceRow>(CATCH_UP_RULES, [nodeId]);
  for (const row of rules.rows) {
    const eventType: WebhookEventType | null =
      row.status === "APPROVED"
        ? "connector.rule.approved"
        : row.status === "REJECTED"
          ? "connector.rule.rejected"
          : null;
    if (eventType === null) continue;
    const saved = await store.enqueue(
      {
        nodeId,
        implementerId: row.implementer_id,
        eventType,
        operationId: null,
        externalRef: null,
        occurredAt: row.decided_at === null ? new Date().toISOString() : asIso(row.decided_at),
        data: { request_id: row.request_id },
        sourceKind: "RULE_REQUEST",
        sourceId: row.request_id,
      },
      signer,
    );
    if (saved !== null) queued += 1;
  }
  return queued;
}

const INSERT_SQL = `INSERT INTO webhook_deliveries (
  delivery_id, node_id, implementer_id, event_type, operation_id,
  payload_text, signature_text, status, attempt_count, next_attempt_at,
  created_at, source_kind, source_id
) VALUES (
  $1::uuid, $2::uuid, $3::uuid, $4, $5::uuid,
  $6, $7, 'PENDING', 0, $8::timestamptz,
  $8::timestamptz, $9, $10::uuid
)
ON CONFLICT ON CONSTRAINT webhook_deliveries_source_uidx DO NOTHING
RETURNING delivery_id::text AS delivery_id, node_id::text AS node_id,
  implementer_id::text AS implementer_id, event_type, operation_id::text AS operation_id,
  payload_text, signature_text, status, attempt_count, next_attempt_at,
  last_status_code, last_error, created_at, delivered_at, source_kind, source_id::text AS source_id`;

const DUE_SQL = `WITH due AS (
  SELECT delivery_id
    FROM webhook_deliveries
   WHERE node_id = $1::uuid
     AND status = 'PENDING'
     AND next_attempt_at <= $2::timestamptz
   LIMIT $3
   FOR UPDATE SKIP LOCKED
)
UPDATE webhook_deliveries AS claimed SET
  next_attempt_at = $4::timestamptz
 WHERE claimed.delivery_id IN (SELECT delivery_id FROM due)
 RETURNING claimed.delivery_id::text AS delivery_id, claimed.node_id::text AS node_id,
  claimed.implementer_id::text AS implementer_id, claimed.event_type,
  claimed.operation_id::text AS operation_id, claimed.payload_text, claimed.signature_text,
  claimed.status, claimed.attempt_count, claimed.next_attempt_at, claimed.last_status_code,
  claimed.last_error, claimed.created_at, claimed.delivered_at, claimed.source_kind,
  claimed.source_id::text AS source_id`;

const MARK_SQL = `UPDATE webhook_deliveries SET
  status = $2,
  attempt_count = $3,
  next_attempt_at = $4::timestamptz,
  last_status_code = $5,
  last_error = $6,
  delivered_at = $7::timestamptz
 WHERE delivery_id = $1::uuid`;

const REQUEUE_SQL = `UPDATE webhook_deliveries SET
  status = 'PENDING',
  attempt_count = 0,
  next_attempt_at = $4::timestamptz,
  last_error = NULL,
  delivered_at = NULL
 WHERE delivery_id = $1::uuid
   AND node_id = $2::uuid
   AND implementer_id = $3::uuid
 RETURNING delivery_id::text AS delivery_id, node_id::text AS node_id,
  implementer_id::text AS implementer_id, event_type, operation_id::text AS operation_id,
  payload_text, signature_text, status, attempt_count, next_attempt_at,
  last_status_code, last_error, created_at, delivered_at, source_kind, source_id::text AS source_id`;

const GET_SQL = `SELECT delivery_id::text AS delivery_id, node_id::text AS node_id,
       implementer_id::text AS implementer_id, event_type, operation_id::text AS operation_id,
       payload_text, signature_text, status, attempt_count, next_attempt_at,
       last_status_code, last_error, created_at, delivered_at, source_kind,
       source_id::text AS source_id
  FROM webhook_deliveries
 WHERE delivery_id = $1::uuid`;

type Row = Record<string, unknown>;

export class SqlWebhookDeliveryStore implements WebhookDeliveryStore {
  constructor(private readonly sql: WebhookDeliverySql) {}

  async enqueue(input: WebhookEnqueueInput, signer: WebhookSigner): Promise<WebhookDeliveryRecord | null> {
    const deliveryId = randomUUID();
    const occurredAt = input.occurredAt;
    const payload: WebhookEventPayloadV1 = {
      v: 1,
      delivery_id: deliveryId,
      node_id: input.nodeId,
      implementer_id: input.implementerId,
      event_type: input.eventType,
      occurred_at: occurredAt,
      operation_id: input.operationId,
      external_ref: input.externalRef,
      data: input.data,
    };
    const signed = await signWebhookPayload(payload, signer);
    const { rows } = await this.sql.query<Row>(INSERT_SQL, [
      deliveryId,
      input.nodeId,
      input.implementerId,
      input.eventType,
      input.operationId,
      signed.body,
      signed.signature,
      occurredAt,
      input.sourceKind,
      input.sourceId,
    ]);
    const row = rows[0];
    return row === undefined ? null : toRecord(row);
  }

  async deliverDue(nodeId: string, ports: WebhookDeliveryPorts, limit = 20): Promise<number> {
    const now = ports.now();
    const lease = new Date(now.getTime() + 30_000).toISOString();
    const { rows } = await this.sql.query<Row>(DUE_SQL, [nodeId, now.toISOString(), limit, lease]);
    let posted = 0;
    for (const row of rows) {
      const record = toRecord(row);
      const outcome = await attemptDelivery(record, ports);
      await this.sql.query(MARK_SQL, [
        record.delivery_id,
        outcome.status,
        outcome.attemptCount,
        outcome.nextAttemptAt,
        outcome.lastStatusCode,
        outcome.lastError,
        outcome.deliveredAt,
      ]);
      if (outcome.status === "DELIVERED") posted += 1;
    }
    return posted;
  }

  async requeue(input: {
    readonly nodeId: string;
    readonly implementerId: string;
    readonly deliveryId: string;
    readonly now: Date;
  }): Promise<WebhookDeliveryRecord | null> {
    const { rows } = await this.sql.query<Row>(REQUEUE_SQL, [
      input.deliveryId,
      input.nodeId,
      input.implementerId,
      input.now.toISOString(),
    ]);
    const row = rows[0];
    return row === undefined ? null : toRecord(row);
  }

  async get(deliveryId: string): Promise<WebhookDeliveryRecord | null> {
    const { rows } = await this.sql.query<Row>(GET_SQL, [deliveryId]);
    const row = rows[0];
    return row === undefined ? null : toRecord(row);
  }
}

export function createSqlWebhookDeliveryStore(sql: WebhookDeliverySql): SqlWebhookDeliveryStore {
  return new SqlWebhookDeliveryStore(sql);
}

export class InMemoryWebhookDeliveryStore implements WebhookDeliveryStore {
  readonly rows = new Map<string, WebhookDeliveryRecord>();

  async enqueue(input: WebhookEnqueueInput, signer: WebhookSigner): Promise<WebhookDeliveryRecord | null> {
    for (const existing of this.rows.values()) {
      if (existing.source_kind === input.sourceKind && existing.source_id === input.sourceId) return null;
    }
    const deliveryId = randomUUID();
    const payload: WebhookEventPayloadV1 = {
      v: 1,
      delivery_id: deliveryId,
      node_id: input.nodeId,
      implementer_id: input.implementerId,
      event_type: input.eventType,
      occurred_at: input.occurredAt,
      operation_id: input.operationId,
      external_ref: input.externalRef,
      data: input.data,
    };
    const signed = await signWebhookPayload(payload, signer);
    const record: WebhookDeliveryRecord = {
      delivery_id: deliveryId,
      node_id: input.nodeId,
      implementer_id: input.implementerId,
      event_type: input.eventType,
      operation_id: input.operationId,
      payload_text: signed.body,
      signature_text: signed.signature,
      status: "PENDING",
      attempt_count: 0,
      next_attempt_at: input.occurredAt,
      last_status_code: null,
      last_error: null,
      created_at: input.occurredAt,
      delivered_at: null,
      source_kind: input.sourceKind,
      source_id: input.sourceId,
    };
    this.rows.set(deliveryId, record);
    return record;
  }

  async deliverDue(nodeId: string, ports: WebhookDeliveryPorts, limit = 20): Promise<number> {
    const now = ports.now().getTime();
    const due = [...this.rows.values()]
      .filter(
        (row) =>
          row.node_id === nodeId &&
          row.status === "PENDING" &&
          Date.parse(row.next_attempt_at) <= now,
      )
      .slice(0, limit);
    let posted = 0;
    for (const record of due) {
      const outcome = await attemptDelivery(record, ports);
      const next: WebhookDeliveryRecord = {
        ...record,
        status: outcome.status,
        attempt_count: outcome.attemptCount,
        next_attempt_at: outcome.nextAttemptAt,
        last_status_code: outcome.lastStatusCode,
        last_error: outcome.lastError,
        delivered_at: outcome.deliveredAt,
      };
      this.rows.set(record.delivery_id, next);
      if (outcome.status === "DELIVERED") posted += 1;
    }
    return posted;
  }

  async requeue(input: {
    readonly nodeId: string;
    readonly implementerId: string;
    readonly deliveryId: string;
    readonly now: Date;
  }): Promise<WebhookDeliveryRecord | null> {
    const existing = this.rows.get(input.deliveryId);
    if (
      existing === undefined ||
      existing.node_id !== input.nodeId ||
      existing.implementer_id !== input.implementerId
    ) {
      return null;
    }
    const next: WebhookDeliveryRecord = {
      ...existing,
      status: "PENDING",
      attempt_count: 0,
      next_attempt_at: input.now.toISOString(),
      last_error: null,
      delivered_at: null,
    };
    this.rows.set(input.deliveryId, next);
    return next;
  }

  async get(deliveryId: string): Promise<WebhookDeliveryRecord | null> {
    return this.rows.get(deliveryId) ?? null;
  }
}

interface AttemptOutcome {
  readonly status: WebhookDeliveryStatus;
  readonly attemptCount: number;
  readonly nextAttemptAt: string;
  readonly lastStatusCode: number | null;
  readonly lastError: string | null;
  readonly deliveredAt: string | null;
}

async function attemptDelivery(
  record: WebhookDeliveryRecord,
  ports: WebhookDeliveryPorts,
): Promise<AttemptOutcome> {
  const now = ports.now();
  const target = await ports.targetFor(record.implementer_id);
  if (target === null) {
    return {
      status: "PENDING",
      attemptCount: record.attempt_count,
      nextAttemptAt: new Date(now.getTime() + 60_000).toISOString(),
      lastStatusCode: null,
      lastError: "target_unavailable",
      deliveredAt: null,
    };
  }
  try {
    await ports.validateTarget(target.url);
  } catch {
    return failure(record, now, null, "guard_rejected");
  }
  let status: number;
  try {
    const response = await ports.post({
      url: target.url,
      body: record.payload_text,
      headers: webhookHeaders(record),
    });
    status = response.status;
  } catch {
    return failure(record, now, null, "post_failed");
  }
  if (status >= 200 && status < 300) {
    return {
      status: "DELIVERED",
      attemptCount: record.attempt_count + 1,
      nextAttemptAt: now.toISOString(),
      lastStatusCode: status,
      lastError: null,
      deliveredAt: now.toISOString(),
    };
  }
  return failure(record, now, status === 0 ? null : status, status === 0 ? "timeout" : "non_success");
}

function failure(
  record: WebhookDeliveryRecord,
  now: Date,
  statusCode: number | null,
  error: string,
): AttemptOutcome {
  const attemptCount = record.attempt_count + 1;
  const delay = delayAfterFailedAttempt(attemptCount);
  if (delay === null) {
    return {
      status: "FAILED_PERMANENT",
      attemptCount,
      nextAttemptAt: now.toISOString(),
      lastStatusCode: statusCode,
      lastError: error,
      deliveredAt: null,
    };
  }
  return {
    status: "PENDING",
    attemptCount,
    nextAttemptAt: new Date(now.getTime() + delay).toISOString(),
    lastStatusCode: statusCode,
    lastError: error,
    deliveredAt: null,
  };
}

function toRecord(row: Row): WebhookDeliveryRecord {
  const eventType = String(row.event_type);
  if (!isWebhookEventType(eventType)) {
    throw new Error("delivery row has an unknown event type");
  }
  const status = String(row.status);
  if (status !== "PENDING" && status !== "DELIVERED" && status !== "FAILED_PERMANENT") {
    throw new Error("delivery row has an unknown status");
  }
  const sourceKind = String(row.source_kind);
  if (sourceKind !== "DURABLE_EVENT" && sourceKind !== "RULE_REQUEST") {
    throw new Error("delivery row has an unknown source kind");
  }
  return {
    delivery_id: String(row.delivery_id),
    node_id: String(row.node_id),
    implementer_id: String(row.implementer_id),
    event_type: eventType,
    operation_id: row.operation_id === null || row.operation_id === undefined ? null : String(row.operation_id),
    payload_text: String(row.payload_text),
    signature_text: String(row.signature_text),
    status,
    attempt_count: Number(row.attempt_count),
    next_attempt_at: asIso(row.next_attempt_at),
    last_status_code:
      row.last_status_code === null || row.last_status_code === undefined
        ? null
        : Number(row.last_status_code),
    last_error: row.last_error === null || row.last_error === undefined ? null : String(row.last_error),
    created_at: asIso(row.created_at),
    delivered_at:
      row.delivered_at === null || row.delivered_at === undefined ? null : asIso(row.delivered_at),
    source_kind: sourceKind,
    source_id: String(row.source_id),
  };
}

function asIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  const parsed = new Date(String(value));
  if (Number.isNaN(parsed.getTime())) return String(value);
  return parsed.toISOString();
}

export async function loadWebhookTarget(
  sql: WebhookDeliverySql,
  implementerId: string,
): Promise<{ readonly url: string } | null> {
  const { rows } = await sql.query<{ webhook_url: string | null }>(TARGET_SQL, [implementerId]);
  const url = rows[0]?.webhook_url;
  return typeof url === "string" && url.length > 0 ? { url } : null;
}

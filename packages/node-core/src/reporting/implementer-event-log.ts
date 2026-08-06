// Durable implementer-scoped event log seam for.
//
// Builds on ImplementerEventReadStore (events-read-service.ts): this module adds
// the append + watermark + optional live-notify surfaces the SSE accelerator and snapshot
// capture need, without inventing a second cursor model. proofRepresentation stays opaque
// exact bytes. Node-global zp-node-event-v1 is never read here.

import type {
  ImplementerEventPage,
  ImplementerEventReadStore,
  ServedImplementerCheckpoint,
  ServedImplementerEvent,
} from "./events-read-service.js";

export const IMPLEMENTER_STREAM_EVENT_TYPES = [
  "receive.ready",
  "receive.landed",
  "internal_move.created",
  "internal_move.landed",
  "external_send.created",
  "external_send.awaiting_redemption",
  "external_send.landed",
  "operation.needs_attention",
  "operation.expired",
] as const;

export type ImplementerStreamEventType = (typeof IMPLEMENTER_STREAM_EVENT_TYPES)[number];

export function isImplementerStreamEventType(value: string): value is ImplementerStreamEventType {
  return (IMPLEMENTER_STREAM_EVENT_TYPES as readonly string[]).includes(value);
}

export interface ImplementerEventAppendInput {
  readonly implementerId: string;
  readonly eventId: string;
  readonly eventType: ImplementerStreamEventType;
  readonly proofRepresentation: string;
  readonly createdAt: string;
}

export interface ImplementerCheckpointAppendInput {
  readonly implementerId: string;
  readonly checkpointEpoch: bigint;
  readonly implementerSeqHead: bigint;
  readonly proofRepresentation: string;
  readonly createdAt: string;
}

export interface StoredImplementerEvent extends ServedImplementerEvent {
  readonly eventId: string;
  readonly createdAt: string;
}

export interface StoredImplementerCheckpoint extends ServedImplementerCheckpoint {
  readonly createdAt: string;
}

export interface ImplementerEventLog extends ImplementerEventReadStore {
  /** Highest gapless implementer_seq for this implementer (0n when empty). */
  watermark(implementerId: string): Promise<bigint>;
  /**
   * Append one durable zp-implementer-checkpoint-v1 proof (UP-07). Fail-closed on
   * empty proof or non-positive epoch. Equal-epoch re-append is refused — consumer C3 conflict
   * handling lives on the platform; the node never overwrites a stored epoch.
   */
  appendCheckpoint(input: ImplementerCheckpointAppendInput): Promise<StoredImplementerCheckpoint>;
  readCheckpoints(implementerId: string): Promise<readonly ServedImplementerCheckpoint[]>;
  /**
   * Process-local live notify. Delivery failure after append must never roll back the row
   * OUTBOX_DECOUPLING / "SSE failure irrelevant to operation truth".
   */
  subscribe(
    implementerId: string,
    listener: (event: StoredImplementerEvent) => void,
  ): () => void;
}

export class ImplementerEventLogError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ImplementerEventLogError";
  }
}

interface TenantBucket {
  readonly events: StoredImplementerEvent[];
  readonly checkpoints: StoredImplementerCheckpoint[];
  watermark: bigint;
  readonly listeners: Set<(event: StoredImplementerEvent) => void>;
}

/**
 * Single-process reference adapter. Production uses createPgImplementerEventLog.
 * The gapless append critical section holds no await between recheck, insert, advance, and
 * listener notify so concurrent appends on one process cannot interleave under JS
 * run-to-completion.
 */
export class InMemoryImplementerEventLog implements ImplementerEventLog {
  private readonly tenants = new Map<string, TenantBucket>();

  private bucket(implementerId: string): TenantBucket {
    let tenant = this.tenants.get(implementerId);
    if (tenant === undefined) {
      tenant = { events: [], checkpoints: [], watermark: 0n, listeners: new Set() };
      this.tenants.set(implementerId, tenant);
    }
    return tenant;
  }

  watermark(implementerId: string): Promise<bigint> {
    return Promise.resolve(this.bucket(implementerId).watermark);
  }

  readEvents(
    implementerId: string,
    afterImplementerSeq: bigint | null,
    limit: number,
  ): Promise<ImplementerEventPage> {
    const tenant = this.bucket(implementerId);
    const after = afterImplementerSeq ?? 0n;
    const events = tenant.events
      .filter((event) => event.implementerSeq > after)
      .slice(0, Math.max(0, limit));
    return Promise.resolve({ events, watermarkSeq: tenant.watermark });
  }

  append(input: ImplementerEventAppendInput): Promise<StoredImplementerEvent> {
    if (!isImplementerStreamEventType(input.eventType)) {
      return Promise.reject(
        new ImplementerEventLogError(
          `event_type ${input.eventType} is outside the closed durable event set`,
        ),
      );
    }
    if (typeof input.proofRepresentation !== "string" || input.proofRepresentation.length === 0) {
      return Promise.reject(new ImplementerEventLogError("proofRepresentation is required"));
    }
    const tenant = this.bucket(input.implementerId);
    const seq = tenant.watermark + 1n;
    const stored: StoredImplementerEvent = Object.freeze({
      implementerSeq: seq,
      eventType: input.eventType,
      proofRepresentation: input.proofRepresentation,
      eventId: input.eventId,
      createdAt: input.createdAt,
    });
    tenant.events.push(stored);
    tenant.watermark = seq;
    for (const listener of [...tenant.listeners]) {
      try {
        listener(stored);
      } catch {
        // Live notify must never undo the durable append.
      }
    }
    return Promise.resolve(stored);
  }

  readCheckpoints(implementerId: string): Promise<readonly ServedImplementerCheckpoint[]> {
    const tenant = this.bucket(implementerId);
    return Promise.resolve(
      tenant.checkpoints.map((row) =>
        Object.freeze({
          checkpointEpoch: row.checkpointEpoch,
          implementerSeqHead: row.implementerSeqHead,
          proofRepresentation: row.proofRepresentation,
        }),
      ),
    );
  }

  appendCheckpoint(input: ImplementerCheckpointAppendInput): Promise<StoredImplementerCheckpoint> {
    if (input.checkpointEpoch <= 0n) {
      return Promise.reject(new ImplementerEventLogError("checkpoint_epoch must be positive"));
    }
    if (input.implementerSeqHead < 0n) {
      return Promise.reject(new ImplementerEventLogError("implementer_seq_head must be non-negative"));
    }
    if (typeof input.proofRepresentation !== "string" || input.proofRepresentation.length === 0) {
      return Promise.reject(new ImplementerEventLogError("proofRepresentation is required"));
    }
    const tenant = this.bucket(input.implementerId);
    if (tenant.checkpoints.some((row) => row.checkpointEpoch === input.checkpointEpoch)) {
      return Promise.reject(
        new ImplementerEventLogError(
          `checkpoint_epoch ${input.checkpointEpoch.toString()} already reserved`,
        ),
      );
    }
    const stored: StoredImplementerCheckpoint = Object.freeze({
      checkpointEpoch: input.checkpointEpoch,
      implementerSeqHead: input.implementerSeqHead,
      proofRepresentation: input.proofRepresentation,
      createdAt: input.createdAt,
    });
    tenant.checkpoints.push(stored);
    tenant.checkpoints.sort((left, right) =>
      left.checkpointEpoch < right.checkpointEpoch ? -1 : 1,
    );
    return Promise.resolve(stored);
  }

  subscribe(
    implementerId: string,
    listener: (event: StoredImplementerEvent) => void,
  ): () => void {
    const tenant = this.bucket(implementerId);
    tenant.listeners.add(listener);
    return () => {
      tenant.listeners.delete(listener);
    };
  }
}

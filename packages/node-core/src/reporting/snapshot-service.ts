// Snapshot service for GET /v1/state/snapshot.
// Transactionally consistent tenant snapshot of non-expired proof-access operations,
// destinations, attention items, and implementer_watermark_seq. Bootstrap/reconciliation
// convenience only — never chain evidence (C1; NC1–NC3).
//
// Consistency: watermark is read from the implementer event log first, then the state
// reader is invoked AT that watermark (under one DB transaction in the PG adapter path),
// so a consumer that applies GET /v1/events?after_implementer_seq=<watermark> sees no gap
// and no duplicate against the snapshot contents.

import type { OperationKind } from "@zucoins/generic-node-contracts/operations";
import type { ImplementerEventLog } from "./implementer-event-log.js";

export interface SnapshotOperation {
  readonly operationId: string;
  readonly operationType: OperationKind;
  readonly state: string;
  readonly rowVersion: number;
  readonly attentionRequired: boolean;
  readonly updatedAt: string;
}

export interface SnapshotDestination {
  readonly destinationId: string;
  readonly state: "PENDING" | "BLESSED" | "RETIRED";
}

export interface SnapshotAttentionItem {
  readonly operationId: string;
  readonly attentionReason: string;
  readonly attentionEpisode: number;
}

export interface ImplementerStateSnapshot {
  readonly implementerId: string;
  readonly implementerWatermarkSeq: string;
  readonly operations: readonly SnapshotOperation[];
  readonly destinations: readonly SnapshotDestination[];
  readonly attentionItems: readonly SnapshotAttentionItem[];
  readonly capturedAt: string;
}

export interface SnapshotStateReader {
  readState(
    implementerId: string,
    watermark: bigint,
  ): Promise<{
    readonly operations: readonly SnapshotOperation[];
    readonly destinations: readonly SnapshotDestination[];
    readonly attentionItems: readonly SnapshotAttentionItem[];
  }>;
}

export interface SnapshotStore {
  save(snapshot: ImplementerStateSnapshot): Promise<void>;
  latest(implementerId: string): Promise<ImplementerStateSnapshot | null>;
}

export type SnapshotActiveCounts = Readonly<Record<string, number>>;

export function deriveActiveCounts(operations: readonly SnapshotOperation[]): SnapshotActiveCounts {
  const counts: Record<string, number> = {};
  for (const operation of operations) {
    counts[operation.state] = (counts[operation.state] ?? 0) + 1;
  }
  return counts;
}

/** Wire body for GET /v1/state/snapshot — field insertion sequence is frozen here. */
export function renderSnapshotBody(snapshot: ImplementerStateSnapshot): string {
  const activeCounts = deriveActiveCounts(snapshot.operations);
  return JSON.stringify({
    implementer_watermark_seq: snapshot.implementerWatermarkSeq,
    operations: snapshot.operations.map((op) => ({
      operation_id: op.operationId,
      operation_type: op.operationType,
      state: op.state,
      row_version: op.rowVersion,
      attention_required: op.attentionRequired,
      updated_at: op.updatedAt,
    })),
    destinations: snapshot.destinations.map((d) => ({
      destination_id: d.destinationId,
      state: d.state,
    })),
    attention_items: snapshot.attentionItems.map((a) => ({
      operation_id: a.operationId,
      attention_reason: a.attentionReason,
      attention_episode: a.attentionEpisode,
    })),
    active_counts: activeCounts,
    captured_at: snapshot.capturedAt,
  });
}

/** Raised when capture exceeds the configured read budget. */
export class SnapshotCaptureTimeoutError extends Error {
  readonly implementerId: string;
  readonly timeoutMs: number;

  constructor(implementerId: string, timeoutMs: number) {
    super(`snapshot capture timed out after ${timeoutMs}ms for implementer ${implementerId}`);
    this.name = "SnapshotCaptureTimeoutError";
    this.implementerId = implementerId;
    this.timeoutMs = timeoutMs;
  }
}

export interface SnapshotServiceConfig {
  readonly log: ImplementerEventLog;
  readonly reader: SnapshotStateReader;
  readonly store: SnapshotStore;
  readonly nowMs?: () => number;
  /**
   * Bounded read budget for watermark + state read + store save.
   * When set to a positive finite ms value, capture rejects with
   * {@link SnapshotCaptureTimeoutError} if the budget elapses before completion.
   * Omitted / non-positive = unbounded (legacy callers).
   */
  readonly captureTimeoutMs?: number;
}

export interface SnapshotService {
  capture(implementerId: string): Promise<ImplementerStateSnapshot>;
  latest(implementerId: string): Promise<ImplementerStateSnapshot | null>;
}

export function createSnapshotService(config: SnapshotServiceConfig): SnapshotService {
  const nowMs = config.nowMs ?? (() => Date.now());
  const captureTimeoutMs = config.captureTimeoutMs;

  const captureBody = async (implementerId: string): Promise<ImplementerStateSnapshot> => {
    const watermark = await config.log.watermark(implementerId);
    const state = await config.reader.readState(implementerId, watermark);
    const snapshot: ImplementerStateSnapshot = {
      implementerId,
      implementerWatermarkSeq: watermark.toString(),
      operations: state.operations,
      destinations: state.destinations,
      attentionItems: state.attentionItems,
      capturedAt: new Date(nowMs()).toISOString(),
    };
    await config.store.save(snapshot);
    return snapshot;
  };

  const capture = async (implementerId: string): Promise<ImplementerStateSnapshot> => {
    if (
      captureTimeoutMs === undefined ||
      !Number.isFinite(captureTimeoutMs) ||
      captureTimeoutMs <= 0
    ) {
      return captureBody(implementerId);
    }
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        captureBody(implementerId),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => {
            reject(new SnapshotCaptureTimeoutError(implementerId, captureTimeoutMs));
          }, captureTimeoutMs);
        }),
      ]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  };

  const latest = (implementerId: string): Promise<ImplementerStateSnapshot | null> =>
    config.store.latest(implementerId);

  return { capture, latest };
}

export class InMemorySnapshotStore implements SnapshotStore {
  private readonly snapshots = new Map<string, ImplementerStateSnapshot>();

  save(snapshot: ImplementerStateSnapshot): Promise<void> {
    this.snapshots.set(snapshot.implementerId, Object.freeze(snapshot));
    return Promise.resolve();
  }

  latest(implementerId: string): Promise<ImplementerStateSnapshot | null> {
    return Promise.resolve(this.snapshots.get(implementerId) ?? null);
  }
}

export class InMemorySnapshotStateReader implements SnapshotStateReader {
  private readonly byImplementer = new Map<
    string,
    {
      operations: readonly SnapshotOperation[];
      destinations: readonly SnapshotDestination[];
      attentionItems: readonly SnapshotAttentionItem[];
    }
  >();

  seed(
    implementerId: string,
    state: {
      operations: readonly SnapshotOperation[];
      destinations: readonly SnapshotDestination[];
      attentionItems: readonly SnapshotAttentionItem[];
    },
  ): void {
    this.byImplementer.set(implementerId, state);
  }

  readState(
    implementerId: string,
    _watermark: bigint,
  ): Promise<{
    readonly operations: readonly SnapshotOperation[];
    readonly destinations: readonly SnapshotDestination[];
    readonly attentionItems: readonly SnapshotAttentionItem[];
  }> {
    const state = this.byImplementer.get(implementerId);
    return Promise.resolve(
      state ?? { operations: [], destinations: [], attentionItems: [] },
    );
  }
}

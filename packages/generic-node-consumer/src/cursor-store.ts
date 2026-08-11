/**
 * Consumer-owned cursor / snapshot persistence (product-neutral; part of the consumer SDK surface).
 *
 * Resume always uses the consumer's own watermark_seq — never a node-supplied
 * cache (the `next_after_implementer_seq` cursor is consumer-owned). In-memory reference
 * implementation; a product would swap the store implementation without
 * changing the pipeline.
 */

import type { CachedIdentityPin } from "@zucoins/node-core/verifier/consumer/pinning";

import type { ConsumerCursorState, ConsumerOperation, ConsumerSnapshot } from "./types.js";

export interface ConsumerStore {
  loadCursor(): ConsumerCursorState | null;
  saveCursor(cursor: ConsumerCursorState): void;
  loadOperations(): readonly ConsumerOperation[];
  saveOperation(op: ConsumerOperation): void;
  loadIdentityPin(): CachedIdentityPin | null;
  saveIdentityPin(pin: CachedIdentityPin): void;
  loadGatewayFingerprint(): string | null;
  saveGatewayFingerprint(fp: string): void;
  /** Serialize durable state for restart. */
  snapshot(nowUnixMs: number): ConsumerSnapshot | null;
  /** Replace in-memory state from a prior snapshot (consumer restart). */
  restore(snapshot: ConsumerSnapshot): void;
}

/** In-memory store — durable enough for the offline fixture scenarios. */
export function createInMemoryConsumerStore(): ConsumerStore {
  let cursor: ConsumerCursorState | null = null;
  const operations = new Map<string, ConsumerOperation>();
  let identityPin: CachedIdentityPin | null = null;
  let gatewayFingerprint: string | null = null;

  return {
    loadCursor: () => cursor,
    saveCursor: (next) => {
      cursor = next;
    },
    loadOperations: () => [...operations.values()],
    saveOperation: (op) => {
      operations.set(op.operationId, op);
    },
    loadIdentityPin: () => identityPin,
    saveIdentityPin: (pin) => {
      identityPin = pin;
    },
    loadGatewayFingerprint: () => gatewayFingerprint,
    saveGatewayFingerprint: (fp) => {
      gatewayFingerprint = fp;
    },
    snapshot: (nowUnixMs) => {
      if (cursor === null || identityPin === null || gatewayFingerprint === null) {
        return null;
      }
      return {
        watermarkSeq: cursor.watermarkSeq,
        operations: [...operations.values()],
        identityPin,
        pinnedGatewayFingerprint: gatewayFingerprint,
        capturedAtUnixMs: nowUnixMs,
      };
    },
    restore: (snap) => {
      cursor = {
        watermarkSeq: snap.watermarkSeq,
        lastPersistedAtUnixMs: snap.capturedAtUnixMs,
      };
      operations.clear();
      for (const op of snap.operations) {
        operations.set(op.operationId, op);
      }
      identityPin = snap.identityPin;
      gatewayFingerprint = snap.pinnedGatewayFingerprint;
    },
  };
}

/** Advance the exclusive event cursor after a successful poll/stream batch. */
export function advanceWatermark(
  store: ConsumerStore,
  nextAfterImplementerSeq: string,
  nowUnixMs: number,
): ConsumerCursorState {
  const next: ConsumerCursorState = {
    watermarkSeq: nextAfterImplementerSeq,
    lastPersistedAtUnixMs: nowUnixMs,
  };
  store.saveCursor(next);
  return next;
}

/** Resume position for the next GET /v1/events call. */
export function resumeAfterSeq(store: ConsumerStore): string | null {
  return store.loadCursor()?.watermarkSeq ?? null;
}

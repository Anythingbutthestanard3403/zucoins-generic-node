// Named consumer cursor manager: idempotent monotonic advance with optimistic-version guard.

import {
  EventLogError,
  type AdvanceCursorOutcome,
  type EventCursorName,
  type EventCursorState,
  type EventCursorStore,
} from "./store.js";

export interface CursorManagerConfig {
  readonly nodeId: string;
  readonly maxAdvanceRetries?: number;
  readonly nowIso?: () => string;
}

const DEFAULT_MAX_ADVANCE_RETRIES = 128;

export class CursorManager {
  private readonly store: EventCursorStore;
  private readonly nodeId: string;
  private readonly maxAdvanceRetries: number;
  private readonly nowIso: () => string;

  constructor(store: EventCursorStore, config: CursorManagerConfig) {
    this.store = store;
    this.nodeId = config.nodeId;
    this.maxAdvanceRetries = config.maxAdvanceRetries ?? DEFAULT_MAX_ADVANCE_RETRIES;
    this.nowIso = config.nowIso ?? (() => new Date().toISOString());
  }

  read(name: EventCursorName): Promise<EventCursorState> {
    return this.store.readCursor(this.nodeId, name);
  }

  list(): Promise<readonly EventCursorState[]> {
    return this.store.listCursors(this.nodeId);
  }

  async advance(name: EventCursorName, toPosition: bigint): Promise<EventCursorState> {
    if (toPosition < 0n) {
      throw new EventLogError("cursor position must be non-negative");
    }
    void this.nowIso;
    for (let attempt = 0; attempt <= this.maxAdvanceRetries; attempt += 1) {
      const current = await this.store.readCursor(this.nodeId, name);
      const outcome: AdvanceCursorOutcome = await this.store.advanceCursor(
        this.nodeId,
        name,
        toPosition,
        current.version,
      );
      if (outcome.kind === "ADVANCED") {
        return outcome.state;
      }
    }
    throw new EventLogError(
      `cursor advance could not commit after ${this.maxAdvanceRetries} retries under contention`,
    );
  }
}

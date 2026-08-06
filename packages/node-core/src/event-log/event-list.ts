// Durable event list service: gapless monotonic append, exclusive after_seq scan, and
// hash-chain verification. CURSOR_CONTRACT (exclusive after_seq,
// watermark_seq, next_after_seq).2 EVENT_HASH_RULE.

import { createHash } from "node:crypto";

import { NEUTRAL_EVENT_TYPES } from "../protocol/suite/index.js";
import {
  EventLogError,
  type AppendEventsOutcome,
  type EventAppendInput,
  type EventListStore,
  type EventRecord,
  type EventStreamTail,
} from "./store.js";

/**
 * EVENT_HASH_RULE: `event_hash = SHA256(preimage_bytes || signature_bytes)`.
 * `signature` is the padded base64url wire form; signature_bytes are the decoded 64-byte
 * Ed25519 signature (same concatenation the A.8 freeze goldens pin).
 */
export function computeEventLogNodeEventHash(preimageText: string, signature: string): string {
  const preimageBytes = Buffer.from(preimageText, "utf8");
  const sigBytes = Buffer.from(signature, "base64url");
  if (sigBytes.length !== 64) {
    throw new EventLogError(
      `event signature must decode to 64 bytes, got ${sigBytes.length}`,
    );
  }
  return createHash("sha256").update(Buffer.concat([preimageBytes, sigBytes])).digest("hex");
}

function defaultEventHashOf(input: EventAppendInput): string {
  return computeEventLogNodeEventHash(input.preimageText, input.signature);
}

const CLOSED_EVENT_TYPES: readonly string[] = NEUTRAL_EVENT_TYPES;

function assertValidInput(input: EventAppendInput): void {
  if (typeof input.eventId !== "string" || input.eventId.length === 0) {
    throw new EventLogError("event input requires a non-empty eventId");
  }
  if (!CLOSED_EVENT_TYPES.includes(input.eventType)) {
    throw new EventLogError(`event type is outside the closed vocabulary: ${input.eventType}`);
  }
  if (typeof input.dataText !== "string") {
    throw new EventLogError("event input requires dataText to be a string");
  }
  if (input.purpose !== "zp-node-event-v1" || input.canonicalVersion !== 1) {
    throw new EventLogError("event input purpose/canonical_version must be zp-node-event-v1 / 1");
  }
  if (typeof input.preimageText !== "string" || input.preimageText.length === 0) {
    throw new EventLogError("event input requires preimageText");
  }
  if (typeof input.signingKeyId !== "string" || input.signingKeyId.length === 0) {
    throw new EventLogError("event input requires signingKeyId");
  }
  if (typeof input.signature !== "string" || input.signature.length === 0) {
    throw new EventLogError("event input requires signature");
  }
  if (typeof input.createdAt !== "string" || input.createdAt.length === 0) {
    throw new EventLogError("event input requires createdAt");
  }
}

function buildBatch(
  nodeId: string,
  inputs: readonly EventAppendInput[],
  tail: EventStreamTail,
  eventHashOf: (input: EventAppendInput, seq: bigint, previousEventHash: string | null) => string,
): readonly EventRecord[] {
  const records: EventRecord[] = [];
  let previousEventHash = tail.lastEventHash;
  let seq = tail.highWater;
  for (const input of inputs) {
    assertValidInput(input);
    seq += 1n;
    const eventHash = eventHashOf(input, seq, previousEventHash);
    const record: EventRecord = Object.freeze({
      seq,
      eventId: input.eventId,
      purpose: input.purpose,
      canonicalVersion: input.canonicalVersion,
      nodeId,
      operationId: input.operationId,
      walletId: input.walletId,
      eventType: input.eventType,
      dataText: input.dataText,
      dataSha256: input.dataSha256,
      preimageText: input.preimageText,
      preimageSha256: input.preimageSha256,
      signingKeyId: input.signingKeyId,
      signature: input.signature,
      previousEventHash,
      eventHash,
      createdAt: input.createdAt,
    });
    records.push(record);
    previousEventHash = eventHash;
  }
  return records;
}

export interface EventScanPage {
  readonly events: readonly EventRecord[];
  readonly watermarkSeq: bigint;
  readonly nextAfterSeq: bigint;
}

export interface EventChainVerification {
  readonly ok: boolean;
  readonly eventCount: number;
  readonly firstBadSeq: bigint | null;
  readonly reason: string | null;
}

export interface EventListServiceConfig {
  readonly nodeId: string;
  readonly maxAppendRetries?: number;
  readonly eventHashOf?: (
    input: EventAppendInput,
    seq: bigint,
    previousEventHash: string | null,
  ) => string;
}

const DEFAULT_MAX_APPEND_RETRIES = 128;
const CHAIN_SCAN_CHUNK = 500;

export class EventListService {
  private readonly store: EventListStore;
  private readonly nodeId: string;
  private readonly maxAppendRetries: number;
  private readonly eventHashOf: (
    input: EventAppendInput,
    seq: bigint,
    previousEventHash: string | null,
  ) => string;

  constructor(store: EventListStore, config: EventListServiceConfig) {
    this.store = store;
    this.nodeId = config.nodeId;
    this.maxAppendRetries = config.maxAppendRetries ?? DEFAULT_MAX_APPEND_RETRIES;
    this.eventHashOf =
      config.eventHashOf ?? ((input, _seq, _previousEventHash) => defaultEventHashOf(input));
  }

  append(input: EventAppendInput): Promise<EventRecord> {
    return this.appendBatch([input]).then((records) => {
      const first = records[0];
      if (first === undefined) {
        throw new EventLogError("append produced no record");
      }
      return first;
    });
  }

  async appendBatch(inputs: readonly EventAppendInput[]): Promise<readonly EventRecord[]> {
    if (inputs.length === 0) return [];
    for (let attempt = 0; attempt <= this.maxAppendRetries; attempt += 1) {
      const tail = await this.store.readTail(this.nodeId);
      const batch = buildBatch(this.nodeId, inputs, tail, this.eventHashOf);
      const outcome: AppendEventsOutcome = await this.store.appendBatch(
        this.nodeId,
        batch,
        tail.highWater,
      );
      if (outcome.kind === "APPENDED") {
        return outcome.records;
      }
    }
    throw new EventLogError(
      `event append could not commit after ${this.maxAppendRetries} retries under contention`,
    );
  }

  highWater(): Promise<bigint> {
    return this.store.readTail(this.nodeId).then((tail) => tail.highWater);
  }

  async scanAfter(afterSeq: bigint | null, limit: number): Promise<EventScanPage> {
    if (limit <= 0) {
      throw new EventLogError("scan limit must be positive");
    }
    const [events, tail] = await Promise.all([
      this.store.scanAfter(this.nodeId, afterSeq, limit),
      this.store.readTail(this.nodeId),
    ]);
    const last = events[events.length - 1];
    const nextAfterSeq = last === undefined ? tail.highWater : last.seq;
    return { events, watermarkSeq: tail.highWater, nextAfterSeq };
  }

  find(seq: bigint): Promise<EventRecord | null> {
    return this.store.find(this.nodeId, seq);
  }

  async verifyChain(): Promise<EventChainVerification> {
    let expectedSeq = 1n;
    let previousEventHash: string | null = null;
    let eventCount = 0;
    for (;;) {
      const events = await this.store.scanAfter(
        this.nodeId,
        expectedSeq === 1n ? null : expectedSeq - 1n,
        CHAIN_SCAN_CHUNK,
      );
      if (events.length === 0) break;
      for (const event of events) {
        if (event.seq !== expectedSeq) {
          return {
            ok: false,
            eventCount,
            firstBadSeq: expectedSeq,
            reason: `expected seq ${expectedSeq.toString()} but found ${event.seq.toString()}`,
          };
        }
        if (event.previousEventHash !== previousEventHash) {
          return {
            ok: false,
            eventCount,
            firstBadSeq: event.seq,
            reason: "previous_event_hash chain break",
          };
        }
        if (event.nodeId !== this.nodeId) {
          return {
            ok: false,
            eventCount,
            firstBadSeq: event.seq,
            reason: "cross-node event",
          };
        }
        let recomputed: string;
        try {
          recomputed = computeEventLogNodeEventHash(event.preimageText, event.signature);
        } catch (error) {
          const detail = error instanceof Error ? error.message : "hash recompute failed";
          return {
            ok: false,
            eventCount,
            firstBadSeq: event.seq,
            reason: `event_hash recompute failed: ${detail}`,
          };
        }
        if (recomputed !== event.eventHash) {
          return {
            ok: false,
            eventCount,
            firstBadSeq: event.seq,
            reason: "event_hash does not match SHA256(preimage_bytes || signature_bytes)",
          };
        }
        eventCount += 1;
        previousEventHash = event.eventHash;
        expectedSeq += 1n;
      }
      if (events.length < CHAIN_SCAN_CHUNK) break;
    }
    return { ok: true, eventCount, firstBadSeq: null, reason: null };
  }
}

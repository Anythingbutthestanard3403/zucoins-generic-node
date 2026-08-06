// the RUNTIME adversarial attack suite for the node-global zp-node-event-v1
// hash-chained event stream. It drives the live createNodeEventVerifier pipeline
// (event-verifier.ts) and the InMemoryReportingStore cursor seam (in-memory-store.ts), feeding the
// actual breaking inputs and asserting each attack fails CLOSED — seq reorder/replay is REJECTED,
// a rewound cursor is CURSOR_STALE, a chain break is a HARD_STOP, and an id-stable content mutation
// is a HARD_STOP_CONFLICT (the invariant-breach/alarm outcome). Companion to the request-pipeline
// attacks in reporting-attack-suite.test.ts.
//
// The stream is a signed pull stream: per-node, gapless, pre-signed seq. In
// evaluateChainAppend / evaluateTenantSeq the chain — not seq continuity — is the gap
// detector, so a sparse tenant-filtered seq is legitimate and never a false gap.

import { describe, expect, it } from "vitest";

import {
  buildNodeEventPreimage,
  decodeCanonicalEd25519Signature,
  NODE_EVENT_CANONICAL_VERSION,
  NODE_EVENT_PURPOSE,
  type NodeEventPayload,
} from "@zucoins/generic-node-contracts";

import { computeNodeEventHash, sha256HexUtf8 } from "./ed25519.js";
import { createNodeEventVerifier, type ServedNodeEvent } from "./event-verifier.js";
import { InMemoryReportingStore } from "./in-memory-store.js";
import type { NodeEventCursor, RecordedNodeEvent } from "./store.js";
import { keyFromSeed, NODE_ID, pubOf, signPadded } from "./test-fixtures.js";

const EVENT_PRIV = keyFromSeed(0x07);
const EVENT_KEY_ID = "ffffffff-ffff-4fff-8fff-ffffffffffff";
const CREATED_BASE = Date.parse("2026-07-18T00:00:00.000Z");

type BuiltEvent = ServedNodeEvent & { readonly eventHash: string };

function seededStore(): InMemoryReportingStore {
  const store = new InMemoryReportingStore();
  store.seedEventSigningKey({
    keyId: EVENT_KEY_ID,
    nodeId: NODE_ID,
    publicKeyEncoded: pubOf(EVENT_PRIV),
    purpose: "EVENT_SIGNING",
    activatedAtMs: 0,
    retiredAtMs: null,
  });
  return store;
}

function makeEvent(input: {
  readonly eventId: string;
  readonly seq: bigint;
  readonly previousHash: string | null;
  readonly createdAtMs: number;
  readonly dataText?: string;
}): BuiltEvent {
  const dataText = input.dataText ?? "{}";
  const payload: NodeEventPayload = {
    purpose: NODE_EVENT_PURPOSE,
    canonical_version: NODE_EVENT_CANONICAL_VERSION,
    node_id: NODE_ID,
    event_id: input.eventId,
    seq: input.seq.toString(),
    operation_id: null,
    wallet_id: null,
    event_type: "receive.ready",
    data_sha256: sha256HexUtf8(dataText),
    previous_event_hash: input.previousHash,
    created_at: new Date(input.createdAtMs).toISOString(),
  };
  const preimageText = buildNodeEventPreimage(payload);
  const signatureEncoded = signPadded(preimageText, EVENT_PRIV);
  const eventHash = computeNodeEventHash(
    preimageText,
    decodeCanonicalEd25519Signature(signatureEncoded)!,
  );
  return { keyId: EVENT_KEY_ID, preimageText, signatureEncoded, servedEventHash: eventHash, dataText, eventHash };
}

function makeChain(seqs: readonly bigint[]): BuiltEvent[] {
  const events: BuiltEvent[] = [];
  let previousHash: string | null = null;
  seqs.forEach((seq, index) => {
    const event = makeEvent({
      eventId: `10000000-0000-4000-8000-${(index + 1).toString().padStart(12, "0")}`,
      seq,
      previousHash,
      createdAtMs: CREATED_BASE + index * 1_000,
    });
    events.push(event);
    previousHash = event.eventHash;
  });
  return events;
}

// --------------------------------------------------------------------------
// Attack 2 — seq-cursor replay / rewind: a stale or rewound cursor cannot re-drive
// already-consumed events.
// --------------------------------------------------------------------------

describe("ATTACK 2: seq-cursor replay and rewind", () => {
  it("rejects a fresh event that chains off the head but rewinds seq to an already-consumed value", async () => {
    const store = seededStore();
    const verifier = createNodeEventVerifier({ store });
    const chain = makeChain([1n, 2n, 3n]);
    expect((await verifier.verifyBatch(NODE_ID, chain)).kind).toBe("ACCEPTED");

    // A NEW event id (so the id-dedup path does not fire) that claims to chain off the head yet
    // carries seq 2 (<= cursor seq 3) — the monotonic seq gate must reject it.
    const rewind = makeEvent({
      eventId: "20000000-0000-4000-8000-000000000002",
      seq: 2n,
      previousHash: chain[2]!.eventHash,
      createdAtMs: CREATED_BASE + 4_000,
    });
    const outcome = await verifier.verifyBatch(NODE_ID, [rewind]);
    expect(outcome.kind).toBe("REJECTED");
    if (outcome.kind === "REJECTED") expect(outcome.reason).toBe("seq reorder or replay");

    // The cursor never regressed.
    const cursor = await store.readCursor(NODE_ID);
    expect(cursor.lastSeq).toBe(3n);
    expect(cursor.lastEventHash).toBe(chain[2]!.eventHash);
  });

  it("the store append is guarded by the optimistic cursor: a rewound expectedCursor is CURSOR_STALE", async () => {
    const store = seededStore();
    const verifier = createNodeEventVerifier({ store });
    const chain = makeChain([1n, 2n, 3n]);
    await verifier.verifyBatch(NODE_ID, chain);

    // Replay the already-consumed batch directly at the store with a REWOUND (genesis) expected
    // cursor — exactly the optimistic-concurrency guard the durable adapter provides with row locks.
    const genesis: NodeEventCursor = { nodeId: NODE_ID, lastEventHash: null, lastSeq: 0n, lastEventId: null };
    const recorded: RecordedNodeEvent[] = chain.map((event, index) => ({
      nodeId: NODE_ID,
      eventId: `10000000-0000-4000-8000-${(index + 1).toString().padStart(12, "0")}`,
      eventHash: event.eventHash,
      seq: BigInt(index + 1),
    }));
    const outcome = await store.appendVerifiedEvents(NODE_ID, recorded, genesis);
    expect(outcome.kind).toBe("CURSOR_STALE");
    expect((await store.readCursor(NODE_ID)).lastSeq).toBe(3n);
  });
});

// --------------------------------------------------------------------------
// Attack 2 (gap surface) — the hash chain, not seq continuity, is the gap detector.
// --------------------------------------------------------------------------

describe("ATTACK 2 (gap): sparse seq is legitimate; a broken chain hard-stops", () => {
  it("accepts a legitimately sparse hash-chained seq (1, 5, 9) without a false gap rejection", async () => {
    const store = seededStore();
    const verifier = createNodeEventVerifier({ store });
    const outcome = await verifier.verifyBatch(NODE_ID, makeChain([1n, 5n, 9n]));
    expect(outcome.kind).toBe("ACCEPTED");
    if (outcome.kind === "ACCEPTED") expect(outcome.accepted).toBe(3);
  });

  it("hard-stops a forged previous_event_hash even with a contiguous seq (the chain is the gap detector)", async () => {
    const store = seededStore();
    const verifier = createNodeEventVerifier({ store });
    expect((await verifier.verifyBatch(NODE_ID, makeChain([1n]))).kind).toBe("ACCEPTED");
    const forgedLink = makeEvent({
      eventId: "20000000-0000-4000-8000-000000000010",
      seq: 2n,
      previousHash: "0".repeat(64),
      createdAtMs: CREATED_BASE + 1_000,
    });
    const outcome = await verifier.verifyBatch(NODE_ID, [forgedLink]);
    expect(outcome.kind).toBe("HARD_STOP_CHAIN_BREAK");
    expect((await store.readCursor(NODE_ID)).lastSeq).toBe(1n);
  });
});

// --------------------------------------------------------------------------
// Attack 1 (event side) — duplicate delivery is deduplicated by (event_id, event_hash);
// an id-stable content mutation is an invariant-breach hard-stop (alarm), never a silent accept.
// --------------------------------------------------------------------------

describe("ATTACK 1 (event side): duplicate redelivery vs id-stable content forgery", () => {
  it("deduplicates a full redelivery by id+hash without double-counting or regressing the cursor", async () => {
    const store = seededStore();
    const verifier = createNodeEventVerifier({ store });
    const chain = makeChain([1n, 2n]);
    expect((await verifier.verifyBatch(NODE_ID, chain)).kind).toBe("ACCEPTED");

    const redelivered = await verifier.verifyBatch(NODE_ID, chain);
    expect(redelivered.kind).toBe("DUPLICATES_ONLY");
    if (redelivered.kind === "DUPLICATES_ONLY") expect(redelivered.duplicates).toBe(2);
    expect((await store.readCursor(NODE_ID)).lastSeq).toBe(2n);
  });

  it("hard-stops the same event_id re-served with altered content (event_hash mismatch = invariant breach)", async () => {
    const store = seededStore();
    const verifier = createNodeEventVerifier({ store });
    const [first] = makeChain([1n]);
    await verifier.verifyBatch(NODE_ID, [first!]);
    // Same event_id and seq, but a mutated data body → a different event_hash.
    const altered = makeEvent({
      eventId: "10000000-0000-4000-8000-000000000001",
      seq: 1n,
      previousHash: null,
      createdAtMs: CREATED_BASE,
      dataText: "{\"tampered\":true}",
    });
    const outcome = await verifier.verifyBatch(NODE_ID, [altered]);
    expect(outcome.kind).toBe("HARD_STOP_CONFLICT");
    if (outcome.kind === "HARD_STOP_CONFLICT") {
      expect(outcome.eventId).toBe("10000000-0000-4000-8000-000000000001");
    }
    expect((await store.readCursor(NODE_ID)).lastEventHash).toBe(first!.eventHash);
  });
});

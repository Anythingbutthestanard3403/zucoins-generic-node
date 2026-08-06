// zp-node-event-v1 batch verification tests.
// Case 1 (event side): the A.8 event goldens A (460 bytes, sha256 9644a48d…,
// event_hash 1f0ec14d…) and B (null wallet_id, chained off A, event_hash ff6f8bba…)
// reproduce through the live path with golden signatures verifying through live node:crypto.
// Case 4: a legitimately sparse tenant-filtered seq sequence never
// false-positives as a gap — the hash chain, not seq continuity, is the gap detector.
// Case 5: duplicate redelivery is deduplicated by event id/hash before any
// chain evaluation; the same event id with altered content is a hard-stop conflict; the
// cursor never advances on a stop and never regresses.

import { describe, expect, it } from "vitest";

import {
  buildNodeEventPreimage,
  decodeCanonicalEd25519Signature,
  decodeCanonicalReportingPublicKey,
  NODE_EVENT_A_EVENT_HASH,
  NODE_EVENT_A_SHA256,
  NODE_EVENT_A_SIGNATURE,
  NODE_EVENT_B_EVENT_HASH,
  NODE_EVENT_B_SIGNATURE,
  NODE_EVENT_CANONICAL_VERSION,
  NODE_EVENT_GOLDEN_A_PREIMAGE,
  NODE_EVENT_GOLDEN_B_PREIMAGE,
  NODE_EVENT_KEY_PUBKEY,
  NODE_EVENT_PURPOSE,
  type NodeEventPayload,
} from "@zucoins/generic-node-contracts";

import { computeNodeEventHash, sha256HexUtf8, verifyDetachedEd25519 } from "./ed25519.js";
import { createNodeEventVerifier, type ServedNodeEvent } from "./event-verifier.js";
import { InMemoryReportingStore } from "./in-memory-store.js";
import { keyFromSeed, NODE_ID, pubOf, signPadded } from "./test-fixtures.js";

const EVENT_KEY_ID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const TEST_EVENT_PRIV = keyFromSeed(0x07);
const TEST_EVENT_KEY_ID = "ffffffff-ffff-4fff-8fff-ffffffffffff";
const CREATED_BASE = Date.parse("2026-07-18T00:00:00.000Z");

function seededStore(): InMemoryReportingStore {
  const store = new InMemoryReportingStore();
  store.seedEventSigningKey({
    keyId: EVENT_KEY_ID,
    nodeId: NODE_ID,
    publicKeyEncoded: NODE_EVENT_KEY_PUBKEY,
    purpose: "EVENT_SIGNING",
    activatedAtMs: 0,
    retiredAtMs: null,
  });
  return store;
}

function makeEvent(input: {
  eventId: string;
  seq: bigint;
  previousHash: string | null;
  createdAtMs: number;
  dataText?: string;
}): ServedNodeEvent & { readonly eventHash: string } {
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
  const signatureEncoded = signPadded(preimageText, TEST_EVENT_PRIV);
  const eventHash = computeNodeEventHash(
    preimageText,
    decodeCanonicalEd25519Signature(signatureEncoded)!,
  );
  return { keyId: TEST_EVENT_KEY_ID, preimageText, signatureEncoded, servedEventHash: eventHash, dataText, eventHash };
}

function makeChain(seqs: readonly bigint[]): (ServedNodeEvent & { readonly eventHash: string })[] {
  const events: (ServedNodeEvent & { readonly eventHash: string })[] = [];
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

function seedTestEventKey(store: InMemoryReportingStore, retiredAtMs: number | null = null): void {
  store.seedEventSigningKey({
    keyId: TEST_EVENT_KEY_ID,
    nodeId: NODE_ID,
    publicKeyEncoded: pubOf(TEST_EVENT_PRIV),
    purpose: "EVENT_SIGNING",
    activatedAtMs: 0,
    retiredAtMs,
  });
}

const GOLDEN_BATCH: readonly ServedNodeEvent[] = [
  {
    keyId: EVENT_KEY_ID,
    preimageText: NODE_EVENT_GOLDEN_A_PREIMAGE,
    signatureEncoded: NODE_EVENT_A_SIGNATURE,
    servedEventHash: NODE_EVENT_A_EVENT_HASH,
    dataText: "{}",
  },
  {
    keyId: EVENT_KEY_ID,
    preimageText: NODE_EVENT_GOLDEN_B_PREIMAGE,
    signatureEncoded: NODE_EVENT_B_SIGNATURE,
    servedEventHash: NODE_EVENT_B_EVENT_HASH,
    dataText: "{}",
  },
];

describe("A.8 event goldens through the live path", () => {
  it("verifies goldens A and B, recomputes their event hashes, and advances the cursor to B", async () => {
    const store = seededStore();
    const verifier = createNodeEventVerifier({ store });
    const outcome = await verifier.verifyBatch(NODE_ID, GOLDEN_BATCH);
    expect(outcome.kind).toBe("ACCEPTED");
    if (outcome.kind !== "ACCEPTED") return;
    expect(outcome.accepted).toBe(2);
    expect(outcome.duplicates).toBe(0);
    expect(outcome.cursor.lastEventHash).toBe(NODE_EVENT_B_EVENT_HASH);
    expect(outcome.cursor.lastSeq).toBe(2n);
    const cursor = await store.readCursor(NODE_ID);
    expect(cursor.lastEventHash).toBe(NODE_EVENT_B_EVENT_HASH);
    expect(cursor.lastEventId).toBe("dddddddd-dddd-4ddd-8ddd-dddddddddddd");
  });

  it("recomputes the golden event hashes and verifies the golden signatures via live node:crypto", () => {
    const publicKey = decodeCanonicalReportingPublicKey(NODE_EVENT_KEY_PUBKEY)!;
    const aSig = decodeCanonicalEd25519Signature(NODE_EVENT_A_SIGNATURE)!;
    expect(sha256HexUtf8(NODE_EVENT_GOLDEN_A_PREIMAGE)).toBe(NODE_EVENT_A_SHA256);
    expect(computeNodeEventHash(NODE_EVENT_GOLDEN_A_PREIMAGE, aSig)).toBe(NODE_EVENT_A_EVENT_HASH);
    expect(
      verifyDetachedEd25519({ publicKeyBytes: publicKey, preimageText: NODE_EVENT_GOLDEN_A_PREIMAGE, signatureBytes: aSig }),
    ).toBe(true);
    const bSig = decodeCanonicalEd25519Signature(NODE_EVENT_B_SIGNATURE)!;
    expect(computeNodeEventHash(NODE_EVENT_GOLDEN_B_PREIMAGE, bSig)).toBe(NODE_EVENT_B_EVENT_HASH);
    expect(
      verifyDetachedEd25519({ publicKeyBytes: publicKey, preimageText: NODE_EVENT_GOLDEN_B_PREIMAGE, signatureBytes: bSig }),
    ).toBe(true);
  });
});

describe("sparse seq and hash-chain gap detection (indicator 4)", () => {
  it("accepts a legitimately sparse seq sequence (1, 5, 9) without a false gap", async () => {
    const store = seededStore();
    seedTestEventKey(store);
    const verifier = createNodeEventVerifier({ store });
    const chain = makeChain([1n, 5n, 9n]);
    const outcome = await verifier.verifyBatch(NODE_ID, chain);
    expect(outcome.kind).toBe("ACCEPTED");
    if (outcome.kind !== "ACCEPTED") return;
    expect(outcome.accepted).toBe(3);
    expect(outcome.cursor.lastSeq).toBe(9n);
    expect(outcome.cursor.lastEventHash).toBe(chain[2]!.eventHash);
  });

  it("hard-stops on a wrong previous_event_hash even with a contiguous seq", async () => {
    const store = seededStore();
    seedTestEventKey(store);
    const verifier = createNodeEventVerifier({ store });
    const first = makeChain([1n]);
    expect((await verifier.verifyBatch(NODE_ID, first)).kind).toBe("ACCEPTED");
    const broken = makeEvent({
      eventId: "20000000-0000-4000-8000-000000000002",
      seq: 2n,
      previousHash: "0".repeat(64),
      createdAtMs: CREATED_BASE + 1_000,
    });
    const outcome = await verifier.verifyBatch(NODE_ID, [broken]);
    expect(outcome.kind).toBe("HARD_STOP_CHAIN_BREAK");
    const cursor = await store.readCursor(NODE_ID);
    expect(cursor.lastSeq).toBe(1n);
    expect(cursor.lastEventHash).toBe(first[0]!.eventHash);
  });

  it("rejects a new event at or below the cursor seq as reorder/replay", async () => {
    const store = seededStore();
    seedTestEventKey(store);
    const verifier = createNodeEventVerifier({ store });
    const chain = makeChain([1n, 5n, 9n]);
    await verifier.verifyBatch(NODE_ID, chain);
    const reordered = makeEvent({
      eventId: "20000000-0000-4000-8000-000000000099",
      seq: 5n,
      previousHash: chain[2]!.eventHash,
      createdAtMs: CREATED_BASE + 3_000,
    });
    const outcome = await verifier.verifyBatch(NODE_ID, [reordered]);
    expect(outcome.kind).toBe("REJECTED");
    if (outcome.kind === "REJECTED") expect(outcome.reason).toBe("seq reorder or replay");
  });
});

describe("idempotent redelivery and conflict (indicator 5)", () => {
  it("deduplicates redelivery by event id/hash before chain evaluation; cursor never regresses", async () => {
    const store = seededStore();
    store.seedEventSigningKey({
      keyId: TEST_EVENT_KEY_ID,
      nodeId: NODE_ID,
      publicKeyEncoded: pubOf(TEST_EVENT_PRIV),
      purpose: "EVENT_SIGNING",
      activatedAtMs: 0,
      retiredAtMs: null,
    });
    const verifier = createNodeEventVerifier({ store });
    const [a, b] = makeChain([1n, 2n]);
    expect((await verifier.verifyBatch(NODE_ID, [a!, b!])).kind).toBe("ACCEPTED");

    const redelivered = await verifier.verifyBatch(NODE_ID, [a!, b!]);
    expect(redelivered.kind).toBe("DUPLICATES_ONLY");
    if (redelivered.kind === "DUPLICATES_ONLY") expect(redelivered.duplicates).toBe(2);

    const c = makeEvent({
      eventId: "20000000-0000-4000-8000-000000000003",
      seq: 3n,
      previousHash: b!.eventHash,
      createdAtMs: CREATED_BASE + 2_000,
    });
    const overlap = await verifier.verifyBatch(NODE_ID, [b!, c]);
    expect(overlap.kind).toBe("ACCEPTED");
    if (overlap.kind !== "ACCEPTED") return;
    expect(overlap.accepted).toBe(1);
    expect(overlap.duplicates).toBe(1);
    expect(overlap.cursor.lastEventHash).toBe(c.eventHash);
    expect(overlap.cursor.lastSeq).toBe(3n);

    const cursor = await store.readCursor(NODE_ID);
    expect(cursor.lastEventHash).toBe(c.eventHash);
  });

  it("hard-stops on the same event id with altered content", async () => {
    const store = seededStore();
    seedTestEventKey(store);
    const verifier = createNodeEventVerifier({ store });
    const [a] = makeChain([1n]);
    await verifier.verifyBatch(NODE_ID, [a!]);
    const altered = makeEvent({
      eventId: "10000000-0000-4000-8000-000000000001",
      seq: 1n,
      previousHash: null,
      createdAtMs: CREATED_BASE + 60_000,
      dataText: "{\"tampered\":true}",
    });
    const outcome = await verifier.verifyBatch(NODE_ID, [altered]);
    expect(outcome.kind).toBe("HARD_STOP_CONFLICT");
    const cursor = await store.readCursor(NODE_ID);
    expect(cursor.lastSeq).toBe(1n);
    expect(cursor.lastEventHash).toBe(a!.eventHash);
  });
});

describe("event tamper and key-validity negatives", () => {
  it("rejects a mutated preimage byte (signature no longer verifies)", async () => {
    const store = seededStore();
    const verifier = createNodeEventVerifier({ store });
    const tampered: ServedNodeEvent = {
      ...GOLDEN_BATCH[0]!,
      preimageText: NODE_EVENT_GOLDEN_A_PREIMAGE.replace("receive.ready", "receive.land"),
    };
    const outcome = await verifier.verifyBatch(NODE_ID, [tampered]);
    expect(outcome.kind).toBe("REJECTED");
  });

  it("rejects an event signed by a key different from the claimed directory key", async () => {
    const store = seededStore();
    seedTestEventKey(store);
    const verifier = createNodeEventVerifier({ store });
    const [a] = makeChain([1n]);
    const wrongKeyClaim: ServedNodeEvent = { ...a!, keyId: EVENT_KEY_ID };
    const outcome = await verifier.verifyBatch(NODE_ID, [wrongKeyClaim]);
    expect(outcome.kind).toBe("REJECTED");
    if (outcome.kind === "REJECTED") expect(outcome.reason).toBe("invalid event signature");
  });

  it("rejects an event created after its key retired (historical validity)", async () => {
    const store = seededStore();
    seedTestEventKey(store, CREATED_BASE - 1);
    const verifier = createNodeEventVerifier({ store });
    const [a] = makeChain([1n]);
    const outcome = await verifier.verifyBatch(NODE_ID, [a!]);
    expect(outcome.kind).toBe("REJECTED");
    if (outcome.kind === "REJECTED") {
      expect(outcome.reason).toBe("event created outside the key validity window");
    }
  });

  it("rejects a false served event_hash claim and a false data text without trusting either", async () => {
    const store = seededStore();
    seedTestEventKey(store);
    const verifier = createNodeEventVerifier({ store });
    const [a] = makeChain([1n]);
    const falseHash = await verifier.verifyBatch(NODE_ID, [{ ...a!, servedEventHash: "f".repeat(64) }]);
    expect(falseHash.kind).toBe("REJECTED");
    if (falseHash.kind === "REJECTED") expect(falseHash.reason).toBe("event hash claim mismatch");
    const falseData = await verifier.verifyBatch(NODE_ID, [{ ...a!, dataText: "{\"other\":true}" }]);
    expect(falseData.kind).toBe("REJECTED");
    if (falseData.kind === "REJECTED") expect(falseData.reason).toBe("event data digest mismatch");
    expect((await store.readCursor(NODE_ID)).lastSeq).toBe(0n);
  });
});

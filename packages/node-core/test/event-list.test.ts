// EventListService unit tests.
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  EVENT_HASH_RULE,
  NODE_EVENT_A_EVENT_HASH,
  NODE_EVENT_A_SIGNATURE,
  NODE_EVENT_B_EVENT_HASH,
  NODE_EVENT_B_SIGNATURE,
  NODE_EVENT_GOLDEN_A_PREIMAGE,
  NODE_EVENT_GOLDEN_B_PREIMAGE,
} from "@zucoins/generic-node-contracts";

import {
  computeEventLogNodeEventHash,
  EventListService,
  InMemoryEventStore,
  type EventAppendInput,
  type EventRecord,
} from "../src/event-log/index.ts";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const KEY_ID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
// 64 zero bytes → padded base64url (86 body + ==). Syntactically valid Ed25519 wire form.
const TEST_SIGNATURE = `${"A".repeat(86)}==`;

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function input(overrides: Partial<EventAppendInput> = {}): EventAppendInput {
  const dataText = overrides.dataText ?? '{"receiver_pubkey":"x","amount_zkz":"1"}';
  const dataSha256 = overrides.dataSha256 ?? sha256Hex(dataText);
  const eventId = overrides.eventId ?? randomUUID();
  const preimageText =
    overrides.preimageText ??
    `zp-node-event-v1\n{"purpose":"zp-node-event-v1","event_id":"${eventId}"}`;
  return {
    eventId,
    operationId: overrides.operationId ?? null,
    walletId: overrides.walletId ?? null,
    eventType: overrides.eventType ?? "receive.ready",
    dataText,
    dataSha256,
    purpose: "zp-node-event-v1",
    canonicalVersion: 1,
    preimageText,
    preimageSha256: overrides.preimageSha256 ?? sha256Hex(preimageText),
    signingKeyId: overrides.signingKeyId ?? KEY_ID,
    signature: overrides.signature ?? TEST_SIGNATURE,
    createdAt: overrides.createdAt ?? "2026-07-18T00:00:00.000Z",
  };
}

function service(store = new InMemoryEventStore()): EventListService {
  return new EventListService(store, { nodeId: NODE_ID });
}

describe("EventListService — sequencing", () => {
  it("allocates gapless monotonic seq starting at 1", async () => {
    const svc = service();
    const a = await svc.append(input());
    const b = await svc.append(input());
    expect(a.seq).toBe(1n);
    expect(b.seq).toBe(2n);
    expect(b.previousEventHash).toBe(a.eventHash);
    expect(await svc.highWater()).toBe(2n);
  });

  it("appends a batch atomically on contiguous seqs", async () => {
    const svc = service();
    const records = await svc.appendBatch([input(), input(), input()]);
    expect(records.map((r) => r.seq)).toEqual([1n, 2n, 3n]);
    expect(records[2]!.previousEventHash).toBe(records[1]!.eventHash);
  });

  it("rejects closed-vocabulary violations without burning a seq", async () => {
    const store = new InMemoryEventStore();
    const svc = service(store);
    await svc.append(input());
    await expect(
      svc.append(input({ eventType: "payment.succeeded" as never })),
    ).rejects.toThrow(/closed vocabulary/);
    expect(await svc.highWater()).toBe(1n);
  });

  it("rejects duplicate event_id without advancing high-water past the conflict", async () => {
    const store = new InMemoryEventStore();
    const svc = service(store);
    const id = randomUUID();
    await svc.append(input({ eventId: id }));
    await expect(svc.append(input({ eventId: id }))).rejects.toThrow(/duplicate/);
    expect(await svc.highWater()).toBe(1n);
  });
});

describe("EventListService — CURSOR_CONTRACT exclusive scan", () => {
  it("scanAfter is exclusive and returns watermark_seq + next_after_seq", async () => {
    const svc = service();
    await svc.appendBatch([input(), input(), input(), input(), input()]);

    const first = await svc.scanAfter(null, 2);
    expect(first.events.map((e) => e.seq)).toEqual([1n, 2n]);
    expect(first.watermarkSeq).toBe(5n);
    expect(first.nextAfterSeq).toBe(2n);

    const next = await svc.scanAfter(2n, 2);
    expect(next.events.map((e) => e.seq)).toEqual([3n, 4n]);
    expect(next.nextAfterSeq).toBe(4n);

    const caughtUp = await svc.scanAfter(5n, 10);
    expect(caughtUp.events).toEqual([]);
    expect(caughtUp.watermarkSeq).toBe(5n);
    expect(caughtUp.nextAfterSeq).toBe(5n);
  });

  it("field names on EventScanPage match CURSOR_CONTRACT response semantics", async () => {
    const { CURSOR_CONTRACT } = await import(
      "../../generic-node-contracts/src/event-sequencing/cursor.ts"
    );
    expect(CURSOR_CONTRACT.requestCursorExclusive).toBe(true);
    expect(CURSOR_CONTRACT.responseWatermarkField).toBe("watermark_seq");
    expect(CURSOR_CONTRACT.responseNextCursorField).toBe("next_after_seq");

    const svc = service();
    await svc.append(input());
    const page = await svc.scanAfter(null, 10);
    expect(Object.keys(page).sort()).toEqual(["events", "nextAfterSeq", "watermarkSeq"].sort());
    expect(page.watermarkSeq).toBe(1n);
    expect(page.nextAfterSeq).toBe(1n);
  });
});

describe("EventListService — EVENT_HASH_RULE default", () => {
  it("default eventHashOf matches golden A/B EVENT_HASH_RULE pins", () => {
    expect(EVENT_HASH_RULE).toBe("SHA256(preimage_bytes || signature_bytes)");
    expect(computeEventLogNodeEventHash(NODE_EVENT_GOLDEN_A_PREIMAGE, NODE_EVENT_A_SIGNATURE)).toBe(
      NODE_EVENT_A_EVENT_HASH,
    );
    expect(computeEventLogNodeEventHash(NODE_EVENT_GOLDEN_B_PREIMAGE, NODE_EVENT_B_SIGNATURE)).toBe(
      NODE_EVENT_B_EVENT_HASH,
    );
  });

  it("default append stores EVENT_HASH_RULE hashes (red if default reverts to invented chain hash)", async () => {
    const svc = service();
    const record = await svc.append(
      input({
        preimageText: NODE_EVENT_GOLDEN_A_PREIMAGE,
        preimageSha256: sha256Hex(NODE_EVENT_GOLDEN_A_PREIMAGE),
        signature: NODE_EVENT_A_SIGNATURE,
      }),
    );
    expect(record.eventHash).toBe(NODE_EVENT_A_EVENT_HASH);
    // Negate: inventing a non-canonical hash must not equal the frozen pin.
    const invented = createHash("sha256")
      .update(`zp-node-event-chain-v1\n1\n${record.eventId}\n${NODE_ID}\n${record.dataSha256}\n`, "utf8")
      .digest("hex");
    expect(record.eventHash).not.toBe(invented);
  });
});

describe("EventListService — chain verification", () => {
  it("verifyChain accepts a contiguous hash-linked stream", async () => {
    const svc = service();
    await svc.appendBatch([input(), input(), input()]);
    const result = await svc.verifyChain();
    expect(result).toEqual({ ok: true, eventCount: 3, firstBadSeq: null, reason: null });
  });

  it("verifyChain accepts empty stream", async () => {
    const empty = new EventListService(new InMemoryEventStore(), { nodeId: NODE_ID });
    expect(await empty.verifyChain()).toMatchObject({ ok: true, eventCount: 0 });
  });

  it("verifyChain fails when stored event_hash diverges from preimage‖signature recompute", async () => {
    const store = new InMemoryEventStore();
    const svc = service(store);
    const good = await svc.append(input());

    // Tamper durable event_hash while leaving linkage fields alone — linkage-only
    // verify would still pass; EVENT_HASH_RULE recompute must catch it.
    const streams = (store as unknown as { streams: Map<string, { events: EventRecord[]; bySeq: Map<string, EventRecord> }> })
      .streams;
    const stream = streams.get(NODE_ID)!;
    const tampered: EventRecord = Object.freeze({
      ...good,
      eventHash: "0".repeat(64),
    });
    stream.events[0] = tampered;
    stream.bySeq.set("1", tampered);

    const result = await svc.verifyChain();
    expect(result.ok).toBe(false);
    expect(result.firstBadSeq).toBe(1n);
    expect(result.reason).toMatch(/event_hash does not match/);
  });
});

describe("EventListService — concurrency gaplessness", () => {
  it("concurrent appends produce a contiguous 1..N sequence", async () => {
    const store = new InMemoryEventStore();
    const svc = service(store);
    const results = await Promise.all(Array.from({ length: 20 }, () => svc.append(input())));
    const seqs = results.map((r) => r.seq).sort((a, b) => (a < b ? -1 : 1));
    expect(seqs).toEqual(Array.from({ length: 20 }, (_, i) => BigInt(i + 1)));
    expect(await svc.verifyChain()).toMatchObject({ ok: true, eventCount: 20 });
  });
});

describe("EventListService — DDL column coverage", () => {
  it("persisted records carry every data-model envelope column", async () => {
    const svc = service();
    const record = await svc.append(input({ operationId: randomUUID(), walletId: randomUUID() }));
    expect(record.purpose).toBe("zp-node-event-v1");
    expect(record.canonicalVersion).toBe(1);
    expect(record.preimageText.length).toBeGreaterThan(0);
    expect(record.preimageSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(record.signingKeyId).toBe(KEY_ID);
    expect(record.signature.length).toBe(88);
    expect(record.eventHash).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("EventListService — source guards", () => {
  it("scan surface is exclusive after_seq (no inclusive fromSeq API)", () => {
    const source = readFileSync(
      fileURLToPath(new URL("../src/event-log/event-list.ts", import.meta.url)),
      "utf8",
    );
    expect(source).toContain("scanAfter");
    expect(source).not.toMatch(/seq\s*>=\s*fromSeq/);
    expect(source).toContain("watermarkSeq");
    expect(source).toContain("nextAfterSeq");
  });
});

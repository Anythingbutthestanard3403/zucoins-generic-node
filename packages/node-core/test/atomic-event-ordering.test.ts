import { describe, expect, it } from "vitest";

import { InMemoryReportingStore } from "../src/reporting/in-memory-store.js";
import type { NodeEventCursor, RecordedNodeEvent } from "../src/reporting/store.js";

const NODE_ID = "atomic-ordering-node";

function makeEvent(nodeId: string, seq: bigint, id: string): RecordedNodeEvent {
  return { nodeId, eventId: id, eventHash: `hash-${id}`, seq };
}

function freshStore(): InMemoryReportingStore {
  return new InMemoryReportingStore();
}

function emptyCursor(nodeId: string): NodeEventCursor {
  return { nodeId, lastEventHash: null, lastSeq: 0n, lastEventId: null };
}

describe("atomic event ordering", () => {
  describe("monotonic sequence numbers", () => {
    it("appends events with strictly increasing seq", async () => {
      const store = freshStore();
      const events: RecordedNodeEvent[] = [];
      let cursor = emptyCursor(NODE_ID);

      for (let i = 1; i <= 100; i++) {
        const seq = BigInt(i);
        const event = makeEvent(NODE_ID, seq, `evt-${i}`);
        const result = await store.appendVerifiedEvents(NODE_ID, [event], cursor);
        expect(result.kind).toBe("APPENDED");
        events.push(event);
        cursor = await store.readCursor(NODE_ID);
      }

      const finalCursor = await store.readCursor(NODE_ID);
      expect(finalCursor.lastSeq).toBe(100n);

      for (let i = 1; i <= 100; i++) {
        const recorded = await store.findRecordedEvent(NODE_ID, `evt-${i}`);
        expect(recorded).not.toBeNull();
        expect(recorded!.seq).toBe(BigInt(i));
      }
    });

    it("batch append preserves seq ordering within the batch", async () => {
      const store = freshStore();
      const batch: RecordedNodeEvent[] = [];
      for (let i = 1; i <= 50; i++) {
        batch.push(makeEvent(NODE_ID, BigInt(i), `batch-${i}`));
      }

      const result = await store.appendVerifiedEvents(NODE_ID, batch, emptyCursor(NODE_ID));
      expect(result.kind).toBe("APPENDED");

      const cursor = await store.readCursor(NODE_ID);
      expect(cursor.lastSeq).toBe(50n);
      expect(cursor.lastEventId).toBe("batch-50");
      expect(cursor.lastEventHash).toBe("hash-batch-50");
    });
  });

  describe("no gaps under concurrent appends", () => {
    it("sequential cursor-chained appends produce a gapless sequence", async () => {
      const store = freshStore();
      const totalEvents = 200;
      let cursor = emptyCursor(NODE_ID);

      for (let i = 1; i <= totalEvents; i++) {
        const event = makeEvent(NODE_ID, BigInt(i), `gap-${i}`);
        const result = await store.appendVerifiedEvents(NODE_ID, [event], cursor);
        expect(result.kind).toBe("APPENDED");
        cursor = await store.readCursor(NODE_ID);
      }

      for (let i = 1; i <= totalEvents; i++) {
        const recorded = await store.findRecordedEvent(NODE_ID, `gap-${i}`);
        expect(recorded).not.toBeNull();
        expect(recorded!.seq).toBe(BigInt(i));
      }

      const finalCursor = await store.readCursor(NODE_ID);
      expect(finalCursor.lastSeq).toBe(BigInt(totalEvents));
    });

    it("concurrent appends with stale cursors are rejected, preserving gap-freedom", async () => {
      const store = freshStore();
      const initialCursor = emptyCursor(NODE_ID);

      const event1 = makeEvent(NODE_ID, 1n, "race-1");
      const result1 = await store.appendVerifiedEvents(NODE_ID, [event1], initialCursor);
      expect(result1.kind).toBe("APPENDED");

      const staleCursor = initialCursor;
      const event2 = makeEvent(NODE_ID, 2n, "race-2");
      const result2 = await store.appendVerifiedEvents(NODE_ID, [event2], staleCursor);
      expect(result2.kind).toBe("CURSOR_STALE");

      const currentCursor = await store.readCursor(NODE_ID);
      const event3 = makeEvent(NODE_ID, 2n, "race-3");
      const result3 = await store.appendVerifiedEvents(NODE_ID, [event3], currentCursor);
      expect(result3.kind).toBe("APPENDED");

      const finalCursor = await store.readCursor(NODE_ID);
      expect(finalCursor.lastSeq).toBe(2n);
      expect(finalCursor.lastEventId).toBe("race-3");
    });

    it("Promise.all with independent stores produces gapless per-store sequences", async () => {
      const storeCount = 10;
      const eventsPerStore = 50;

      const results = await Promise.all(
        Array.from({ length: storeCount }, async (_, storeIdx) => {
          const store = freshStore();
          const nodeId = `node-${storeIdx}`;
          let cursor = emptyCursor(nodeId);

          for (let i = 1; i <= eventsPerStore; i++) {
            const event = makeEvent(nodeId, BigInt(i), `s${storeIdx}-e${i}`);
            const result = await store.appendVerifiedEvents(nodeId, [event], cursor);
            expect(result.kind).toBe("APPENDED");
            cursor = await store.readCursor(nodeId);
          }

          const finalCursor = await store.readCursor(nodeId);
          return { nodeId, lastSeq: finalCursor.lastSeq, store };
        }),
      );

      for (const { nodeId, lastSeq, store } of results) {
        expect(lastSeq).toBe(BigInt(eventsPerStore));
        for (let i = 1; i <= eventsPerStore; i++) {
          const recorded = await store.findRecordedEvent(
            nodeId,
            `${nodeId.replace("node-", "s")}-e${i}`,
          );
          expect(recorded).not.toBeNull();
          expect(recorded!.seq).toBe(BigInt(i));
        }
      }
    });
  });

  describe("deterministic ordering", () => {
    it("same inputs produce identical cursor state across independent runs", async () => {
      const eventCount = 75;

      async function runSequence(): Promise<NodeEventCursor> {
        const store = freshStore();
        let cursor = emptyCursor(NODE_ID);
        for (let i = 1; i <= eventCount; i++) {
          const event = makeEvent(NODE_ID, BigInt(i), `det-${i}`);
          await store.appendVerifiedEvents(NODE_ID, [event], cursor);
          cursor = await store.readCursor(NODE_ID);
        }
        return cursor;
      }

      const [cursor1, cursor2, cursor3] = await Promise.all([
        runSequence(),
        runSequence(),
        runSequence(),
      ]);

      expect(cursor1.lastSeq).toBe(cursor2.lastSeq);
      expect(cursor2.lastSeq).toBe(cursor3.lastSeq);
      expect(cursor1.lastEventId).toBe(cursor2.lastEventId);
      expect(cursor2.lastEventId).toBe(cursor3.lastEventId);
      expect(cursor1.lastEventHash).toBe(cursor2.lastEventHash);
      expect(cursor2.lastEventHash).toBe(cursor3.lastEventHash);
    });

    it("batch ordering is deterministic regardless of external scheduling", async () => {
      async function runBatch(): Promise<{
        cursor: NodeEventCursor;
        events: RecordedNodeEvent[];
      }> {
        const store = freshStore();
        const batch: RecordedNodeEvent[] = [];
        for (let i = 1; i <= 30; i++) {
          batch.push(makeEvent(NODE_ID, BigInt(i), `ord-${i}`));
        }
        await store.appendVerifiedEvents(NODE_ID, batch, emptyCursor(NODE_ID));
        const cursor = await store.readCursor(NODE_ID);
        return { cursor, events: batch };
      }

      const [run1, run2] = await Promise.all([runBatch(), runBatch()]);

      expect(run1.cursor.lastSeq).toBe(run2.cursor.lastSeq);
      expect(run1.cursor.lastEventId).toBe(run2.cursor.lastEventId);
      expect(run1.events.map((e) => e.seq)).toEqual(run2.events.map((e) => e.seq));
    });
  });

  describe("atomic counter increment", () => {
    it("burn counter produces gapless monotonic sequence under concurrent burns", async () => {
      const store = freshStore();
      store.seedRestoreHold(NODE_ID, false);
      store.seedLifecycleHead(NODE_ID, "impl-1", {
        epoch: 1n,
        authHold: false,
        currentKeyId: "key-1",
        priorKeyId: null,
        overlapExpiresAtMs: null,
        successorCommittedAtMs: null,
      });
      store.seedReportingKeyState(NODE_ID, "impl-1", "key-1", {
        state: "ACTIVE",
        revokedAtMs: null,
      });

      const burnCount = 100;
      const results = await Promise.all(
        Array.from({ length: burnCount }, (_, i) =>
          store.burnNonceAtomically({
            expectedEpoch: 1n,
            evidence: {
              nodeId: NODE_ID,
              implementerId: "impl-1",
              reportingKeyId: "key-1",
              nonce: `nonce-${i}`,
              receivedAtMs: Date.now(),
            },
          }),
        ),
      );

      const burned = results.filter((r) => r.kind === "BURNED");
      expect(burned.length).toBe(burnCount);

      const sequences = burned
        .map((r) => (r.kind === "BURNED" ? r.evidence.nonceBurnSequence : -1n))
        .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

      for (let i = 0; i < sequences.length; i++) {
        expect(sequences[i]).toBe(BigInt(i + 1));
      }
    });

    it("no lost updates: all concurrent burns are accounted for", async () => {
      const store = freshStore();
      store.seedRestoreHold(NODE_ID, false);
      store.seedLifecycleHead(NODE_ID, "impl-1", {
        epoch: 1n,
        authHold: false,
        currentKeyId: "key-1",
        priorKeyId: null,
        overlapExpiresAtMs: null,
        successorCommittedAtMs: null,
      });
      store.seedReportingKeyState(NODE_ID, "impl-1", "key-1", {
        state: "ACTIVE",
        revokedAtMs: null,
      });

      const burnCount = 250;
      const results = await Promise.all(
        Array.from({ length: burnCount }, (_, i) =>
          store.burnNonceAtomically({
            expectedEpoch: 1n,
            evidence: {
              nodeId: NODE_ID,
              implementerId: "impl-1",
              reportingKeyId: "key-1",
              nonce: `lost-${i}`,
              receivedAtMs: Date.now(),
            },
          }),
        ),
      );

      const burned = results.filter((r) => r.kind === "BURNED");
      expect(burned.length).toBe(burnCount);

      const seqSet = new Set(
        burned.map((r) => (r.kind === "BURNED" ? r.evidence.nonceBurnSequence : -1n)),
      );
      expect(seqSet.size).toBe(burnCount);

      const maxSeq = Math.max(
        ...burned.map((r) => (r.kind === "BURNED" ? Number(r.evidence.nonceBurnSequence) : 0)),
      );
      expect(maxSeq).toBe(burnCount);
    });

    it("duplicate nonces are rejected as replays under concurrency", async () => {
      const store = freshStore();
      store.seedRestoreHold(NODE_ID, false);
      store.seedLifecycleHead(NODE_ID, "impl-1", {
        epoch: 1n,
        authHold: false,
        currentKeyId: "key-1",
        priorKeyId: null,
        overlapExpiresAtMs: null,
        successorCommittedAtMs: null,
      });
      store.seedReportingKeyState(NODE_ID, "impl-1", "key-1", {
        state: "ACTIVE",
        revokedAtMs: null,
      });

      const duplicateCount = 50;
      const results = await Promise.all(
        Array.from({ length: duplicateCount }, () =>
          store.burnNonceAtomically({
            expectedEpoch: 1n,
            evidence: {
              nodeId: NODE_ID,
              implementerId: "impl-1",
              reportingKeyId: "key-1",
              nonce: "same-nonce",
              receivedAtMs: Date.now(),
            },
          }),
        ),
      );

      const burned = results.filter((r) => r.kind === "BURNED");
      const replayed = results.filter((r) => r.kind === "REPLAY");
      expect(burned.length).toBe(1);
      expect(replayed.length).toBe(duplicateCount - 1);
    });
  });
});

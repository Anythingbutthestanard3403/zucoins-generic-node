// Snapshot service.
import { describe, expect, it } from "vitest";

import { InMemoryImplementerEventLog } from "../src/reporting/implementer-event-log.ts";
import {
  createSnapshotService,
  deriveActiveCounts,
  InMemorySnapshotStateReader,
  InMemorySnapshotStore,
  renderSnapshotBody,
  SnapshotCaptureTimeoutError,
  type SnapshotOperation,
  type SnapshotStateReader,
} from "../src/reporting/snapshot-service.ts";
import { listEvents } from "../src/reporting/events-read-service.ts";
import { IMPLEMENTER_ID } from "../src/reporting/test-fixtures.ts";

const ops: readonly SnapshotOperation[] = [
  {
    operationId: "33333333-3333-4333-8333-333333333333",
    operationType: "RECEIVE_EXTERNAL",
    state: "READY",
    amountZkz: "1.5",
    rowVersion: 2,
    attentionRequired: false,
    attentionReason: null,
    createdAt: "2026-07-18T00:00:00.000Z",
    updatedAt: "2026-07-18T00:00:00.000Z",
    terminalAt: null,
    verificationMaterialAvailableUntil: null,
  },
  {
    operationId: "44444444-4444-4444-8444-444444444444",
    operationType: "SEND_EXTERNAL",
    state: "NEEDS_ATTENTION",
    amountZkz: "2",
    rowVersion: 1,
    attentionRequired: true,
    attentionReason: "manual_review",
    createdAt: "2026-07-18T00:00:01.000Z",
    updatedAt: "2026-07-18T00:00:01.000Z",
    terminalAt: null,
    verificationMaterialAvailableUntil: null,
  },
];

describe("snapshot service", () => {
  it("derives per-state active counts", () => {
    expect(deriveActiveCounts(ops)).toEqual({ READY: 1, NEEDS_ATTENTION: 1 });
  });

  it("captures watermark then state at that watermark", async () => {
    const log = new InMemoryImplementerEventLog();
    await log.append({
      implementerId: IMPLEMENTER_ID,
      eventId: "e1",
      eventType: "receive.ready",
      proofRepresentation: '{"implementer_seq":"1"}',
      createdAt: "2026-07-18T00:00:00.000Z",
    });
    await log.append({
      implementerId: IMPLEMENTER_ID,
      eventId: "e2",
      eventType: "receive.landed",
      proofRepresentation: '{"implementer_seq":"2"}',
      createdAt: "2026-07-18T00:00:01.000Z",
    });

    const reader = new InMemorySnapshotStateReader();
    reader.seed(IMPLEMENTER_ID, {
      operations: ops,
      destinations: [{ destinationId: "d1", state: "BLESSED", moveEligible: true }],
      attentionItems: [
        {
          operationId: "44444444-4444-4444-8444-444444444444",
          attentionReason: "manual_review",
          attentionEpisode: 1,
        },
      ],
    });
    const store = new InMemorySnapshotStore();
    const service = createSnapshotService({
      log,
      reader,
      store,
      nowMs: () => Date.parse("2026-07-18T12:00:00.000Z"),
    });

    const snapshot = await service.capture(IMPLEMENTER_ID);
    expect(snapshot.implementerWatermarkSeq).toBe("2");
    expect(snapshot.operations).toHaveLength(2);
    expect(snapshot.destinations).toEqual([{ destinationId: "d1", state: "BLESSED", moveEligible: true }]);
    expect(await service.latest(IMPLEMENTER_ID)).toEqual(snapshot);
  });

  it("snapshot-then-cursor: events after watermark have no gap/duplicate vs snapshot", async () => {
    const log = new InMemoryImplementerEventLog();
    for (let i = 1; i <= 3; i += 1) {
      await log.append({
        implementerId: IMPLEMENTER_ID,
        eventId: `e${i}`,
        eventType: "receive.ready",
        proofRepresentation: `{"implementer_seq":"${i}"}`,
        createdAt: "2026-07-18T00:00:00.000Z",
      });
    }
    const reader = new InMemorySnapshotStateReader();
    reader.seed(IMPLEMENTER_ID, { operations: ops, destinations: [], attentionItems: [] });
    const service = createSnapshotService({
      log,
      reader,
      store: new InMemorySnapshotStore(),
      nowMs: () => 0,
    });
    const snapshot = await service.capture(IMPLEMENTER_ID);
    const watermark = BigInt(snapshot.implementerWatermarkSeq);

    // Append post-snapshot events.
    await log.append({
      implementerId: IMPLEMENTER_ID,
      eventId: "e4",
      eventType: "operation.needs_attention",
      proofRepresentation: '{"implementer_seq":"4"}',
      createdAt: "2026-07-18T00:00:04.000Z",
    });

    const after = await listEvents(log, {
      implementerId: IMPLEMENTER_ID,
      afterImplementerSeq: watermark,
      limit: 100,
    });
    // No event at-or-before watermark appears after the exclusive cursor.
    expect(after.events.every((e) => e.implementerSeq > watermark)).toBe(true);
    expect(after.events.map((e) => e.implementerSeq)).toEqual([4n]);
    // Snapshot contents (operations) are independent of post-watermark events.
    expect(snapshot.operations).toEqual(ops);
  });

  it("renderSnapshotBody exposes implementer_watermark_seq as decimal string", async () => {
    const body = renderSnapshotBody({
      implementerId: IMPLEMENTER_ID,
      implementerWatermarkSeq: "1043",
      operations: [],
      destinations: [],
      attentionItems: [],
      capturedAt: "2026-07-18T00:00:00.000Z",
    });
    const parsed = JSON.parse(body) as { implementer_watermark_seq: string };
    expect(parsed.implementer_watermark_seq).toBe("1043");
    expect(body).not.toContain("private_key");
    expect(body).not.toContain("transfer_code");
  });

  it("renderSnapshotBody emits §3 operation shape and move_eligible (ZTR-1170)", () => {
    const body = renderSnapshotBody({
      implementerId: IMPLEMENTER_ID,
      implementerWatermarkSeq: "7",
      operations: ops,
      destinations: [{ destinationId: "d1", state: "BLESSED", moveEligible: true }],
      attentionItems: [],
      capturedAt: "2026-07-18T00:00:00.000Z",
    });
    const parsed = JSON.parse(body) as {
      operations: Array<Record<string, unknown>>;
      destinations: Array<Record<string, unknown>>;
    };
    expect(parsed.operations[0]).toEqual({
      operation_id: ops[0]!.operationId,
      operation_type: "RECEIVE_EXTERNAL",
      state: "READY",
      amount_zkz: "1.5",
      row_version: 2,
      attention_required: false,
      attention_reason: null,
      created_at: "2026-07-18T00:00:00.000Z",
      updated_at: "2026-07-18T00:00:00.000Z",
      terminal_at: null,
      verification_material_available_until: null,
    });
    expect(parsed.destinations).toEqual([
      { destination_id: "d1", state: "BLESSED", move_eligible: true },
    ]);
  });

  it("captureTimeoutMs rejects with SnapshotCaptureTimeoutError and leaves store empty", async () => {
    const log = new InMemoryImplementerEventLog();
    await log.append({
      implementerId: IMPLEMENTER_ID,
      eventId: "e-timeout",
      eventType: "receive.ready",
      proofRepresentation: '{"implementer_seq":"1"}',
      createdAt: "2026-07-18T00:00:00.000Z",
    });
    const hanging: SnapshotStateReader = {
      readState: () => new Promise(() => {}),
    };
    const store = new InMemorySnapshotStore();
    const service = createSnapshotService({
      log,
      reader: hanging,
      store,
      captureTimeoutMs: 30,
      nowMs: () => Date.parse("2026-07-18T12:00:00.000Z"),
    });
    await expect(service.capture(IMPLEMENTER_ID)).rejects.toBeInstanceOf(
      SnapshotCaptureTimeoutError,
    );
    expect(await store.latest(IMPLEMENTER_ID)).toBeNull();
  });
});

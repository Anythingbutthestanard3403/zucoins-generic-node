// GET /v1/state/snapshot transport edge.
import { describe, expect, it } from "vitest";

import {
  DEFAULT_STATE_SNAPSHOT_CAPTURE_TIMEOUT_MS,
  handleGetStateSnapshot,
} from "../src/api/state-snapshot.ts";
import { InMemoryImplementerEventLog } from "../src/reporting/implementer-event-log.ts";
import {
  InMemorySnapshotStateReader,
  InMemorySnapshotStore,
} from "../src/reporting/snapshot-service.ts";
import { IMPLEMENTER_ID } from "../src/reporting/test-fixtures.ts";

describe("handleGetStateSnapshot", () => {
  it("returns 200 with implementer_watermark_seq and tenant projections", async () => {
    const log = new InMemoryImplementerEventLog();
    await log.append({
      implementerId: IMPLEMENTER_ID,
      eventId: "e1",
      eventType: "receive.ready",
      proofRepresentation: '{"implementer_seq":"1"}',
      createdAt: "2026-07-18T00:00:00.000Z",
    });
    const reader = new InMemorySnapshotStateReader();
    reader.seed(IMPLEMENTER_ID, {
      operations: [
        {
          operationId: "33333333-3333-4333-8333-333333333333",
          operationType: "RECEIVE_EXTERNAL",
          state: "READY",
          rowVersion: 1,
          attentionRequired: false,
          updatedAt: "2026-07-18T00:00:00.000Z",
        },
      ],
      destinations: [{ destinationId: "d1", state: "BLESSED" }],
      attentionItems: [],
    });
    const response = await handleGetStateSnapshot(
      {
        log,
        reader,
        store: new InMemorySnapshotStore(),
        nowMs: () => Date.parse("2026-07-18T12:00:00.000Z"),
        newRequestId: () => "req-1",
      },
      IMPLEMENTER_ID,
      "req-1",
    );
    expect(response.status).toBe(200);
    if (response.status !== 200) return;
    const body = JSON.parse(response.body) as {
      implementer_watermark_seq: string;
      operations: unknown[];
      destinations: unknown[];
      active_counts: Record<string, number>;
    };
    expect(body.implementer_watermark_seq).toBe("1");
    expect(body.operations).toHaveLength(1);
    expect(body.destinations).toEqual([{ destination_id: "d1", state: "BLESSED" }]);
    expect(body.active_counts).toEqual({ READY: 1 });
    expect(response.body).not.toContain("private_key");
    expect(response.body).not.toContain("transfer_code");
  });

  it("applies DEFAULT_STATE_SNAPSHOT_CAPTURE_TIMEOUT_MS and returns 503 on hang", async () => {
    expect(DEFAULT_STATE_SNAPSHOT_CAPTURE_TIMEOUT_MS).toBeGreaterThan(0);
    const log = new InMemoryImplementerEventLog();
    await log.append({
      implementerId: IMPLEMENTER_ID,
      eventId: "e-hang",
      eventType: "receive.ready",
      proofRepresentation: "{}",
      createdAt: "2026-07-18T00:00:00.000Z",
    });
    const hanging = {
      readState: () => new Promise(() => {}),
    };
    const response = await handleGetStateSnapshot(
      {
        log,
        reader: hanging as never,
        store: new InMemorySnapshotStore(),
        nowMs: () => Date.parse("2026-07-18T12:00:00.000Z"),
        newRequestId: () => "req-hang",
        captureTimeoutMs: 25,
      },
      IMPLEMENTER_ID,
      "req-hang",
    );
    expect(response.status).toBe(503);
  });

});

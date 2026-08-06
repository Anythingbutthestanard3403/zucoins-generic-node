// InMemoryImplementerEventLog gapless cursor + ImplementerEventReadStore parity.
import { describe, expect, it } from "vitest";

import {
  InMemoryImplementerEventLog,
  ImplementerEventLogError,
  isImplementerStreamEventType,
} from "../src/reporting/implementer-event-log.ts";
import { listEvents, frameImplementerEventStream } from "../src/reporting/events-read-service.ts";
import { IMPLEMENTER_ID } from "../src/reporting/test-fixtures.ts";

const proof = (seq: bigint): string =>
  `{"purpose":"zp-implementer-event-v1","implementer_seq":"${seq}"}`;

describe("InMemoryImplementerEventLog", () => {
  it("assigns gapless implementer_seq starting at 1", async () => {
    const log = new InMemoryImplementerEventLog();
    const a = await log.append({
      implementerId: IMPLEMENTER_ID,
      eventId: "e1",
      eventType: "receive.ready",
      proofRepresentation: proof(1n),
      createdAt: "2026-07-18T00:00:00.000Z",
    });
    const b = await log.append({
      implementerId: IMPLEMENTER_ID,
      eventId: "e2",
      eventType: "receive.landed",
      proofRepresentation: proof(2n),
      createdAt: "2026-07-18T00:00:01.000Z",
    });
    expect(a.implementerSeq).toBe(1n);
    expect(b.implementerSeq).toBe(2n);
    expect(await log.watermark(IMPLEMENTER_ID)).toBe(2n);
  });

  it("rejects event types outside the closed set", async () => {
    expect(isImplementerStreamEventType("not.a.real.event")).toBe(false);
    const log = new InMemoryImplementerEventLog();
    await expect(
      log.append({
        implementerId: IMPLEMENTER_ID,
        eventId: "e1",
        // @ts-expect-error intentional closed-set breach
        eventType: "not.a.real.event",
        proofRepresentation: "{}",
        createdAt: "2026-07-18T00:00:00.000Z",
      }),
    ).rejects.toBeInstanceOf(ImplementerEventLogError);
  });

  it("isolates implementers", async () => {
    const log = new InMemoryImplementerEventLog();
    await log.append({
      implementerId: "aaaaaaa1-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      eventId: "e1",
      eventType: "receive.ready",
      proofRepresentation: proof(1n),
      createdAt: "2026-07-18T00:00:00.000Z",
    });
    expect(await log.watermark("bbbbbbb1-bbbb-4bbb-8bbb-bbbbbbbbbbbb")).toBe(0n);
    const page = await log.readEvents("bbbbbbb1-bbbb-4bbb-8bbb-bbbbbbbbbbbb", null, 10);
    expect(page.events).toEqual([]);
  });

  it("serves exclusive after reads compatible with listEvents", async () => {
    const log = new InMemoryImplementerEventLog();
    for (let i = 1; i <= 5; i += 1) {
      await log.append({
        implementerId: IMPLEMENTER_ID,
        eventId: `e${i}`,
        eventType: "receive.ready",
        proofRepresentation: proof(BigInt(i)),
        createdAt: "2026-07-18T00:00:00.000Z",
      });
    }
    const listed = await listEvents(log, {
      implementerId: IMPLEMENTER_ID,
      afterImplementerSeq: 2n,
      limit: 2,
    });
    expect(listed.events.map((e) => e.implementerSeq)).toEqual([3n, 4n]);
    expect(listed.watermarkSeq).toBe(5n);
    expect(listed.nextAfterSeq).toBe(4n);
  });

  it("notifies subscribers after append without rolling back on listener throw", async () => {
    const log = new InMemoryImplementerEventLog();
    const seen: bigint[] = [];
    log.subscribe(IMPLEMENTER_ID, (event) => {
      seen.push(event.implementerSeq);
      throw new Error("listener boom");
    });
    await log.append({
      implementerId: IMPLEMENTER_ID,
      eventId: "e1",
      eventType: "receive.landed",
      proofRepresentation: proof(1n),
      createdAt: "2026-07-18T00:00:00.000Z",
    });
    expect(seen).toEqual([1n]);
    expect(await log.watermark(IMPLEMENTER_ID)).toBe(1n);
  });

  it("proof bytes survive pull framing unchanged", async () => {
    const log = new InMemoryImplementerEventLog();
    const exact = '{"purpose":"zp-implementer-event-v1","implementer_seq":"1","sig":"x"}';
    await log.append({
      implementerId: IMPLEMENTER_ID,
      eventId: "e1",
      eventType: "receive.ready",
      proofRepresentation: exact,
      createdAt: "2026-07-18T00:00:00.000Z",
    });
    const page = await log.readEvents(IMPLEMENTER_ID, null, 1);
    expect(frameImplementerEventStream(page.events)).toBe(
      `id: 1\nevent: receive.ready\ndata: ${exact}\n\n`,
    );
  });
});

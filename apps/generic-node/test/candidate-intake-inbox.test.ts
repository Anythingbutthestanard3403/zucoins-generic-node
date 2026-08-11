// ZTR-1188 — the candidate-intake inbox is bounded and the anonymous relay lane cannot
// starve the authenticated push lane. Pure in-memory: no DB, no sockets, so this runs
// under test/setup-network-guard.ts unchanged.

import { describe, expect, it } from "vitest";

import type { CandidateIntakeRequest } from "@zucoins/node-core";

import {
  createCandidateIntakeInbox,
  INTAKE_BATCH_LIMIT,
  type CandidateIntakeSource,
} from "../src/money-workers/receive-candidate-intake-step.js";

const CAP = 8;

function request(marker: string): CandidateIntakeRequest {
  return {
    locate: { receiverPubkey: `pk-${marker}`, discriminator: marker, expiry: "1900000000" },
    inner_preimage_text: `{"marker":"${marker}"}`,
    step_1_signature: `sig-${marker}`,
  };
}

function markersOf(batch: readonly CandidateIntakeRequest[]): string[] {
  return batch.map((entry) => entry.locate.discriminator);
}

function fill(
  inbox: ReturnType<typeof createCandidateIntakeInbox>,
  source: CandidateIntakeSource,
  count: number,
): void {
  for (let i = 0; i < count; i++) inbox.enqueue(request(`${source}-${i}`), source);
}

describe("createCandidateIntakeInbox — bounded, lane-separated intake (ZTR-1188)", () => {
  it("refuses past the per-lane cap instead of growing", () => {
    const inbox = createCandidateIntakeInbox(CAP);

    for (let i = 0; i < CAP; i++) {
      expect(inbox.enqueue(request(`relay-${i}`), "relay")).toEqual({ enqueued: true });
    }
    // A burst an order of magnitude past the cap must not add a single entry.
    for (let i = 0; i < CAP * 10; i++) {
      expect(inbox.enqueue(request(`flood-${i}`), "relay")).toEqual({
        enqueued: false,
        reason: "inbox_full",
      });
    }
    expect(inbox.size()).toBe(CAP);
  });

  it("caps each lane separately, so a relay flood leaves push capacity intact", () => {
    const inbox = createCandidateIntakeInbox(CAP);
    fill(inbox, "relay", CAP * 10);

    expect(inbox.size()).toBe(CAP);
    expect(inbox.enqueue(request("push-after-flood"), "push")).toEqual({ enqueued: true });
    expect(inbox.size()).toBe(CAP + 1);
  });

  it("serves the authenticated push lane ahead of an existing relay backlog", () => {
    const inbox = createCandidateIntakeInbox(CAP);
    // Relay backlog first — under a single FIFO these would all be taken before the
    // push delivery that arrives afterwards.
    fill(inbox, "relay", CAP);
    inbox.enqueue(request("genuine-delivery"), "push");

    expect(markersOf(inbox.take(INTAKE_BATCH_LIMIT))[0]).toBe("genuine-delivery");
  });

  it("spends leftover batch budget on the relay lane", () => {
    const inbox = createCandidateIntakeInbox(CAP);
    inbox.enqueue(request("push-0"), "push");
    fill(inbox, "relay", CAP);

    expect(markersOf(inbox.take(INTAKE_BATCH_LIMIT))).toEqual([
      "push-0",
      "relay-0",
      "relay-1",
      "relay-2",
      "relay-3",
    ]);
  });

  it("empties in a bounded number of batches once the producers stop", () => {
    const inbox = createCandidateIntakeInbox(CAP);
    fill(inbox, "push", CAP);
    fill(inbox, "relay", CAP);

    let batches = 0;
    while (inbox.size() > 0) {
      expect(inbox.take(INTAKE_BATCH_LIMIT).length).toBeGreaterThan(0);
      batches += 1;
      expect(batches).toBeLessThanOrEqual(Math.ceil((CAP * 2) / INTAKE_BATCH_LIMIT));
    }
    expect(batches).toBe(Math.ceil((CAP * 2) / INTAKE_BATCH_LIMIT));
    expect(inbox.take(INTAKE_BATCH_LIMIT)).toEqual([]);
  });

  it("refuses to construct without a usable cap", () => {
    expect(() => createCandidateIntakeInbox(0)).toThrow(/maxPerSource/);
    expect(() => createCandidateIntakeInbox(-1)).toThrow(/maxPerSource/);
    expect(() => createCandidateIntakeInbox(1.5)).toThrow(/maxPerSource/);
  });

  it("reports per-source depth for the backlog gauge (ZTR-1216)", () => {
    const inbox = createCandidateIntakeInbox(CAP);
    fill(inbox, "relay", 3);
    fill(inbox, "push", 2);
    expect(inbox.sizeBySource("relay")).toBe(3);
    expect(inbox.sizeBySource("push")).toBe(2);
    expect(inbox.size()).toBe(5);
    // take prefers push (2) then fills remaining budget from relay (INTAKE_BATCH_LIMIT - 2).
    inbox.take(INTAKE_BATCH_LIMIT);
    expect(inbox.sizeBySource("push")).toBe(0);
    expect(inbox.sizeBySource("relay")).toBe(3 - (INTAKE_BATCH_LIMIT - 2));
  });
});

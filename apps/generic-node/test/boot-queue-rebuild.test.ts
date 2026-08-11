/**
 * ZTR-1172 / doc 09 §7.7 — boot queue rebuild is not a log-only no-op.
 *
 * Unit proof: seedReconcileCursor / rebuildReceiveAdmissionQueue materialise
 * process-local seeds. PG integration of hydrateRawBytePriors → seed is covered
 * when observation rows exist (sql-boot-recovery listObservationCursors path).
 */
import { describe, expect, it, vi } from "vitest";

import {
  hydrateRawBytePriors,
  type BootRecoveryStore,
  type ObservationCursorHint,
} from "@zucoins/node-core";

import { createSqlBootRecovery } from "../src/boot/sql-boot-recovery.js";

describe("boot queue rebuild seeds (ZTR-1172 §7.7)", () => {
  it("seedReconcileCursor stores exact prior raw bytes on the process-local seed map", async () => {
    const logger = { info: vi.fn(), error: vi.fn() };
    const pool = {
      query: vi.fn(async () => ({ rows: [], rowCount: 0 })),
    };
    const vault = {} as never;
    const { actions, seeds } = createSqlBootRecovery(pool as never, logger, vault);

    const prior = new Uint8Array([1, 2, 3, 4, 5]);
    await actions.seedReconcileCursor("observer:walletpk", prior);
    await actions.seedReconcileCursor("empty-stream", null);

    expect(seeds.reconcileCursorPriors.get("observer:walletpk")).toEqual(prior);
    // Defensive copy — mutating the input must not alter the seed.
    prior[0] = 99;
    expect(seeds.reconcileCursorPriors.get("observer:walletpk")![0]).toBe(1);
    expect(seeds.reconcileCursorPriors.get("empty-stream")).toBeNull();
    expect(logger.info).toHaveBeenCalled();
  });

  it("rebuildReceiveAdmissionQueue materialises the CREATED receive set", async () => {
    const logger = { info: vi.fn(), error: vi.fn() };
    const pool = {
      query: vi.fn(async () => ({ rows: [], rowCount: 0 })),
    };
    const { actions, seeds } = createSqlBootRecovery(pool as never, logger, {} as never);

    await actions.rebuildReceiveAdmissionQueue(["op-a", "op-b"]);
    expect(seeds.receiveAdmissionQueue).toEqual(["op-a", "op-b"]);
    await actions.rebuildReceiveAdmissionQueue(["op-c"]);
    expect(seeds.receiveAdmissionQueue).toEqual(["op-c"]);
  });

  it("hydrateRawBytePriors seeds exact bytes for the first post-restart dedup comparison", async () => {
    const prior = new TextEncoder().encode("pre-restart-observation-body");
    const cursors: ObservationCursorHint[] = [
      {
        streamKey: "obs:pk",
        lastRecordedObservationId: "obs-1",
        lastRawResponseSha256: "deadbeef",
      },
    ];
    const store: BootRecoveryStore = {
      listActiveLeases: async () => [],
      listNonterminalOperations: async () => [],
      listLeaseGroupOperations: async () => [],
      listKeyCorrespondenceRows: async () => [],
      listObservationCursors: async () => cursors,
      readRawResponseBytes: async (id) => (id === "obs-1" ? new Uint8Array(prior) : null),
      listQueuedReceiveOperationIds: async () => ["recv-1"],
    };
    const logger = { info: vi.fn(), error: vi.fn() };
    const { actions, seeds } = createSqlBootRecovery(
      { query: vi.fn(async () => ({ rows: [], rowCount: 0 })) } as never,
      logger,
      {} as never,
    );

    const hydrations = await hydrateRawBytePriors(store, actions);
    expect(hydrations).toEqual([
      {
        streamKey: "obs:pk",
        ok: true,
        usedDigestShortcut: false,
        reason: "raw_bytes_loaded",
      },
    ]);
    expect(Buffer.from(seeds.reconcileCursorPriors.get("obs:pk")!).equals(Buffer.from(prior))).toBe(
      true,
    );

    const queued = await store.listQueuedReceiveOperationIds();
    await actions.rebuildReceiveAdmissionQueue(queued);
    expect(seeds.receiveAdmissionQueue).toEqual(["recv-1"]);
  });
});

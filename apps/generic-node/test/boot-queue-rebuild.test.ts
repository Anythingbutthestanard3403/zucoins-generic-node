/**
 * ZTR-1172 / doc 09 §7.7 — boot queue rebuild is not a log-only no-op.
 *
 * Unit proof: seedReconcileCursor / rebuildReceiveAdmissionQueue materialise
 * process-local seeds. PG integration of hydrateRawBytePriors → seed is covered
 * when observation rows exist (sql-boot-recovery listObservationCursors path).
 */
import { describe, expect, it, vi } from "vitest";

import {
  createSqlStreamWriterEffects,
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
      listKeyCorrespondence: async () => [],
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


describe("stream writer boot seed handoff (ZTR-1172 §7.7)", () => {
  it("createSqlStreamWriterEffects prefers boot-hydrated prior raw bytes on first loadPrior", async () => {
    const seeded = new Uint8Array([9, 8, 7, 6]);
    const sqlRaw = new Uint8Array([1, 2, 3, 4]);
    let step = 0;
    const effects = createSqlStreamWriterEffects({
      sql: {
        query: (async () => {
          step += 1;
          if (step % 3 === 1) {
            return { rows: [{ last_recorded_observation_id: "obs-row-1" }] };
          }
          if (step % 3 === 2) {
            return {
              rows: [
                {
                  next_wallet_seq: "2",
                  consecutive_repeat_count: "0",
                  last_recorded_observation_id: "obs-row-1",
                  last_raw_response_sha256: "aa".repeat(32),
                  last_semantic_fingerprint: null,
                  wallet_seq: "1",
                  raw_response_bytes: Buffer.from(sqlRaw),
                  raw_response_sha256: "bb".repeat(32),
                  parse_result: "VERIFIED_GENESIS",
                  wallet_role: "genesis",
                  s_signature: "sig-s",
                  p_signature: "sig-p",
                  semantic_fingerprint: "fp",
                },
              ],
            };
          }
          return {
            rows: [
              {
                wallet_seq: "1",
                parse_result: "VERIFIED_GENESIS",
                wallet_role: "genesis",
                s_signature: "sig-s",
                p_signature: "sig-p",
                semantic_fingerprint: "fp",
                relationship: "FIRST",
              },
            ],
          };
        }) as never,
      },
      project: () => {
        throw new Error("project unused in loadPrior-only test");
      },
      onAnomalyRequired: async () => {},
      takeAdvisoryLock: false,
      bootPriorRawByStreamKey: new Map([["obs-1:wallet-pk", seeded]]),
    });

    const prior = await effects.loadPrior({ observerId: "obs-1", walletPublicKey: "wallet-pk" });
    expect(prior).not.toBeNull();
    if (prior === null) throw new Error("expected prior");
    expect(Buffer.from(prior.lastRecorded!.rawResponseBytes).equals(Buffer.from(seeded))).toBe(
      true,
    );

    const prior2 = await effects.loadPrior({ observerId: "obs-1", walletPublicKey: "wallet-pk" });
    if (prior2 === null) throw new Error("expected prior2");
    expect(Buffer.from(prior2.lastRecorded!.rawResponseBytes).equals(Buffer.from(sqlRaw))).toBe(
      true,
    );
  });
});

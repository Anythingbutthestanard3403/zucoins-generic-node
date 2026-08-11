import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  buildScheduledBackupMarkers,
  compareContinuityMarkers,
  deriveContinuitySnapshotOnClient,
  loadContinuityMarkers,
  parseContinuityMarkers,
  writeContinuityMarkers,
} from "../../src/dr/markers.js";

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

const HASH = "11".repeat(32);

describe("continuity markers", () => {
  it("round-trips write/load", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gn-mark-"));
    dirs.push(dir);
    const path = join(dir, "markers.json");
    const markers = buildScheduledBackupMarkers(
      { lifecycleEpoch: 3n, nonceBurnHighWater: 9n, terminalEventHash: HASH },
      {
        backupArtifactSha256: "22".repeat(32),
        backupOutputPath: "/offsite/generic-node.zbkp",
        observedAt: new Date("2026-07-26T00:00:00.000Z"),
      },
    );
    await writeContinuityMarkers(path, markers);
    const loaded = await loadContinuityMarkers(path);
    expect(loaded.ok).toBe(true);
    if (loaded.ok) {
      expect(loaded.markers.lifecycleEpoch).toBe("3");
      expect(loaded.markers.terminalEventHash).toBe(HASH);
    }
  });

  it("rejects unknown format and bad hash", () => {
    expect(parseContinuityMarkers({ format: "nope" }).ok).toBe(false);
    expect(
      parseContinuityMarkers({
        format: "zp-gn-continuity-markers-v1",
        trustedSourceId: "x",
        trustedSourceObservedAt: "2026-07-26T00:00:00.000Z",
        lifecycleEpoch: "1",
        nonceBurnHighWater: "0",
        terminalEventHash: "not-hex",
      }).ok,
    ).toBe(false);
  });

  it("compare requires exact equality", () => {
    const markers = buildScheduledBackupMarkers(
      { lifecycleEpoch: 1n, nonceBurnHighWater: 0n, terminalEventHash: HASH },
      {
        backupArtifactSha256: "22".repeat(32),
        backupOutputPath: "/offsite/generic-node.zbkp",
        observedAt: new Date("2026-07-26T00:00:00.000Z"),
      },
    );
    expect(
      compareContinuityMarkers(
        { lifecycleEpoch: 1n, nonceBurnHighWater: 0n, terminalEventHash: HASH },
        markers,
      ),
    ).toEqual({ equal: true });
    expect(
      compareContinuityMarkers(
        { lifecycleEpoch: 2n, nonceBurnHighWater: 0n, terminalEventHash: HASH },
        markers,
      ).equal,
    ).toBe(false);
  });

  it("missing file is fail-closed", async () => {
    const loaded = await loadContinuityMarkers("/no/such/markers.json");
    expect(loaded).toEqual({ ok: false, reason: "markers_source_unreadable" });
  });

  it("refuses a self-derived marker without successful-backup provenance", () => {
    expect(
      parseContinuityMarkers({
        format: "zp-gn-continuity-markers-v1",
        trustedSourceId: "file:/restored-db/markers.json",
        trustedSourceObservedAt: "2026-07-26T00:00:00.000Z",
        lifecycleEpoch: "1",
        nonceBurnHighWater: "0",
        terminalEventHash: HASH,
      }),
    ).toEqual({ ok: false, reason: "markers_not_from_successful_backup" });
  });

  it("derives the logical pre-restore continuity point from live DB rows", async () => {
    const calls: Array<{ sql: string; params?: readonly unknown[] }> = [];
    const snapshot = await deriveContinuitySnapshotOnClient(
      {
        query: async (sql: string, params?: readonly unknown[]) => {
          calls.push({ sql, params });
          return {
            rowCount: 1,
            rows: [{ lifecycle_epoch: "7", nonce_burn_high_water: "42", terminal_event_hash: HASH }],
          };
        },
      },
      "11111111-1111-4111-8111-111111111111",
    );
    expect(snapshot).toEqual({ lifecycleEpoch: 7n, nonceBurnHighWater: 42n, terminalEventHash: HASH });
    expect(calls[0]?.sql).toMatch(/AUTH_HOLD_SET/);
    expect(calls[0]?.sql).toMatch(/restore_auth_hold/);
    expect(calls[0]?.params).toEqual(["11111111-1111-4111-8111-111111111111"]);
  });
});

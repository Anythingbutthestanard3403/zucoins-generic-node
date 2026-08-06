import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  buildMarkersFromLocal,
  compareContinuityMarkers,
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
    const markers = buildMarkersFromLocal(
      { lifecycleEpoch: 3n, nonceBurnHighWater: 9n, terminalEventHash: HASH },
      "file:test",
      new Date("2026-07-26T00:00:00.000Z"),
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
    const markers = buildMarkersFromLocal(
      { lifecycleEpoch: 1n, nonceBurnHighWater: 0n, terminalEventHash: HASH },
      "src",
      new Date("2026-07-26T00:00:00.000Z"),
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
});

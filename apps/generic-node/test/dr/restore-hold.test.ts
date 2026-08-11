import { describe, expect, it } from "vitest";

import {
  buildScheduledBackupMarkers,
  hashHoldReleaseEvidence,
  type ContinuityMarkers,
  type LocalContinuitySnapshot,
} from "../../src/dr/markers.js";
import {
  buildForceRestoreHoldUpsert,
  buildEnsureRestoreHoldInsert,
  buildRestoreHoldReleaseUpdate,
  evaluateRestoreHoldRelease,
} from "../../src/dr/restore-hold.js";

const HASH_A = "ab".repeat(32);
const HASH_B = "cd".repeat(32);

function local(overrides: Partial<LocalContinuitySnapshot> = {}): LocalContinuitySnapshot {
  return {
    lifecycleEpoch: 7n,
    nonceBurnHighWater: 42n,
    terminalEventHash: HASH_A,
    ...overrides,
  };
}

function trusted(overrides: Partial<ContinuityMarkers> = {}): ContinuityMarkers {
  return {
    format: "zp-gn-continuity-markers-v1",
    trustedSourceId: "file:/var/lib/gn/markers.json",
    trustedSourceObservedAt: "2026-07-26T00:00:00.000Z",
    lifecycleEpoch: "7",
    nonceBurnHighWater: "42",
    terminalEventHash: HASH_A,
    provenance: "successful_scheduled_backup",
    backupArtifactSha256: "22".repeat(32),
    backupOutputPath: "/offsite/backup.zbkp",
    ...overrides,
  };
}

describe("evaluateRestoreHoldRelease — fail-closed matrix", () => {
  it("releases only when external markers exactly match local snapshot", () => {
    const decision = evaluateRestoreHoldRelease({ trusted: trusted(), local: local() });
    expect(decision.release).toBe(true);
    if (decision.release) {
      expect(decision.holdReleaseEvidenceSha256).toBe(hashHoldReleaseEvidence(trusted()));
      expect(decision.holdReleaseEvidenceSha256).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("fault 6: missing trusted source stays held", () => {
    expect(evaluateRestoreHoldRelease({ trusted: null, local: local() })).toEqual({
      release: false,
      reason: "missing_trusted_source",
    });
  });

  it("fault 6: missing local snapshot stays held", () => {
    expect(evaluateRestoreHoldRelease({ trusted: trusted(), local: null })).toEqual({
      release: false,
      reason: "missing_local_snapshot",
    });
  });

  it("fault 1: lifecycle-epoch regression stays held", () => {
    const decision = evaluateRestoreHoldRelease({
      trusted: trusted({ lifecycleEpoch: "5" }),
      local: local({ lifecycleEpoch: 5n }),
      priorTrusted: { lifecycleEpoch: 7n, nonceBurnHighWater: 40n },
    });
    expect(decision.release).toBe(false);
    if (!decision.release) expect(decision.reason).toBe("regression_lifecycle_epoch");
  });

  it("fault 1: nonce-burn high-water regression stays held", () => {
    const decision = evaluateRestoreHoldRelease({
      trusted: trusted({ nonceBurnHighWater: "10" }),
      local: local({ nonceBurnHighWater: 10n }),
      priorTrusted: { lifecycleEpoch: 7n, nonceBurnHighWater: 40n },
    });
    expect(decision.release).toBe(false);
    if (!decision.release) expect(decision.reason).toBe("regression_nonce_burn_high_water");
  });

  it("fault 7: epoch mismatch stays held", () => {
    const decision = evaluateRestoreHoldRelease({
      trusted: trusted({ lifecycleEpoch: "8" }),
      local: local({ lifecycleEpoch: 7n }),
    });
    expect(decision.release).toBe(false);
    if (!decision.release) expect(decision.reason).toBe("lifecycle_epoch_mismatch");
  });

  it("fault 7: high-water mismatch stays held", () => {
    const decision = evaluateRestoreHoldRelease({
      trusted: trusted({ nonceBurnHighWater: "99" }),
      local: local(),
    });
    expect(decision.release).toBe(false);
    if (!decision.release) expect(decision.reason).toBe("nonce_burn_high_water_mismatch");
  });

  it("fault 7: event-hash mismatch stays held", () => {
    const decision = evaluateRestoreHoldRelease({
      trusted: trusted({ terminalEventHash: HASH_B }),
      local: local(),
    });
    expect(decision.release).toBe(false);
    if (!decision.release) expect(decision.reason).toBe("terminal_event_hash_mismatch");
  });

  it("fault 8: equal local markers without external source cannot release", () => {
    const decision = evaluateRestoreHoldRelease({ trusted: null, local: local() });
    expect(decision.release).toBe(false);
  });

  it("scheduled-backup markers + evaluate is the explicit external path", () => {
    const snap = local();
    const markers = buildScheduledBackupMarkers(snap, {
      backupArtifactSha256: "22".repeat(32),
      backupOutputPath: "/offsite/backup.zbkp",
    });
    const decision = evaluateRestoreHoldRelease({ trusted: markers, local: snap });
    expect(decision.release).toBe(true);
  });
});

describe("restore-hold SQL builders", () => {
  it("release UPDATE populates every CHECK-constrained column", () => {
    const decision = evaluateRestoreHoldRelease({ trusted: trusted(), local: local() });
    expect(decision.release).toBe(true);
    if (!decision.release) return;
    const { sql, params } = buildRestoreHoldReleaseUpdate({
      nodeId: "11111111-1111-4111-8111-111111111111",
      decision,
      now: new Date("2026-07-26T12:00:00.000Z"),
    });
    expect(sql).toMatch(/restore_hold = false/);
    expect(sql).toMatch(/hold_release_evidence_sha256/);
    expect(params).toHaveLength(11);
    expect(params[3]).toBe(HASH_A);
    expect(params[9]).toBe(decision.holdReleaseEvidenceSha256);
  });

  it("force upsert sets restore_hold=true and clears release evidence on conflict", () => {
    const { sql, params } = buildForceRestoreHoldUpsert({
      nodeId: "11111111-1111-4111-8111-111111111111",
      now: new Date("2026-07-26T12:00:00.000Z"),
    });
    expect(sql).toMatch(/restore_hold/);
    expect(sql).toMatch(/ON CONFLICT \(node_id\) DO UPDATE/);
    expect(sql).toMatch(/restore_hold = true/);
    expect(sql).toMatch(/local_lifecycle_epoch = NULL/);
    expect(sql).toMatch(/hold_release_evidence_sha256 = NULL/);
    expect(sql).toMatch(/hold_released_at = NULL/);
    expect(sql).not.toMatch(/DO NOTHING/);
    expect(params[0]).toBe("11111111-1111-4111-8111-111111111111");
  });

  it("buildEnsureRestoreHoldInsert aliases the force upsert", () => {
    const a = buildForceRestoreHoldUpsert({
      nodeId: "11111111-1111-4111-8111-111111111111",
      now: new Date("2026-07-26T12:00:00.000Z"),
    });
    const b = buildEnsureRestoreHoldInsert({
      nodeId: "11111111-1111-4111-8111-111111111111",
      now: new Date("2026-07-26T12:00:00.000Z"),
    });
    expect(b.sql).toBe(a.sql);
    expect(b.params).toEqual(a.params);
  });
});

import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  createBackupScheduler,
  interruptibleSleep,
  type BackupSchedulerHandle,
} from "../../src/dr/schedule.js";
import {
  buildScheduledBackupMarkers,
  writeContinuityMarkers,
} from "../../src/dr/markers.js";

function deferred<T = void>(): {
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
} {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

describe("interruptibleSleep", () => {
  it("resolves early when wake is invoked (deploy SIGTERM must not wait intervalMs)", async () => {
    const started = Date.now();
    let wake!: () => void;
    const sleepP = interruptibleSleep(60_000, (w) => {
      wake = w;
    });
    wake();
    await sleepP;
    expect(Date.now() - started).toBeLessThan(5_000);
  });
});

describe("createBackupScheduler — graceful stop", () => {
  const handles: BackupSchedulerHandle[] = [];
  const dirs: string[] = [];

  afterEach(async () => {
    for (const h of handles.splice(0)) h.stop();
    await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  function baseConfig(
    overrides: Partial<Parameters<typeof createBackupScheduler>[0]> = {},
  ): Parameters<typeof createBackupScheduler>[0] {
    return {
      enabled: true,
      databaseUrl: "postgres://unused",
      masterKey: "k".repeat(32),
      outputDir: "/tmp/fixture-unused",
      intervalMs: 60_000,
      logger: { info: () => {}, error: () => {} },
      ...overrides,
    };
  }

  it("stop() interrupts inter-run sleep so drain finishes without waiting intervalMs", async () => {
    let runs = 0;
    const enteredSleep = deferred();
    const scheduler = createBackupScheduler(
      baseConfig({
        sleep: async (_ms, signal) => {
          enteredSleep.resolve();
          while (!signal.stopped()) {
            await new Promise((r) => setTimeout(r, 5));
          }
        },
        trackInflight: async (work) => {
          runs += 1;
          return work.catch(() => undefined as never);
        },
      }),
    );
    handles.push(scheduler);
    scheduler.start();
    await enteredSleep.promise;
    const t0 = Date.now();
    scheduler.stop();
    await scheduler.drain();
    expect(Date.now() - t0).toBeLessThan(5_000);
    expect(runs).toBeGreaterThanOrEqual(1);
  });

  it("writes externally held continuity evidence after a successful backup run", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gn-scheduled-marker-"));
    dirs.push(dir);
    const markerPath = join(dir, "continuity.json");
    const sha256 = "22".repeat(32);
    const dumpBoundSnapshot = {
      lifecycleEpoch: 7n,
      nonceBurnHighWater: 42n,
      terminalEventHash: "ab".repeat(32),
    };
    const scheduler = createBackupScheduler(
      baseConfig({
        outputDir: dir,
        nowMs: () => 1_000,
        // Production path: continuitySnapshot is captured with the dump snapshot.
        exportBackup: async (_databaseUrl, outputPath) => {
          await writeFile(outputPath, "encrypted-backup", "utf8");
          return {
            outputPath,
            bytesWritten: 16,
            sha256,
            continuitySnapshot: dumpBoundSnapshot,
          };
        },
        afterSuccess: async (success) => {
          const snapshot = success.result.continuitySnapshot;
          if (snapshot === undefined) throw new Error("missing dump-bound snapshot");
          await writeContinuityMarkers(
            markerPath,
            buildScheduledBackupMarkers(snapshot, {
              backupArtifactSha256: success.result.sha256,
              backupOutputPath: success.result.outputPath,
              observedAt: new Date(success.finishedAtMs),
            }),
          );
        },
      }),
    );
    handles.push(scheduler);

    const success = await scheduler.runOnce();
    const marker = JSON.parse(await readFile(markerPath, "utf8")) as Record<string, unknown>;
    expect(marker).toMatchObject({
      provenance: "successful_scheduled_backup",
      backupArtifactSha256: success.result.sha256,
      backupOutputPath: success.result.outputPath,
      lifecycleEpoch: "7",
      nonceBurnHighWater: "42",
    });
    // RPO anchors advance only after marker pairing.
    expect(scheduler.status().lastSuccessAtMs).toBe(success.finishedAtMs);
    expect(scheduler.status().rpoBreached).toBe(false);
  });

  it("does not advance RPO / lastSuccess when afterSuccess (marker pair) fails", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gn-marker-fail-"));
    dirs.push(dir);
    const sha256 = "33".repeat(32);
    const scheduler = createBackupScheduler(
      baseConfig({
        outputDir: dir,
        nowMs: () => 2_000,
        policy: {
          rpoTargetMs: 1,
          rtoTargetMs: 1,
          retentionDays: 7,
          scheduleIntervalMs: 1,
        },
        exportBackup: async (_databaseUrl, outputPath) => {
          await writeFile(outputPath, "encrypted-backup", "utf8");
          return {
            outputPath,
            bytesWritten: 16,
            sha256,
            continuitySnapshot: {
              lifecycleEpoch: 1n,
              nonceBurnHighWater: 0n,
              terminalEventHash: "cd".repeat(32),
            },
          };
        },
        afterSuccess: async () => {
          throw new Error("marker write refused");
        },
      }),
    );
    handles.push(scheduler);

    await expect(scheduler.runOnce()).rejects.toThrow(/marker write refused/);
    const st = scheduler.status();
    expect(st.lastSuccessAtMs).toBeNull();
    expect(st.newestArtifactAtMs).toBeNull();
    expect(st.consecutiveFailures).toBe(1);
    expect(st.lastError).toMatch(/marker write refused/);
    // Owner with no paired success must report RPO breach under tight policy.
    expect(st.rpoBreached).toBe(true);
    // Unpaired final artifact must not remain on disk.
    const { readdir } = await import("node:fs/promises");
    const leftovers = (await readdir(dir)).filter((n) => n.endsWith(".zbkp"));
    expect(leftovers).toEqual([]);
  });

  it("uses dump-bound continuitySnapshot from export — not a post-seal re-derive", async () => {
    const dir = await mkdtemp(join(tmpdir(), "gn-dump-bound-"));
    dirs.push(dir);
    const markerPath = join(dir, "continuity.json");
    const dumpEpoch = 9n;
    let afterSaw: bigint | undefined;
    const scheduler = createBackupScheduler(
      baseConfig({
        outputDir: dir,
        nowMs: () => 3_000,
        continuityNodeId: "00000000-0000-4000-8000-000000000099",
        exportBackup: async (_databaseUrl, outputPath, _key, options) => {
          // Scheduler must request snapshot-bound export when continuityNodeId is set.
          expect(options?.continuityNodeId).toBe("00000000-0000-4000-8000-000000000099");
          await writeFile(outputPath, "enc", "utf8");
          return {
            outputPath,
            bytesWritten: 3,
            sha256: "44".repeat(32),
            continuitySnapshot: {
              lifecycleEpoch: dumpEpoch,
              nonceBurnHighWater: 100n,
              terminalEventHash: "ef".repeat(32),
            },
          };
        },
        afterSuccess: async (success) => {
          afterSaw = success.result.continuitySnapshot?.lifecycleEpoch;
          await writeContinuityMarkers(
            markerPath,
            buildScheduledBackupMarkers(success.result.continuitySnapshot!, {
              backupArtifactSha256: success.result.sha256,
              backupOutputPath: success.result.outputPath,
              observedAt: new Date(success.finishedAtMs),
            }),
          );
        },
      }),
    );
    handles.push(scheduler);
    await scheduler.runOnce();
    expect(afterSaw).toBe(dumpEpoch);
    const marker = JSON.parse(await readFile(markerPath, "utf8")) as { lifecycleEpoch: string };
    expect(marker.lifecycleEpoch).toBe("9");
  });

  it("drain() awaits an in-flight export started before stop()", async () => {
    const holdExport = deferred();
    let exportEntered = false;
    let exportFinished = false;

    const scheduler = createBackupScheduler(
      baseConfig({
        sleep: async (_ms, signal) => {
          while (!signal.stopped()) await new Promise((r) => setTimeout(r, 5));
        },
        trackInflight: (work) => {
          exportEntered = true;
          // Gate settlement so drain observes a live export across stop().
          return holdExport.promise.then(() =>
            work.then(
              (v) => {
                exportFinished = true;
                return v;
              },
              (e) => {
                exportFinished = true;
                throw e;
              },
            ),
          );
        },
      }),
    );
    handles.push(scheduler);
    scheduler.start();

    for (let i = 0; i < 200 && !exportEntered; i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
    expect(exportEntered).toBe(true);

    scheduler.stop();
    let drained = false;
    const drainP = scheduler.drain().then(() => {
      drained = true;
    });

    await new Promise((r) => setTimeout(r, 30));
    expect(drained).toBe(false);
    expect(exportFinished).toBe(false);

    holdExport.resolve();
    await drainP;
    expect(drained).toBe(true);
    expect(exportFinished).toBe(true);
  });

  it("stop() prevents a subsequent loop iteration after the current run settles", async () => {
    let runs = 0;
    const firstStarted = deferred();
    const firstRelease = deferred();

    const scheduler = createBackupScheduler(
      baseConfig({
        intervalMs: 1,
        sleep: async (_ms, signal) => {
          while (!signal.stopped()) await new Promise((r) => setTimeout(r, 5));
        },
        trackInflight: async (work) => {
          runs += 1;
          if (runs === 1) {
            firstStarted.resolve();
            await firstRelease.promise;
          }
          return work.catch(() => undefined as never);
        },
      }),
    );
    handles.push(scheduler);
    scheduler.start();
    await firstStarted.promise;
    scheduler.stop();
    firstRelease.resolve();
    await scheduler.drain();
    await new Promise((r) => setTimeout(r, 30));
    expect(runs).toBe(1);
  });
});


describe("createBackupScheduler — leadership gate (ZTR-1183)", () => {
  const handles: BackupSchedulerHandle[] = [];

  afterEach(() => {
    for (const h of handles.splice(0)) h.stop();
  });

  function baseConfig(
    overrides: Partial<Parameters<typeof createBackupScheduler>[0]> = {},
  ): Parameters<typeof createBackupScheduler>[0] {
    return {
      enabled: true,
      databaseUrl: "postgres://unused",
      masterKey: "k".repeat(32),
      outputDir: "/tmp/fixture-unused",
      intervalMs: 60_000,
      logger: { info: () => {}, error: () => {} },
      ...overrides,
    };
  }

  it("start() is a no-op when isLeader returns false (follower)", async () => {
    let runs = 0;
    const scheduler = createBackupScheduler(
      baseConfig({
        isLeader: () => false,
        trackInflight: async (work) => {
          runs += 1;
          return work.catch(() => undefined as never);
        },
      }),
    );
    handles.push(scheduler);
    scheduler.start();
    await new Promise((r) => setTimeout(r, 30));
    expect(runs).toBe(0);
    const st = scheduler.status();
    expect(st.ownership).toBe("standby");
    expect(st.enabled).toBe(true);
    expect(st.rpoBreached).toBe(false);
    expect(st.running).toBe(false);
  });

  it("status() ownership distinguishes standby from disabled", () => {
    const standby = createBackupScheduler(baseConfig({ isLeader: () => false }));
    handles.push(standby);
    expect(standby.status().ownership).toBe("standby");
    expect(standby.status().rpoBreached).toBe(false);

    const disabled = createBackupScheduler(baseConfig({ enabled: false }));
    handles.push(disabled);
    disabled.start();
    expect(disabled.status().ownership).toBe("disabled");
    expect(disabled.status().enabled).toBe(false);
  });

  it("lost leadership mid-loop stops further beginTrackedRun iterations", async () => {
    let leader = true;
    let runs = 0;
    const firstStarted = deferred();
    const firstRelease = deferred();

    const scheduler = createBackupScheduler(
      baseConfig({
        intervalMs: 1,
        isLeader: () => leader,
        sleep: async (_ms, signal) => {
          while (!signal.stopped()) await new Promise((r) => setTimeout(r, 5));
        },
        trackInflight: async (work) => {
          runs += 1;
          if (runs === 1) {
            firstStarted.resolve();
            await firstRelease.promise;
          }
          return work.catch(() => undefined as never);
        },
      }),
    );
    handles.push(scheduler);
    scheduler.start();
    await firstStarted.promise;
    // Drop leadership before the first run settles — next loop iteration must skip.
    leader = false;
    firstRelease.resolve();
    await scheduler.drain();
    await new Promise((r) => setTimeout(r, 40));
    expect(runs).toBe(1);
    expect(scheduler.status().ownership).toBe("standby");
    scheduler.stop();
  });

  it("owner status reports rpoBreached when no success yet and policy is tight", () => {
    const scheduler = createBackupScheduler(
      baseConfig({
        isLeader: () => true,
        policy: {
          rpoTargetMs: 1,
          rtoTargetMs: 1,
          retentionDays: 1,
          scheduleIntervalMs: 1,
        },
        nowMs: () => 1_000_000,
      }),
    );
    handles.push(scheduler);
    const st = scheduler.status();
    expect(st.ownership).toBe("owner");
    // No artifact yet → RPO breached for the owner.
    expect(st.rpoBreached).toBe(true);
  });

  it("standby never reports rpoBreached even with no artifacts", () => {
    const scheduler = createBackupScheduler(
      baseConfig({
        isLeader: () => false,
        policy: {
          rpoTargetMs: 1,
          rtoTargetMs: 1,
          retentionDays: 1,
          scheduleIntervalMs: 1,
        },
        nowMs: () => 1_000_000,
      }),
    );
    handles.push(scheduler);
    expect(scheduler.status().rpoBreached).toBe(false);
  });
});

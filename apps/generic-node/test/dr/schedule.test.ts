import { afterEach, describe, expect, it } from "vitest";

import {
  createBackupScheduler,
  interruptibleSleep,
  type BackupSchedulerHandle,
} from "../../src/dr/schedule.js";

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

// Stage-1 SIGTERM shutdown is bounded and rejection-safe.
// Fake emitter / stop / exit / timers — no real signal reaches the test process.

import { EventEmitter } from "node:events";

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  DEFAULT_STAGE1_SHUTDOWN_TIMEOUT_MS,
  installStage1GracefulStop,
} from "../src/stage1-shutdown.js";
import { startStage1Service } from "../src/stage1-main.js";
import { loadStage1Config } from "../src/stage1-config.js";

const silentLogger = { info: () => {}, error: () => {} };

describe("installStage1GracefulStop", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("registers handlers for both SIGTERM and SIGINT", () => {
    const emitter = new EventEmitter();
    const onSpy = vi.spyOn(emitter, "on");
    installStage1GracefulStop({
      stop: async () => {},
      logger: silentLogger,
      exit: () => {},
      emitter,
    });
    const registered = onSpy.mock.calls.map((c) => c[0]);
    expect(registered).toContain("SIGTERM");
    expect(registered).toContain("SIGINT");
  });

  it("clean stop exits 0", async () => {
    const emitter = new EventEmitter();
    const stop = vi.fn(async () => {});
    const exit = vi.fn();
    installStage1GracefulStop({ stop, logger: silentLogger, exit, emitter });

    emitter.emit("SIGTERM");
    await vi.waitFor(() => expect(exit).toHaveBeenCalledWith(0));
    expect(stop).toHaveBeenCalledTimes(1);
  });

  it("rejected DB/stop failures exit 1 and never exit 0", async () => {
    const emitter = new EventEmitter();
    const exit = vi.fn();
    const logger = { info: vi.fn(), error: vi.fn() };
    installStage1GracefulStop({
      stop: async () => {
        throw new Error("pool end failed");
      },
      logger,
      exit,
      emitter,
    });

    emitter.emit("SIGTERM");
    await vi.waitFor(() => expect(exit).toHaveBeenCalledWith(1));
    expect(exit).not.toHaveBeenCalledWith(0);
    expect(logger.error).toHaveBeenCalled();
    const [message, err] = logger.error.mock.calls[0] as [string, unknown];
    // Fixed operational prose only — never interpolates config/env into the line.
    expect(message).toMatch(/^shutdown: Stage-1 stop failed/);
    expect(message).not.toMatch(/password|DATABASE_URL|postgresql:\/\//i);
    expect(String(err)).toContain("pool end failed");
  });

  it("hung stop is bounded by the deadline and exits 1", async () => {
    vi.useFakeTimers();
    const emitter = new EventEmitter();
    const exit = vi.fn();
    installStage1GracefulStop({
      stop: () => new Promise(() => {}),
      logger: silentLogger,
      exit,
      emitter,
      timeoutMs: 5_000,
    });

    emitter.emit("SIGTERM");
    expect(exit).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(5_000);
    expect(exit).toHaveBeenCalledWith(1);
  });

  it("uses the default timeout when none is provided", async () => {
    vi.useFakeTimers();
    const emitter = new EventEmitter();
    const exit = vi.fn();
    installStage1GracefulStop({
      stop: () => new Promise(() => {}),
      logger: silentLogger,
      exit,
      emitter,
    });

    emitter.emit("SIGTERM");
    await vi.advanceTimersByTimeAsync(DEFAULT_STAGE1_SHUTDOWN_TIMEOUT_MS - 1);
    expect(exit).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(exit).toHaveBeenCalledWith(1);
  });

  it("repeated signals are idempotent — stop runs once", () => {
    const emitter = new EventEmitter();
    let resolveStop: (() => void) | undefined;
    const stop = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          resolveStop = resolve;
        }),
    );
    installStage1GracefulStop({
      stop,
      logger: silentLogger,
      exit: () => {},
      emitter,
    });

    emitter.emit("SIGTERM");
    emitter.emit("SIGINT");
    emitter.emit("SIGTERM");
    expect(stop).toHaveBeenCalledTimes(1);
    resolveStop?.();
  });

  it("late stop resolution after deadline does not double-exit", async () => {
    vi.useFakeTimers();
    const emitter = new EventEmitter();
    const exit = vi.fn();
    let resolveStop: (() => void) | undefined;
    installStage1GracefulStop({
      stop: () =>
        new Promise<void>((resolve) => {
          resolveStop = resolve;
        }),
      logger: silentLogger,
      exit,
      emitter,
      timeoutMs: 1_000,
    });

    emitter.emit("SIGTERM");
    await vi.advanceTimersByTimeAsync(1_000);
    expect(exit).toHaveBeenCalledTimes(1);
    expect(exit).toHaveBeenCalledWith(1);

    resolveStop?.();
    await vi.advanceTimersByTimeAsync(0);
    expect(exit).toHaveBeenCalledTimes(1);
  });
});

describe("startStage1Service.stop rejection surfaces", () => {
  async function boot() {
    const config = loadStage1Config({
      BIND_HOST: "127.0.0.1",
      DATABASE_URL: "postgresql://stage1.invalid/zunode",
    });
    return startStage1Service(
      { ...config, port: 0 },
      {
        runMigrations: async () => {},
        pingDatabase: async () => {},
        closeDatabase: async () => {},
        // Fake emitter: the graceful stop is installed inside startStage1Service
        // (before migrations) and must not touch the vitest process.
        shutdown: { emitter: new EventEmitter(), exit: () => {}, logger: silentLogger },
      },
    );
  }

  it("rejects when server.close reports an error", async () => {
    const service = await boot();
    const realClose = service.server.close.bind(service.server);
    const closeError = new Error("close failed");
    vi.spyOn(service.server, "close").mockImplementation(((cb?: (err?: Error) => void) => {
      cb?.(closeError);
      return service.server;
    }) as typeof service.server.close);

    await expect(service.stop()).rejects.toThrow("close failed");
    // Real drain so the ListenPort from port:0 does not leak across tests.
    await new Promise<void>((resolve) => realClose(() => resolve()));
  });

  it("rejects when closeDatabase rejects after a clean server close", async () => {
    const config = loadStage1Config({
      BIND_HOST: "127.0.0.1",
      DATABASE_URL: "postgresql://stage1.invalid/zunode",
    });
    const service = await startStage1Service(
      { ...config, port: 0 },
      {
        runMigrations: async () => {},
        pingDatabase: async () => {},
        closeDatabase: async () => {
          throw new Error("pool end failed");
        },
        shutdown: { emitter: new EventEmitter(), exit: () => {}, logger: silentLogger },
      },
    );

    await expect(service.stop()).rejects.toThrow("pool end failed");
  });

  it("stop sheds idle keep-alive sockets after close()", async () => {
    const service = await boot();
    const realClose = service.server.close.bind(service.server);
    const order: string[] = [];
    const close = vi.spyOn(service.server, "close").mockImplementation(((cb?: (err?: Error) => void) => {
      order.push("close");
      cb?.();
      return service.server;
    }) as typeof service.server.close);
    const closeIdle = vi
      .spyOn(service.server, "closeIdleConnections")
      .mockImplementation(() => {
        order.push("closeIdleConnections");
      });

    await service.stop();
    expect(close).toHaveBeenCalledTimes(1);
    expect(closeIdle).toHaveBeenCalledTimes(1);
    expect(order).toEqual(["close", "closeIdleConnections"]);
    await new Promise<void>((resolve) => realClose(() => resolve()));
  });
});

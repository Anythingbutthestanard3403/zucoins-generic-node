import { describe, expect, it } from "vitest";

import { installFatalExceptionHandler } from "../src/boot/fatal-exception.js";

// ZTR-1185: the process-level net. Emitter, exit and timers are injected so a test
// never signals or exits the real process — same discipline as graceful-stop.test.ts.

interface Harness {
  readonly fire: (err: unknown, origin?: string) => void;
  readonly fireDeadline: () => void;
  readonly exits: number[];
  readonly logs: { message: string; details?: unknown }[];
}

function install(options: { timeoutMs?: number } = {}): {
  handler: ReturnType<typeof installFatalExceptionHandler>;
  harness: Harness;
} {
  let listener: ((err: unknown, origin: string) => void) | undefined;
  let deadline: (() => void) | undefined;
  const exits: number[] = [];
  const logs: { message: string; details?: unknown }[] = [];
  const handler = installFatalExceptionHandler({
    ...options,
    logger: { error: (message, details) => logs.push({ message, details }) },
    exit: (code) => exits.push(code),
    emitter: {
      on(_event, next) {
        listener = next;
        return this;
      },
    },
    timers: {
      setTimeout(callback) {
        deadline = callback;
        return 0;
      },
    },
  });
  return {
    handler,
    harness: {
      fire: (err, origin = "uncaughtException") => listener?.(err, origin),
      fireDeadline: () => deadline?.(),
      exits,
      logs,
    },
  };
}

describe("installFatalExceptionHandler", () => {
  it("exits 1 immediately when a fatal beats the graceful stop being wired", () => {
    const { harness } = install();
    harness.fire(new Error("boom"));
    expect(harness.exits).toEqual([1]);
  });

  it("runs the wired graceful stop instead of exiting directly, and floors its exit code", () => {
    const { handler, harness } = install();
    let stopped = 0;
    handler.wire(() => {
      stopped += 1;
    });
    expect(handler.tripped()).toBe(false);

    harness.fire(new Error("boom"));
    expect(stopped).toBe(1);
    expect(harness.exits).toEqual([]);
    // The composition root reads this to floor a clean stop's exit(0) to exit(1).
    expect(handler.tripped()).toBe(true);
  });

  it("exits 1 on the absolute deadline when the graceful stop hangs", () => {
    const { handler, harness } = install({ timeoutMs: 5 });
    handler.wire(() => {
      /* never completes */
    });
    harness.fire(new Error("boom"));
    harness.fireDeadline();
    expect(harness.exits).toEqual([1]);
  });

  it("exits 1 when the graceful stop itself throws", () => {
    const { handler, harness } = install();
    handler.wire(() => {
      throw new Error("stop is broken too");
    });
    harness.fire(new Error("boom"));
    expect(harness.exits).toEqual([1]);
  });

  it("does not restart the stop for a second fatal already on the exit path", () => {
    const { handler, harness } = install();
    let stopped = 0;
    handler.wire(() => {
      stopped += 1;
    });
    harness.fire(new Error("first"));
    harness.fire(new Error("second"));
    expect(stopped).toBe(1);
    expect(harness.logs).toHaveLength(2); // every fatal is still logged
  });

  it("covers unhandled rejections, which Node routes here with that origin", () => {
    const { harness } = install();
    harness.fire(new Error("rejected"), "unhandledRejection");
    expect(harness.logs[0]?.message).toContain("unhandledRejection");
    expect(harness.exits).toEqual([1]);
  });

  it("logs through the central redactor rather than the raw error", () => {
    const { harness } = install();
    harness.fire({ vaultMasterKey: "should-never-appear", note: "diagnostic" });
    const details = harness.logs[0]?.details as { err: Record<string, unknown> };
    expect(details.err.vaultMasterKey).toBe("[redacted]");
    expect(details.err.note).toBe("diagnostic");
  });
});

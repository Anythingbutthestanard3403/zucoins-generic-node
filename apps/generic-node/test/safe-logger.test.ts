// The production logger is the redactor's only adapter (ZTR-1187). Two failure
// classes are gated here:
//   1. A never-log value reaches the sink instead of the placeholder.
//   2. An entry point grows a raw console call and quietly opts out — the
//      enduring risk, because the redactor exists so a contributor writing a
//      log line under time pressure does not have to think about it.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  createSafeConsoleLogger,
  safeJsonLine,
  type SafeLoggerSink,
} from "../src/boot/safe-logger.js";
import { sanitizeFailureCause } from "../src/runtime-listener.js";

const REDACTED = "[redacted]";

function captureSink(): { sink: SafeLoggerSink; lines: string[] } {
  const lines: string[] = [];
  return {
    lines,
    sink: {
      log: (message) => lines.push(message),
      error: (message, details) =>
        lines.push(details === undefined ? message : `${message} ${JSON.stringify(details)}`),
    },
  };
}

describe("production logger routes through the central redactor", () => {
  it("emits the placeholder, not the value, for a never-log field", () => {
    const line = safeJsonLine({ event: "boot", vaultMasterKey: "MK-UNIQUE-VALUE", ok: true });
    expect(line).not.toContain("MK-UNIQUE-VALUE");
    expect(JSON.parse(line)).toEqual({ event: "boot", vaultMasterKey: REDACTED, ok: true });
  });

  it("keeps a structured line parseable — redaction is by field name, not text", () => {
    const line = safeJsonLine({ password: "p@ss", nested: { apiKeyPlaintext: "zp_live_x" } });
    expect(() => JSON.parse(line) as unknown).not.toThrow();
    expect(line).not.toContain("zp_live_x");
  });

  // The composition main.ts:171-179 actually uses: safeJsonLine serializes the
  // event, then the logger scrubs that JSON as text. The two passes have to
  // agree — a text scrub that eats the closing quote of the last string value
  // hands the operator's aggregator a line it cannot parse, on exactly the
  // events that carried a secret. sanitizeFailureCause runs first, as in
  // production: its keyword list is deliberately narrower than isNeverLog, so
  // these three assignments survive it and reach the scrubber.
  const LISTENER_CAUSES = [
    "vault unlock failed vaultMasterKey=MK-UNIQUE-VALUE",
    "session rejected sessionToken=ST-UNIQUE-VALUE",
    'db auth failed pwd="PW-UNIQUE-VALUE"',
  ];

  for (const cause of LISTENER_CAUSES) {
    it(`keeps the composed listener line parseable and redacted — ${cause}`, () => {
      const { sink, lines } = captureSink();
      createSafeConsoleLogger(sink).error(
        safeJsonLine({
          event: "operation_listener_unexpected_failure",
          request_id: "00000000-0000-4000-8000-0000000000ff",
          method: "POST",
          path_class: "POST /v1/operations",
          ...sanitizeFailureCause(new Error(cause)),
        }),
      );
      expect(lines).toHaveLength(1);
      expect(lines[0]).not.toContain("UNIQUE-VALUE");
      const parsed = JSON.parse(lines[0]) as Record<string, unknown>;
      expect(parsed["event"]).toBe("operation_listener_unexpected_failure");
      expect(parsed["cause_message"]).toContain(REDACTED);
    });
  }

  it("scrubs a never-log assignment out of an info message", () => {
    const { sink, lines } = captureSink();
    createSafeConsoleLogger(sink).info("boot: env loaded VAULT_MASTER_KEY=MK-UNIQUE-VALUE");
    expect(lines).toEqual([`boot: env loaded VAULT_MASTER_KEY=${REDACTED}`]);
  });

  it("scrubs the error's message and stack rather than printing the Error raw", () => {
    const { sink, lines } = captureSink();
    createSafeConsoleLogger(sink).error(
      "fatal: unexpected boot failure",
      new Error("connect failed password=hunter2"),
    );
    expect(lines).toHaveLength(1);
    expect(lines[0]).not.toContain("hunter2");
    expect(lines[0]).toContain(REDACTED);
  });

  it("does not mutate the error the caller passed", () => {
    const { sink } = captureSink();
    const err = new Error("connect failed password=hunter2");
    createSafeConsoleLogger(sink).error("fatal", err);
    expect(err.message).toBe("connect failed password=hunter2");
  });
});

// Source gate. A raw console call in an entry point is exactly the defect this
// ticket fixed; it must not come back one log line at a time.
describe("entry points hold no raw console call", () => {
  const CONSOLE_CALL = /\bconsole\.(log|error|warn|info|debug|trace)\s*\(/;

  for (const entry of ["main.ts", "stage1-main.ts"]) {
    it(`${entry} logs only through the redacting adapter`, () => {
      const source = readFileSync(
        fileURLToPath(new URL(`../src/${entry}`, import.meta.url)),
        "utf8",
      );
      const offenders = source
        .split("\n")
        .map((line, index) => ({ line, number: index + 1 }))
        .filter(({ line }) => CONSOLE_CALL.test(line))
        .map(({ line, number }) => `${entry}:${number}: ${line.trim()}`);
      expect(offenders).toEqual([]);
    });
  }
});

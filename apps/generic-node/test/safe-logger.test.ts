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

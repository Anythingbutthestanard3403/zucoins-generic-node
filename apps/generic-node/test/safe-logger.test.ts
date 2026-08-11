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
  // event, then the logger redacts that line. Both properties have to hold at
  // once, on every quote shape — the operator's aggregator needs a parseable
  // line, and the plaintext must not be in it. Redacting the line as *text*
  // could only ever satisfy one: a quote-consuming pattern eats the string
  // terminator (r0), a quote-refusing one emits the truncated value verbatim
  // (r1). sanitizeFailureCause runs first, as in production — its keyword list
  // is deliberately narrower than isNeverLog, so every assignment below
  // survives it and reaches the redactor.
  //
  // `tail_field` sits after the cause on purpose: a line whose last value is the
  // damaged one hides the class of defect where the scrub runs on across a JSON
  // string boundary into the next field.
  const LISTENER_CAUSES = [
    "vault unlock failed vaultMasterKey=MK-UNIQUE-VALUE",
    "session rejected sessionToken=ST-UNIQUE-VALUE",
    'db auth failed pwd="PW-UNIQUE-VALUE"',
    'db auth failed pwd="PW-UNIQUE-VALUE',
    "db auth failed pwd='PW-UNIQUE-VALUE",
    'db auth failed pwd=\\"PW-UNIQUE-VALUE',
    'session rejected sessionToken="ST-UNIQUE-VALUE',
    // Longer than MAX_CAUSE_MESSAGE_CHARS, so sanitizeFailureCause cuts it
    // mid-value and appends the ellipsis — the truncation shape, produced the
    // way production produces it rather than hand-written.
    `db auth failed pwd="PW-UNIQUE-VALUE${"x".repeat(400)}`,
    // Degenerate assignments: the never-log key is the last thing in the
    // message, so the character after the separator is the JSON terminator.
    "db auth failed pwd=",
    'db auth failed pwd="',
  ];

  for (const cause of LISTENER_CAUSES) {
    it(`keeps the composed listener line parseable and redacted — ${cause.slice(0, 48)}`, () => {
      const { sink, lines } = captureSink();
      createSafeConsoleLogger(sink).error(
        safeJsonLine({
          event: "operation_listener_unexpected_failure",
          request_id: "00000000-0000-4000-8000-0000000000ff",
          method: "POST",
          path_class: "POST /v1/operations",
          ...sanitizeFailureCause(new Error(cause)),
          tail_field: "sentinel",
        }),
      );
      expect(lines).toHaveLength(1);
      expect(lines[0]).not.toContain("UNIQUE-VALUE");
      const parsed = JSON.parse(lines[0]) as Record<string, unknown>;
      expect(parsed["event"]).toBe("operation_listener_unexpected_failure");
      expect(parsed["tail_field"]).toBe("sentinel");
      // Every case but the empty assignment has a value to censor.
      if (!cause.endsWith("pwd=")) expect(parsed["cause_message"]).toContain(REDACTED);
    });
  }

  it("re-redacts a serialized line structurally, not as text", () => {
    const { sink, lines } = captureSink();
    // Fail-closed: a JSON line built anywhere other than safeJsonLine is still
    // redacted, by field name, and stays parseable.
    createSafeConsoleLogger(sink).error(
      JSON.stringify({ event: "x", vaultMasterKey: "MK-UNIQUE-VALUE", tail: "sentinel" }),
    );
    const parsed = JSON.parse(lines[0]) as Record<string, unknown>;
    expect(parsed["vaultMasterKey"]).toBe(REDACTED);
    expect(parsed["tail"]).toBe("sentinel");
  });

  it("scrubs a message that only looks like JSON", () => {
    const { sink, lines } = captureSink();
    createSafeConsoleLogger(sink).info("{not json after all pwd=PW-UNIQUE-VALUE");
    expect(lines).toEqual([`{not json after all pwd=${REDACTED}`]);
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

// ZTR-1215: DR / operator CLIs and the in-process pool error handler must use
// the same redactor seam. A raw console.* in any of these files is the defect.
describe("DR/operator CLI surfaces hold no raw console call (ZTR-1215)", () => {
  const CONSOLE_CALL = /\bconsole\.(log|error|warn|info|debug|trace)\s*\(/;
  const SURFACES = [
    "dr/cli.ts",
    "dr/schedule.ts",
    "db/client.ts",
    "db/migrate.ts",
    "ops/run-recovery-ceremony.ts",
    "operations/rotate-master-key.cli.ts",
  ] as const;

  for (const rel of SURFACES) {
    it(`${rel} logs only through the redacting adapter`, () => {
      const source = readFileSync(
        fileURLToPath(new URL(`../src/${rel}`, import.meta.url)),
        "utf8",
      );
      const offenders = source
        .split("\n")
        .map((line, index) => ({ line, number: index + 1 }))
        .filter(({ line }) => CONSOLE_CALL.test(line))
        // Default parameter `sink: SafeLoggerSink = console` is the injection
        // seam, not a write — allow the bare identifier, refuse the call form.
        .filter(({ line }) => CONSOLE_CALL.test(line))
        .map(({ line, number }) => `${rel}:${number}: ${line.trim()}`);
      expect(offenders).toEqual([]);
    });
  }

  it("createSafeCliIo redacts a bare secret on the DR CLI default sink", async () => {
    const { createSafeCliIo } = await import("../src/boot/safe-logger.js");
    const { REDACTED } = await import("@zucoins/node-core/observability");
    const lines: string[] = [];
    const io = createSafeCliIo({
      log: (m) => lines.push(m),
      error: (m) => lines.push(m),
    });
    const secret = "AbCdEfGhIjKlMnOpQrStUvWx012345";
    io.error(`drill failed postgres://u:${secret}@h/db bare=${secret}`);
    expect(lines).toHaveLength(1);
    expect(lines[0]).not.toContain(secret);
    expect(lines[0]).toContain(REDACTED);
  });

  it("pool idle-error handler redacts a driver message that quotes a DSN password", async () => {
    const { createPool } = await import("../src/db/client.js");
    const { REDACTED } = await import("@zucoins/node-core/observability");
    const secret = "S3cret-Passw0rd-UniqueXX";
    const errors: string[] = [];
    const origError = console.error;
    console.error = (...args: unknown[]) => {
      errors.push(args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" "));
    };
    try {
      const pool = createPool("postgres://user:pass@127.0.0.1:1/does-not-matter");
      try {
        pool.emit(
          "error",
          new Error(`Connection terminated unexpectedly password=${secret}`),
        );
      } finally {
        await pool.end();
      }
    } finally {
      console.error = origError;
    }
    expect(errors.length).toBeGreaterThan(0);
    const joined = errors.join("\n");
    expect(joined).not.toContain(secret);
    expect(joined).toContain(REDACTED);
  });
});

// The console adapter that puts the central redactor in front of every log
// line the composition roots write (ZTR-1187).
//
// safe-log.ts is deliberately framework-free — its header says "adapters wrap
// pino/console via redactLogFields", and until now no adapter did, so whether a
// secret reached stdout depended on whoever wrote each individual log call.
// This is that adapter, and it is the only one: both entry points build their
// logger here, so a new log call cannot opt out of redaction by being written
// somewhere else.
//
// Logs are the one egress nobody makes a decision about. Everything else the
// node emits has a schema, an encryption step, or a body someone wrote; a log
// line is written under time pressure, and on a hosted platform it lands in a
// searchable store that more people can read than can read the database.
//
// Subpath import, not the root barrel — same reason as fatal-exception.ts:
// stage1-main.ts builds its logger here and must not pull node-core's vault /
// signing-key / gateway surfaces into the zero-custody module graph.
// observability is a leaf.
import { redactLogFields, scrubErrorDetails, scrubText } from "@zucoins/node-core/observability";

// Type-only, so this module gains no runtime edge to boot-lane.ts (which does
// import the node-core root barrel).
import type { BootLogger } from "./boot-lane.js";

/** Injection seam so tests never write to the real console. */
export interface SafeLoggerSink {
  log(message: string): void;
  error(message: string, details?: unknown): void;
}

/**
 * JSON line for a structured event. Redaction is structural (by field name)
 * rather than textual, so the emitted line stays parseable JSON.
 */
export function safeJsonLine(fields: Record<string, unknown>): string {
  return JSON.stringify(redactLogFields(fields));
}

/**
 * Redact one line on its way to a text sink.
 *
 * A serialized event line is redacted *structurally* — parsed, run back through
 * redactLogFields, re-serialized — so it stays parseable by construction.
 * Anything else is free text and gets the text scrubber.
 *
 * The split is the point. Composition roots log `safeJsonLine(event)`, so the
 * adapter is handed JSON; the text scrubber has to consume an unbalanced
 * opening quote, because the runtime listener truncates causes at 200 chars and
 * cuts quoted values mid-string. A quote-consuming pattern run across a JSON
 * string terminator destroys the line, and a pattern that refuses quotes leaks
 * exactly those truncated values. Both were tried (ZTR-1187 r0, r1). Neither
 * defect exists once the text pattern never sees JSON.
 *
 * Re-redacting rather than passing the parsed line straight through keeps this
 * fail-closed: a JSON line built anywhere else is still redacted, and both
 * redactLogFields and scrubText are idempotent, so the second pass is a no-op
 * on a line safeJsonLine already produced.
 */
function redactMessage(message: string): string {
  if (message.startsWith("{")) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(message);
    } catch {
      return scrubText(message);
    }
    if (parsed !== null && typeof parsed === "object") {
      return safeJsonLine(parsed as Record<string, unknown>);
    }
  }
  return scrubText(message);
}

/**
 * BootLogger that redacts the message and routes the error through the central
 * redactor. Never mutates what the caller passed — redactLogFields deep-copies,
 * which the money path relies on for byte-exactness.
 */
export function createSafeConsoleLogger(sink: SafeLoggerSink = console): BootLogger {
  return {
    info: (message) => {
      sink.log(redactMessage(message));
    },
    error: (message, err) => {
      if (err === undefined) {
        sink.error(redactMessage(message));
        return;
      }
      // Wrapped in a field, because `message` and `stack` are non-enumerable on
      // Error: the redactor's Error branch is only reached through a value.
      sink.error(redactMessage(message), scrubErrorDetails({ err }));
    },
  };
}

/**
 * One-shot free-text write through the same redactor the BootLogger uses.
 * Operator/DR CLIs that only need `log`/`error` line sinks use this so they
 * cannot bypass the chokepoint by talking to `console` directly.
 */
export function createSafeCliIo(sink: SafeLoggerSink = console): {
  log(line: string): void;
  error(line: string): void;
} {
  return {
    log: (line) => {
      sink.log(redactMessage(line));
    },
    error: (line) => {
      sink.error(redactMessage(line));
    },
  };
}

/**
 * RotationLogger adapter: structured fields go through redactLogFields so a
 * never-log key cannot reach stdout even when the CLI builds the payload.
 */
export function createSafeRotationLogger(sink: SafeLoggerSink = console): {
  info(obj: Record<string, unknown>, msg?: string): void;
  error(obj: Record<string, unknown>, msg?: string): void;
} {
  const emit = (level: "info" | "error", obj: Record<string, unknown>, msg?: string) => {
    const line = safeJsonLine({ level, msg, ...obj });
    if (level === "info") sink.log(line);
    else sink.error(line);
  };
  return {
    info: (obj, msg) => emit("info", obj, msg),
    error: (obj, msg) => emit("error", obj, msg),
  };
}

/**
 * Redact a free-text diagnostic line (no structured fields). Shared by CLI
 * helpers that still format a single string before writing.
 */
export function safeConsoleText(line: string): string {
  return redactMessage(line);
}

/**
 * Format an unknown error for a text sink: message+stack go through scrubText
 * via the Error branch of scrubErrorDetails. Returns a single string so CLI
 * paths that only accept lines stay simple.
 */
export function safeFormatError(err: unknown): string {
  if (err === undefined || err === null) return "";
  const scrubbed = scrubErrorDetails({ err }) as {
    err?: { type?: string; message?: string; stack?: string } | string;
  };
  const body = scrubbed.err;
  if (body === undefined) return safeConsoleText(String(err));
  if (typeof body === "string") return body;
  return body.stack ?? body.message ?? body.type ?? "";
}

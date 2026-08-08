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
 * BootLogger that scrubs the message text and routes the error through the
 * central redactor. Never mutates what the caller passed — redactLogFields
 * deep-copies, which the money path relies on for byte-exactness.
 */
export function createSafeConsoleLogger(sink: SafeLoggerSink = console): BootLogger {
  return {
    info: (message) => {
      sink.log(scrubText(message));
    },
    error: (message, err) => {
      if (err === undefined) {
        sink.error(scrubText(message));
        return;
      }
      // Wrapped in a field, because `message` and `stack` are non-enumerable on
      // Error: the redactor's Error branch is only reached through a value.
      sink.error(scrubText(message), scrubErrorDetails({ err }));
    },
  };
}

// real-PostgreSQL durability for the implementer event log + snapshot
// store over frozen implementer-event-stream.sql.
//
// Proves restart survival (open store A, append, drop reference, open store B, rows remain)
// and that SSE delivery failure cannot undo a committed append.
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  createPgImplementerEventLog,
  type SqlQueryFn as ImplementerEventLogSqlQueryFn,
  type SqlTxFn as ImplementerEventLogSqlTxFn,
} from "../src/reporting/pg-implementer-event-log.ts";
import { createPgSnapshotStore } from "../src/reporting/pg-snapshot-store.ts";
import { createEventStreamAccelerator } from "../src/reporting/event-stream-sse.ts";
import { listEvents } from "../src/reporting/events-read-service.ts";
import type {
  ImplementerEventLog,
  ImplementerStreamEventType,
  StoredImplementerEvent,
} from "../src/reporting/implementer-event-log.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaSql = readFileSync(
  resolve(here, "../src/schema/implementer-event-stream.sql"),
  "utf8",
);

const SCHEMA = "implementer_event_impl_events";
const databaseUrl = process.env.TEST_DATABASE_URL;
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const END_MARKER = "__SQL_END__";

function pgEnv(): NodeJS.ProcessEnv {
  const url = new URL(databaseUrl as string);
  return {
    ...process.env,
    PGHOST: url.hostname,
    PGPORT: url.port || "5432",
    PGUSER: decodeURIComponent(url.username),
    PGPASSWORD: decodeURIComponent(url.password),
    PGDATABASE: url.pathname.replace(/^\//, ""),
  };
}

function sqlLiteral(value: unknown): string {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "number" || typeof value === "bigint") return String(value);
  if (typeof value === "boolean") return value ? "TRUE" : "FALSE";
  if (typeof value === "string") return `'${value.replace(/'/g, "''")}'`;
  throw new Error(`unsupported sql param type: ${typeof value}`);
}

function bindSql(text: string, params: readonly unknown[] = []): string {
  let bound = text;
  for (let n = params.length; n >= 1; n -= 1) {
    const re = new RegExp(`\\$${n}(?!\\d)`, "g");
    bound = bound.replace(re, () => sqlLiteral(params[n - 1]));
  }
  return bound;
}

class PsqlSession {
  private child: ChildProcessWithoutNullStreams | null = null;
  private buffer = "";
  private readonly pending: Array<(payload: string) => void> = [];

  start(): void {
    if (this.child) return;
    this.child = spawn("psql", ["-X", "-q", "-A", "-t", "-v", "VERBOSITY=verbose"], {
      env: pgEnv(),
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.child.stdout.setEncoding("utf8");
    this.child.stderr.setEncoding("utf8");
    this.child.stderr.on("data", (chunk: string) => {
      this.buffer += chunk;
    });
    this.child.stdout.on("data", (chunk: string) => {
      this.buffer += chunk;
      let idx = this.buffer.indexOf(`${END_MARKER}\n`);
      while (idx !== -1) {
        const payload = this.buffer.slice(0, idx);
        this.buffer = this.buffer.slice(idx + END_MARKER.length + 1);
        this.pending.shift()?.(payload);
        idx = this.buffer.indexOf(`${END_MARKER}\n`);
      }
    });
  }

  stop(): void {
    if (!this.child) return;
    try {
      this.child.stdin.end();
    } catch {
      /* ignore */
    }
    this.child.kill("SIGTERM");
    this.child = null;
  }

  private send(sql: string): Promise<string> {
    this.start();
    const child = this.child!;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`psql session timeout: ${sql.slice(0, 80)}`)),
        30_000,
      );
      this.pending.push((payload) => {
        clearTimeout(timer);
        if (/\bERROR:\s+/i.test(payload)) {
          reject(new Error(payload.trim()));
          return;
        }
        resolve(payload);
      });
      child.stdin.write(`${sql};\n\\echo ${END_MARKER}\n`);
    });
  }

  async exec(sql: string): Promise<void> {
    await this.send(sql);
  }

  async queryRows(
    sql: string,
    values: readonly unknown[] = [],
  ): Promise<readonly Record<string, unknown>[]> {
    const bound = bindSql(sql, values).replace(/;\s*$/, "");
    const trimmed = bound.trim();
    const isSelect = /^SELECT\b/i.test(trimmed) || /^WITH\b/i.test(trimmed);
    if (!isSelect) {
      if (/\bRETURNING\b/i.test(trimmed)) {
        // Trailing `-- comment` lines in frozen SQL constants must not be glued to the
        // wrapper's closing paren on the same physical line (SQL line comments run to
        // end-of-line and would swallow it, leaving an unterminated statement that wedges
        // this shared psql session for every query for the rest of the process).
        const wrapped =
          `WITH q AS (\n${trimmed}\n) ` +
          `SELECT COALESCE(json_agg(row_to_json(q)), '[]'::json)::text AS payload FROM q`;
        const out = await this.send(wrapped);
        return this.#parseJsonAgg(out);
      }
      await this.send(trimmed);
      return [];
    }
    // See the RETURNING branch above: keep the closing paren on its own line so a
    // trailing SQL line-comment in `trimmed` can never swallow it.
    const wrapped =
      `SELECT COALESCE(json_agg(row_to_json(q)), '[]'::json)::text AS payload FROM (\n${trimmed}\n) q`;
    const out = await this.send(wrapped);
    return this.#parseJsonAgg(out);
  }

  #parseJsonAgg(out: string): Record<string, unknown>[] {
    const lines = out
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
    const jsonLine = lines[lines.length - 1] ?? "[]";
    return JSON.parse(jsonLine === "" ? "[]" : jsonLine) as Record<string, unknown>[];
  }
}

async function psqlOneShot(sql: string): Promise<string> {
  return new Promise((settle, fail) => {
    const child = spawn(
      "psql",
      ["-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose", "-f", "-"],
      { env: pgEnv(), stdio: ["pipe", "pipe", "pipe"] },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (c: string) => {
      stdout += c;
    });
    child.stderr.on("data", (c: string) => {
      stderr += c;
    });
    child.on("error", fail);
    child.on("close", (code) => {
      if ((code ?? 1) !== 0) fail(new Error(stderr.trim() || stdout.trim()));
      else settle(stdout);
    });
    child.stdin.end(`${sql.trimEnd().endsWith(";") ? sql : `${sql};`}\n`);
  });
}

const inSchema = (sql: string): string => `SET search_path TO ${SCHEMA};\n${sql}`;

let session: PsqlSession | null = null;

const query: ImplementerEventLogSqlQueryFn = async (text, values) => {
  if (!session) throw new Error("psql session not started");
  return session.queryRows(text, values);
};

const withTransaction: ImplementerEventLogSqlTxFn = async (body) => {
  if (!session) throw new Error("psql session not started");
  await session.exec("BEGIN");
  try {
    const result = await body(query);
    await session.exec("COMMIT");
    return result;
  } catch (error) {
    try {
      await session.exec("ROLLBACK");
    } catch {
      /* session may already be aborted */
    }
    throw error;
  }
};

const nodeId = randomUUID();
const implementerId = randomUUID();

// removed the caller-less `append` from ImplementerEventLog / createPgImplementerEventLog
// — event-log/dual-chain-appender.ts is now the sole durable writer of implementer_events. This
// harness reproduces the exact ensure/lock/insert/advance sequence the deleted adapter method
// used to run (no previous-hash lookup: implementer_events carries no chain-hash column, chain
// continuity lives inside the caller-supplied proof_representation bytes), so the coverage below
// keeps exercising real inserts against the real schema instead of a synthetic seam.
const ENSURE_COUNTER = `
INSERT INTO implementer_event_seq_counters (node_id, implementer_id, next_seq)
VALUES ($1::uuid, $2::uuid, 1)
ON CONFLICT (node_id, implementer_id) DO NOTHING
`;

const LOCK_COUNTER = `
SELECT next_seq FROM implementer_event_seq_counters
 WHERE node_id = $1::uuid AND implementer_id = $2::uuid
 FOR UPDATE
`;

const ADVANCE_COUNTER = `
UPDATE implementer_event_seq_counters
   SET next_seq = $3::bigint
 WHERE node_id = $1::uuid AND implementer_id = $2::uuid AND next_seq = $4::bigint
RETURNING next_seq
`;

const INSERT_EVENT = `
INSERT INTO implementer_events (
  node_id, implementer_id, implementer_seq, event_id, event_type,
  proof_representation, created_at
) VALUES (
  $1::uuid, $2::uuid, $3::bigint, $4::uuid, $5::text, $6::text, $7::timestamptz
)
`;

interface RawAppendInput {
  readonly implementerId: string;
  readonly eventId: string;
  readonly eventType: ImplementerStreamEventType;
  readonly proofRepresentation: string;
  readonly createdAt: string;
}

async function appendRaw(input: RawAppendInput): Promise<StoredImplementerEvent> {
  return withTransaction(async (tx) => {
    await tx(ENSURE_COUNTER, [nodeId, input.implementerId]);
    const locked = await tx(LOCK_COUNTER, [nodeId, input.implementerId]);
    const lockRow = locked[0];
    if (lockRow === undefined) {
      throw new Error("implementer_event_seq_counters row missing after ensure");
    }
    const nextSeq = BigInt(lockRow.next_seq as number | string);
    await tx(INSERT_EVENT, [
      nodeId,
      input.implementerId,
      nextSeq.toString(),
      input.eventId,
      input.eventType,
      input.proofRepresentation,
      input.createdAt,
    ]);
    const advanced = await tx(ADVANCE_COUNTER, [
      nodeId,
      input.implementerId,
      (nextSeq + 1n).toString(),
      nextSeq.toString(),
    ]);
    if (advanced[0] === undefined) {
      throw new Error("implementer_seq counter advance lost race under lock");
    }
    return Object.freeze({
      implementerSeq: nextSeq,
      eventType: input.eventType,
      proofRepresentation: input.proofRepresentation,
      eventId: input.eventId,
      createdAt: input.createdAt,
    });
  });
}

function makeLog(): ImplementerEventLog {
  return createPgImplementerEventLog({ nodeId, query, withTransaction });
}

let schemaReady = false;

beforeAll(async () => {
  if (!databaseUrl) return;
  await psqlOneShot(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
  await psqlOneShot(`CREATE SCHEMA ${SCHEMA}`);
  await psqlOneShot(inSchema(schemaSql));
  session = new PsqlSession();
  session.start();
  await session.exec(`SET search_path TO ${SCHEMA}`);
  schemaReady = true;
}, 120_000);

afterAll(async () => {
  session?.stop();
  session = null;
  if (!databaseUrl) return;
  try {
    await psqlOneShot(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
  } catch {
    /* best-effort */
  }
});

describe.skipIf(!databaseUrl)("implementer event stream PG durability", () => {
  it("appends gapless implementer_seq and serves exclusive after pages", async () => {
    expect(schemaReady).toBe(true);
    const log = makeLog();
    const a = await appendRaw({
      implementerId,
      eventId: randomUUID(),
      eventType: "receive.ready",
      proofRepresentation: '{"purpose":"zp-implementer-event-v1","implementer_seq":"1"}',
      createdAt: "2026-07-18T00:00:00.000Z",
    });
    const b = await appendRaw({
      implementerId,
      eventId: randomUUID(),
      eventType: "receive.landed",
      proofRepresentation: '{"purpose":"zp-implementer-event-v1","implementer_seq":"2"}',
      createdAt: "2026-07-18T00:00:01.000Z",
    });
    expect(a.implementerSeq).toBe(1n);
    expect(b.implementerSeq).toBe(2n);
    expect(await log.watermark(implementerId)).toBe(2n);

    const page = await listEvents(log, {
      implementerId,
      afterImplementerSeq: 1n,
      limit: 10,
    });
    expect(page.events.map((e) => e.implementerSeq)).toEqual([2n]);
    expect(page.watermarkSeq).toBe(2n);
  });

  it("restart: a fresh log instance resumes from durable watermark with no reuse", async () => {
    expect(schemaReady).toBe(true);
    // Drop the prior reference — new adapter instance over the same DB.
    const restarted = makeLog();
    expect(await restarted.watermark(implementerId)).toBe(2n);
    const c = await appendRaw({
      implementerId,
      eventId: randomUUID(),
      eventType: "operation.needs_attention",
      proofRepresentation: '{"implementer_seq":"3"}',
      createdAt: "2026-07-18T00:00:02.000Z",
    });
    expect(c.implementerSeq).toBe(3n);

    const again = makeLog();
    const page = await again.readEvents(implementerId, null, 10);
    expect(page.events.map((e) => e.implementerSeq)).toEqual([1n, 2n, 3n]);
    expect(page.events[0]?.proofRepresentation).toContain("zp-implementer-event-v1");
  });

  it("SSE kill after commit leaves durable row intact (failure irrelevance)", async () => {
    expect(schemaReady).toBe(true);
    const log = makeLog();
    const before = await log.watermark(implementerId);
    const stored = await appendRaw({
      implementerId,
      eventId: randomUUID(),
      eventType: "external_send.landed",
      proofRepresentation: `{"event":"external_send.landed","seq":"${before + 1n}"}`,
      createdAt: "2026-07-18T00:00:03.000Z",
    });

    const chunks: string[] = [];
    const accel = createEventStreamAccelerator({ log, pollMs: 0 });
    const outcome = await accel.open(
      {
        requestId: "r1",
        implementerId,
        afterImplementerSeq: before,
        lastEventId: before === 0n ? null : before.toString(),
      },
      {
        write: (c) => {
          chunks.push(c);
        },
        close: () => undefined,
      },
    );
    expect(outcome.kind).toBe("OPEN");
    if (outcome.kind !== "OPEN") return;
    // Kill stream immediately after open (delivery aborted).
    outcome.connection.close();

    // Pull route still serves the committed event byte-identically.
    const page = await makeLog().readEvents(implementerId, before, 10);
    expect(page.events.some((e) => e.implementerSeq === stored.implementerSeq)).toBe(true);
    const found = page.events.find((e) => e.implementerSeq === stored.implementerSeq);
    expect(found?.proofRepresentation).toBe(stored.proofRepresentation);
  });

  it("snapshot store survives restart at the captured watermark", async () => {
    expect(schemaReady).toBe(true);
    const log = makeLog();
    const watermark = await log.watermark(implementerId);
    const storeA = createPgSnapshotStore({ nodeId, query });
    await storeA.save({
      implementerId,
      implementerWatermarkSeq: watermark.toString(),
      operations: [
        {
          operationId: randomUUID(),
          operationType: "RECEIVE_EXTERNAL",
          state: "READY",
          rowVersion: 1,
          attentionRequired: false,
          updatedAt: "2026-07-18T00:00:00.000Z",
        },
      ],
      destinations: [],
      attentionItems: [],
      capturedAt: "2026-07-18T12:00:00.000Z",
    });

    const storeB = createPgSnapshotStore({ nodeId, query });
    const latest = await storeB.latest(implementerId);
    expect(latest).not.toBeNull();
    expect(latest?.implementerWatermarkSeq).toBe(watermark.toString());
    expect(latest?.operations).toHaveLength(1);
  });

  it("TX rollback on mid-append failure burns no implementer_seq", async () => {
    expect(schemaReady).toBe(true);
    const log = makeLog();
    const before = await log.watermark(implementerId);
    // Force failure via a colliding event_id — the schema's UNIQUE (node_id, implementer_id,
    // event_id) constraint fires mid-INSERT, appendRaw's withTransaction catches, ROLLBACKs,
    // and rethrows (same as the deleted adapter method did).
    const eventId = randomUUID();
    await appendRaw({
      implementerId,
      eventId,
      eventType: "receive.ready",
      proofRepresentation: '{"x":1}',
      createdAt: "2026-07-18T00:00:10.000Z",
    });
    const mid = await log.watermark(implementerId);
    expect(mid).toBe(before + 1n);

    await expect(
      appendRaw({
        implementerId,
        eventId, // unique violation
        eventType: "receive.ready",
        proofRepresentation: '{"x":2}',
        createdAt: "2026-07-18T00:00:11.000Z",
      }),
    ).rejects.toThrow();

    expect(await makeLog().watermark(implementerId)).toBe(mid);
  });
});

describe("implementer event stream PG gate", () => {
  it("does not silently skip under PG_REQUIRED", () => {
    if (PG_REQUIRED && !databaseUrl) {
      throw new Error("PG_REQUIRED=1 but TEST_DATABASE_URL is unset");
    }
    if (PG_REQUIRED && databaseUrl && !schemaReady) {
      throw new Error("PG_REQUIRED=1 but implementer-event-stream schema setup failed");
    }
    expect(true).toBe(true);
  });
});

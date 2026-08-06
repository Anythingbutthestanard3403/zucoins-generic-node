// real-PostgreSQL durability for the event list over frozen
// event-ledger.sql (node_event_seq_counters + node_events).
//
// D-B2: BEGIN/body/COMMIT share one long-lived psql session so adapter TX atomicity
// is exercised (fresh-psql-per-statement cannot roll back prior work).
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  EventListService,
  createPgEventListStore,
  type EventAppendInput,
  type EventListStore,
  type EventLogSqlQueryFn,
  type EventLogSqlTxFn,
  type EventRecord,
} from "../src/event-log/index.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaFile = (name: string): string =>
  readFileSync(resolve(here, "../src/schema", name), "utf8");

const eventLedgerSql = schemaFile("event-ledger.sql");

function frozenDeclaration(sql: string, opening: string): string {
  const start = sql.indexOf(opening);
  if (start === -1) throw new Error(`frozen declaration not found: ${opening}`);
  const end = sql.indexOf(";", start);
  if (end === -1) throw new Error(`unterminated frozen declaration: ${opening}`);
  return `${sql.slice(start, end + 1)}\n`;
}

const SCHEMA = "event_log_event_log";
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
  // Replace highest placeholders first so $1 does not consume the leading digits of $10+.
  let bound = text;
  for (let n = params.length; n >= 1; n -= 1) {
    const re = new RegExp(`\\$${n}(?!\\d)`, "g");
    bound = bound.replace(re, () => sqlLiteral(params[n - 1]));
  }
  return bound;
}

/**
 * One long-lived psql connection. Statements share a backend so BEGIN…body…COMMIT/ROLLBACK
 * are a real single-session transaction (D-B2 clearance).
 */
class PsqlSession {
  private child: ChildProcessWithoutNullStreams | null = null;
  private buffer = "";
  private readonly pending: Array<(payload: string) => void> = [];

  start(): void {
    if (this.child) return;
    // No ON_ERROR_STOP: a mid-tx failure must leave the session alive for ROLLBACK.
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

  async queryRows(sql: string, values: readonly unknown[] = []): Promise<readonly Record<string, unknown>[]> {
    const bound = bindSql(sql, values).replace(/;\s*$/, "");
    const trimmed = bound.trim();
    const isSelect = /^SELECT\b/i.test(trimmed) || /^WITH\b/i.test(trimmed);
    if (!isSelect) {
      // DML may carry RETURNING. UPDATE/INSERT cannot appear in FROM (...); use WITH.
      if (/\bRETURNING\b/i.test(trimmed)) {
        const wrapped =
          `WITH q AS (${trimmed}) ` +
          `SELECT COALESCE(json_agg(row_to_json(q)), '[]'::json)::text AS payload FROM q`;
        const out = await this.send(wrapped);
        return this.#parseJsonAgg(out);
      }
      await this.send(trimmed);
      return [];
    }
    const wrapped =
      `SELECT COALESCE(json_agg(row_to_json(q)), '[]'::json)::text AS payload FROM (${trimmed}) q`;
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

/** Autocommit one-shot (schema setup / teardown only — not used for adapter TX). */
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

// Shared session for all adapter traffic — single backend, real TX scope.
let session: PsqlSession | null = null;

const query: EventLogSqlQueryFn = async (text, values) => {
  if (!session) throw new Error("psql session not started");
  // Ensure search_path on every statement (session-level SET at start also applied).
  return session.queryRows(text, values);
};

const withTransaction: EventLogSqlTxFn = async (body) => {
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

const SIGNATURE = `${"A".repeat(86)}==`;
const PUBKEY = `${"A".repeat(43)}=`;

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

const nodeId = randomUUID();
const signingKeyId = randomUUID();

function appendInput(overrides: Partial<EventAppendInput> = {}): EventAppendInput {
  const dataText = overrides.dataText ?? '{"amount_zkz":"1"}';
  const dataSha256 = overrides.dataSha256 ?? sha256Hex(dataText);
  const eventId = overrides.eventId ?? randomUUID();
  const preimageText =
    overrides.preimageText ??
    `zp-node-event-v1\n{"purpose":"zp-node-event-v1","event_id":"${eventId}"}`;
  return {
    eventId,
    operationId: null,
    walletId: null,
    eventType: "receive.ready",
    dataText,
    dataSha256,
    purpose: "zp-node-event-v1",
    canonicalVersion: 1,
    preimageText,
    preimageSha256: sha256Hex(preimageText),
    signingKeyId,
    signature: SIGNATURE,
    createdAt: "2026-07-18T00:00:00.000Z",
    ...overrides,
  };
}

function makeService(): EventListService {
  const store = createPgEventListStore({ query, withTransaction });
  return new EventListService(store, { nodeId });
}

function makeStore(): EventListStore {
  return createPgEventListStore({ query, withTransaction });
}

let schemaReady = false;

beforeAll(async () => {
  if (!databaseUrl) return;
  await psqlOneShot(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
  await psqlOneShot(`CREATE SCHEMA ${SCHEMA}`);

  const domains = [
    frozenDeclaration(eventLedgerSql, "CREATE DOMAIN sha256_hex AS text"),
    frozenDeclaration(eventLedgerSql, "CREATE DOMAIN padded_base64url_signature AS text"),
  ].join("\n");
  await psqlOneShot(inSchema(domains));

  await psqlOneShot(
    inSchema(`
CREATE TABLE nodes (
  id uuid PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE node_signing_keys (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  public_key text NOT NULL,
  purpose text NOT NULL DEFAULT 'EVENT_SIGNING',
  activated_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz
);
CREATE TABLE operations (id uuid PRIMARY KEY);
CREATE TABLE wallets (id uuid PRIMARY KEY);
`),
  );

  const tablesAndTriggers = eventLedgerSql
    .replace(/CREATE DOMAIN sha256_hex AS text[\s\S]*?;/, "")
    .replace(/CREATE DOMAIN padded_base64url_signature AS text[\s\S]*?;/, "");
  await psqlOneShot(inSchema(tablesAndTriggers));

  await psqlOneShot(inSchema(`INSERT INTO nodes (id) VALUES ('${nodeId}'::uuid)`));
  await psqlOneShot(
    inSchema(
      `INSERT INTO node_signing_keys (id, node_id, public_key) VALUES ('${signingKeyId}'::uuid, '${nodeId}'::uuid, '${PUBKEY}')`,
    ),
  );

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

describe.skipIf(!databaseUrl)("event-log PG durability", () => {
  it("appends gapless seq and serves exclusive after_seq pages with full envelope columns", async () => {
    expect(schemaReady).toBe(true);
    const svc = makeService();
    const a = await svc.append(appendInput());
    const b = await svc.append(appendInput());
    expect(a.seq).toBe(1n);
    expect(b.seq).toBe(2n);
    expect(b.previousEventHash).toBe(a.eventHash);
    expect(a.purpose).toBe("zp-node-event-v1");
    expect(a.canonicalVersion).toBe(1);
    expect(a.preimageText.startsWith("zp-node-event-v1\n")).toBe(true);
    expect(a.signingKeyId).toBe(signingKeyId);
    expect(a.signature).toBe(SIGNATURE);
    // EVENT_HASH_RULE default — not an invented internal chain hash.
    expect(a.eventHash).toMatch(/^[0-9a-f]{64}$/);
    expect(a.eventHash).toBe(
      createHash("sha256")
        .update(Buffer.concat([Buffer.from(a.preimageText, "utf8"), Buffer.from(a.signature, "base64url")]))
        .digest("hex"),
    );

    const page = await svc.scanAfter(null, 10);
    expect(page.events.map((e) => e.seq)).toEqual([1n, 2n]);
    expect(page.watermarkSeq).toBe(2n);
    expect(page.nextAfterSeq).toBe(2n);

    const afterFirst = await svc.scanAfter(1n, 10);
    expect(afterFirst.events.map((e) => e.seq)).toEqual([2n]);
    expect(afterFirst.nextAfterSeq).toBe(2n);
  });

  it("restart: a fresh service instance resumes from durable high-water with no reuse", async () => {
    expect(schemaReady).toBe(true);
    const restarted = makeService();
    expect(await restarted.highWater()).toBe(2n);
    const c = await restarted.append(appendInput());
    expect(c.seq).toBe(3n);
    expect(await restarted.highWater()).toBe(3n);

    const again = makeService();
    const d = await again.append(appendInput());
    expect(d.seq).toBe(4n);
  });

  it("adapter TX rollback burns no seq — mid-batch failure rolls back insert + counter", async () => {
    expect(schemaReady).toBe(true);
    const svc = makeService();
    const before = await svc.highWater();
    const store = makeStore();
    const tail = await store.readTail(nodeId);
    expect(tail.highWater).toBe(before);

    // Build a two-record batch where the second event_id collides with the first already-durable
    // row — INSERT of record 2 fails inside createPgEventListStore.appendBatch's withTransaction;
    // both inserts and the counter advance must roll back on the same session.
    const existing = await svc.find(1n);
    expect(existing).not.toBeNull();
    const firstNewId = randomUUID();
    const collidingId = existing!.eventId;

    const mkRecord = (seq: bigint, eventId: string, prev: string | null, eventHash: string): EventRecord =>
      Object.freeze({
        seq,
        eventId,
        purpose: "zp-node-event-v1" as const,
        canonicalVersion: 1 as const,
        nodeId,
        operationId: null,
        walletId: null,
        eventType: "receive.ready" as const,
        dataText: '{"amount_zkz":"1"}',
        dataSha256: sha256Hex('{"amount_zkz":"1"}'),
        preimageText: `zp-node-event-v1\n{"event_id":"${eventId}"}`,
        preimageSha256: sha256Hex(`zp-node-event-v1\n{"event_id":"${eventId}"}`),
        signingKeyId,
        signature: SIGNATURE,
        previousEventHash: prev,
        eventHash,
        createdAt: "2026-07-18T00:00:00.000Z",
      });

    const r1Hash = createHash("sha256")
      .update(
        Buffer.concat([
          Buffer.from(`zp-node-event-v1\n{"event_id":"${firstNewId}"}`, "utf8"),
          Buffer.from(SIGNATURE, "base64url"),
        ]),
      )
      .digest("hex");
    const r2Hash = createHash("sha256")
      .update(
        Buffer.concat([
          Buffer.from(`zp-node-event-v1\n{"event_id":"${collidingId}"}`, "utf8"),
          Buffer.from(SIGNATURE, "base64url"),
        ]),
      )
      .digest("hex");

    const batch = [
      mkRecord(before + 1n, firstNewId, tail.lastEventHash, r1Hash),
      mkRecord(before + 2n, collidingId, r1Hash, r2Hash),
    ];

    await expect(store.appendBatch(nodeId, batch, before)).rejects.toThrow();

    const after = await makeService().highWater();
    expect(after).toBe(before);
    // First-of-batch row must not have leaked.
    const leaked = await session!.queryRows(
      `SELECT seq FROM node_events WHERE node_id = $1::uuid AND event_id = $2::uuid`,
      [nodeId, firstNewId],
    );
    expect(leaked).toEqual([]);

    const next = await makeService().append(appendInput());
    expect(next.seq).toBe(before + 1n);
  });

  it("chain verify walks the durable stream, recomputing EVENT_HASH_RULE", async () => {
    expect(schemaReady).toBe(true);
    const svc = makeService();
    const result = await svc.verifyChain();
    expect(result.ok).toBe(true);
    expect(result.eventCount).toBeGreaterThanOrEqual(4);
  });
});

describe("event-log PG gate", () => {
  it("does not silently skip under PG_REQUIRED", () => {
    if (PG_REQUIRED && !databaseUrl) {
      throw new Error("PG_REQUIRED=1 but TEST_DATABASE_URL is unset");
    }
    if (PG_REQUIRED && databaseUrl && !schemaReady) {
      throw new Error("PG_REQUIRED=1 but event-log schema setup failed");
    }
    expect(true).toBe(true);
  });
});

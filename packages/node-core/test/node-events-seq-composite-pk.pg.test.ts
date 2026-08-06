// real-PostgreSQL proof that two nodes sharing one database
// can append concurrently without node_events_pkey collision, each keeping an
// independent gapless hash chain and cursor resume.
//
// Also proves the brownfield ALTER (node-events-seq-composite-pk.sql) rewrites a
// table that still carries the legacy single-column `seq` primary key.
//
// Harness mirrors event-log.pg.test.ts (long-lived psql session per connection).
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
  type EventLogSqlQueryFn,
  type EventLogSqlTxFn,
} from "../src/event-log/index.ts";
import {
  NODE_EVENTS_SEQ_COMPOSITE_PK_INVARIANTS,
  NODE_EVENTS_SEQ_COMPOSITE_PK_SCHEMA_FILE,
} from "../src/schema/node-events-seq-composite-pk.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaFile = (name: string): string =>
  readFileSync(resolve(here, "../src/schema", name), "utf8");

const eventLedgerSql = schemaFile("event-ledger.sql");
const compositePkSql = schemaFile(NODE_EVENTS_SEQ_COMPOSITE_PK_SCHEMA_FILE);

function frozenDeclaration(sql: string, opening: string): string {
  const start = sql.indexOf(opening);
  if (start === -1) throw new Error(`frozen declaration not found: ${opening}`);
  const end = sql.indexOf(";", start);
  if (end === -1) throw new Error(`unterminated frozen declaration: ${opening}`);
  return `${sql.slice(start, end + 1)}\n`;
}

const SCHEMA = "node_events_seq_node_events_pk";
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
    return new Promise((resolvePromise, reject) => {
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
        resolvePromise(payload);
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

const SIGNATURE = `${"A".repeat(86)}==`;
const PUBKEY = `${"A".repeat(43)}=`;

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

const nodeA = randomUUID();
const nodeB = randomUUID();
const keyA = randomUUID();
const keyB = randomUUID();

function appendInput(signingKeyId: string, overrides: Partial<EventAppendInput> = {}): EventAppendInput {
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
    createdAt: "2026-08-02T00:00:00.000Z",
    ...overrides,
  };
}

function makeService(
  nodeId: string,
  query: EventLogSqlQueryFn,
  withTransaction: EventLogSqlTxFn,
): EventListService {
  const store = createPgEventListStore({ query, withTransaction });
  return new EventListService(store, { nodeId });
}

function makeSessionPorts(session: PsqlSession): {
  query: EventLogSqlQueryFn;
  withTransaction: EventLogSqlTxFn;
} {
  const query: EventLogSqlQueryFn = async (text, values) => session.queryRows(text, values);
  const withTransaction: EventLogSqlTxFn = async (body) => {
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
  return { query, withTransaction };
}

/** Legacy single-column PK shape — what already-applied DBs still carry before the ALTER. */
const LEGACY_NODE_EVENTS_DDL = `
CREATE TABLE node_events (
  seq bigint PRIMARY KEY,
  event_id uuid NOT NULL UNIQUE,
  purpose text NOT NULL DEFAULT 'zp-node-event-v1'
    CHECK (purpose = 'zp-node-event-v1'),
  canonical_version integer NOT NULL CHECK (canonical_version = 1),
  node_id uuid NOT NULL REFERENCES nodes(id),
  operation_id uuid REFERENCES operations(id),
  wallet_id uuid REFERENCES wallets(id),
  event_type text NOT NULL CHECK (event_type IN (
    'receive.ready',
    'receive.landed',
    'internal_move.created',
    'internal_move.landed',
    'external_send.created',
    'external_send.awaiting_redemption',
    'external_send.landed',
    'operation.needs_attention',
    'operation.expired'
  )),
  data_text text NOT NULL,
  data_sha256 sha256_hex NOT NULL,
  preimage_text text NOT NULL,
  preimage_sha256 sha256_hex NOT NULL,
  signing_key_id uuid NOT NULL REFERENCES node_signing_keys(id),
  signature padded_base64url_signature NOT NULL,
  previous_event_hash sha256_hex,
  event_hash sha256_hex NOT NULL UNIQUE,
  created_at timestamptz NOT NULL
);
CREATE FUNCTION reporting_reject_immutable_change()
RETURNS trigger LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: % is forbidden', TG_TABLE_NAME, TG_OP
    USING ERRCODE = '55000';
END
$$;
CREATE TRIGGER node_events_no_update
  BEFORE UPDATE ON node_events
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER node_events_no_delete
  BEFORE DELETE ON node_events
  FOR EACH ROW EXECUTE FUNCTION reporting_reject_immutable_change();
CREATE TRIGGER node_events_no_truncate
  BEFORE TRUNCATE ON node_events
  FOR EACH STATEMENT EXECUTE FUNCTION reporting_reject_immutable_change();
`;

let sessionA: PsqlSession | null = null;
let sessionB: PsqlSession | null = null;
let schemaReady = false;
let drillsRan = 0;

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
CREATE TABLE node_event_seq_counters (
  node_id uuid PRIMARY KEY REFERENCES nodes(id),
  next_seq bigint NOT NULL DEFAULT 1 CHECK (next_seq > 0)
);
`),
  );

  // Brownfield: install the LEGACY single-column PK, then run the fix-forward ALTER.
  await psqlOneShot(inSchema(LEGACY_NODE_EVENTS_DDL));
  await psqlOneShot(inSchema(compositePkSql));

  await psqlOneShot(
    inSchema(`
INSERT INTO nodes (id) VALUES ('${nodeA}'::uuid), ('${nodeB}'::uuid);
INSERT INTO node_signing_keys (id, node_id, public_key) VALUES
  ('${keyA}'::uuid, '${nodeA}'::uuid, '${PUBKEY}'),
  ('${keyB}'::uuid, '${nodeB}'::uuid, '${PUBKEY}');
`),
  );

  sessionA = new PsqlSession();
  sessionB = new PsqlSession();
  sessionA.start();
  sessionB.start();
  await sessionA.exec(`SET search_path TO ${SCHEMA}`);
  await sessionB.exec(`SET search_path TO ${SCHEMA}`);
  schemaReady = true;
}, 120_000);

afterAll(async () => {
  sessionA?.stop();
  sessionB?.stop();
  sessionA = null;
  sessionB = null;
  if (!databaseUrl) return;
  try {
    await psqlOneShot(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
  } catch {
    /* best-effort */
  }
});

describe("node-events-seq-composite-pk contract census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = NODE_EVENTS_SEQ_COMPOSITE_PK_INVARIANTS.filter(
      (invariant) => !compositePkSql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });
});

describe.skipIf(!databaseUrl)(
  "node_events composite PK two-node concurrent append",
  () => {
    it("ALTER rewrote the live primary key to (node_id, seq)", async () => {
      expect(schemaReady).toBe(true);
      const rows = await sessionA!.queryRows(`
SELECT array_agg(att.attname::text ORDER BY u.ord) AS pk_cols
  FROM pg_constraint c
  JOIN pg_class rel ON rel.oid = c.conrelid
  JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
  JOIN unnest(c.conkey) WITH ORDINALITY AS u(attnum, ord) ON true
  JOIN pg_attribute att ON att.attrelid = c.conrelid AND att.attnum = u.attnum
 WHERE nsp.nspname = current_schema()
   AND rel.relname = 'node_events'
   AND c.conname = 'node_events_pkey'
   AND c.contype = 'p'
`);
      expect(rows[0]?.pk_cols).toEqual(["node_id", "seq"]);
      drillsRan += 1;
    });

    it("two nodes append concurrently: no pkey collision, per-node chain + cursor resume", async () => {
      expect(schemaReady).toBe(true);
      const portsA = makeSessionPorts(sessionA!);
      const portsB = makeSessionPorts(sessionB!);
      const svcA = makeService(nodeA, portsA.query, portsA.withTransaction);
      const svcB = makeService(nodeB, portsB.query, portsB.withTransaction);

      // Concurrent: both nodes allocate seq=1..N in the same shared table without disjoint ranges.
      const PER_NODE = 8;
      const tasksA = Array.from({ length: PER_NODE }, (_, i) =>
        () => svcA.append(appendInput(keyA, { dataText: `{"node":"A","i":${i}}` })),
      );
      const tasksB = Array.from({ length: PER_NODE }, (_, i) =>
        () => svcB.append(appendInput(keyB, { dataText: `{"node":"B","i":${i}}` })),
      );

      // Interleave starts so both backends race under real locking; each service serializes
      // its own chain via the per-node counter FOR UPDATE, but the two nodes must not collide.
      const results = await Promise.all([
        (async () => {
          const out = [];
          for (const t of tasksA) out.push(await t());
          return out;
        })(),
        (async () => {
          const out = [];
          for (const t of tasksB) out.push(await t());
          return out;
        })(),
      ]);

      const [recsA, recsB] = results;
      expect(recsA.map((r) => r.seq)).toEqual(
        Array.from({ length: PER_NODE }, (_, i) => BigInt(i + 1)),
      );
      expect(recsB.map((r) => r.seq)).toEqual(
        Array.from({ length: PER_NODE }, (_, i) => BigInt(i + 1)),
      );

      // Independent hash chains (genesis previous = null; each link binds prior on that node).
      expect(recsA[0]!.previousEventHash).toBeNull();
      expect(recsB[0]!.previousEventHash).toBeNull();
      for (let i = 1; i < PER_NODE; i += 1) {
        expect(recsA[i]!.previousEventHash).toBe(recsA[i - 1]!.eventHash);
        expect(recsB[i]!.previousEventHash).toBe(recsB[i - 1]!.eventHash);
      }
      // Chains must not cross-link across nodes.
      expect(recsA[0]!.eventHash).not.toBe(recsB[0]!.eventHash);

      // Table holds 2 * PER_NODE rows; equal seq values coexist across node_id.
      const counts = await sessionA!.queryRows(
        `SELECT node_id::text AS node_id, count(*)::text AS n,
                min(seq)::text AS min_seq, max(seq)::text AS max_seq
           FROM node_events
          GROUP BY node_id
          ORDER BY node_id`,
      );
      expect(counts).toHaveLength(2);
      for (const row of counts) {
        expect(row.n).toBe(String(PER_NODE));
        expect(row.min_seq).toBe("1");
        expect(row.max_seq).toBe(String(PER_NODE));
      }

      // Cursor resume: exclusive after_seq pages and high-water are per-node.
      expect(await svcA.highWater()).toBe(BigInt(PER_NODE));
      expect(await svcB.highWater()).toBe(BigInt(PER_NODE));
      const pageA = await svcA.scanAfter(null, 100);
      const pageB = await svcB.scanAfter(null, 100);
      expect(pageA.events.map((e) => e.seq)).toEqual(
        Array.from({ length: PER_NODE }, (_, i) => BigInt(i + 1)),
      );
      expect(pageB.events.map((e) => e.seq)).toEqual(
        Array.from({ length: PER_NODE }, (_, i) => BigInt(i + 1)),
      );
      expect(pageA.events.every((e) => e.nodeId === nodeA)).toBe(true);
      expect(pageB.events.every((e) => e.nodeId === nodeB)).toBe(true);

      const midA = await svcA.scanAfter(4n, 100);
      expect(midA.events.map((e) => e.seq)).toEqual([5n, 6n, 7n, 8n]);
      expect(midA.nextAfterSeq).toBe(8n);

      // Fresh service instances resume from durable high-water with no reuse.
      const restartedA = makeService(nodeA, portsA.query, portsA.withTransaction);
      const nextA = await restartedA.append(appendInput(keyA, { dataText: '{"node":"A","resume":true}' }));
      expect(nextA.seq).toBe(BigInt(PER_NODE + 1));
      expect(nextA.previousEventHash).toBe(recsA[PER_NODE - 1]!.eventHash);

      const verifyA = await restartedA.verifyChain();
      expect(verifyA.ok).toBe(true);
      expect(verifyA.eventCount).toBe(PER_NODE + 1);

      const restartedB = makeService(nodeB, portsB.query, portsB.withTransaction);
      const verifyB = await restartedB.verifyChain();
      expect(verifyB.ok).toBe(true);
      expect(verifyB.eventCount).toBe(PER_NODE);

      // Idempotent re-apply of the ALTER is a no-op on the composite key.
      await psqlOneShot(inSchema(compositePkSql));
      drillsRan += 1;
    });
  },
);

describe("node_events composite PK PG gate", () => {
  it("does not silently skip under PG_REQUIRED", () => {
    if (PG_REQUIRED && !databaseUrl) {
      throw new Error("PG_REQUIRED=1 but TEST_DATABASE_URL is unset");
    }
    if (PG_REQUIRED && databaseUrl && !schemaReady) {
      throw new Error("PG_REQUIRED=1 but node_events composite-pk schema setup failed");
    }
    if (PG_REQUIRED && databaseUrl && drillsRan < 2) {
      throw new Error(
        "PostgreSQL was reachable but the real-PG two-node composite-pk drills did not all run — undischarged",
      );
    }
    expect(true).toBe(true);
  });
});

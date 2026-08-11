/**
 * operation-route-store.pg.test.ts.
 *
 * Disposable PostgreSQL: create + query admits for RECEIVE_EXTERNAL, MOVE_INTERNAL,
 * and SEND_EXTERNAL via createSqlOperationRouteStore, without live ZKZ / gateway.
 *
 * Also pins the one-in-flight-per-wallet rule (one-in-flight-per-wallet) and rule 4 (idempotent replay /
 * no blind second create) through the engines' DB constraints, not fakes.
 */
import { createHash, createPrivateKey, randomUUID, sign as edSign } from "node:crypto";
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { readFileSync } from "node:fs";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createSqlOperationRouteStore } from "../src/operation-route-store.js";
import { SqlReceiveAdmissionStore } from "../src/receive/sql-store.js";
import {
  MOVE_ADMISSION_EVENTS_DDL,
  SqlMoveCreateStore,
  type SqlExecutor,
  type SqlQueryResult,
  type SqlTxFn,
} from "../src/move/sql-store.js";
import { SqlSendCreateStore } from "../src/send/sql-store.js";
import type { SendArtifactSigner } from "../src/send/create.js";
import { WalletBusyError, IdempotencyKeyReusedError } from "../src/api/routes/operation-routes.js";

const MAINTENANCE_DB = "postgres";
const EXPECTED_DRILL_COUNT = 6;

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const runPsql = (db: string, sql: string): PsqlOutcome => {
  try {
    const stdout = execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql], {
      encoding: "utf-8",
      timeout: 15_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
};

const psqlMust = (db: string, sql: string): void => {
  const outcome = runPsql(db, sql);
  if (!outcome.ok) {
    throw new Error(`psql setup failed on ${db}: ${outcome.stderr.trim() || "unknown error"}`);
  }
};

const applyDdl = (db: string, ddl: string): void => {
  try {
    execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
      input: ddl,
      encoding: "utf-8",
      timeout: 60_000,
    });
  } catch (err) {
    const e = err as { stderr?: string };
    throw new Error(`DDL apply failed: ${(e.stderr ?? "").trim() || "unknown error"}`);
  }
};

const pgUsable = (): boolean => runPsql(MAINTENANCE_DB, "SELECT 1").ok;
const pgRequired = process.env.PG_REQUIRED === "1";
const describeIfPg =
  pgUsable() || pgRequired ? describe : describe.skip;

if (pgRequired && !pgUsable()) {
  throw new Error("PG_REQUIRED=1 but PostgreSQL is not usable");
}

const readSchema = (file: string): string =>
  readFileSync(new URL(`../src/schema/${file}`, import.meta.url), "utf-8");

const prerequisiteDdl = ((): string => {
  const base = readSchema("base-enums-domains.sql");
  const registry = readSchema("node-implementer-registry.sql");
  const nodes = /^CREATE TABLE nodes \([\s\S]*?^\);$/m.exec(registry);
  const implementers = /^CREATE TABLE implementers \([\s\S]*?^\);$/m.exec(registry);
  if (nodes === null || implementers === null) {
    throw new Error("node-implementer-registry.sql: nodes/implementers blocks not found");
  }
  return `${base}\n${nodes[0]}\n${implementers[0]}\n`;
})();

const CUSTODY_DDL = readSchema("custody-eligibility.sql");
const RECEIVE_DDL = readSchema("receive-admission.sql");
const SEND_DDL = readSchema("send-external-create.sql");
/** subscription_handles only (sha256_hex already from base-enums-domains). */
const SUBSCRIPTION_HANDLES_DDL = ((): string => {
  const raw = readSchema("session-subscription-stores.sql");
  const start = raw.indexOf("CREATE TABLE subscription_handles");
  const end = raw.indexOf("CREATE TABLE admin_sessions");
  if (start < 0 || end < 0) {
    throw new Error("session-subscription-stores.sql: subscription_handles block not found");
  }
  return raw.slice(start, end);
})();
const operationsDdl = ((): string => {
  const raw = readSchema("operations.sql");
  const start = raw.indexOf("CREATE TABLE operations");
  if (start < 0) throw new Error("operations.sql: CREATE TABLE operations not found");
  return raw.slice(start);
})();

const LEASE_FRAGMENT = `
CREATE TABLE lease_groups (
  id uuid PRIMARY KEY,
  root_operation_id uuid NOT NULL UNIQUE,
  created_at timestamptz NOT NULL,
  child_disposition text NOT NULL DEFAULT 'NONE'
    CHECK (child_disposition IN ('NONE', 'PENDING', 'JOINED')),
  released_at timestamptz,
  release_proof_id uuid
);
CREATE TABLE lease_group_operations (
  lease_group_id uuid NOT NULL REFERENCES lease_groups (id),
  operation_id uuid NOT NULL UNIQUE,
  joined_at timestamptz NOT NULL,
  completed_at timestamptz,
  PRIMARY KEY (lease_group_id, operation_id)
);
`;

const PROJECTION_FRAGMENT = `
CREATE TABLE operation_transactions (
  operation_id uuid NOT NULL REFERENCES operations(id),
  attempt_no integer NOT NULL CHECK (attempt_no = 1),
  attempt_phase text NOT NULL,
  PRIMARY KEY (operation_id, attempt_no)
);
CREATE TABLE external_send_sign_intents (
  operation_id uuid PRIMARY KEY REFERENCES operations(id)
);
CREATE TABLE external_send_partials (
  operation_id uuid PRIMARY KEY REFERENCES operations(id),
  first_delivered_at timestamptz
);
CREATE TABLE operation_expected_artifacts (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE REFERENCES operations(id),
  signing_key_id uuid NOT NULL,
  preimage_text text NOT NULL,
  preimage_sha256 sha256_hex NOT NULL,
  signature padded_base64url_signature NOT NULL
);
CREATE TABLE gateway_submit_attempts (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL REFERENCES operations(id),
  started_at timestamptz,
  completed_at timestamptz
);
CREATE TABLE operation_verifications (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL REFERENCES operations(id),
  verdict verification_verdict NOT NULL
);
`;

const NODE_ID = "c9210000-0000-4000-8000-000000000001";
const IMPLEMENTER_A = "c9210000-0000-4000-8000-00000000000a";
const IMPLEMENTER_B = "c9210000-0000-4000-8000-00000000000b";
const SOURCE_WALLET = "d9210000-0000-4000-8000-000000000001";
const DEST_WALLET = "d9210000-0000-4000-8000-000000000002";
const DESTINATION_ID = "d9210000-0000-4000-8000-000000000003";
const RECOVERY_1 = "d9210000-0000-4000-8000-000000000011";
const RECOVERY_2 = "d9210000-0000-4000-8000-000000000012";
const DEVICE_KEY = "d9210000-0000-4000-8000-000000000021";
const BLESSING_ART = "d9210000-0000-4000-8000-000000000022";
const SIGNING_KEY_ID = "d9210000-0000-4000-8000-000000000031";
const SHA_A = "a".repeat(64);
const DEST_ADDRESS = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
const SOURCE_PUBKEY = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";

/** Unique valid padded-base64url Ed25519 public key (32 bytes). */
const uniquePubkey = (seed: number): string => {
  const raw = Buffer.alloc(32, seed & 0xff);
  raw[0] = seed & 0xff;
  raw[1] = (seed >> 8) & 0xff;
  const unpadded = raw.toString("base64url");
  return unpadded + "=".repeat((4 - (unpadded.length % 4)) % 4);
};

const pubkey = (suffix: string): string => `${"A".repeat(43 - suffix.length)}${suffix}=`;

const litParam = (value: unknown): string => {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return `'${String(value).replace(/'/g, "''")}'`;
};

const bindParams = (text: string, params: readonly unknown[]): string =>
  text.replace(/\$(\d+)/g, (_m, n: string) => litParam(params[Number(n) - 1]));

class RoutePsqlSession implements SqlExecutor {
  private child: ChildProcessWithoutNullStreams | null = null;
  private buffer = "";
  private readonly pending: Array<(payload: string) => void> = [];

  constructor(private readonly db: string) {}

  start(): void {
    if (this.child) return;
    this.child = spawn(
      "psql",
      ["-d", this.db, "-X", "-q", "-A", "-t", "-v", "VERBOSITY=verbose"],
      { stdio: ["pipe", "pipe", "pipe"] },
    );
    this.child.stdout.setEncoding("utf8");
    this.child.stderr.setEncoding("utf8");
    this.child.stderr.on("data", (chunk: string) => {
      this.buffer += chunk;
    });
    this.child.stdout.on("data", (chunk: string) => {
      this.buffer += chunk;
      let idx = this.buffer.indexOf("__PSQL_END__\n");
      while (idx !== -1) {
        const payload = this.buffer.slice(0, idx);
        this.buffer = this.buffer.slice(idx + "__PSQL_END__\n".length);
        this.pending.shift()?.(payload);
        idx = this.buffer.indexOf("__PSQL_END__\n");
      }
    });
  }

  stop(): void {
    if (!this.child) return;
    const child = this.child;
    this.child = null;
    try {
      child.stdin.write("ROLLBACK;\n");
    } catch {
      /* ignore */
    }
    try {
      child.stdin.end();
    } catch {
      /* ignore */
    }
    try {
      child.kill("SIGKILL");
    } catch {
      /* ignore */
    }
  }

  private send(sql: string): Promise<string> {
    this.start();
    const child = this.child!;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error(`psql timeout: ${sql.slice(0, 80)}`)),
        20_000,
      );
      this.pending.push((payload) => {
        clearTimeout(timer);
        if (/\bERROR:\s+/i.test(payload)) {
          const err = new Error(payload.trim()) as Error & { code?: string; constraint?: string };
          const st = /\bERROR:\s+([0-9A-Z]{5}):/.exec(payload);
          if (st) err.code = st[1];
          const cn = /CONSTRAINT NAME:\s+(\S+)/.exec(payload);
          if (cn) err.constraint = cn[1];
          reject(err);
          return;
        }
        resolve(payload);
      });
      child.stdin.write(`${sql};\n\\echo __PSQL_END__\n`);
    });
  }

  async query<R>(text: string, params: readonly unknown[] = []): Promise<SqlQueryResult<R>> {
    const bound = bindParams(text, params).trim().replace(/;+\s*$/, "");
    const parseJsonRows = async (sql: string): Promise<SqlQueryResult<R>> => {
      const out = await this.send(sql);
      const lines = out
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.length > 0);
      const rows = JSON.parse(lines[lines.length - 1] ?? "[]") as R[];
      return { rows, rowCount: rows.length };
    };
    if (/^(INSERT|UPDATE|DELETE)\b/i.test(bound) && /\bRETURNING\b/i.test(bound)) {
      return parseJsonRows(
        `WITH __m AS (${bound}) SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM __m t`,
      );
    }
    // Data-modifying WITH must stay top-level (Postgres 0A000). Outer form is typically
    // WITH cte AS (INSERT…RETURNING) INSERT…RETURNING cols — rewrite final INSERT into a CTE.
    if (/^WITH\b/i.test(bound) && /\b(INSERT|UPDATE|DELETE)\b/i.test(bound)) {
      const ret = /\bRETURNING\s+(.+)$/i.exec(bound);
      if (ret === null) {
        await this.send(bound);
        return { rows: [] as R[], rowCount: 0 };
      }
      const cols = ret[1].trim();
      // Split at the top-level ") INSERT|UPDATE|DELETE" that closes the CTE list.
      const split = /\)\s*(INSERT|UPDATE|DELETE)\b/i.exec(bound);
      if (split === null || split.index === undefined) {
        throw new Error("modifying WITH missing trailing INSERT/UPDATE/DELETE");
      }
      const withHead = bound.slice(0, split.index + 1); // includes closing )
      const tailStart = split.index + 1;
      const tail = bound.slice(tailStart, ret.index).trim(); // INSERT … (no RETURNING)
      const jsonSql =
        `${withHead}, __result AS (${tail} RETURNING ${cols}) ` +
        `SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM __result t`;
      return parseJsonRows(jsonSql);
    }
    if (/^(SELECT|WITH)\b/i.test(bound)) {
      return parseJsonRows(
        `SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (${bound}) t`,
      );
    }
    await this.send(bound);
    return { rows: [] as R[], rowCount: 0 };
  }

  readonly withTransaction: SqlTxFn = async (body) => {
    await this.send("BEGIN");
    try {
      const result = await body(this);
      await this.send("COMMIT");
      return result;
    } catch (err) {
      try {
        await this.send("ROLLBACK");
      } catch {
        /* aborted */
      }
      throw err;
    }
  };
}

const NODE_IDENTITY_KEY = createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 0)]),
  format: "der",
  type: "pkcs8",
});

const testSigner: SendArtifactSigner = {
  signingKeyId: SIGNING_KEY_ID,
  sign: (preimageBytes) => edSign(null, preimageBytes, NODE_IDENTITY_KEY),
};

const idem = (label: string): string =>
  createHash("sha256").update(label, "utf8").digest("hex").slice(0, 32);

describeIfPg("OperationRouteStore — offline PG create+query (no live ZKZ)", () => {
  const scratchDb = `operation_route_store_ops_${process.pid}_${Date.now().toString(36)}`;
  let drillsCompleted = 0;
  let session: RoutePsqlSession;

  beforeAll(() => {
    psqlMust(MAINTENANCE_DB, `CREATE DATABASE ${scratchDb}`);
    applyDdl(scratchDb, prerequisiteDdl);
    applyDdl(scratchDb, CUSTODY_DDL);
    applyDdl(scratchDb, RECEIVE_DDL);
    applyDdl(scratchDb, SUBSCRIPTION_HANDLES_DDL);
    applyDdl(scratchDb, operationsDdl);
    applyDdl(scratchDb, LEASE_FRAGMENT);
    applyDdl(scratchDb, MOVE_ADMISSION_EVENTS_DDL);
    applyDdl(scratchDb, PROJECTION_FRAGMENT);
    applyDdl(scratchDb, SEND_DDL);

    psqlMust(
      scratchDb,
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ('${NODE_ID}', 'operation-route-store', '${pubkey("NODE")}');`,
    );
    psqlMust(
      scratchDb,
      `INSERT INTO implementers (id, name) VALUES ('${IMPLEMENTER_A}', 'a'), ('${IMPLEMENTER_B}', 'b');`,
    );
    // Source wallet for move/send — public key matches golden-compatible pad.
    psqlMust(
      scratchDb,
      `INSERT INTO wallets (id, node_id, public_key, key_origin, state) ` +
        `VALUES ('${SOURCE_WALLET}', '${NODE_ID}', '${SOURCE_PUBKEY}', 'node_generated', 'AVAILABLE'); ` +
        `INSERT INTO wallet_recovery_verifications ` +
        `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
        `VALUES ('${RECOVERY_1}', '${SOURCE_WALLET}', 'AUDITED_EXPORT', '${SHA_A}', '${SOURCE_PUBKEY}', ` +
        `'${RECOVERY_1}', now(), 'operation-route-store'); ` +
        `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${RECOVERY_1}' ` +
        `WHERE id = '${SOURCE_WALLET}';`,
    );
    psqlMust(
      scratchDb,
      `INSERT INTO wallets (id, node_id, public_key, key_origin, state) ` +
        `VALUES ('${DEST_WALLET}', '${NODE_ID}', '${pubkey("DST")}', 'node_generated', 'AVAILABLE'); ` +
        `INSERT INTO wallet_recovery_verifications ` +
        `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
        `VALUES ('${RECOVERY_2}', '${DEST_WALLET}', 'AUDITED_EXPORT', '${SHA_A}', '${pubkey("DST")}', ` +
        `'${RECOVERY_2}', now(), 'operation-route-store'); ` +
        `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${RECOVERY_2}' ` +
        `WHERE id = '${DEST_WALLET}';`,
    );
    psqlMust(
      scratchDb,
      `INSERT INTO destinations (id, node_id, wallet_id, state, blessed_at, blessed_by_device_key_id, blessing_artifact_id) ` +
        `VALUES ('${DESTINATION_ID}', '${NODE_ID}', '${DEST_WALLET}', 'BLESSED', now(), ` +
        `'${DEVICE_KEY}', '${BLESSING_ART}');`,
    );

    session = new RoutePsqlSession(scratchDb);
    session.start();
  }, 120_000);

  afterAll(() => {
    session?.stop();
    runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
    if (drillsCompleted < EXPECTED_DRILL_COUNT && (pgUsable() || pgRequired)) {
      throw new Error(
        `drills incomplete: ${drillsCompleted}/${EXPECTED_DRILL_COUNT} (fail-closed)`,
      );
    }
  });

  function store() {
    const receive = new SqlReceiveAdmissionStore(session, {
      withTransaction: session.withTransaction,
    });
    const move = new SqlMoveCreateStore({
      sql: session,
      withTransaction: session.withTransaction,
    });
    const send = new SqlSendCreateStore(session);
    return createSqlOperationRouteStore({
      nodeId: NODE_ID,
      queueCap: 50,
      receive,
      move,
      send,
      sendSigner: testSigner,
      generateId: () => randomUUID(),
      now: () => Date.now(),
    });
  }

  it("RECEIVE_EXTERNAL create + tenant-scoped get", async () => {
    const ops = store();
    const key = idem("recv-create-1");
    const created = await ops.createReceive({
      amount_zkz: "1.25",
      anchor: "pay_recv_1",
      after_landing: { kind: "HOLD", destination_id: null },
      idempotencyKey: key,
      implementerId: IMPLEMENTER_A,
    });
    expect(created.status).toBe(202);
    expect(created.body.operation.operation_type).toBe("RECEIVE_EXTERNAL");
    expect(created.body.operation.state).toBe("CREATED");
    // ZTR-1142: non-empty subscription_handle on create; hash-only at rest.
    expect(created.body.subscription_handle.startsWith("sh_")).toBe(true);
    const id = created.body.operation.operation_id;
    const handlePlain = created.body.subscription_handle;

    const got = await ops.getReceive(id, IMPLEMENTER_A);
    expect(got).not.toBeNull();
    expect(got!.operation.operation_id).toBe(id);
    // Point-read body still carries the field at the store layer; the route handler strips it.
    expect(got!.subscription_handle).toBe(handlePlain);
    // Cross-tenant point read is null — never leaks.
    expect(await ops.getReceive(id, IMPLEMENTER_B)).toBeNull();

    // The never-blind-retry rule: same key + body → idempotent replay, no second row.
    const replay = await ops.createReceive({
      amount_zkz: "1.25",
      anchor: "pay_recv_1",
      after_landing: { kind: "HOLD", destination_id: null },
      idempotencyKey: key,
      implementerId: IMPLEMENTER_A,
    });
    expect(replay.idempotentReplay).toBe(true);
    expect(replay.body.operation.operation_id).toBe(id);
    // Same handle on replay — never a second mint.
    expect(replay.body.subscription_handle).toBe(handlePlain);
    drillsCompleted += 1;
  });

  it("RECEIVE_EXTERNAL wrong-body idempotency_key_reused (no blind retry invent)", async () => {
    const ops = store();
    const key = idem("recv-conflict-1");
    await ops.createReceive({
      amount_zkz: "2",
      anchor: "pay_recv_x",
      after_landing: { kind: "HOLD", destination_id: null },
      idempotencyKey: key,
      implementerId: IMPLEMENTER_A,
    });
    await expect(
      ops.createReceive({
        amount_zkz: "9.99",
        anchor: "pay_recv_x",
        after_landing: { kind: "HOLD", destination_id: null },
        idempotencyKey: key,
        implementerId: IMPLEMENTER_A,
      }),
    ).rejects.toBeInstanceOf(IdempotencyKeyReusedError);
    drillsCompleted += 1;
  });

  it("MOVE_INTERNAL create + tenant-scoped get", async () => {
    const ops = store();
    const key = idem("move-create-1");
    const created = await ops.createInternalMove({
      source_wallet_id: SOURCE_WALLET,
      destination_id: DESTINATION_ID,
      amount_zkz: "0.5",
      idempotencyKey: key,
      implementerId: IMPLEMENTER_A,
    });
    expect(created.status).toBe(201);
    expect(created.body.operation.operation_type).toBe("MOVE_INTERNAL");
    const id = created.body.operation.operation_id;

    const got = await ops.getInternalMove(id, IMPLEMENTER_A);
    expect(got).not.toBeNull();
    expect(got!.operation.operation_id).toBe(id);
    expect(got).toMatchObject({
      lease_status: "WAITING",
      execution_phase: "NOT_STARTED",
      expected_artifact: null,
      source_terminal_observation_id: null,
      destination_terminal_observation_id: null,
    });
    expect(await ops.getInternalMove(id, IMPLEMENTER_B)).toBeNull();

    const replay = await ops.createInternalMove({
      source_wallet_id: SOURCE_WALLET,
      destination_id: DESTINATION_ID,
      amount_zkz: "0.5",
      idempotencyKey: key,
      implementerId: IMPLEMENTER_A,
    });
    expect(replay.idempotentReplay).toBe(true);
    expect(replay.body.operation.operation_id).toBe(id);
    drillsCompleted += 1;
  });

  it("SEND_EXTERNAL create + tenant-scoped get (offline signer, no live ZKZ)", async () => {
    const ops = store();
    const sendWallet = "d9210000-0000-4000-8000-000000000099";
    const sendRecovery = "d9210000-0000-4000-8000-000000000098";
    const sendPub = uniquePubkey(99);
    psqlMust(
      scratchDb,
      `INSERT INTO wallets (id, node_id, public_key, key_origin, state) ` +
        `VALUES ('${sendWallet}', '${NODE_ID}', '${sendPub}', 'node_generated', 'AVAILABLE'); ` +
        `INSERT INTO wallet_recovery_verifications ` +
        `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
        `VALUES ('${sendRecovery}', '${sendWallet}', 'AUDITED_EXPORT', '${SHA_A}', '${sendPub}', ` +
        `'${sendRecovery}', now(), 'operation-route-store'); ` +
        `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${sendRecovery}' ` +
        `WHERE id = '${sendWallet}';`,
    );

    const key = idem("send-create-1");
    const created = await ops.createExternalSend({
      source_wallet_id: sendWallet,
      destination_address: DEST_ADDRESS,
      amount_zkz: "0.01",
      idempotencyKey: key,
      implementerId: IMPLEMENTER_A,
    });
    expect(created.status).toBe(201);
    expect(created.body.operation.operation_type).toBe("SEND_EXTERNAL");
    expect(created.body.expected_artifact).not.toBeNull();
    const id = created.body.operation.operation_id;

    const got = await ops.getExternalSend(id, IMPLEMENTER_A);
    expect(got).not.toBeNull();
    expect(got!.operation.operation_id).toBe(id);
    expect(await ops.getExternalSend(id, IMPLEMENTER_B)).toBeNull();

    const replay = await ops.createExternalSend({
      source_wallet_id: sendWallet,
      destination_address: DEST_ADDRESS,
      amount_zkz: "0.01",
      idempotencyKey: key,
      implementerId: IMPLEMENTER_A,
    });
    expect(replay.idempotentReplay).toBe(true);
    drillsCompleted += 1;
  });

  it("the one-in-flight-per-wallet rule — second unsettled send on same source is wallet_busy", async () => {
    const ops = store();
    const sendWallet = "d9210000-0000-4000-8000-000000000088";
    const sendRecovery = "d9210000-0000-4000-8000-000000000087";
    const sendPub = uniquePubkey(88);
    psqlMust(
      scratchDb,
      `INSERT INTO wallets (id, node_id, public_key, key_origin, state) ` +
        `VALUES ('${sendWallet}', '${NODE_ID}', '${sendPub}', 'node_generated', 'AVAILABLE'); ` +
        `INSERT INTO wallet_recovery_verifications ` +
        `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
        `VALUES ('${sendRecovery}', '${sendWallet}', 'AUDITED_EXPORT', '${SHA_A}', '${sendPub}', ` +
        `'${sendRecovery}', now(), 'operation-route-store'); ` +
        `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${sendRecovery}' ` +
        `WHERE id = '${sendWallet}';`,
    );
    await ops.createExternalSend({
      source_wallet_id: sendWallet,
      destination_address: DEST_ADDRESS,
      amount_zkz: "0.01",
      idempotencyKey: idem("send-route-a"),
      implementerId: IMPLEMENTER_A,
    });
    await expect(
      ops.createExternalSend({
        source_wallet_id: sendWallet,
        destination_address: DEST_ADDRESS,
        amount_zkz: "0.02",
        idempotencyKey: idem("send-route-b"),
        implementerId: IMPLEMENTER_A,
      }),
    ).rejects.toBeInstanceOf(WalletBusyError);
    drillsCompleted += 1;
  });

  it("main composition: live store only under implementer_bearer (source ratchet)", () => {
    const mainSrc = readFileSync(
      new URL("../../../apps/generic-node/src/main.ts", import.meta.url),
      "utf8",
    );
    expect(mainSrc).toMatch(/createSqlOperationRouteStore\s*\(/);
    expect(mainSrc).toMatch(/createImplementerBearerAuthFromService\s*\(/);
    expect(mainSrc).not.toMatch(/createFailClosedOperationStore\s*\(/);
    expect(mainSrc).not.toMatch(/createRejectAllOperationAuth\s*\(/);
    drillsCompleted += 1;
  });
});

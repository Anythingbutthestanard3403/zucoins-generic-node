// real-PostgreSQL proof that the `receive.ready` appender is DURABLE on both
// continuity chains and that GET /v1/events serves the resulting signed proof.
//
// Invariants: node_events / implementer_events dual continuity; the served
// artifact is zp-implementer-event-v1, never zp-node-event-v1; both signing
// tuples, the frozen envelope, and the closed event set.
//
// The schema is the real frozen money pack applied by the production migrator — no hand-built
// stub tables — so every FK, domain and append-only trigger is the one production runs.
//
// Covered: durable append inside the caller's TX; hash-chain continuity across a restart
// (fresh appender instance); gapless monotonic seq under CONCURRENT transactions; and the
// per-implementer append quota that keeps the append-only tables from growing without bound.

import {
  createHash,
  createPublicKey,
  randomBytes,
  randomUUID,
  verify as edVerify,
} from "node:crypto";
import { execFileSync } from "node:child_process";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import {
  createPgImplementerEventLog,
  deriveRootKey,
  ensureActiveNodeSigningKey,
  listEvents,
  migrateLeaseFoundation,
  toBase64UrlPadded,
  RECEIVE_READY_STATEMENTS,
  type NodeEventSigner,
} from "@zucoins/node-core";

import { ensureNodeRow } from "../src/bootstrap/genesis.js";
import { createEventSignerAuthority } from "../src/boot/event-signer-authority.js";
import { createReceiveLeasePort } from "../src/money-workers/receive-lease-port.js";
import { createDurableReceiveReadyEventAppender } from "../src/money-workers/receive-ready-event-appender.js";

const PG_TEST_TIMEOUT_MS = 180_000;
const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";
const VAULT_ROOT_KDF_SALT = Buffer.from("zupayments-vault-root-kdf-salt-v1", "utf8");
const MASTER = "event-append-master-key-32b!!!!!!!!!!!";

function hasClientTool(bin: string): boolean {
  try {
    execFileSync(bin, bin === "pg_isready" ? ["-q"] : ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const PG_AVAILABLE = (() => {
  try {
    if (hasClientTool("pg_isready")) {
      execFileSync("pg_isready", ["-q"], { stdio: "ignore" });
      return true;
    }
  } catch {
    /* fall through */
  }
  return false;
})();

function adminConfig(database = "postgres") {
  return {
    host: PG_HOST,
    port: PG_PORT,
    user: PG_USER,
    database,
    password: process.env.PGPASSWORD,
  };
}

function assertSafeDbName(dbName: string): void {
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(dbName)) {
    throw new Error(`unsafe test db name: ${dbName}`);
  }
}

async function adminExec(sql: string): Promise<void> {
  const client = new Client(adminConfig());
  await client.connect();
  try {
    await client.query(sql);
  } finally {
    await client.end();
  }
}

function pgDatabaseUrl(dbName: string): string {
  const auth = process.env.PGPASSWORD
    ? `${encodeURIComponent(PG_USER)}:${encodeURIComponent(process.env.PGPASSWORD)}`
    : encodeURIComponent(PG_USER);
  return `postgres://${auth}@${PG_HOST}:${PG_PORT}/${dbName}`;
}

/** Ed25519 public key bytes from the padded base64url wire form. */
function publicKeyObject(paddedBase64Url: string) {
  const raw = Buffer.from(paddedBase64Url, "base64url");
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
  return createPublicKey({ key: spki, format: "der", type: "spki" });
}

function eventHashOf(preimageText: string, signature: string): string {
  return createHash("sha256")
    .update(Buffer.concat([Buffer.from(preimageText, "utf8"), Buffer.from(signature, "base64url")]))
    .digest("hex");
}

interface Envelope {
  readonly key_id: string;
  readonly preimage_text: string;
  readonly preimage_sha256: string;
  readonly signature: string;
}

function payloadOf(preimageText: string): Record<string, unknown> {
  return JSON.parse(preimageText.slice(preimageText.indexOf("\n") + 1)) as Record<string, unknown>;
}

const silentLogger = { info: () => {}, error: () => {} };

describe.skipIf(!PG_AVAILABLE)("durable receive.ready append (disposable PG)", () => {
  const dbName = `receive_ready_event_${process.pid}_${Date.now()}`;
  let pool: Pool;
  let nodeId: string;
  let implementerId: string;
  let walletId: string;
  let signer: NodeEventSigner;
  let eventPublicKey: string;

  const sqlOn = (client: { query: (t: string, p?: unknown[]) => Promise<{ rows: unknown[] }> }) => ({
    async query<R>(text: string, params?: readonly unknown[]) {
      const result = await client.query(text, params as unknown[]);
      return { rows: result.rows as R[], rowCount: result.rows.length };
    },
  });

  /** Seed one CREATED receive operation plus its mirrored `operations` row. */
  async function seedReceive(owner: string): Promise<string> {
    const operationId = randomUUID();
    const reqSha = createHash("sha256").update(`recv|${operationId}`, "utf8").digest("hex");
    await pool.query(
      `INSERT INTO receive_operations (
         operation_id, implementer_id, node_id, kind, status, http_method, route,
         idempotency_key, request_sha256, amount_zkz, anchor, ttl_ms, after_landing_kind
       ) VALUES (
         $1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL', 'CREATED', 'POST', '/v1/receives',
         $4, $5, '0.01', 'receive-ready-event', 300000, 'HOLD'
       )`,
      [operationId, owner, nodeId, `idem-${operationId}`, reqSha],
    );
    await pool.query(
      `INSERT INTO operations (
         id, node_id, implementer_id, kind, status, amount_zkz, after_landing,
         discriminator, anchor, idempotency_key, request_sha256, formation_state
       ) VALUES (
         $1::uuid, $2::uuid, $3::uuid, 'RECEIVE_EXTERNAL'::operation_kind,
         'CREATED'::operation_status, '0.01', 'HOLD', $1::uuid, 'receive-ready-event', $4, $5,
         'NOT_REQUIRED'::external_formation_state
       )`,
      [operationId, nodeId, owner, `idem-${operationId}`, reqSha],
    );
    return operationId;
  }

  /** Run one append on a dedicated connection inside a real transaction. */
  async function appendOn(
    operationId: string,
    options: {
      readonly quota?: { windowCap: number; windowMs: number };
      /** Override the signer to drill runtime EVENT_SIGNING loss. */
      readonly signer?: NodeEventSigner;
    } = {},
  ): Promise<void> {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const appender = createDurableReceiveReadyEventAppender({
        sql: sqlOn(client),
        nodeId,
        eventSigner: options.signer ?? signer,
        logger: silentLogger,
        ...(options.quota !== undefined ? { quota: options.quota } : {}),
      });
      await appender.appendReceiveReady({
        operationId,
        walletId,
        dataText: `{"operation_id":"${operationId}","code_status":"AWAITING_ARM"}`,
        dataSha256: createHash("sha256").update(`data|${operationId}`, "utf8").digest("hex"),
      });
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  /**
   * a wallet with a real RECEIVE_WINDOW lease, so the production
   * CREATED→READY CAS (which requires the matching lease row) can actually fire.
   * `wallet_active_leases.wallet_id` is a primary key, so each drill needs its own.
   */
  async function seedLeasedWallet(operationId: string): Promise<{
    readonly walletId: string;
    readonly leaseEpoch: bigint;
  }> {
    const leasedWalletId = randomUUID();
    const publicKey = toBase64UrlPadded(randomBytes(32));
    await pool.query(
      `INSERT INTO wallets (id, node_id, public_key, key_origin)
       VALUES ($1::uuid, $2::uuid, $3, 'node_generated')`,
      [leasedWalletId, nodeId, publicKey],
    );
    // G1: the custody trigger refuses a RECEIVE_WINDOW lease on a wallet with no
    // recovery verification, and both wallets columns must be set together.
    const verificationId = randomUUID();
    await pool.query(
      `INSERT INTO wallet_recovery_verifications
         (id, wallet_id, method, public_key, export_sha256, audit_event_id, verified_at, verifier_identity)
       VALUES ($1::uuid, $2::uuid, 'AUDITED_EXPORT', $3, $4, $5::uuid, now(), 'fixture-b-suite')`,
      [
        verificationId,
        leasedWalletId,
        publicKey,
        createHash("sha256").update(leasedWalletId, "utf8").digest("hex"),
        randomUUID(),
      ],
    );
    await pool.query(
      `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = $2::uuid
        WHERE id = $1::uuid`,
      [leasedWalletId, verificationId],
    );
    const leases = createReceiveLeasePort();
    const db = sqlOn(pool);
    const leaseGroupId = await leases.createLeaseGroup(db, operationId);
    const { leaseEpoch } = await leases.acquireReceiveWindowLease(db, {
      walletId: leasedWalletId,
      leaseGroupId,
      operationId,
      ownerInstanceId: nodeId,
    });
    return { walletId: leasedWalletId, leaseEpoch };
  }

  /**
   * The two writes `finishReadyTransition` performs, in its order and in ONE
   * transaction: the production CREATED→READY CAS statement, then the production event
   * appender. Commits only if the append returns; any throw rolls the whole thing back,
   * which is the behaviour under test. Returns the row_version the CAS produced.
   */
  async function readyTransitionOn(params: {
    readonly operationId: string;
    readonly walletId: string;
    readonly leaseEpoch: bigint;
    readonly signer: NodeEventSigner;
  }): Promise<void> {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const sql = sqlOn(client);
      const cas = await sql.query<{ operation_id: string }>(
        RECEIVE_READY_STATEMENTS.CAS_CREATED_TO_READY,
        [
          params.operationId,
          1,
          params.leaseEpoch.toString(),
          new Date().toISOString(),
          `${Math.floor(Date.now() / 1000) + 3600}`,
          randomUUID(),
          params.walletId,
        ],
      );
      if (cas.rows.length !== 1) {
        throw new Error(`CREATED→READY CAS did not match for ${params.operationId}`);
      }
      const appender = createDurableReceiveReadyEventAppender({
        sql,
        nodeId,
        eventSigner: params.signer,
        logger: silentLogger,
      });
      await appender.appendReceiveReady({
        operationId: params.operationId,
        walletId: params.walletId,
        dataText: `{"operation_id":"${params.operationId}","code_status":"AWAITING_ARM"}`,
        dataSha256: createHash("sha256").update(`data|${params.operationId}`, "utf8").digest("hex"),
      });
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  const operationStatus = async (operationId: string): Promise<string> => {
    const rows = await pool.query<{ status: string }>(
      `SELECT status::text AS status FROM operations WHERE id = $1::uuid`,
      [operationId],
    );
    return rows.rows[0]!.status;
  };

  const nodeEventCount = async (operationId: string): Promise<number> => {
    const rows = await pool.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM node_events
        WHERE node_id = $1::uuid AND operation_id = $2::uuid`,
      [nodeId, operationId],
    );
    return Number(rows.rows[0]!.n);
  };

  beforeAll(async () => {
    assertSafeDbName(dbName);
    await adminExec(`CREATE DATABASE ${dbName}`);
    pool = new Pool(adminConfig(dbName));
    const previousUrl = process.env.DATABASE_URL;
    process.env.DATABASE_URL = pgDatabaseUrl(dbName);
    const { runMigrationsOnPool } = await import("../src/db/migrate.js");
    await runMigrationsOnPool(pool, { databaseUrl: process.env.DATABASE_URL });
    if (previousUrl === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = previousUrl;
    await migrateLeaseFoundation(sqlOn(pool));

    nodeId = randomUUID();
    implementerId = randomUUID();
    walletId = randomUUID();
    await ensureNodeRow(pool, {
      nodeId,
      displayName: "fixture-event-append",
      identityPublicKey: toBase64UrlPadded(Buffer.alloc(32, 7)),
    });
    await pool.query(
      `INSERT INTO implementers (id, name, created_at) VALUES ($1::uuid, 'fixture-impl', now())`,
      [implementerId],
    );
    await pool.query(
      `INSERT INTO wallets (id, node_id, public_key, key_origin)
       VALUES ($1::uuid, $2::uuid, $3, 'node_generated')`,
      [walletId, nodeId, toBase64UrlPadded(Buffer.alloc(32, 9))],
    );

    // Real sealed EVENT_SIGNING key — the same ensure production boot runs.
    const rootKey = deriveRootKey(MASTER, VAULT_ROOT_KDF_SALT);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const key = await ensureActiveNodeSigningKey({
        sql: sqlOn(client),
        rootKey,
        nodeId,
        purpose: "EVENT_SIGNING",
      });
      await client.query("COMMIT");
      eventPublicKey = key.publicKey;
      signer = {
        signingKeyId: key.signingKeyId,
        sign: (bytes) => toBase64UrlPadded(Buffer.from(key.sign(bytes))),
      };
    } finally {
      client.release();
    }
  }, PG_TEST_TIMEOUT_MS);

  afterAll(async () => {
    await pool?.end().catch(() => {});
    await adminExec(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`).catch(() => {});
  }, PG_TEST_TIMEOUT_MS);

  it(
    "appends a signed receive.ready on both chains and serves it on GET /v1/events",
    async () => {
      const operationId = await seedReceive(implementerId);
      await appendOn(operationId);

      const nodeRows = await pool.query<{
        seq: string;
        event_id: string;
        event_type: string;
        preimage_text: string;
        signature: string;
        event_hash: string;
        previous_event_hash: string | null;
        signing_key_id: string;
      }>(
        `SELECT seq::text AS seq, event_id::text AS event_id, event_type, preimage_text,
                signature, event_hash, previous_event_hash, signing_key_id::text AS signing_key_id
           FROM node_events WHERE node_id = $1::uuid ORDER BY seq`,
        [nodeId],
      );
      expect(nodeRows.rows).toHaveLength(1);
      const nodeRow = nodeRows.rows[0]!;
      expect(nodeRow.event_type).toBe("receive.ready");
      expect(nodeRow.previous_event_hash).toBeNull();
      expect(nodeRow.signing_key_id).toBe(signer.signingKeyId);
      // The stored hash really is SHA256(preimage_bytes ‖ signature_bytes).
      expect(eventHashOf(nodeRow.preimage_text, nodeRow.signature)).toBe(nodeRow.event_hash);
      // …and the signature verifies under the registered EVENT_SIGNING public key.
      expect(
        edVerify(
          null,
          Buffer.from(nodeRow.preimage_text, "utf8"),
          publicKeyObject(eventPublicKey),
          Buffer.from(nodeRow.signature, "base64url"),
        ),
      ).toBe(true);

      // GET /v1/events read path — the exact store + service the route handler uses.
      const log = createPgImplementerEventLog({
        nodeId,
        query: async (text, values) => (await pool.query(text, values as unknown[])).rows,
        withTransaction: async (body) =>
          body(async (text, values) => (await pool.query(text, values as unknown[])).rows),
      });
      const page = await listEvents(log, {
        implementerId,
        afterImplementerSeq: null,
        limit: 10,
      });
      expect(page.events).toHaveLength(1);
      const served = page.events[0]!;
      expect(served.implementerSeq).toBe(1n);
      expect(served.eventType).toBe("receive.ready");

      const envelope = JSON.parse(served.proofRepresentation) as Envelope;
      const payload = payloadOf(envelope.preimage_text);
      expect(payload.purpose).toBe("zp-implementer-event-v1");
      expect(payload.event_type).toBe("receive.ready");
      expect(payload.implementer_id).toBe(implementerId);
      expect(payload.implementer_seq).toBe("1");
      expect(payload.implementer_previous_event_hash).toBeNull();
      // Binds to its node-global counterpart without disclosing the global seq (NC2).
      expect(payload.node_event_hash).toBe(nodeRow.event_hash);
      expect(payload.seq).toBeUndefined();
      expect(
        edVerify(
          null,
          Buffer.from(envelope.preimage_text, "utf8"),
          publicKeyObject(eventPublicKey),
          Buffer.from(envelope.signature, "base64url"),
        ),
      ).toBe(true);
      expect(envelope.preimage_sha256).toBe(
        createHash("sha256").update(envelope.preimage_text, "utf8").digest("hex"),
      );
      // No private key material rides on the wire.
      expect(served.proofRepresentation).not.toContain("PRIVATE");
      expect(payload.event_type).not.toMatch(/^payment\./);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "a fresh appender after restart continues both chains from the durable tail",
    async () => {
      const operationId = await seedReceive(implementerId);
      // appendOn builds a brand-new appender over a brand-new connection each call — this IS
      // the restart case: no in-process chain state survives between appends.
      await appendOn(operationId);

      const nodeRows = await pool.query<{
        seq: string;
        preimage_text: string;
        signature: string;
        event_hash: string;
        previous_event_hash: string | null;
      }>(
        `SELECT seq::text AS seq, preimage_text, signature, event_hash, previous_event_hash
           FROM node_events WHERE node_id = $1::uuid ORDER BY seq`,
        [nodeId],
      );
      expect(nodeRows.rows.map((r) => r.seq)).toEqual(["1", "2"]);
      expect(nodeRows.rows[1]!.previous_event_hash).toBe(nodeRows.rows[0]!.event_hash);

      const implRows = await pool.query<{ implementer_seq: string; proof_representation: string }>(
        `SELECT implementer_seq::text AS implementer_seq, proof_representation
           FROM implementer_events WHERE node_id = $1::uuid AND implementer_id = $2::uuid
          ORDER BY implementer_seq`,
        [nodeId, implementerId],
      );
      expect(implRows.rows.map((r) => r.implementer_seq)).toEqual(["1", "2"]);
      const first = JSON.parse(implRows.rows[0]!.proof_representation) as Envelope;
      const second = JSON.parse(implRows.rows[1]!.proof_representation) as Envelope;
      expect(payloadOf(second.preimage_text).implementer_previous_event_hash).toBe(
        eventHashOf(first.preimage_text, first.signature),
      );
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "concurrent transactions stay gapless and strictly monotonic on both chains",
    async () => {
      const before = await pool.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM node_events WHERE node_id = $1::uuid`,
        [nodeId],
      );
      const baseline = Number(before.rows[0]!.n);

      const ops = await Promise.all([
        seedReceive(implementerId),
        seedReceive(implementerId),
        seedReceive(implementerId),
        seedReceive(implementerId),
      ]);
      await Promise.all(ops.map((operationId) => appendOn(operationId)));

      const nodeSeqs = await pool.query<{ seq: string }>(
        `SELECT seq::text AS seq FROM node_events WHERE node_id = $1::uuid ORDER BY seq`,
        [nodeId],
      );
      const seqs = nodeSeqs.rows.map((r) => Number(r.seq));
      expect(seqs).toHaveLength(baseline + ops.length);
      // Gapless 1..n and strictly increasing — no duplicate, no burnt seq.
      expect(seqs).toEqual(Array.from({ length: seqs.length }, (_, i) => i + 1));

      const implSeqs = await pool.query<{ implementer_seq: string }>(
        `SELECT implementer_seq::text AS implementer_seq FROM implementer_events
          WHERE node_id = $1::uuid AND implementer_id = $2::uuid ORDER BY implementer_seq`,
        [nodeId, implementerId],
      );
      const impl = implSeqs.rows.map((r) => Number(r.implementer_seq));
      expect(impl).toEqual(Array.from({ length: impl.length }, (_, i) => i + 1));

      // The whole node chain still verifies end to end after concurrent interleaving.
      const chain = await pool.query<{
        preimage_text: string;
        signature: string;
        event_hash: string;
        previous_event_hash: string | null;
      }>(
        `SELECT preimage_text, signature, event_hash, previous_event_hash
           FROM node_events WHERE node_id = $1::uuid ORDER BY seq`,
        [nodeId],
      );
      let previous: string | null = null;
      for (const row of chain.rows) {
        expect(row.previous_event_hash).toBe(previous);
        expect(eventHashOf(row.preimage_text, row.signature)).toBe(row.event_hash);
        previous = row.event_hash;
      }
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "the per-implementer window quota rejects rather than growing either table",
    async () => {
      // Fresh tenant so the cap is the only thing under test.
      const quotaImplementer = randomUUID();
      await pool.query(
        `INSERT INTO implementers (id, name, created_at) VALUES ($1::uuid, 'fixture-quota', now())`,
        [quotaImplementer],
      );
      const quota = { windowCap: 2, windowMs: 3_600_000 };

      for (let i = 0; i < 2; i += 1) {
        await appendOn(await seedReceive(quotaImplementer), { quota });
      }
      const nodeBefore = await pool.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM node_events WHERE node_id = $1::uuid`,
        [nodeId],
      );

      // Third append inside the same window: over the cap. over-quota is a
      // refusal, not a silent drop: the append throws so the caller's transition rolls
      // back rather than committing READY with no event on either chain.
      await expect(
        appendOn(await seedReceive(quotaImplementer), { quota }),
      ).rejects.toThrow(/over event quota/);

      const implRows = await pool.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM implementer_events
          WHERE node_id = $1::uuid AND implementer_id = $2::uuid`,
        [nodeId, quotaImplementer],
      );
      expect(Number(implRows.rows[0]!.n)).toBe(quota.windowCap);
      // The node-global chain must not grow either — a bound on one table only is no bound.
      const nodeAfter = await pool.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM node_events WHERE node_id = $1::uuid`,
        [nodeId],
      );
      expect(nodeAfter.rows[0]!.n).toBe(nodeBefore.rows[0]!.n);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "6 concurrent appenders against a cap=2 quota let exactly 2 through",
    async () => {
      // Regression test for the quota TOCTOU: overQuota() reads implementer_events with no
      // lock of its own, so before the fix, concurrent transactions could all pass the probe
      // before any of them committed — breaching the cap. The fix takes the node-global
      // counter row lock (lockNodeEventCounter) before the probe, fully serializing every
      // append() for this node so each transaction sees the latest committed state.
      const quotaImplementer = randomUUID();
      await pool.query(
        `INSERT INTO implementers (id, name, created_at) VALUES ($1::uuid, 'fixture-c-race', now())`,
        [quotaImplementer],
      );
      const quota = { windowCap: 2, windowMs: 3_600_000 };

      const operationIds = await Promise.all(
        Array.from({ length: 6 }, () => seedReceive(quotaImplementer)),
      );
      // All 6 fire at once, each on its own connection/transaction — the race the fix closes.
      // The 4 over the cap reject (their transitions roll back); the 2 under it commit.
      const outcomes = await Promise.allSettled(
        operationIds.map((operationId) => appendOn(operationId, { quota })),
      );
      expect(outcomes.filter((o) => o.status === "fulfilled")).toHaveLength(quota.windowCap);
      for (const rejected of outcomes.filter((o) => o.status === "rejected")) {
        expect(String((rejected as PromiseRejectedResult).reason)).toMatch(/over event quota/);
      }

      const implRows = await pool.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM implementer_events
          WHERE node_id = $1::uuid AND implementer_id = $2::uuid`,
        [nodeId, quotaImplementer],
      );
      // Exactly the cap succeeded — not fewer (no false rejects), not more (no TOCTOU breach).
      expect(Number(implRows.rows[0]!.n)).toBe(quota.windowCap);

      const nodeRows = await pool.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM node_events
          WHERE node_id = $1::uuid
            AND operation_id IN (${operationIds.map((_, i) => `$${i + 2}::uuid`).join(", ")})`,
        [nodeId, ...operationIds],
      );
      // The node-global chain for these 6 ops grew by exactly the cap too — one bound, both
      // tables, no partial write on the rejected 4.
      expect(Number(nodeRows.rows[0]!.n)).toBe(quota.windowCap);
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "Byte-exact: a lost signer takes the CREATED→READY transition down with it",
    async () => {
      // Drill: the sealed key stops signing WHILE the money path is live (the case the
      // boot gate alone cannot cover). Byte-exact says the transition must not commit without
      // its signed event, so the transaction that ran the CAS must roll back — not
      // commit READY and log the missing event as a residual.
      const operationId = await seedReceive(implementerId);
      const { walletId: leasedWalletId, leaseEpoch } = await seedLeasedWallet(operationId);
      // implementer_events carries no operation_id (it stores the opaque proof), so its
      // fail-closed proof is "this tenant's chain did not grow at all".
      const implCount = async (): Promise<number> => {
        const rows = await pool.query<{ n: string }>(
          `SELECT count(*)::text AS n FROM implementer_events
            WHERE node_id = $1::uuid AND implementer_id = $2::uuid`,
          [nodeId, implementerId],
        );
        return Number(rows.rows[0]!.n);
      };
      const implBefore = await implCount();
      const withdrawn: string[] = [];
      let readyStamp = true;
      const authority = createEventSignerAuthority({
        readiness: { setEventSignerAvailable: (available) => { readyStamp = available; } },
        withdrawSignerAuthority: () => withdrawn.push("SIGNER_AUTHORITY_WITHDRAW"),
        stopWorkers: () => withdrawn.push("ENGINE_QUIESCE"),
        logger: silentLogger,
      });
      const armed = authority.arm({
        signingKeyId: signer.signingKeyId,
        sign: () => {
          throw new Error("sealed EVENT_SIGNING row unreadable");
        },
      });
      expect(readyStamp).toBe(true);
      expect(await operationStatus(operationId)).toBe("CREATED");

      await expect(
        readyTransitionOn({ operationId, walletId: leasedWalletId, leaseEpoch, signer: armed }),
      ).rejects.toThrow(/sealed EVENT_SIGNING row unreadable/);

      // THE assertion: the CAS ran and matched inside that transaction (readyTransitionOn
      // throws if it did not), and the rollback took it with the missing event. The money
      // did not move.
      expect(await operationStatus(operationId)).toBe("CREATED");
      expect(await nodeEventCount(operationId)).toBe(0);
      expect(await implCount()).toBe(implBefore);

      // …and the loss withdrew authority + quiesced the money surface, in that order.
      expect(withdrawn).toEqual(["SIGNER_AUTHORITY_WITHDRAW", "ENGINE_QUIESCE"]);
      expect(readyStamp).toBe(false);
      expect(authority.withdrawn).toBe(true);

      // Fail-closed afterwards: the held signer keeps refusing rather than reverting to
      // the appender's null branch, which would skip the event and keep the money.
      const stillArmed = signer;
      expect(() => armed.sign(Buffer.from("x", "utf8"))).toThrow(/authority withdrawn/);
      expect(stillArmed.sign(Buffer.from("x", "utf8"))).toBeTypeOf("string");
    },
    PG_TEST_TIMEOUT_MS,
  );

  it(
    "Byte-exact: a failure BETWEEN the two chain writes discards the node_events row already inserted",
    async () => {
      // The sharpest form of the rollback claim. This signer succeeds for the node-chain
      // event (so `INSERT INTO node_events` really happens inside the transaction) and
      // fails on the implementer-chain event. If the transaction did not roll back, the
      // node_events row would survive — a half-written dual chain under a READY row.
      const operationId = await seedReceive(implementerId);
      const { walletId: leasedWalletId, leaseEpoch } = await seedLeasedWallet(operationId);
      let signCalls = 0;
      const halfway: NodeEventSigner = {
        signingKeyId: signer.signingKeyId,
        sign: (bytes) => {
          signCalls += 1;
          if (signCalls > 1) {
            throw new Error("implementer-chain sign failed mid-append");
          }
          return signer.sign(bytes);
        },
      };

      await expect(
        readyTransitionOn({ operationId, walletId: leasedWalletId, leaseEpoch, signer: halfway }),
      ).rejects.toThrow(/implementer-chain sign failed mid-append/);

      // Non-vacuity: the node-chain event really was signed and inserted before the throw.
      expect(signCalls).toBe(2);
      expect(await nodeEventCount(operationId)).toBe(0);
      expect(await operationStatus(operationId)).toBe("CREATED");
    },
    PG_TEST_TIMEOUT_MS,
  );
});

describe("append PG gate", () => {
  it("does not silently skip under PG_REQUIRED", () => {
    if (process.env.PG_REQUIRED === "1" && !PG_AVAILABLE) {
      throw new Error("PG_REQUIRED=1 but no reachable PostgreSQL");
    }
    expect(true).toBe(true);
  });
});

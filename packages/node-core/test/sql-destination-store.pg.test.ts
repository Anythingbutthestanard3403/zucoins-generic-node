// Real-PostgreSQL proof for destination register idempotency (ZTR-1310).
//
//   1. findByIdempotencyKey returns the original destinations row for a prior
//      successful register under that (node_id, key).
//   2. A second register with the same key does not mint another wallet;
//      it returns already_registered + the original destination record.
//   3. The unique index rejects a second dest row under the same (node, key).
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { randomUUID } from "node:crypto";

import {
  createDestinationService,
  DestinationIdempotencyKeyClaimedError,
  type DestinationWalletKeyGenerator,
} from "../src/api/destination.js";
import { insertNodeGeneratedWalletWithPendingDestination } from "../src/api/insert-node-generated-wallet.js";
import { createSqlDestinationStore } from "../src/api/sql-destination-store.js";
import type { Uuid, WalletPublicKey } from "../src/protocol/scalars.js";
import { registerPgRequiredGuard } from "./pg-required-guard.js";
import {
  PsqlExecutor,
  PsqlSessionExecutor,
  extractSqlstate,
  runPsql,
  withDatabase,
} from "./psql-harness.js";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";

const readSchema = (file: string): string =>
  readFileSync(new URL(`../src/schema/${file}`, import.meta.url), "utf-8");

const prerequisiteDdl = ((): string => {
  const base = readSchema("base-enums-domains.sql");
  const registry = readSchema("node-implementer-registry.sql");
  const nodes = /^CREATE TABLE nodes \([\s\S]*?^\);$/m.exec(registry);
  if (nodes === null) {
    throw new Error("node-implementer-registry.sql: CREATE TABLE nodes block not found");
  }
  return `${base}\n${nodes[0]}\n`;
})();

const schemaDdl = `${prerequisiteDdl}${readSchema("custody-eligibility.sql")}\n${readSchema("wallet-money-capability.sql")}\n`;
const keySliceDdl = readSchema("destinations-idempotency-key.sql");

const scratchDb = `ztr_1310_lane_${Date.now()}_${process.pid}`;
let scratchDbUrl = "";
let schemaReady = false;

const adminPsql = (url: string, sql: string): void => {
  execFileSync("psql", [url, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql], {
    encoding: "utf-8",
    timeout: 60_000,
  });
};

const NODE = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const OTHER_NODE = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";
const PUB = (ch: string) => `${ch.repeat(43)}=`;
const KEY = "register-retry-key-1";

beforeAll(() => {
  if (!TEST_DATABASE_URL) return;
  adminPsql(TEST_DATABASE_URL, `CREATE DATABASE ${scratchDb}`);
  scratchDbUrl = withDatabase(TEST_DATABASE_URL, scratchDb);
  execFileSync("psql", [scratchDbUrl, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
    input: schemaDdl,
    encoding: "utf-8",
    timeout: 60_000,
  });
  execFileSync("psql", [scratchDbUrl, "-v", "ON_ERROR_STOP=1", "-1", "-f", "-"], {
    input: keySliceDdl,
    encoding: "utf-8",
    timeout: 15_000,
  });
  execFileSync(
    "psql",
    [
      scratchDbUrl,
      "-v",
      "ON_ERROR_STOP=1",
      "-qAt",
      "-c",
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES
         ('${NODE}', 'ztr-1310-a', '${PUB("N")}'),
         ('${OTHER_NODE}', 'ztr-1310-b', '${PUB("O")}')
       ON CONFLICT (id) DO NOTHING;`,
    ],
    { encoding: "utf-8", timeout: 15_000 },
  );
  schemaReady = true;
}, 90_000);

afterAll(() => {
  if (!schemaReady) return;
  try {
    adminPsql(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
  } catch {
    /* best-effort teardown */
  }
});

registerPgRequiredGuard({
  name: "sql-destination-store.pg",
  databaseUrl: TEST_DATABASE_URL,
  isReady: () => schemaReady,
});

function mintWalletSql(walletId: string, nodeId: string, pub: string): string {
  return `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
          VALUES ('${walletId}', '${nodeId}', '${pub}', 'node_generated', 'AVAILABLE')`;
}

describe("sql destination store register idempotency PG (ZTR-1310)", () => {
  it("findByIdempotencyKey returns the original destination after insert", async () => {
    if (!schemaReady) return;
    const sql = new PsqlExecutor(scratchDbUrl);
    const store = createSqlDestinationStore(sql);
    const destId = "11111111-1111-4111-8111-111111111111" as Uuid;
    const walletId = "22222222-2222-4222-8222-222222222222" as Uuid;
    const pub = PUB("A") as WalletPublicKey;
    const applied = runPsql(scratchDbUrl, mintWalletSql(walletId, NODE, pub));
    expect(applied.ok, applied.stderr).toBe(true);

    const created = await store.insert(
      {
        destinationId: destId,
        nodeId: NODE as Uuid,
        walletId,
        walletPublicKey: pub,
        label: "Primary sink",
        createdAt: "2026-08-15T00:00:00.000Z",
      },
      KEY,
    );
    expect(created.destinationId).toBe(destId);
    expect(created.walletId).toBe(walletId);

    const hit = await store.findByIdempotencyKey(NODE as Uuid, KEY);
    expect(hit).not.toBeNull();
    expect(hit?.destinationId).toBe(created.destinationId);
    expect(hit?.walletId).toBe(created.walletId);
    expect(hit?.walletPublicKey).toBe(created.walletPublicKey);
    expect(hit?.nodeId).toBe(created.nodeId);
    expect(hit?.label).toBe(created.label);
    expect(hit?.state).toBe(created.state);

    const miss = await store.findByIdempotencyKey(NODE as Uuid, "register-retry-key-9");
    expect(miss).toBeNull();

    const otherNode = await store.findByIdempotencyKey(OTHER_NODE as Uuid, KEY);
    expect(otherNode).toBeNull();
  });

  it("retried register returns already_registered and does not mint another wallet", async () => {
    if (!schemaReady) return;
    const sql = new PsqlExecutor(scratchDbUrl);
    const store = createSqlDestinationStore(sql);
    let mintCount = 0;
    const keyGenerator: DestinationWalletKeyGenerator = {
      async generate(nodeId) {
        mintCount += 1;
        const walletId = `33333333-3333-4333-8333-${String(mintCount).padStart(12, "0")}` as Uuid;
        const publicKey = PUB(String(mintCount)) as WalletPublicKey;
        const minted = runPsql(scratchDbUrl, mintWalletSql(walletId, nodeId, publicKey));
        if (!minted.ok) throw new Error(minted.stderr);
        return { walletId, publicKey };
      },
    };
    let destSeq = 0;
    const service = createDestinationService({
      store,
      keyGenerator,
      blessingAuthorizer: {
        async authorize() {
          return null;
        },
      },
      clock: { now: () => "2026-08-15T00:00:00.000Z" },
      ids: {
        destinationId: () => {
          destSeq += 1;
          return `44444444-4444-4444-8444-${String(destSeq).padStart(12, "0")}` as Uuid;
        },
      },
    });

    const first = await service.register({
      nodeId: NODE as Uuid,
      label: "retry sink",
      idempotencyKey: "register-retry-key-2",
    });
    expect(first.status).toBe("created");
    if (first.status !== "created") return;
    expect(mintCount).toBe(1);

    const second = await service.register({
      nodeId: NODE as Uuid,
      label: "retry sink",
      idempotencyKey: "register-retry-key-2",
    });
    expect(second.status).toBe("already_registered");
    expect(mintCount).toBe(1);
    if (second.status !== "already_registered") return;
    expect(second.destination.destinationId).toBe(first.destination.destinationId);
    expect(second.destination.walletId).toBe(first.destination.walletId);
    expect(second.destination.walletPublicKey).toBe(first.destination.walletPublicKey);
    expect(second.destination.nodeId).toBe(first.destination.nodeId);
    expect(second.destination.label).toBe(first.destination.label);
    expect(second.destination.state).toBe(first.destination.state);
    const replay = await store.findByIdempotencyKey(NODE as Uuid, "register-retry-key-2");
    expect(second.destination).toEqual(replay);

    const count = runPsql(
      scratchDbUrl,
      `SELECT count(*)::text FROM destinations WHERE node_id = '${NODE}' AND idempotency_key = 'register-retry-key-2'`,
    );
    expect(count.ok, count.stderr).toBe(true);
    expect(count.stdout.trim()).toBe("1");
  });

  it("duplicate (node_id, idempotency_key) insert is unique_violation 23505", async () => {
    if (!schemaReady) return;
    const w1 = "55555555-5555-4555-8555-555555555551";
    const w2 = "55555555-5555-4555-8555-555555555552";
    const d1 = "66666666-6666-4666-8666-666666666661";
    const d2 = "66666666-6666-4666-8666-666666666662";
    expect(runPsql(scratchDbUrl, mintWalletSql(w1, NODE, PUB("X"))).ok).toBe(true);
    expect(runPsql(scratchDbUrl, mintWalletSql(w2, NODE, PUB("Y"))).ok).toBe(true);
    const first = runPsql(
      scratchDbUrl,
      `INSERT INTO destinations (id, node_id, wallet_id, label, state, idempotency_key)
       VALUES ('${d1}', '${NODE}', '${w1}', 'a', 'PENDING', 'register-retry-key-3')`,
    );
    expect(first.ok, first.stderr).toBe(true);
    const second = runPsql(
      scratchDbUrl,
      `INSERT INTO destinations (id, node_id, wallet_id, label, state, idempotency_key)
       VALUES ('${d2}', '${NODE}', '${w2}', 'b', 'PENDING', 'register-retry-key-3')`,
    );
    expect(second.ok).toBe(false);
    expect(extractSqlstate(second.stderr)).toBe("23505");
  });

  it("timeout after keyed persist: retry does not mint and returns already_registered", async () => {
    if (!schemaReady) return;
    const sql = new PsqlExecutor(scratchDbUrl);
    const store = createSqlDestinationStore(sql);
    const walletId = "77777777-7777-4777-8777-777777777777" as Uuid;
    const destId = "88888888-8888-4888-8888-888888888888" as Uuid;
    const pub = PUB("T") as WalletPublicKey;
    const key = "register-timeout-key-1";
    expect(runPsql(scratchDbUrl, mintWalletSql(walletId, NODE, pub)).ok).toBe(true);
    const seeded = runPsql(
      scratchDbUrl,
      `INSERT INTO destinations (id, node_id, wallet_id, label, state, idempotency_key)
       VALUES ('${destId}', '${NODE}', '${walletId}', 'seeded', 'PENDING', '${key}')`,
    );
    expect(seeded.ok, seeded.stderr).toBe(true);
    let mintCount = 0;
    const service = createDestinationService({
      store,
      keyGenerator: {
        async generate() {
          mintCount += 1;
          throw new Error("generate must not run after keyed persist");
        },
      },
      blessingAuthorizer: { async authorize() { return null; } },
      clock: { now: () => "2026-08-15T00:00:00.000Z" },
      ids: { destinationId: () => randomUUID() as Uuid },
    });
    const walletsBefore = runPsql(
      scratchDbUrl,
      `SELECT count(*)::text FROM wallets WHERE node_id = '${NODE}' AND public_key = '${pub}'`,
    );
    expect(walletsBefore.stdout.trim()).toBe("1");
    const retry = await service.register({
      nodeId: NODE as Uuid,
      label: "seeded",
      idempotencyKey: key,
    });
    expect(retry.status).toBe("already_registered");
    expect(mintCount).toBe(0);
    if (retry.status !== "already_registered") return;
    expect(retry.destination.destinationId).toBe(destId);
    expect(retry.destination.walletId).toBe(walletId);
    expect(retry.destination.walletPublicKey).toBe(pub);
    const walletsAfter = runPsql(
      scratchDbUrl,
      `SELECT count(*)::text FROM wallets WHERE node_id = '${NODE}' AND public_key = '${pub}'`,
    );
    expect(walletsAfter.stdout.trim()).toBe("1");
  });

  it("23505 rolls back the loser wallet; winner dest carries the key", async () => {
    if (!schemaReady) return;
    const key = "register-rollback-key-1";
    const wa = "a1111111-1111-4111-8111-111111111111";
    const wb = "a2222222-2222-4222-8222-222222222222";
    const da = "b1111111-1111-4111-8111-111111111111";
    const db = "b2222222-2222-4222-8222-222222222222";
    const winner = new PsqlSessionExecutor(scratchDbUrl);
    const loser = new PsqlSessionExecutor(scratchDbUrl);
    try {
      await winner.begin();
      await loser.begin();
      await winner.query(mintWalletSql(wa, NODE, PUB("P")));
      await loser.query(mintWalletSql(wb, NODE, PUB("Q")));
      await winner.query(
        `INSERT INTO destinations (id, node_id, wallet_id, label, state, idempotency_key)
         VALUES ($1, $2, $3, 'winner', 'PENDING', $4)`,
        [da, NODE, wa, key],
      );
      const loserInsert = loser.query(
        `INSERT INTO destinations (id, node_id, wallet_id, label, state, idempotency_key)
         VALUES ($1, $2, $3, 'loser', 'PENDING', $4)`,
        [db, NODE, wb, key],
      );
      await winner.commit();
      await expect(loserInsert).rejects.toMatchObject({ code: "23505" });
      await loser.rollback();
    } finally {
      winner.stop();
      loser.stop();
    }
    const winnerWallet = runPsql(scratchDbUrl, `SELECT count(*)::text FROM wallets WHERE id = '${wa}'`);
    const loserWallet = runPsql(scratchDbUrl, `SELECT count(*)::text FROM wallets WHERE id = '${wb}'`);
    const keyed = runPsql(
      scratchDbUrl,
      `SELECT wallet_id::text FROM destinations WHERE node_id = '${NODE}' AND idempotency_key = '${key}'`,
    );
    expect(winnerWallet.stdout.trim()).toBe("1");
    expect(loserWallet.stdout.trim()).toBe("0");
    expect(keyed.ok, keyed.stderr).toBe(true);
    expect(keyed.stdout.trim()).toBe(wa);
  });

  it("concurrent overlapping register: one created dest/wallet, zero NULL-key dests", async () => {
    if (!schemaReady) return;
    const sql = new PsqlExecutor(scratchDbUrl);
    const store = createSqlDestinationStore(sql);
    const key = "register-overlap-key-1";
    const attempted = new Set<string>();
    let mintSeq = 0;
    const persist: DestinationWalletKeyGenerator = {
      async generate(nodeId, claim) {
        mintSeq += 1;
        const session = new PsqlSessionExecutor(scratchDbUrl);
        const walletId = randomUUID() as Uuid;
        attempted.add(walletId);
        const publicKey = PUB(mintSeq === 1 ? "J" : "K") as WalletPublicKey;
        try {
          await session.begin();
          await insertNodeGeneratedWalletWithPendingDestination(session, {
            walletId,
            nodeId,
            publicKey,
            label: claim?.label ?? "",
            idempotencyKey: claim?.idempotencyKey,
          });
          await session.commit();
          return { walletId, publicKey };
        } catch (err) {
          await session.rollback();
          const code =
            err !== null && typeof err === "object" && "code" in err
              ? String((err as { code?: unknown }).code)
              : "";
          if (code === "23505" && claim !== undefined) {
            throw new DestinationIdempotencyKeyClaimedError(nodeId, claim.idempotencyKey);
          }
          throw err;
        } finally {
          session.stop();
        }
      },
    };
    const service = createDestinationService({
      store,
      keyGenerator: persist,
      blessingAuthorizer: { async authorize() { return null; } },
      clock: { now: () => "2026-08-15T00:00:00.000Z" },
      ids: { destinationId: () => randomUUID() as Uuid },
    });
    const [left, right] = await Promise.all([
      service.register({ nodeId: NODE as Uuid, label: "overlap", idempotencyKey: key }),
      service.register({ nodeId: NODE as Uuid, label: "overlap", idempotencyKey: key }),
    ]);
    const statuses = [left.status, right.status].sort().join("+");
    expect(
      statuses === "already_registered+created" || statuses === "already_registered+already_registered",
      statuses,
    ).toBe(true);
    expect(left.destination.destinationId).toBe(right.destination.destinationId);
    expect(left.destination.walletId).toBe(right.destination.walletId);
    expect(left.destination.walletPublicKey).toBe(right.destination.walletPublicKey);
    const destCount = runPsql(
      scratchDbUrl,
      `SELECT count(*)::text FROM destinations WHERE node_id = '${NODE}' AND idempotency_key = '${key}'`,
    );
    expect(destCount.stdout.trim()).toBe("1");
    const ids = [...attempted].map((id) => `'${id}'`).join(",");
    const walletCount = runPsql(
      scratchDbUrl,
      `SELECT count(*)::text FROM wallets WHERE id IN (${ids})`,
    );
    expect(walletCount.stdout.trim()).toBe("1");
    const nullKeys = runPsql(
      scratchDbUrl,
      `SELECT count(*)::text FROM destinations WHERE wallet_id IN (${ids}) AND idempotency_key IS NULL`,
    );
    expect(nullKeys.stdout.trim()).toBe("0");
  });
});

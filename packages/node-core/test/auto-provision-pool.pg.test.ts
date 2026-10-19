// GN-102 reserve + worker floors against real PostgreSQL.
// One ensure mints the Main Reserve, then five send workers, then five receive
// workers. Receive destinations stay PENDING so the allocator can still select
// them. A second call and a concurrent pair must not mint a second reserve.

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  ensureNodeReserveAndWorkerPool,
  type EnsureNodeReserveDeps,
} from "../src/receive/auto-provision-pool.ts";
import { PsqlExecutor, withTx } from "./psql-harness.ts";
import {
  applyReservePoolSchema,
  psqlMust,
  seedReserveNode,
  withDatabase,
} from "./receive/reserve-pool-schema.ts";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const live = TEST_DATABASE_URL.length > 0;
const NODE = "b0000000-0000-4000-8000-000000000265";

interface WalletRow {
  readonly id: string;
  readonly money_mode: string;
  readonly display_label: string | null;
  readonly stamped: boolean;
  readonly dest_state: string;
}

const names: string[] = [];
let template = "";

const clone = (): string => {
  const name = `ztr1325_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
  psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${name} TEMPLATE ${template}`);
  names.push(name);
  return withDatabase(TEST_DATABASE_URL, name);
};

function depsFor(url: string, poolCapTotal: number, seals: string[]): EnsureNodeReserveDeps {
  const autocommit = new PsqlExecutor(url);
  return {
    nodeId: NODE,
    poolCapTotal,
    withTx: (fn) => withTx(url, fn),
    query: (text, params) => autocommit.query(text, params),
    seal: async (minted) => {
      if (minted.secret.length !== 64) {
        throw new Error(`secret length ${minted.secret.length}`);
      }
      seals.push(minted.walletId);
    },
  };
}

async function loadWallets(url: string): Promise<WalletRow[]> {
  const db = new PsqlExecutor(url);
  const out = await db.query<WalletRow>(`
    SELECT w.id::text AS id,
           w.money_mode::text AS money_mode,
           w.display_label,
           (w.recovery_verified_at IS NOT NULL) AS stamped,
           d.state::text AS dest_state
      FROM wallets w
      JOIN destinations d ON d.wallet_id = w.id
  `);
  return out.rows;
}

describe("GN-102 automatic reserve and worker pool (real PG)", () => {
  beforeAll(() => {
    if (!live) {
      if (PG_REQUIRED) {
        throw new Error("PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned");
      }
      return;
    }
    template = `ztr1325_tpl_${Date.now().toString(36)}`;
    psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${template}`);
    names.push(template);
    const url = withDatabase(TEST_DATABASE_URL, template);
    applyReservePoolSchema(url);
    seedReserveNode(url, NODE);
  }, 120_000);

  afterAll(() => {
    if (!live) return;
    for (const name of names) {
      try {
        psqlMust(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
      } catch {
        // Best-effort cleanup under shared PostgreSQL contention.
      }
    }
  });

  it("skips cleanly only when Postgres is absent and not required", () => {
    if (live) {
      expect(template.length).toBeGreaterThan(0);
      return;
    }
    expect(PG_REQUIRED).toBe(false);
  });

  it("mints one reserve, five send workers, and five receive workers, then stays idle", async () => {
    if (!live) return;
    const url = clone();
    const seals: string[] = [];
    const first = await ensureNodeReserveAndWorkerPool(depsFor(url, 50, seals));
    expect(first.mintedWalletIds).toHaveLength(11);
    expect(seals).toHaveLength(11);

    const wallets = await loadWallets(url);
    expect(wallets).toHaveLength(11);
    const reserve = wallets.filter(
      (row) => row.money_mode === "INTERNAL_ONLY" && row.display_label === "Main Reserve",
    );
    expect(reserve).toHaveLength(1);
    expect(reserve[0]?.stamped).toBe(true);
    expect(reserve[0]?.dest_state).toBe("BLESSED");

    const send = wallets.filter((row) => row.money_mode === "SEND_ONLY");
    expect(send).toHaveLength(5);
    expect(send.every((row) => row.dest_state === "WORKER" && row.stamped)).toBe(true);

    const receive = wallets.filter((row) => row.money_mode === "RECEIVE_ONLY");
    expect(receive).toHaveLength(5);
    expect(receive.every((row) => row.dest_state === "PENDING" && row.stamped)).toBe(true);

    const db = new PsqlExecutor(url);
    const setting = await db.query<{ setting_value: string }>(`
      SELECT setting_value
        FROM node_settings
       WHERE setting_key = 'integration.default_funding_wallet_id'
    `);
    expect(setting.rows.map((row) => row.setting_value)).toEqual([reserve[0]?.id]);

    const audit = await db.query<{ action: string; actor_kind: string; actor_id: string }>(`
      SELECT action, actor_kind, actor_id FROM audit_log
    `);
    expect(audit.rows).toEqual([
      {
        action: "wallet.main_reserve_provisioned",
        actor_kind: "SYSTEM",
        actor_id: "SYSTEM",
      },
    ]);

    const second = await ensureNodeReserveAndWorkerPool(depsFor(url, 50, seals));
    expect(second.mintedWalletIds).toEqual([]);
    expect(seals).toHaveLength(11);
    expect(await loadWallets(url)).toHaveLength(11);
    const auditAgain = await db.query<{ action: string }>(`SELECT action FROM audit_log`);
    expect(auditAgain.rows).toHaveLength(1);
  }, 180_000);

  it("two concurrent ensures still leave exactly one Main Reserve", async () => {
    if (!live) return;
    const url = clone();
    const left: string[] = [];
    const right: string[] = [];
    await Promise.all([
      ensureNodeReserveAndWorkerPool(depsFor(url, 50, left)),
      ensureNodeReserveAndWorkerPool(depsFor(url, 50, right)),
    ]);
    const wallets = await loadWallets(url);
    expect(wallets.filter((row) => row.display_label === "Main Reserve")).toHaveLength(1);
    expect(wallets.filter((row) => row.money_mode === "SEND_ONLY")).toHaveLength(5);
    expect(wallets.filter((row) => row.money_mode === "RECEIVE_ONLY")).toHaveLength(5);
    expect(wallets).toHaveLength(11);
    expect(left.length + right.length).toBe(11);
  }, 180_000);

  it("a cap of 6 stops at the reserve plus five send workers", async () => {
    if (!live) return;
    const url = clone();
    const seals: string[] = [];
    await ensureNodeReserveAndWorkerPool(depsFor(url, 6, seals));
    const wallets = await loadWallets(url);
    expect(wallets).toHaveLength(6);
    expect(wallets.filter((row) => row.money_mode === "INTERNAL_ONLY")).toHaveLength(1);
    expect(wallets.filter((row) => row.money_mode === "SEND_ONLY")).toHaveLength(5);
    expect(wallets.filter((row) => row.money_mode === "RECEIVE_ONLY")).toHaveLength(0);
    expect(seals).toHaveLength(6);
  }, 180_000);
});

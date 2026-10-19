/**
 * ZTR-1326 / GN-103 — omitted after_landing resolves to the connector default
 * reserve destination, and an explicit override is gated by allow_custom_routing.
 *
 * Real PostgreSQL. psql sessions drive SqlReceiveAdmissionStore and the HTTP
 * handler so 201/202 and 422 are the statuses under test.
 */
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { PipelineContext } from "../src/api/pipeline.js";
import { handleCreateReceive } from "../src/api/routes/operation-routes.js";
import { createSqlOperationRouteStore } from "../src/operation-route-store.js";
import { admitReceiveExternal } from "../src/receive/admission.js";
import { SqlReceiveAdmissionStore } from "../src/receive/sql-store.js";
import { PsqlSessionExecutor } from "./psql-harness.js";
import { verificationModeFixtureSql } from "./verification-mode-fixture.js";

const MAINTENANCE_DB = "postgres";
const NODE_ID = "a1326000-0000-4000-8000-000000000001";
const IMPL = "a1326000-0000-4000-8000-00000000000a";
const IMPL_BARE = "a1326000-0000-4000-8000-00000000000b";
const DEVICE_KEY = "a1326000-0000-4000-8000-000000000041";
const BLESSING_ART = "a1326000-0000-4000-8000-000000000042";
const R1 = "a1326000-0000-4000-8000-000000000011";
const R2 = "a1326000-0000-4000-8000-000000000012";
const R3 = "a1326000-0000-4000-8000-000000000013";
const D1 = "a1326000-0000-4000-8000-000000000021";
const D2 = "a1326000-0000-4000-8000-000000000022";
const D3 = "a1326000-0000-4000-8000-000000000023";
const SHA = "a".repeat(64);
const REQUEST_ID = "a1326000-0000-4000-8000-0000000000c1";
const SETTING_KEY = "integration.default_funding_wallet_id";

interface PsqlOutcome {
  readonly ok: boolean;
  readonly stdout: string;
  readonly stderr: string;
}

const runPsql = (db: string, sql: string): PsqlOutcome => {
  try {
    const stdout = execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql], {
      encoding: "utf-8",
      timeout: 20_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, stdout, stderr: "" };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string };
    return { ok: false, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
};

const psqlMust = (db: string, sql: string): string => {
  const outcome = runPsql(db, sql);
  if (!outcome.ok) {
    throw new Error(`psql setup failed on ${db}: ${outcome.stderr.trim() || "unknown error"}`);
  }
  return outcome.stdout;
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
if (pgRequired && !pgUsable()) {
  throw new Error("PG_REQUIRED=1 but PostgreSQL is not usable");
}
const describeIfPg = pgUsable() || pgRequired ? describe : describe.skip;

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

const subscriptionHandlesDdl = ((): string => {
  const raw = readSchema("session-subscription-stores.sql");
  const start = raw.indexOf("CREATE TABLE subscription_handles");
  const end = raw.indexOf("CREATE TABLE admin_sessions");
  if (start < 0 || end < 0) {
    throw new Error("session-subscription-stores.sql: subscription_handles block not found");
  }
  return raw.slice(start, end);
})();

const pubkey = (suffix: string): string => `${"B".repeat(43 - suffix.length)}${suffix}=`;

function reserveSql(walletId: string, destinationId: string, label: string): string {
  const key = pubkey(label);
  const recoveryId = randomUUID();
  return (
    `INSERT INTO wallets (id, node_id, public_key, key_origin, state) ` +
    `VALUES ('${walletId}', '${NODE_ID}', '${key}', 'node_generated', 'AVAILABLE'); ` +
    `INSERT INTO wallet_recovery_verifications ` +
    `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
    `VALUES ('${recoveryId}', '${walletId}', 'AUDITED_EXPORT', '${SHA}', '${key}', ` +
    `'${recoveryId}', now(), 'receive-custom-routing'); ` +
    `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = '${recoveryId}' ` +
    `WHERE id = '${walletId}'; ` +
    `INSERT INTO destinations (id, node_id, wallet_id, state, blessed_at, blessed_by_device_key_id, blessing_artifact_id) ` +
    `VALUES ('${destinationId}', '${NODE_ID}', '${walletId}', 'BLESSED', now(), '${DEVICE_KEY}', '${BLESSING_ART}');`
  );
}

describeIfPg("receive custom routing (ZTR-1326)", () => {
  const scratchDb = `receive_custom_routing_${process.pid}_${Date.now().toString(36)}`;
  let session: PsqlSessionExecutor;

  beforeAll(() => {
    psqlMust(MAINTENANCE_DB, `CREATE DATABASE ${scratchDb}`);
    applyDdl(scratchDb, prerequisiteDdl);
    applyDdl(scratchDb, readSchema("custody-eligibility.sql"));
    applyDdl(scratchDb, readSchema("wallet-money-capability.sql"));
    applyDdl(scratchDb, readSchema("implementer-funding-wallet.sql"));
    applyDdl(scratchDb, readSchema("connector-reserve-wallets.sql"));
    applyDdl(scratchDb, readSchema("receive-admission.sql"));
    applyDdl(scratchDb, subscriptionHandlesDdl);
    applyDdl(scratchDb, verificationModeFixtureSql());

    psqlMust(
      scratchDb,
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ('${NODE_ID}', 'custom-routing', '${pubkey("ND")}'); ` +
        `INSERT INTO implementers (id, name, allow_custom_routing) VALUES ('${IMPL}', 'connector', false), ('${IMPL_BARE}', 'bare', false);`,
    );
    psqlMust(scratchDb, reserveSql(R1, D1, "R1"));
    psqlMust(scratchDb, reserveSql(R2, D2, "R2"));
    psqlMust(scratchDb, reserveSql(R3, D3, "R3"));
    psqlMust(
      scratchDb,
      `INSERT INTO implementer_reserve_wallets (implementer_id, wallet_id, is_default) ` +
        `VALUES ('${IMPL}', '${R1}', true), ('${IMPL}', '${R2}', false); ` +
        `INSERT INTO node_settings (setting_key, setting_value) VALUES ('${SETTING_KEY}', '${R2}');`,
    );

    session = new PsqlSessionExecutor(`postgresql:///${scratchDb}`);
    session.start();
  }, 120_000);

  afterAll(() => {
    session?.stop();
    runPsql(MAINTENANCE_DB, `DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
  });

  function store() {
    const receive = new SqlReceiveAdmissionStore(session, {
      withTransaction: async (fn) => {
        await session.begin();
        try {
          const result = await fn(session);
          await session.commit();
          return result;
        } catch (err) {
          await session.rollback();
          throw err;
        }
      },
    });
    return {
      receive,
      routes: createSqlOperationRouteStore({
        nodeId: NODE_ID,
        queueCap: 50,
        receive,
        move: {} as never,
        send: {} as never,
        sendSigner: {} as never,
        generateId: () => randomUUID(),
        now: () => Date.now(),
      }),
    };
  }

  function ctx(
    implementerId: string,
    idempotencyKey: string,
    body: Record<string, unknown>,
  ): PipelineContext {
    return {
      requestId: REQUEST_ID,
      request: {
        method: "POST",
        path: "/v1/receives",
        rawBody: new Uint8Array(),
        headers: { "idempotency-key": idempotencyKey },
        query: {},
      },
      routeSchema: { method: "POST", path: "/v1/receives", requiresIdempotencyKey: true },
      parsedBody: { amount_zkz: "1.5", anchor: "anchor_custom_route", ...body },
      principal: { implementerId, scopes: ["receive:create"] },
    };
  }

  async function post(
    implementerId: string,
    idempotencyKey: string,
    body: Record<string, unknown> = {},
  ) {
    return handleCreateReceive(ctx(implementerId, idempotencyKey, body), store().routes);
  }

  function releaseInFlight(): void {
    psqlMust(
      scratchDb,
      `UPDATE receive_operations SET status = 'EXPIRED' WHERE status IN ('CREATED', 'READY');`,
    );
  }

  it("omitted after_landing stores INTERNAL_MOVE to the connector default, ahead of the node setting", async () => {
    const result = await post(IMPL, "custom-route-omit-0001");
    expect(result.ok, JSON.stringify(result)).toBe(true);
    if (!result.ok) return;
    expect([201, 202]).toContain(result.status);
    const body = JSON.parse(result.body) as {
      after_landing: { kind: string; destination_id: string | null };
    };
    expect(body.after_landing).toEqual({ kind: "INTERNAL_MOVE", destination_id: D1 });
    const stored = psqlMust(
      scratchDb,
      `SELECT after_landing_kind || '|' || destination_id::text FROM receive_operations WHERE idempotency_key = 'custom-route-omit-0001';`,
    ).trim();
    expect(stored).toBe(`INTERNAL_MOVE|${D1}`);
    releaseInFlight();
  });

  it("rejects explicit HOLD and a non-default destination when custom routing is off, and admits the default", async () => {
    const hold = await post(IMPL, "custom-route-hold-0001", {
      after_landing: { kind: "HOLD", destination_id: null },
    });
    expect(hold.ok).toBe(false);
    if (hold.ok) return;
    expect(hold.error.status).toBe(422);
    expect(JSON.parse(hold.error.body)).toMatchObject({
      error: {
        code: "custom_routing_not_allowed",
        message: "Connector is not permitted to override default reserve routing.",
      },
    });

    const other = await post(IMPL, "custom-route-other-001", {
      after_landing: { kind: "INTERNAL_MOVE", destination_id: D2 },
    });
    expect(other.ok).toBe(false);
    if (other.ok) return;
    expect(other.error.status).toBe(422);
    expect(JSON.parse(other.error.body).error.code).toBe("custom_routing_not_allowed");

    const same = await post(IMPL, "custom-route-same-0001", {
      after_landing: { kind: "INTERNAL_MOVE", destination_id: D1 },
    });
    expect(same.ok, JSON.stringify(same)).toBe(true);
    if (!same.ok) return;
    expect([201, 202]).toContain(same.status);
    releaseInFlight();
  });

  it("with custom routing on, admits HOLD and an INTERNAL_MOVE to a linked reserve", async () => {
    psqlMust(scratchDb, `UPDATE implementers SET allow_custom_routing = true WHERE id = '${IMPL}';`);
    const hold = await post(IMPL, "custom-route-hold-0002", {
      after_landing: { kind: "HOLD", destination_id: null },
    });
    expect(hold.ok, JSON.stringify(hold)).toBe(true);
    if (!hold.ok) return;
    expect([201, 202]).toContain(hold.status);
    expect(JSON.parse(hold.body).after_landing).toEqual({ kind: "HOLD", destination_id: null });

    const linked = await post(IMPL, "custom-route-link-0001", {
      after_landing: { kind: "INTERNAL_MOVE", destination_id: D2 },
    });
    expect(linked.ok, JSON.stringify(linked)).toBe(true);
    if (!linked.ok) return;
    expect([201, 202]).toContain(linked.status);
    expect(JSON.parse(linked.body).after_landing).toEqual({
      kind: "INTERNAL_MOVE",
      destination_id: D2,
    });
    releaseInFlight();
  });

  it("rejects an unlinked reserve destination with destination_not_eligible at HTTP 422", async () => {
    const { receive } = store();
    const admission = await admitReceiveExternal(
      receive,
      {
        implementerId: IMPL,
        nodeId: NODE_ID,
        amountZkz: "1.5",
        anchor: "anchor_custom_route",
        ttlMs: 60_000,
        afterLanding: { kind: "INTERNAL_MOVE", destinationId: D3 },
        idempotencyKey: "custom-route-unlinked-1",
      },
      { queueCap: 50, generateId: () => randomUUID(), now: () => Date.now() },
    );
    expect(admission).toMatchObject({ outcome: "REJECTED", code: "destination_not_eligible" });

    const http = await post(IMPL, "custom-route-unlinked-2", {
      after_landing: { kind: "INTERNAL_MOVE", destination_id: D3 },
    });
    expect(http.ok).toBe(false);
    if (http.ok) return;
    expect(http.error.status).toBe(422);
  });

  it("falls back to the node funding-wallet destination, then HOLD when that is unset", async () => {
    const routed = await post(IMPL_BARE, "custom-route-bare-0001");
    expect(routed.ok, JSON.stringify(routed)).toBe(true);
    if (!routed.ok) return;
    expect(JSON.parse(routed.body).after_landing).toEqual({
      kind: "INTERNAL_MOVE",
      destination_id: D2,
    });
    releaseInFlight();

    psqlMust(scratchDb, `DELETE FROM node_settings WHERE setting_key = '${SETTING_KEY}';`);
    const held = await post(IMPL_BARE, "custom-route-bare-0002");
    expect(held.ok, JSON.stringify(held)).toBe(true);
    if (!held.ok) return;
    expect(JSON.parse(held.body).after_landing).toEqual({ kind: "HOLD", destination_id: null });
    const stored = psqlMust(
      scratchDb,
      `SELECT after_landing_kind FROM receive_operations WHERE idempotency_key = 'custom-route-bare-0002';`,
    ).trim();
    expect(stored).toBe("HOLD");
  });
});

// ZTR-1304 — NODE_VERIFIED move landing releases MOVE_SOURCE + MOVE_DESTINATION same-TX.
// Real PostgreSQL via psql harness (no app lander orchestration).

import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  assertLeaseFoundationReady,
  createLeaseGroup,
  migrateLeaseFoundation,
} from "../src/leases/index.ts";
import { acquireMoveLeases, type MoveLeaseRequest } from "../src/move/acquire-leases.ts";
import { releaseNodeVerifiedMoveLeasesOnLanding } from "../src/core/move-node-verified-landing-release.ts";
import { PsqlExecutor, psqlMust, runPsql, withDatabase, withTx } from "./psql-harness.ts";
import {
  NODE,
  OWNER,
  W,
  applyPoolSchema,
  countRows,
  seedRegistry,
  seedWallets,
} from "./receive/pool-fixture.ts";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const live = TEST_DATABASE_URL.length > 0;

const IMPL = "a0000000-0000-4000-8000-000000000201";

const destinationId = (walletId: string): string =>
  `d0000000-0000-4000-8000-1304${walletId.slice(-8)}`;

describe("move NODE_VERIFIED landing release (PG)", () => {
  let dbName = "";
  let dbUrl = "";
  let db: PsqlExecutor;
  let walletCursor = 1;

  beforeAll(async () => {
    if (!live) {
      if (PG_REQUIRED) {
        throw new Error("PG_REQUIRED=1 but TEST_DATABASE_URL is empty");
      }
      return;
    }
    dbName = `mv_nv_land_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
    psqlMust(TEST_DATABASE_URL, `CREATE DATABASE ${dbName}`);
    dbUrl = withDatabase(TEST_DATABASE_URL, dbName);
    db = new PsqlExecutor(dbUrl);
    applyPoolSchema(dbUrl);
    seedRegistry(dbUrl);
    seedWallets(dbUrl, { eligibleCount: 8 });
    await migrateLeaseFoundation(db);
    await assertLeaseFoundationReady(db);
    psqlMust(
      dbUrl,
      `ALTER TABLE operations
         ADD COLUMN IF NOT EXISTS verification_mode text NOT NULL DEFAULT 'INDEPENDENT';
       ALTER TABLE operations
         ADD COLUMN IF NOT EXISTS receive_release_status text;
       DO $$ BEGIN
         IF NOT EXISTS (
           SELECT 1 FROM pg_constraint WHERE conname = 'chk_operations_verification_mode'
         ) THEN
           ALTER TABLE operations
             ADD CONSTRAINT chk_operations_verification_mode
             CHECK (verification_mode IN ('INDEPENDENT', 'NODE_VERIFIED'));
         END IF;
       END $$;
       INSERT INTO implementers (id, name, created_at)
       VALUES ('${IMPL}', 'mv-nv', now()) ON CONFLICT DO NOTHING;`,
    );
  }, 120_000);

  afterAll(() => {
    if (!live || dbName === "") return;
    try {
      runPsql(TEST_DATABASE_URL, `DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    } catch {
      /* best-effort */
    }
  });

  function takePair(): { src: string; dst: string } {
    const src = W(walletCursor);
    walletCursor += 1;
    const dst = W(walletCursor);
    walletCursor += 1;
    return { src, dst };
  }

  async function seedMove(
    mode: "NODE_VERIFIED" | "INDEPENDENT",
  ): Promise<{ operationId: string; src: string; dst: string }> {
    const { src, dst } = takePair();
    const destId = destinationId(dst);
    psqlMust(
      dbUrl,
      `INSERT INTO destinations
         (id, node_id, wallet_id, state, blessed_at, blessed_by_device_key_id, blessing_artifact_id)
       VALUES ('${destId}', '${NODE}', '${dst}', 'BLESSED', now(),
               '${randomUUID()}', '${randomUUID()}')
       ON CONFLICT DO NOTHING;`,
    );
    const operationId = randomUUID();
    const leaseGroupId = await withTx(dbUrl, (tx) =>
      createLeaseGroup(tx, { rootOperationId: operationId, childDisposition: "NONE" }),
    );
    psqlMust(
      dbUrl,
      `INSERT INTO operations (
         id, node_id, implementer_id, kind, status, amount_zkz,
         source_wallet_id, destination_id, idempotency_key, request_sha256,
         formation_state, verification_mode
       ) VALUES (
         '${operationId}', '${NODE}', '${IMPL}', 'MOVE_INTERNAL', 'INTERNAL_MOVE_LANDED', '1',
         '${src}', '${destId}', 'idem-${operationId}', '${"a".repeat(64)}',
         'NOT_REQUIRED', '${mode}'
       );`,
    );
    const req: MoveLeaseRequest = {
      operationId,
      leaseGroupId,
      sourceWalletId: src,
      destinationWalletId: dst,
      ownerInstanceId: OWNER,
      spawnedFromOperationId: null,
    };
    const outcome = await acquireMoveLeases((body) => withTx(dbUrl, (tx) => body(tx)), req);
    expect(outcome.outcome).toBe("HELD");
    return { operationId, src, dst };
  }

  it("AC2: NODE_VERIFIED releases both MOVE_* leases + stamps RELEASED_NODE_VERIFIED", async ({
    skip,
  }) => {
    if (!live) {
      skip();
      return;
    }
    const { operationId, src, dst } = await seedMove("NODE_VERIFIED");
    await withTx(dbUrl, async (tx) => {
      const result = await releaseNodeVerifiedMoveLeasesOnLanding(tx, {
        operationId,
        sourceTerminalObservationId: randomUUID(),
        destinationTerminalObservationId: randomUUID(),
      });
      expect(result.kind).toBe("RELEASED");
      if (result.kind === "RELEASED") {
        expect([...result.releasedWalletIds].sort()).toEqual([src, dst].sort());
      }
    });
    expect(countRows(dbUrl, "wallet_active_leases", `operation_id = '${operationId}'`)).toBe(0);
    expect(countRows(dbUrl, "lease_release_proofs", `operation_id = '${operationId}'`)).toBe(2);
    const stamp = runPsql(
      dbUrl,
      `SELECT receive_release_status FROM operations WHERE id = '${operationId}'`,
    );
    expect(stamp.stdout.trim()).toBe("RELEASED_NODE_VERIFIED");
    const kinds = runPsql(
      dbUrl,
      `SELECT proof_kind FROM lease_release_proofs WHERE operation_id = '${operationId}'`,
    );
    const lines = kinds.stdout.trim().split("\n").filter(Boolean);
    expect(lines).toHaveLength(2);
    expect(lines.every((k) => k === "INTERNAL_MOVE_LANDED")).toBe(true);
  });

  it("AC2: INDEPENDENT skips release; both leases remain", async ({ skip }) => {
    if (!live) {
      skip();
      return;
    }
    const { operationId } = await seedMove("INDEPENDENT");
    await withTx(dbUrl, async (tx) => {
      const result = await releaseNodeVerifiedMoveLeasesOnLanding(tx, {
        operationId,
        sourceTerminalObservationId: randomUUID(),
        destinationTerminalObservationId: randomUUID(),
      });
      expect(result.kind).toBe("SKIPPED_INDEPENDENT");
    });
    expect(countRows(dbUrl, "wallet_active_leases", `operation_id = '${operationId}'`)).toBe(2);
    expect(countRows(dbUrl, "lease_release_proofs", `operation_id = '${operationId}'`)).toBe(0);
  });
});

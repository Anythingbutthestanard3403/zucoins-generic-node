// T0 capture stub: durable VERIFIED_GENESIS observation for money workers.

import { createHash, randomUUID } from "node:crypto";
import type { Pool } from "pg";

import { applyMoneyPathStatementTimeout } from "../db/client.js";
import { MONEY_PATH_STATEMENT_TIMEOUT_MS_DEFAULT } from "../config/constants.js";

import {
  DEFAULT_SERIALIZATION_RETRY_POLICY,
  GENESIS_PROJECTION,
  withSerializationRetry,
  type ReceiveT0Observer,
  type ReceiveT0Observation,
} from "@zucoins/node-core";

const ENDPOINT_FINGERPRINT = createHash("sha256")
  .update("zupayments-money-worker-t0-stub-v1", "utf8")
  .digest("hex");
const GENESIS_RAW = Buffer.from('{"stub":"VERIFIED_GENESIS"}', "utf8");
const GENESIS_RAW_SHA = createHash("sha256").update(GENESIS_RAW).digest("hex");
const GENESIS_SEMANTIC = createHash("sha256")
  .update('genesis|S=""|P=""|B="0"', "utf8")
  .digest("hex");

/**
 * One capture attempt: the whole `max(wallet_seq)` read-then-INSERT runs inside a single
 * `SERIALIZABLE` transaction on a pinned client (`CONVENTIONS.md` §1, money-path). This is
 * the only observation writer that takes no advisory lock — its two siblings
 * (`gateway-t0-observer.ts`, `sql-fresh-head-reader.ts`) go through the serialized stream
 * writer with `takeAdvisoryLock: true`, which is the row-lock arm of the same convention.
 *
 * The body is DB-only and re-runnable: every id and timestamp is minted inside it, and the
 * failed attempt has rolled back before the caller retries (the never-blind-retry rule —
 * there is no chain submit, no gateway call, and no non-DB side effect anywhere in here).
 * Serialization failures propagate so `withSerializationRetry` can see them; the
 * `INDETERMINATE` mapping stays outside the retried body.
 */
async function captureGenesisObservation(
  deps: {
    readonly pool: Pool;
    readonly nodeId: string;
    readonly moneyPathStatementTimeoutMs?: number;
  },
  walletPublicKey: string,
): Promise<ReceiveT0Observation> {
  const statementTimeoutMs =
    deps.moneyPathStatementTimeoutMs ?? MONEY_PATH_STATEMENT_TIMEOUT_MS_DEFAULT;
  const client = await deps.pool.connect();
  try {
    await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
    await applyMoneyPathStatementTimeout(client, statementTimeoutMs);
    const existingObserver = await client.query<{ id: string }>(
      `SELECT id::text AS id FROM observers
        WHERE domain = 'NODE' AND owner_id = $1::uuid LIMIT 1`,
      [deps.nodeId],
    );
    let observerId = existingObserver.rows[0]?.id;
    if (observerId === undefined) {
      observerId = randomUUID();
      await client.query(
        `INSERT INTO observers (id, domain, owner_id, gateway_endpoint_fingerprint, created_at)
         VALUES ($1::uuid, 'NODE', $2::uuid, $3, now())
         ON CONFLICT (domain, owner_id) DO NOTHING`,
        [observerId, deps.nodeId, ENDPOINT_FINGERPRINT],
      );
      const again = await client.query<{ id: string }>(
        `SELECT id::text AS id FROM observers
          WHERE domain = 'NODE' AND owner_id = $1::uuid LIMIT 1`,
        [deps.nodeId],
      );
      observerId = again.rows[0]?.id ?? observerId;
    }

    const wallet = await client.query<{ id: string }>(
      `SELECT id::text AS id FROM wallets WHERE public_key = $1 LIMIT 1`,
      [walletPublicKey],
    );
    const walletId = wallet.rows[0]?.id ?? null;
    const maxSeq = await client.query<{ m: string | null }>(
      `SELECT max(wallet_seq)::text AS m FROM gateway_observations
        WHERE observer_id = $1::uuid AND wallet_public_key = $2`,
      [observerId, walletPublicKey],
    );
    const nextSeq = BigInt(maxSeq.rows[0]?.m ?? "0") + 1n;
    const observationId = randomUUID();
    const now = new Date().toISOString();
    await client.query(
      `INSERT INTO gateway_observations (
         id, observer_id, endpoint_fingerprint, wallet_id, wallet_public_key, wallet_seq,
         observed_at, http_status, raw_response_bytes, raw_response_sha256,
         parse_result, relationship, semantic_fingerprint, state_changed,
         wallet_role, s_signature, p_signature, b_amount,
         inner_preimage_text, step_1_signature, step_2_signature,
         completed_transaction_text, completed_transaction_sha256,
         previous_recorded_observation_id
       ) VALUES (
         $1::uuid, $2::uuid, $3, $4::uuid, $5, $6,
         $7, 200, $8, $9,
         'VERIFIED_GENESIS'::observation_parse_result,
         'FIRST'::observation_relationship,
         $10, true,
         'genesis', '', '', '0',
         NULL, NULL, NULL, NULL, NULL, NULL
       )`,
      [
        observationId,
        observerId,
        ENDPOINT_FINGERPRINT,
        walletId,
        walletPublicKey,
        nextSeq.toString(),
        now,
        GENESIS_RAW,
        GENESIS_RAW_SHA,
        GENESIS_SEMANTIC,
      ],
    );
    await client.query("COMMIT");
    return { kind: "VERIFIED", observationId, projection: GENESIS_PROJECTION };
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch {
      /* original */
    }
    throw err;
  } finally {
    client.release();
  }
}

export function createGenesisT0Observer(deps: {
  readonly pool: Pool;
  readonly nodeId: string;
  readonly moneyPathStatementTimeoutMs?: number;
}): ReceiveT0Observer {
  return {
    async observe(walletPublicKey: string): Promise<ReceiveT0Observation> {
      try {
        return await withSerializationRetry(DEFAULT_SERIALIZATION_RETRY_POLICY, () =>
          captureGenesisObservation(deps, walletPublicKey),
        );
      } catch (err) {
        return {
          kind: "INDETERMINATE",
          detail: err instanceof Error ? err.message : "genesis T0 stub failed",
        };
      }
    },
  };
}

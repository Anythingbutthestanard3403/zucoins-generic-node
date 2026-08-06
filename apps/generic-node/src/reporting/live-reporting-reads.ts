// LIVE composition for reporting list/stream/snapshot + verification-material
// and durable subscription_handles (SSE op lifecycle).
//
// Bound to the same Pool as DurableReportingRequestStore so event pages and handle
// lookups survive process restart.
//
// Boundary: apps/generic-node imports only @zucoins/node-core (no subpaths) plus local modules.

import type { Pool } from "pg";

import {
  REPORTING_ROUTE_IDS,
  assembleVerificationMaterialFromTables,
  createDestinationsListRouteHandler,
  createEventsListRouteHandler,
  createEventsStreamRouteHandler,
  createPgImplementerEventLog,
  createPgSnapshotStateReader,
  createPgSnapshotStore,
  createSqlOperationLifecycleStore,
  createSqlSubscriptionHandleStore,
  createSqlVerificationMaterialTablePort,
  createGatedTableVerificationMaterialSource,
  createStateSnapshotRouteHandler,
  createTableBackedVerificationMaterialSource,
  type DestinationService,
  type LoadOperationFn,
  type OperationSubscribeRouteDeps,
  type ReportingHandlerRegistry,
  type ReportingRouteHandler,
  type VerificationMaterialSource,
  type ProofBodyStore,
  type VerificationAccessWindowStore,
} from "@zucoins/node-core";

import { createVerificationMaterialRouteHandler } from "../operations/verification-material-route.js";
import {
  LIVE_VERIFICATION_COMPLETE_ENGINE,
  createVerificationCompleteRouteHandler,
} from "../operations/verification-complete-route.js";

export { LIVE_VERIFICATION_COMPLETE_ENGINE };

/**
 * Behavioural liveness brand. Defined here (not full-http-mount) so live-reporting-reads
 * does not circular-import from the module that re-exports its engine constants.
 */
export const LIVE_HANDLER_BRAND = Symbol.for("zupayments.liveReportingEngine");
export type LiveReportingRouteHandler = ReportingRouteHandler & {
  readonly [LIVE_HANDLER_BRAND]: true;
};

/** Brand a handler as LIVE so the census positively identifies it. */
export function brandLiveHandler(handler: ReportingRouteHandler): LiveReportingRouteHandler {
  return Object.assign(handler, { [LIVE_HANDLER_BRAND]: true as const });
}

export const LIVE_EVENTS_LIST_ENGINE = Object.freeze({
  routeId: "events_list" as const,
  handler: "createEventsListRouteHandler + createPgImplementerEventLog",
  ticket: "live GET /v1/events over durable implementer event log",
});

export const LIVE_EVENTS_STREAM_ENGINE = Object.freeze({
  routeId: "events_stream" as const,
  handler:
    "createEventsStreamRouteHandler + createPgImplementerEventLog + http-adapter openSink hold",
  ticket: "live GET /v1/events/stream over durable implementer event log (SSE hold)",
});

export const LIVE_STATE_SNAPSHOT_ENGINE = Object.freeze({
  routeId: "state_snapshot" as const,
  handler: "createStateSnapshotRouteHandler + createPgSnapshotStore/StateReader",
  ticket: "live GET /v1/state/snapshot over durable snapshot SQL",
});

export const LIVE_VERIFICATION_MATERIAL_ENGINE = Object.freeze({
  routeId: "verification_material" as const,
  handler: "createVerificationMaterialRouteHandler + SQL table port",
  ticket: "live GET verification-material over durable tables",
});

export const LIVE_DESTINATIONS_LIST_ENGINE = Object.freeze({
  routeId: "destinations_list" as const,
  handler: "createDestinationsListRouteHandler",
  ticket: "live GET /v1/destinations over the signed reporting credential (dual auth)",
});

export const DURABLE_SUBSCRIPTION_HANDLES = Object.freeze({
  kind: "durable-pg" as const,
  store: "createSqlSubscriptionHandleStore + createSqlOperationLifecycleStore",
  ticket: "durable subscription_handles + operations lifecycle for reporting SSE",
});

export type LiveReportingReadEngine =
  | typeof LIVE_EVENTS_LIST_ENGINE
  | typeof LIVE_EVENTS_STREAM_ENGINE
  | typeof LIVE_STATE_SNAPSHOT_ENGINE
  | typeof LIVE_VERIFICATION_MATERIAL_ENGINE
  | typeof LIVE_VERIFICATION_COMPLETE_ENGINE
  | typeof LIVE_DESTINATIONS_LIST_ENGINE;

type SqlQ = (
  text: string,
  values?: readonly unknown[],
) => Promise<readonly Record<string, unknown>[]>;

function poolQuery(pool: Pool): SqlQ {
  return async (text, values) => {
    const result = await pool.query(text, (values ?? []) as unknown[]);
    return result.rows as Record<string, unknown>[];
  };
}

function poolTx(pool: Pool): <T>(body: (query: SqlQ) => Promise<T>) => Promise<T> {
  return async (body) => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const query: SqlQ = async (text, values) => {
        const result = await client.query(text, (values ?? []) as unknown[]);
        return result.rows as Record<string, unknown>[];
      };
      const out = await body(query);
      await client.query("COMMIT");
      return out;
    } catch (err) {
      try {
        await client.query("ROLLBACK");
      } catch {
        /* ignore */
      }
      throw err;
    } finally {
      client.release();
    }
  };
}

function poolSqlExecutor(pool: Pool) {
  return {
    async query<R extends Record<string, unknown> = Record<string, unknown>>(
      text: string,
      params?: readonly unknown[],
    ): Promise<{ rows: R[] }> {
      const result = await pool.query(text, (params ?? []) as unknown[]);
      return { rows: result.rows as R[] };
    },
  };
}

const LOAD_OP_HEADER = `
SELECT kind::text AS kind,
       status::text AS status,
       CASE WHEN verification_material_available_until IS NULL THEN NULL
            ELSE (EXTRACT(EPOCH FROM verification_material_available_until) * 1000)::bigint
       END AS verification_material_available_until_ms
  FROM operations
 WHERE id = $1::uuid AND implementer_id = $2::uuid
 LIMIT 1
`;

function createLoadOperation(pool: Pool): LoadOperationFn {
  return async (operationId, implementerId) => {
    const result = await pool.query(LOAD_OP_HEADER, [operationId, implementerId]);
    const row = result.rows[0] as
      | {
          kind: string;
          status: string;
          verification_material_available_until_ms: string | number | null;
        }
      | undefined;
    if (row === undefined) return null;
    const until = row.verification_material_available_until_ms;
    return {
      kind: row.kind as never,
      status: row.status,
      verification_material_available_until_ms:
        until === null || until === undefined ? null : Number(until),
    };
  };
}

export function createVerificationMaterialSource(
  pool: Pool,
  proofBodyStore: ProofBodyStore,
  accessWindowStore: VerificationAccessWindowStore,
  nowMs: () => number,
): VerificationMaterialSource {
  const query = poolQuery(pool);
  // Prefer lineage_path_bodies (default BODIES_SELECT). proof_channel_candidate_bodies
  // is a separate OBS channel and is often empty after land writers that only promote
  // lineage. Fall back to the proof-body store when lineage has no rows.
  if (proofBodyStore.findByPathProof === undefined) {
    throw new Error("production proofBodyStore must support exact path reads by path_index");
  }
  const port = createSqlVerificationMaterialTablePort(query, {
    loadProofBodies: async (pathProofId) => {
      const lineage = await query(
        `SELECT path_index, step_2_signature, p_signature,
                completed_transaction_sha256, completed_transaction_text
           FROM lineage_path_bodies
          WHERE path_proof_id = $1::uuid
          ORDER BY path_index ASC -- contract-allow:order:frozen structural vocabulary`,
        [pathProofId],
      );
      if (lineage.length > 0) {
        return lineage.map((b) => ({
          path_index: Number(b.path_index),
          step_2_signature: String(b.step_2_signature ?? ""),
          p_signature: String(b.p_signature ?? ""),
          completed_transaction_sha256: String(b.completed_transaction_sha256 ?? ""),
          completed_transaction_text: String(b.completed_transaction_text ?? ""),
        }));
      }
      return (await proofBodyStore.findByPathProof!(pathProofId)).map((body) => ({
        path_index: body.path_index,
        step_2_signature: body.step_2_signature,
        p_signature: body.p_signature,
        completed_transaction_sha256: body.completed_transaction_sha256,
        completed_transaction_text: body.completed_transaction_text,
      }));
    },
  });
  const inner = createTableBackedVerificationMaterialSource({
    assemble: assembleVerificationMaterialFromTables as never,
    port,
    loadOperation: createLoadOperation(pool),
  });
  return createGatedTableVerificationMaterialSource({ inner, accessWindowStore, nowMs });
}

export interface LiveReportingReadsConfig {
  readonly pool: Pool;
  readonly nodeId: string;
  readonly newRequestId: () => string;
  readonly nowMs: () => number;
  readonly failClosed: ReportingRouteHandler;
  readonly liveArm: ReportingRouteHandler;
  readonly destinationService?: DestinationService;
  readonly proofBodyStore: ProofBodyStore;
  readonly verificationAccessStore: VerificationAccessWindowStore;
}

export interface LiveReportingReadsSurface {
  readonly handlers: ReportingHandlerRegistry;
  readonly subscribeDeps: OperationSubscribeRouteDeps;
  readonly liveEngines: readonly LiveReportingReadEngine[];
  readonly subscriptionHandlesKind: typeof DURABLE_SUBSCRIPTION_HANDLES;
}

/**
 * Build live reporting read handlers + durable subscribe deps for custody production.
 */
export function createLiveReportingReads(
  config: LiveReportingReadsConfig,
): LiveReportingReadsSurface {
  const query = poolQuery(config.pool);
  const withTransaction = poolTx(config.pool);
  const eventLog = createPgImplementerEventLog({
    nodeId: config.nodeId,
    query,
    withTransaction,
  });
  const snapshotStore = createPgSnapshotStore({ nodeId: config.nodeId, query });
  const snapshotReader = createPgSnapshotStateReader({
    nodeId: config.nodeId,
    query,
    nowMs: config.nowMs,
  });
  const vmSource = createVerificationMaterialSource(
    config.pool, config.proofBodyStore, config.verificationAccessStore, config.nowMs,
  );

  const handlers = Object.freeze({
    [REPORTING_ROUTE_IDS.destinationsList]:
      config.destinationService !== undefined
        ? brandLiveHandler(createDestinationsListRouteHandler({
            service: config.destinationService,
            newRequestId: config.newRequestId,
          }))
        : config.failClosed,
    [REPORTING_ROUTE_IDS.eventsList]: brandLiveHandler(createEventsListRouteHandler({
      store: eventLog,
      nowMs: config.nowMs,
      newRequestId: config.newRequestId,
    })),
    [REPORTING_ROUTE_IDS.eventsStream]: brandLiveHandler(createEventsStreamRouteHandler({
      log: eventLog,
      nowMs: config.nowMs,
      newRequestId: config.newRequestId,
    })),
    [REPORTING_ROUTE_IDS.stateSnapshot]: brandLiveHandler(createStateSnapshotRouteHandler({
      log: eventLog,
      reader: snapshotReader,
      store: snapshotStore,
      nowMs: config.nowMs,
      newRequestId: config.newRequestId,
    })),
    [REPORTING_ROUTE_IDS.verificationMaterial]: brandLiveHandler(createVerificationMaterialRouteHandler({
      source: vmSource,
      nowMs: config.nowMs,
      newRequestId: config.newRequestId,
    })),
    [REPORTING_ROUTE_IDS.operationArmed]: brandLiveHandler(config.liveArm),
    [REPORTING_ROUTE_IDS.verificationComplete]: brandLiveHandler(createVerificationCompleteRouteHandler({
      pool: config.pool,
      nodeId: config.nodeId,
      newRequestId: config.newRequestId,
      nowMs: config.nowMs,
    })),
  }) satisfies ReportingHandlerRegistry;

  const sql = poolSqlExecutor(config.pool);
  const subscribeDeps: OperationSubscribeRouteDeps = {
    handleStore: createSqlSubscriptionHandleStore(sql),
    lifecycleStore: createSqlOperationLifecycleStore(sql),
    nowMs: config.nowMs,
    newRequestId: config.newRequestId,
    pollMs: 250,
  };

  return Object.freeze({
    handlers,
    subscribeDeps,
    liveEngines: Object.freeze([
      LIVE_EVENTS_LIST_ENGINE,
      LIVE_EVENTS_STREAM_ENGINE,
      LIVE_STATE_SNAPSHOT_ENGINE,
      LIVE_VERIFICATION_MATERIAL_ENGINE,
      LIVE_VERIFICATION_COMPLETE_ENGINE,
      ...(config.destinationService !== undefined ? [LIVE_DESTINATIONS_LIST_ENGINE] : []),
    ]),
    subscriptionHandlesKind: DURABLE_SUBSCRIPTION_HANDLES,
  });
}

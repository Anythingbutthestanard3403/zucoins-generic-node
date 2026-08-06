// Durable `receive.ready` appender for the custody money path, replacing the
// earlier noop that only logged "node_events chain residual".
//
// Invariants: the event is appended in the READY transaction (dual continuity);
// the appended zp-implementer-event-v1 proof is what GET /v1/events serves.
//
// The appender is built PER TRANSACTION and bound to the same `tx` that performs the
// CREATED→READY CAS, so the event is durable exactly when READY is. Nothing here pushes:
// the node appends, the tenant pulls (no outbox, no delivery table).
//
// fail-closed on EVERY branch. There is exactly one rule here: no
// committed transition without its signed event (Byte-exact). Whenever the event cannot be
// appended — signer unavailable, no `receive_operations` row to resolve the implementer,
// or the tenant is over its event quota — this throws, so the caller's transaction (the
// one running the CREATED→READY CAS) rolls back and the transition is simply not made.
// It never returns normally after skipping the append: that would let the money move and
// log the missing evidence as a residual, which is the defect this file used to have.

import {
  createDualChainEventAppender,
  type DualChainEventQuota,
  type NodeEventSigner,
  type ReceiveReadyEventAppender,
} from "@zucoins/node-core";

import type { MoneyWorkerLogger } from "./start-money-workers.js";

/** Same shape the money workers already use for SQL inside a transaction. */
export interface AppenderSql {
  query<R>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ rows: R[]; rowCount: number | null }>;
}

const SELECT_IMPLEMENTER = `
SELECT implementer_id::text AS implementer_id
  FROM receive_operations
 WHERE operation_id = $1::uuid
`;

export interface ReceiveReadyEventAppenderDeps {
  /** MUST be the transaction running the READY CAS. */
  readonly sql: AppenderSql;
  readonly nodeId: string;
  readonly eventSigner: NodeEventSigner | null;
  readonly logger: MoneyWorkerLogger;
  readonly quota?: DualChainEventQuota;
  readonly now?: () => Date;
}

export function createDurableReceiveReadyEventAppender(
  deps: ReceiveReadyEventAppenderDeps,
): ReceiveReadyEventAppender {
  const now = deps.now ?? (() => new Date());
  return {
    async appendReceiveReady(input) {
      const signer = deps.eventSigner;
      if (signer === null) {
        throw new Error(
          `money-workers: receive.ready NOT appended op=${input.operationId} — EVENT_SIGNING signer unavailable; refusing the READY transition (Byte-exact)`,
        );
      }

      const owner = await deps.sql.query<{ implementer_id: string }>(SELECT_IMPLEMENTER, [
        input.operationId,
      ]);
      const implementerId = owner.rows[0]?.implementer_id;
      if (implementerId === undefined) {
        // The CAS updates `operations` while this lookup reads `receive_operations` — two
        // tables, so a projection gap is real and would otherwise commit READY eventless.
        throw new Error(
          `money-workers: receive.ready NOT appended op=${input.operationId} — no receive_operations row to resolve implementer_id; refusing the READY transition (Byte-exact)`,
        );
      }

      const appender = createDualChainEventAppender({
        nodeId: deps.nodeId,
        // Bind to the caller's transaction so both chain rows commit with READY.
        query: async (text, values) => {
          const result = await deps.sql.query<Record<string, unknown>>(text, values);
          return result.rows;
        },
        signer,
        ...(deps.quota !== undefined ? { quota: deps.quota } : {}),
      });

      const outcome = await appender.append({
        implementerId,
        eventType: "receive.ready",
        operationId: input.operationId,
        walletId: input.walletId,
        dataText: input.dataText,
        dataSha256: input.dataSha256,
        createdAt: now().toISOString(),
      });

      if (outcome.kind === "QUOTA_EXCEEDED") {
        // The quota bounds table growth, not custody. Over the cap the transition
        // does not happen at all — the operation stays CREATED and expires on its own TTL
        // rather than becoming READY with no event on either chain.
        throw new Error(
          `money-workers: receive.ready NOT appended op=${input.operationId} — implementer ${implementerId} over event quota (${outcome.windowCap} per ${outcome.windowMs}ms); refusing the READY transition (Byte-exact)`,
        );
      }
      deps.logger.info(
        `money-workers: receive.ready appended op=${input.operationId} node_seq=${outcome.nodeSeq.toString()} implementer_seq=${outcome.implementerSeq.toString()}`,
      );
    },
  };
}

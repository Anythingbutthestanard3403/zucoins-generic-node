// RECEIVE candidate intake worker step.
// Production importer of createCandidateIntakeService.

import {
  CandidateIntakeError,
  createCandidateIntakeService,
  type CandidateIntakeRequest,
  type CandidateIntakeService,
  type MetricCandidateIntakeSource,
  type MetricsHooks,
  type SenderPreflightObserver,
  type SqlQueryFn,
} from "@zucoins/node-core";

import type { MoneyWorkerLogger } from "./start-money-workers.js";
import {
  createCandidateRawCapturePort,
  createSqlCandidatePersistPort,
  createSqlLocateReceivePort,
} from "./sql-candidate-intake-ports.js";

export const INTAKE_BATCH_LIMIT = 5;

/**
 * Producer lane. Alias of the closed metric domain so the label vocabulary has one
 * source of truth: `push` is the Web Push delivery channel (authenticated by the ECE
 * auth secret + endpoint id), `relay` the anonymous origin-relay POST.
 */
export type CandidateIntakeSource = MetricCandidateIntakeSource;

export interface CandidateIntakeEnqueueResult {
  readonly enqueued: boolean;
  /** Set only on refusal. Coarse — never echoes signed material. */
  readonly reason?: "inbox_full";
}

export interface CandidateIntakeInbox {
  readonly size: () => number;
  /** Current depth of one producer lane (for the backlog gauge). */
  readonly sizeBySource: (source: CandidateIntakeSource) => number;
  readonly take: (limit: number) => readonly CandidateIntakeRequest[];
  readonly enqueue: (
    request: CandidateIntakeRequest,
    source: CandidateIntakeSource,
  ) => CandidateIntakeEnqueueResult;
}

/**
 * Two capped lanes behind one inbox, so both producers are bounded by construction.
 *
 * `maxPerSource` is the per-lane ceiling and is derived, never a free number: pass
 * RECEIVE_QUEUE_CAP (= POOL_CAP_TOTAL; see config/env-schema.ts receiveQueueCap). A
 * deposit is only useful if it matches a live receive, and POOL_CAP_TOTAL is the hard
 * maximum wallets across all states, so at most that many receives can be outstanding
 * at once. A single lane holding more than that cannot be all-distinct-and-genuine —
 * past the cap the marginal entry is backlog, not signal.
 *
 * Per-lane rather than shared: a shared cap would let an anonymous flood consume the
 * authenticated lane's headroom, converting the starvation into an outright refusal
 * of genuine deliveries.
 */
export function createCandidateIntakeInbox(maxPerSource: number): CandidateIntakeInbox {
  if (!Number.isInteger(maxPerSource) || maxPerSource < 1) {
    throw new Error(
      `candidate intake inbox requires an integer maxPerSource >= 1, got ${String(maxPerSource)}`,
    );
  }
  const lanes: Record<CandidateIntakeSource, CandidateIntakeRequest[]> = { push: [], relay: [] };
  return {
    size: () => lanes.push.length + lanes.relay.length,
    sizeBySource: (source) => lanes[source].length,
    take(limit) {
      if (limit <= 0) return [];
      // Strict preference for the authenticated lane: relay entries are only served
      // with the budget push leaves behind, so an anonymous backlog can never delay a
      // verified delivery. Push is itself bounded by the push service's delivery rate.
      const batch = lanes.push.splice(0, Math.min(limit, lanes.push.length));
      if (batch.length < limit) {
        batch.push(...lanes.relay.splice(0, limit - batch.length));
      }
      return batch;
    },
    enqueue(request, source) {
      const lane = lanes[source];
      if (lane.length >= maxPerSource) return { enqueued: false, reason: "inbox_full" };
      lane.push(request);
      return { enqueued: true };
    },
  };
}

export interface ReceiveCandidateIntakeStepDeps {
  readonly query: SqlQueryFn;
  readonly inbox: CandidateIntakeInbox;
  readonly observeSender: SenderPreflightObserver;
  readonly logger: MoneyWorkerLogger;
  /** Optional: publish gn_candidate_intake_backlog after the batch. */
  readonly metricsHooks?: MetricsHooks;
  readonly nowMs?: () => number;
  readonly nowIso?: () => string;
}

export function createProductionCandidateIntakeService(
  deps: Omit<ReceiveCandidateIntakeStepDeps, "inbox" | "logger">,
): CandidateIntakeService {
  const nowMs = deps.nowMs ?? (() => Date.now());
  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  return createCandidateIntakeService({
    locate: createSqlLocateReceivePort(deps.query),
    capture: createCandidateRawCapturePort(nowIso),
    observeSender: deps.observeSender,
    persist: createSqlCandidatePersistPort(deps.query),
    clock: { nowMs, nowIso },
  });
}

export async function runReceiveCandidateIntakeStep(
  deps: ReceiveCandidateIntakeStepDeps,
): Promise<number> {
  const batch = deps.inbox.take(INTAKE_BATCH_LIMIT);
  // Depth after take is the truth the gauge should show — publish even on an empty
  // batch so a scrape after a full empty does not keep a stale non-zero.
  deps.metricsHooks?.setCandidateIntakeBacklog("push", deps.inbox.sizeBySource("push"));
  deps.metricsHooks?.setCandidateIntakeBacklog("relay", deps.inbox.sizeBySource("relay"));
  if (batch.length === 0) return 0;

  const service = createProductionCandidateIntakeService(deps);
  let accepted = 0;
  for (const request of batch) {
    try {
      const result = await service.intake(request);
      accepted += 1;
      deps.logger.info(
        `money-workers: candidate intake ACCEPTED op=${result.operationId} phase=${result.attemptPhase} inner_sha=${result.innerSha256.slice(0, 12)}…`,
      );
    } catch (err) {
      const reason =
        err instanceof CandidateIntakeError
          ? err.reason
          : err instanceof Error
            ? err.message
            : "unknown";
      deps.logger.info(
        `money-workers: candidate intake rejected reason=${reason} recv=${request.locate.receiverPubkey.slice(0, 12)}…`,
      );
    }
  }
  return accepted;
}

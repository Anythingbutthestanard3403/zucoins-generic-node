// RECEIVE candidate intake worker step.
// Production importer of createCandidateIntakeService.

import {
  CandidateIntakeError,
  createCandidateIntakeService,
  type CandidateIntakeRequest,
  type CandidateIntakeService,
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

export interface CandidateIntakeInbox {
  readonly size: () => number;
  readonly take: (limit: number) => readonly CandidateIntakeRequest[];
  readonly enqueue: (request: CandidateIntakeRequest) => void;
}

export function createCandidateIntakeInbox(): CandidateIntakeInbox {
  const q: CandidateIntakeRequest[] = [];
  return {
    size: () => q.length,
    take(limit) {
      if (limit <= 0 || q.length === 0) return [];
      return q.splice(0, Math.min(limit, q.length));
    },
    enqueue(request) {
      q.push(request);
    },
  };
}

export interface ReceiveCandidateIntakeStepDeps {
  readonly query: SqlQueryFn;
  readonly inbox: CandidateIntakeInbox;
  readonly observeSender: SenderPreflightObserver;
  readonly logger: MoneyWorkerLogger;
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

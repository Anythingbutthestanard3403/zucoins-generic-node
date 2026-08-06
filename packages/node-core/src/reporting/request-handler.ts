// post-burn orchestration for verified signed reporting requests
// (POST_BURN_STAGES): completed-idempotency lookup and fingerprint check →
// tenant-scoped protected lookup → injected handler. Every outcome of this stage — replay,
// conflict, absent object, handler crash — RETAINS the committed nonce burn; the burn is
// never folded into or rolled back with the handler's mutation.
//
// Replay returns the stored exact status and body bytes as a fresh byte copy with
// `Idempotency-Replayed: true`. A completed record with a different
// (method, raw target, body digest) fingerprint is a 409 conflict resolved BEFORE any
// protected-object lookup, so object existence is never revealed (the persistence CONTRACT's
// no-existence-oracle rule). Business handlers are later slices: the registry ships empty by
// default and an unhandled route resolves as the absent-object 404 after the burn.
//
// A successful mutation's guarded child row and completed idempotency parent commit
// as ONE unit of work via store.commitMutationWithCompletedIdempotency. The handler does not
// return a pre-committed childRecordId — it supplies persistChild so the child is written
// inside the same transaction that inserts the completion row: together or neither, as
// MUTATION_IDEMPOTENCY_PERSISTENCE.mutationAndCompletedResultAtomic requires.

import { randomUUID } from "node:crypto";

import { sameLogicalFingerprint, type LogicalFingerprintInput } from "@zucoins/generic-node-contracts";

import { reportingErrorResponse, type ReportingHttpResponse } from "./errors.js";
import type { CapturedReportRequest, ReportingRequestVerifier, VerifiedReportRequest } from "./request-verifier.js";
import type {
  CompletedIdempotencyRecord,
  ReportingMutationTx,
  ReportingRequestStore,
} from "./store.js";
import type { SseSink } from "./event-stream-sse.js";

export interface ReportingHandlerResult {
  readonly response: ReportingHttpResponse;
  // null → no mutation committed, so no completion row is written (reads, 4xx business
  // outcomes, etc.). A 2xx mutation MUST supply persistChild so the child + parent pair
  // commits atomically; an empty string child id is rejected by the store.
  // persistChild receives the completion parent PK (`draft.id`) — child
  // `mutation_idempotency_id` MUST equal that value (deferred FK + correlation assert).
  readonly persistChild:
    | ((tx: ReportingMutationTx, completedIdempotencyId: string) => Promise<string>)
    | null;
}

/** Per-request SSE side-channel supplied by the HTTP adapter (r2). */
export interface ReportingTransportSideChannel {
  readonly openSink: (headers: Readonly<Record<string, string>>) => SseSink;
}

export type ReportingRouteHandler = (
  request: VerifiedReportRequest,
  transport?: ReportingTransportSideChannel,
) => Promise<ReportingHandlerResult>;

export type ReportingHandlerRegistry = Readonly<Record<string, ReportingRouteHandler>>;

export interface ReportingRequestHandlerConfig {
  readonly verifier: ReportingRequestVerifier;
  readonly store: ReportingRequestStore;
  readonly handlers: ReportingHandlerRegistry;
  readonly newRequestId: () => string;
  readonly nowMs: () => number;
}

export interface ReportingRequestHandler {
  handle(
    captured: CapturedReportRequest,
    transport?: ReportingTransportSideChannel,
  ): Promise<ReportingHttpResponse>;
}

function fingerprintOf(
  request: VerifiedReportRequest,
  method: string,
  rawTarget: string,
  bodySha256: string,
): LogicalFingerprintInput {
  return {
    method,
    rawTarget,
    bodySha256,
    nonce: request.nonceEvidence.nonce,
    reportingKeyId: request.nonceEvidence.reportingKeyId,
    lifecycleEpoch: request.nonceEvidence.lifecycleEpoch,
    issuedAt: request.nonceEvidence.issuedAt,
    expiresAt: request.nonceEvidence.expiresAt,
    idempotencyKey: request.idempotencyKey ?? "",
  };
}

function replayResponse(record: CompletedIdempotencyRecord): ReportingHttpResponse {
  return {
    status: record.responseStatus,
    headers: { "content-type": "application/json", "idempotency-replayed": "true" },
    bodyBytes: new Uint8Array(record.responseBytes),
  };
}

function handlerResultShapeIsValid(result: ReportingHandlerResult): boolean {
  const { status } = result.response;
  if (!Number.isInteger(status) || status < 100 || status > 599) return false;
  if (status < 200 || status >= 300) return true;
  return result.persistChild === null || typeof result.persistChild === "function";
}

export function createReportingRequestHandler(
  config: ReportingRequestHandlerConfig,
): ReportingRequestHandler {
  const conflict = (): ReportingHttpResponse =>
    reportingErrorResponse("idempotency_conflict", config.newRequestId());

  const resolveCompleted = async (
    verified: VerifiedReportRequest,
  ): Promise<ReportingHttpResponse | null> => {
    if (verified.route.requestClass !== "MUTATION" || verified.idempotencyKey === null) {
      return null;
    }
    const completed = await config.store.findCompletedIdempotency(
      verified.nonceEvidence.nodeId,
      verified.nonceEvidence.implementerId,
      verified.route.routeId,
      verified.idempotencyKey,
    );
    if (completed === null) return null;
    const matches = sameLogicalFingerprint(
      fingerprintOf(verified, completed.method, completed.rawTarget, completed.bodySha256),
      fingerprintOf(verified, verified.fingerprint.method, verified.fingerprint.rawTarget, verified.fingerprint.bodySha256),
    );
    return matches ? replayResponse(completed) : conflict();
  };

  const commitMutation = async (
    verified: VerifiedReportRequest,
    result: ReportingHandlerResult,
  ): Promise<ReportingHttpResponse | null> => {
    if (
      verified.route.requestClass !== "MUTATION" ||
      verified.idempotencyKey === null ||
      result.persistChild === null ||
      result.response.status < 200 ||
      result.response.status >= 300
    ) {
      return null;
    }
    // Parents PK is a uuid (reporting_mutation_idempotency.id). Replay looks up by
    // (node_id, implementer_id, route_id, idempotency_key) so the PK need not be
    // deterministic across retries. Within ONE unit of work the same
    // uuid is the child's mutation_idempotency_id (deferred FK + correlation assert)
    // store.commitMutationWithCompletedIdempotency passes draft.id into persistChild.
    const draft = {
      id: randomUUID(),
      nodeId: verified.nonceEvidence.nodeId,
      implementerId: verified.nonceEvidence.implementerId,
      routeId: verified.route.routeId,
      idempotencyKey: verified.idempotencyKey,
      reportingNonceId: verified.nonceEvidence.id,
      method: verified.fingerprint.method,
      rawTarget: verified.fingerprint.rawTarget,
      bodySha256: verified.fingerprint.bodySha256,
      logicalFingerprint: verified.nonceEvidence.logicalFingerprint,
      responseStatus: result.response.status,
      responseBytes: Uint8Array.from(result.response.bodyBytes),
      completedAtMs: config.nowMs(),
    };
    const committed = await config.store.commitMutationWithCompletedIdempotency({
      persistChild: result.persistChild,
      record: draft,
    });
    if (committed.kind === "INSERTED") return null;
    return (await resolveCompleted(verified)) ?? conflict();
  };

  const handle = async (
    captured: CapturedReportRequest,
    transport?: ReportingTransportSideChannel,
  ): Promise<ReportingHttpResponse> => {
    const outcome = await config.verifier.verify(captured);
    if (!outcome.ok) {
      return reportingErrorResponse(outcome.code, config.newRequestId(), outcome.message);
    }
    const completed = await resolveCompleted(outcome);
    if (completed !== null) return completed;

    const handler = config.handlers[outcome.route.routeId];
    if (handler === undefined) {
      return reportingErrorResponse("not_found", config.newRequestId());
    }
    let result: ReportingHandlerResult;
    try {
      result = await handler(outcome, transport);
    } catch {
      return reportingErrorResponse("internal_error", config.newRequestId());
    }
    if (!handlerResultShapeIsValid(result)) {
      return reportingErrorResponse("internal_error", config.newRequestId());
    }
    try {
      const raced = await commitMutation(outcome, result);
      return raced ?? result.response;
    } catch {
      return reportingErrorResponse("internal_error", config.newRequestId());
    }
  };

  return { handle };
}

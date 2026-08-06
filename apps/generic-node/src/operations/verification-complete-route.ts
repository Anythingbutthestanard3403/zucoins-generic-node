// generic-node LIVE composition for
// `POST /v1/operations/:operation_id/verification-complete`.
//
// Implements the frozen verification-complete request/response contract, its
// atomicity freeze, and the consumer ACK barrier (consumer posture stays
// independent verification — it never trusts a node success claim).
//
// Auth is the signed reporting credential (`zp-report-request-v1`) — the reporting
// request pipeline verifies the credential (signature, nonce burn, window) before this
// handler runs. This module only binds `createSqlVerificationCompleteStore` to that
// pipeline under the frozen reporting route id `verification_complete`.
//
// Atomicity freeze: "verification-complete atomically commits its acknowledgement, any lease
// release, and a completed idempotency row with exact status and response-body bytes." The
// store's `freezeResponse` hook writes the completed-idempotency row on the SAME transaction
// as the acknowledgement and the lease release (see verification-complete-store.ts). The
// reporting runtime must therefore not write a second completion parent — this handler returns
// `persistChild: null`, exactly as the live ARM composition does (arm-live.ts). A replay is
// served by the runtime's own `findCompletedIdempotency` lookup from the row committed here.
//
// The byte-exact signing rule (byte-exact signing): the signed bytes travel on `request.nonceEvidence`
// (requestPreimageText / requestSignature) and are carried verbatim into the envelope — they
// are never re-derived or re-serialized here.
//
// Boundary: apps/generic-node may import only `@zucoins/node-core` (no subpaths).

import { randomUUID } from "node:crypto";

import {
  IdempotencyConflictError,
  OperationVersionConflictError,
  ProtocolPredicateFailedError,
  REPORTING_ROUTE_IDS,
  apiErrorResponse,
  parseStrictJson,
  reportingErrorResponse,
  VerificationCompleteBody,
  type AckWalletEvidenceInput,
  type ApiErrorCode,
  type ReportingHandlerResult,
  type ReportingHttpResponse,
  type ReportingRouteHandler,
  type VerificationCompleteInput,
  type VerificationCompleteSuccessResponse,
  type WalletEvidenceWire,
  type VerifiedReportRequest,
} from "@zucoins/node-core";
import type { Pool } from "pg";
import { isUniqueViolation } from "../reporting/pg-client.js";

import {
  createPoolVerificationCompleteTxFactory,
  createSqlVerificationCompleteStore,
  type VerificationCompleteEnvelope,
  type VerificationCompleteTx,
  type VerificationCompleteTxFactory,
} from "./verification-complete-store.js";

export const VERIFICATION_COMPLETE_ROUTE_ID = REPORTING_ROUTE_IDS.verificationComplete;

export const VERIFICATION_COMPLETE_PATH =
  "/v1/operations/:operation_id/verification-complete" as const;

const OPERATION_ID_FROM_TARGET =
  /^\/v1\/operations\/([^/?#]+)\/verification-complete(?:\?.*)?$/;

export function operationIdFromVerificationCompleteTarget(rawTarget: string): string | null {
  const match = OPERATION_ID_FROM_TARGET.exec(rawTarget);
  return match?.[1] ?? null;
}

const SELECT_OPERATION_FOR_ENVELOPE = `
  SELECT o.id                AS operation_id,
         o.node_id           AS node_id,
         o.implementer_id    AS implementer_id,
         o.kind::text        AS kind,
         o.row_version::text AS row_version,
         lgo.lease_group_id  AS lease_group_id,
         o.source_wallet_id  AS source_wallet_id,
         sw.public_key       AS source_public_key,
         o.receiver_wallet_id AS receiver_wallet_id,
         rw.public_key       AS receiver_public_key,
         o.destination_address AS destination_address,
         dw.id               AS destination_wallet_id,
         dw.public_key       AS destination_public_key
    FROM operations o
    LEFT JOIN lease_group_operations lgo ON lgo.operation_id = o.id
    LEFT JOIN wallets sw ON sw.id = o.source_wallet_id
    LEFT JOIN wallets rw ON rw.id = o.receiver_wallet_id
    LEFT JOIN destinations d ON d.id = o.destination_id
    LEFT JOIN wallets dw ON dw.id = d.wallet_id
   WHERE o.id = $1`;

interface OperationForEnvelopeRow {
  readonly operation_id: string;
  readonly node_id: string;
  readonly implementer_id: string;
  readonly kind: string;
  readonly row_version: string;
  readonly lease_group_id: string | null;
  readonly source_wallet_id: string | null;
  readonly source_public_key: string | null;
  readonly receiver_wallet_id: string | null;
  readonly receiver_public_key: string | null;
  readonly destination_address: string | null;
  readonly destination_wallet_id: string | null;
  readonly destination_public_key: string | null;
}

function resolveWalletEvidence(
  body: readonly WalletEvidenceWire[],
  operation: OperationForEnvelopeRow,
): readonly AckWalletEvidenceInput[] {
  const byRole: Record<string, { walletId: string | null; walletPublicKey: string }> = {
    RECEIVER: { walletId: operation.receiver_wallet_id, walletPublicKey: operation.receiver_public_key ?? "" },
    SOURCE: { walletId: operation.source_wallet_id, walletPublicKey: operation.source_public_key ?? "" },
    DESTINATION: { walletId: operation.destination_wallet_id, walletPublicKey: operation.destination_public_key ?? operation.destination_address ?? "" },
  };
  return body.map((entry) => {
    const expected = byRole[entry.role];
    return {
      walletId: entry.wallet_id,
      walletPublicKey: expected?.walletPublicKey ?? "",
      role: entry.role,
      t0: { observationId: entry.t0.observation_id },
      terminal: { observationId: entry.terminal.observation_id },
    };
  });
}

function successResponse(body: VerificationCompleteSuccessResponse): ReportingHttpResponse {
  return { status: 200, headers: { "content-type": "application/json" }, bodyBytes: new TextEncoder().encode(JSON.stringify(body)) };
}

function mapStoreError(err: unknown, requestId: string): ReportingHttpResponse {
  if (err instanceof OperationVersionConflictError) {
    const api = apiErrorResponse("operation_version_conflict", requestId);
    return { status: api.status, headers: api.headers, bodyBytes: new TextEncoder().encode(api.body) };
  }
  if (err instanceof IdempotencyConflictError) {
    const api = apiErrorResponse("idempotency_conflict", requestId);
    return { status: api.status, headers: api.headers, bodyBytes: new TextEncoder().encode(api.body) };
  }
  if (err instanceof ProtocolPredicateFailedError) {
    const api = apiErrorResponse("protocol_predicate_failed", requestId);
    return { status: api.status, headers: api.headers, bodyBytes: new TextEncoder().encode(api.body) };
  }
  return reportingErrorResponse("internal_error", requestId);
}

const INSERT_COMPLETED_IDEMPOTENCY = `
  INSERT INTO reporting_mutation_idempotency (
    id, node_id, implementer_id, route_id, idempotency_key, reporting_nonce_id,
    child_record_id, method, raw_target, body_sha256, response_status, response_bytes,
    completed_at, created_at
  ) VALUES (
    $1::uuid, $2::uuid, $3::uuid, $4, $5, $6::uuid,
    $7::uuid, $8, $9, $10, $11::int, $12::bytea,
    $13::timestamptz, $13::timestamptz
  )`;

export interface VerificationCompleteRouteDeps {
  readonly pool: Pool;
  readonly nodeId: string;
  readonly newRequestId: () => string;
  readonly nowMs: () => number;
  readonly txFactory?: VerificationCompleteTxFactory;
  readonly freezeResponse?: (tx: VerificationCompleteTx, operationId: string, body: VerificationCompleteSuccessResponse) => Promise<void>;
}

export const LIVE_VERIFICATION_COMPLETE_ENGINE = Object.freeze({
  routeId: "verification_complete" as const,
  handler: "createVerificationCompleteRouteHandler + createSqlVerificationCompleteStore (SQL ack + lease release)",
  ticket: "live verification-complete composition mounts the ACK + lease release",
});

export function createVerificationCompleteRouteHandler(deps: VerificationCompleteRouteDeps): ReportingRouteHandler {
  const txFactory = deps.txFactory ?? createPoolVerificationCompleteTxFactory(deps.pool);
  return async (request: VerifiedReportRequest): Promise<ReportingHandlerResult> => {
    const requestId = deps.newRequestId();
    const operationId = operationIdFromVerificationCompleteTarget(request.fingerprint.rawTarget);
    if (operationId === null) return { response: reportingErrorResponse("not_found", requestId), persistChild: null };
    // Strict-JSON intake ahead of the schema, mirroring arm-preopen.ts /
    // pipeline.ts. A bare JSON.parse is reviver-based and silently last-wins on duplicate
    // keys (D1) and never rejects a structurally wrong body before mutation side effects
    // run (D2) — both are forbidden per AC1. Nothing below this gate has touched the DB
    // or burned a nonce/idempotency slot yet.
    const jsonOutcome = parseStrictJson(request.bodyBytes);
    if (!jsonOutcome.ok) {
      const api = apiErrorResponse(jsonOutcome.code as ApiErrorCode, requestId);
      return { response: { status: api.status, headers: api.headers, bodyBytes: new TextEncoder().encode(api.body) }, persistChild: null };
    }

    const schemaResult = VerificationCompleteBody.safeParse(jsonOutcome.value);
    if (!schemaResult.success) {
      const issue = schemaResult.error.issues[0];
      const code: ApiErrorCode = issue?.code === "unrecognized_keys" ? "unknown_field" : "invalid_scalar";
      const api = apiErrorResponse(code, requestId);
      return { response: { status: api.status, headers: api.headers, bodyBytes: new TextEncoder().encode(api.body) }, persistChild: null };
    }

    const parsed: Omit<VerificationCompleteInput, "idempotencyKey"> = schemaResult.data;
    const mutationIdempotencyId = randomUUID();
    const envelopeFor = async (): Promise<VerificationCompleteEnvelope> => {
      const result = await deps.pool.query<OperationForEnvelopeRow>(SELECT_OPERATION_FOR_ENVELOPE, [operationId]);
      const row = result.rows[0];
      if (row === undefined) throw new ProtocolPredicateFailedError("OPERATION_NOT_FOUND");
      return {
        // Adversarial fix (Blocker 1): envelope tenant from the VERIFIED credential
        // binding (request.binding), NOT the operation row — so the ack service's
        // TENANT_MISMATCH predicate (acknowledgement.ts:398-407) compares the operation's own
        // tenant against the credential's tenant, reachable for a foreign-credential query
        // (instead of the unreachable x !== x the row-sourced tenant produced). Sibling
        // arm-live.ts:379-380 does the same.
        nodeId: request.binding.nodeId,
        implementerId: request.binding.implementerId,
        reportingNonceId: request.nonceEvidence.id,
        mutationIdempotencyId,
        rawTarget: request.fingerprint.rawTarget,
        requestBodySha256: request.fingerprint.bodySha256,
        requestPreimageText: request.nonceEvidence.requestPreimageText,
        requestSignature: request.nonceEvidence.requestSignature,
        ownerInstanceId: deps.nodeId,
        walletEvidence: resolveWalletEvidence(parsed.wallet_evidence, row),
      };
    };
    const freezeResponse = deps.freezeResponse ?? (async (tx: VerificationCompleteTx, _opId: string, body: VerificationCompleteSuccessResponse) => {
      const bodyText = JSON.stringify(body);
      await tx.query(INSERT_COMPLETED_IDEMPOTENCY, [
        mutationIdempotencyId, request.binding.nodeId, request.binding.implementerId, "verification_complete",
        request.idempotencyKey ?? "", request.nonceEvidence.id, body.acknowledgement_id,
        request.fingerprint.method, request.fingerprint.rawTarget, request.fingerprint.bodySha256,
        200, Buffer.from(bodyText, "utf8"), new Date(deps.nowMs()).toISOString(),
      ]);
    });
    const store = createSqlVerificationCompleteStore({ txFactory, envelopeFor, freezeResponse });
    const input: VerificationCompleteInput = { ...parsed, idempotencyKey: request.idempotencyKey ?? "" };
    try {
      const result = await store.verificationComplete(operationId, input);
      const body: VerificationCompleteSuccessResponse = result.body;
      const response = successResponse(body);
      if (result.idempotentReplay) {
        return { response: { ...response, headers: { ...response.headers, "idempotency-replayed": "true" } }, persistChild: null };
      }
      return { response, persistChild: null };
} catch (err) {
      // Adversarial fix (Defect 5): a concurrent same-Idempotency-Key loser races past
      // the runtime's resolveCompleted, both run the store, and the loser violates the
      // completed-idempotency UNIQUE (node_id, implementer_id, route_id, idempotency_key)
      // when freezeResponse inserts. The spec wants a replay or typed 409, never a bare 500
      // (arm-live.ts:505 handles the same race). Surface a 409 idempotency_conflict.
      if (isUniqueViolation(err)) {
        const api = apiErrorResponse("idempotency_conflict", requestId);
        return { response: { status: api.status, headers: api.headers, bodyBytes: new TextEncoder().encode(api.body) }, persistChild: null };
      }
      return { response: mapStoreError(err, requestId), persistChild: null };
    }
  };
}

export function verificationCompleteHandlerEntry(deps: VerificationCompleteRouteDeps): Readonly<Record<string, ReportingRouteHandler>> {
  return { [VERIFICATION_COMPLETE_ROUTE_ID]: createVerificationCompleteRouteHandler(deps) };
}

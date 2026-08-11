// live OperationRouteStore binding SQL admission stores to the three-ops engines.
//
// Root-level (like money-path-admission.ts) so it may compose api + receive + move + send
// without introducing an api↔receive cycle.
//
// Governing: the API contract (credential-bound implementerId, operation response shapes)
// and the operation-flow admission steps; the one-in-flight-per-wallet and never-blind-retry rules
// (one-in-flight / reconcile-before-retry — owned by the engines' DB unique indexes, never
// re-implemented here). Composition strongly refuses a live store without implementer_bearer
// (createOperationRouter).

import {
  DEFAULT_EXPIRES_IN_SECONDS,
  admitReceiveExternal,
  type AfterLanding,
  type ReceiveAdmissionStore,
  type ReceiveOperation,
  type ReceiveRejectionCode,
  type StoredReceiveOperation,
} from "./receive/admission.js";
import {
  createInternalMove,
  moveOutcomeToRouteResult,
  readInternalMove,
  type MoveCreateStore,
} from "./move/create.js";
import {
  buildExternalSendResponse,
  createExternalSend,
  readExternalSend,
  type ExternalSendPartialLoader,
  type SendArtifactSigner,
  type SendCreateOutcome,
  type SendCreateStore,
  type SendRejectionCode,
} from "./send/create.js";
import {
  IdempotencyInProgressError,
  IdempotencyKeyReusedError,
  ReceiveAdmissionError,
  ReceiveQueueFullError,
  SendAdmissionError,
  WalletBusyError,
  type CreateExternalSendInput,
  type CreateInternalMoveInput,
  type CreateReceiveInput,
  type ExternalSendResponse,
  type InternalMoveResponse,
  type OperationRouteStore,
  type ReceiveResponse,
} from "./api/routes/operation-routes.js";

export interface SqlOperationRouteStoreConfig {
  readonly nodeId: string;
  /** RECEIVE_QUEUE_CAP (= POOL_CAP_TOTAL). Required — no unbounded default. */
  readonly queueCap: number;
  readonly receive: ReceiveAdmissionStore;
  readonly move: MoveCreateStore;
  readonly send: SendCreateStore;
  /**
   * Node-identity artifact signer for SEND_EXTERNAL create. The key-custody rule:
   * node-core never holds key material; the composition root injects this port.
   */
  readonly sendSigner: SendArtifactSigner;
  /**
   * durable external_send_partials loader so GET at AWAITING_REDEMPTION returns
   * transfer_code / transfer_code_sha256. Optional: omit for create-only composition tests.
   */
  readonly sendPartials?: ExternalSendPartialLoader;
  readonly generateId?: () => string;
  readonly now?: () => number;
  /**
   * hard gate for EXTERNAL send: the source wallet must hold an ACTIVE push
   * subscription. Late-bound by the composition root (push is composed after the operation
   * store). MOVE_INTERNAL must NOT inject this port.
   */
  readonly requireActiveSubscription?: (walletId: string) => Promise<void>;
  /**
   * Operator-configured default receive TTL in seconds (RECEIVE_TTL_DEFAULT_SECS).
   * When omitted, falls back to DEFAULT_EXPIRES_IN_SECONDS (300) for unit tests.
   * Composition root must thread the live config value (ZTR-1170).
   */
  readonly receiveTtlDefaultSecs?: number;
}

function wireAfterLanding(
  wire: CreateReceiveInput["after_landing"],
): AfterLanding {
  if (wire.kind === "INTERNAL_MOVE") {
    if (typeof wire.destination_id !== "string" || wire.destination_id.length === 0) {
      throw new ReceiveAdmissionError("invalid_after_landing", "destination_id required");
    }
    return { kind: "INTERNAL_MOVE", destinationId: wire.destination_id };
  }
  return { kind: "HOLD", destinationId: null };
}

function wireAfterLandingBody(
  after: AfterLanding,
): ReceiveResponse["after_landing"] {
  return after.kind === "INTERNAL_MOVE"
    ? { kind: "INTERNAL_MOVE", destination_id: after.destinationId }
: { kind: "HOLD", destination_id: null };
}

/** Exact key insertion sequence for stringified storage (the byte-exact signing rule). */
function buildReceiveAcceptedBody(
  operation: ReceiveOperation,
  subscriptionHandle: string,
): ReceiveResponse {
  const createdAt = new Date(operation.createdAt).toISOString();
  return {
    operation: {
      operation_id: operation.operationId,
      operation_type: "RECEIVE_EXTERNAL",
      state: operation.status,
      amount_zkz: operation.amountZkz,
      row_version: 1,
      attention_required: false,
      attention_reason: null,
      created_at: createdAt,
      updated_at: createdAt,
      terminal_at: null,
      verification_material_available_until: null,
    },
    receiver_pubkey: null,
    discriminator: operation.operationId,
    expires_at: null,
    after_landing: wireAfterLandingBody(operation.afterLanding),
    code_status: "NOT_CREATED",
    transfer_code: null,
    expected_artifact: null,
    t0: null,
    // Plaintext returned once on create (and exact idempotent replay of stored body).
    // Point GET strips this field. Only the hash is durable.
    subscription_handle: subscriptionHandle,
  };
}

function receiveFromStored(row: StoredReceiveOperation): ReceiveResponse {
  // Prefer live status when the op has advanced past create-time frozen body
  // (workers overwrite response_body on READY; still guard status !== CREATED).
  // Point GET strips subscription_handle regardless; fall back uses empty string
  // only when no stored body exists (should not happen post-create completion).
  let body: ReceiveResponse;
  if (row.responseBody !== null && row.status === "CREATED") {
    body = JSON.parse(row.responseBody) as ReceiveResponse;
  } else if (row.responseBody !== null && row.status !== "CREATED") {
    try {
      const parsed = JSON.parse(row.responseBody) as ReceiveResponse;
      if (parsed.operation?.state === row.status || row.liveStatus !== undefined) {
        body = parsed;
      } else {
        body = buildReceiveAcceptedBody(row, parsed.subscription_handle ?? "");
      }
    } catch {
      body = buildReceiveAcceptedBody(row, "");
    }
  } else {
    body = buildReceiveAcceptedBody(row, "");
  }

  // overlay live operations facts. Frozen READY response_body keeps
  // row_version/state from the READY commit; land bumps operations.row_version and
  // status to RECEIVE_LANDED. verification-complete CAS needs the live version.
  if (row.liveStatus !== undefined && row.liveRowVersion !== undefined) {
    return {
...body,
      operation: {
...body.operation,
        state: row.liveStatus,
        row_version: row.liveRowVersion,
        updated_at: row.liveUpdatedAt ?? body.operation.updated_at,
        terminal_at:
          row.liveTerminalAt !== undefined ? row.liveTerminalAt : body.operation.terminal_at,
        verification_material_available_until:
          row.liveVerificationMaterialAvailableUntil !== undefined
            ? row.liveVerificationMaterialAvailableUntil
: body.operation.verification_material_available_until,
        attention_required: row.liveAttentionRequired ?? body.operation.attention_required,
        attention_reason:
          row.liveAttentionReason !== undefined
            ? row.liveAttentionReason
: body.operation.attention_reason,
      },
    };
  }
  return body;
}

function throwReceiveRejection(code: ReceiveRejectionCode, detail?: string, retry?: number): never {
  if (code === "wallet_in_flight") throw new WalletBusyError();
  if (code === "receive_queue_full") {
    throw new ReceiveQueueFullError(retry);
  }
  // Idempotency rules 2-3 — surface the disposition on the wire.
  if (code === "idempotency_key_reused") throw new IdempotencyKeyReusedError();
  if (code === "idempotency_in_progress") throw new IdempotencyInProgressError(retry ?? 1);
  throw new ReceiveAdmissionError(code, detail, retry);
}

function throwSendRejection(code: SendRejectionCode, detail?: string, retry?: number): never {
  if (code === "wallet_in_flight") throw new WalletBusyError();
  if (code === "idempotency_key_reused") throw new IdempotencyKeyReusedError();
  if (code === "idempotency_in_progress") throw new IdempotencyInProgressError(retry ?? 1);
  throw new SendAdmissionError(code, detail, retry);
}

function sendOutcomeToRouteResult(outcome: SendCreateOutcome): {
  readonly status: 201;
  readonly body: ExternalSendResponse;
  readonly idempotentReplay?: boolean;
} {
  if (outcome.outcome === "CREATED") {
    return {
      status: 201,
      body: buildExternalSendResponse(outcome.operation, outcome.artifact),
    };
  }
  if (outcome.outcome === "IDEMPOTENT_REPLAY") {
    return {
      status: 201,
      body: JSON.parse(outcome.responseBody) as ExternalSendResponse,
      idempotentReplay: true,
    };
  }
  throwSendRejection(outcome.code, outcome.detail, outcome.retryAfterSeconds);
}

/**
 * Live OperationRouteStore: engines own money decisions; this adapter only maps wire
 * shapes, tenant scope, and engine outcomes onto the route contract.
 */
export function createSqlOperationRouteStore(
  config: SqlOperationRouteStoreConfig,
): OperationRouteStore {
  const generateId = config.generateId;
  const now = config.now;
  const receiveTtlDefaultSecs =
    config.receiveTtlDefaultSecs ?? DEFAULT_EXPIRES_IN_SECONDS;

  return {
    async createReceive(input: CreateReceiveInput) {
      const afterLanding = wireAfterLanding(input.after_landing);
      const ttlMs =
        (input.expires_in_seconds ?? receiveTtlDefaultSecs) * 1000;
      const admission = await admitReceiveExternal(
        config.receive,
        {
          implementerId: input.implementerId,
          nodeId: config.nodeId,
          amountZkz: input.amount_zkz,
          anchor: input.anchor,
          ttlMs,
          afterLanding,
          idempotencyKey: input.idempotencyKey,
        },
        { queueCap: config.queueCap, generateId, now },
      );

      if (admission.outcome === "IDEMPOTENT_REPLAY") {
        return {
          status: (admission.responseStatus === 201 ? 201 : 202) as 201 | 202,
          body: JSON.parse(admission.responseBody) as ReceiveResponse,
          idempotentReplay: true,
        };
      }
      if (admission.outcome === "REJECTED") {
        throwReceiveRejection(admission.code, admission.detail, admission.retryAfterSeconds);
      }

      // Mint happened inside the admission TX; plaintext is returned exactly once here
      // and embedded in the stored response_body so idempotent replay is byte-identical
      // (never a second mint — the never-blind-retry rule).
      const body = buildReceiveAcceptedBody(
        admission.operation,
        admission.subscriptionHandlePlaintext,
      );
      const bodyText = JSON.stringify(body);
      // Store the first completed status+body so a concurrent retry gets exact replay
      // (or idempotency_in_progress) — never a fabricated second admit (the never-blind-retry rule).
      // Honour the boolean: if another writer already completed (or the row vanished),
      // do not pretend durable complete — surface in-progress so the client retries
      // and the READY worker cannot race a missing create body (ZTR-1142).
      const completed = await config.receive.completeOperation(
        admission.operation.operationId,
        202,
        bodyText,
      );
      if (!completed) {
        // Winner's body may already be durable (exact replay) or still racing.
        const existing = await config.receive.findByOperationId(
          admission.operation.operationId,
          input.implementerId,
        );
        if (
          existing !== null &&
          existing.responseBody !== null &&
          existing.responseStatus !== null
        ) {
          return {
            status: (existing.responseStatus === 201 ? 201 : 202) as 201 | 202,
            body: JSON.parse(existing.responseBody) as ReceiveResponse,
            idempotentReplay: true,
          };
        }
        throw new IdempotencyInProgressError(1);
      }
      return { status: 202 as const, body };
    },

    async getReceive(operationId: string, implementerId: string) {
      const row = await config.receive.findByOperationId(operationId, implementerId);
      if (row === null) return null;
      return receiveFromStored(row);
    },

    async createInternalMove(input: CreateInternalMoveInput) {
      const outcome = await createInternalMove(
        config.move,
        {
          implementerId: input.implementerId,
          nodeId: config.nodeId,
          sourceWalletId: input.source_wallet_id,
          destinationId: input.destination_id,
          amountZkz: input.amount_zkz,
          idempotencyKey: input.idempotencyKey,
        },
        { generateId, now },
      );
      // moveOutcomeToRouteResult throws MoveAdmissionError on rejection.
      const routed = moveOutcomeToRouteResult(outcome);
      return {
        status: routed.status,
        body: routed.body as InternalMoveResponse,
        idempotentReplay: routed.idempotentReplay,
      };
    },

    async getInternalMove(operationId: string, implementerId: string) {
      const found = await readInternalMove(config.move, operationId);
      if (found.outcome === "NOT_FOUND") return null;
      // Tenant predicate after the engine read — store.findByOperationId is unscoped.
      const owner = await config.move.findByOperationId(operationId);
      if (owner === null || owner.implementerId !== implementerId) return null;
      return found.response as InternalMoveResponse;
    },

    async createExternalSend(input: CreateExternalSendInput) {
      const outcome = await createExternalSend(
        config.send,
        config.sendSigner,
        {
          implementerId: input.implementerId,
          nodeId: config.nodeId,
          sourceWalletId: input.source_wallet_id,
          destinationAddress: input.destination_address,
          amountZkz: input.amount_zkz,
          referencesOperationId: input.references_operation_id ?? null,
          clientReference: input.client_reference ?? null,
          description: input.description ?? null,
          idempotencyKey: input.idempotencyKey,
        },
        { generateId, now, requireActiveSubscription: config.requireActiveSubscription },
      );
      const routed = sendOutcomeToRouteResult(outcome);
      if (outcome.outcome === "CREATED") {
        // Persist the exact create response for idempotent replay (same as receive path).
        const bodyText = JSON.stringify(routed.body);
        await config.send.completeOperation(outcome.operation.operationId, 201, bodyText);
      }
      return routed;
    },

    async getExternalSend(operationId: string, implementerId: string) {
      const found = await readExternalSend(config.send, operationId, config.sendPartials);
      if (found.outcome === "NOT_FOUND" || found.outcome === "OUT_OF_SLICE") return null;
      const owned = await config.send.findByOperationId(operationId);
      if (owned === null || owned.operation.implementerId !== implementerId) return null;
      return found.response as ExternalSendResponse;
    },
  };
}

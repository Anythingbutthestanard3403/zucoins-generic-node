// The isolated single-shot SUBMIT primitive: submit is single-shot per authorized
// attempt; the never-blind-retry rule / never-blind-retry submit — never blind-retry a submit. Re-derives the retired v1 submitOnce shape
// (packages/splitchain/src/failover.ts, reference-only): each invocation makes exactly
// ONE exchange against exactly ONE endpoint. The guarantee is per-invocation, NOT
// per-decision — the transport adapter is re-callable; a re-invocation is stopped by
// the schema backstop (gateway_submit_attempts.decision_id is UNIQUE, so a second ROW
// is a database violation) and, for the second POST itself, by one in-flight tx per wallet chain-side dedup.
// This module contains no iteration construct over endpoints or attempts — its core
// takes a single endpoint STRING (there is structurally nothing to iterate), and it
// shares no call site with the read/retry path (read.ts is never imported here).
//
// Outcome classification (the submit-outcome table): the one exchange is made exactly once, then
// ACK 2xx: the gateway acknowledged receipt. Receipt ONLY: a status:true
// acknowledgement is NEVER settlement (receipt-only ACK posture / C-09; frozen as
// SUBMIT_ACK_STATUS_TRUE_MEANS_SETTLED=false in the transfer-code
// concern). Landing requires a fresh signature-verified chain
// observation via the landing-path oracle landing oracle — not implemented here.
// REJECT 4xx: the gateway parsed and definitively rejected the request.
// INDETERMINATE transport ambiguity (network failure / timeout / unreadable or
// over-limit body) or a non-2xx/4xx status (e.g. 5xx, 3xx): the
// exchange's effect is unknown. Reconcile ONLY — no re-attempt, no
// rebuild, no assumed failure, and NO generic proven-not-landed
// authority (a landing oracle is not a retry oracle).
//
// Every authorized submit lands exactly one append-only gateway_submit_attempts row
// carrying the exact request bytes + digest and, when captured, the exact
// response bytes + digest. The node never creates a submit attempt for the external
// send operation kind — that prohibition is application-level authority recorded in
// src/schema/submit-attempts.contract.ts, not transport logic.

import { SUBMIT_ACTION_NAME } from "@zucoins/generic-node-contracts/transfer-code";

import { GatewayConfigurationError } from "./client.js";
import {
  GatewayTransportAmbiguityError,
  createGatewayExchangeTransport,
  sha256Hex,
  type GatewayExchangeCapture,
  type GatewayExchangeTransport,
} from "./capture.js";
import { buildGatewayActionRequest } from "./request.js";
import {
  defaultNowIso,
  type GatewaySubmitAttemptRecord,
  type NowIsoFn,
  type SubmitAttemptRecorder,
  type SubmitTransportOutcome,
} from "./records.js";
import type { GatewayLimits, GatewaySubmitCredentials, GatewaySubmitTransport } from "./types.js";
import type { GatewayRequest, GatewayResponse } from "../protocol/index.js";

// 2xx -> ACK (receipt only, never settlement); 4xx -> REJECT (definite gateway
// answer); everything else (5xx, 3xx, 1xx) -> INDETERMINATE (reconcile-only).
export function classifySubmitHttpStatus(statusCode: number): SubmitTransportOutcome {
  if (statusCode >= 200 && statusCode < 300) {
    return "ACK";
  }
  if (statusCode >= 400 && statusCode < 500) {
    return "REJECT";
  }
  return "INDETERMINATE";
}

// The authorization that permits the single shot: an already-persisted
// submit_decisions row (decision = 'INITIAL_SINGLE_SHOT', transaction_attempt_no = 1).
// The transport never creates or validates decisions — it consumes their ids
// as evidence linkage. A submit without such a row is unrepresentable at the schema
// level (gateway_submit_attempts.decision_id is UNIQUE and foreign-keyed).
export interface SubmitAuthorization {
  readonly submitDecisionId: string;
  readonly operationId: string;
  readonly transactionAttemptNo: number;
}

export interface SubmitGatewayActionOptions {
  // A single endpoint string, by design — submit is never spread across the list.
  readonly endpoint: string;
  readonly limits: GatewayLimits;
  readonly recorder: SubmitAttemptRecorder;
  readonly exchange?: GatewayExchangeTransport;
  readonly nowIso?: NowIsoFn;
}

export interface SubmitGatewayActionResult {
  readonly transportOutcome: SubmitTransportOutcome;
  // null exactly when transport ambiguity left no complete response to capture.
  readonly capture: GatewayExchangeCapture | null;
  readonly recordedAttempt: GatewaySubmitAttemptRecord;
}

// The single shot: ONE exchange against ONE endpoint, then classify and record. There
// is no loop, no failover, and no second call on any branch — a transport failure or
// timeout does NOT prove the POST did not land, so re-POSTing an identical signed
// transaction risks a permanent double-submit collision against the one-in-flight-
// per-wallet invariant (one in-flight tx per wallet). Definite local failures (e.g. an over-limit request
// that never left the node) propagate without an attempt row: no exchange occurred.
export async function submitGatewayActionOnce(
  actionName: typeof SUBMIT_ACTION_NAME,
  actionData: unknown,
  authorization: SubmitAuthorization,
  options: SubmitGatewayActionOptions,
): Promise<SubmitGatewayActionResult> {
  const request = buildGatewayActionRequest(actionName, actionData);
  return await submitGatewayRequestOnce(request, authorization, options);
}

// Request-level core shared by the typed action entry point and the transport
// adapter below. Still single-shot: one exchange, one recorded row, no iteration.
export async function submitGatewayRequestOnce(
  request: GatewayRequest,
  authorization: SubmitAuthorization,
  options: SubmitGatewayActionOptions,
): Promise<SubmitGatewayActionResult> {
  const exchange = options.exchange ?? createGatewayExchangeTransport({ limits: options.limits });
  const nowIso = options.nowIso ?? defaultNowIso;
  const startedAt = nowIso();
  const requestSha256 = sha256Hex(request.bodyBytes);

  let capture: GatewayExchangeCapture;
  try {
    capture = await exchange.exchange(options.endpoint, request);
  } catch (error) {
    if (!(error instanceof GatewayTransportAmbiguityError)) {
      throw error;
    }
    const recordedAttempt: GatewaySubmitAttemptRecord = {
      decisionId: authorization.submitDecisionId,
      operationId: authorization.operationId,
      attemptNo: 1,
      transactionAttemptNo: authorization.transactionAttemptNo,
      requestBytes: request.bodyBytes,
      requestSha256,
      responseBytes: null,
      responseSha256: null,
      transportOutcome: "INDETERMINATE",
      startedAt,
      completedAt: nowIso(),
    };
    await recordSubmitAttemptOrIndeterminate(options.recorder, recordedAttempt);
    return { transportOutcome: "INDETERMINATE", capture: null, recordedAttempt };
  }

  const transportOutcome = classifySubmitHttpStatus(capture.statusCode);
  const recordedAttempt: GatewaySubmitAttemptRecord = {
    decisionId: authorization.submitDecisionId,
    operationId: authorization.operationId,
    attemptNo: 1,
    transactionAttemptNo: authorization.transactionAttemptNo,
    requestBytes: request.bodyBytes,
    requestSha256,
    responseBytes: capture.responseBytes,
    responseSha256: capture.responseSha256,
    transportOutcome,
    startedAt,
    completedAt: nowIso(),
  };
  await recordSubmitAttemptOrIndeterminate(options.recorder, recordedAttempt);
  return { transportOutcome, capture, recordedAttempt };
}

// Raised whenever the single shot is INDETERMINATE: by the transport adapter on an
// ambiguous or non-2xx/4xx outcome (the attempt row is already persisted), and by
// submitGatewayRequestOnce when the recorder fails after the exchange (the row could
// NOT be persisted — the record that should have landed is still attached, with the
// recorder error as `cause`). Either way the ONLY safe next step is reconcile against
// the sender's chain head — never rebuild, never resubmit, never assume failed
// (the never-blind-retry rule). Carries the recorded attempt so the caller has the evidence linkage.
export class SubmitIndeterminateError extends Error {
  constructor(
    message: string,
    readonly recordedAttempt: GatewaySubmitAttemptRecord,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "SubmitIndeterminateError";
  }
}

// The exchange (or its ambiguous attempt) has ALREADY happened by the time the recorder
// runs: a persistence failure there is not a definite local failure — the POST may have
// landed with no attempt row to evidence it. Fail closed as INDETERMINATE, preserving
// the recorder error as cause, so every caller keys on the typed reconcile-only signal
// rather than misclassifying a possibly-landed submit (the never-blind-retry rule).
async function recordSubmitAttemptOrIndeterminate(
  recorder: SubmitAttemptRecorder,
  recordedAttempt: GatewaySubmitAttemptRecord,
): Promise<void> {
  try {
    await recorder.recordSubmitAttempt(recordedAttempt);
  } catch (cause) {
    throw new SubmitIndeterminateError(
      "submit evidence could not be persisted after the exchange; the outcome is INDETERMINATE — reconcile is the only safe next step (the never-blind-retry rule)",
      recordedAttempt,
      { cause },
    );
  }
}

export interface SingleShotSubmitTransportOptions {
  readonly credentials: GatewaySubmitCredentials;
  readonly limits: GatewayLimits;
  readonly recorder: SubmitAttemptRecorder;
  readonly authorization: SubmitAuthorization;
  readonly exchange?: GatewayExchangeTransport;
  readonly nowIso?: NowIsoFn;
}

// Adapts the single shot to the GatewaySubmitTransport seam consumed by
// createGatewayClient. The client passes its full resolved endpoint list; this adapter
// targets ONLY the primary (first) endpoint — one string, one call — and converts an
// INDETERMINATE outcome into SubmitIndeterminateError so no ambiguous result can be
// mistaken by a caller for a gateway response.
export function createSingleShotSubmitTransport(
  options: SingleShotSubmitTransportOptions,
): GatewaySubmitTransport {
  return {
    credentials: options.credentials,
    submit: async (endpoints, request) => {
      const primary = endpoints[0];
      if (primary === undefined) {
        throw new GatewayConfigurationError(
          "gateway endpoint list is empty; submit requires a primary endpoint",
        );
      }
      const result = await submitGatewayRequestOnce(request, options.authorization, {
        endpoint: primary,
        limits: options.limits,
        recorder: options.recorder,
        exchange: options.exchange,
        nowIso: options.nowIso,
      });
      if (result.transportOutcome === "INDETERMINATE") {
        throw new SubmitIndeterminateError(
          `submit outcome is INDETERMINATE against ${primary}: the only safe next step is reconcile — never rebuild, never resubmit, never assume failed (the never-blind-retry rule)`,
          result.recordedAttempt,
        );
      }
      const capture = result.capture;
      if (capture === null) {
        throw new SubmitIndeterminateError(
          "submit produced no captured response; reconcile is the only safe next step",
          result.recordedAttempt,
        );
      }
      const response: GatewayResponse = {
        statusCode: capture.statusCode,
        bodyBytes: capture.responseBytes,
      };
      return response;
    },
  };
}

// The bounded, jittered, idempotent READ primitive: read retry is bounded and
// jittered, and only for transport ambiguity.
// Re-derives the retired v1 failover + retry shape (packages/splitchain/src/failover.ts
// and retry.ts, reference-only) on top of the resolved configuration: one call
// iterates the endpoint list (primary first) per attempt, retries across attempts with
// jittered exponential backoff, and stops at the first COMPLETE HTTP response — any
// status code is the gateway's authoritative answer and is returned verbatim (this
// module interprets no envelope codes).
//
// The load-bearing structural guarantee (the never-blind-retry rule): submit_transaction__v1
// can never sit inside this loop. readGatewayAction's parameter type is
// GatewayReadActionName, which excludes the submit action at compile time, and the
// runtime guard (assertReadSafeActionName) ALSO runs at the top of the request-level
// core readGatewayRequest — the lowest execution layer every entry point (typed
// action, request-level core.1 transport adapter) funnels through — so an
// unsafe rpc is rejected before any endpoint is touched regardless of how the request
// arrived. The single-shot submit path (submit.ts) shares no code with this module.
//
// Retry triggers are EXACTLY one class: GatewayTransportAmbiguityError from the shared
// exchange (network failure, timeout, unreadable/over-limit body — the exchange's
// effect is unknown). Every other error (a definite local failure such as an over-limit
// request, or a recorder failure) propagates immediately without consuming attempts.

import { GatewayConfigurationError, fingerprintEndpoint } from "./client.js";
import {
  GatewayTransportAmbiguityError,
  createGatewayExchangeTransport,
  type GatewayExchangeCapture,
  type GatewayExchangeTransport,
} from "./capture.js";
import { assertReadSafeActionName, type GatewayReadActionName } from "./actions.js";
import { buildGatewayActionRequest } from "./request.js";
import { defaultNowIso, type NowIsoFn, type ObservationRecorder } from "./records.js";
import type { GatewayLimits, GatewayReadCredentials, GatewayReadTransport } from "./types.js";
import type { GatewayRequest } from "../protocol/index.js";

// Implementer-judgment read schedule (the specification fixes no numeric read cadence,
// requiring only bounded + jittered). Conservative named defaults, overridable per
// call: at most READ_MAX_ATTEMPTS passes over the endpoint list, with jittered
// exponential backoff between passes (250 / 500 / 1000ms base, capped at 4000ms, plus
// up to 100ms jitter). No sleep follows the final pass.
export const READ_MAX_ATTEMPTS = 4;
export const READ_BACKOFF_BASE_MS = 250;
export const READ_BACKOFF_MAX_MS = 4_000;
export const READ_BACKOFF_JITTER_MS = 100;

export type SleepFn = (ms: number) => Promise<void>;

const defaultSleep: SleepFn = async (ms) =>
  await new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

// Base-plus-jitter delay before the next attempt (1-indexed attempt just completed):
// min(READ_BACKOFF_MAX_MS, READ_BACKOFF_BASE_MS * 2^(attempt-1)) + jitter * jitterCap.
// Jitter is injected so tests drive the schedule deterministically; production uses
// Math.random.
export function readBackoffDelayMs(
  attempt: number,
  jitter: () => number = Math.random,
  backoffMaxMs: number = READ_BACKOFF_MAX_MS,
): number {
  const base = Math.min(backoffMaxMs, READ_BACKOFF_BASE_MS * 2 ** (attempt - 1));
  return base + jitter() * READ_BACKOFF_JITTER_MS;
}

export interface ReadAttemptFailure {
  readonly endpoint: string;
  readonly error: unknown;
}

// Every attempt across every endpoint failed with transport ambiguity. Distinct from
// GatewayTransportAmbiguityError (one exchange) so callers can tell "the whole bounded
// schedule is exhausted" from "one exchange was ambiguous".
export class GatewayReadExhaustedError extends Error {
  constructor(
    message: string,
    readonly failures: readonly ReadAttemptFailure[],
  ) {
    super(message);
    this.name = "GatewayReadExhaustedError";
  }
}

export interface ReadGatewayRequestOptions {
  readonly endpoints: readonly string[];
  readonly limits: GatewayLimits;
  readonly recorder: ObservationRecorder;
  readonly exchange?: GatewayExchangeTransport;
  readonly sleep?: SleepFn;
  readonly jitter?: () => number;
  readonly nowIso?: NowIsoFn;
  // Optional cap on passes over the endpoint list. Absent resolves to
  // READ_MAX_ATTEMPTS; a present value must be a positive finite integer (fail-closed).
  readonly maxAttempts?: number;
  // Optional cap on the exponential backoff ceiling between passes. Absent resolves to
  // READ_BACKOFF_MAX_MS; a present value must be a positive finite integer (fail-closed).
  readonly backoffMaxMs?: number;
}

export interface ReadGatewayRequestResult {
  readonly capture: GatewayExchangeCapture;
  readonly attemptNo: number;
}

async function recordExchange(
  recorder: ObservationRecorder,
  capture: GatewayExchangeCapture,
  observedAt: string,
): Promise<void> {
  await recorder.recordObservation({
    endpointFingerprint: capture.endpointFingerprint,
    observedAt,
    httpStatus: capture.statusCode,
    rawResponseBytes: capture.responseBytes,
    rawResponseSha256: capture.responseSha256,
    transportAmbiguous: false,
  });
}

async function recordAmbiguity(
  recorder: ObservationRecorder,
  endpointFingerprint: string,
  observedAt: string,
): Promise<void> {
  await recorder.recordObservation({
    endpointFingerprint,
    observedAt,
    httpStatus: null,
    rawResponseBytes: null,
    rawResponseSha256: null,
    transportAmbiguous: true,
  });
}

// Fail-closed bound on the retry schedule: boundedness must be structural, not merely
// the default. Mirrors requireConfiguredLimit in client.js — absent resolves to
// READ_MAX_ATTEMPTS; a present-but-invalid value (zero, negative, non-integer,
// Infinity, NaN) throws before any endpoint is touched.
function requireMaxAttempts(configured: number | undefined): number {
  if (configured === undefined) {
    return READ_MAX_ATTEMPTS;
  }
  if (typeof configured !== "number" || !Number.isInteger(configured) || configured <= 0) {
    throw new GatewayConfigurationError(
      "gateway read maxAttempts must be a positive finite integer",
    );
  }
  return configured;
}

// Mirrors requireMaxAttempts: boundedness of the backoff ceiling must be structural.
function requireBackoffMaxMs(configured: number | undefined): number {
  if (configured === undefined) {
    return READ_BACKOFF_MAX_MS;
  }
  if (typeof configured !== "number" || !Number.isInteger(configured) || configured <= 0) {
    throw new GatewayConfigurationError(
      "gateway read backoffMaxMs must be a positive finite integer",
    );
  }
  return configured;
}

// The bounded read loop over a pre-built request. Each endpoint touched lands one
// gateway_observations contribution: the raw response bytes + digest on any complete
// HTTP response, or a transport-ambiguous marker row when the exchange's effect is
// unknown. Returns on the FIRST complete response of any status — the gateway's
// authoritative answer; only transport ambiguity continues the iteration.
export async function readGatewayRequest(
  request: GatewayRequest,
  options: ReadGatewayRequestOptions,
): Promise<ReadGatewayRequestResult> {
  // The never-blind-retry rule at the lowest execution layer: every read entry point (typed action,
  // transport adapter, direct call) funnels through here, so an unsafe rpc —
  // submit_transaction__v1 smuggled past the type system, or any name outside the
  // frozen read-safe list — is rejected before any endpoint is touched and before any
  // attempt is consumed. Defense-in-depth with the identical call in
  // readGatewayAction, which keeps the typed-entry guarantee.
  assertReadSafeActionName(request.rpc);
  if (options.endpoints.length === 0) {
    throw new GatewayConfigurationError("gateway endpoint list is empty; cannot read");
  }
  const exchange = options.exchange ?? createGatewayExchangeTransport({ limits: options.limits });
  const recorder = options.recorder;
  const sleep = options.sleep ?? defaultSleep;
  const jitter = options.jitter ?? Math.random;
  const nowIso = options.nowIso ?? defaultNowIso;
  const maxAttempts = requireMaxAttempts(options.maxAttempts);
  const backoffMaxMs = requireBackoffMaxMs(options.backoffMaxMs);

  const failures: ReadAttemptFailure[] = [];
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    for (const endpoint of options.endpoints) {
      let capture: GatewayExchangeCapture;
      try {
        capture = await exchange.exchange(endpoint, request);
      } catch (error) {
        if (!(error instanceof GatewayTransportAmbiguityError)) {
          throw error;
        }
        failures.push({ endpoint, error });
        await recordAmbiguity(recorder, fingerprintForAmbiguity(endpoint), nowIso());
        continue;
      }
      await recordExchange(recorder, capture, nowIso());
      return { capture, attemptNo: attempt };
    }
    if (attempt < maxAttempts) {
      await sleep(readBackoffDelayMs(attempt, jitter, backoffMaxMs));
    }
  }

  throw new GatewayReadExhaustedError(
    `all ${maxAttempts} read attempt(s) across ${options.endpoints.length} endpoint(s) failed with transport ambiguity for rpc ${request.rpc}`,
    failures,
  );
}

// The ambiguity path has no capture to take the fingerprint from; recompute it over the
// same canonical preimage (the resolved endpoint string) the exchange would have used.
function fingerprintForAmbiguity(endpoint: string): string {
  return fingerprintEndpoint(endpoint);
}

// The typed read entry point: actionName is GatewayReadActionName, so the submit action
// is excluded at compile time; the runtime guard backstops cast bypasses (golden
// rule 4). Builds the official frozen form body via the shared codec, then runs the
// bounded read loop.
export async function readGatewayAction(
  actionName: GatewayReadActionName,
  actionData: unknown,
  options: ReadGatewayRequestOptions,
): Promise<ReadGatewayRequestResult> {
  assertReadSafeActionName(actionName);
  return await readGatewayRequest(buildGatewayActionRequest(actionName, actionData), options);
}

export interface GatewayReadTransportOptions {
  readonly credentials: GatewayReadCredentials;
  readonly limits: GatewayLimits;
  readonly recorder: ObservationRecorder;
  readonly exchange?: GatewayExchangeTransport;
  readonly sleep?: SleepFn;
  readonly jitter?: () => number;
  readonly nowIso?: NowIsoFn;
  // Optional cap on passes over the endpoint list. Absent resolves to
  // READ_MAX_ATTEMPTS; a present value must be a positive finite integer (fail-closed).
  readonly maxAttempts?: number;
  // Optional cap on the exponential backoff ceiling between passes. Absent resolves to
  // READ_BACKOFF_MAX_MS; a present value must be a positive finite integer (fail-closed).
  readonly backoffMaxMs?: number;
}

// Adapts the bounded read primitive to the GatewayReadTransport seam consumed
// by createGatewayClient: the client supplies its resolved endpoint list per call.
export function createGatewayReadTransport(options: GatewayReadTransportOptions): GatewayReadTransport {
  return {
    credentials: options.credentials,
    read: async (endpoints, request) => {
      const result = await readGatewayRequest(request, { ...options, endpoints });
      return { statusCode: result.capture.statusCode, bodyBytes: result.capture.responseBytes };
    },
  };
}

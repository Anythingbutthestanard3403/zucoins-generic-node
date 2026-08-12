// Identical-byte redelivery of a previously authorized submit.
//
// When the UNIQUE gateway_submit_attempts claim slot is already burned and the
// wallet head(s) are still unmoved, the only recovery that is not a blind retry of a
// different authorization is to POST the exact same request bytes again — no second
// claim, no second attempt row, no rebuilt body (ZTR-1243 receive / ZTR-1244 move).
//
// Callers MUST confirm-read unmoved heads before invoking. Transport errors are
// swallowed: the follow-up confirm-read / reconcile is the only adjudicator.

import {
  createGatewayExchangeTransport,
  type GatewayExchangeTransport,
} from "./capture.js";
import type { GatewayLimits } from "./types.js";
import type { GatewayRequest } from "../protocol/index.js";

export interface IdenticalByteRedeliveryOptions {
  readonly endpoint: string;
  readonly limits: GatewayLimits;
  readonly exchange?: GatewayExchangeTransport;
}

/**
 * POST the exact same signed request bytes again. Deliberately bypasses claim mint and
 * attempt-row insert: both are UNIQUE one-per-attempt, and inventing a second row would be a
 * second authorization.
 */
export async function redeliverIdenticalSignedRequest(
  signedRequest: GatewayRequest,
  options: IdenticalByteRedeliveryOptions,
): Promise<void> {
  const exchange =
    options.exchange ?? createGatewayExchangeTransport({ limits: options.limits });
  try {
    await exchange.exchange(options.endpoint, signedRequest);
  } catch {
    // Redelivery ambiguity is reconcile-only; confirm-read decides.
  }
}

/**
 * Rebuild a GatewayRequest from durable `gateway_submit_attempts.request_body` bytes.
 * The rpc field is informational for local typing; the wire body is bodyBytes alone.
 */
export function gatewayRequestFromPersistedBody(
  requestBody: Uint8Array,
  rpc = "submit_transaction__v1",
): GatewayRequest {
  return { rpc, bodyBytes: requestBody };
}

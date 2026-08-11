// Composition-root wrapper around node-core's bounded gateway read.
//
// ZTR-1162: `recordGatewayReadFailure` / `recordGatewayReadSuccess` had a
// consumer (readiness budget → degraded / not-ready) and no production
// producer. Every runtime gateway read on this node must pass through one
// outcome sink so the consecutive-failure counter and its reset cannot drift.
//
// Lives in the app shell, not node-core — readiness is a composition concern.
// Success = the bounded read returned a complete capture (any HTTP status is
// the gateway's authoritative answer). Failure = the read threw (exhausted
// transport ambiguity, config, recorder, etc.). Boot-lane still stamps success
// after its validated probe; a double success is idempotent (counter stays 0).

import {
  readGatewayAction,
  type GatewayReadActionName,
  type ReadGatewayRequestOptions,
  type ReadGatewayRequestResult,
} from "@zucoins/node-core";

/** Minimal readiness surface the wrapper needs — NodeReadiness satisfies this. */
export interface GatewayReadOutcomeSink {
  recordGatewayReadSuccess(): void;
  recordGatewayReadFailure(): void;
}

export type ObservedReadGatewayAction = (
  actionName: GatewayReadActionName,
  actionData: unknown,
  options: ReadGatewayRequestOptions,
) => Promise<ReadGatewayRequestResult>;

/**
 * Bind success/failure stamping to every outcome of `readGatewayAction`.
 * Production main builds one instance and fans it into boot + money-worker
 * readers so the GATEWAY_READ_FAILURE_BUDGET dial is actually counted.
 */
export function createObservedGatewayRead(
  sink: GatewayReadOutcomeSink,
): ObservedReadGatewayAction {
  return async (actionName, actionData, options) => {
    try {
      const result = await readGatewayAction(actionName, actionData, options);
      sink.recordGatewayReadSuccess();
      return result;
    } catch (error) {
      sink.recordGatewayReadFailure();
      throw error;
    }
  };
}

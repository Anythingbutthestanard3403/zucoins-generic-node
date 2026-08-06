// Endpoint failover as first-class evidence (step 2:
// every read goes to an independently configured endpoint and records the endpoint
// fingerprint;: a transport/read failure keeps the lease and stays read-only). The
// bounded read primitive (read.ts) is stateless — it iterates the endpoint list per call
// but carries no memory of which endpoint last served observation, so a switch from an
// unreachable endpoint to a backup is invisible across calls. This module adds exactly
// that cross-call state and records the switch itself as evidence.
//
// A failover is EVIDENCE, never a gap: the read primitive still lands one
// gateway_observations row per endpoint it touches (the unreachable endpoint's
// transport-ambiguous marker row plus the backup's captured response), so the observation
// stream stays contiguous. The failover event recorded here is an additional audit row
// describing the endpoint switch — it does not replace, delete, or stand in for any
// observation row, and it creates no retry/submit authority (the never-blind-retry rule).
//
// Endpoint disagreement (the load-bearing obligation): a backup that serves after the
// active endpoint goes transport-ambiguous is NOT silently adopted. Its semantic state is
// compared against the failed endpoint's prior accepted state ("immediate prior
// accepted state"). If they DIFFER, two independently configured gateway endpoints
// disagree — the service halts the affected read stream, records an
// EndpointDisagreementAnomaly via the injected AnomalyRecorder port, marks the read
// INDETERMINATE, and does NOT adopt the backup ("two independent gateway
// endpoints disagree → halt affected wallet/operation → INDETERMINATE; oracle incident").
// A compromised or forked secondary endpoint therefore cannot be accepted on failover
// without a halt. The concrete DDL-backed AnomalyRecorder (an observation_anomalies row)
// is deferred to — see anomaly.ts.
//
// The never-blind-retry rule is preserved structurally: the only read entry point takes a
// GatewayReadActionName (the submit action is absent from that union at compile time) and
// re-asserts read-safety at runtime before delegating to the bounded read primitive,
// which asserts it again at the lowest layer. This service shares no code with the
// single-shot submit path.

import { assertReadSafeActionName, type GatewayReadActionName } from "./actions.js";
import type { AnomalyRecorder, EndpointDisagreementAnomaly } from "./anomaly.js";
import type { GatewayExchangeCapture } from "./capture.js";
import { fingerprintEndpoint, GatewayConfigurationError } from "./client.js";
import {
  readGatewayAction,
  type ReadGatewayRequestOptions,
  type ReadGatewayRequestResult,
} from "./read.js";
import type { NowIsoFn } from "./records.js";
import { defaultNowIso } from "./records.js";

// One endpoint-failover audit row: the observer switched observation from an endpoint
// that failed with transport ambiguity to a backup that served a complete response AND
// AGREED with the prior accepted state. Identified by endpoint fingerprints (copied at
// failover time so later reconfiguration cannot rewrite provenance, mirroring the
// observation endpoint_fingerprint), never by the mutable endpoint string alone.
export interface EndpointFailoverEvent {
  readonly observerId: string;
  readonly fromEndpointFingerprint: string;
  readonly toEndpointFingerprint: string;
  readonly fromIndex: number;
  readonly toIndex: number;
  readonly ambiguousFailures: number;
  readonly failedAt: string;
}

export interface EndpointFailoverRecorder {
  recordFailover(event: EndpointFailoverEvent): Promise<void>;
}

// A read reduced to an observer-independent semantic token (semantic
// fingerprint). The reduction itself — envelope decode plus the verification pipeline
// is a SEPARATE concern; this module treats the token as opaque and only
// compares tokens for equality across endpoints.
// ponytail: default reducer = raw response sha256 (envelope-INtolerant, so any envelope
// difference reads as a potential disagreement and fails closed rather than being
// silently accepted). Inject the semantic-fingerprint reducer to gain
// EQUIVALENT_STATE_DIFFERENT_ENVELOPE tolerance once that lane exists.
export type SemanticStateReducer = (capture: GatewayExchangeCapture) => string;

const rawDigestSemanticState: SemanticStateReducer = (capture) => capture.responseSha256;

// ACCEPTED: the served read is accepted as this stream's state. INDETERMINATE: a
// fail-closed halt (endpoint disagreement) — money automation for the affected
// wallet/operation is frozen until the configured authority policy resolves the incident.
export type FailoverVerificationStatus = "ACCEPTED" | "INDETERMINATE";

export interface EndpointFailoverResult extends ReadGatewayRequestResult {
  // True only when the active endpoint DURABLY switched to a backup (an agreeing
  // failover). A disagreeing backup is served (its observation row lands) but never
  // adopted, so failedOver is false and verificationStatus is INDETERMINATE.
  readonly failedOver: boolean;
  readonly servedEndpoint: string;
  readonly servedEndpointFingerprint: string;
  readonly failover: EndpointFailoverEvent | null;
  readonly verificationStatus: FailoverVerificationStatus;
  readonly disagreement: EndpointDisagreementAnomaly | null;
}

export interface EndpointFailoverServiceOptions {
  readonly endpoints: readonly string[];
  readonly observerId?: string;
  readonly recorder?: EndpointFailoverRecorder;
  // Anomaly persistence seam. Required in effect: if a disagreement is detected and
  // no recorder is configured, the read fails closed (the anomaly cannot be persisted).
  readonly anomalyRecorder?: AnomalyRecorder;
  readonly semanticState?: SemanticStateReducer;
  readonly nowIso?: NowIsoFn;
}

export interface EndpointFailoverService {
  readonly endpoints: readonly string[];
  readonly endpointFingerprints: readonly string[];
  readonly observerId: string;
  activeEndpoint(): string;
  activeEndpointFingerprint(): string;
  failoverCount(): number;
  // True after a disagreement halt; money automation for this stream must stay frozen
  // while true. Sticky until resolveHalt (the configured authority policy) clears it.
  isHalted(): boolean;
  haltAnomaly(): EndpointDisagreementAnomaly | null;
  // The configured authority policy's resolution hook: clears a halt so reads may
  // resume. The policy DECISION (declare the correct head, quarantine an endpoint, open an
  // oracle incident) is the caller's / remit; this only lifts the mechanical
  // freeze once that decision is made.
  resolveHalt(): void;
  read(
    actionName: GatewayReadActionName,
    actionData: unknown,
    options: ReadGatewayRequestOptions,
  ): Promise<EndpointFailoverResult>;
}

const DEFAULT_OBSERVER_ID = "node";

// Raised when a read is attempted on a service halted by an unresolved endpoint
// disagreement. Fail-closed: the caller must resolve the incident (resolveHalt) before
// any further automated read of the affected stream.
export class GatewayEndpointHaltError extends Error {
  constructor(
    message: string,
    readonly disagreement: EndpointDisagreementAnomaly,
  ) {
    super(message);
    this.name = "GatewayEndpointHaltError";
  }
}

// A baseline observation (T0) bound to the endpoint fingerprint that
// established it.
export interface T0Baseline {
  readonly semanticState: string;
  readonly establishedByFingerprint: string;
}

export interface ContinuityObservation {
  readonly semanticState: string;
  readonly servedEndpointFingerprint: string;
}

// D3 anti-laundering: the reuse barrier ("releases only after fresh accepted
// observation semantically identical to T0") is provable ONLY by the same endpoint that
// established the baseline. A post-failover read served by a DIFFERENT endpoint does NOT
// prove continuity even when its semantic state matches T0 — a compromised or forked
// backup must not launder a continuity claim the primary alone had authority to make.
// The caller treats a false result as unproven / INDETERMINATE, never as "still at T0".
export function provesT0Continuity(
  baseline: T0Baseline,
  observation: ContinuityObservation,
): boolean {
  return (
    observation.semanticState === baseline.semanticState &&
    observation.servedEndpointFingerprint === baseline.establishedByFingerprint
  );
}

// The endpoint sequence for one attempt: the active endpoint first, then the remaining
// configured endpoints in their original positions. A stable rotation — the active
// endpoint leads, the rest follow unchanged — so the bounded primitive tries the current
// source of observation before any backup.
function orderedFrom(activeIndex: number, endpoints: readonly string[]): readonly string[] {
  return [...endpoints.slice(activeIndex), ...endpoints.slice(0, activeIndex)];
}

export function createEndpointFailoverService(
  options: EndpointFailoverServiceOptions,
): EndpointFailoverService {
  const endpoints = options.endpoints;
  if (endpoints.length === 0) {
    throw new GatewayConfigurationError("gateway endpoint list is empty; cannot fail over");
  }
  const endpointFingerprints = Object.freeze(endpoints.map((endpoint) => fingerprintEndpoint(endpoint)));
  const observerId = options.observerId ?? DEFAULT_OBSERVER_ID;
  const recorder = options.recorder;
  const anomalyRecorder = options.anomalyRecorder;
  const semanticState = options.semanticState ?? rawDigestSemanticState;
  const nowIso = options.nowIso ?? defaultNowIso;

  let activeIndex = 0;
  let failovers = 0;
  // Last accepted semantic state for this read stream and the endpoint that established
  // it ("immediate prior accepted state"). Null until the first accepted read.
  // Carried across calls so a failover compares the backup's read against the failed
  // endpoint's prior accepted state (D1) instead of silently healing the gap.
  let lastAccepted: { state: string; fingerprint: string } | null = null;
  // Sticky fail-closed halt. Once an endpoint disagreement is detected, no
  // further automated read proceeds until resolveHalt lifts it.
  let halt: EndpointDisagreementAnomaly | null = null;

  function activeEndpoint(): string {
    return endpoints[activeIndex] as string;
  }

  async function read(
    actionName: GatewayReadActionName,
    actionData: unknown,
    readOptions: ReadGatewayRequestOptions,
  ): Promise<EndpointFailoverResult> {
    // The never-blind-retry rule at the failover layer: the submit action can never enter the
    // read/failover path. Defence-in-depth with the identical guard inside the bounded
    // read primitive this delegates to.
    assertReadSafeActionName(actionName);

    // Fail closed on an unresolved disagreement: money automation for this stream is
    // frozen, and a compromised/forked endpoint must not be re-read into acceptance until
    // the authority policy resolves the incident.
    if (halt !== null) {
      throw new GatewayEndpointHaltError(
        `endpoint failover service is halted on an unresolved endpoint disagreement (observer ${observerId}); resolve the incident before reading`,
        halt,
      );
    }

    const fromIndex = activeIndex;
    const result = await readGatewayAction(actionName, actionData, {
      ...readOptions,
      endpoints: orderedFrom(fromIndex, endpoints),
    });

    const servedEndpoint = result.capture.endpoint;
    const servedIndex = endpoints.indexOf(servedEndpoint);
    const servedFingerprint = result.capture.endpointFingerprint;
    const servedState = semanticState(result.capture);
    const failedOver = servedIndex !== fromIndex;

    if (!failedOver) {
      // The active endpoint served: this read establishes/updates the accepted state.
      lastAccepted = { state: servedState, fingerprint: servedFingerprint };
      return {
        ...result,
        failedOver: false,
        servedEndpoint,
        servedEndpointFingerprint: servedFingerprint,
        failover: null,
        verificationStatus: "ACCEPTED",
        disagreement: null,
      };
    }

    // A backup served after the active endpoint went transport-ambiguous. Before adopting
    // it, compare its semantic state against the failed endpoint's prior accepted state
    // A DIFFERENCE is two independent gateway endpoints disagreeing.
    if (lastAccepted !== null && servedState !== lastAccepted.state) {
      const anomaly: EndpointDisagreementAnomaly = {
        observerId,
        acceptedEndpointFingerprint: lastAccepted.fingerprint,
        servingEndpointFingerprint: servedFingerprint,
        acceptedSemanticState: lastAccepted.state,
        servingSemanticState: servedState,
        detectedAt: nowIso(),
      };
      // Fail closed BEFORE any attempt to persist: the halt stands even if the anomaly
      // cannot be recorded, and the backup is never adopted (activeIndex and lastAccepted
      // are left untouched — no silent switch to a possibly forked endpoint).
      halt = anomaly;
      if (anomalyRecorder === undefined) {
        throw new GatewayConfigurationError(
          `endpoint disagreement detected on failover (observer ${observerId}) but no AnomalyRecorder is configured; cannot persist the anomaly — failing closed`,
        );
      }
      await anomalyRecorder.recordDisagreement(anomaly);
      return {
        ...result,
        failedOver: false,
        servedEndpoint,
        servedEndpointFingerprint: servedFingerprint,
        failover: null,
        verificationStatus: "INDETERMINATE",
        disagreement: anomaly,
      };
    }

    // Agreement (equal state) or no prior accepted state (the first read is a failover):
    // a legitimate transport failover. Record it as evidence before advancing, so a
    // recorder failure fails closed and the active endpoint is not advanced on an
    // unrecorded failover.
    const event: EndpointFailoverEvent = {
      observerId,
      fromEndpointFingerprint: endpointFingerprints[fromIndex] as string,
      toEndpointFingerprint: endpointFingerprints[servedIndex] as string,
      fromIndex,
      toIndex: servedIndex,
      ambiguousFailures: (servedIndex - fromIndex + endpoints.length) % endpoints.length,
      failedAt: nowIso(),
    };
    if (recorder !== undefined) {
      await recorder.recordFailover(event);
    }
    activeIndex = servedIndex;
    failovers += 1;
    lastAccepted = { state: servedState, fingerprint: servedFingerprint };

    return {
      ...result,
      failedOver: true,
      servedEndpoint,
      servedEndpointFingerprint: servedFingerprint,
      failover: event,
      verificationStatus: "ACCEPTED",
      disagreement: null,
    };
  }

  return {
    endpoints,
    endpointFingerprints,
    observerId,
    activeEndpoint,
    activeEndpointFingerprint: () => endpointFingerprints[activeIndex] as string,
    failoverCount: () => failovers,
    isHalted: () => halt !== null,
    haltAnomaly: () => halt,
    resolveHalt: () => {
      halt = null;
    },
    read,
  };
}

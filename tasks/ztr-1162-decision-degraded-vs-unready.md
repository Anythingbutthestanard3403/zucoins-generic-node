# ZTR-1162 decision — degraded versus unready

**Date:** 2026-08-11
**Ticket:** ZTR-1162

## Decision

Wire the gateway-read failure counter as a **readiness flip to `status: "degraded"`**
(HTTP 503 on `/health/ready`) once `GATEWAY_READ_FAILURE_BUDGET` consecutive failures
are observed after at least one success. Do **not** invent a separate metric-only
observe phase: the evaluator (`evaluateReadinessFromProbes`) and metrics
(`gn_observation_degraded`) already implement that posture.

## Rollout order (as shipped)

1. **Producer wired** — `createObservedGatewayRead` stamps success and failure from
   every boot + money-path gateway read outcome (this ticket).
2. **Budget governs behaviour** — default `GATEWAY_READ_FAILURE_BUDGET=3` consecutive
   failures close `observation_read_capable` and set `observationDegraded`.
3. **Visibility** — `/health/ready` body `status: "degraded"`, checks include
   `observation_read_capable: false`, metric `gn_observation_degraded=1`, SPA already
   renders degraded via `admin-readiness.ts`.
4. **Failover service** — **not** wired this ticket. Module header on
   `packages/node-core/src/gateway/failover.ts` states production does not construct
   `createEndpointFailoverService`; compensating controls listed there. Follow-on
   slice for AnomalyRecorder adapter + composition-root wiring.

## Why not metric-only first

The ticket recommended "degraded + metric first; promote to readiness flip later."
The codebase already promotes: `observationDegraded` ⇒ readiness status `degraded`
and 503. Adding a second parallel channel would duplicate state. Keeping the
existing semantics and connecting the missing producer is the smaller, correct fix.

## Submit path

`SPLITCHAIN_GATEWAY_URLS[0]` submit selection remains single-endpoint, no failover
(never-blind-retry). Comment recorded at `main.ts` startMoneyWorkers site.

/**
 * Closed map: every purpose a tenant-reachable route serves → the consumer
 * verifier that authenticates it. The gate test
 * (`route-purpose-verifier.gate.test.ts`) fails if a served purpose is missing
 * a verifier, so a green suite cannot pin a purpose the route never serves
 * (ZTR-1145: the prior gate exercised synthetic zp-node-event-v1 only).
 *
 * Sources of truth for "served":
 *   - GET /v1/events `events[]`     → zp-implementer-event-v1
 *     (events-read-service.ts; dual-chain-appender.ts)
 *   - GET /v1/events `checkpoints[]` → zp-implementer-checkpoint-v1
 *     (UP-07; implementer-checkpoint.ts CHECKPOINT_DELIVERY_CHANNEL)
 *   - GET /v1/events/stream SSE data → zp-implementer-event-v1
 *     (same proof representation as the list route)
 *
 * Not listed (deliberately):
 *   - zp-node-event-v1 — operator/auditor-only; never on a reporting-credential route
 *   - zp-implementer-keyrotation-v1 — byte-frozen, verifier ships, but no tenant
 *     route serves it yet (assessed under ZTR-1145; ticket separately if routed)
 */

import {
  authenticateImplementerEvent,
  type ArtifactEnvelope,
  type NodeArtifactResult,
  type NodeVerificationKey,
} from "@zucoins/node-core/verifier/consumer";

export const ROUTE_SERVED_PURPOSES = [
  "zp-implementer-event-v1",
  "zp-implementer-checkpoint-v1",
] as const;

export type RouteServedPurpose = (typeof ROUTE_SERVED_PURPOSES)[number];

export type ConsumerPurposeVerifier = (
  envelope: ArtifactEnvelope,
  nodeKeyMaterial: NodeVerificationKey,
) => NodeArtifactResult;

/**
 * One verifier entry per served purpose. Both purposes share
 * `authenticateImplementerEvent`, which dispatches on the preimage prefix.
 */
export const CONSUMER_VERIFIER_BY_PURPOSE: Readonly<
  Record<RouteServedPurpose, ConsumerPurposeVerifier>
> = Object.freeze({
  "zp-implementer-event-v1": authenticateImplementerEvent,
  "zp-implementer-checkpoint-v1": authenticateImplementerEvent,
});

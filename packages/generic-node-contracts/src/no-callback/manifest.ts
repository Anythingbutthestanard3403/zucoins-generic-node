// Concern manifest: the serialized surface the freeze gate snapshots.
// buildNoCallbackManifest() aggregates the rejected surfaces, egress-absence census, sole-channel
// data, and residual guardrail; manifest.freeze.test.ts diffs it against gen/no-callback.json.

import { defineConcernManifest } from "../testkit/concernManifest.ts";
import { REJECTED_SURFACES } from "./rejected-surfaces.js";
import { ALLOWED_EGRESS_KIND, OPERATION_EGRESS, OPERATIONS } from "./egress.js";
import { AUTHORITATIVE_CHANNELS, AUTHORITATIVE_EVENT_PURPOSE, WEBHOOK_RELOCATION } from "./channels.js";
import { RESIDUAL_GUARDRAIL } from "./residual-guardrail.js";

export const noCallbackConcernManifest = {
  concern: "no-callback",
  frozen: ["REJECTED_SURFACES", "EGRESS_ABSENCE", "AUTHORITATIVE_CHANNELS", "RESIDUAL_GUARDRAIL"],
} as const;

export function buildNoCallbackManifest() {
  return {
    concern: noCallbackConcernManifest.concern,
    governing: {
      spec: "api receive surface; operation-flow delivery channels",
      decision: "no-callback-removal",
      dependsOn: "reporting-tuples",
    },
    rejectedSurfaces: REJECTED_SURFACES.map((s) => ({ surface: s.surface, location: s.location, ground: s.ground })),
    egressAbsence: {
      allowedEgressKind: ALLOWED_EGRESS_KIND,
      operations: [...OPERATIONS],
      operationEgress: OPERATION_EGRESS.map((r) => ({ operation: r.operation, nonGatewayEgress: r.nonGatewayEgress })),
    },
    soleChannel: {
      authoritativeChannels: AUTHORITATIVE_CHANNELS.map((c) => ({ channel: c.channel, route: c.route, egress: c.egress, role: c.role })),
      authoritativeEventPurpose: AUTHORITATIVE_EVENT_PURPOSE,
      webhookRelocation: {
        owner: WEBHOOK_RELOCATION.owner,
        name: WEBHOOK_RELOCATION.name,
        builtFrom: WEBHOOK_RELOCATION.builtFrom,
        grounds: [...WEBHOOK_RELOCATION.grounds],
      },
    },
    residualGuardrail: {
      active: RESIDUAL_GUARDRAIL.active,
      appliesOnlyIf: RESIDUAL_GUARDRAIL.appliesOnlyIf,
      requirements: [...RESIDUAL_GUARDRAIL.requirements],
    },
  } as const;
}

export type NoCallbackManifest = ReturnType<typeof buildNoCallbackManifest>;

/**
 * The no-callback concern's self-registered ConcernManifest (the concern-manifest
 * registry leave-behind shape; see testkit/concernManifest.ts). Wraps the exact
 * `buildNoCallbackManifest()` output — the same call the freeze gate diffs against
 * `gen/no-callback.json` — byte-identically under the canonical shape;
 * `noCallbackConcernManifest` above is the provisional form it supersedes.
 * Sibling `attack-manifest.ts` self-registers the attack census separately (kept apart per this
 * directory's own convention: "earlier slices win"). Registration export only — the registry
 * assembly is `src/registry.ts`.
 */
export const NO_CALLBACK_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "no-callback",
  decisionRefs: ["no-callback-removal"],
  frozenValues: { noCallback: buildNoCallbackManifest() },
  goldenRefs: [
    {
      path: "src/no-callback/gen/no-callback.json",
      sha256: "8896bb07dba9d32ea894268a5b2297b6c49792ad635fbf3256e0d132e254b59b",
    },
  ],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "api receive surface",
    "operation-flow delivery channels",
    "no-callback-removal",
  ],
});

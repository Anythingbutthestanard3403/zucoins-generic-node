// Concern sub-manifest: the serialized attack-neutralization census + cursor-authority
// facts the freeze gate snapshots ("attack callback transport and replay" evidence,
// converted to the no-callback world). Kept SEPARATE from the frozen no-callback.json —
// earlier slices win — so that freeze is untouched. attack-transport.freeze.test.ts diffs this
// against gen/attack-surface.json.

import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  NEUTRALIZED_REPLAY_ATTACKS,
  NEUTRALIZED_TRANSPORT_ATTACKS,
  NON_GATEWAY_DESTINATION_CLASSES,
} from "./attack-surface.js";
import { AUTHORITATIVE_CURSOR_ROLE, SSE_ACCELERATOR_ROLE } from "./cursor-authority.js";

export const attackSurfaceConcernManifest = {
  concern: "no-callback",
  frozen: ["NEUTRALIZED_TRANSPORT_ATTACKS", "NEUTRALIZED_REPLAY_ATTACKS", "NON_GATEWAY_DESTINATION_CLASSES", "CURSOR_AUTHORITY"],
} as const;

export function buildAttackSurfaceManifest() {
  return {
    concern: attackSurfaceConcernManifest.concern,
    governing: {
      spec: "api receive surface; operation-flow delivery channels",
      decisions: ["no-callback-removal", "reporting-channel", "ssrf-url-guard"],
      dependsOn: ["no-callback", "reporting-behavior", "event-sequencing"],
    },
    transportAttacks: NEUTRALIZED_TRANSPORT_ATTACKS.map((a) => ({
      attack: a.attack,
      classicVector: a.classicVector,
      neutralizedBy: a.neutralizedBy,
    })),
    replayAttacks: NEUTRALIZED_REPLAY_ATTACKS.map((a) => ({
      attack: a.attack,
      classicVector: a.classicVector,
      neutralizedBy: a.neutralizedBy,
    })),
    nonGatewayDestinationClasses: NON_GATEWAY_DESTINATION_CLASSES.map((d) => ({
      class: d.class,
      exampleHost: d.exampleHost,
    })),
    cursorAuthority: {
      authoritativeCursorRole: AUTHORITATIVE_CURSOR_ROLE,
      sseAcceleratorRole: SSE_ACCELERATOR_ROLE,
    },
  } as const;
}

export type AttackSurfaceManifest = ReturnType<typeof buildAttackSurfaceManifest>;

/**
 * The attack census's self-registered ConcernManifest (the concern-manifest registry
 * leave-behind shape; see testkit/concernManifest.ts). Wraps the exact
 * `buildAttackSurfaceManifest()` output — the same call `attack-transport.freeze.test.ts`
 * diffs against `gen/attack-surface.json` — byte-identically under the canonical shape;
 * `attackSurfaceConcernManifest` above is the provisional form it supersedes. Kept separate
 * from sibling `manifest.ts`'s channel-freeze registration per this directory's own
 * convention ("earlier slices win"). Registration export only — the registry assembly is
 * `src/registry.ts`, which merges both `no-callback` exports under one directory key.
 */
export const ATTACK_SURFACE_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "no-callback",
  decisionRefs: ["no-callback-removal", "reporting-channel", "ssrf-url-guard"],
  frozenValues: { attackSurface: buildAttackSurfaceManifest() },
  goldenRefs: [
    {
      path: "src/no-callback/gen/attack-surface.json",
      sha256: "e242c4d32ad2ae749f48dcf128674a84fd751bc3775c3564c1c1f139ba6c03d3",
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
    "reporting-channel",
    "ssrf-url-guard",
  ],
});

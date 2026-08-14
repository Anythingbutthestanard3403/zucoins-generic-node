import { defineConcernManifest } from "../testkit/concernManifest.ts";
import { OPERATION_KINDS, CHILD_LINK, WORKFLOW_GRAPH_SUPPORTED } from "./operations.contract.ts";
import { AFTER_LANDING_KINDS, LIFECYCLE_RULES } from "./lifecycle.contract.ts";
import { OPERATION_STATES, FORBIDDEN_STATE_ALIASES } from "./states.contract.ts";
import { DURABLE_EVENTS, FORBIDDEN_EVENT_ALIASES } from "./events.contract.ts";
import {
  VERIFICATION_MODES,
  DEFAULT_VERIFICATION_MODE,
  RELEASED_NODE_VERIFIED,
  ALLOW_NODE_VERIFIED_SETTING_KEY,
  VERIFICATION_MODE_ERROR_CODES,
} from "./verification-mode.contract.ts";
import { PUBLIC_ROUTES, ADMIN_ROUTES, RETIRED_ROUTES } from "./routes.contract.ts";
import { CORE_CAPABILITIES, ABSENT_CAPABILITIES, LAUNCH_EXCLUSIONS } from "./capabilities.contract.ts";

/**
 * The operations concern's self-registered ConcernManifest (see ../../CONTRACT.md,
 * "ConcernManifest schema"). Registration export only — the concern-manifest registry
 * assembles `src/registry.ts`; nothing else touches it.
 */
export const OPERATIONS_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "operations",
  decisionRefs: ["three-operation-model", "launch-deferral"],
  frozenValues: {
    OPERATION_KINDS,
    CHILD_LINK,
    WORKFLOW_GRAPH_SUPPORTED,
    AFTER_LANDING_KINDS,
    LIFECYCLE_RULES,
    OPERATION_STATES,
    FORBIDDEN_STATE_ALIASES,
    DURABLE_EVENTS,
    FORBIDDEN_EVENT_ALIASES,
    VERIFICATION_MODES,
    DEFAULT_VERIFICATION_MODE,
    RELEASED_NODE_VERIFIED,
    ALLOW_NODE_VERIFIED_SETTING_KEY,
    VERIFICATION_MODE_ERROR_CODES,
    PUBLIC_ROUTES,
    ADMIN_ROUTES,
    RETIRED_ROUTES,
    CORE_CAPABILITIES,
    ABSENT_CAPABILITIES,
    LAUNCH_EXCLUSIONS,
  },
  goldenRefs: [],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "forbidden-terms:packages/node-core/src",
    "forbidden-terms:apps/generic-node/src",
    "dependency-boundary:packages/generic-node-contracts/src",
    "anti-self-reference:operation-kind-enum",
  ],
  sourceDocCitations: [
    "three-operation-model: the node exposes exactly three public money operations",
    "launch-deferral: no wallet-key import capability ships at launch",
    "core capabilities and launch exclusions",
    "API contract: route inventory and retired paths",
    "state-event reference: states, events, transitions, forbidden aliases",
    "per-operation verification mode: INDEPENDENT | NODE_VERIFIED metadata (ZTR-1299)",
  ],
});

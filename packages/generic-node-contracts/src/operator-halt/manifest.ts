import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  HALT_KINDS,
  OUT_OF_SCOPE_HALT_MECHANISMS,
  HALT_GATED_OPERATION_KINDS,
  HALT_EXEMPT_OPERATION_KINDS,
  HALT_NEVER_GATED_INTERNAL_PATHS,
  OPERATOR_RECOVERY_ACTIONS,
  RECOVERY_ACTION_REAUTHORIZED_FORMATION,
  HALT_GATED_RECOVERY_ACTIONS,
  HALT_NEVER_GATED_RECOVERY_ACTIONS,
  HALT_TOGGLE_AUTH,
  HALT_ADMIN_ROUTES,
  HALT_PERSISTENCE,
} from "./halt.contract.ts";
import {
  SIGNING_TRIGGERS,
  SIGNING_PURPOSE_BY_OPERATION_KIND,
  MONEY_MUTATION_HALT_MAP,
} from "./gating.contract.ts";
import {
  HALT_RACE_PHASES,
  PHASE_APPLICABILITY,
  HALT_RACE_TABLE,
  CONCURRENT_TOGGLE_RESOLUTION,
} from "./races.contract.ts";

/**
 * The operator-halt concern's self-registered ConcernManifest (../../CONTRACT.md "ConcernManifest schema
 * (the concern-manifest registry leave-behind)"). Registration import only — the concern-manifest registry assembles `src/registry.ts`; no
 * other lane touches it.
 */
export const OPERATOR_HALT_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "operator-halt",
  decisionRefs: ["operator-kill-switch", "scale-to-zero"],
  frozenValues: {
    HALT_KINDS,
    OUT_OF_SCOPE_HALT_MECHANISMS,
    HALT_GATED_OPERATION_KINDS,
    HALT_EXEMPT_OPERATION_KINDS,
    HALT_NEVER_GATED_INTERNAL_PATHS,
    OPERATOR_RECOVERY_ACTIONS,
    RECOVERY_ACTION_REAUTHORIZED_FORMATION,
    HALT_GATED_RECOVERY_ACTIONS,
    HALT_NEVER_GATED_RECOVERY_ACTIONS,
    HALT_TOGGLE_AUTH,
    HALT_ADMIN_ROUTES,
    HALT_PERSISTENCE,
    SIGNING_TRIGGERS,
    SIGNING_PURPOSE_BY_OPERATION_KIND,
    MONEY_MUTATION_HALT_MAP,
    HALT_RACE_PHASES,
    PHASE_APPLICABILITY,
    HALT_RACE_TABLE,
    CONCURRENT_TOGGLE_RESOLUTION,
  },
  goldenRefs: [],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "forbidden-terms:packages/node-core/src",
    "forbidden-terms:apps/generic-node/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "operator-kill-switch",
    "scale-to-zero",
    "operations recovery",
    "guarded CAS mutation",
    "state-event applies-to table",
  ],
});

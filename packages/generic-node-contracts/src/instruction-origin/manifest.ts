import { defineConcernManifest } from "../testkit/concernManifest.ts";
import { ORIGIN_CLASSES, ORIGIN_CLASS_CLAIMS } from "./origin-classes.contract.ts";
import {
  DISCOVERY_PATH,
  PIN_REJECT_REASONS,
} from "./identity-pin.contract.ts";
import {
  CAPABILITY_IDS,
  CAPABILITY_MANIFEST,
  NON_CAPABILITIES,
} from "./capability-manifest.contract.ts";
import {
  PRESENTATION_HANDOFF_FIELDS,
  SUBSTITUTION_THREAT_TABLE,
} from "./presentation-handoff.contract.ts";

/**
 * The instruction-origin concern's self-registered ConcernManifest. Registration import only — the concern-manifest registry assembles `src/registry.ts`. No raw byte
 * artifacts are frozen by this concern (it is data + pure predicates only, per its
 * CONTRACT_FREEZE gate), so `goldenRefs` is empty; `scanRules` covers only the forbidden-term
 * and dependency-boundary gates that apply to every concern.
 */
export const INSTRUCTION_ORIGIN_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "instruction-origin",
  decisionRefs: ["instruction-origin-identity"],
  frozenValues: {
    ORIGIN_CLASSES,
    ORIGIN_CLASS_CLAIMS,
    DISCOVERY_PATH,
    PIN_REJECT_REASONS,
    CAPABILITY_IDS,
    CAPABILITY_MANIFEST,
    NON_CAPABILITIES,
    PRESENTATION_HANDOFF_FIELDS,
    SUBSTITUTION_THREAT_TABLE,
  },
  goldenRefs: [],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "implementer-controlled-origin model",
    "system overview",
    "signing custody and security",
    "API discovery and proof surfaces",
    "instruction-origin-identity",
  ],
});

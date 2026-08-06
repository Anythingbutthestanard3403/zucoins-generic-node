import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  IMPORT_DRAIN_DEFERRAL,
  CUTOVER_GATE,
  LAUNCH_COMMAND_SURFACE,
  SCHEMA_WRITER_SURFACE,
  FORBIDDEN_LAUNCH_CAPABILITY_VERBS,
  RUNTIME_OBLIGATIONS,
} from "./deferral.contract.ts";

/**
 * The launch-deferral concern's self-registered ConcernManifest (the concern-manifest registry
 * leave-behind shape; see testkit/concernManifest.ts). Registration export only — the
 * registry assembly is `src/registry.ts`; nothing else touches it.
 */
export const LAUNCH_DEFERRAL_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "launch-deferral",
  decisionRefs: ["launch-capability-deferral"],
  frozenValues: {
    IMPORT_DRAIN_DEFERRAL,
    CUTOVER_GATE,
    LAUNCH_COMMAND_SURFACE,
    SCHEMA_WRITER_SURFACE,
    FORBIDDEN_LAUNCH_CAPABILITY_VERBS,
    RUNTIME_OBLIGATIONS,
  },
  goldenRefs: [],
  scanRules: ["forbidden-terms:packages/generic-node-contracts/src"],
  sourceDocCitations: [
    "launch-capability-deferral",
    "system-overview launch scope",
    "node-core launch capabilities",
  ],
});

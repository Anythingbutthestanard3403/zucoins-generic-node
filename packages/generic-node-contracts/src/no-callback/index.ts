// Public surface of the no-callback concern. Concern-local barrel owned by the channel-freeze
// slice; NOT the package index (src/index.ts, owned by the concern-manifest registry). The attack census + the runtime network-containment gate consume this.

export { type RejectedSurface, REJECTED_SURFACES } from "./rejected-surfaces.js";

export {
  type OperationName,
  ALLOWED_EGRESS_KIND,
  OPERATIONS,
  OPERATION_EGRESS,
  isEgressAllowed,
  operationMakesNoNonGatewayEgress,
} from "./egress.js";

export {
  AUTHORITATIVE_CHANNELS,
  AUTHORITATIVE_EVENT_PURPOSE,
  WEBHOOK_RELOCATION,
} from "./channels.js";

export { RESIDUAL_GUARDRAIL } from "./residual-guardrail.js";

export {
  type ChannelShape,
  type CanonicalChannelShape,
  type GuardrailShape,
  isRejectedSurface,
  callbackHostForbidden,
  soleChannelIsAuthoritativePull,
  authoritativeChannelsAreCanonical,
  residualGuardrailInactive,
} from "./verifier.js";

export {
  type NoCallbackManifest,
  noCallbackConcernManifest,
  buildNoCallbackManifest,
} from "./manifest.js";

// Attack-neutralization census + cursor-authority (scope converted after callback removal).
export {
  type TransportAttack,
  type ReplayAttack,
  type NonGatewayDestinationClass,
  type EgressCensusRow,
  NEUTRALIZED_BY_EGRESS_ABSENCE,
  NEUTRALIZED_BY_PULL_CURSOR,
  NEUTRALIZED_TRANSPORT_ATTACKS,
  NEUTRALIZED_REPLAY_ATTACKS,
  NON_GATEWAY_DESTINATION_CLASSES,
  egressRowIsClean,
  egressCensusIsClean,
  attackIsNeutralized,
} from "./attack-surface.js";

export {
  type CursorChannelShape,
  type SseCursorModelShape,
  AUTHORITATIVE_CURSOR_ROLE,
  SSE_ACCELERATOR_ROLE,
  pullIsSoleCursorAuthority,
  sseModelKeepsCursorAuthority,
  sparseTenantViewIsComplete,
  gapDetectorIsChainNotContiguity,
} from "./cursor-authority.js";

export {
  type AttackSurfaceManifest,
  attackSurfaceConcernManifest,
  buildAttackSurfaceManifest,
} from "./attack-manifest.js";

// Audit correction — the pure callback/webhook/push surface census (defects 2 & 3).
export {
  CALLBACK_SURFACE_MATRIX,
  scanForCallbackSurfaces,
  isConcernPathExempt,
  maskComments,
} from "./callback-census.js";

// Docs anti-reintroduction extension — the bare callback-term
// census for prose (v2 proposal docs), as opposed to callback-census.ts's code-surface-shaped matrix.
export { DOC_CALLBACK_TERM_CLASS, scanForCallbackTerms } from "./doc-census.js";

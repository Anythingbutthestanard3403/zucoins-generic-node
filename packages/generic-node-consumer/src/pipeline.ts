/**
 * Product-neutral independent verification pipeline for the installable SDK (originally
 * shipped in @zucoins/consumer-example).
 *
 * Steps implemented:
 *   1. Authenticate node event signature/sequence (claim only).
 *   2. Obtain expected artifact via verification-material (server-authenticated channel).
 *   3. Read required wallet heads from consumer-configured SplitChain endpoints.
 *   4. Run the independent consumer verifier library.
 *   5. Record operation_verified separately from node_claim.
 *   6. POST verification-complete when the consumer reaches a terminal verdict.
 *
 * Node identity keys are resolved only through the consumer's own pinning workflow.
 */

import { Buffer } from "node:buffer";

import {
  authenticateImplementerEvent,
  parseProofBundle,
  verifyOperationProof,
  type ArtifactEnvelope,
  type NodeVerificationKey,
  type OperationProofVerdict,
  type WireProofBundle,
} from "@zucoins/node-core/verifier/consumer";
import {
  pinAndAuthenticateArtifact,
  type CachedIdentityPin,
  type DiscoveryIdentityWire,
  type OriginClass,
} from "@zucoins/node-core/verifier/consumer/pinning";
import type { WalletStateProjection } from "@zucoins/node-core";

import {
  advanceWatermark,
  resumeAfterSeq,
  type ConsumerStore,
} from "./cursor-store.js";
import {
  deriveLandingProof,
  type IndependentHeadForRole,
} from "./landing-proof.js";
import {
  classifyIndependentStream,
  projectionsAgree,
  readIndependentHead,
  type IndependentHeadRead,
} from "./observation.js";
import type {
  CompositionLabel,
  ConsumerOperation,
  DirectGatewayObservation,
  NodeClaimRecord,
  NodeEventWake,
  PublicOperationKind,
  SubscribeLifecycleProjection,
  TriggerSource,
  VerificationCompleteRequest,
  VerificationCompleteResponse,
  VerificationMaterialWire,
} from "./types.js";
import { COMPOSITION_TO_KIND } from "./types.js";

// ---------------------------------------------------------------------------
// Open / track
// ---------------------------------------------------------------------------

export function openConsumerOperation(input: {
  readonly operationId: string;
  readonly compositionLabel: CompositionLabel;
  readonly rowVersion?: number;
  readonly clientReference?: string | null;
}): ConsumerOperation {
  return {
    operationId: input.operationId,
    kind: COMPOSITION_TO_KIND[input.compositionLabel],
    compositionLabel: input.compositionLabel,
    status: "OPEN",
    rowVersion: input.rowVersion ?? 1,
    clientReference: input.clientReference ?? null,
    nodeClaim: null,
    operationVerified: null,
    lastTriggerSource: null,
    acknowledgementId: null,
    leaseReleaseStatus: null,
  };
}

// ---------------------------------------------------------------------------
// Step 1 — event-as-trigger (never settlement authority)
// ---------------------------------------------------------------------------

export type TriggerResult =
  | {
      readonly ok: true;
      readonly operation: ConsumerOperation;
      readonly nodeClaim: NodeClaimRecord;
    }
  | {
      readonly ok: false;
      readonly reason: "event_not_authenticated" | "operation_id_mismatch";
      readonly detail: string;
      readonly operation: ConsumerOperation;
    };

/**
 * Ingest a signed reporting-credential event purely as a wake signal.
 * Authenticates the claim; never writes operation_verified from the claim.
 */
export function ingestEventWake(
  operation: ConsumerOperation,
  wake: NodeEventWake,
  nodeEventKey: NodeVerificationKey,
  source: TriggerSource,
  nowUnixMs: number,
): TriggerResult {
  if (wake.operation_id !== operation.operationId) {
    return {
      ok: false,
      reason: "operation_id_mismatch",
      detail: "event operation_id does not match tracked operation",
      operation,
    };
  }

  // Wire event artifact fields are plain strings; the verifier brands them at the boundary.
  // GET /v1/events serves zp-implementer-event-v1 (not zp-node-event-v1).
  const auth = authenticateImplementerEvent(
    wake.artifact as ArtifactEnvelope,
    nodeEventKey,
  );
  const nodeClaim: NodeClaimRecord = {
    state: wake.node_claim_state,
    eventType: wake.event_type,
    authenticated: auth.authenticated,
    source,
    implementerSeq: wake.implementer_seq,
    observedAtUnixMs: nowUnixMs,
  };

  if (!auth.authenticated) {
    // Lying-node path: forged/unauthenticated claim is retained as node_claim
    // with authenticated=false; operation_verified stays untouched.
    const next: ConsumerOperation = {
      ...operation,
      status: operation.status === "OPEN" ? "AWAITING_TRIGGER" : operation.status,
      nodeClaim,
      lastTriggerSource: source,
    };
    return {
      ok: false,
      reason: "event_not_authenticated",
      detail: auth.reason,
      operation: next,
    };
  }

  const next: ConsumerOperation = {
    ...operation,
    status: "AWAITING_TRIGGER",
    nodeClaim,
    lastTriggerSource: source,
    // Deliberately do NOT touch operationVerified.
  };
  return { ok: true, operation: next, nodeClaim };
}

/**
 * Browser-facing subscribe handle. Lifecycle-only — never proof.
 * Records a wake without claiming event authentication (handle is low-authority).
 */
export function ingestSubscribeProjection(
  operation: ConsumerOperation,
  projection: SubscribeLifecycleProjection,
  nowUnixMs: number,
): ConsumerOperation {
  if (projection.operation_id !== operation.operationId) {
    return operation;
  }
  const nodeClaim: NodeClaimRecord = {
    state: projection.state,
    eventType: "subscribe.lifecycle",
    authenticated: false, // the subscribe stream is not a signed proof channel
    source: "subscribe_handle",
    implementerSeq: null,
    observedAtUnixMs: nowUnixMs,
  };
  return {
    ...operation,
    status: "AWAITING_TRIGGER",
    nodeClaim,
    lastTriggerSource: "subscribe_handle",
  };
}

// ---------------------------------------------------------------------------
// Steps 2–5 — material + independent observation + verdict
// ---------------------------------------------------------------------------

export interface VerifyOperationInput {
  readonly operation: ConsumerOperation;
  readonly material: VerificationMaterialWire;
  /** Consumer's own gateway captures keyed by evidence role. */
  readonly directObservations: readonly DirectGatewayObservation[];
  readonly identityPin: CachedIdentityPin;
  readonly discovery: DiscoveryIdentityWire | null;
  readonly originClass: OriginClass;
  readonly pinnedGatewayFingerprint: string;
  readonly nowUnixMs: number;
  readonly liveChain?: boolean;
  /**
   * Optional baselines derived earlier by the consumer (T0). When omitted,
   * genesis / deriveBaseline-from-response defaults apply inside the verifier.
   */
  readonly baselines?: {
    readonly receiver?: WalletStateProjection;
    readonly source?: WalletStateProjection;
    readonly destination?: WalletStateProjection;
  };
}

export type VerifyOperationResult = {
  readonly operation: ConsumerOperation;
  readonly verdict: OperationProofVerdict;
  readonly pinOk: boolean;
  readonly pinDetail?: string;
  readonly endpointDisagreement: boolean;
  readonly anomalyBlocked: boolean;
  readonly anomalyKind?: string;
};

function kindFromMaterial(
  material: VerificationMaterialWire,
): PublicOperationKind | null {
  switch (material.operation_type) {
    case "RECEIVE_EXTERNAL":
      return "receive";
    case "MOVE_INTERNAL":
      return "move";
    case "SEND_EXTERNAL":
      return "send";
    default:
      return null;
  }
}

function observationForRole(
  obs: readonly DirectGatewayObservation[],
  role: DirectGatewayObservation["role"],
): DirectGatewayObservation | undefined {
  return obs.find((o) => o.role === role);
}

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function buildWireBundle(
  kind: PublicOperationKind,
  artifact: ArtifactEnvelope,
  direct: readonly DirectGatewayObservation[],
  baselines: VerifyOperationInput["baselines"],
): WireProofBundle | { error: string } {
  const b64 = (role: DirectGatewayObservation["role"]) => {
    const o = observationForRole(direct, role);
    if (!o) return null;
    return { base64url: toBase64Url(o.rawResponseBytes) };
  };

  switch (kind) {
    case "receive": {
      const response = b64("RECEIVER");
      if (!response) return { error: "missing RECEIVER direct observation" };
      return {
        kind: "receive",
        artifact,
        response,
        baseline: baselines?.receiver,
      };
    }
    case "move": {
      const sourceResponse = b64("SOURCE");
      const destinationResponse = b64("DESTINATION");
      if (!sourceResponse) return { error: "missing SOURCE direct observation" };
      if (!destinationResponse) return { error: "missing DESTINATION direct observation" };
      return {
        kind: "move",
        artifact,
        sourceResponse,
        destinationResponse,
        sourceBaseline: baselines?.source,
        destinationBaseline: baselines?.destination,
      };
    }
    case "send": {
      // Wire shape (parseProofBundle): send uses `response` + `baseline`, same as receive
      // (not sourceResponse — that field is move-only).
      const response = b64("SOURCE");
      if (!response) return { error: "missing SOURCE direct observation" };
      return {
        kind: "send",
        artifact,
        response,
        baseline: baselines?.source,
      };
    }
  }
}

function indeterminate(
  kind: PublicOperationKind,
  stage: "artifact" | "envelope" | "transaction" | "delta",
  reason: string,
): OperationProofVerdict {
  return { verdict: "INDETERMINATE", kind, stage, reason };
}

/**
 * Full independent verification. Never copies material.state / node_claim into
 * operation_verified. Endpoint disagreement and pin failure fail closed.
 */
export function verifyOperationIndependently(input: VerifyOperationInput): VerifyOperationResult {
  const {
    operation,
    material,
    directObservations,
    identityPin,
    discovery,
    originClass,
    pinnedGatewayFingerprint,
    nowUnixMs,
    liveChain,
    baselines,
  } = input;

  const kind = kindFromMaterial(material) ?? operation.kind;

  // --- Endpoint pin + independent head presence ---
  let endpointDisagreement = false;
  for (const obs of directObservations) {
    const head = readIndependentHead(
      {
        rawResponseBytes: obs.rawResponseBytes,
        walletPublicKey: obs.walletPublicKey,
        endpointFingerprint: obs.endpointFingerprint,
      },
      pinnedGatewayFingerprint,
    );
    if (!head.ok && head.reason === "endpoint_fingerprint_mismatch") {
      endpointDisagreement = true;
    }
  }

  if (endpointDisagreement) {
    const verdict = indeterminate(
      kind,
      "envelope",
      "endpoint_disagreement: independent gateway fingerprint mismatch; never prefer node",
    );
    const next: ConsumerOperation = {
      ...operation,
      status: "INDETERMINATE",
      operationVerified: verdict,
    };
    return {
      operation: next,
      verdict,
      pinOk: false,
      endpointDisagreement: true,
      anomalyBlocked: false,
    };
  }

  // --- Node-relayed vs independent projection disagreement ---
  for (const evidence of material.observation_evidence) {
    if (evidence.terminal === null) continue;
    const evidenceRole = evidence.evidence_role;
    // Direct gateway observations only ever cover the consumer's own node-controlled
    // wallets — an externally owned counterparty (EXTERNAL_SENDER_PREFLIGHT /
    // EXTERNAL_DESTINATION_PARTIAL) is never independently read.
    if (evidenceRole !== "RECEIVER" && evidenceRole !== "SOURCE" && evidenceRole !== "DESTINATION") continue;
    const direct = observationForRole(directObservations, evidenceRole);
    if (!direct) continue;
    const head = readIndependentHead(
      {
        rawResponseBytes: direct.rawResponseBytes,
        walletPublicKey: direct.walletPublicKey,
        endpointFingerprint: direct.endpointFingerprint,
      },
      pinnedGatewayFingerprint,
    );
    if (!head.ok) continue;
    if (!projectionsAgree(head.projection, evidence.terminal.projection)) {
      const verdict = indeterminate(
        kind,
        "delta",
        "endpoint_disagreement: independent head projection disagrees with node-relayed terminal",
      );
      const next: ConsumerOperation = {
        ...operation,
        status: "INDETERMINATE",
        operationVerified: verdict,
      };
      return {
        operation: next,
        verdict,
        pinOk: true,
        endpointDisagreement: true,
        anomalyBlocked: false,
      };
    }
  }

  // --- Pin + authenticate expected artifact (pinning workflow) ---
  // Verification-material wire fields are plain strings; brands are applied at the verifier boundary.
  const artifact = material.expected_artifact as ArtifactEnvelope;

  const pinResult = pinAndAuthenticateArtifact({
    cached: identityPin,
    discovery,
    originClass,
    artifact,
    nowUnixMs,
    liveChain,
  });

  if (!pinResult.ok) {
    const verdict = indeterminate(kind, "artifact", `pin_refused:${pinResult.reason}`);
    const next: ConsumerOperation = {
      ...operation,
      status: "INDETERMINATE",
      operationVerified: verdict,
    };
    return {
      operation: next,
      verdict,
      pinOk: false,
      pinDetail: pinResult.reason,
      endpointDisagreement: false,
      anomalyBlocked: false,
    };
  }

  // --- Build + parse proof bundle from *independent* observations ---
  const wireOrErr = buildWireBundle(kind, artifact, directObservations, baselines);
  if ("error" in wireOrErr) {
    const verdict = indeterminate(kind, "envelope", wireOrErr.error);
    const next: ConsumerOperation = {
      ...operation,
      status: "INDETERMINATE",
      operationVerified: verdict,
    };
    return {
      operation: next,
      verdict,
      pinOk: true,
      endpointDisagreement: false,
      anomalyBlocked: false,
    };
  }

  const parsed = parseProofBundle(wireOrErr);
  if (!parsed.ok) {
    const verdict = indeterminate(kind, "envelope", `${parsed.reason}:${parsed.detail}`);
    const next: ConsumerOperation = {
      ...operation,
      status: "INDETERMINATE",
      operationVerified: verdict,
    };
    return {
      operation: next,
      verdict,
      pinOk: true,
      endpointDisagreement: false,
      anomalyBlocked: false,
    };
  }

  // --- Independent verifier pipeline under the pinned key ---
  const verdict = verifyOperationProof(parsed.bundle, pinResult.verificationKey);

  const status =
    verdict.verdict === "VERIFIED"
      ? "VERIFIED"
      : verdict.verdict === "REJECTED"
        ? "REJECTED"
        : "INDETERMINATE";

  const next: ConsumerOperation = {
    ...operation,
    status,
    operationVerified: verdict,
    // nodeClaim retained as-is — never overwritten from verdict.
  };

  return {
    operation: next,
    verdict,
    pinOk: true,
    endpointDisagreement: false,
    anomalyBlocked: false,
  };
}

// ---------------------------------------------------------------------------
// Regression / jump gate (observation stream, not the proof pipeline)
// ---------------------------------------------------------------------------

export function gateAnomalousObservation(input: {
  readonly prior: Parameters<typeof classifyIndependentStream>[0]["prior"];
  readonly next: Parameters<typeof classifyIndependentStream>[0]["next"];
  readonly priorHistoryHasNonGenesis: boolean;
  readonly acceptedStateSignatureHistory: readonly string[];
}): {
  readonly mayAct: boolean;
  readonly relationship: string;
  readonly reason?: string;
} {
  const outcome = classifyIndependentStream(input);
  if (!outcome.actionable) {
    return {
      mayAct: false,
      relationship: outcome.relationship,
      reason: outcome.reason,
    };
  }
  return { mayAct: true, relationship: outcome.relationship };
}

// ---------------------------------------------------------------------------
// Step 6 — verification-complete acknowledgement
// ---------------------------------------------------------------------------

/**
 * This pipeline's own independently-verified head for one `RECEIVER`/`SOURCE`/`DESTINATION`
 * wallet, sourced from `OperationProofVerdict` (never the node's `ancestor_proofs` claim).
 * `receive`/`send` only ever verify one wallet (the verdict's primary `projection`); `move`
 * verifies both source and destination but the verdict type carries only one primary role, so
 * the non-primary side rides `secondaryProjection` (populated by `verifyMoveProof`).
 */
function independentHeadForRole(
  verdict: OperationProofVerdict,
  role: "RECEIVER" | "SOURCE" | "DESTINATION",
): IndependentHeadForRole | undefined {
  if (verdict.verdict !== "VERIFIED") return undefined;
  const primaryRole = verdict.kind === "receive" ? "RECEIVER" : "SOURCE";
  if (role === primaryRole) {
    return { projection: verdict.projection, completedTransactionSha256: verdict.completedTransactionSha256 };
  }
  if (verdict.kind === "move" && role === "DESTINATION" && verdict.secondaryProjection !== undefined) {
    return {
      projection: verdict.secondaryProjection,
      completedTransactionSha256: verdict.secondaryCompletedTransactionSha256!,
    };
  }
  return undefined;
}

export function buildVerificationCompleteRequest(input: {
  readonly operation: ConsumerOperation;
  readonly material: VerificationMaterialWire;
  readonly consumedCursor: string;
}): VerificationCompleteRequest | { error: string } {
  const { operation, material, consumedCursor } = input;
  const proofVerdict = operation.operationVerified;
  if (proofVerdict === null) {
    return { error: "operation_verified is null; cannot acknowledge" };
  }

  const wallet_evidence: VerificationCompleteRequest["wallet_evidence"][number][] = [];
  for (const ev of material.observation_evidence) {
    const role = ev.evidence_role;
    // wallet_evidence[].role is the 3-value node-controlled-wallet vocabulary —
    // narrower than observation_evidence's 5-value evidence_role. An externally owned
    // counterparty (EXTERNAL_SENDER_PREFLIGHT / EXTERNAL_DESTINATION_PARTIAL) never gets a
    // wallet_evidence row: it has no node-controlled wallet_id and the server's WalletEvidence
    // schema doesn't accept those role tokens.
    if (role !== "RECEIVER" && role !== "SOURCE" && role !== "DESTINATION") continue;
    if (ev.wallet_id === null) {
      return { error: `observation_evidence role ${role} has a null wallet_id; cannot build wallet_evidence` };
    }

    const ancestorProof = material.ancestor_proofs?.find((a) => a.evidence_role === role);
    const independentHead = independentHeadForRole(proofVerdict, role);
    const landingProofResult = deriveLandingProof({ ancestorProof, independentHead });
    if (!landingProofResult.ok) {
      return {
        error:
          `cannot independently derive landing_proof for role ${role}: ${landingProofResult.reason}; ` +
          "refusing to submit rather than fabricate wallet_evidence[].landing_proof",
      };
    }

    const terminal = ev.terminal ?? ev.t0;
    wallet_evidence.push({
      wallet_id: ev.wallet_id,
      role,
      t0: {
        observation_id: ev.t0.observation_id,
        projection: { ...ev.t0.projection },
      },
      terminal: {
        observation_id: terminal.observation_id,
        projection: { ...terminal.projection },
      },
      landing_proof: landingProofResult.landingProof,
    });
  }

  if (wallet_evidence.length === 0) {
    return { error: "no wallet_evidence rows derivable from verification material" };
  }

  return {
    expected_row_version: operation.rowVersion,
    consumed_cursor: consumedCursor,
    verdict: proofVerdict.verdict,
    wallet_evidence,
  };
}

/**
 * Apply a successful verification-complete response.
 *
 * Current frozen-wire limitation: `buildVerificationCompleteRequest` can only construct a
 * request for a VERIFIED verdict because the server requires `landing_proof` unconditionally,
 * while a REJECTED / INDETERMINATE verdict has no independently verified head from which to
 * derive one. Until the protocol defines a distinct non-VERIFIED acknowledgement shape, the
 * builder fails closed rather than fabricating landing authority. This function therefore
 * applies only a response to a request the builder was actually able to construct.
 */
export function applyVerificationComplete(
  operation: ConsumerOperation,
  response: VerificationCompleteResponse,
): ConsumerOperation {
  return {
    ...operation,
    status: "ACKNOWLEDGED",
    acknowledgementId: response.acknowledgement_id,
    leaseReleaseStatus: response.lease_release_status,
    rowVersion: operation.rowVersion + 1,
  };
}

// ---------------------------------------------------------------------------
// Cursor helpers re-exported for the example runner
// ---------------------------------------------------------------------------

export { advanceWatermark, resumeAfterSeq };
export type { ConsumerStore };

/** Helper: wrap a direct read for tests / runners. */
export function asDirectObservation(
  role: DirectGatewayObservation["role"],
  walletPublicKey: string,
  rawResponseBytes: Uint8Array,
  endpointFingerprint: string,
): DirectGatewayObservation {
  return { role, walletPublicKey, rawResponseBytes, endpointFingerprint };
}

export type { IndependentHeadRead };

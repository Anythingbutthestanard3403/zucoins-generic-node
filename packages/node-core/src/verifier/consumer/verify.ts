// consumer verifier kit — operation-proof verification.
//
// Composes the internal pipeline stages into one consumer call per operation:
// 1. refuse the golden test keys when liveChain is set;
// 2. authenticate the node-signed expected artifact against the node key (suite verify);
// 3. parse the raw gateway head observation (envelope stage);
// 4. verify the settled transaction for the queried wallet;
// 5. evaluate the operation economic predicate against the baseline.
//
// Pure: typed bundle in, typed verdict out. No state mutation, no retry authority (golden
// rule 4), no key custody (the key-custody rule). No function in this module signs anything.
//
// Verdict taxonomy:
// - every predicate true → VERIFIED
// - cryptographically determinate mismatch (bad artifact/suite sig, bad SplitChain step
// signature, invalid wallet role, determinate economic/binding failure) → REJECTED
// - anomaly / gap / regression / contradiction / backlink jump (chain_link_mismatch) /
// malformed or unavailable evidence / budget exhaustion → INDETERMINATE
// (authorizes NO landing, non-landing, retry/rebuild/resubmit)
import {
  evaluateExternalSendDelta,
  evaluateInternalMoveDelta,
  evaluateReceiveDelta,
  type DeltaRejectionReason,
} from "../../protocol/economic-predicates.js";
import type { SettledSplitChainTransaction } from "../../protocol/inner.js";
import { parseUuid, parseWalletPublicKey } from "../../protocol/scalars.js";
import {
  verifyMoveInternalExpectedArtifact,
  verifyNodeEvent,
  verifyReceiveExpectedArtifact,
  verifySendExternalExpectedArtifact,
  type ResolvedSuiteVerificationKey,
} from "../../protocol/suite/verify.js";
import {
  verifyImplementerCheckpoint,
  verifyImplementerEvent,
} from "../../protocol/implementer-events/verify.js";
import type { ParsedSuiteTuple } from "../../protocol/suite/parsers.js";
import {
  GENESIS_PROJECTION,
  type WalletStateProjection,
} from "../../protocol/wallet-role.js";
import { parseGatewayEnvelope } from "../gateway-envelope.js";
import {
  verifySettledTransaction,
  type TransactionVerifyVerdict,
  type VerifiedTransactionVerdict,
} from "../transaction-verify.js";
import type {
  ArtifactEnvelope,
  MoveProofBundle,
  NodeArtifactResult,
  NodeVerificationKey,
  OperationProofKind,
  OperationProofStage,
  OperationProofVerdict,
  ProofBundle,
  ReceiveProofBundle,
  SendProofBundle,
} from "./types.js";

// Golden fixture identifiers / public keys. Public in the repo as test-only
// material; live-chain mode must refuse them.
export const A8_GOLDEN_NODE_ID = "11111111-1111-4111-8111-111111111111" as const;

// Canonical padded base64url public keys for A.8 seeds 00–05 (identity/event, device, sender,
// receiver, reporting, predecessor). Live-chain mode refuses any of these as a node key.
export const A8_GOLDEN_PUBLIC_KEYS: ReadonlySet<string> = new Set([
  "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=", // seed 00 — node identity/event
  "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=", // seed 01 — device
  "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=", // seed 02 — sender
  "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=", // seed 03 — receiver
  "ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw=", // seed 04 — reporting
  "bnoc3Smwt4_ROvTFWY_v9O8qlxZuPKby5Pv8zYBQW_E=", // seed 05 — predecessor
]);

// Delta reasons that are buried-tx / anomaly / contradiction — landing-path oracle names backlink
// explicitly as INDETERMINATE. Determinate economic/binding failures stay REJECTED.
const INDETERMINATE_DELTA_REASONS: ReadonlySet<DeltaRejectionReason> = new Set([
  "chain_link_mismatch",
  "same_transaction_mismatch",
  "spawn_continuity_mismatch",
]);

function stripPad(value: string): string {
  return value.replace(/=+$/, "");
}

export function isA8GoldenKey(key: NodeVerificationKey): boolean {
  if (key.keyId === A8_GOLDEN_NODE_ID) return true;
  // Compare padded and unpadded forms so a consumer cannot smuggle a golden key past the gate
  // by stripping the trailing "=" that A.8 publishes.
  const bare = stripPad(key.publicKey);
  for (const golden of A8_GOLDEN_PUBLIC_KEYS) {
    if (stripPad(golden) === bare) return true;
  }
  return false;
}

// A.9 item 16: refuse any A.8 golden/seed key when live-chain mode is enabled.
// Returns a reason string on refusal, null when the key is admissible.
export function assertNotGoldenKey(key: NodeVerificationKey): string | null {
  if (key.liveChain !== true) return null;
  if (!isA8GoldenKey(key)) return null;
  return "A.9 item 16: golden fixture key refused under live-chain mode";
}

function nodeKey<TClass extends "node_identity" | "node_event">(
  key: NodeVerificationKey,
  keyClass: TClass,
): ResolvedSuiteVerificationKey<TClass> {
  return {
    keyId: parseUuid(key.keyId),
    keyClass,
    publicKey: parseWalletPublicKey(key.publicKey),
  };
}

function verifyErrorReason(error: unknown): string {
  const reason = (error as { reason?: unknown }).reason;
  return typeof reason === "string" ? reason : "verification_failed";
}

function rejected(kind: OperationProofKind, stage: OperationProofStage, reason: string): OperationProofVerdict {
  return { verdict: "REJECTED", kind, stage, reason };
}

function indeterminate(kind: OperationProofKind, stage: OperationProofStage, reason: string): OperationProofVerdict {
  return { verdict: "INDETERMINATE", kind, stage, reason };
}

function verified(
  kind: OperationProofKind,
  head: VerifiedTransactionVerdict,
  secondary?: VerifiedTransactionVerdict,
): OperationProofVerdict {
  return {
    verdict: "VERIFIED",
    kind,
    projection: head.projection,
    semanticFingerprint: head.semanticFingerprint,
    completedTransactionSha256: head.completedTransactionSha256,
    ...(secondary === undefined
      ? {}
      : {
          secondaryProjection: secondary.projection,
          secondaryCompletedTransactionSha256: secondary.completedTransactionSha256,
        }),
  };
}

// Map a non-VERIFIED transaction-verify outcome onto the verdict taxonomy:
// UNVERIFIED_SIGNATURE / WALLET_ROLE_INVALID → REJECTED (determinate tamper)
// MALFORMED_TRANSACTION → INDETERMINATE (cannot evaluate)
function mapTxFailure(
  kind: OperationProofKind,
  verdict: Exclude<TransactionVerifyVerdict, VerifiedTransactionVerdict>,
): OperationProofVerdict {
  switch (verdict.verdict) {
    case "UNVERIFIED_SIGNATURE":
      return rejected(kind, "transaction", `unverified_signature:step_${verdict.failedStep}`);
    case "WALLET_ROLE_INVALID":
      return rejected(kind, "transaction", `wallet_role_invalid:${verdict.detail}`);
    case "MALFORMED_TRANSACTION":
      return indeterminate(kind, "envelope", `malformed_transaction:${verdict.rejection}`);
  }
}

// Map a failed economic delta onto the taxonomy (D1): chain_link_mismatch (and other
// anomaly/contradiction reasons) → INDETERMINATE; determinate amount/binding → REJECTED.
function mapDeltaFailure(
  kind: OperationProofKind,
  reason: DeltaRejectionReason,
  detail: string,
): OperationProofVerdict {
  const message = `${reason}: ${detail}`;
  if (INDETERMINATE_DELTA_REASONS.has(reason)) {
    return indeterminate(kind, "delta", message);
  }
  return rejected(kind, "delta", message);
}

// Parses and verifies one raw gateway head observation for a queried wallet.
// Distinguishes envelope failure (INDETERMINATE) from determinate tx tamper (REJECTED).
type ObserveHeadResult =
  | { readonly ok: true; readonly head: VerifiedTransactionVerdict }
  | { readonly ok: false; readonly failure: Exclude<TransactionVerifyVerdict, VerifiedTransactionVerdict> | "envelope" };

function observeHead(rawResponseBytes: Uint8Array, walletPublicKey: string): ObserveHeadResult {
  const envelope = parseGatewayEnvelope(rawResponseBytes);
  if (envelope.classification !== "HEAD") return { ok: false, failure: "envelope" };
  const verdict = verifySettledTransaction(envelope.parsed, walletPublicKey);
  if (verdict.verdict === "VERIFIED") return { ok: true, head: verdict };
  return { ok: false, failure: verdict };
}

function isVerifiedHead(
  value: VerifiedTransactionVerdict | OperationProofVerdict,
): value is VerifiedTransactionVerdict {
  return "transaction" in value;
}

function observeOrVerdict(
  kind: OperationProofKind,
  rawResponseBytes: Uint8Array,
  walletPublicKey: string,
  label: string,
): VerifiedTransactionVerdict | OperationProofVerdict {
  const result = observeHead(rawResponseBytes, walletPublicKey);
  if (result.ok) return result.head;
  if (result.failure === "envelope") {
    return indeterminate(kind, "envelope", `${label} head observation malformed or unverified`);
  }
  return mapTxFailure(kind, result.failure);
}

// Authenticates a node-signed expected artifact against the node's published identity key.
// Dispatches on the preimage purpose prefix (receive / move / send).
export function authenticateArtifact(
  artifact: ArtifactEnvelope,
  nodeKeyMaterial: NodeVerificationKey,
): NodeArtifactResult {
  const goldenRefusal = assertNotGoldenKey(nodeKeyMaterial);
  if (goldenRefusal !== null) return { authenticated: false, reason: goldenRefusal };

  const key = nodeKey(nodeKeyMaterial, "node_identity");
  const text = artifact.preimage_text;
  try {
    if (text.startsWith("zp-receive-expected-v1\n")) {
      verifyReceiveExpectedArtifact(artifact, key);
      return { authenticated: true };
    }
    if (text.startsWith("zp-move-internal-expected-v1\n")) {
      verifyMoveInternalExpectedArtifact(artifact, key);
      return { authenticated: true };
    }
    if (text.startsWith("zp-send-external-expected-v1\n")) {
      verifySendExternalExpectedArtifact(artifact, key);
      return { authenticated: true };
    }
    return { authenticated: false, reason: "unsupported_artifact_purpose" };
  } catch (error) {
    return { authenticated: false, reason: `artifact: ${verifyErrorReason(error)}` };
  }
}

// Authenticates a node event envelope against the node's published node-event key: verify
// the node event signature/sequence only to authenticate the claim.
//
// NOTE: GET /v1/events serves `zp-implementer-event-v1`, not `zp-node-event-v1`. Prefer
// `authenticateImplementerEvent` for the tenant pull stream. This function remains for the
// operator/auditor-only node-global chain.
export function authenticateNodeEvent(
  envelope: ArtifactEnvelope,
  nodeKeyMaterial: NodeVerificationKey,
): NodeArtifactResult {
  const goldenRefusal = assertNotGoldenKey(nodeKeyMaterial);
  if (goldenRefusal !== null) return { authenticated: false, reason: goldenRefusal };

  const key = nodeKey(nodeKeyMaterial, "node_event");
  try {
    verifyNodeEvent(envelope, key);
    return { authenticated: true };
  } catch (error) {
    return { authenticated: false, reason: `node event: ${verifyErrorReason(error)}` };
  }
}

// Authenticates a tenant-facing implementer continuity envelope (GET /v1/events events[]
// and checkpoints[]) against the node's published node-event key. Dispatches on the
// preimage purpose prefix: zp-implementer-event-v1 or zp-implementer-checkpoint-v1.
// Purpose is checked before the signature (suite discipline).
export function authenticateImplementerEvent(
  envelope: ArtifactEnvelope,
  nodeKeyMaterial: NodeVerificationKey,
): NodeArtifactResult {
  const goldenRefusal = assertNotGoldenKey(nodeKeyMaterial);
  if (goldenRefusal !== null) return { authenticated: false, reason: goldenRefusal };

  const key = nodeKey(nodeKeyMaterial, "node_event");
  const text = envelope.preimage_text;
  try {
    if (text.startsWith("zp-implementer-event-v1\n")) {
      verifyImplementerEvent(envelope, key);
      return { authenticated: true };
    }
    if (text.startsWith("zp-implementer-checkpoint-v1\n")) {
      verifyImplementerCheckpoint(envelope, key);
      return { authenticated: true };
    }
    return { authenticated: false, reason: "unsupported_implementer_event_purpose" };
  } catch (error) {
    const reason =
      typeof (error as { reason?: unknown }).reason === "string"
        ? (error as { reason: string }).reason
        : "verification_failed";
    return { authenticated: false, reason: `implementer event: ${reason}` };
  }
}

// Derives a wallet's baseline projection (T0) from one raw gateway head observation. Returns
// null when the observation is malformed or does not verify for the wallet — the caller treats
// that as INDETERMINATE, never as genesis.
export function deriveBaseline(rawResponseBytes: Uint8Array, walletPublicKey: string): WalletStateProjection | null {
  const result = observeHead(rawResponseBytes, walletPublicKey);
  return result.ok ? result.head.projection : null;
}

// RECEIVE_EXTERNAL: the reserved wallet is the step-2 receiver; the inbound
// head must chain to the receiver baseline and credit exactly the artifact amount.
export function verifyReceiveProof(
  bundle: ReceiveProofBundle,
  nodeKeyMaterial: NodeVerificationKey,
): OperationProofVerdict {
  const goldenRefusal = assertNotGoldenKey(nodeKeyMaterial);
  if (goldenRefusal !== null) return rejected("receive", "artifact", goldenRefusal);

  const key = nodeKey(nodeKeyMaterial, "node_identity");
  let artifact: ParsedSuiteTuple<ReturnType<typeof verifyReceiveExpectedArtifact>["payload"]>;
  try {
    artifact = verifyReceiveExpectedArtifact(bundle.artifact, key);
  } catch (error) {
    return rejected("receive", "artifact", verifyErrorReason(error));
  }
  const expected = artifact.payload;

  const headOr = observeOrVerdict("receive", bundle.receiverResponse, expected.receiver_pubkey, "receiver");
  if (!isVerifiedHead(headOr)) return headOr;
  const head = headOr;

  const baseline = bundle.receiverBaseline ?? GENESIS_PROJECTION;
  const delta = evaluateReceiveDelta({
    baseline,
    candidateTx: head.transaction as SettledSplitChainTransaction,
    reservedWalletPublicKey: expected.receiver_pubkey,
    operation: { amountZkz: expected.amount_zkz, receiverPubkey: expected.receiver_pubkey },
  });
  if (!delta.ok) return mapDeltaFailure("receive", delta.reason, delta.detail);

  return verified("receive", head);
}

// MOVE_INTERNAL: one dual-signed transaction observed independently from the
// source (sender) and destination (receiver) wallets; both legs chain to their baselines and
// move exactly the artifact amount. An optional parent-receive link proves a spawned auto-move.
export function verifyMoveProof(
  bundle: MoveProofBundle,
  nodeKeyMaterial: NodeVerificationKey,
): OperationProofVerdict {
  const goldenRefusal = assertNotGoldenKey(nodeKeyMaterial);
  if (goldenRefusal !== null) return rejected("move", "artifact", goldenRefusal);

  const key = nodeKey(nodeKeyMaterial, "node_identity");
  let artifact: ParsedSuiteTuple<ReturnType<typeof verifyMoveInternalExpectedArtifact>["payload"]>;
  try {
    artifact = verifyMoveInternalExpectedArtifact(bundle.artifact, key);
  } catch (error) {
    return rejected("move", "artifact", verifyErrorReason(error));
  }
  const expected = artifact.payload;

  const sourceOr = observeOrVerdict("move", bundle.sourceResponse, expected.source_pubkey, "source");
  if (!isVerifiedHead(sourceOr)) return sourceOr;
  const sourceHead = sourceOr;

  const destOr = observeOrVerdict("move", bundle.destinationResponse, expected.destination_pubkey, "destination");
  if (!isVerifiedHead(destOr)) return destOr;
  const destinationHead = destOr;

  // Same dual-signed transaction observed from both wallets (dual-wallet equality).
  // Two independently-valid disagreeing heads are a contradiction → INDETERMINATE.
  if (sourceHead.transaction.step_2_signature !== destinationHead.transaction.step_2_signature) {
    return indeterminate(
      "move",
      "transaction",
      "same_transaction_mismatch: source and destination observations are not the same transaction",
    );
  }

  const sourceBaseline = bundle.sourceBaseline ?? GENESIS_PROJECTION;
  const destinationBaseline = bundle.destinationBaseline ?? GENESIS_PROJECTION;
  const delta = evaluateInternalMoveDelta({
    source: {
      baseline: sourceBaseline,
      candidateTx: sourceHead.transaction as SettledSplitChainTransaction,
      walletPublicKey: expected.source_pubkey,
    },
    destination: {
      baseline: destinationBaseline,
      candidateTx: destinationHead.transaction as SettledSplitChainTransaction,
      walletPublicKey: expected.destination_pubkey,
    },
    operation: {
      amountZkz: expected.amount_zkz,
      sourcePubkey: expected.source_pubkey,
      destinationPubkey: expected.destination_pubkey,
    },
    spawnedFromReceive: bundle.spawnedFromReceive,
  });
  if (!delta.ok) return mapDeltaFailure("move", delta.reason, delta.detail);

  return verified("move", sourceHead, destinationHead);
}

// SEND_EXTERNAL: the node-controlled source is the step-1 sender; the
// completed transaction chains to the source baseline, debits exactly the artifact amount, and
// pays the approved destination address.
export function verifySendProof(
  bundle: SendProofBundle,
  nodeKeyMaterial: NodeVerificationKey,
): OperationProofVerdict {
  const goldenRefusal = assertNotGoldenKey(nodeKeyMaterial);
  if (goldenRefusal !== null) return rejected("send", "artifact", goldenRefusal);

  const key = nodeKey(nodeKeyMaterial, "node_identity");
  let artifact: ParsedSuiteTuple<ReturnType<typeof verifySendExternalExpectedArtifact>["payload"]>;
  try {
    artifact = verifySendExternalExpectedArtifact(bundle.artifact, key);
  } catch (error) {
    return rejected("send", "artifact", verifyErrorReason(error));
  }
  const expected = artifact.payload;

  const headOr = observeOrVerdict("send", bundle.sourceResponse, expected.source_pubkey, "source");
  if (!isVerifiedHead(headOr)) return headOr;
  const head = headOr;

  const baseline = bundle.sourceBaseline ?? GENESIS_PROJECTION;
  const delta = evaluateExternalSendDelta({
    baseline,
    candidateTx: head.transaction as SettledSplitChainTransaction,
    sourceWalletPublicKey: expected.source_pubkey,
    operation: {
      amountZkz: expected.amount_zkz,
      sourcePubkey: expected.source_pubkey,
      destinationAddress: expected.destination_address,
    },
  });
  if (!delta.ok) return mapDeltaFailure("send", delta.reason, delta.detail);

  return verified("send", head);
}

// Verifies one parsed proof bundle against the node key, dispatching on bundle.kind.
export function verifyOperationProof(
  bundle: ProofBundle,
  nodeKeyMaterial: NodeVerificationKey,
): OperationProofVerdict {
  switch (bundle.kind) {
    case "receive":
      return verifyReceiveProof(bundle, nodeKeyMaterial);
    case "move":
      return verifyMoveProof(bundle, nodeKeyMaterial);
    case "send":
      return verifySendProof(bundle, nodeKeyMaterial);
  }
}

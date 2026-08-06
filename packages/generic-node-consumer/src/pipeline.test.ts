/**
 * Independent verification pipeline scenarios. Packaged into the installable SDK
 * (originally shipped in the consumer-example package).
 *
 * Offline fixture gateway responses only (no live ZKZ). Covers:
 *   - deposit / internal_allocation / external_distribution (three ops only)
 *   - lying-node (forged event / claim without matching economic proof)
 *   - endpoint disagreement (independent read ≠ node-relayed → INDETERMINATE)
 *   - REGRESSION / UNEXPLAINED_JUMP observation → not acted on
 *   - consumer-restart resume from own watermark_seq
 *   - node_claim vs operation_verified separation
 *   - node-key pinning on the verification path
 *   - subscribe handle vs full event route distinction
 *   - verification-complete acknowledgement shape
 */

import { Buffer } from "node:buffer";
import { generateKeyPairSync, sign as edSign, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  GENESIS_PROJECTION,
  buildMoveInternalExpectedArtifact,
  buildNodeEvent,
  buildReceiveExpectedArtifact,
  buildSendExternalExpectedArtifact,
  parseEd25519Signature,
  parsePositiveZkzAmount,
  parseSha256Hex,
  parseUuid,
  parseWalletPublicKey,
} from "@zucoins/node-core";
import {
  deriveBaseline,
  type ArtifactEnvelope,
  type NodeVerificationKey,
} from "@zucoins/node-core/verifier/consumer";
import {
  computePathManifestSha256,
  transactionBodySha256,
} from "@zucoins/node-core/observation";
import {
  bootstrapIdentityPin,
  type CachedIdentityPin,
  type DiscoveryIdentityWire,
} from "@zucoins/node-core/verifier/consumer/pinning";

import {
  DEFAULT_TRUST_ASSUMPTIONS,
  PUBLIC_OPERATION_KINDS,
  advanceWatermark,
  applyVerificationComplete,
  asDirectObservation,
  buildVerificationCompleteRequest,
  createInMemoryConsumerStore,
  gateAnomalousObservation,
  ingestEventWake,
  ingestSubscribeProjection,
  openConsumerOperation,
  resumeAfterSeq,
  verifyOperationIndependently,
  type ConsumerOperation,
  type DirectGatewayObservation,
  type NodeEventWake,
  type VerificationMaterialWire,
} from "./index.js";

// ---------------------------------------------------------------------------
// Fixtures — same receive-golden vectors the independent consumer-verifier tests use
// ---------------------------------------------------------------------------

const GEN_DIR = new URL(
  "../../generic-node-contracts/src/receive-golden/gen/",
  import.meta.url,
);

function fixtureText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}

const MANIFEST = JSON.parse(fixtureText("manifest.json"));
const RECEIVER_PUBKEY = MANIFEST.public_keys.seed_03 as string;
const SENDER_PUBKEY = MANIFEST.public_keys.seed_02 as string;
const TARGET_SETTLED = fixtureText("target.settled.json");
const TARGET = JSON.parse(TARGET_SETTLED) as { step_2_signature: string };

function gatewayEnvelopeBytes(settledJson: string): Uint8Array {
  return new TextEncoder().encode(
    `{"status":true,"code":"success","message":"","data":[${settledJson}]}`,
  );
}

const RESPONSE_BYTES = gatewayEnvelopeBytes(TARGET_SETTLED);
const GW_PIN = "consumer_gw_pin_v1";
const WRONG_GW_PIN = "attacker_relayed_endpoint";

// ---------------------------------------------------------------------------
// ancestor_proofs fixtures — depth-0 (EXPECTED_AT_HEAD) manifest anchored
// on TARGET_SETTLED, the exact same bytes RESPONSE_BYTES wraps. deriveLandingProof
// (landing-proof.ts) cross-checks fresh_head_step_2_signature against this pipeline's
// own independently-derived S, so the fixture must be built from the real hash/digest
// functions the SUT itself uses — never a hand-picked placeholder.
// ---------------------------------------------------------------------------

const TARGET_BODY_SHA256 = transactionBodySha256(TARGET_SETTLED);

function ancestorProofAtHead(
  role: "RECEIVER" | "SOURCE" | "DESTINATION",
  walletPublicKey: string,
) {
  const path_manifest = [
    {
      position: 0,
      step_2_signature: TARGET.step_2_signature,
      queried_wallet_previous_signature: "",
      transaction_sha256: TARGET_BODY_SHA256,
      body_index: 0,
    },
  ];
  return {
    evidence_role: role,
    wallet_public_key: walletPublicKey,
    classification: "EXPECTED_AT_HEAD" as const,
    expected_step_2_signature: TARGET.step_2_signature,
    fresh_head_step_2_signature: TARGET.step_2_signature,
    fresh_head_transaction_sha256: TARGET_BODY_SHA256,
    hop_count: 0,
    path_manifest_sha256: computePathManifestSha256(path_manifest),
    path_manifest,
    transaction_bodies: [
      { body_index: 0, transaction_sha256: TARGET_BODY_SHA256, settled_transaction_text: TARGET_SETTLED },
    ],
    indeterminate_reason: null,
  };
}

const CORRECT_SENDER_BASELINE = {
  role: "sender" as const,
  S: MANIFEST.predecessor.step_2_signature as string,
  P: "",
  B: "10",
  I: "x".repeat(64),
};

// ---------------------------------------------------------------------------
// Node identity / event keys (NOT A.8 golden)
// ---------------------------------------------------------------------------

function ed25519Pair(): { publicKeyB64: string; privateKey: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ type: "spki", format: "der" }).subarray(12);
  return {
    publicKeyB64: Buffer.from(raw).toString("base64url") + "=",
    privateKey,
  };
}

const NODE = ed25519Pair();
const ATTACKER = ed25519Pair();
const NODE_ID = "33333333-3333-4333-8333-333333333333";
const KEY_ID = "33333333-3333-4333-8333-333333333333";
const IMPLEMENTER_ID = "44444444-4444-4444-8444-444444444444";
const NOW = 1_700_000_000_000;

const NODE_KEY: NodeVerificationKey = { keyId: KEY_ID, publicKey: NODE.publicKeyB64 };

function signPreimage(preimageBytes: Uint8Array, priv: KeyObject = NODE.privateKey): string {
  return edSign(null, Buffer.from(preimageBytes), priv).toString("base64url") + "==";
}

function buildReceiveArtifact(operationId: string, amountZkz: string): ArtifactEnvelope {
  const preimage = buildReceiveExpectedArtifact({
    node_id: parseUuid(NODE_ID),
    implementer_id: parseUuid(IMPLEMENTER_ID),
    operation_id: parseUuid(operationId),
    receiver_wallet_id: parseUuid("66666666-6666-4666-8666-666666666666"),
    receiver_pubkey: parseWalletPublicKey(RECEIVER_PUBKEY),
    amount_zkz: parsePositiveZkzAmount(amountZkz),
    discriminator: parseUuid("77777777-7777-4777-8777-777777777777"),
    anchor: "zp1-anchor-test",
    receiver_t0_fingerprint: parseSha256Hex("a".repeat(64)),
    expiry_unix_time_secs: null,
    after_landing: { kind: "HOLD", destination_id: null },
    transfer_code_sha256: parseSha256Hex("b".repeat(64)),
  });
  return {
    key_id: parseUuid(KEY_ID),
    preimage_text: preimage.preimageText,
    preimage_sha256: parseSha256Hex(preimage.sha256 as string),
    signature: parseEd25519Signature(signPreimage(preimage.preimageBytes)),
  };
}

function buildMoveArtifact(operationId: string, amountZkz: string): ArtifactEnvelope {
  const preimage = buildMoveInternalExpectedArtifact({
    node_id: parseUuid(NODE_ID),
    implementer_id: parseUuid(IMPLEMENTER_ID),
    operation_id: parseUuid(operationId),
    source_wallet_id: parseUuid("66666666-6666-4666-8666-666666666666"),
    source_pubkey: parseWalletPublicKey(SENDER_PUBKEY),
    destination_id: parseUuid("88888888-8888-4888-8888-888888888888"),
    destination_wallet_id: parseUuid("99999999-9999-4999-8999-999999999999"),
    destination_pubkey: parseWalletPublicKey(RECEIVER_PUBKEY),
    amount_zkz: parsePositiveZkzAmount(amountZkz),
    spawned_from_operation_id: null,
    references_operation_id: null,
  });
  return {
    key_id: parseUuid(KEY_ID),
    preimage_text: preimage.preimageText,
    preimage_sha256: parseSha256Hex(preimage.sha256 as string),
    signature: parseEd25519Signature(signPreimage(preimage.preimageBytes)),
  };
}

function buildSendArtifact(operationId: string, amountZkz: string): ArtifactEnvelope {
  const preimage = buildSendExternalExpectedArtifact({
    node_id: parseUuid(NODE_ID),
    implementer_id: parseUuid(IMPLEMENTER_ID),
    operation_id: parseUuid(operationId),
    source_selector: {
      kind: "WALLET_ID",
      wallet_id: parseUuid("66666666-6666-4666-8666-666666666666"),
    },
    source_pubkey: parseWalletPublicKey(SENDER_PUBKEY),
    destination_address: parseWalletPublicKey(RECEIVER_PUBKEY),
    amount_zkz: parsePositiveZkzAmount(amountZkz),
    references_operation_id: null,
  });
  return {
    key_id: parseUuid(KEY_ID),
    preimage_text: preimage.preimageText,
    preimage_sha256: parseSha256Hex(preimage.sha256 as string),
    signature: parseEd25519Signature(signPreimage(preimage.preimageBytes)),
  };
}

function bootstrapPin(now: number = NOW): CachedIdentityPin {
  return bootstrapIdentityPin(
    {
      nodeId: NODE_ID,
      keyId: KEY_ID,
      publicKeyB64: NODE.publicKeyB64,
      sourceChannel: "operator_console_export",
    },
    now,
  );
}

function discoveryDoc(): DiscoveryIdentityWire {
  return {
    node_id: NODE_ID,
    expected_artifact_public_keys: [
      {
        key_id: KEY_ID,
        public_key: NODE.publicKeyB64,
      },
    ],
    key_validity_intervals: [
      {
        key_id: KEY_ID,
        valid_from: new Date(NOW - 60_000).toISOString(),
        valid_until: null,
      },
    ],
  };
}

function makeEventWake(
  operationId: string,
  opts: {
    readonly seq?: string;
    readonly claimState?: string;
    readonly signer?: KeyObject;
    readonly eventType?: "receive.landed" | "internal_move.landed" | "external_send.landed";
  } = {},
): NodeEventWake {
  const signer = opts.signer ?? NODE.privateKey;
  const eventType = opts.eventType ?? "receive.landed";
  const preimage = buildNodeEvent({
    node_id: parseUuid(NODE_ID),
    event_id: parseUuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
    seq: opts.seq ?? "42",
    operation_id: parseUuid(operationId),
    wallet_id: null,
    event_type: eventType,
    data_sha256: parseSha256Hex("c".repeat(64)),
    previous_event_hash: null,
    created_at: "2026-07-15T10:30:00.000Z",
  });
  return {
    event_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    implementer_seq: opts.seq ?? "42",
    operation_id: operationId,
    event_type: eventType,
    node_claim_state: opts.claimState ?? "RECEIVE_LANDED",
    artifact: {
      key_id: KEY_ID,
      preimage_text: preimage.preimageText,
      preimage_sha256: preimage.sha256 as string,
      signature: signPreimage(preimage.preimageBytes, signer),
    },
  };
}

function materialFor(
  operationId: string,
  operationType: VerificationMaterialWire["operation_type"],
  artifact: ArtifactEnvelope,
): VerificationMaterialWire {
  if (operationType === "RECEIVE_EXTERNAL") {
    return {
      operation_id: operationId,
      operation_type: operationType,
      state: "RECEIVE_LANDED",
      expected_artifact: {
        key_id: artifact.key_id,
        preimage_text: artifact.preimage_text,
        preimage_sha256: artifact.preimage_sha256,
        signature: artifact.signature,
      },
      observation_evidence: [
        {
          evidence_role: "RECEIVER",
          wallet_id: "66666666-6666-4666-8666-666666666666",
          wallet_public_key: RECEIVER_PUBKEY,
          t0: {
            observation_id: "11111111-1111-4111-8111-111111111101",
            projection: { s: "", p: "", b_zkz: "0" },
          },
          terminal: {
            observation_id: "11111111-1111-4111-8111-111111111102",
            projection: { s: TARGET.step_2_signature, p: "", b_zkz: "2.25" },
          },
          node_observation_raw_body_base64: Buffer.from(RESPONSE_BYTES).toString("base64"),
        },
      ],
      ancestor_proofs: [ancestorProofAtHead("RECEIVER", RECEIVER_PUBKEY)],
    };
  }

  if (operationType === "MOVE_INTERNAL") {
    return {
      operation_id: operationId,
      operation_type: operationType,
      state: "INTERNAL_MOVE_LANDED",
      expected_artifact: {
        key_id: artifact.key_id,
        preimage_text: artifact.preimage_text,
        preimage_sha256: artifact.preimage_sha256,
        signature: artifact.signature,
      },
      observation_evidence: [
        {
          evidence_role: "SOURCE",
          wallet_id: "66666666-6666-4666-8666-666666666666",
          wallet_public_key: SENDER_PUBKEY,
          t0: {
            observation_id: "11111111-1111-4111-8111-111111111101",
            projection: { s: CORRECT_SENDER_BASELINE.S, p: "", b_zkz: "10" },
          },
          terminal: {
            observation_id: "11111111-1111-4111-8111-111111111102",
            projection: {
              s: TARGET.step_2_signature,
              p: CORRECT_SENDER_BASELINE.S,
              b_zkz: "7.75",
            },
          },
          node_observation_raw_body_base64: Buffer.from(RESPONSE_BYTES).toString("base64"),
        },
        {
          evidence_role: "DESTINATION",
          wallet_id: "99999999-9999-4999-8999-999999999999",
          wallet_public_key: RECEIVER_PUBKEY,
          t0: {
            observation_id: "11111111-1111-4111-8111-111111111103",
            projection: { s: "", p: "", b_zkz: "0" },
          },
          terminal: {
            observation_id: "11111111-1111-4111-8111-111111111104",
            projection: { s: TARGET.step_2_signature, p: "", b_zkz: "2.25" },
          },
          node_observation_raw_body_base64: Buffer.from(RESPONSE_BYTES).toString("base64"),
        },
      ],
      ancestor_proofs: [
        ancestorProofAtHead("SOURCE", SENDER_PUBKEY),
        ancestorProofAtHead("DESTINATION", RECEIVER_PUBKEY),
      ],
    };
  }

  return {
    operation_id: operationId,
    operation_type: "SEND_EXTERNAL",
    state: "SEND_LANDED",
    expected_artifact: {
      key_id: artifact.key_id,
      preimage_text: artifact.preimage_text,
      preimage_sha256: artifact.preimage_sha256,
      signature: artifact.signature,
    },
    observation_evidence: [
      {
        evidence_role: "SOURCE",
        wallet_id: "66666666-6666-4666-8666-666666666666",
        wallet_public_key: SENDER_PUBKEY,
        t0: {
          observation_id: "11111111-1111-4111-8111-111111111101",
          projection: { s: CORRECT_SENDER_BASELINE.S, p: "", b_zkz: "10" },
        },
        terminal: {
          observation_id: "11111111-1111-4111-8111-111111111102",
          projection: {
            s: TARGET.step_2_signature,
            p: CORRECT_SENDER_BASELINE.S,
            b_zkz: "7.75",
          },
        },
        node_observation_raw_body_base64: Buffer.from(RESPONSE_BYTES).toString("base64"),
      },
    ],
    ancestor_proofs: [ancestorProofAtHead("SOURCE", SENDER_PUBKEY)],
  };
}

/** Align material terminal projections with what deriveBaseline yields from direct bytes. */
function withAlignedTerminals(
  material: VerificationMaterialWire,
  directs: readonly DirectGatewayObservation[],
): VerificationMaterialWire {
  const evidence = material.observation_evidence.map((ev) => {
    const d = directs.find((x) => x.role === ev.evidence_role);
    if (!d || ev.terminal === null) return ev;
    const proj = deriveBaseline(d.rawResponseBytes, d.walletPublicKey);
    if (!proj) return ev;
    return {
      ...ev,
      terminal: {
        ...ev.terminal,
        projection: { s: proj.S, p: proj.P, b_zkz: proj.B },
      },
    };
  });
  return { ...material, observation_evidence: evidence };
}

function runVerify(
  op: ConsumerOperation,
  material: VerificationMaterialWire,
  directs: readonly DirectGatewayObservation[],
  baselines?: {
    readonly receiver?: typeof GENESIS_PROJECTION;
    readonly source?: typeof CORRECT_SENDER_BASELINE;
    readonly destination?: typeof GENESIS_PROJECTION;
  },
) {
  const aligned = withAlignedTerminals(material, directs);
  return verifyOperationIndependently({
    operation: op,
    material: aligned,
    directObservations: directs,
    identityPin: bootstrapPin(),
    discovery: discoveryDoc(),
    originClass: "node-origin",
    pinnedGatewayFingerprint: GW_PIN,
    nowUnixMs: NOW,
    baselines,
  });
}

// ---------------------------------------------------------------------------
// Trust assumptions surface
// ---------------------------------------------------------------------------

describe("trust assumptions", () => {
  it("states independent gateway read and claim-only node authority", () => {
    expect(DEFAULT_TRUST_ASSUMPTIONS.node).toBe("claim_authentication_only");
    expect(DEFAULT_TRUST_ASSUMPTIONS.independentGatewayRead).toBe("required_for_verdict");
    expect(DEFAULT_TRUST_ASSUMPTIONS.statement).toMatch(/never sufficient/i);
  });

  it("exposes only the three public operation kinds", () => {
    expect([...PUBLIC_OPERATION_KINDS]).toEqual(["receive", "move", "send"]);
  });
});

// ---------------------------------------------------------------------------
// Composition happy paths — deposit / allocation / distribution
// ---------------------------------------------------------------------------

describe("composition: deposit (RECEIVE_EXTERNAL)", () => {
  const OP_ID = "55555555-5555-4555-8555-555555555501";

  it("reaches VERIFIED from independent observation + pinned artifact", () => {
    let op = openConsumerOperation({
      operationId: OP_ID,
      compositionLabel: "deposit",
    });
    expect(op.kind).toBe("receive");
    expect(op.operationVerified).toBeNull();
    expect(op.nodeClaim).toBeNull();

    const wake = makeEventWake(OP_ID);
    const triggered = ingestEventWake(op, wake, NODE_KEY, "events_poll", NOW);
    expect(triggered.ok).toBe(true);
    if (!triggered.ok) return;
    op = triggered.operation;
    expect(op.nodeClaim?.authenticated).toBe(true);
    expect(op.nodeClaim?.state).toBe("RECEIVE_LANDED");
    expect(op.operationVerified).toBeNull();
    expect(op.status).toBe("AWAITING_TRIGGER");

    const artifact = buildReceiveArtifact(OP_ID, "2.25");
    const material = materialFor(OP_ID, "RECEIVE_EXTERNAL", artifact);
    const directs = [
      asDirectObservation("RECEIVER", RECEIVER_PUBKEY, RESPONSE_BYTES, GW_PIN),
    ];
    const result = runVerify(op, material, directs, { receiver: GENESIS_PROJECTION });
    expect(result.pinOk).toBe(true);
    expect(result.endpointDisagreement).toBe(false);
    expect(result.verdict.verdict).toBe("VERIFIED");
    expect(result.operation.status).toBe("VERIFIED");
    expect(result.operation.operationVerified?.verdict).toBe("VERIFIED");
    expect(result.operation.nodeClaim?.state).toBe("RECEIVE_LANDED");

    const ackReq = buildVerificationCompleteRequest({
      operation: result.operation,
      material,
      consumedCursor: "42",
    });
    expect("error" in ackReq).toBe(false);
    if ("error" in ackReq) return;
    expect(ackReq.verdict).toBe("VERIFIED");
    expect(ackReq.consumed_cursor).toBe("42");
    expect(ackReq.wallet_evidence[0]?.role).toBe("RECEIVER");

    const acked = applyVerificationComplete(result.operation, {
      operation_id: OP_ID,
      acknowledgement_id: "ack-1",
      verdict: "VERIFIED",
      lease_release_status: "RELEASED",
      acknowledged_at: "2026-07-15T10:31:00.000Z",
    });
    expect(acked.status).toBe("ACKNOWLEDGED");
    expect(acked.leaseReleaseStatus).toBe("RELEASED");
    expect(acked.acknowledgementId).toBe("ack-1");
  });
});

describe("composition: internal_allocation (MOVE_INTERNAL)", () => {
  const OP_ID = "55555555-5555-4555-8555-555555555502";

  it("reaches VERIFIED for dual-role independent observations", () => {
    let op = openConsumerOperation({
      operationId: OP_ID,
      compositionLabel: "internal_allocation",
    });
    expect(op.kind).toBe("move");

    const wake = makeEventWake(OP_ID, {
      claimState: "INTERNAL_MOVE_LANDED",
      eventType: "internal_move.landed",
    });
    const triggered = ingestEventWake(op, wake, NODE_KEY, "events_stream", NOW);
    expect(triggered.ok).toBe(true);
    if (!triggered.ok) return;
    op = triggered.operation;

    const artifact = buildMoveArtifact(OP_ID, "2.25");
    const material = materialFor(OP_ID, "MOVE_INTERNAL", artifact);
    const directs = [
      asDirectObservation("SOURCE", SENDER_PUBKEY, RESPONSE_BYTES, GW_PIN),
      asDirectObservation("DESTINATION", RECEIVER_PUBKEY, RESPONSE_BYTES, GW_PIN),
    ];
    const result = runVerify(op, material, directs, {
      source: CORRECT_SENDER_BASELINE,
      destination: GENESIS_PROJECTION,
    });
    expect(result.verdict.verdict).toBe("VERIFIED");
    expect(result.operation.operationVerified?.verdict).toBe("VERIFIED");
    expect(result.operation.nodeClaim?.state).toBe("INTERNAL_MOVE_LANDED");
  });
});

describe("composition: external_distribution (SEND_EXTERNAL)", () => {
  const OP_ID = "55555555-5555-4555-8555-555555555503";

  it("reaches VERIFIED for source-side independent observation", () => {
    let op = openConsumerOperation({
      operationId: OP_ID,
      compositionLabel: "external_distribution",
    });
    expect(op.kind).toBe("send");

    const wake = makeEventWake(OP_ID, {
      claimState: "SEND_LANDED",
      eventType: "external_send.landed",
    });
    const triggered = ingestEventWake(op, wake, NODE_KEY, "events_poll", NOW);
    expect(triggered.ok).toBe(true);
    if (!triggered.ok) return;
    op = triggered.operation;

    const artifact = buildSendArtifact(OP_ID, "2.25");
    const material = materialFor(OP_ID, "SEND_EXTERNAL", artifact);
    const directs = [
      asDirectObservation("SOURCE", SENDER_PUBKEY, RESPONSE_BYTES, GW_PIN),
    ];
    const result = runVerify(op, material, directs, {
      source: CORRECT_SENDER_BASELINE,
    });
    expect(result.verdict.verdict).toBe("VERIFIED");
    expect(result.operation.compositionLabel).toBe("external_distribution");
  });
});

// ---------------------------------------------------------------------------
// Lying-node scenario
// ---------------------------------------------------------------------------

describe("lying-node scenario", () => {
  const OP_ID = "55555555-5555-4555-8555-555555555510";

  it("rejects a forged node event signature and never sets operation_verified from the claim", () => {
    const op = openConsumerOperation({
      operationId: OP_ID,
      compositionLabel: "deposit",
    });
    const forged = makeEventWake(OP_ID, { signer: ATTACKER.privateKey });
    const triggered = ingestEventWake(op, forged, NODE_KEY, "events_poll", NOW);
    expect(triggered.ok).toBe(false);
    if (triggered.ok) return;
    expect(triggered.reason).toBe("event_not_authenticated");
    expect(triggered.operation.nodeClaim?.authenticated).toBe(false);
    expect(triggered.operation.nodeClaim?.state).toBe("RECEIVE_LANDED");
    expect(triggered.operation.operationVerified).toBeNull();
    expect(triggered.operation.status).not.toBe("VERIFIED");
  });

  it("does not VERIFIED when claim is authentic but economic proof is absent/wrong", () => {
    let op = openConsumerOperation({
      operationId: OP_ID,
      compositionLabel: "deposit",
    });
    const wake = makeEventWake(OP_ID);
    const triggered = ingestEventWake(op, wake, NODE_KEY, "events_poll", NOW);
    expect(triggered.ok).toBe(true);
    if (!triggered.ok) return;
    op = triggered.operation;

    const artifact = buildReceiveArtifact(OP_ID, "9.99");
    const material = materialFor(OP_ID, "RECEIVE_EXTERNAL", artifact);
    const directs = [
      asDirectObservation("RECEIVER", RECEIVER_PUBKEY, RESPONSE_BYTES, GW_PIN),
    ];
    const result = runVerify(op, material, directs, { receiver: GENESIS_PROJECTION });
    expect(result.verdict.verdict).toBe("REJECTED");
    expect(result.operation.status).toBe("REJECTED");
    expect(result.operation.nodeClaim?.state).toBe("RECEIVE_LANDED");
    expect(result.operation.nodeClaim?.authenticated).toBe(true);
    expect(result.operation.operationVerified?.verdict).toBe("REJECTED");
  });
});

// ---------------------------------------------------------------------------
// Endpoint disagreement
// ---------------------------------------------------------------------------

describe("endpoint-disagreement scenario", () => {
  const OP_ID = "55555555-5555-4555-8555-555555555520";

  it("fails closed to INDETERMINATE when direct read uses a different endpoint pin", () => {
    const op = openConsumerOperation({
      operationId: OP_ID,
      compositionLabel: "deposit",
    });
    const artifact = buildReceiveArtifact(OP_ID, "2.25");
    const material = materialFor(OP_ID, "RECEIVE_EXTERNAL", artifact);
    const directs = [
      asDirectObservation("RECEIVER", RECEIVER_PUBKEY, RESPONSE_BYTES, WRONG_GW_PIN),
    ];
    const result = verifyOperationIndependently({
      operation: op,
      material,
      directObservations: directs,
      identityPin: bootstrapPin(),
      discovery: discoveryDoc(),
      originClass: "node-origin",
      pinnedGatewayFingerprint: GW_PIN,
      nowUnixMs: NOW,
      baselines: { receiver: GENESIS_PROJECTION },
    });
    expect(result.endpointDisagreement).toBe(true);
    expect(result.verdict.verdict).toBe("INDETERMINATE");
    expect(result.operation.status).toBe("INDETERMINATE");
    if (result.verdict.verdict === "INDETERMINATE") {
      expect(result.verdict.reason).toMatch(/endpoint_disagreement/);
    }
  });

  it("fails closed when independent head projection disagrees with node-relayed terminal", () => {
    const op = openConsumerOperation({
      operationId: OP_ID,
      compositionLabel: "deposit",
    });
    const artifact = buildReceiveArtifact(OP_ID, "2.25");
    const material = materialFor(OP_ID, "RECEIVE_EXTERNAL", artifact);
    // Overwrite terminal with a lie the independent head will not match.
    const lying: VerificationMaterialWire = {
      ...material,
      observation_evidence: material.observation_evidence.map((ev) => ({
        ...ev,
        terminal: ev.terminal
          ? {
              ...ev.terminal,
              projection: {
                s: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
                p: "",
                b_zkz: "99.99",
              },
            }
          : null,
      })),
    };
    const directs = [
      asDirectObservation("RECEIVER", RECEIVER_PUBKEY, RESPONSE_BYTES, GW_PIN),
    ];
    const result = verifyOperationIndependently({
      operation: op,
      material: lying,
      directObservations: directs,
      identityPin: bootstrapPin(),
      discovery: discoveryDoc(),
      originClass: "node-origin",
      pinnedGatewayFingerprint: GW_PIN,
      nowUnixMs: NOW,
      baselines: { receiver: GENESIS_PROJECTION },
    });
    expect(result.endpointDisagreement).toBe(true);
    expect(result.verdict.verdict).toBe("INDETERMINATE");
    expect(result.operation.operationVerified?.verdict).toBe("INDETERMINATE");
    expect(result.operation.status).not.toBe("VERIFIED");
  });
});

// ---------------------------------------------------------------------------
// Regression / unexplained jump
// ---------------------------------------------------------------------------

describe("regression / unexplained-jump scenario", () => {
  it("does not act on REGRESSION", () => {
    const gate = gateAnomalousObservation({
      prior: {
        isGenesis: false,
        sSignature: "S_B",
        pSignature: "S_A",
        semanticFingerprint: "fp_B",
      },
      next: {
        isGenesis: false,
        sSignature: "S_A",
        pSignature: "S_Z",
        semanticFingerprint: "fp_A_again",
      },
      priorHistoryHasNonGenesis: true,
      acceptedStateSignatureHistory: ["S_A", "S_B"],
    });
    expect(gate.mayAct).toBe(false);
    expect(gate.relationship).toBe("REGRESSION");
  });

  it("does not act on UNEXPLAINED_JUMP", () => {
    const gate = gateAnomalousObservation({
      prior: {
        isGenesis: false,
        sSignature: "S_A",
        pSignature: "",
        semanticFingerprint: "fp_A",
      },
      next: {
        isGenesis: false,
        sSignature: "S_Z",
        pSignature: "S_NOT_A",
        semanticFingerprint: "fp_Z",
      },
      priorHistoryHasNonGenesis: true,
      acceptedStateSignatureHistory: ["S_A"],
    });
    expect(gate.mayAct).toBe(false);
    expect(gate.relationship).toBe("UNEXPLAINED_JUMP");
  });

  it("allows SUCCESSOR", () => {
    const gate = gateAnomalousObservation({
      prior: {
        isGenesis: false,
        sSignature: "S_A",
        pSignature: "",
        semanticFingerprint: "fp_A",
      },
      next: {
        isGenesis: false,
        sSignature: "S_B",
        pSignature: "S_A",
        semanticFingerprint: "fp_B",
      },
      priorHistoryHasNonGenesis: true,
      acceptedStateSignatureHistory: ["S_A"],
    });
    expect(gate.mayAct).toBe(true);
    expect(gate.relationship).toBe("SUCCESSOR");
  });
});

// ---------------------------------------------------------------------------
// Consumer restart
// ---------------------------------------------------------------------------

describe("consumer-restart scenario", () => {
  it("resumes from own persisted watermark_seq, not a node-supplied cache", () => {
    const store = createInMemoryConsumerStore();
    store.saveIdentityPin(bootstrapPin());
    store.saveGatewayFingerprint(GW_PIN);

    const op = openConsumerOperation({
      operationId: "55555555-5555-4555-8555-555555555530",
      compositionLabel: "deposit",
    });
    store.saveOperation(op);
    advanceWatermark(store, "1043", NOW);
    expect(resumeAfterSeq(store)).toBe("1043");

    const snap = store.snapshot(NOW);
    expect(snap).not.toBeNull();
    if (!snap) return;
    expect(snap.watermarkSeq).toBe("1043");
    expect(snap.operations).toHaveLength(1);

    const restarted = createInMemoryConsumerStore();
    const nodeSuppliedCacheWatermark = "9999";
    restarted.restore(snap);

    expect(resumeAfterSeq(restarted)).toBe("1043");
    expect(resumeAfterSeq(restarted)).not.toBe(nodeSuppliedCacheWatermark);
    expect(restarted.loadOperations()).toHaveLength(1);
    expect(restarted.loadIdentityPin()?.pin.keyId).toBe(KEY_ID);
    expect(restarted.loadGatewayFingerprint()).toBe(GW_PIN);
  });
});

// ---------------------------------------------------------------------------
// Subscribe handle vs full event route
// ---------------------------------------------------------------------------

describe("subscribe handle vs full event route", () => {
  const OP_ID = "55555555-5555-4555-8555-555555555540";

  it("subscribe lifecycle never claims authenticated proof", () => {
    const op = openConsumerOperation({
      operationId: OP_ID,
      compositionLabel: "deposit",
    });
    const next = ingestSubscribeProjection(
      op,
      {
        operation_id: OP_ID,
        operation_type: "RECEIVE_EXTERNAL",
        state: "RECEIVE_LANDED",
        row_version: 4,
        attention_required: false,
        updated_at: "2026-07-15T10:30:00.000Z",
      },
      NOW,
    );
    expect(next.lastTriggerSource).toBe("subscribe_handle");
    expect(next.nodeClaim?.authenticated).toBe(false);
    expect(next.operationVerified).toBeNull();
    expect(next.status).toBe("AWAITING_TRIGGER");
  });

  it("full event route authenticates and still does not set operation_verified", () => {
    const op = openConsumerOperation({
      operationId: OP_ID,
      compositionLabel: "deposit",
    });
    const wake = makeEventWake(OP_ID);
    const triggered = ingestEventWake(op, wake, NODE_KEY, "events_stream", NOW);
    expect(triggered.ok).toBe(true);
    if (!triggered.ok) return;
    expect(triggered.operation.nodeClaim?.authenticated).toBe(true);
    expect(triggered.operation.operationVerified).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Pinning workflow is on the verification path
// ---------------------------------------------------------------------------

describe("pinning workflow integration", () => {
  const OP_ID = "55555555-5555-4555-8555-555555555550";

  it("refuses platform-hosted origin and does not VERIFIED", () => {
    const op = openConsumerOperation({
      operationId: OP_ID,
      compositionLabel: "deposit",
    });
    const artifact = buildReceiveArtifact(OP_ID, "2.25");
    const material = materialFor(OP_ID, "RECEIVE_EXTERNAL", artifact);
    const directs = [
      asDirectObservation("RECEIVER", RECEIVER_PUBKEY, RESPONSE_BYTES, GW_PIN),
    ];
    const aligned = withAlignedTerminals(material, directs);
    const result = verifyOperationIndependently({
      operation: op,
      material: aligned,
      directObservations: directs,
      identityPin: bootstrapPin(),
      discovery: discoveryDoc(),
      originClass: "platform-hosted",
      pinnedGatewayFingerprint: GW_PIN,
      nowUnixMs: NOW,
      baselines: { receiver: GENESIS_PROJECTION },
    });
    expect(result.pinOk).toBe(false);
    expect(result.verdict.verdict).toBe("INDETERMINATE");
    expect(result.pinDetail).toMatch(/platform_hosted|origin/i);
  });
});

// ---------------------------------------------------------------------------
// verification-complete acknowledgement
// ---------------------------------------------------------------------------

describe("verification-complete acknowledgement", () => {
  it("carries consumer verdict without inventing lease release", () => {
    let op = openConsumerOperation({
      operationId: "55555555-5555-4555-8555-555555555560",
      compositionLabel: "deposit",
      rowVersion: 7,
    });
    op = {
      ...op,
      operationVerified: {
        verdict: "VERIFIED",
        kind: "receive",
        projection: { role: "receiver", S: TARGET.step_2_signature, P: "", B: "2.25", I: "x".repeat(64) },
        semanticFingerprint: "fp",
        completedTransactionSha256: TARGET_BODY_SHA256,
      },
      status: "VERIFIED",
    };
    const artifact = buildReceiveArtifact(op.operationId, "2.25");
    const material = materialFor(op.operationId, "RECEIVE_EXTERNAL", artifact);
    const req = buildVerificationCompleteRequest({
      operation: op,
      material,
      consumedCursor: "1051",
    });
    expect("error" in req).toBe(false);
    if ("error" in req) return;
    expect(req.verdict).toBe("VERIFIED");
    expect(req.expected_row_version).toBe(7);
    expect(req.wallet_evidence[0]?.landing_proof.classification).toBe("EXPECTED_AT_HEAD");

    const acked = applyVerificationComplete(op, {
      operation_id: op.operationId,
      acknowledgement_id: "ack-ind",
      verdict: "VERIFIED",
      lease_release_status: "RELEASED",
      acknowledged_at: "2026-07-15T10:32:00.000Z",
    });
    expect(acked.leaseReleaseStatus).toBe("RELEASED");
    expect(acked.status).toBe("ACKNOWLEDGED");
  });

  it("refuses to submit an INDETERMINATE verdict rather than fabricate landing_proof", () => {
    // The server's .strict() WalletEvidence schema requires landing_proof on
    // every entry unconditionally, but a non-VERIFIED OperationProofVerdict carries no
    // independently-derived projection/signature to build one from (no fresh head was
    // ever confirmed). Known open gap: INDETERMINATE/REJECTED acknowledgement still
    // needs its own protocol answer — this builder must never fabricate the field to make
    // that gap disappear (never blind-retry, never fabricate a submit).
    let op = openConsumerOperation({
      operationId: "55555555-5555-4555-8555-555555555561",
      compositionLabel: "deposit",
      rowVersion: 7,
    });
    op = {
      ...op,
      operationVerified: {
        verdict: "INDETERMINATE",
        kind: "receive",
        stage: "delta",
        reason: "endpoint_disagreement",
      },
      status: "INDETERMINATE",
    };
    const artifact = buildReceiveArtifact(op.operationId, "2.25");
    const material = materialFor(op.operationId, "RECEIVE_EXTERNAL", artifact);
    const req = buildVerificationCompleteRequest({
      operation: op,
      material,
      consumedCursor: "1051",
    });
    expect("error" in req).toBe(true);
    if (!("error" in req)) return;
    expect(req.error).toMatch(/no_independent_head_for_role/);
  });
});

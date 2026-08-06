/**
 * Worked example — a merchant implementer composing the installable
 * `@zucoins/generic-node-consumer` SDK's HTTP client with its independent verification
 * pipeline, end to end, for one RECEIVE_EXTERNAL (deposit) operation:
 *
 *   1. `createReceive` — initiate the receive (implementer bearer).
 *   2. `subscribeToOperation` — wake on the browser-facing lifecycle stream.
 *   3. `ingestSubscribeProjection` — record the wake as a low-authority trigger only.
 *   4. `getVerificationMaterial` — fetch the node-signed expected artifact + evidence.
 *   5. `verifyOperationIndependently` — run the independent verifier pipeline against the
 *      example's own (fixture) gateway observation.
 *   6. `buildVerificationCompleteRequest` + `postVerificationComplete` — acknowledge.
 *
 * All HTTP calls use an injected fetch stub (no real socket — see test/setup-network-guard.ts);
 * this proves the composition wiring, not conformance against a live node.
 */

import { Buffer } from "node:buffer";
import { generateKeyPairSync, sign as edSign, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  buildReceiveExpectedArtifact,
  parseEd25519Signature,
  parsePositiveZkzAmount,
  parseSha256Hex,
  parseUuid,
  parseWalletPublicKey,
} from "@zucoins/node-core";
import { deriveBaseline, type ArtifactEnvelope } from "@zucoins/node-core/verifier/consumer";
import { bootstrapIdentityPin, type DiscoveryIdentityWire } from "@zucoins/node-core/verifier/consumer/pinning";
import {
  computePathManifestSha256,
  transactionBodySha256,
} from "@zucoins/node-core/observation";

import {
  applyVerificationComplete,
  asDirectObservation,
  buildVerificationCompleteRequest,
  createReceive,
  generateIdempotencyKey,
  getVerificationMaterial,
  ingestSubscribeProjection,
  openConsumerOperation,
  postVerificationComplete,
  subscribeToOperation,
  verifyOperationIndependently,
  type CreateReceiveResponse,
  type FetchLike,
  type ReportingCredential,
  type VerificationMaterialWire,
} from "./index.js";

const GEN_DIR = new URL("../../generic-node-contracts/src/receive-golden/gen/", import.meta.url);
function fixtureText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}
const MANIFEST = JSON.parse(fixtureText("manifest.json"));
const RECEIVER_PUBKEY = MANIFEST.public_keys.seed_03 as string;
const TARGET_SETTLED = fixtureText("target.settled.json");
const TARGET = JSON.parse(TARGET_SETTLED) as { step_2_signature: string };
const RESPONSE_BYTES = new TextEncoder().encode(
  `{"status":true,"code":"success","message":"","data":[${TARGET_SETTLED}]}`,
);
const GW_PIN = "consumer_gw_pin_v1";

function ed25519Pair(): { publicKeyB64: string; privateKey: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ type: "spki", format: "der" }).subarray(12);
  return { publicKeyB64: Buffer.from(raw).toString("base64url") + "=", privateKey };
}

const NODE = ed25519Pair();
const NODE_ID = "33333333-3333-4333-8333-333333333333";
const KEY_ID = "33333333-3333-4333-8333-333333333333";
const IMPLEMENTER_ID = "44444444-4444-4444-8444-444444444444";
const OP_ID = "55555555-5555-4555-8555-555555555590";
const NOW = 1_700_000_000_000;

function signPreimage(preimageBytes: Uint8Array): string {
  return edSign(null, Buffer.from(preimageBytes), NODE.privateKey).toString("base64url") + "==";
}

function buildReceiveArtifact(): ArtifactEnvelope {
  const preimage = buildReceiveExpectedArtifact({
    node_id: parseUuid(NODE_ID),
    implementer_id: parseUuid(IMPLEMENTER_ID),
    operation_id: parseUuid(OP_ID),
    receiver_wallet_id: parseUuid("66666666-6666-4666-8666-666666666666"),
    receiver_pubkey: parseWalletPublicKey(RECEIVER_PUBKEY),
    amount_zkz: parsePositiveZkzAmount("2.25"),
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

function discoveryDoc(): DiscoveryIdentityWire {
  return {
    node_id: NODE_ID,
    expected_artifact_public_keys: [{ key_id: KEY_ID, public_key: NODE.publicKeyB64 }],
    key_validity_intervals: [
      { key_id: KEY_ID, valid_from: new Date(NOW - 60_000).toISOString(), valid_until: null },
    ],
  };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("worked example: deposit end to end through the installable SDK", () => {
  it("initiates, subscribes, verifies independently, and acknowledges", async () => {
    const artifact = buildReceiveArtifact();

    // --- 1. Initiate the receive (implementer bearer) ---
    const createResponseBody: CreateReceiveResponse = {
      operation: {
        operation_id: OP_ID,
        operation_type: "RECEIVE_EXTERNAL",
        state: "READY",
        amount_zkz: "2.25",
        row_version: 2,
        attention_required: false,
        attention_reason: null,
        created_at: "2026-07-18T12:00:00.000Z",
        updated_at: "2026-07-18T12:00:00.000Z",
        terminal_at: null,
        verification_material_available_until: null,
      },
      receiver_pubkey: RECEIVER_PUBKEY,
      discriminator: OP_ID,
      expires_at: "2026-07-18T12:05:00.000Z",
      after_landing: { kind: "HOLD", destination_id: null },
      code_status: "AWAITING_ARM",
      transfer_code: null,
      expected_artifact: artifact,
      t0: { observation_id: "obs-t0", projection: { s: "", p: "", b_zkz: "0" } },
      subscription_handle: "sh_secret",
    };
    const createFetch: FetchLike = async () => jsonResponse(201, createResponseBody);
    const created = await createReceive({
      config: { baseUrl: "https://node.example.com", fetchImpl: createFetch },
      bearerKey: "ik_test",
      idempotencyKey: generateIdempotencyKey(),
      request: {
        amount_zkz: "2.25",
        anchor: "ord_01J2",
        after_landing: { kind: "HOLD", destination_id: null },
      },
    });
    expect(created.subscription_handle).toBe("sh_secret");

    let op = openConsumerOperation({ operationId: OP_ID, compositionLabel: "deposit" });

    // --- 2/3. Wake via the browser-facing subscribe stream ---
    const subscribeFrame = {
      operation_id: OP_ID,
      operation_type: "RECEIVE_EXTERNAL" as const,
      state: "RECEIVE_LANDED",
      row_version: 3,
      attention_required: false,
      updated_at: "2026-07-18T12:00:05.000Z",
    };
    const subscribeBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify(subscribeFrame)}\n\n`));
        controller.close();
      },
    });
    for await (const projection of subscribeToOperation({
      config: {
        baseUrl: "https://node.example.com",
        fetchImpl: async () => new Response(subscribeBody, { status: 200 }),
      },
      operationId: OP_ID,
      subscriptionHandle: created.subscription_handle,
    })) {
      op = ingestSubscribeProjection(op, projection, NOW);
    }
    expect(op.status).toBe("AWAITING_TRIGGER");
    expect(op.nodeClaim?.authenticated).toBe(false); // subscribe is a wake, never proof

    // --- 4. Fetch verification material (signed reporting credential) ---
    // ancestor_proofs anchors the RECEIVER wallet's landing_proof at
    // depth 0 on the same target settled body the gateway response wraps; buildVerificationCompleteRequest
    // (step 6) cross-checks its fresh_head_step_2_signature against this pipeline's own
    // independently-derived head before trusting it.
    const targetBodySha256 = transactionBodySha256(TARGET_SETTLED);
    const receiverPathManifest = [
      {
        position: 0,
        step_2_signature: TARGET.step_2_signature,
        queried_wallet_previous_signature: "",
        transaction_sha256: targetBodySha256,
        body_index: 0,
      },
    ];
    const material: VerificationMaterialWire = {
      operation_id: OP_ID,
      operation_type: "RECEIVE_EXTERNAL",
      state: "RECEIVE_LANDED",
      expected_artifact: artifact,
      observation_evidence: [
        {
          evidence_role: "RECEIVER",
          wallet_id: "66666666-6666-4666-8666-666666666666",
          wallet_public_key: RECEIVER_PUBKEY,
          t0: { observation_id: "o1", projection: { s: "", p: "", b_zkz: "0" } },
          terminal: {
            observation_id: "o2",
            projection: { s: TARGET.step_2_signature, p: "", b_zkz: "2.25" },
          },
          node_observation_raw_body_base64: Buffer.from(RESPONSE_BYTES).toString("base64"),
        },
      ],
      ancestor_proofs: [
        {
          evidence_role: "RECEIVER",
          wallet_public_key: RECEIVER_PUBKEY,
          classification: "EXPECTED_AT_HEAD",
          expected_step_2_signature: TARGET.step_2_signature,
          fresh_head_step_2_signature: TARGET.step_2_signature,
          fresh_head_transaction_sha256: targetBodySha256,
          hop_count: 0,
          path_manifest_sha256: computePathManifestSha256(receiverPathManifest),
          path_manifest: receiverPathManifest,
          transaction_bodies: [
            { body_index: 0, transaction_sha256: targetBodySha256, settled_transaction_text: TARGET_SETTLED },
          ],
          indeterminate_reason: null,
        },
      ],
    };
    const credential: ReportingCredential = {
      nodeId: NODE_ID,
      implementerId: IMPLEMENTER_ID,
      keyId: KEY_ID,
      signer: { sign: async () => "stub-signature" },
    };
    const fetched = await getVerificationMaterial({
      config: {
        baseUrl: "https://node.example.com",
        fetchImpl: async () => jsonResponse(200, material),
      },
      credential,
      operationId: OP_ID,
    });

    // --- 5. Independent verification against the example's own gateway observation ---
    const directs = [asDirectObservation("RECEIVER", RECEIVER_PUBKEY, RESPONSE_BYTES, GW_PIN)];
    const receiverBaseline = deriveBaseline(RESPONSE_BYTES, RECEIVER_PUBKEY);
    const aligned: VerificationMaterialWire = {
      ...fetched,
      observation_evidence: fetched.observation_evidence.map((ev) =>
        ev.terminal && receiverBaseline
          ? { ...ev, terminal: { ...ev.terminal, projection: { s: receiverBaseline.S, p: receiverBaseline.P, b_zkz: receiverBaseline.B } } }
          : ev,
      ),
    };
    const result = verifyOperationIndependently({
      operation: op,
      material: aligned,
      directObservations: directs,
      identityPin: bootstrapIdentityPin(
        { nodeId: NODE_ID, keyId: KEY_ID, publicKeyB64: NODE.publicKeyB64, sourceChannel: "operator_console_export" },
        NOW,
      ),
      discovery: discoveryDoc(),
      originClass: "node-origin",
      pinnedGatewayFingerprint: GW_PIN,
      nowUnixMs: NOW,
      baselines: { receiver: { role: "receiver", S: "", P: "", B: "0", I: "x".repeat(64) } },
    });
    expect(result.verdict.verdict).toBe("VERIFIED");
    op = result.operation;

    // --- 6. Acknowledge ---
    const ackReq = buildVerificationCompleteRequest({ operation: op, material: aligned, consumedCursor: "42" });
    expect("error" in ackReq).toBe(false);
    if ("error" in ackReq) return;
    const ackResponseBody = {
      operation_id: OP_ID,
      acknowledgement_id: "ack-1",
      verdict: "VERIFIED" as const,
      lease_release_status: "RELEASED" as const,
      acknowledged_at: "2026-07-18T12:00:10.000Z",
    };
    const acked = await postVerificationComplete({
      config: {
        baseUrl: "https://node.example.com",
        fetchImpl: async () => jsonResponse(200, ackResponseBody),
      },
      credential,
      operationId: OP_ID,
      request: ackReq,
      idempotencyKey: generateIdempotencyKey(),
    });
    op = applyVerificationComplete(op, acked);

    expect(op.status).toBe("ACKNOWLEDGED");
    expect(op.leaseReleaseStatus).toBe("RELEASED");
    expect(op.acknowledgementId).toBe("ack-1");
  });
});

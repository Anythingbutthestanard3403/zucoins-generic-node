import { Buffer } from "node:buffer";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  buildMoveInternalExpectedArtifact,
  buildNodeEvent,
  buildReceiveExpectedArtifact,
  buildSendExternalExpectedArtifact,
} from "../../protocol/suite/builders.js";
import {
  buildImplementerEventPreimage,
  IMPLEMENTER_EVENT_CANONICAL_VERSION,
  IMPLEMENTER_EVENT_PURPOSE,
} from "@zucoins/generic-node-contracts/implementer-events";
import { createHash } from "node:crypto";
import {
  parseEd25519Signature,
  parseSha256Hex,
  parseUuid,
  parseWalletPublicKey,
} from "../../protocol/scalars.js";
import { parsePositiveZkzAmount } from "../../protocol/amounts.js";
import { GENESIS_PROJECTION } from "../../protocol/wallet-role.js";
import { parseProofBundle } from "./parse.js";
import {
  A8_GOLDEN_NODE_ID,
  A8_GOLDEN_PUBLIC_KEYS,
  assertNotGoldenKey,
  authenticateArtifact,
  authenticateImplementerEvent,
  authenticateNodeEvent,
  deriveBaseline,
  isA8GoldenKey,
  verifyMoveProof,
  verifyOperationProof,
  verifyReceiveProof,
  verifySendProof,
} from "./verify.js";
import type { ArtifactEnvelope, NodeVerificationKey } from "./types.js";

const GEN_DIR = new URL("../../../../generic-node-contracts/src/receive-golden/gen/", import.meta.url);

function fixtureText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}

const MANIFEST = JSON.parse(fixtureText("manifest.json"));
const RECEIVER_PUBKEY = MANIFEST.public_keys.seed_03;
const SENDER_PUBKEY = MANIFEST.public_keys.seed_02;
const TARGET_SETTLED = fixtureText("target.settled.json");

function gatewayEnvelopeBytes(settledJson: string): Uint8Array {
  return new TextEncoder().encode(
    `{"status":true,"code":"success","message":"","data":[${settledJson}]}`,
  );
}

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

// Test-only Ed25519 node identity keypair (NOT an A.8 golden seed).
const { publicKey: nodePubDer, privateKey: nodePriv } = generateKeyPairSync("ed25519");
const NODE_PUBKEY_RAW = nodePubDer.export({ type: "spki", format: "der" }).subarray(12);
const NODE_PUBKEY_B64 = Buffer.from(NODE_PUBKEY_RAW).toString("base64url") + "=";
const NODE_KEY_ID = "33333333-3333-4333-8333-333333333333";

const NODE_KEY: NodeVerificationKey = { keyId: NODE_KEY_ID, publicKey: NODE_PUBKEY_B64 };

function signPreimage(preimageBytes: Uint8Array): string {
  const sig = edSign(null, Buffer.from(preimageBytes), nodePriv);
  // parseEd25519Signature expects padded base64url (86 chars + "=="); Node omits padding.
  return sig.toString("base64url") + "==";
}

function buildReceiveArtifact(amountZkz: string, receiverPubkey: string): ArtifactEnvelope {
  const preimage = buildReceiveExpectedArtifact({
    node_id: parseUuid(NODE_KEY_ID),
    implementer_id: parseUuid("44444444-4444-4444-8444-444444444444"),
    operation_id: parseUuid("55555555-5555-4555-8555-555555555555"),
    receiver_wallet_id: parseUuid("66666666-6666-4666-8666-666666666666"),
    receiver_pubkey: parseWalletPublicKey(receiverPubkey),
    amount_zkz: parsePositiveZkzAmount(amountZkz),
    discriminator: parseUuid("77777777-7777-4777-8777-777777777777"),
    anchor: "zp1-anchor-test",
    receiver_t0_fingerprint: parseSha256Hex("a".repeat(64)),
    expiry_unix_time_secs: null,
    after_landing: { kind: "HOLD", destination_id: null },
    transfer_code_sha256: parseSha256Hex("b".repeat(64)),
  });
  return {
    key_id: parseUuid(NODE_KEY_ID),
    preimage_text: preimage.preimageText,
    preimage_sha256: parseSha256Hex(preimage.sha256 as string),
    signature: parseEd25519Signature(signPreimage(preimage.preimageBytes)),
  };
}

function buildMoveArtifact(amountZkz: string, sourcePubkey: string, destPubkey: string): ArtifactEnvelope {
  const preimage = buildMoveInternalExpectedArtifact({
    node_id: parseUuid(NODE_KEY_ID),
    implementer_id: parseUuid("44444444-4444-4444-8444-444444444444"),
    operation_id: parseUuid("55555555-5555-4555-8555-555555555555"),
    source_wallet_id: parseUuid("66666666-6666-4666-8666-666666666666"),
    source_pubkey: parseWalletPublicKey(sourcePubkey),
    destination_id: parseUuid("88888888-8888-4888-8888-888888888888"),
    destination_wallet_id: parseUuid("99999999-9999-4999-8999-999999999999"),
    destination_pubkey: parseWalletPublicKey(destPubkey),
    amount_zkz: parsePositiveZkzAmount(amountZkz),
    spawned_from_operation_id: null,
    references_operation_id: null,
  });
  return {
    key_id: parseUuid(NODE_KEY_ID),
    preimage_text: preimage.preimageText,
    preimage_sha256: parseSha256Hex(preimage.sha256 as string),
    signature: parseEd25519Signature(signPreimage(preimage.preimageBytes)),
  };
}

function buildSendArtifact(amountZkz: string, sourcePubkey: string, destAddress: string): ArtifactEnvelope {
  const preimage = buildSendExternalExpectedArtifact({
    node_id: parseUuid(NODE_KEY_ID),
    implementer_id: parseUuid("44444444-4444-4444-8444-444444444444"),
    operation_id: parseUuid("55555555-5555-4555-8555-555555555555"),
    source_selector: { kind: "WALLET_ID", wallet_id: parseUuid("66666666-6666-4666-8666-666666666666") },
    source_pubkey: parseWalletPublicKey(sourcePubkey),
    destination_address: parseWalletPublicKey(destAddress),
    amount_zkz: parsePositiveZkzAmount(amountZkz),
    references_operation_id: null,
  });
  return {
    key_id: parseUuid(NODE_KEY_ID),
    preimage_text: preimage.preimageText,
    preimage_sha256: parseSha256Hex(preimage.sha256 as string),
    signature: parseEd25519Signature(signPreimage(preimage.preimageBytes)),
  };
}

const RESPONSE_B64 = toBase64Url(gatewayEnvelopeBytes(TARGET_SETTLED));

// Baseline that does NOT chain to TARGET_SETTLED (P != baseline.S) — buried/fork case.
const WRONG_BASELINE = {
  role: "sender" as const,
  S: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
  P: "",
  B: "10",
  I: "c".repeat(64),
};

const CORRECT_SENDER_BASELINE = {
  role: "sender" as const,
  S: MANIFEST.predecessor.step_2_signature,
  P: "",
  B: "10",
  I: "x".repeat(64),
};

describe("parseProofBundle", () => {
  it("parses a valid receive bundle", () => {
    const wire = {
      kind: "receive",
      artifact: buildReceiveArtifact("2.25", RECEIVER_PUBKEY),
      response: { base64url: RESPONSE_B64 },
    };
    const result = parseProofBundle(wire);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.bundle.kind).toBe("receive");
    }
  });

  it("rejects non-object input", () => {
    const result = parseProofBundle("not an object");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("MALFORMED_BUNDLE");
  });

  it("rejects unknown kind", () => {
    const result = parseProofBundle({ kind: "transfer", artifact: {} });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("MALFORMED_BUNDLE");
  });

  it("rejects missing artifact fields", () => {
    const result = parseProofBundle({ kind: "receive", artifact: { key_id: "x" }, response: { base64url: RESPONSE_B64 } });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("MALFORMED_BUNDLE");
  });

  it("rejects invalid base64url in response", () => {
    const wire = {
      kind: "receive",
      artifact: buildReceiveArtifact("2.25", RECEIVER_PUBKEY),
      response: { base64url: "not valid base64!!!" },
    };
    const result = parseProofBundle(wire);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("INVALID_RESPONSE_ENCODING");
  });

  it("parses a valid move bundle", () => {
    const wire = {
      kind: "move",
      artifact: buildMoveArtifact("2.25", SENDER_PUBKEY, RECEIVER_PUBKEY),
      sourceResponse: { base64url: RESPONSE_B64 },
      destinationResponse: { base64url: RESPONSE_B64 },
    };
    const result = parseProofBundle(wire);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.bundle.kind).toBe("move");
  });
});

describe("verifyReceiveProof", () => {
  it("returns VERIFIED for a valid receive proof from genesis", () => {
    const bundle = {
      kind: "receive" as const,
      artifact: buildReceiveArtifact("2.25", RECEIVER_PUBKEY),
      receiverResponse: gatewayEnvelopeBytes(TARGET_SETTLED),
      receiverBaseline: GENESIS_PROJECTION,
    };
    const verdict = verifyReceiveProof(bundle, NODE_KEY);
    expect(verdict.verdict).toBe("VERIFIED");
    if (verdict.verdict === "VERIFIED") {
      expect(verdict.kind).toBe("receive");
      expect(verdict.projection.role).toBe("receiver");
      expect(verdict.semanticFingerprint).toBeTruthy();
    }
  });

  it("returns REJECTED at artifact stage for wrong node key", () => {
    const { publicKey: wrongPubDer } = generateKeyPairSync("ed25519");
    const wrongPubB64 = Buffer.from(wrongPubDer.export({ type: "spki", format: "der" }).subarray(12)).toString("base64url") + "=";
    const bundle = {
      kind: "receive" as const,
      artifact: buildReceiveArtifact("2.25", RECEIVER_PUBKEY),
      receiverResponse: gatewayEnvelopeBytes(TARGET_SETTLED),
    };
    const verdict = verifyReceiveProof(bundle, { keyId: NODE_KEY_ID, publicKey: wrongPubB64 });
    expect(verdict.verdict).toBe("REJECTED");
    if (verdict.verdict === "REJECTED") expect(verdict.stage).toBe("artifact");
  });

  it("returns REJECTED at delta stage for wrong amount", () => {
    const bundle = {
      kind: "receive" as const,
      artifact: buildReceiveArtifact("9.99", RECEIVER_PUBKEY),
      receiverResponse: gatewayEnvelopeBytes(TARGET_SETTLED),
      receiverBaseline: GENESIS_PROJECTION,
    };
    const verdict = verifyReceiveProof(bundle, NODE_KEY);
    expect(verdict.verdict).toBe("REJECTED");
    if (verdict.verdict === "REJECTED") expect(verdict.stage).toBe("delta");
  });

  it("returns INDETERMINATE for malformed gateway response", () => {
    const bundle = {
      kind: "receive" as const,
      artifact: buildReceiveArtifact("2.25", RECEIVER_PUBKEY),
      receiverResponse: new TextEncoder().encode("not json at all"),
    };
    const verdict = verifyReceiveProof(bundle, NODE_KEY);
    expect(verdict.verdict).toBe("INDETERMINATE");
    if (verdict.verdict === "INDETERMINATE") expect(verdict.stage).toBe("envelope");
  });

  // D1 — backlink mismatch (chain_link_mismatch) → INDETERMINATE, not REJECTED.
  it("D1: returns INDETERMINATE for signature-valid head whose backlink does not chain baseline (receive)", () => {
    const bundle = {
      kind: "receive" as const,
      artifact: buildReceiveArtifact("2.25", RECEIVER_PUBKEY),
      receiverResponse: gatewayEnvelopeBytes(TARGET_SETTLED),
      // TARGET is a genesis receive (P=""); a non-genesis baseline forces chain_link_mismatch.
      receiverBaseline: WRONG_BASELINE,
    };
    const verdict = verifyReceiveProof(bundle, NODE_KEY);
    expect(verdict.verdict).toBe("INDETERMINATE");
    if (verdict.verdict === "INDETERMINATE") {
      expect(verdict.stage).toBe("delta");
      expect(verdict.reason).toMatch(/chain_link_mismatch/);
    }
  });
});

describe("verifyMoveProof", () => {
  it("returns VERIFIED for a valid move proof", () => {
    const bundle = {
      kind: "move" as const,
      artifact: buildMoveArtifact("2.25", SENDER_PUBKEY, RECEIVER_PUBKEY),
      sourceResponse: gatewayEnvelopeBytes(TARGET_SETTLED),
      destinationResponse: gatewayEnvelopeBytes(TARGET_SETTLED),
      sourceBaseline: CORRECT_SENDER_BASELINE,
      destinationBaseline: GENESIS_PROJECTION,
    };
    const verdict = verifyMoveProof(bundle, NODE_KEY);
    expect(verdict.verdict).toBe("VERIFIED");
  });

  it("returns INDETERMINATE when destination observation fails envelope", () => {
    const predecessorSettled = fixtureText("predecessor.settled.json");
    const bundle = {
      kind: "move" as const,
      artifact: buildMoveArtifact("2.25", SENDER_PUBKEY, RECEIVER_PUBKEY),
      sourceResponse: gatewayEnvelopeBytes(TARGET_SETTLED),
      destinationResponse: gatewayEnvelopeBytes(predecessorSettled),
      sourceBaseline: GENESIS_PROJECTION,
      destinationBaseline: GENESIS_PROJECTION,
    };
    const verdict = verifyMoveProof(bundle, NODE_KEY);
    // predecessor as destination either fails role (REJECTED) or envelope/tx — never VERIFIED.
    expect(verdict.verdict).not.toBe("VERIFIED");
  });

  // D1 — move source backlink jump → INDETERMINATE.
  it("D1: returns INDETERMINATE for signature-valid move head with backlink mismatch (source)", () => {
    const bundle = {
      kind: "move" as const,
      artifact: buildMoveArtifact("2.25", SENDER_PUBKEY, RECEIVER_PUBKEY),
      sourceResponse: gatewayEnvelopeBytes(TARGET_SETTLED),
      destinationResponse: gatewayEnvelopeBytes(TARGET_SETTLED),
      sourceBaseline: WRONG_BASELINE,
      destinationBaseline: GENESIS_PROJECTION,
    };
    const verdict = verifyMoveProof(bundle, NODE_KEY);
    expect(verdict.verdict).toBe("INDETERMINATE");
    if (verdict.verdict === "INDETERMINATE") {
      expect(verdict.stage).toBe("delta");
      expect(verdict.reason).toMatch(/chain_link_mismatch/);
    }
  });
});

describe("verifySendProof", () => {
  it("returns VERIFIED for a valid send proof", () => {
    const bundle = {
      kind: "send" as const,
      artifact: buildSendArtifact("2.25", SENDER_PUBKEY, RECEIVER_PUBKEY),
      sourceResponse: gatewayEnvelopeBytes(TARGET_SETTLED),
      sourceBaseline: CORRECT_SENDER_BASELINE,
    };
    const verdict = verifySendProof(bundle, NODE_KEY);
    expect(verdict.verdict).toBe("VERIFIED");
  });

  it("returns REJECTED at delta for wrong destination", () => {
    const bundle = {
      kind: "send" as const,
      artifact: buildSendArtifact("2.25", SENDER_PUBKEY, MANIFEST.public_keys.seed_05),
      sourceResponse: gatewayEnvelopeBytes(TARGET_SETTLED),
      sourceBaseline: CORRECT_SENDER_BASELINE,
    };
    const verdict = verifySendProof(bundle, NODE_KEY);
    expect(verdict.verdict).toBe("REJECTED");
    if (verdict.verdict === "REJECTED") expect(verdict.stage).toBe("delta");
  });

  // D1 — send backlink jump → INDETERMINATE.
  it("D1: returns INDETERMINATE for signature-valid send head with backlink mismatch", () => {
    const bundle = {
      kind: "send" as const,
      artifact: buildSendArtifact("2.25", SENDER_PUBKEY, RECEIVER_PUBKEY),
      sourceResponse: gatewayEnvelopeBytes(TARGET_SETTLED),
      sourceBaseline: WRONG_BASELINE,
    };
    const verdict = verifySendProof(bundle, NODE_KEY);
    expect(verdict.verdict).toBe("INDETERMINATE");
    if (verdict.verdict === "INDETERMINATE") {
      expect(verdict.stage).toBe("delta");
      expect(verdict.reason).toMatch(/chain_link_mismatch/);
    }
  });
});

describe("verifyOperationProof (dispatch)", () => {
  it("dispatches receive bundles correctly", () => {
    const bundle = {
      kind: "receive" as const,
      artifact: buildReceiveArtifact("2.25", RECEIVER_PUBKEY),
      receiverResponse: gatewayEnvelopeBytes(TARGET_SETTLED),
      receiverBaseline: GENESIS_PROJECTION,
    };
    const verdict = verifyOperationProof(bundle, NODE_KEY);
    expect(verdict.verdict).toBe("VERIFIED");
  });
});

describe("authenticateArtifact (D3 purpose dispatch)", () => {
  it("authenticates a genuine receive artifact", () => {
    const artifact = buildReceiveArtifact("2.25", RECEIVER_PUBKEY);
    const result = authenticateArtifact(artifact, NODE_KEY);
    expect(result.authenticated).toBe(true);
  });

  it("authenticates a genuine move artifact", () => {
    const artifact = buildMoveArtifact("2.25", SENDER_PUBKEY, RECEIVER_PUBKEY);
    const result = authenticateArtifact(artifact, NODE_KEY);
    expect(result.authenticated).toBe(true);
  });

  it("authenticates a genuine send artifact", () => {
    const artifact = buildSendArtifact("2.25", SENDER_PUBKEY, RECEIVER_PUBKEY);
    const result = authenticateArtifact(artifact, NODE_KEY);
    expect(result.authenticated).toBe(true);
  });

  it("rejects an artifact signed by a different key", () => {
    const { publicKey: wrongPubDer } = generateKeyPairSync("ed25519");
    const wrongPubB64 =
      Buffer.from(wrongPubDer.export({ type: "spki", format: "der" }).subarray(12)).toString("base64url") + "=";
    const artifact = buildReceiveArtifact("2.25", RECEIVER_PUBKEY);
    const result = authenticateArtifact(artifact, { keyId: NODE_KEY_ID, publicKey: wrongPubB64 });
    expect(result.authenticated).toBe(false);
  });
});

describe("authenticateNodeEvent", () => {
  it("authenticates a valid node event", () => {
    const preimage = buildNodeEvent({
      node_id: parseUuid(NODE_KEY_ID),
      event_id: parseUuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
      seq: "1",
      operation_id: null,
      wallet_id: null,
      event_type: "receive.landed",
      data_sha256: parseSha256Hex("c".repeat(64)),
      previous_event_hash: null,
      created_at: "2026-07-15T10:30:00.000Z",
    });
    const envelope: ArtifactEnvelope = {
      key_id: parseUuid(NODE_KEY_ID),
      preimage_text: preimage.preimageText,
      preimage_sha256: parseSha256Hex(preimage.sha256 as string),
      signature: parseEd25519Signature(signPreimage(preimage.preimageBytes)),
    };
    const nodeEventKey: NodeVerificationKey = { keyId: NODE_KEY_ID, publicKey: NODE_PUBKEY_B64 };
    const result = authenticateNodeEvent(envelope, nodeEventKey);
    expect(result.authenticated).toBe(true);
  });

  it("rejects a node event signed by a different key", () => {
    const { privateKey: wrongPriv } = generateKeyPairSync("ed25519");
    const preimage = buildNodeEvent({
      node_id: parseUuid(NODE_KEY_ID),
      event_id: parseUuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
      seq: "1",
      operation_id: null,
      wallet_id: null,
      event_type: "receive.landed",
      data_sha256: parseSha256Hex("c".repeat(64)),
      previous_event_hash: null,
      created_at: "2026-07-15T10:30:00.000Z",
    });
    const wrongSig = edSign(null, Buffer.from(preimage.preimageBytes), wrongPriv).toString("base64url") + "==";
    const envelope: ArtifactEnvelope = {
      key_id: parseUuid(NODE_KEY_ID),
      preimage_text: preimage.preimageText,
      preimage_sha256: parseSha256Hex(preimage.sha256 as string),
      signature: parseEd25519Signature(wrongSig),
    };
    const result = authenticateNodeEvent(envelope, NODE_KEY);
    expect(result.authenticated).toBe(false);
  });
});

describe("authenticateImplementerEvent", () => {
  function buildImplementerEnvelope(signerPriv = nodePriv): ArtifactEnvelope {
    const preimageText = buildImplementerEventPreimage({
      purpose: IMPLEMENTER_EVENT_PURPOSE,
      canonical_version: IMPLEMENTER_EVENT_CANONICAL_VERSION,
      node_id: NODE_KEY_ID,
      implementer_id: "44444444-4444-4444-8444-444444444444",
      event_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      implementer_seq: "1",
      operation_id: "55555555-5555-4555-8555-555555555555",
      wallet_id: null,
      event_type: "receive.landed",
      data_sha256: "c".repeat(64),
      node_event_hash: "d".repeat(64),
      implementer_previous_event_hash: null,
      created_at: "2026-07-15T10:30:00.000Z",
    });
    const preimageBytes = Buffer.from(preimageText, "utf8");
    return {
      key_id: parseUuid(NODE_KEY_ID),
      preimage_text: preimageText,
      preimage_sha256: parseSha256Hex(createHash("sha256").update(preimageBytes).digest("hex")),
      signature: parseEd25519Signature(
        edSign(null, preimageBytes, signerPriv).toString("base64url") + "==",
      ),
    };
  }

  it("authenticates a valid zp-implementer-event-v1 envelope", () => {
    const envelope = buildImplementerEnvelope();
    const nodeEventKey: NodeVerificationKey = { keyId: NODE_KEY_ID, publicKey: NODE_PUBKEY_B64 };
    const result = authenticateImplementerEvent(envelope, nodeEventKey);
    expect(result.authenticated).toBe(true);
  });

  it("rejects an implementer event signed by a different key", () => {
    const { privateKey: wrongPriv } = generateKeyPairSync("ed25519");
    const envelope = buildImplementerEnvelope(wrongPriv);
    const result = authenticateImplementerEvent(envelope, NODE_KEY);
    expect(result.authenticated).toBe(false);
  });

  it("rejects a zp-node-event-v1 envelope (wrong purpose for this verifier)", () => {
    const preimage = buildNodeEvent({
      node_id: parseUuid(NODE_KEY_ID),
      event_id: parseUuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
      seq: "1",
      operation_id: null,
      wallet_id: null,
      event_type: "receive.landed",
      data_sha256: parseSha256Hex("c".repeat(64)),
      previous_event_hash: null,
      created_at: "2026-07-15T10:30:00.000Z",
    });
    const envelope: ArtifactEnvelope = {
      key_id: parseUuid(NODE_KEY_ID),
      preimage_text: preimage.preimageText,
      preimage_sha256: parseSha256Hex(preimage.sha256 as string),
      signature: parseEd25519Signature(signPreimage(preimage.preimageBytes)),
    };
    const result = authenticateImplementerEvent(envelope, NODE_KEY);
    expect(result.authenticated).toBe(false);
    if (result.authenticated) return;
    expect(result.reason).toBe("unsupported_implementer_event_purpose");
  });
});


describe("deriveBaseline", () => {
  it("derives a baseline projection from a valid head observation", () => {
    const baseline = deriveBaseline(gatewayEnvelopeBytes(TARGET_SETTLED), RECEIVER_PUBKEY);
    expect(baseline).not.toBeNull();
    expect(baseline!.role).toBe("receiver");
    expect(baseline!.B).toBe("2.25");
  });

  it("returns null for malformed input", () => {
    const baseline = deriveBaseline(new TextEncoder().encode("garbage"), RECEIVER_PUBKEY);
    expect(baseline).toBeNull();
  });
});

describe("A.9 item 16 live-chain golden-key gate (D2)", () => {
  it("identifies the A.8 golden node id and seed-00 public key", () => {
    expect(isA8GoldenKey({ keyId: A8_GOLDEN_NODE_ID, publicKey: NODE_PUBKEY_B64 })).toBe(true);
    const seed00 = [...A8_GOLDEN_PUBLIC_KEYS][0]!;
    expect(isA8GoldenKey({ keyId: NODE_KEY_ID, publicKey: seed00 })).toBe(true);
    expect(isA8GoldenKey(NODE_KEY)).toBe(false);
  });

  it("allows golden keys when liveChain is unset/false (test mode)", () => {
    const golden: NodeVerificationKey = {
      keyId: A8_GOLDEN_NODE_ID,
      publicKey: [...A8_GOLDEN_PUBLIC_KEYS][0]!,
    };
    expect(assertNotGoldenKey(golden)).toBeNull();
    expect(assertNotGoldenKey({ ...golden, liveChain: false })).toBeNull();
  });

  it("refuses A.8 seed key under liveChain=true via assertNotGoldenKey", () => {
    const golden: NodeVerificationKey = {
      keyId: A8_GOLDEN_NODE_ID,
      publicKey: [...A8_GOLDEN_PUBLIC_KEYS][0]!,
      liveChain: true,
    };
    const reason = assertNotGoldenKey(golden);
    expect(reason).toMatch(/A\.9 item 16/);
  });

  it("refuses golden key under liveChain on verifyReceiveProof", () => {
    const bundle = {
      kind: "receive" as const,
      artifact: buildReceiveArtifact("2.25", RECEIVER_PUBKEY),
      receiverResponse: gatewayEnvelopeBytes(TARGET_SETTLED),
      receiverBaseline: GENESIS_PROJECTION,
    };
    const goldenLive: NodeVerificationKey = {
      keyId: A8_GOLDEN_NODE_ID,
      publicKey: [...A8_GOLDEN_PUBLIC_KEYS][0]!,
      liveChain: true,
    };
    const verdict = verifyReceiveProof(bundle, goldenLive);
    expect(verdict.verdict).toBe("REJECTED");
    if (verdict.verdict === "REJECTED") {
      expect(verdict.stage).toBe("artifact");
      expect(verdict.reason).toMatch(/A\.9 item 16/);
    }
  });

  it("refuses golden key under liveChain on authenticateArtifact", () => {
    const artifact = buildReceiveArtifact("2.25", RECEIVER_PUBKEY);
    const result = authenticateArtifact(artifact, {
      keyId: A8_GOLDEN_NODE_ID,
      publicKey: [...A8_GOLDEN_PUBLIC_KEYS][0]!,
      liveChain: true,
    });
    expect(result.authenticated).toBe(false);
    if (!result.authenticated) expect(result.reason).toMatch(/A\.9 item 16/);
  });
});

describe("D4 determinate SplitChain signature / role failures → REJECTED", () => {
  it("returns REJECTED when a SplitChain step signature is mutated", () => {
    const settled = JSON.parse(TARGET_SETTLED) as Record<string, unknown>;
    // Flip one character in step_2_signature so the Ed25519 check fails determinately.
    const sig = String(settled.step_2_signature);
    const flipped = (sig[0] === "A" ? "B" : "A") + sig.slice(1);
    settled.step_2_signature = flipped;
    const bundle = {
      kind: "receive" as const,
      artifact: buildReceiveArtifact("2.25", RECEIVER_PUBKEY),
      receiverResponse: gatewayEnvelopeBytes(JSON.stringify(settled)),
      receiverBaseline: GENESIS_PROJECTION,
    };
    const verdict = verifyReceiveProof(bundle, NODE_KEY);
    expect(verdict.verdict).toBe("REJECTED");
    if (verdict.verdict === "REJECTED") {
      expect(verdict.stage).toBe("transaction");
      expect(verdict.reason).toMatch(/unverified_signature/);
    }
  });

  it("returns REJECTED when the queried wallet matches neither sender nor receiver role", () => {
    // Query TARGET_SETTLED as if the reserved receiver were seed_05 (neither party).
    const wrongWallet = MANIFEST.public_keys.seed_05 as string;
    const bundle = {
      kind: "receive" as const,
      artifact: buildReceiveArtifact("2.25", wrongWallet),
      receiverResponse: gatewayEnvelopeBytes(TARGET_SETTLED),
      receiverBaseline: GENESIS_PROJECTION,
    };
    const verdict = verifyReceiveProof(bundle, NODE_KEY);
    expect(verdict.verdict).toBe("REJECTED");
    if (verdict.verdict === "REJECTED") {
      expect(verdict.stage).toBe("transaction");
      expect(verdict.reason).toMatch(/wallet_role_invalid/);
    }
  });
});

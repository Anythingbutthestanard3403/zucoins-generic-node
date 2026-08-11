// Unified cryptographic golden-vector freeze test.
// Independently reproduces EVERY golden from A.8.1 (SplitChain) and A.8.2 (suite tuples) using
// only node:crypto and the A.8 test-only Ed25519 seeds. No gateway import, no environment-key
// read, no submission. Each golden is verified byte-exact against the frozen constants.
//
// Covers A.1.1 (suite serializer), A.1.2 (SplitChain native), A.8 (goldens),
// A.9 (negative vectors); artifacts freeze, compatibility-literal preservation, two-timer
// separation, reporting-key enrolment.
// The byte-exact signing rule: byte-exact JSON.stringify signing — never reformat.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { describe, expect, it } from "vitest";

import { readGoldenText, sha256OfGolden } from "../testkit/byteGolden.ts";

import {
  COMPAT_LITERALS,
  EVENT_HASH_CHAIN,
  FIXTURE_IDS,
  PREDECESSOR_DIGESTS,
  PREDECESSOR_STEP_1_PREIMAGE,
  SEED_PUBLIC_KEYS,
  SEND_PARTIAL_DIGESTS,
  SEND_PARTIAL_STEP_1_PREIMAGE,
  SEND_PARTIAL_STEP_2_PREIMAGE,
  SEND_REDEMPTION_DIGESTS,
  SEND_REDEMPTION_STEP_1_PREIMAGE,
  SUITE_GOLDEN_OUTPUTS,
  SUITE_GOLDEN_PREIMAGES,
  TARGET_DIGESTS,
  TARGET_STEP_1_PREIMAGE,
} from "./goldens.js";
import {
  ALL_NEGATIVE_VECTORS,
  GENERAL_NEGATIVE_COUNT,
  GENERAL_NEGATIVE_VECTORS,
  REGISTER_NEGATIVE_COUNT,
  REGISTER_NEGATIVE_VECTORS,
  TOTAL_NEGATIVE_COUNT,
} from "./negative-vectors.js";

// --- Independent crypto helpers (from first principles, no shared code path) ---
const paddedBase64Url = (bytes: Buffer): string =>
  bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");

const sha256Hex = (input: Buffer | string): string =>
  createHash("sha256")
    .update(typeof input === "string" ? Buffer.from(input, "utf8") : input)
    .digest("hex");

const keyFromSeed = (byte: number) => {
  const der = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.alloc(32, byte),
  ]);
  return createPrivateKey({ key: der, type: "pkcs8", format: "der" });
};

const derivePublicKey = (priv: ReturnType<typeof keyFromSeed>): string =>
  paddedBase64Url(createPublicKey(priv).export({ type: "spki", format: "der" }).subarray(-32));

const edSign = (text: string, priv: ReturnType<typeof keyFromSeed>): string =>
  paddedBase64Url(sign(null, Buffer.from(text, "utf8"), priv));

const edVerify = (text: string, sig: string, priv: ReturnType<typeof keyFromSeed>): boolean =>
  verify(null, Buffer.from(text, "utf8"), createPublicKey(priv), Buffer.from(sig, "base64url"));

// Derive all keys independently from seeds
const nodeKey = keyFromSeed(0x00);
const deviceKey = keyFromSeed(0x01);
const senderKey = keyFromSeed(0x02);
const receiverKey = keyFromSeed(0x03);
const reportingKey = keyFromSeed(0x04);
const predecessorKey = keyFromSeed(0x05);

const SIGNING_KEYS: Record<string, ReturnType<typeof keyFromSeed>> = {
  node: nodeKey,
  device: deviceKey,
  sender: senderKey,
  receiver: receiverKey,
  reporting: reportingKey,
  predecessor: predecessorKey,
};

// --- A.8 seed public key derivation ---
describe("the crypto-goldens freeze A.8 seed public key derivation", () => {
  it("derives all six public keys independently from filled-byte Ed25519 seeds", () => {
    expect(derivePublicKey(nodeKey)).toBe(SEED_PUBLIC_KEYS.node);
    expect(derivePublicKey(deviceKey)).toBe(SEED_PUBLIC_KEYS.device);
    expect(derivePublicKey(senderKey)).toBe(SEED_PUBLIC_KEYS.sender);
    expect(derivePublicKey(receiverKey)).toBe(SEED_PUBLIC_KEYS.receiver);
    expect(derivePublicKey(reportingKey)).toBe(SEED_PUBLIC_KEYS.reporting);
    expect(derivePublicKey(predecessorKey)).toBe(SEED_PUBLIC_KEYS.predecessor);
  });
});

// --- A.8.0 SEND transfer-code golden inner ---
describe("the crypto-goldens freeze A.8.0 SEND transfer-code golden inner (the receive-golden transfer-code concern)", () => {
  it("reproduces the step-1 digest from the exact preimage bytes", () => {
    expect(sha256Hex(SEND_PARTIAL_STEP_1_PREIMAGE)).toBe(SEND_PARTIAL_DIGESTS.step_1_sha256);
  });

  it("reproduces the step-1 signature from the sender key (seed 0x02)", () => {
    expect(edSign(SEND_PARTIAL_STEP_1_PREIMAGE, senderKey)).toBe(SEND_PARTIAL_DIGESTS.step_1_signature);
    expect(edVerify(SEND_PARTIAL_STEP_1_PREIMAGE, SEND_PARTIAL_DIGESTS.step_1_signature, senderKey)).toBe(true);
  });

  it("reproduces the step-2 preimage, digest, and signature", () => {
    // Full-string pin (A.8.0): never parse→stringify the expected bytes inside the golden test.
    expect(SEND_PARTIAL_STEP_2_PREIMAGE).toBe(
      '{"inner":' +
        SEND_PARTIAL_STEP_1_PREIMAGE +
        ',"step_1_signature":"' +
        SEND_PARTIAL_DIGESTS.step_1_signature +
        '"}',
    );
    expect(sha256Hex(SEND_PARTIAL_STEP_2_PREIMAGE)).toBe(SEND_PARTIAL_DIGESTS.step_2_sha256);
    expect(edSign(SEND_PARTIAL_STEP_2_PREIMAGE, receiverKey)).toBe(SEND_PARTIAL_DIGESTS.step_2_signature);
  });

  it("reproduces the full-tx settled digest", () => {
    const inner = JSON.parse(SEND_PARTIAL_STEP_1_PREIMAGE) as Record<string, unknown>;
    const settled = JSON.stringify({
      inner,
      step_1_signature: SEND_PARTIAL_DIGESTS.step_1_signature,
      step_2_signature: SEND_PARTIAL_DIGESTS.step_2_signature,
    });
    expect(sha256Hex(settled)).toBe(SEND_PARTIAL_DIGESTS.full_tx_sha256);
  });

  it("reproduces the transfer-code digest from the exact string", () => {
    expect(sha256Hex(FIXTURE_IDS.transfer_code)).toBe(SEND_PARTIAL_DIGESTS.transfer_code_sha256);
  });
});

// --- A.8.3 SEND_EXTERNAL redemption golden (D9.14 expiry) ---
describe("the crypto-goldens freeze A.8.3 SEND_EXTERNAL redemption golden", () => {
  it("pins the A.8.3 step-1 digest and signature from the exact preimage bytes", () => {
    expect(sha256Hex(SEND_REDEMPTION_STEP_1_PREIMAGE)).toBe(SEND_REDEMPTION_DIGESTS.step_1_sha256);
    expect(edSign(SEND_REDEMPTION_STEP_1_PREIMAGE, senderKey)).toBe(SEND_REDEMPTION_DIGESTS.step_1_signature);
    expect(edVerify(SEND_REDEMPTION_STEP_1_PREIMAGE, SEND_REDEMPTION_DIGESTS.step_1_signature, senderKey)).toBe(true);
  });

  it("matches the tier-3 on-disk golden bytes (no trailing newline) and pinned file digest", () => {
    const disk = readGoldenText("send-redemption/a83-send-external-redemption.step1.preimage.txt");
    expect(disk).toBe(SEND_REDEMPTION_STEP_1_PREIMAGE);
    expect(disk.endsWith("\n")).toBe(false);
    expect(sha256OfGolden("send-redemption/a83-send-external-redemption.step1.preimage.txt")).toBe(
      SEND_REDEMPTION_DIGESTS.preimage_file_sha256,
    );
    expect(readGoldenText("send-redemption/a83-send-external-redemption.step1.sig.b64")).toBe(
      SEND_REDEMPTION_DIGESTS.step_1_signature,
    );
  });

  it("differs from A.8.0 only in expiry__unix_time_secs (redemption window 300s)", () => {
    expect(SEND_REDEMPTION_STEP_1_PREIMAGE).toContain('"expiry__unix_time_secs":"1784333100"');
    expect(SEND_PARTIAL_STEP_1_PREIMAGE).toContain('"expiry__unix_time_secs":"1784336400"');
    expect(SEND_REDEMPTION_DIGESTS.step_1_sha256).not.toBe(SEND_PARTIAL_DIGESTS.step_1_sha256);
    expect(SEND_REDEMPTION_DIGESTS.step_1_sha256).toMatch(/^46ba7528/);
    expect(SEND_REDEMPTION_DIGESTS.step_1_signature).toMatch(/^KKyZRQ/);
  });
});

describe("the crypto-goldens freeze A.8.0 step-2 full-string disk pin", () => {
  it("on-disk step-2 preimage equals the frozen full string and pinned digest", () => {
    const disk = readGoldenText("split-chain/a80-send-partial.step2.preimage.txt");
    expect(disk).toBe(SEND_PARTIAL_STEP_2_PREIMAGE);
    expect(disk.endsWith("\n")).toBe(false);
    expect(sha256Hex(disk)).toBe(SEND_PARTIAL_DIGESTS.step_2_sha256);
  });
});

// --- A.8.1 SplitChain RECEIVE golden (predecessor) ---
describe("the crypto-goldens freeze A.8.1 predecessor transaction", () => {
  it("reproduces step-1 digest and signature (seed-05 signs)", () => {
    expect(sha256Hex(PREDECESSOR_STEP_1_PREIMAGE)).toBe(PREDECESSOR_DIGESTS.step_1_sha256);
    expect(edSign(PREDECESSOR_STEP_1_PREIMAGE, predecessorKey)).toBe(PREDECESSOR_DIGESTS.step_1_signature);
    expect(edVerify(PREDECESSOR_STEP_1_PREIMAGE, PREDECESSOR_DIGESTS.step_1_signature, predecessorKey)).toBe(true);
  });

  it("reproduces step-2 preimage, digest, and signature (seed-02 signs)", () => {
    const inner = JSON.parse(PREDECESSOR_STEP_1_PREIMAGE) as Record<string, unknown>;
    const step2 = JSON.stringify({ inner, step_1_signature: PREDECESSOR_DIGESTS.step_1_signature });
    expect(sha256Hex(step2)).toBe(PREDECESSOR_DIGESTS.step_2_sha256);
    expect(edSign(step2, senderKey)).toBe(PREDECESSOR_DIGESTS.step_2_signature);
    expect(edVerify(step2, PREDECESSOR_DIGESTS.step_2_signature, senderKey)).toBe(true);
  });

  it("reproduces the settled digest", () => {
    const inner = JSON.parse(PREDECESSOR_STEP_1_PREIMAGE) as Record<string, unknown>;
    const settled = JSON.stringify({
      inner,
      step_1_signature: PREDECESSOR_DIGESTS.step_1_signature,
      step_2_signature: PREDECESSOR_DIGESTS.step_2_signature,
    });
    expect(sha256Hex(settled)).toBe(PREDECESSOR_DIGESTS.settled_sha256);
  });
});

// --- A.8.1 SplitChain RECEIVE golden (target) ---
describe("the crypto-goldens freeze A.8.1 target transaction", () => {
  it("links the target's previous_step_1_state_signature to the predecessor's step_2_signature", () => {
    const inner = JSON.parse(TARGET_STEP_1_PREIMAGE) as Record<string, unknown>;
    expect(inner.previous_step_1_state_signature).toBe(PREDECESSOR_DIGESTS.step_2_signature);
    expect(inner.previous_step_2_state_signature).toBe("");
  });

  it("reproduces step-1 digest and signature (seed-02 signs)", () => {
    expect(sha256Hex(TARGET_STEP_1_PREIMAGE)).toBe(TARGET_DIGESTS.step_1_sha256);
    expect(edSign(TARGET_STEP_1_PREIMAGE, senderKey)).toBe(TARGET_DIGESTS.step_1_signature);
    expect(edVerify(TARGET_STEP_1_PREIMAGE, TARGET_DIGESTS.step_1_signature, senderKey)).toBe(true);
  });

  it("reproduces step-2 preimage, digest, and signature (seed-03 signs)", () => {
    const inner = JSON.parse(TARGET_STEP_1_PREIMAGE) as Record<string, unknown>;
    const step2 = JSON.stringify({ inner, step_1_signature: TARGET_DIGESTS.step_1_signature });
    expect(sha256Hex(step2)).toBe(TARGET_DIGESTS.step_2_sha256);
    expect(edSign(step2, receiverKey)).toBe(TARGET_DIGESTS.step_2_signature);
    expect(edVerify(step2, TARGET_DIGESTS.step_2_signature, receiverKey)).toBe(true);
  });

  it("reproduces the settled digest", () => {
    const inner = JSON.parse(TARGET_STEP_1_PREIMAGE) as Record<string, unknown>;
    const settled = JSON.stringify({
      inner,
      step_1_signature: TARGET_DIGESTS.step_1_signature,
      step_2_signature: TARGET_DIGESTS.step_2_signature,
    });
    expect(sha256Hex(settled)).toBe(TARGET_DIGESTS.settled_sha256);
  });
});

// --- A.8.2 Suite tuple goldens: byte-exact digest + signature reproduction ---
describe("the crypto-goldens freeze A.8.2 suite tuple goldens", () => {
  const entries = Object.entries(SUITE_GOLDEN_PREIMAGES) as [string, string][];

  it.each(entries)("reproduces SHA-256 for %s from independent computation", (key, preimage) => {
    const output = SUITE_GOLDEN_OUTPUTS[key as keyof typeof SUITE_GOLDEN_OUTPUTS];
    expect(sha256Hex(preimage)).toBe(output.sha256);
  });

  it.each(entries.filter(([, p]) => !p.includes("wallet-head-fingerprint")))(
    "reproduces Ed25519 signature for %s from the correct signing key",
    (key, preimage) => {
      const output = SUITE_GOLDEN_OUTPUTS[key as keyof typeof SUITE_GOLDEN_OUTPUTS];
      if (output.signingKey === null) return;
      const priv = SIGNING_KEYS[output.signingKey];
      expect(edSign(preimage, priv)).toBe(output.signature);
      expect(edVerify(preimage, output.signature as string, priv)).toBe(true);
    },
  );

  it("zp-wallet-head-fingerprint-v1 is hashed but NOT signed", () => {
    const output = SUITE_GOLDEN_OUTPUTS["zp-wallet-head-fingerprint-v1"];
    expect(output.signature).toBeNull();
    expect(output.signingKey).toBeNull();
  });
});

// --- A.8.2 event hash chain ---
describe("the crypto-goldens freeze A.8.2 zp-node-event-v1 hash chain", () => {
  it("golden_a event_hash = SHA256(preimage_bytes || signature_bytes)", () => {
    const preimage = SUITE_GOLDEN_PREIMAGES["zp-node-event-v1-golden-a"];
    const sig = SUITE_GOLDEN_OUTPUTS["zp-node-event-v1-golden-a"].signature as string;
    const preimageBytes = Buffer.from(preimage, "utf8");
    const sigBytes = Buffer.from(sig, "base64url");
    expect(sha256Hex(Buffer.concat([preimageBytes, sigBytes]))).toBe(EVENT_HASH_CHAIN.golden_a_event_hash);
  });

  it("golden_b event_hash = SHA256(preimage_bytes || signature_bytes)", () => {
    const preimage = SUITE_GOLDEN_PREIMAGES["zp-node-event-v1-golden-b"];
    const sig = SUITE_GOLDEN_OUTPUTS["zp-node-event-v1-golden-b"].signature as string;
    const preimageBytes = Buffer.from(preimage, "utf8");
    const sigBytes = Buffer.from(sig, "base64url");
    expect(sha256Hex(Buffer.concat([preimageBytes, sigBytes]))).toBe(EVENT_HASH_CHAIN.golden_b_event_hash);
  });

  it("golden_b previous_event_hash equals golden_a event_hash (chain linkage)", () => {
    const goldenB = JSON.parse(
      SUITE_GOLDEN_PREIMAGES["zp-node-event-v1-golden-b"].slice(
        SUITE_GOLDEN_PREIMAGES["zp-node-event-v1-golden-b"].indexOf("\n") + 1,
      ),
    ) as { previous_event_hash: string };
    expect(goldenB.previous_event_hash).toBe(EVENT_HASH_CHAIN.golden_a_event_hash);
  });

  it("golden_a previous_event_hash is null (first event)", () => {
    const goldenA = JSON.parse(
      SUITE_GOLDEN_PREIMAGES["zp-node-event-v1-golden-a"].slice(
        SUITE_GOLDEN_PREIMAGES["zp-node-event-v1-golden-a"].indexOf("\n") + 1,
      ),
    ) as { previous_event_hash: null };
    expect(goldenA.previous_event_hash).toBeNull();
  });
});

// --- A.8.2 suite preimage structural validation ---
describe("the crypto-goldens freeze A.8.2 preimage structure (A.1.1 rules)", () => {
  const entries = Object.entries(SUITE_GOLDEN_PREIMAGES) as [string, string][];

  it.each(entries)("%s has purpose prefix + LF + JSON payload with purpose as field 1", (key, preimage) => {
    const lfIndex = preimage.indexOf("\n");
    expect(lfIndex).toBeGreaterThan(0);
    const prefix = preimage.slice(0, lfIndex);
    const jsonPart = preimage.slice(lfIndex + 1);
    const payload = JSON.parse(jsonPart) as Record<string, unknown>;
    // Prefix equals the purpose (domain separation)
    const purpose = prefix.startsWith("zp-node-event-v1") ? "zp-node-event-v1" : prefix;
    expect(payload.purpose).toBe(purpose);
    // canonical_version is number 1
    expect(payload.canonical_version).toBe(1);
    // No trailing newline
    expect(preimage.endsWith("\n")).toBe(false);
    // Key is a valid suite golden key
    expect(key).toBeTruthy();
  });

  it.each(entries)("%s has no BOM, no trailing whitespace", (_key, preimage) => {
    expect(preimage.charCodeAt(0)).not.toBe(0xfeff);
    expect(preimage.endsWith(" ")).toBe(false);
    expect(preimage.endsWith("\r")).toBe(false);
  });
});

// --- Compatibility literals ---
describe("compatibility literals (compatibility-literal preservation)", () => {
  it("freezes the zp1: receive-message prefix", () => {
    expect(COMPAT_LITERALS.zp1Prefix).toBe("zp1:");
  });

  it("freezes the zupay/zupayments compatibility names", () => {
    expect(COMPAT_LITERALS.zupayName).toBe("zupay");
    expect(COMPAT_LITERALS.zupaymentsName).toBe("zupayments");
  });

  it("freezes the X-ZP-* header family", () => {
    expect(COMPAT_LITERALS.headers).toContain("X-ZP-Reporting-Key-Id");
    expect(COMPAT_LITERALS.headers).toContain("X-ZP-Reporting-Timestamp");
    expect(COMPAT_LITERALS.headers).toContain("X-ZP-Reporting-Expires-At");
    expect(COMPAT_LITERALS.headers).toContain("X-ZP-Reporting-Nonce");
    expect(COMPAT_LITERALS.headers).toContain("X-ZP-Reporting-Signature");
    expect(COMPAT_LITERALS.headers).toContain("X-ZP-TOTP");
    expect(COMPAT_LITERALS.headers).toHaveLength(6);
  });

  it("the receive message in the target inner uses the zp1: prefix pattern", () => {
    const inner = JSON.parse(TARGET_STEP_1_PREIMAGE) as { message: string };
    expect(inner.message.startsWith("zp1:")).toBe(true);
    expect(inner.message).toBe(`zp1:${FIXTURE_IDS.operation_id}:ord_7YQ3`);
  });
});

// --- A.9 negative vectors census ---
describe("the crypto-goldens freeze A.9 negative vectors census", () => {
  it("has exactly 17 general negative vectors", () => {
    expect(GENERAL_NEGATIVE_COUNT).toBe(17);
    expect(GENERAL_NEGATIVE_VECTORS).toHaveLength(17);
  });

  it("has exactly 6 zp-reporting-register-v1 specific negative vectors", () => {
    expect(REGISTER_NEGATIVE_COUNT).toBe(6);
    expect(REGISTER_NEGATIVE_VECTORS).toHaveLength(6);
  });

  it("has 23 total negative vectors", () => {
    expect(TOTAL_NEGATIVE_COUNT).toBe(23);
    expect(ALL_NEGATIVE_VECTORS).toHaveLength(23);
  });

  it("every vector has a documented rejection reason and spec reference", () => {
    for (const vector of ALL_NEGATIVE_VECTORS) {
      expect(vector.rejectionReason.length).toBeGreaterThan(10);
      expect(vector.specRef).toMatch(/^A\.9/);
      expect(vector.id.length).toBeGreaterThan(0);
    }
  });

  it("general vectors cover all 17 A.9 numbered cases", () => {
    const specRefs = GENERAL_NEGATIVE_VECTORS.map((v) => v.specRef);
    for (let i = 1; i <= 17; i++) {
      expect(specRefs).toContain(`A.9 #${i}`);
    }
  });

  it("register vectors cover all 6 register-specific cases", () => {
    const specRefs = REGISTER_NEGATIVE_VECTORS.map((v) => v.specRef);
    for (let i = 1; i <= 6; i++) {
      expect(specRefs).toContain(`A.9 register #${i}`);
    }
  });
});

// --- A.9 negative vector byte-level demonstrations ---
describe("the crypto-goldens freeze A.9 negative vector demonstrations", () => {
  const receivePreimage = SUITE_GOLDEN_PREIMAGES["zp-receive-expected-v1"];
  const receiveJson = receivePreimage.slice(receivePreimage.indexOf("\n") + 1);

  it("#1 field reorder changes the digest (never matches golden)", () => {
    const payload = JSON.parse(receiveJson) as Record<string, unknown>;
    const { purpose, canonical_version, ...rest } = payload;
    const reordered = JSON.stringify({ canonical_version, purpose, ...rest });
    expect(sha256Hex(`zp-receive-expected-v1\n${reordered}`)).not.toBe(
      SUITE_GOLDEN_OUTPUTS["zp-receive-expected-v1"].sha256,
    );
  });

  it("#2 prefix/payload purpose mismatch changes the preimage", () => {
    const mismatched = `zp-move-internal-expected-v1\n${receiveJson}`;
    expect(sha256Hex(mismatched)).not.toBe(SUITE_GOLDEN_OUTPUTS["zp-receive-expected-v1"].sha256);
  });

  it("#3 canonical_version as string changes the digest", () => {
    const mutated = receivePreimage.replace('"canonical_version":1', '"canonical_version":"1"');
    expect(sha256Hex(mutated)).not.toBe(SUITE_GOLDEN_OUTPUTS["zp-receive-expected-v1"].sha256);
  });

  it("#4 uppercase UUID changes the digest", () => {
    // node_id is all digits so uppercasing is a no-op; use reporting_key_id which has hex letters
    const registerPreimage = SUITE_GOLDEN_PREIMAGES["zp-reporting-register-v1"];
    const mutatedRegister = registerPreimage.replace(
      "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      "CCCCCCCC-CCCC-4CCC-8CCC-CCCCCCCCCCCC",
    );
    expect(mutatedRegister).not.toBe(registerPreimage);
    expect(sha256Hex(mutatedRegister)).not.toBe(SUITE_GOLDEN_OUTPUTS["zp-reporting-register-v1"].sha256);
  });

  it("#5 unpadded key changes the digest", () => {
    const mutated = receivePreimage.replace(
      "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=",
      "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E",
    );
    expect(sha256Hex(mutated)).not.toBe(SUITE_GOLDEN_OUTPUTS["zp-receive-expected-v1"].sha256);
  });

  it("#7 timestamp without three fractional digits changes the digest", () => {
    const approvalPreimage = SUITE_GOLDEN_PREIMAGES["zp-send-external-approval-v1"];
    const mutated = approvalPreimage.replace("2026-07-18T00:00:00.000Z", "2026-07-18T00:00:00.00Z");
    expect(sha256Hex(mutated)).not.toBe(SUITE_GOLDEN_OUTPUTS["zp-send-external-approval-v1"].sha256);
  });

  it("#8 trailing newline changes the digest", () => {
    expect(sha256Hex(`${receivePreimage}\n`)).not.toBe(SUITE_GOLDEN_OUTPUTS["zp-receive-expected-v1"].sha256);
  });

  it("#10 cross-purpose signature fails verification", () => {
    // Sign with device key but verify against node key — must fail
    const sig = edSign(receivePreimage, deviceKey);
    expect(edVerify(receivePreimage, sig, nodeKey)).toBe(false);
  });

  it("#11 transfer-code hash of decoded bytes differs from exact-string hash", () => {
    // The transfer_code_sha256 in the receive golden is the hash of the exact stored bytes
    // of the receive-code fixture, NOT the hash of the illustrative identifier
    const illustrativeHash = sha256Hex(FIXTURE_IDS.transfer_code);
    const receivePayload = JSON.parse(receiveJson) as { transfer_code_sha256: string };
    expect(receivePayload.transfer_code_sha256).not.toBe(illustrativeHash);
    expect(receivePayload.transfer_code_sha256).toBe(
      "104eb00c3bda958b82b7ce5a24e582dd9efa3e63d2192838fe26b5b23dcb2bab",
    );
  });

  it("#17 funded-sender genesis predecessor produces a different digest than the golden target", () => {
    const inner = JSON.parse(TARGET_STEP_1_PREIMAGE) as Record<string, unknown>;
    const genesisInner = { ...inner, previous_step_1_state_signature: "" };
    const genesisPreimage = JSON.stringify(genesisInner);
    expect(sha256Hex(genesisPreimage)).not.toBe(TARGET_DIGESTS.step_1_sha256);
    // But it IS the A.8.0 SEND partial (empty predecessor)
    expect(sha256Hex(SEND_PARTIAL_STEP_1_PREIMAGE)).toBe(SEND_PARTIAL_DIGESTS.step_1_sha256);
  });

  it("register #1 supersedes_key_id omitted changes the digest", () => {
    const registerPreimage = SUITE_GOLDEN_PREIMAGES["zp-reporting-register-v1"];
    const registerJson = registerPreimage.slice(registerPreimage.indexOf("\n") + 1);
    const dropped = registerJson.replace(',"supersedes_key_id":null', "");
    expect(sha256Hex(`zp-reporting-register-v1\n${dropped}`)).not.toBe(
      SUITE_GOLDEN_OUTPUTS["zp-reporting-register-v1"].sha256,
    );
  });

  it("register #4 window over 300s changes the digest", () => {
    const registerPreimage = SUITE_GOLDEN_PREIMAGES["zp-reporting-register-v1"];
    const mutated = registerPreimage.replace("2026-07-18T00:05:00.000Z", "2026-07-18T00:05:00.001Z");
    expect(sha256Hex(mutated)).not.toBe(SUITE_GOLDEN_OUTPUTS["zp-reporting-register-v1"].sha256);
  });
});

// --- Cross-validation: suite golden digests match the A.8.2 table ---
describe("the crypto-goldens freeze cross-validation against A.8.2 machine-output table", () => {
  it("all signed tuples have 64-char lowercase hex SHA-256 digests", () => {
    for (const [key, output] of Object.entries(SUITE_GOLDEN_OUTPUTS)) {
      expect(output.sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(key).toBeTruthy();
    }
  });

  it("all signed tuples have valid padded base64url signatures (88 chars, == padded)", () => {
    for (const [key, output] of Object.entries(SUITE_GOLDEN_OUTPUTS)) {
      if (output.signature === null) continue;
      expect(output.signature).toMatch(/^[A-Za-z0-9_-]{86}==$/);
      expect(key).toBeTruthy();
    }
  });

  it("signing key assignments match the A.8 role table", () => {
    expect(SUITE_GOLDEN_OUTPUTS["zp-receive-expected-v1"].signingKey).toBe("node");
    expect(SUITE_GOLDEN_OUTPUTS["zp-move-internal-expected-v1"].signingKey).toBe("node");
    expect(SUITE_GOLDEN_OUTPUTS["zp-send-external-expected-v1"].signingKey).toBe("node");
    expect(SUITE_GOLDEN_OUTPUTS["zp-send-external-approval-v1"].signingKey).toBe("device");
    expect(SUITE_GOLDEN_OUTPUTS["zp-destination-bless-v1"].signingKey).toBe("device");
    expect(SUITE_GOLDEN_OUTPUTS["zp-device-enrol-v1"].signingKey).toBe("device");
    expect(SUITE_GOLDEN_OUTPUTS["zp-report-request-v1"].signingKey).toBe("reporting");
    expect(SUITE_GOLDEN_OUTPUTS["zp-reporting-register-v1"].signingKey).toBe("reporting");
    expect(SUITE_GOLDEN_OUTPUTS["zp-node-event-v1-golden-a"].signingKey).toBe("node");
    expect(SUITE_GOLDEN_OUTPUTS["zp-node-event-v1-golden-b"].signingKey).toBe("node");
    expect(SUITE_GOLDEN_OUTPUTS["zp-wallet-head-fingerprint-v1"].signingKey).toBeNull();
  });
});

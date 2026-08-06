// form receive code + zp-receive-expected-v1 (steps 5–7).
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { buildReceiveExpectedArtifact } from "../protocol/suite/builders.js";
import { parseSha256Hex, parseUuid, parseWalletPublicKey } from "../protocol/scalars.js";
import { parsePositiveZkzAmount } from "../protocol/amounts.js";
import {
  RECEIVE_EXPECTED_ARTIFACT_PURPOSE,
  buildReceiverT0Fingerprint,
  classifyReceiveCodePhase,
  formReceiveCodeAndArtifact,
  type FormReceiveCodeInput,
  type NodeIdentitySigner,
  type ReceiveCodeFormationStore,
} from "./code-formation.js";

const GOLDEN_PREIMAGE = readFileSync(
  join(
    dirname(fileURLToPath(import.meta.url)),
    "../../../generic-node-contracts/goldens/artifacts/zp-receive-expected-v1.preimage.txt",
  ),
  "utf8",
);
const GOLDEN_DIGEST = readFileSync(
  join(
    dirname(fileURLToPath(import.meta.url)),
    "../../../generic-node-contracts/goldens/artifacts/zp-receive-expected-v1.digest.hex",
  ),
  "utf8",
).trim();
const GOLDEN_CODE = readFileSync(
  join(
    dirname(fileURLToPath(import.meta.url)),
    "../../../generic-node-contracts/goldens/transfer-code/receive-code.v1.b64url.txt",
  ),
  "utf8",
);

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IMPLEMENTER_ID = "22222222-2222-4222-8222-222222222222";
const OPERATION_ID = "33333333-3333-4333-8333-333333333333";
const WALLET_ID = "55555555-5555-4555-8555-555555555555";
const ARTIFACT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SIGNING_KEY_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const PUBKEY = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
const ANCHOR = "ord_7YQ3";
const AMOUNT = "2.25";
// Formation clock such that floor(now/1000)+ttl = 1784336400 with ttl=300.
const FORMATION_NOW_MS = (1_784_336_400 - 300) * 1000;
const TTL_BOUNDS = { defaultSecs: 300, minSecs: 60, maxSecs: 3600 } as const;

function paddedBase64Url(bytes: Buffer): string {
  return bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}

function nodeIdentitySignerFromSeed(byte: number): NodeIdentitySigner & { publicKey: string } {
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.alloc(32, byte),
  ]);
  const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const publicKey = paddedBase64Url(
    createPublicKey(privateKey).export({ type: "spki", format: "der" }).subarray(-32),
  );
  return {
    signingKeyId: SIGNING_KEY_ID,
    publicKey,
    sign(preimageBytes: Uint8Array): string {
      return paddedBase64Url(sign(null, Buffer.from(preimageBytes), privateKey));
    },
  };
}

class MemoryFormationStore implements ReceiveCodeFormationStore {
  preimage: {
    artifactId: string;
    operationId: string;
    preimageText: string;
    preimageSha256: string;
    signingKeyId: string | null;
    signature: string | null;
  } | null = null;
  signerAudit = false;
  codeComplete = false;
  signCalls: Uint8Array[] = [];

  async persistArtifactPreimage(
    input: Parameters<ReceiveCodeFormationStore["persistArtifactPreimage"]>[0],
  ) {
    if (this.preimage !== null) {
      if (
        this.preimage.preimageText !== input.preimageText ||
        this.preimage.preimageSha256 !== input.preimageSha256
      ) {
        throw new Error("preimage bytes diverged on re-persist");
      }
      return { artifactId: this.preimage.artifactId, alreadyPresent: true };
    }
    this.preimage = {
      artifactId: input.artifactId,
      operationId: input.operationId,
      preimageText: input.preimageText,
      preimageSha256: input.preimageSha256,
      signingKeyId: null,
      signature: null,
    };
    return { artifactId: input.artifactId, alreadyPresent: false };
  }

  async persistArtifactSignature(
    input: Parameters<ReceiveCodeFormationStore["persistArtifactSignature"]>[0],
  ) {
    if (this.preimage === null) throw new Error("no preimage");
    if (this.preimage.preimageSha256 !== input.expectedPreimageSha256) {
      throw new Error("signature digest mismatch");
    }
    this.preimage = {
      ...this.preimage,
      signingKeyId: input.signingKeyId,
      signature: input.signature,
    };
    this.signerAudit = true;
  }

  async loadArtifactPreimage(operationId: string) {
    if (this.preimage === null || this.preimage.operationId !== operationId) return null;
    return { ...this.preimage };
  }

  async hasSignerAuditForArtifact() {
    return this.signerAudit;
  }

  async hasCompleteCodeRecord() {
    return this.codeComplete;
  }
}

function baseInput(
  store: ReceiveCodeFormationStore,
  signer: NodeIdentitySigner,
  overrides: Partial<FormReceiveCodeInput> = {},
): FormReceiveCodeInput {
  return {
    nodeId: NODE_ID,
    implementerId: IMPLEMENTER_ID,
    operationId: OPERATION_ID,
    receiverWalletId: WALLET_ID,
    receiverPubkey: PUBKEY,
    amountZkz: AMOUNT,
    anchor: ANCHOR,
    afterLanding: { kind: "HOLD", destination_id: null },
    t0: {
      observationId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      s0: "",
      p0: "",
      b0: "0",
    },
    requestedTtlSecs: 300,
    ttlBounds: TTL_BOUNDS,
    nowUnixMs: FORMATION_NOW_MS,
    artifactId: ARTIFACT_ID,
    signer,
    store,
    ...overrides,
  };
}

describe("buildReceiverT0Fingerprint", () => {
  it("builds a non-zero genesis fingerprint for S0=P0=\"\" B0=\"0\"", () => {
    const fp = buildReceiverT0Fingerprint(PUBKEY, { s0: "", p0: "", b0: "0" });
    expect(fp.ok).toBe(true);
    if (!fp.ok) return;
    expect(fp.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(fp.fingerprint).not.toBe("0".repeat(64));
  });
});

describe("formReceiveCodeAndArtifact", () => {
  it("byte-matches the transfer code and binds its digest into the artifact", async () => {
    const store = new MemoryFormationStore();
    const signer = nodeIdentitySignerFromSeed(0x00);
    const result = await formReceiveCodeAndArtifact(baseInput(store, signer));
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.formed.transferCode.transferCodeText).toBe(GOLDEN_CODE);
    expect(result.formed.transferCode.transferCodeSha256).toBe(
      createHash("sha256").update(GOLDEN_CODE, "utf8").digest("hex"),
    );
    expect(result.formed.expiryUnixTimeSecs).toBe("1784336400");
    expect(result.formed.artifact.envelope.preimage_text.startsWith("zp-receive-expected-v1\n")).toBe(
      true,
    );
    expect(result.formed.artifact.envelope.preimage_sha256).toBe(
      createHash("sha256")
        .update(result.formed.artifact.envelope.preimage_text, "utf8")
        .digest("hex"),
    );
    // transfer_code_sha256 field inside the preimage equals the code digest.
    const payload = JSON.parse(
      result.formed.artifact.envelope.preimage_text.slice(
        result.formed.artifact.envelope.preimage_text.indexOf("\n") + 1,
      ),
    ) as { transfer_code_sha256: string; purpose: string; canonical_version: number };
    expect(payload.purpose).toBe(RECEIVE_EXPECTED_ARTIFACT_PURPOSE);
    expect(payload.canonical_version).toBe(1);
    expect(payload.transfer_code_sha256).toBe(result.formed.transferCode.transferCodeSha256);
  });

  it("persists preimage before signature (two separate store writes)", async () => {
    const writeSequence: string[] = [];
    const store = new MemoryFormationStore();
    const origPre = store.persistArtifactPreimage.bind(store);
    const origSig = store.persistArtifactSignature.bind(store);
    store.persistArtifactPreimage = async (input) => {
      writeSequence.push("preimage");
      expect(store.preimage).toBeNull();
      return origPre(input);
    };
    store.persistArtifactSignature = async (input) => {
      writeSequence.push("signature");
      expect(store.preimage).not.toBeNull();
      expect(store.preimage?.signature).toBeNull();
      return origSig(input);
    };
    const signer = nodeIdentitySignerFromSeed(0x00);
    const result = await formReceiveCodeAndArtifact(baseInput(store, signer));
    expect(result.ok).toBe(true);
    expect(writeSequence).toEqual(["preimage", "signature"]);
    expect(store.preimage?.signature).toBeTruthy();
  });

  it("idempotent signing: crash between preimage and signature resumes on identical bytes", async () => {
    const store = new MemoryFormationStore();
    const signer = nodeIdentitySignerFromSeed(0x00);
    const seenPreimages: string[] = [];

    // First attempt: persist preimage then fail the signer.
    const failingSigner: NodeIdentitySigner = {
      signingKeyId: SIGNING_KEY_ID,
      sign(preimageBytes) {
        seenPreimages.push(Buffer.from(preimageBytes).toString("utf8"));
        throw new Error("simulated crash after preimage");
      },
    };
    const first = await formReceiveCodeAndArtifact(baseInput(store, failingSigner));
    expect(first.ok).toBe(false);
    if (first.ok) return;
    expect(first.reason).toBe("signer_rejected");
    expect(store.preimage).not.toBeNull();
    expect(store.preimage?.signature).toBeNull();
    const durablePreimage = store.preimage!.preimageText;

    // Resume: signer must see the identical stored preimage, never a re-derived one.
    const resumeSigner: NodeIdentitySigner = {
      signingKeyId: SIGNING_KEY_ID,
      sign(preimageBytes) {
        const text = Buffer.from(preimageBytes).toString("utf8");
        seenPreimages.push(text);
        expect(text).toBe(durablePreimage);
        return signer.sign(preimageBytes) as string;
      },
    };
    const second = await formReceiveCodeAndArtifact(baseInput(store, resumeSigner));
    expect(second.ok).toBe(true);
    if (!second.ok) return;
    expect(second.formed.artifact.envelope.preimage_text).toBe(durablePreimage);
    expect(seenPreimages[0]).toBe(seenPreimages[1]);
  });

  it("OPS resume freezes expiry from durable preimage when clock advances ≥1s", async () => {
    // Regression: resume re-derived expiry from nowUnixMs, so a ≥1s wall-clock
    // advance rebuilt a different transfer_code_sha256 and rejected the durable unsigned
    // preimage with preimage_bytes_diverged instead of signing the identical bytes.
    const store = new MemoryFormationStore();
    const signer = nodeIdentitySignerFromSeed(0x00);
    const seenPreimages: string[] = [];

    const failingSigner: NodeIdentitySigner = {
      signingKeyId: SIGNING_KEY_ID,
      sign(preimageBytes) {
        seenPreimages.push(Buffer.from(preimageBytes).toString("utf8"));
        throw new Error("simulated crash after preimage");
      },
    };
    const first = await formReceiveCodeAndArtifact(
      baseInput(store, failingSigner, { nowUnixMs: FORMATION_NOW_MS }),
    );
    expect(first.ok).toBe(false);
    if (first.ok) return;
    expect(first.reason).toBe("signer_rejected");
    expect(store.preimage).not.toBeNull();
    expect(store.preimage?.signature).toBeNull();
    const durablePreimage = store.preimage!.preimageText;
    const durablePayload = JSON.parse(
      durablePreimage.slice(durablePreimage.indexOf("\n") + 1),
    ) as { expiry_unix_time_secs: string; transfer_code_sha256: string };
    expect(durablePayload.expiry_unix_time_secs).toBe("1784336400");

    const resumeSigner: NodeIdentitySigner = {
      signingKeyId: SIGNING_KEY_ID,
      sign(preimageBytes) {
        const text = Buffer.from(preimageBytes).toString("utf8");
        seenPreimages.push(text);
        expect(text).toBe(durablePreimage);
        return signer.sign(preimageBytes) as string;
      },
    };
    const second = await formReceiveCodeAndArtifact(
      baseInput(store, resumeSigner, { nowUnixMs: FORMATION_NOW_MS + 1000 }),
    );
    expect(second.ok).toBe(true);
    if (!second.ok) return;
    expect(second.formed.artifact.envelope.preimage_text).toBe(durablePreimage);
    expect(second.formed.expiryUnixTimeSecs).toBe(durablePayload.expiry_unix_time_secs);
    expect(second.formed.transferCode.transferCodeSha256).toBe(
      durablePayload.transfer_code_sha256,
    );
    expect(seenPreimages[0]).toBe(seenPreimages[1]);
    expect(seenPreimages[0]).toBe(durablePreimage);
  });

  it("byte-golden: A.3.1 field sequence matches the frozen suite builder against fixed inputs", () => {
    // The frozen A.8 golden uses receiver_t0_fingerprint of 64 zeros (illustrative T0).
    // Production formation binds the real A.7 digest; this test freezes the builder path
    // against the same field sequence/values the golden encodes (except the fingerprint slot
    // is supplied explicitly so the preimage is byte-comparable to a captured fixture).
    const fp = "0".repeat(64);
    const built = buildReceiveExpectedArtifact({
      node_id: parseUuid(NODE_ID),
      implementer_id: parseUuid(IMPLEMENTER_ID),
      operation_id: parseUuid(OPERATION_ID),
      receiver_wallet_id: parseUuid(WALLET_ID),
      receiver_pubkey: parseWalletPublicKey(PUBKEY),
      amount_zkz: parsePositiveZkzAmount(AMOUNT),
      discriminator: parseUuid(OPERATION_ID),
      anchor: ANCHOR,
      receiver_t0_fingerprint: parseSha256Hex(fp),
      expiry_unix_time_secs: "1784336400" as never,
      after_landing: { kind: "HOLD", destination_id: null },
      transfer_code_sha256: parseSha256Hex(
        createHash("sha256").update(GOLDEN_CODE, "utf8").digest("hex"),
      ),
    });
    expect(built.preimageText).toBe(GOLDEN_PREIMAGE);
    expect(built.sha256).toBe(GOLDEN_DIGEST);
  });

  it("A.9 negatives: field reorder / omitted-null / wrong canonical_version change the digest", () => {
    const fp = buildReceiverT0Fingerprint(PUBKEY, { s0: "", p0: "", b0: "0" });
    expect(fp.ok).toBe(true);
    if (!fp.ok) return;
    const codeSha = createHash("sha256").update(GOLDEN_CODE, "utf8").digest("hex");
    const canonical = buildReceiveExpectedArtifact({
      node_id: parseUuid(NODE_ID),
      implementer_id: parseUuid(IMPLEMENTER_ID),
      operation_id: parseUuid(OPERATION_ID),
      receiver_wallet_id: parseUuid(WALLET_ID),
      receiver_pubkey: parseWalletPublicKey(PUBKEY),
      amount_zkz: parsePositiveZkzAmount(AMOUNT),
      discriminator: parseUuid(OPERATION_ID),
      anchor: ANCHOR,
      receiver_t0_fingerprint: fp.fingerprint,
      expiry_unix_time_secs: "1784336400" as never,
      after_landing: { kind: "HOLD", destination_id: null },
      transfer_code_sha256: parseSha256Hex(codeSha),
    });

    // Reorder: purpose after amount
    const reordered =
      'zp-receive-expected-v1\n{"canonical_version":1,"amount_zkz":"2.25","purpose":"zp-receive-expected-v1"}';
    expect(createHash("sha256").update(reordered, "utf8").digest("hex")).not.toBe(
      canonical.sha256,
    );

    // Omitted nullable expiry (must be present as null)
    const omitted = canonical.preimageText.replace(
      '"expiry_unix_time_secs":"1784336400",',
      "",
    );
    expect(omitted).not.toBe(canonical.preimageText);
    expect(createHash("sha256").update(omitted, "utf8").digest("hex")).not.toBe(canonical.sha256);

    // Wrong canonical_version type (string "1")
    const wrongType = canonical.preimageText.replace(
      '"canonical_version":1',
      '"canonical_version":"1"',
    );
    expect(createHash("sha256").update(wrongType, "utf8").digest("hex")).not.toBe(
      canonical.sha256,
    );
  });

  it("rejects zero-form amounts via validateOperationAmount", async () => {
    const store = new MemoryFormationStore();
    const signer = nodeIdentitySignerFromSeed(0x00);
    for (const amount of ["0", "0.0", "999999999"]) {
      // 999999999 is >= 1e8 exclusive bound when parsed as operation amount? 1e8-1 max int part is 99999999
      const result = await formReceiveCodeAndArtifact(
        baseInput(store, signer, { amountZkz: amount }),
      );
      expect(result.ok).toBe(false);
    }
    // magnitude ≥ 1e8
    const big = await formReceiveCodeAndArtifact(
      baseInput(store, signer, { amountZkz: "100000000" }),
    );
    expect(big.ok).toBe(false);
  });
});

describe("classifyReceiveCodePhase", () => {
  it("NO_PREIMAGE when nothing durable and no signer audit", async () => {
    const store = new MemoryFormationStore();
    expect(await classifyReceiveCodePhase(store, OPERATION_ID)).toBe("NO_PREIMAGE");
  });

  it("PREIMAGE_UNSIGNED when preimage exists, signature absent, no audit", async () => {
    const store = new MemoryFormationStore();
    await store.persistArtifactPreimage({
      artifactId: ARTIFACT_ID,
      operationId: OPERATION_ID,
      purpose: RECEIVE_EXPECTED_ARTIFACT_PURPOSE,
      canonicalVersion: 1,
      preimageText: "zp-receive-expected-v1\n{}",
      preimageSha256: "a".repeat(64),
    });
    expect(await classifyReceiveCodePhase(store, OPERATION_ID)).toBe("PREIMAGE_UNSIGNED");
  });

  it("INVARIANT_BREACH when signer audit without matching byte record", async () => {
    const store = new MemoryFormationStore();
    store.signerAudit = true;
    expect(await classifyReceiveCodePhase(store, OPERATION_ID)).toBe("INVARIANT_BREACH");
  });

  it("INVARIANT_BREACH when preimage unsigned but signer audit says called", async () => {
    const store = new MemoryFormationStore();
    await store.persistArtifactPreimage({
      artifactId: ARTIFACT_ID,
      operationId: OPERATION_ID,
      purpose: RECEIVE_EXPECTED_ARTIFACT_PURPOSE,
      canonicalVersion: 1,
      preimageText: "zp-receive-expected-v1\n{}",
      preimageSha256: "a".repeat(64),
    });
    store.signerAudit = true;
    expect(await classifyReceiveCodePhase(store, OPERATION_ID)).toBe("INVARIANT_BREACH");
  });

  it("CODE_COMPLETE_STATE_PENDING when artifact+code durable", async () => {
    const store = new MemoryFormationStore();
    const signer = nodeIdentitySignerFromSeed(0x00);
    const formed = await formReceiveCodeAndArtifact(baseInput(store, signer));
    expect(formed.ok).toBe(true);
    store.codeComplete = true;
    expect(await classifyReceiveCodePhase(store, OPERATION_ID)).toBe(
      "CODE_COMPLETE_STATE_PENDING",
    );
  });

  it("ARTIFACT_COMPLETE when signed preimage exists but code row does not", async () => {
    const store = new MemoryFormationStore();
    const signer = nodeIdentitySignerFromSeed(0x00);
    const formed = await formReceiveCodeAndArtifact(baseInput(store, signer));
    expect(formed.ok).toBe(true);
    store.codeComplete = false;
    expect(await classifyReceiveCodePhase(store, OPERATION_ID)).toBe("ARTIFACT_COMPLETE");
  });
});

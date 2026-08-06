import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { BigNumber } from "bignumber.js";
import { describe, expect, it } from "vitest";

const paddedBase64Url = (bytes: Buffer): string =>
  bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
const sha256 = (value: Buffer | string): string =>
  createHash("sha256")
    .update(typeof value === "string" ? Buffer.from(value, "utf8") : value)
    .digest("hex");
const keyFromSeed = (byte: number) => {
  const der = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.alloc(32, byte),
  ]);
  return createPrivateKey({ key: der, type: "pkcs8", format: "der" });
};
const publicKey = (privateKey: ReturnType<typeof keyFromSeed>): string =>
  paddedBase64Url(createPublicKey(privateKey).export({ type: "spki", format: "der" }).subarray(-32));
const signature = (text: string, privateKey: ReturnType<typeof keyFromSeed>): string =>
  paddedBase64Url(sign(null, Buffer.from(text, "utf8"), privateKey));

const seed02 = keyFromSeed(0x02);
const seed03 = keyFromSeed(0x03);
const seed05 = keyFromSeed(0x05);
const seed02Public = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
const seed03Public = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
const seed05Public = "bnoc3Smwt4_ROvTFWY_v9O8qlxZuPKby5Pv8zYBQW_E=";
const seed05BoundaryS =
  "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQ==";

const buildPredecessorInner = () => ({
  type: "unique_combinable",
  version: "2",
  unix_time_secs: "1784332700",
  signer_steps: 2,
  step_1_signer: "sender",
  step_2_signer: "receiver",
  step_1_key_public__base64urlsafe: seed05Public,
  step_2_key_public__base64urlsafe: seed02Public,
  step_1_state: { amount: "0" },
  step_2_state: { amount: "10" },
  previous_step_1_state_signature: seed05BoundaryS,
  previous_step_2_state_signature: "",
});

const predecessorInner = buildPredecessorInner();
const predecessorStep1 = JSON.stringify(predecessorInner);
const predecessorStep1Signature =
  "MsWTpjUtoofWFb13BCpLqLB6tgYiasFakfd2hufS2V2dHg7N2PdRe8n-wrqQhJKc3-Bml7xK6jUfEv2BBiPxAA==";
const predecessorStep2 = JSON.stringify({
  inner: predecessorInner,
  step_1_signature: predecessorStep1Signature,
});
const predecessorStep2Signature =
  "IfsGs-NrmBAQ6VWohtlXDcyrd830Agx1IzW8rcHiqYqndeGLoG8b297PjqC-grrIXFrl3GgDcV2qi6xJBlerCQ==";
const predecessorSettled = JSON.stringify({
  inner: predecessorInner,
  step_1_signature: predecessorStep1Signature,
  step_2_signature: predecessorStep2Signature,
});

const buildTargetInner = (
  senderPredecessor: string,
  balances: Readonly<{ senderPost: string; receiverPost: string }> = {
    senderPost: "7.75",
    receiverPost: "2.25",
  },
) => ({
  type: "unique_combinable",
  version: "2",
  unix_time_secs: "1784332800.125",
  signer_steps: 2,
  step_1_signer: "sender",
  step_2_signer: "receiver",
  step_1_key_public__base64urlsafe: seed02Public,
  step_2_key_public__base64urlsafe: seed03Public,
  step_1_state: { amount: balances.senderPost },
  step_2_state: { amount: balances.receiverPost },
  previous_step_1_state_signature: senderPredecessor,
  previous_step_2_state_signature: "",
  expiry__unix_time_secs: "1784336400",
  message: "zp1:33333333-3333-4333-8333-333333333333:ord_7YQ3",
});

const targetInner = buildTargetInner(predecessorStep2Signature);
const targetStep1 = JSON.stringify(targetInner);
const targetStep1Signature =
  "wpAPEHD-wRRyfdoLM5FUgwS5OhCVwkQBV5w-XFDSx_VK19QiW5szD6Cuy1ogiNlIlvWtx4LlZPIdAm81eKX0BA==";
const targetStep2 = JSON.stringify({ inner: targetInner, step_1_signature: targetStep1Signature });
const targetStep2Signature =
  "uP0HeCG-ZT1svQK-drwexhc1mrxx4QLBdfgFlw8nqRrwwvcJcPazgcPxp8aMdz7iJricO75II0bUzvwlBUUDDw==";
const targetSettled = JSON.stringify({
  inner: targetInner,
  step_1_signature: targetStep1Signature,
  step_2_signature: targetStep2Signature,
});

const receiverHeadPayload = {
  purpose: "zp-wallet-head-fingerprint-v1",
  canonical_version: 1,
  wallet_public_key: seed03Public,
  state_kind: "HEAD",
  s_signature: targetStep2Signature,
  p_signature: "",
  b_amount: "2.25",
  inner_sha256: "ce0741df9ed652b25d0294746c67acd6d9ecb4e3318c3691582fc2acdd52be51",
  step_1_signature: targetStep1Signature,
  step_2_signature: targetStep2Signature,
};
const receiverHeadPreimage = `${receiverHeadPayload.purpose}\n${JSON.stringify(receiverHeadPayload)}`;

const artifactDir = fileURLToPath(new URL("./gen/", import.meta.url));
const readArtifact = (name: string): string => readFileSync(new URL(`./gen/${name}`, import.meta.url), "utf8");

describe("RECEIVE golden byte freeze", () => {
  it("derives the three wallet public keys independently from filled-byte Ed25519 seeds", () => {
    expect(publicKey(seed02)).toBe(seed02Public);
    expect(publicKey(seed03)).toBe(seed03Public);
    expect(publicKey(seed05)).toBe(seed05Public);
  });

  it("freezes every raw artifact without a trailing LF", () => {
    const expected = {
      "predecessor.step-1.json": predecessorStep1,
      "predecessor.step-2.json": predecessorStep2,
      "predecessor.settled.json": predecessorSettled,
      "target.step-1.json": targetStep1,
      "target.step-2.json": targetStep2,
      "target.settled.json": targetSettled,
      "receiver-head-fingerprint.txt": receiverHeadPreimage,
    };
    expect(readdirSync(artifactDir).sort()).toEqual([...Object.keys(expected), "manifest.json"].sort());
    for (const [name, bytes] of Object.entries(expected)) {
      const raw = readArtifact(name);
      expect(raw).toBe(bytes);
      expect(raw.endsWith("\n")).toBe(false);
    }
    expect(readArtifact("manifest.json").endsWith("\n")).toBe(false);
  });

  it("verifies the fully modeled predecessor signatures and exact digests", () => {
    expect(sha256(predecessorStep1)).toBe("9bda00a6bbb423a2ea3a9ee2660742dded80562ad58acde106097e2be0583bec");
    expect(signature(predecessorStep1, seed05)).toBe(predecessorStep1Signature);
    expect(
      verify(
        null,
        Buffer.from(predecessorStep1, "utf8"),
        createPublicKey(seed05),
        Buffer.from(predecessorStep1Signature, "base64url"),
      ),
    ).toBe(true);
    expect(sha256(predecessorStep2)).toBe("07c6dd592f1dd3aa4e70c58f6ab2f92beaa4153d988ae240e6266c41afa22ce5");
    expect(signature(predecessorStep2, seed02)).toBe(predecessorStep2Signature);
    expect(
      verify(
        null,
        Buffer.from(predecessorStep2, "utf8"),
        createPublicKey(seed02),
        Buffer.from(predecessorStep2Signature, "base64url"),
      ),
    ).toBe(true);
    expect(sha256(predecessorSettled)).toBe("51dd611df7564d3cac3bdf8a3415ce9326ee29b920daa1338447c57a4c78505b");
    expect(Buffer.from(seed05BoundaryS, "base64url")).toHaveLength(64);
    expect(paddedBase64Url(Buffer.from(seed05BoundaryS, "base64url"))).toBe(seed05BoundaryS);
  });

  it("links the funded sender exactly and freezes the target transaction bytes", () => {
    expect(targetInner.previous_step_1_state_signature).toBe(predecessorStep2Signature);
    expect(targetInner.previous_step_2_state_signature).toBe("");
    expect(sha256(targetStep1)).toBe("ce0741df9ed652b25d0294746c67acd6d9ecb4e3318c3691582fc2acdd52be51");
    expect(signature(targetStep1, seed02)).toBe(targetStep1Signature);
    expect(sha256(targetStep2)).toBe("163d8ef498c09a58d621ed2673c50ed89e79272fcfd14251661c36940e1bb9d0");
    expect(signature(targetStep2, seed03)).toBe(targetStep2Signature);
    expect(sha256(targetSettled)).toBe("5554ffa03050cb94173406a85a50aa72c4eca604ab630f0511e61bec7969aebf");
    expect(sha256(receiverHeadPreimage)).toBe("d03a98b770684e577667f9bde01276b196b98db31663f23b0900623d6dffca2a");
  });
});

describe("preserved artifact-freeze digest pins", () => {
  const suiteDigest = (payload: { purpose: string }): string =>
    sha256(`${payload.purpose}\n${JSON.stringify(payload)}`);
  const sourceSelector = {
    kind: "WALLET_ID",
    wallet_id: "55555555-5555-4555-8555-555555555555",
  };

  it("keeps RECEIVE, MOVE, SEND, approval, and transfer-code hashes unchanged", () => {
    const transferCodeHash = "104eb00c3bda958b82b7ce5a24e582dd9efa3e63d2192838fe26b5b23dcb2bab";
    const receive = {
      purpose: "zp-receive-expected-v1",
      canonical_version: 1,
      node_id: "11111111-1111-4111-8111-111111111111",
      implementer_id: "22222222-2222-4222-8222-222222222222",
      operation_id: "33333333-3333-4333-8333-333333333333",
      receiver_wallet_id: "55555555-5555-4555-8555-555555555555",
      receiver_pubkey: seed03Public,
      amount_zkz: "2.25",
      discriminator: "33333333-3333-4333-8333-333333333333",
      anchor: "ord_7YQ3",
      receiver_t0_fingerprint: "0".repeat(64),
      expiry_unix_time_secs: "1784336400",
      after_landing: { kind: "HOLD", destination_id: null },
      transfer_code_sha256: transferCodeHash,
    };
    const move = {
      purpose: "zp-move-internal-expected-v1",
      canonical_version: 1,
      node_id: "11111111-1111-4111-8111-111111111111",
      implementer_id: "22222222-2222-4222-8222-222222222222",
      operation_id: "33333333-3333-4333-8333-333333333333",
      source_wallet_id: "55555555-5555-4555-8555-555555555555",
      source_pubkey: seed02Public,
      destination_id: "66666666-6666-4666-8666-666666666666",
      destination_wallet_id: "44444444-4444-4444-8444-444444444444",
      destination_pubkey: seed03Public,
      amount_zkz: "2.25",
      spawned_from_operation_id: null,
      references_operation_id: null,
    };
    const sendExpected = {
      purpose: "zp-send-external-expected-v1",
      canonical_version: 1,
      node_id: "11111111-1111-4111-8111-111111111111",
      implementer_id: "22222222-2222-4222-8222-222222222222",
      operation_id: "33333333-3333-4333-8333-333333333333",
      source_selector: sourceSelector,
      source_pubkey: seed02Public,
      destination_address: seed03Public,
      amount_zkz: "2.25",
      references_operation_id: null,
    };
    const approval = {
      purpose: "zp-send-external-approval-v1",
      canonical_version: 1,
      node_id: "11111111-1111-4111-8111-111111111111",
      operation_id: "33333333-3333-4333-8333-333333333333",
      source_selector: sourceSelector,
      source_pubkey: seed02Public,
      destination_address: seed03Public,
      amount_zkz: "2.25",
      references_operation_id: null,
      nonce: "99999999-9999-4999-8999-999999999999",
      issued_at: "2026-07-18T00:00:00.000Z",
      expires_at: "2026-07-18T00:05:00.000Z",
    };

    expect(suiteDigest(receive)).toBe("f49635f02d8de86c5b4324f13520cc38c094d79ee2c0df5df60547c590ede498");
    expect(suiteDigest(move)).toBe("ad964723e07ca2aef3356f1e02990e07b90be49b5387a7095091398a10944a14");
    expect(suiteDigest(sendExpected)).toBe("f094f981f833c908fae1fa661cb6d9f6c3cdf29bab792f2660b866c588f22cb5");
    expect(suiteDigest(approval)).toBe("d7c03561bd9bc87e302c533f03741c34d44058fc0aaf1b59b17a4f28f8022146");
    expect(transferCodeHash).toBe("104eb00c3bda958b82b7ce5a24e582dd9efa3e63d2192838fe26b5b23dcb2bab");
  });
});

// -----------------------------------------------------------------------------------------
// Negative vectors — committed STATIC adversarial fixtures, not runtime proof.
//
// Runtime semantic enforcement of the receive pre-sign boundary (funded-sender backlink and
// exact-balance/delta conservation) is DEFERRED to the external-partial-intake concern
// ("Implement external partial intake, co-sign, and single submit"; acceptance: "every invalid
// or indeterminate candidate fails before co-sign"). No reusable pre-sign semantic validator
// exists in this contracts package or in the (skeleton-only) @zucoins/node-core runtime yet,
// and this package's dependency-boundary/CONTRACT_FREEZE gate forbids the fresh-read sender
// preflight such a validator requires — so this file does NOT assert runtime rejection with a
// test-local mock. It freezes each adversarial candidate byte-exact, proves it is a *validly
// re-signed* but structurally/economically invalid RECEIVE target, and records the
// external-partial-intake concern as the integration owner via the negative-vectors manifest.
// That concern MUST feed these fixtures through the real validator once it lands.
const readNegative = (name: string): string =>
  readFileSync(new URL(`./negative-vectors/${name}`, import.meta.url), "utf8");

const NEGATIVE_REJECTIONS = [
  "funded-sender/genesis-predecessor",
  "sender-amount-mismatch",
  "receiver-amount-mismatch",
] as const;
type NegativeRejection = (typeof NEGATIVE_REJECTIONS)[number];

type NegativeManifestVector = Readonly<{
  name: string;
  inner_file: string;
  step_1_signature_file: string;
  inner_sha256: string;
  step_1_signature: string;
  defect: string;
  expected_rejection: string;
  canonical_source: string;
}>;
type NegativeManifest = Readonly<{
  runtime_enforcement: Readonly<{ status: string; owner: string; owner_title: string }>;
  preflight: Readonly<{ sender_balance_zkz: string; receiver_t0_balance_zkz: string; expected_amount_zkz: string }>;
  positive_target_step_1_sha256: string;
  vectors: readonly NegativeManifestVector[];
}>;

const negativeManifest = JSON.parse(readNegative("manifest.json")) as NegativeManifest;

// The exact adversarial inner each committed fixture must equal, reconstructed from the same
// seed primitives as the positive target so a hand-fabricated fixture cannot pass. Each entry
// mutates exactly ONE property away from the frozen positive target.
const negativeReconstruction: Readonly<
  Record<string, Readonly<{ inner: ReturnType<typeof buildTargetInner>; expectedRejection: NegativeRejection }>>
> = {
  "funded-sender-genesis-predecessor": {
    inner: buildTargetInner(""),
    expectedRejection: "funded-sender/genesis-predecessor",
  },
  "wrong-sender-balance": {
    inner: buildTargetInner(predecessorStep2Signature, { senderPost: "7.74", receiverPost: "2.25" }),
    expectedRejection: "sender-amount-mismatch",
  },
  "wrong-receiver-balance": {
    inner: buildTargetInner(predecessorStep2Signature, { senderPost: "7.75", receiverPost: "2.24" }),
    expectedRejection: "receiver-amount-mismatch",
  },
};

describe("negative vectors are committed static adversarial fixtures", () => {
  it("records the external-partial-intake concern as the deferred runtime-enforcement owner and never claims rejection here", () => {
    expect(negativeManifest.runtime_enforcement.status).toBe("DEFERRED");
    expect(negativeManifest.runtime_enforcement.owner).toBe("external-partial-intake");
    expect(negativeManifest.preflight).toEqual({
      sender_balance_zkz: "10",
      receiver_t0_balance_zkz: "0",
      expected_amount_zkz: "2.25",
    });
    expect(negativeManifest.positive_target_step_1_sha256).toBe(
      "ce0741df9ed652b25d0294746c67acd6d9ecb4e3318c3691582fc2acdd52be51",
    );
    expect(negativeManifest.vectors.map((vector) => vector.name)).toEqual(Object.keys(negativeReconstruction));
  });

  it("pins the funded-sender classification to canonical negative vector 17", () => {
    const vector17 = negativeManifest.vectors.find((vector) => vector.name === "funded-sender-genesis-predecessor");
    expect(vector17?.expected_rejection).toBe("funded-sender/genesis-predecessor");
    expect(vector17?.canonical_source).toContain("vector 17");
  });

  it.each(negativeManifest.vectors)(
    "freezes $name: committed bytes reconstruct, its step-1 signature is valid, and it is not the golden",
    (vector) => {
      const rebuilt = negativeReconstruction[vector.name];
      if (!rebuilt) throw new Error(`no reconstruction for negative vector ${vector.name}`);
      const expectedInnerText = JSON.stringify(rebuilt.inner);

      const committedInner = readNegative(vector.inner_file);
      expect(committedInner).toBe(expectedInnerText);
      expect(committedInner.endsWith("\n")).toBe(false);
      expect(sha256(committedInner)).toBe(vector.inner_sha256);

      // A genuinely distinct object — never the frozen positive RECEIVE target.
      expect(vector.inner_sha256).not.toBe(negativeManifest.positive_target_step_1_sha256);

      // Validly re-signed: signature verification alone must NOT make the candidate acceptable.
      // That gap is exactly what the deferred external-partial-intake semantic validator has to close.
      const committedSignature = readNegative(vector.step_1_signature_file);
      expect(committedSignature).toBe(vector.step_1_signature);
      expect(committedSignature.endsWith("\n")).toBe(false);
      expect(
        verify(
          null,
          Buffer.from(committedInner, "utf8"),
          createPublicKey(seed02),
          Buffer.from(committedSignature, "base64url"),
        ),
      ).toBe(true);

      expect(NEGATIVE_REJECTIONS).toContain(vector.expected_rejection);
      expect(vector.expected_rejection).toBe(rebuilt.expectedRejection);
    },
  );

  it.each(negativeManifest.vectors)(
    "isolates the exact defect in $name against the frozen preflight",
    (vector) => {
      const inner = JSON.parse(readNegative(vector.inner_file)) as ReturnType<typeof buildTargetInner>;
      const senderBalance = new BigNumber(negativeManifest.preflight.sender_balance_zkz);
      const receiverT0Balance = new BigNumber(negativeManifest.preflight.receiver_t0_balance_zkz);
      const amount = new BigNumber(negativeManifest.preflight.expected_amount_zkz);
      const senderDebit = senderBalance.minus(inner.step_1_state.amount);
      const receiverCredit = new BigNumber(inner.step_2_state.amount).minus(receiverT0Balance);
      const fundedPredecessor = inner.previous_step_1_state_signature !== "";

      if (vector.name === "funded-sender-genesis-predecessor") {
        // ONLY the backlink is wrong: a funded sender with an empty genesis predecessor while
        // both balance deltas still conserve exactly — isolating vector 17 from the balance ones.
        expect(fundedPredecessor).toBe(false);
        expect(senderDebit.isEqualTo(amount)).toBe(true);
        expect(receiverCredit.isEqualTo(amount)).toBe(true);
      } else if (vector.name === "wrong-sender-balance") {
        expect(fundedPredecessor).toBe(true);
        expect(senderDebit.isEqualTo("2.26")).toBe(true);
        expect(senderDebit.isEqualTo(amount)).toBe(false);
        expect(receiverCredit.isEqualTo(amount)).toBe(true);
      } else {
        expect(fundedPredecessor).toBe(true);
        expect(senderDebit.isEqualTo(amount)).toBe(true);
        expect(receiverCredit.isEqualTo("2.24")).toBe(true);
        expect(receiverCredit.isEqualTo(amount)).toBe(false);
      }
    },
  );
});

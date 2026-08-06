import { beforeAll, describe, expect, it } from "vitest";

import { ready, keypairFromSeedByte, encodeBase64Url, digestPreimage } from "../testkit/independentCrypto.ts";
import { defaultSuiteVerificationCrypto } from "../testkit/suiteVerificationCrypto.ts";
import { readGoldenText, sha256OfGolden } from "../testkit/byteGolden.ts";
import { verifyExpectedArtifact, type ArtifactEnvelope, type VerifyRejectReason } from "./verify.ts";
import { type NodeIdentityKeyRecord } from "./signing-contract.ts";
import { EXPECTED_ARTIFACT_PURPOSES } from "./expected-artifacts.contract.ts";

const NODE_PUB = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=";
let devicePub: string;

beforeAll(async () => {
  await ready();
  devicePub = encodeBase64Url(keypairFromSeedByte(0x01).publicKey);
});

const nodeKey = (over: Partial<NodeIdentityKeyRecord> = {}): NodeIdentityKeyRecord => ({
  keyId: "node-identity-golden",
  role: "node_identity",
  publicKeyB64: NODE_PUB,
  status: "ACTIVE",
  validFromUnixMs: 0,
  validUntilUnixMs: null,
  ...over,
});

const load = (purpose: string): { prefix: string; payload: Record<string, unknown>; sig: string } => {
  const pre = readGoldenText(`artifacts/${purpose}.preimage.txt`);
  const nl = pre.indexOf("\n");
  return {
    prefix: pre.slice(0, nl),
    payload: JSON.parse(pre.slice(nl + 1)) as Record<string, unknown>,
    sig: readGoldenText(`artifacts/${purpose}.sig.b64`),
  };
};

const envelopeFrom = (prefix: string, payload: Record<string, unknown>, sig: string): ArtifactEnvelope => {
  const preimage_text = `${prefix}\n${JSON.stringify(payload)}`;
  return { key_id: "node-identity-golden", preimage_text, preimage_sha256: digestPreimage(preimage_text), signature: sig };
};

describe("golden byte-integrity (the artifacts golden integrity)", () => {
  it("every recorded golden file digest matches the on-disk bytes", () => {
    for (const purpose of EXPECTED_ARTIFACT_PURPOSES) {
      const meta = JSON.parse(readGoldenText(`artifacts/${purpose}.meta.json`)) as {
        artifact_digest_sha256: string;
        files: Record<string, { sha256: string }>;
      };
      for (const [fileName, entry] of Object.entries(meta.files)) {
        expect(sha256OfGolden(`artifacts/${fileName}`)).toBe(entry.sha256);
      }
      // A.8 invariant: the preimage file's own SHA-256 equals the artifact's pinned digest.
      expect(sha256OfGolden(`artifacts/${purpose}.preimage.txt`)).toBe(meta.artifact_digest_sha256);
      expect(readGoldenText(`artifacts/${purpose}.digest.hex`)).toBe(meta.artifact_digest_sha256);
    }
  });

  it("the node identity pubkey golden matches its provenance record", () => {
    const meta = JSON.parse(readGoldenText("artifacts/node-identity.pub.meta.json")) as {
      sha256: string;
      public_key_b64: string;
    };
    expect(sha256OfGolden("artifacts/node-identity.pub.b64")).toBe(meta.sha256);
    expect(readGoldenText("artifacts/node-identity.pub.b64")).toBe(meta.public_key_b64);
    expect(meta.public_key_b64).toBe(NODE_PUB);
  });
});

describe("mutation vectors: each MUST fail verification (the artifacts golden integrity, A.9)", () => {
  const expectReject = async (input: Parameters<typeof verifyExpectedArtifact>[0], reason: VerifyRejectReason) => {
    const result = await verifyExpectedArtifact(input, defaultSuiteVerificationCrypto);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe(reason);
    }
  };

  it("reordered field sequence -> field_sequence_mismatch", async () => {
    const { prefix, payload, sig } = load("zp-receive-expected-v1");
    const entries = Object.entries(payload);
    [entries[6], entries[7]] = [entries[7], entries[6]]; // swap receiver_pubkey and amount_zkz
    await expectReject(
      { envelope: envelopeFrom(prefix, Object.fromEntries(entries), sig), key: nodeKey(), signedAtUnixMs: 1 },
      "field_sequence_mismatch",
    );
  });

  it("omitted nullable field -> field_sequence_mismatch", async () => {
    const { prefix, payload, sig } = load("zp-send-external-expected-v1");
    const entries = Object.entries(payload).filter(([k]) => k !== "references_operation_id");
    await expectReject(
      { envelope: envelopeFrom(prefix, Object.fromEntries(entries), sig), key: nodeKey(), signedAtUnixMs: 1 },
      "field_sequence_mismatch",
    );
  });

  it("prefix purpose != payload purpose -> payload_purpose_mismatch", async () => {
    const { payload, sig } = load("zp-receive-expected-v1");
    await expectReject(
      { envelope: envelopeFrom("zp-move-internal-expected-v1", payload, sig), key: nodeKey(), signedAtUnixMs: 1 },
      "payload_purpose_mismatch",
    );
  });

  it("canonical_version as string \"1\" -> canonical_version_invalid", async () => {
    const { prefix, payload, sig } = load("zp-receive-expected-v1");
    await expectReject(
      { envelope: envelopeFrom(prefix, { ...payload, canonical_version: "1" }, sig), key: nodeKey(), signedAtUnixMs: 1 },
      "canonical_version_invalid",
    );
  });

  it("amount as a JSON number -> field_value_invalid", async () => {
    const { prefix, payload, sig } = load("zp-receive-expected-v1");
    await expectReject(
      { envelope: envelopeFrom(prefix, { ...payload, amount_zkz: 2.25 }, sig), key: nodeKey(), signedAtUnixMs: 1 },
      "field_value_invalid",
    );
  });

  it("uppercase (non-canonical) UUID -> field_value_invalid", async () => {
    const { prefix, payload, sig } = load("zp-receive-expected-v1");
    await expectReject(
      {
        envelope: envelopeFrom(prefix, { ...payload, node_id: "11111111-1111-4111-8111-11111111111A" }, sig),
        key: nodeKey(),
        signedAtUnixMs: 1,
      },
      "field_value_invalid",
    );
  });

  it("wrong key (device pubkey resolved) -> signature_invalid", async () => {
    const { prefix, payload, sig } = load("zp-receive-expected-v1");
    await expectReject(
      { envelope: envelopeFrom(prefix, payload, sig), key: nodeKey({ publicKeyB64: devicePub }), signedAtUnixMs: 1 },
      "signature_invalid",
    );
  });

  it("pinned pubkey mismatch -> key_pubkey_mismatch", async () => {
    const { prefix, payload, sig } = load("zp-receive-expected-v1");
    await expectReject(
      {
        envelope: envelopeFrom(prefix, payload, sig),
        key: nodeKey(),
        signedAtUnixMs: 1,
        pinnedPublicKeyB64: devicePub,
      },
      "key_pubkey_mismatch",
    );
  });

  it("revoked key -> key_not_accepted", async () => {
    const { prefix, payload, sig } = load("zp-receive-expected-v1");
    await expectReject(
      { envelope: envelopeFrom(prefix, payload, sig), key: nodeKey({ status: "REVOKED" }), signedAtUnixMs: 1 },
      "key_not_accepted",
    );
  });

  it("rotation-window violation (signed after valid_until) -> key_not_accepted", async () => {
    const { prefix, payload, sig } = load("zp-receive-expected-v1");
    await expectReject(
      {
        envelope: envelopeFrom(prefix, payload, sig),
        key: nodeKey({ validUntilUnixMs: 1_000 }),
        signedAtUnixMs: 2_000,
      },
      "key_not_accepted",
    );
  });

  it("cross-purpose expected guard -> cross_purpose_expected_mismatch", async () => {
    const { prefix, payload, sig } = load("zp-receive-expected-v1");
    await expectReject(
      {
        envelope: envelopeFrom(prefix, payload, sig),
        key: nodeKey(),
        signedAtUnixMs: 1,
        expectedPurpose: "zp-move-internal-expected-v1",
      },
      "cross_purpose_expected_mismatch",
    );
  });

  it("cross-purpose signature substitution (move preimage + receive signature) -> signature_invalid", async () => {
    const move = load("zp-move-internal-expected-v1");
    const receiveSig = readGoldenText("artifacts/zp-receive-expected-v1.sig.b64");
    await expectReject(
      { envelope: envelopeFrom(move.prefix, move.payload, receiveSig), key: nodeKey(), signedAtUnixMs: 1 },
      "signature_invalid",
    );
  });

  it("trailing newline appended to the preimage -> signature_invalid", async () => {
    const { prefix, payload, sig } = load("zp-receive-expected-v1");
    const tampered = `${prefix}\n${JSON.stringify(payload)}\n`;
    await expectReject(
      {
        envelope: { key_id: "node-identity-golden", preimage_text: tampered, preimage_sha256: digestPreimage(tampered), signature: sig },
        key: nodeKey(),
        signedAtUnixMs: 1,
      },
      "malformed_preimage",
    );
  });
});

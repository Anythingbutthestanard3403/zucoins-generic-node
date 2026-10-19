import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  ConsumerHttpError,
  ReceiveInstructionTamperError,
  fetchAndVerifyReceiveInstruction,
  type PublicReceiveInstructionResponse,
} from "../src/index.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IMPL_ID = "22222222-2222-4222-8222-222222222222";
const OP_ID = "33333333-3333-4333-8333-333333333333";
const WALLET_ID = "44444444-4444-4444-8444-444444444444";
const KEY_ID = "55555555-5555-4555-8555-555555555555";
const EXPIRY_SECS = "1893456000";
const EXPIRY_ISO = new Date(Number(EXPIRY_SECS) * 1000).toISOString();

function createSignedFixture(overrides?: {
  amountZkz?: string;
  recipientPubkey?: string;
  operationId?: string;
  signerPrivateKey?: ReturnType<typeof generateKeyPairSync>["privateKey"];
  signerPublicKeyPem?: string;
}) {
  const kp = generateKeyPairSync("ed25519");
  const privKey = overrides?.signerPrivateKey ?? kp.privateKey;
  const pubPem =
    overrides?.signerPublicKeyPem ??
    (kp.publicKey.export({ type: "spki", format: "pem" }) as string);

  const rawPub = Buffer.from(kp.publicKey.export({ type: "spki", format: "der" })).subarray(-32);
  const defaultRecipient = rawPub.toString("base64url");
  const recipient = overrides?.recipientPubkey ?? defaultRecipient;
  const amount = overrides?.amountZkz ?? "12.50";
  const opId = overrides?.operationId ?? OP_ID;

  const preimage = `zp-receive-expected-v1\n${JSON.stringify({
    purpose: "zp-receive-expected-v1",
    canonical_version: 1,
    node_id: NODE_ID,
    implementer_id: IMPL_ID,
    operation_id: opId,
    receiver_wallet_id: WALLET_ID,
    receiver_pubkey: recipient,
    amount_zkz: amount,
    expiry_unix_time_secs: EXPIRY_SECS,
  })}`;

  const sig = sign(null, Buffer.from(preimage, "utf8"), privKey).toString("base64url");
  const sha = createHash("sha256").update(preimage, "utf8").digest("hex");

  const response: PublicReceiveInstructionResponse = {
    operation_id: opId,
    state: "READY",
    expected_amount_zkz: amount,
    recipient_wallet_address: recipient,
    expires_at: EXPIRY_ISO,
    transfer_code: "xfer-code-ready-plaintext",
    node_id: NODE_ID,
    node_public_key_pem: pubPem,
    signed_expected_envelope: {
      purpose: "zp-receive-expected-v1",
      key_id: KEY_ID,
      preimage_text: preimage,
      preimage_sha256: sha,
      signature: sig,
    },
  };

  return { response, pubPem, kp };
}

function mockFetchJson(body: unknown, status = 200) {
  return async (url: string): Promise<Response> => {
    return new Response(JSON.stringify(body), {
      status,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "x-fetched-url": url,
      },
    });
  };
}

describe("fetchAndVerifyReceiveInstruction (ZTR-1336 / GN-302)", () => {
  it("resolves with the verified instruction when signature and pinned public key match", async () => {
    const { response, pubPem } = createSignedFixture();
    let requestedUrl = "";
    const verified = await fetchAndVerifyReceiveInstruction({
      nodeBaseUrl: "https://node.example.com/",
      operationId: OP_ID,
      expectedNodePublicKeyPem: pubPem,
      expectedAmountZkz: "12.50",
      fetchImpl: async (url) => {
        requestedUrl = url;
        return mockFetchJson(response)(url);
      },
    });

    expect(requestedUrl).toBe(`https://node.example.com/v1/receives/${OP_ID}/instruction`);
    expect(verified).toEqual(response);
  });

  it("rejects outer recipient_wallet_address tampering with PAYLOAD_MISMATCH", async () => {
    const { response, pubPem } = createSignedFixture();
    const tamperedAddress =
      response.recipient_wallet_address.slice(0, -1) +
      (response.recipient_wallet_address.endsWith("A") ? "B" : "A");

    const tampered: PublicReceiveInstructionResponse = {
      ...response,
      recipient_wallet_address: tamperedAddress,
    };

    await expect(
      fetchAndVerifyReceiveInstruction({
        nodeBaseUrl: "https://node.example.com",
        operationId: OP_ID,
        expectedNodePublicKeyPem: pubPem,
        fetchImpl: mockFetchJson(tampered),
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(ReceiveInstructionTamperError);
      expect((err as ReceiveInstructionTamperError).reasonCode).toBe("PAYLOAD_MISMATCH");
      return true;
    });
  });

  it("rejects preimage tampering or invalid Ed25519 signature with SIGNATURE_INVALID", async () => {
    const { response, pubPem } = createSignedFixture();
    const forgedPreimage = response.signed_expected_envelope.preimage_text.replace(
      response.recipient_wallet_address,
      "rogue_wallet_address_override_0000000000000",
    );
    const tampered: PublicReceiveInstructionResponse = {
      ...response,
      recipient_wallet_address: "rogue_wallet_address_override_0000000000000",
      signed_expected_envelope: {
        ...response.signed_expected_envelope,
        preimage_text: forgedPreimage,
      },
    };

    await expect(
      fetchAndVerifyReceiveInstruction({
        nodeBaseUrl: "https://node.example.com",
        operationId: OP_ID,
        expectedNodePublicKeyPem: pubPem,
        fetchImpl: mockFetchJson(tampered),
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(ReceiveInstructionTamperError);
      expect((err as ReceiveInstructionTamperError).reasonCode).toBe("SIGNATURE_INVALID");
      return true;
    });
  });

  it("rejects rogue node key substitution when re-signed by an attacker key with PUBLIC_KEY_MISMATCH", async () => {
    const merchant = createSignedFixture();
    const attacker = createSignedFixture({
      recipientPubkey: "attacker_wallet_pubkey_00000000000000000000",
    });

    await expect(
      fetchAndVerifyReceiveInstruction({
        nodeBaseUrl: "https://node.example.com",
        operationId: OP_ID,
        expectedNodePublicKeyPem: merchant.pubPem,
        fetchImpl: mockFetchJson(attacker.response),
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(ReceiveInstructionTamperError);
      expect((err as ReceiveInstructionTamperError).reasonCode).toBe("PUBLIC_KEY_MISMATCH");
      return true;
    });
  });

  it("rejects expectedAmountZkz mismatch with AMOUNT_MISMATCH even when node signature is valid", async () => {
    const { response, pubPem } = createSignedFixture({ amountZkz: "12.50" });

    await expect(
      fetchAndVerifyReceiveInstruction({
        nodeBaseUrl: "https://node.example.com",
        operationId: OP_ID,
        expectedNodePublicKeyPem: pubPem,
        expectedAmountZkz: "99.00",
        fetchImpl: mockFetchJson(response),
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(ReceiveInstructionTamperError);
      expect((err as ReceiveInstructionTamperError).reasonCode).toBe("AMOUNT_MISMATCH");
      return true;
    });
  });

  it("throws ConsumerHttpError (NodeApiError) on non-200 HTTP responses", async () => {
    const { pubPem } = createSignedFixture();
    const errorBody = {
      error: {
        code: "RECEIVE_NOT_FOUND",
        message: "Receive operation not found.",
        request_id: "req-1",
        details: {},
      },
    };

    await expect(
      fetchAndVerifyReceiveInstruction({
        nodeBaseUrl: "https://node.example.com",
        operationId: OP_ID,
        expectedNodePublicKeyPem: pubPem,
        fetchImpl: mockFetchJson(errorBody, 404),
      }),
    ).rejects.toSatisfy((err: unknown) => {
      expect(err).toBeInstanceOf(ConsumerHttpError);
      expect((err as ConsumerHttpError).status).toBe(404);
      expect((err as ConsumerHttpError).code).toBe("RECEIVE_NOT_FOUND");
      return true;
    });
  });
});

import { Buffer } from "node:buffer";
import { generateKeyPairSync, sign as edSign, verify as edVerify, type KeyObject } from "node:crypto";

import { buildReportRequestPreimage, type ReportRequestPayload } from "@zucoins/generic-node-contracts";
import { describe, expect, it } from "vitest";

import {
  bodySha256Hex,
  buildSignedReportingHeaders,
  ReportingRequestInvalidError,
  type ReportingCredential,
  type ReportingSigner,
} from "./reporting-signer.js";

function ed25519Pair(): { publicKey: KeyObject; privateKey: KeyObject } {
  return generateKeyPairSync("ed25519");
}

function signerFor(privateKey: KeyObject): ReportingSigner {
  return {
    async sign(preimage: Uint8Array): Promise<string> {
      return edSign(null, Buffer.from(preimage), privateKey).toString("base64url");
    },
  };
}

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IMPLEMENTER_ID = "22222222-2222-4222-8222-222222222222";
const KEY_ID = "33333333-3333-4333-8333-333333333333";

describe("buildSignedReportingHeaders", () => {
  it("produces the five headers with a signature that verifies against the reconstructed preimage", async () => {
    const { publicKey, privateKey } = ed25519Pair();
    const credential: ReportingCredential = {
      nodeId: NODE_ID,
      implementerId: IMPLEMENTER_ID,
      keyId: KEY_ID,
      signer: signerFor(privateKey),
    };
    const bodyBytes = new TextEncoder().encode(JSON.stringify({ a: 1 }));
    const issuedAt = new Date("2026-07-18T00:00:00.000Z");

    const headers = await buildSignedReportingHeaders({
      credential,
      method: "POST",
      rawTarget: "/v1/operations/33333333-3333-4333-8333-333333333333/verification-complete",
      bodyBytes,
      issuedAt,
    });

    expect(headers.get("X-ZP-Reporting-Key-Id")).toBe(KEY_ID);
    expect(headers.get("X-ZP-Reporting-Timestamp")).toBe("2026-07-18T00:00:00.000Z");
    expect(headers.get("X-ZP-Reporting-Expires-At")).toBe("2026-07-18T00:01:00.000Z");
    expect(headers.get("X-ZP-Reporting-Nonce")).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );

    const payload: ReportRequestPayload = {
      purpose: "zp-report-request-v1",
      canonical_version: 1,
      node_id: NODE_ID,
      implementer_id: IMPLEMENTER_ID,
      method: "POST",
      path: "/v1/operations/33333333-3333-4333-8333-333333333333/verification-complete",
      body_sha256: bodySha256Hex(bodyBytes),
      nonce: headers.get("X-ZP-Reporting-Nonce")!,
      issued_at: headers.get("X-ZP-Reporting-Timestamp")!,
      expires_at: headers.get("X-ZP-Reporting-Expires-At")!,
    };
    const preimage = buildReportRequestPreimage(payload);
    const signature = headers.get("X-ZP-Reporting-Signature")!;
    const verified = edVerify(
      null,
      Buffer.from(preimage),
      publicKey,
      Buffer.from(signature, "base64url"),
    );
    expect(verified).toBe(true);
  });

  it("mints a fresh nonce on every call", async () => {
    const { privateKey } = ed25519Pair();
    const credential: ReportingCredential = {
      nodeId: NODE_ID,
      implementerId: IMPLEMENTER_ID,
      keyId: KEY_ID,
      signer: signerFor(privateKey),
    };
    const bodyBytes = new Uint8Array(0);
    const a = await buildSignedReportingHeaders({
      credential,
      method: "GET",
      rawTarget: "/v1/events",
      bodyBytes,
    });
    const b = await buildSignedReportingHeaders({
      credential,
      method: "GET",
      rawTarget: "/v1/events",
      bodyBytes,
    });
    expect(a.get("X-ZP-Reporting-Nonce")).not.toBe(b.get("X-ZP-Reporting-Nonce"));
  });

  it("refuses an invalid request target rather than signing a lie", async () => {
    const { privateKey } = ed25519Pair();
    const credential: ReportingCredential = {
      nodeId: NODE_ID,
      implementerId: IMPLEMENTER_ID,
      keyId: KEY_ID,
      signer: signerFor(privateKey),
    };
    await expect(
      buildSignedReportingHeaders({
        credential,
        method: "GET",
        rawTarget: "/v1/not-a-real-route",
        bodyBytes: new Uint8Array(0),
      }),
    ).rejects.toBeInstanceOf(ReportingRequestInvalidError);
  });

  it("refuses a window beyond the frozen 60-second ceiling", async () => {
    const { privateKey } = ed25519Pair();
    const credential: ReportingCredential = {
      nodeId: NODE_ID,
      implementerId: IMPLEMENTER_ID,
      keyId: KEY_ID,
      signer: signerFor(privateKey),
    };
    await expect(
      buildSignedReportingHeaders({
        credential,
        method: "GET",
        rawTarget: "/v1/events",
        bodyBytes: new Uint8Array(0),
        windowSeconds: 61,
      }),
    ).rejects.toBeInstanceOf(ReportingRequestInvalidError);
  });
});

// ZTR-1335 public receive instruction, in-process HTTP seam.
// Proves CORS, the unauthenticated read, withheld-code secrecy, the landed
// projection, and the per-address volume cap. The real SQL read is the pg suite.

import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  createFailClosedOperationStore,
  createRejectAllOperationAuth,
  toBase64UrlPadded,
} from "@zucoins/node-core";
import type { PublicReceiveInstructionResponse } from "@zucoins/generic-node-contracts/operations";

import { NodeReadiness } from "../src/boot/readiness.js";
import type { ReceiveInstructionSql } from "../src/public-receive-instruction.js";
import {
  RECEIVE_INSTRUCTION_RATE_MAX_REQUESTS,
  loadPublicReceiveInstruction,
} from "../src/public-receive-instruction.js";
import { createNodeRuntimeListener, type NodeRuntimeListenerDeps } from "../src/runtime-listener.js";

const OP = "33333333-3333-4333-8333-333333333333";
const NODE = "11111111-1111-4111-8111-111111111111";
const WALLET = "44444444-4444-4444-8444-444444444444";
const KEY = "55555555-5555-4555-8555-555555555555";
const IMPL = "22222222-2222-4222-8222-222222222222";
const EXPIRY = "1893456000";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const rawPub = Buffer.from(publicKey.export({ type: "spki", format: "der" })).subarray(-32);
const pubkey = toBase64UrlPadded(rawPub);

const preimage = `zp-receive-expected-v1\n${JSON.stringify({
  purpose: "zp-receive-expected-v1",
  node_id: NODE,
  implementer_id: IMPL,
  operation_id: OP,
  receiver_wallet_id: WALLET,
  receiver_pubkey: pubkey,
  amount_zkz: "12.50",
  expiry_unix_time_secs: EXPIRY,
})}`;
const signature = toBase64UrlPadded(sign(null, Buffer.from(preimage), privateKey));
const preimageSha = createHash("sha256").update(preimage, "utf8").digest("hex");

interface Captured {
  status: number;
  headers: Record<string, string>;
  body: string;
}

function verifyReceiveExpectedEnvelope(
  envelope: PublicReceiveInstructionResponse["signed_expected_envelope"],
  pem: string,
): boolean {
  const sig = Buffer.from(envelope.signature, "base64url");
  return verify(null, Buffer.from(envelope.preimage_text, "utf8"), createPublicKey(pem), sig);
}

function row(status: string, codeStatus: string | null, code: string | null) {
  return {
    operation_id: OP,
    node_id: NODE,
    amount_zkz: "12.50",
    admission_status: status,
    live_status: status,
    recipient_pubkey: pubkey,
    code_status: codeStatus,
    transfer_code_text: code,
    expiry_unix_time_secs: EXPIRY,
    preimage_text: preimage,
    preimage_sha256: preimageSha,
    artifact_signature: signature,
    signing_key_id: KEY,
    node_public_key: pubkey,
  };
}

function listener(sql: ReceiveInstructionSql): NodeRuntimeListenerDeps {
  return {
    readiness: new NodeReadiness(3),
    pingDb: async () => {
      throw new Error("unused");
    },
    operationStore: createFailClosedOperationStore(),
    operationAuth: createRejectAllOperationAuth(),
    newRequestId: () => randomUUID(),
    nodeId: NODE,
    receiveInstructionSql: sql,
  };
}

function invoke(
  handler: ReturnType<typeof createNodeRuntimeListener>,
  method: string,
  url: string,
  headers: Record<string, string> = {},
  remoteAddress = "203.0.113.9",
): Promise<Captured> {
  return new Promise((resolve) => {
    const captured: Captured = { status: 0, headers: {}, body: "" };
    const response = {
      writeHead(status: number, responseHeaders: Record<string, string>) {
        captured.status = status;
        captured.headers = responseHeaders;
      },
      end(payload?: string) {
        captured.body = payload ?? "";
        resolve(captured);
      },
    } as unknown as ServerResponse;
    const request = {
      method,
      url,
      headers,
      rawHeaders: Object.entries(headers).flat(),
      socket: { remoteAddress },
      async *[Symbol.asyncIterator]() {
        /* no body */
      },
    } as unknown as IncomingMessage;
    handler(request, response);
  });
}

describe("public receive instruction", () => {
  it("returns the signed envelope with CORS and no credential", async () => {
    const phase = { status: "READY", codeStatus: "RELEASED", code: "xfer-code-ready" };
    const sql: ReceiveInstructionSql = {
      async query() {
        if (phase.status === "ABSENT") return { rows: [] };
        return { rows: [row(phase.status, phase.codeStatus, phase.code)] };
      },
    };
    const handler = createNodeRuntimeListener(listener(sql));
    const ready = await invoke(
      handler,
      "GET",
      `/v1/receives/${OP}/instruction`,
      { origin: "https://shop.example.com", accept: "application/json" },
    );
    expect(ready.status).toBe(200);
    expect(ready.headers["Access-Control-Allow-Origin"]).toBe("*");
    expect(ready.headers["Access-Control-Allow-Methods"]).toBe("GET, OPTIONS");
    const body = JSON.parse(ready.body) as PublicReceiveInstructionResponse;
    expect(body.transfer_code).toBe("xfer-code-ready");
    expect(body.state).toBe("READY");
    expect(body.expected_amount_zkz).toBe("12.50");
    expect(body.recipient_wallet_address).toBe(pubkey);
    expect(body.expires_at).toBe(new Date(Number(EXPIRY) * 1000).toISOString());
    expect(body.node_id).toBe(NODE);
    expect(verifyReceiveExpectedEnvelope(body.signed_expected_envelope, body.node_public_key_pem)).toBe(
      true,
    );
    expect(body.signed_expected_envelope.preimage_text).toBe(preimage);
    expect(Object.hasOwn(body, "implementer_id")).toBe(false);
    expect(Object.hasOwn(body, "external_ref")).toBe(false);
    expect(Object.hasOwn(body, "metadata")).toBe(false);
    const { preimage_text: _hidden, ...envelopeRest } = body.signed_expected_envelope;
    const withoutPreimage = JSON.stringify({ ...body, signed_expected_envelope: envelopeRest });
    expect(withoutPreimage).not.toContain("implementer_id");
    expect(ready.body).not.toContain("external_ref");

    phase.status = "RECEIVE_LANDED";
    const landed = await invoke(handler, "GET", `/v1/receives/${OP}/instruction`, {
      origin: "https://shop.example.com",
    });
    const landedBody = JSON.parse(landed.body) as PublicReceiveInstructionResponse;
    expect(landed.status).toBe(200);
    expect(landedBody.state).toBe("SETTLED");
    expect(landedBody.transfer_code).toBeNull();
    expect(landed.headers["Access-Control-Allow-Origin"]).toBe("*");
  });

  it("withholds the code until it is released, and answers 404 with CORS", async () => {
    const sql: ReceiveInstructionSql = {
      async query(_text, params) {
        const id = params?.[0];
        if (id !== OP) return { rows: [] };
        return { rows: [row("READY", "AWAITING_ARM", "withheld-plaintext")] };
      },
    };
    const withheld = await loadPublicReceiveInstruction(sql, OP);
    expect(withheld?.state).toBe("READY");
    expect(withheld?.transfer_code).toBeNull();
    expect(JSON.stringify(withheld)).not.toContain("withheld-plaintext");

    const missing = await invoke(
      createNodeRuntimeListener(listener(sql)),
      "GET",
      `/v1/receives/${"9".repeat(8)}-9999-4999-8999-999999999999/instruction`,
    );
    expect(missing.status).toBe(404);
    expect(JSON.parse(missing.body)).toEqual({
      error: { code: "RECEIVE_NOT_FOUND", message: "Receive operation not found." },
    });
    expect(missing.headers["Access-Control-Allow-Origin"]).toBe("*");
  });

  it("answers OPTIONS without consuming the volume cap, then caps GET", async () => {
    let reads = 0;
    const sql: ReceiveInstructionSql = {
      async query() {
        reads += 1;
        return { rows: [row("READY", "RELEASED", "xfer-code-ready")] };
      },
    };
    const handler = createNodeRuntimeListener(listener(sql));
    const preflight = await invoke(handler, "OPTIONS", `/v1/receives/${OP}/instruction`, {
      origin: "https://shop.example.com",
      "access-control-request-method": "GET",
    });
    expect(preflight.status).toBe(204);
    expect(preflight.headers["Access-Control-Allow-Origin"]).toBe("*");
    expect(preflight.headers["Access-Control-Allow-Headers"]).toBe("Content-Type, Accept");
    expect(reads).toBe(0);

    for (let i = 0; i < RECEIVE_INSTRUCTION_RATE_MAX_REQUESTS; i += 1) {
      const ok = await invoke(handler, "GET", `/v1/receives/${OP}/instruction`);
      expect(ok.status).toBe(200);
    }
    const limited = await invoke(handler, "GET", `/v1/receives/${OP}/instruction`);
    expect(limited.status).toBe(429);
    expect(JSON.parse(limited.body).error.code).toBe("rate_limited");
    expect(limited.headers["Access-Control-Allow-Origin"]).toBe("*");
    const otherAddress = await invoke(
      handler,
      "GET",
      `/v1/receives/${OP}/instruction`,
      {},
      "203.0.113.10",
    );
    expect(otherAddress.status).toBe(200);
  });
});

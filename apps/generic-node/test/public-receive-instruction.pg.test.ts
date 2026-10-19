// ZTR-1335 public receive instruction against PostgreSQL.
//
// POST /v1/receives admits CREATED. The browser instruction exists once the
// ready commit has persisted the zp-receive-expected-v1 artifact. NODE_VERIFIED
// releases the code at that commit; this suite plants that durable projection
// and reads it back through the public listener with no credential.
// A landed status projects to SETTLED and the code plaintext drops out of the
// response while the row itself stays.

import { createHash, createPublicKey, generateKeyPairSync, randomUUID, sign, verify } from "node:crypto";
import { execFileSync } from "node:child_process";
import type { IncomingMessage, ServerResponse } from "node:http";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";

import {
  createFailClosedOperationStore,
  createRejectAllOperationAuth,
  toBase64UrlPadded,
} from "@zucoins/node-core";
import type { PublicReceiveInstructionResponse } from "@zucoins/generic-node-contracts/operations";

import { NodeReadiness } from "../src/boot/readiness.js";
import type { ReceiveInstructionSql } from "../src/public-receive-instruction.js";
import { createNodeRuntimeListener } from "../src/runtime-listener.js";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const live = TEST_DATABASE_URL.length > 0;

const SCHEMA = "ztr1335_receive_instruction";
const NODE = "11111111-1111-4111-8111-111111111111";
const OP = "33333333-3333-4333-8333-333333333333";
const WALLET = "44444444-4444-4444-8444-444444444444";
const KEY = "55555555-5555-4555-8555-555555555555";
const IMPL = "22222222-2222-4222-8222-222222222222";
const EXPIRY = "1893456000";
const CODE = "xfer-code-ready-plaintext";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const rawPub = Buffer.from(publicKey.export({ type: "spki", format: "der" })).subarray(-32);
const pubkey = toBase64UrlPadded(rawPub);
const preimage = `zp-receive-expected-v1\n${JSON.stringify({
  purpose: "zp-receive-expected-v1",
  canonical_version: 1,
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

const STUBS = `
CREATE TABLE receive_operations (
  operation_id uuid PRIMARY KEY,
  node_id uuid NOT NULL,
  kind text NOT NULL,
  status text NOT NULL,
  amount_zkz text NOT NULL,
  wallet_id uuid
);
CREATE TABLE operations (
  id uuid PRIMARY KEY,
  status text NOT NULL
);
CREATE TABLE wallets (
  id uuid PRIMARY KEY,
  public_key text NOT NULL
);
CREATE TABLE receive_codes (
  operation_id uuid PRIMARY KEY,
  receiver_wallet_id uuid NOT NULL,
  code_status text NOT NULL,
  transfer_code_text text NOT NULL,
  expiry_unix_time_secs text NOT NULL
);
CREATE TABLE operation_expected_artifacts (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE,
  purpose text NOT NULL,
  preimage_text text NOT NULL,
  preimage_sha256 text NOT NULL,
  signature text NOT NULL,
  signing_key_id uuid NOT NULL
);
CREATE TABLE node_signing_keys (
  id uuid PRIMARY KEY,
  purpose text NOT NULL,
  public_key text NOT NULL,
  retired_at timestamptz
);
`;

let pool: Pool | undefined;

function psql(sql: string): void {
  execFileSync("psql", [TEST_DATABASE_URL, "-v", "ON_ERROR_STOP=1", "-q", "-c", sql], {
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function verifyReceiveExpectedEnvelope(
  envelope: PublicReceiveInstructionResponse["signed_expected_envelope"],
  pem: string,
): boolean {
  return verify(
    null,
    Buffer.from(envelope.preimage_text, "utf8"),
    createPublicKey(pem),
    Buffer.from(envelope.signature, "base64url"),
  );
}

interface Captured {
  status: number;
  headers: Record<string, string>;
  body: string;
}

function invoke(
  handler: ReturnType<typeof createNodeRuntimeListener>,
  method: string,
  url: string,
  headers: Record<string, string>,
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
      socket: { remoteAddress: "203.0.113.20" },
      async *[Symbol.asyncIterator]() {
        /* no body */
      },
    } as unknown as IncomingMessage;
    handler(request, response);
  });
}

describe("public receive instruction (real PG)", () => {
  beforeAll(async () => {
    if (!live) {
      if (PG_REQUIRED) throw new Error("PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned");
      return;
    }
    psql(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE; CREATE SCHEMA ${SCHEMA};`);
    psql(`SET search_path TO ${SCHEMA}; ${STUBS}`);
    pool = new Pool({ connectionString: TEST_DATABASE_URL });
    const client = await pool.connect();
    try {
      await client.query(`SET search_path TO ${SCHEMA}`);
      await client.query(
        `INSERT INTO wallets (id, public_key) VALUES ($1, $2)`,
        [WALLET, pubkey],
      );
      await client.query(
        `INSERT INTO node_signing_keys (id, purpose, public_key, retired_at) VALUES ($1, 'NODE_IDENTITY', $2, NULL)`,
        [KEY, pubkey],
      );
      await client.query(
        `INSERT INTO operations (id, status) VALUES ($1, 'READY')`,
        [OP],
      );
      await client.query(
        `INSERT INTO receive_operations (operation_id, node_id, kind, status, amount_zkz, wallet_id)
         VALUES ($1, $2, 'RECEIVE_EXTERNAL', 'READY', '12.50', $3)`,
        [OP, NODE, WALLET],
      );
      await client.query(
        `INSERT INTO receive_codes (operation_id, receiver_wallet_id, code_status, transfer_code_text, expiry_unix_time_secs)
         VALUES ($1, $2, 'RELEASED', $3, $4)`,
        [OP, WALLET, CODE, EXPIRY],
      );
      await client.query(
        `INSERT INTO operation_expected_artifacts (
           id, operation_id, purpose, preimage_text, preimage_sha256, signature, signing_key_id
         ) VALUES ($1, $2, 'zp-receive-expected-v1', $3, $4, $5, $6)`,
        [randomUUID(), OP, preimage, preimageSha, signature, KEY],
      );
    } finally {
      client.release();
    }
  }, 120_000);

  afterAll(async () => {
    await pool?.end();
    if (!live) return;
    try {
      psql(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
    } catch {
      // Shared PostgreSQL may already be dropping the schema.
    }
  });

  it("serves the signed instruction, then hides the code after landing", async () => {
    if (!live || pool === undefined) return;
    const db = pool;
    const sql: ReceiveInstructionSql = {
      async query(text, params) {
        const client = await db.connect();
        try {
          await client.query(`SET search_path TO ${SCHEMA}`);
          const result = await client.query(text, params as unknown[] | undefined);
          return { rows: result.rows as Record<string, unknown>[] };
        } finally {
          client.release();
        }
      },
    };
    const handler = createNodeRuntimeListener({
      readiness: new NodeReadiness(3),
      pingDb: async () => {
        throw new Error("unused");
      },
      operationStore: createFailClosedOperationStore(),
      operationAuth: createRejectAllOperationAuth(),
      newRequestId: () => randomUUID(),
      nodeId: NODE,
      receiveInstructionSql: sql,
    });
    const ready = await invoke(handler, "GET", `/v1/receives/${OP}/instruction`, {
      origin: "https://shop.example.com",
      accept: "application/json",
    });
    expect(ready.status).toBe(200);
    expect(ready.headers["Access-Control-Allow-Origin"]).toBe("*");
    expect(ready.headers.authorization).toBeUndefined();
    const body = JSON.parse(ready.body) as PublicReceiveInstructionResponse;
    expect(body.state).toBe("READY");
    expect(body.transfer_code).toBe(CODE);
    expect(verifyReceiveExpectedEnvelope(body.signed_expected_envelope, body.node_public_key_pem)).toBe(
      true,
    );
    expect(Object.hasOwn(body, "implementer_id")).toBe(false);
    expect(Object.hasOwn(body, "external_ref")).toBe(false);
    expect(ready.body).not.toContain("external_ref");
    const { preimage_text: _hidden, ...rest } = body.signed_expected_envelope;
    expect(JSON.stringify({ ...body, signed_expected_envelope: rest })).not.toContain("implementer_id");

    const client = await db.connect();
    try {
      await client.query(`SET search_path TO ${SCHEMA}`);
      await client.query(`UPDATE operations SET status = 'RECEIVE_LANDED' WHERE id = $1`, [OP]);
      await client.query(
        `UPDATE receive_operations SET status = 'RECEIVE_LANDED' WHERE operation_id = $1`,
        [OP],
      );
    } finally {
      client.release();
    }

    const landed = await invoke(handler, "GET", `/v1/receives/${OP}/instruction`, {
      origin: "https://shop.example.com",
    });
    const landedBody = JSON.parse(landed.body) as PublicReceiveInstructionResponse;
    expect(landed.status).toBe(200);
    expect(landed.headers["Access-Control-Allow-Origin"]).toBe("*");
    expect(landedBody.state).toBe("SETTLED");
    expect(landedBody.transfer_code).toBeNull();
    expect(landed.body).not.toContain(CODE);

    const missing = await invoke(
      handler,
      "GET",
      "/v1/receives/99999999-9999-4999-8999-999999999999/instruction",
      { origin: "https://shop.example.com" },
    );
    expect(missing.status).toBe(404);
    expect(JSON.parse(missing.body)).toEqual({
      error: { code: "RECEIVE_NOT_FOUND", message: "Receive operation not found." },
    });
    expect(missing.headers["Access-Control-Allow-Origin"]).toBe("*");
  });
});

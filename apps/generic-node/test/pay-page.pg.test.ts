// ZTR-1337 (GN-303) node-hosted minimal transfer instruction page (GET /pay/:operation_id).

import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { execFileSync } from "node:child_process";
import type { IncomingMessage, ServerResponse } from "node:http";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";

import {
  createFailClosedOperationStore,
  createRejectAllOperationAuth,
  toBase64UrlPadded,
} from "@zucoins/node-core";

import { NodeReadiness } from "../src/boot/readiness.js";
import { PAY_PAGE_CSP, sanitizeReturnUrl } from "../src/pay-page.js";
import type { ReceiveInstructionSql } from "../src/public-receive-instruction.js";
import { createNodeRuntimeListener } from "../src/runtime-listener.js";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
const PG_REQUIRED = process.env.PG_REQUIRED === "1";
const live = TEST_DATABASE_URL.length > 0;

const SCHEMA = "ztr1337_pay_page";
const NODE = "11111111-1111-4111-8111-111111111111";
const OP = "33333333-3333-4333-8333-333333333333";
const WALLET = "44444444-4444-4444-8444-444444444444";
const KEY = "55555555-5555-4555-8555-555555555555";
const IMPL = "22222222-2222-4222-8222-222222222222";
const EXPIRY = "1893456000";
const CODE = "xfer-code-pay-page-ready";

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
  amount_zkz: "25.00",
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

interface Captured {
  status: number;
  headers: Record<string, string>;
  body: string;
}

function invoke(
  handler: ReturnType<typeof createNodeRuntimeListener>,
  method: string,
  url: string,
  headers: Record<string, string> = {},
): Promise<Captured> {
  return new Promise((resolve) => {
    const captured: Captured = { status: 0, headers: {}, body: "" };
    const response = {
      headersSent: false,
      writeHead(status: number, responseHeaders: Record<string, string>) {
        this.headersSent = true;
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
      socket: { remoteAddress: "203.0.113.25" },
      async *[Symbol.asyncIterator]() {
        /* no body */
      },
    } as unknown as IncomingMessage;
    handler(request, response);
  });
}

const inMemorySql: ReceiveInstructionSql = {
  async query<T extends Record<string, unknown>>(
    _text: string,
    params?: readonly unknown[],
  ): Promise<{ rows: T[] }> {
    const opId = params?.[0];
    if (opId !== OP) return { rows: [] };
    return {
      rows: [
        {
          operation_id: OP,
          node_id: NODE,
          amount_zkz: "25.00",
          admission_status: "READY",
          live_status: "READY",
          recipient_pubkey: pubkey,
          code_status: "RELEASED",
          transfer_code_text: CODE,
          expiry_unix_time_secs: EXPIRY,
          preimage_text: preimage,
          preimage_sha256: preimageSha,
          artifact_signature: signature,
          signing_key_id: KEY,
          node_public_key: pubkey,
        } as unknown as T,
      ],
    };
  },
};

describe("GET /pay/:operation_id (ZTR-1337 / GN-303)", () => {
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
      await client.query(`INSERT INTO wallets (id, public_key) VALUES ($1, $2)`, [WALLET, pubkey]);
      await client.query(
        `INSERT INTO node_signing_keys (id, purpose, public_key, retired_at) VALUES ($1, 'NODE_IDENTITY', $2, NULL)`,
        [KEY, pubkey],
      );
      await client.query(`INSERT INTO operations (id, status) VALUES ($1, 'READY')`, [OP]);
      await client.query(
        `INSERT INTO receive_operations (operation_id, node_id, kind, status, amount_zkz, wallet_id)
         VALUES ($1, $2, 'RECEIVE_EXTERNAL', 'READY', '25.00', $3)`,
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
      // ignore cleanup race
    }
  });

  it("renders 200 OK HTML with CSP, expected_amount_zkz, recipient_wallet_address, and inline SVG QR", async () => {
    const db = pool;
    const sql: ReceiveInstructionSql =
      live && db !== undefined
        ? {
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
          }
        : inMemorySql;

    const handler = createNodeRuntimeListener({
      readiness: new NodeReadiness(3),
      pingDb: async () => {},
      operationStore: createFailClosedOperationStore(),
      operationAuth: createRejectAllOperationAuth(),
      newRequestId: () => randomUUID(),
      nodeId: NODE,
      receiveInstructionSql: sql,
    });

    const res = await invoke(
      handler,
      "GET",
      `/pay/${OP}?return_url=${encodeURIComponent("https://platform.example.com/complete")}`,
    );
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toBe("text/html; charset=utf-8");
    expect(res.headers["content-security-policy"]).toBe(PAY_PAGE_CSP);
    expect(res.body).toContain("25.00 ZKZ");
    expect(res.body).toContain(pubkey);
    expect(res.body).toContain(CODE);
    expect(res.body).toContain('<svg id="qr-svg"');
    expect(res.body).toContain(`Verified by Node ${NODE.slice(0, 8)}`);
    expect(res.body).toContain("https://platform.example.com/complete");
  });

  it("strips javascript: and data: return_url values to prevent XSS and open redirects", async () => {
    expect(sanitizeReturnUrl("javascript:alert(1)")).toBeNull();
    expect(sanitizeReturnUrl("data:text/html,<script>alert(1)</script>")).toBeNull();
    expect(sanitizeReturnUrl("http://evil.example.com/phish")).toBeNull();
    expect(sanitizeReturnUrl("http://localhost:3000/callback")).toBe(
      "http://localhost:3000/callback",
    );

    const handler = createNodeRuntimeListener({
      readiness: new NodeReadiness(3),
      pingDb: async () => {},
      operationStore: createFailClosedOperationStore(),
      operationAuth: createRejectAllOperationAuth(),
      newRequestId: () => randomUUID(),
      nodeId: NODE,
      receiveInstructionSql: inMemorySql,
    });

    const xssRes = await invoke(handler, "GET", `/pay/${OP}?return_url=javascript:alert(1)`);
    expect(xssRes.status).toBe(200);
    expect(xssRes.body).not.toContain("javascript:alert(1)");
    expect(xssRes.body).not.toContain('id="continue-link"');

    const missingRes = await invoke(
      handler,
      "GET",
      "/pay/99999999-9999-4999-8999-999999999999",
    );
    expect(missingRes.status).toBe(404);
    expect(missingRes.headers["content-type"]).toBe("text/html; charset=utf-8");
  });
});

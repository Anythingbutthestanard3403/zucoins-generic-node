// shared fixtures for the reporting module's colocated tests: Ed25519
// seed-key idioms (mirroring the contracts' freeze tests), golden store seeding, and signed
// request assembly via the frozen builders. Not exported from the module barrel; production
// code never imports this file.

import { createPrivateKey, createPublicKey, sign, type KeyObject } from "node:crypto";

import {
  buildReportRequestPreimage,
  REPORTING_KEY_PUBKEY,
  REPORT_REQUEST_CANONICAL_VERSION,
  REPORT_REQUEST_GOLDEN_SIGNATURE,
  REPORT_REQUEST_PURPOSE,
} from "@zucoins/generic-node-contracts";
// the guard-free money-path serializer is confined to the `./testkit` subpath (it is
// no longer on the public `.` barrel). This test-fixtures module is the sole sanctioned
// importer; production code never imports this file (see header).
import { serializeReportRequestPayload } from "@zucoins/generic-node-contracts/testkit";

import { sha256HexUtf8 } from "./ed25519.js";
import { InMemoryReportingRateLimiter } from "./in-memory-rate-limiter.js";
import { InMemoryReportingStore } from "./in-memory-store.js";
import {
  createReportingRequestVerifier,
  type CapturedReportRequest,
  type ReportingRequestVerifier,
} from "./request-verifier.js";

export const NODE_ID = "11111111-1111-4111-8111-111111111111";
export const IMPLEMENTER_ID = "22222222-2222-4222-8222-222222222222";
export const KEY_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
export const GOLDEN_TARGET = "/v1/operations/33333333-3333-4333-8333-333333333333/verification-complete";
export const GOLDEN_NONCE = "99999999-9999-4999-8999-999999999999";
export const ISSUED_MS = Date.parse("2026-07-18T00:00:00.000Z");
export const MID_WINDOW_MS = ISSUED_MS + 30_000;
export const IDEMPOTENCY_KEY = "idempotency-key-0001";
export const TEST_KEY_SEED = 0x42;

export const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

export function keyFromSeed(byte: number): KeyObject {
  const seed = Buffer.alloc(32, byte);
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}

export function paddedBase64Url(bytes: Buffer): string {
  return bytes.toString("base64").replaceAll("+", "-").replaceAll("/", "_");
}

export function pubOf(privateKey: KeyObject): string {
  return paddedBase64Url(
    createPublicKey(privateKey).export({ type: "spki", format: "der" }).subarray(-32),
  );
}

export function signPadded(preimageText: string, privateKey: KeyObject): string {
  return paddedBase64Url(sign(null, Buffer.from(preimageText, "utf8"), privateKey));
}

export function seedGoldenStore(
  store: InMemoryReportingStore,
  publicKeyEncoded: string = REPORTING_KEY_PUBKEY,
): void {
  store.seedRegistration({
    reportingKeyId: KEY_ID,
    nodeId: NODE_ID,
    implementerId: IMPLEMENTER_ID,
    publicKeyEncoded,
  });
  store.seedRestoreHold(NODE_ID, false);
  store.seedLifecycleHead(NODE_ID, IMPLEMENTER_ID, {
    epoch: 1n,
    authHold: false,
    currentKeyId: KEY_ID,
    priorKeyId: null,
    overlapExpiresAtMs: null,
    successorCommittedAtMs: null,
  });
  store.seedReportingKeyState(NODE_ID, IMPLEMENTER_ID, KEY_ID, {
    state: "ACTIVE",
    revokedAtMs: null,
  });
}

export function makeVerifier(
  store: InMemoryReportingStore,
  nowMs: () => number = () => MID_WINDOW_MS,
): ReportingRequestVerifier {
  return createReportingRequestVerifier({
    nodeId: NODE_ID,
    store,
    rateLimiter: new InMemoryReportingRateLimiter(60_000, 1_000),
    nowMs,
  });
}

export function goldenHeaders(signature: string, nonce: string): string[] {
  return [
    "X-ZP-Reporting-Key-Id", KEY_ID,
    "X-ZP-Reporting-Timestamp", "2026-07-18T00:00:00.000Z",
    "X-ZP-Reporting-Expires-At", "2026-07-18T00:01:00.000Z",
    "X-ZP-Reporting-Nonce", nonce,
    "X-ZP-Reporting-Signature", signature,
    "Idempotency-Key", IDEMPOTENCY_KEY,
  ];
}

export function goldenCaptured(): CapturedReportRequest {
  return {
    method: "POST",
    rawTarget: GOLDEN_TARGET,
    rawHeaders: goldenHeaders(REPORT_REQUEST_GOLDEN_SIGNATURE, GOLDEN_NONCE),
    bodyBytes: utf8("{}"),
    receivedAtMs: MID_WINDOW_MS,
  };
}

// Assemble a signed request exactly as a conforming implementer would: the preimage comes
// from the frozen builder (signedTarget defaults to the delivered target; a divergence
// between the two is how a rewriting adapter is simulated).
//
// `allowInvalidWindow` opts out of the mint-time 60s window guard by signing over the
// guard-free serializer instead. This is the ONLY way a test can hand the verifier a genuinely
// out-of-window SIGNED request (over-60s or zero-window) — the honest minter refuses to mint one,
// but the verifier is the security control and must reject it on the SIGNED fields regardless
// (signed pull event stream). Both paths serialize through the same source of truth, so in-window requests are
// byte-identical whichever path is taken.
export function signRequest(input: {
  privateKey: KeyObject;
  method: string;
  target: string;
  body: string;
  nonce: string;
  issuedAtMs: number;
  expiresAtMs: number;
  keyId?: string;
  signedTarget?: string;
  idempotencyKey?: string;
  allowInvalidWindow?: boolean;
}): CapturedReportRequest {
  const payload = {
    purpose: REPORT_REQUEST_PURPOSE,
    canonical_version: REPORT_REQUEST_CANONICAL_VERSION,
    node_id: NODE_ID,
    implementer_id: IMPLEMENTER_ID,
    method: input.method,
    path: input.signedTarget ?? input.target,
    body_sha256: sha256HexUtf8(input.body),
    nonce: input.nonce,
    issued_at: new Date(input.issuedAtMs).toISOString(),
    expires_at: new Date(input.expiresAtMs).toISOString(),
  } as const;
  const preimage = input.allowInvalidWindow
    ? serializeReportRequestPayload(payload)
    : buildReportRequestPreimage(payload);
  const signature = signPadded(preimage, input.privateKey);
  const idem =
    input.method === "POST"
      ? ["Idempotency-Key", input.idempotencyKey ?? IDEMPOTENCY_KEY]
      : [];
  return {
    method: input.method,
    rawTarget: input.target,
    rawHeaders: [
      "X-ZP-Reporting-Key-Id", input.keyId ?? KEY_ID,
      "X-ZP-Reporting-Timestamp", new Date(input.issuedAtMs).toISOString(),
      "X-ZP-Reporting-Expires-At", new Date(input.expiresAtMs).toISOString(),
      "X-ZP-Reporting-Nonce", input.nonce,
      "X-ZP-Reporting-Signature", signature,
      ...idem,
    ],
    bodyBytes: utf8(input.body),
    receivedAtMs: input.issuedAtMs + 1_000,
  };
}

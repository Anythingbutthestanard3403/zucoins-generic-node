/**
 * Browser & Node 20+ receive instruction verifier (ZTR-1336 / GN-302).
 *
 * Fetches `GET /v1/receives/:operation_id/instruction`, verifies the
 * `zp-receive-expected-v1` Ed25519 signature strictly against the caller's
 * pinned `expectedNodePublicKeyPem` via WebCrypto (`globalThis.crypto.subtle`),
 * and cross-checks that every outer response field (`operation_id`,
 * `recipient_wallet_address`, `expected_amount_zkz`, `expires_at`, `node_id`)
 * matches the signed preimage before returning the instruction.
 */

import {
  PUBLIC_RECEIVE_INSTRUCTION_STATES,
  type PersistedReceiveExpectedEnvelope,
  type PublicReceiveInstructionResponse,
  type PublicReceiveInstructionState,
} from "@zucoins/generic-node-contracts/operations";

import type { FetchLike } from "./client-types.js";
import { NodeApiError, readNodeApiError } from "./errors.js";

export {
  PUBLIC_RECEIVE_INSTRUCTION_STATES,
  type PersistedReceiveExpectedEnvelope,
  type PublicReceiveInstructionResponse,
  type PublicReceiveInstructionState,
};

export const RECEIVE_INSTRUCTION_TAMPER_REASON_CODES = [
  "PUBLIC_KEY_MISMATCH",
  "SIGNATURE_INVALID",
  "PAYLOAD_MISMATCH",
  "AMOUNT_MISMATCH",
] as const;

export type ReceiveInstructionTamperReasonCode =
  (typeof RECEIVE_INSTRUCTION_TAMPER_REASON_CODES)[number];

export class ReceiveInstructionTamperError extends Error {
  readonly reasonCode: ReceiveInstructionTamperReasonCode;
  readonly code: ReceiveInstructionTamperReasonCode;

  constructor(reasonCode: ReceiveInstructionTamperReasonCode, message: string) {
    super(message);
    this.name = "ReceiveInstructionTamperError";
    this.reasonCode = reasonCode;
    this.code = reasonCode;
  }
}

export {
  ReceiveInstructionTamperError as ReceiveInstructionVerificationError,
  NodeApiError as ConsumerHttpError,
};

export interface VerifyReceiveInstructionOptions {
  readonly nodeBaseUrl: string;
  readonly operationId: string;
  readonly expectedNodePublicKeyPem: string;
  readonly expectedAmountZkz?: string;
  readonly expectedRecipientWalletAddress?: string;
  readonly fetchImpl?: FetchLike;
}

const ARTIFACT_PURPOSE = "zp-receive-expected-v1";

/** ASN.1 SubjectPublicKeyInfo prefix for a 32-byte Ed25519 public key (RFC 8410). */
const ED25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function decodeBase64Standard(b64: string): Uint8Array | null {
  const cleaned = b64.replace(/\s+/g, "");
  if (cleaned.length === 0 || cleaned.length % 4 === 1) return null;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(cleaned)) return null;
  try {
    const binary = globalThis.atob(cleaned);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      out[i] = binary.charCodeAt(i);
    }
    return out;
  } catch {
    return null;
  }
}

function decodeBase64Url(input: string): Uint8Array | null {
  if (input.length === 0 || /\s/.test(input)) return null;
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(input)) return null;
  const standard = input.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (standard.length % 4)) % 4;
  return decodeBase64Standard(standard + "=".repeat(padLen));
}

function hasSpkiPrefix(bytes: Uint8Array): boolean {
  if (bytes.length !== 44) return false;
  for (let i = 0; i < ED25519_SPKI_PREFIX.length; i += 1) {
    if (bytes[i] !== ED25519_SPKI_PREFIX[i]) return false;
  }
  return true;
}

/**
 * Parse an Ed25519 public key in SPKI PEM or raw 32-byte base64url form into
 * its canonical 44-byte SPKI DER representation.
 */
function parseEd25519SpkiDer(keyInput: string): Uint8Array | null {
  const trimmed = keyInput.trim();
  if (trimmed.includes("BEGIN PUBLIC KEY")) {
    const body = trimmed
      .replace(/-----BEGIN PUBLIC KEY-----/g, "")
      .replace(/-----END PUBLIC KEY-----/g, "")
      .replace(/\s+/g, "");
    const der = decodeBase64Standard(body);
    if (der === null || !hasSpkiPrefix(der)) return null;
    return der;
  }
  const raw = decodeBase64Url(trimmed) ?? decodeBase64Standard(trimmed);
  if (raw === null) return null;
  if (hasSpkiPrefix(raw)) return raw;
  if (raw.length === 32) {
    const der = new Uint8Array(44);
    der.set(ED25519_SPKI_PREFIX, 0);
    der.set(raw, ED25519_SPKI_PREFIX.length);
    return der;
  }
  return null;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += (bytes[i] ?? 0).toString(16).padStart(2, "0");
  }
  return out;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const entries = keys
    .filter((k) => record[k] !== undefined)
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(record[k])}`);
  return `{${entries.join(",")}}`;
}

function isPublicState(value: unknown): value is PublicReceiveInstructionState {
  return (
    typeof value === "string" &&
    (PUBLIC_RECEIVE_INSTRUCTION_STATES as readonly string[]).includes(value)
  );
}

function asNonEmptyString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function toExactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

async function verifyEd25519WebCrypto(
  spkiDer: Uint8Array,
  preimageBytes: Uint8Array,
  signatureBytes: Uint8Array,
): Promise<boolean> {
  if (signatureBytes.length !== 64) return false;
  const subtle = globalThis.crypto?.subtle;
  if (subtle === undefined) {
    throw new Error("WebCrypto SubtleCrypto is unavailable in this environment");
  }
  try {
    const cryptoKey = await subtle.importKey(
      "spki",
      toExactArrayBuffer(spkiDer),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return await subtle.verify(
      { name: "Ed25519" },
      cryptoKey,
      toExactArrayBuffer(signatureBytes),
      toExactArrayBuffer(preimageBytes),
    );
  } catch {
    return false;
  }
}

async function sha256HexWebCrypto(bytes: Uint8Array): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle === undefined) {
    throw new Error("WebCrypto SubtleCrypto is unavailable in this environment");
  }
  const digest = await subtle.digest("SHA-256", toExactArrayBuffer(bytes));
  return toHex(new Uint8Array(digest));
}

interface ExtractedEnvelope {
  readonly preimageText: string;
  readonly preimageSha256: string | null;
  readonly signatureBase64Url: string;
  readonly payload: Record<string, unknown>;
  readonly normalizedEnvelope: PersistedReceiveExpectedEnvelope;
}

function extractEnvelope(rawEnvelope: unknown): ExtractedEnvelope {
  if (rawEnvelope === null || typeof rawEnvelope !== "object" || Array.isArray(rawEnvelope)) {
    throw new ReceiveInstructionTamperError(
      "PAYLOAD_MISMATCH",
      "signed_expected_envelope is missing or not an object",
    );
  }
  const env = rawEnvelope as Record<string, unknown>;
  if (env.purpose !== undefined && env.purpose !== ARTIFACT_PURPOSE) {
    throw new ReceiveInstructionTamperError(
      "PAYLOAD_MISMATCH",
      `Unexpected envelope purpose: ${String(env.purpose)}`,
    );
  }

  const preimageText = asNonEmptyString(env.preimage_text);
  const signature =
    asNonEmptyString(env.signature) ?? asNonEmptyString(env.signature_base64url);

  if (preimageText !== null && signature !== null) {
    const prefix = `${ARTIFACT_PURPOSE}\n`;
    if (!preimageText.startsWith(prefix)) {
      throw new ReceiveInstructionTamperError(
        "PAYLOAD_MISMATCH",
        "preimage_text does not start with zp-receive-expected-v1 prefix",
      );
    }
    let parsedPayload: unknown;
    try {
      parsedPayload = JSON.parse(preimageText.slice(prefix.length));
    } catch {
      throw new ReceiveInstructionTamperError(
        "PAYLOAD_MISMATCH",
        "preimage_text payload is not valid JSON",
      );
    }
    if (
      parsedPayload === null ||
      typeof parsedPayload !== "object" ||
      Array.isArray(parsedPayload)
    ) {
      throw new ReceiveInstructionTamperError(
        "PAYLOAD_MISMATCH",
        "preimage_text payload is not a JSON object",
      );
    }
    const preimageSha256 = asNonEmptyString(env.preimage_sha256);
    const keyId = asNonEmptyString(env.key_id) ?? "unknown";
    return {
      preimageText,
      preimageSha256,
      signatureBase64Url: signature,
      payload: parsedPayload as Record<string, unknown>,
      normalizedEnvelope: {
        purpose: ARTIFACT_PURPOSE,
        key_id: keyId,
        preimage_text: preimageText,
        preimage_sha256: preimageSha256 ?? "",
        signature,
      },
    };
  }

  // Fallback for synthetic envelope with `{ payload, signature_base64url }`
  if (
    env.payload !== null &&
    typeof env.payload === "object" &&
    !Array.isArray(env.payload) &&
    signature !== null
  ) {
    const payloadObj = env.payload as Record<string, unknown>;
    const canonicalPreimage = `${ARTIFACT_PURPOSE}\n${canonicalJson(payloadObj)}`;
    const keyId = asNonEmptyString(env.key_id) ?? "unknown";
    return {
      preimageText: canonicalPreimage,
      preimageSha256: asNonEmptyString(env.preimage_sha256),
      signatureBase64Url: signature,
      payload: payloadObj,
      normalizedEnvelope: {
        purpose: ARTIFACT_PURPOSE,
        key_id: keyId,
        preimage_text: canonicalPreimage,
        preimage_sha256: asNonEmptyString(env.preimage_sha256) ?? "",
        signature,
      },
    };
  }

  throw new ReceiveInstructionTamperError(
    "PAYLOAD_MISMATCH",
    "signed_expected_envelope is missing preimage_text or signature",
  );
}

/**
 * Verify an already-fetched receive instruction response object against the
 * caller's pinned `expectedNodePublicKeyPem` and expected parameters.
 */
export async function verifyReceiveInstructionResponse(
  rawBody: unknown,
  options: Omit<VerifyReceiveInstructionOptions, "nodeBaseUrl" | "fetchImpl">,
): Promise<PublicReceiveInstructionResponse> {
  const expectedSpki = parseEd25519SpkiDer(options.expectedNodePublicKeyPem);
  if (expectedSpki === null) {
    throw new ReceiveInstructionTamperError(
      "PUBLIC_KEY_MISMATCH",
      "expectedNodePublicKeyPem is not a valid Ed25519 public key",
    );
  }

  if (rawBody === null || typeof rawBody !== "object" || Array.isArray(rawBody)) {
    throw new ReceiveInstructionTamperError(
      "PAYLOAD_MISMATCH",
      "Receive instruction response body is not a JSON object",
    );
  }
  const body = rawBody as Record<string, unknown>;

  const responsePubKeyPem = asNonEmptyString(body.node_public_key_pem);
  if (responsePubKeyPem === null) {
    throw new ReceiveInstructionTamperError(
      "PUBLIC_KEY_MISMATCH",
      "Response node_public_key_pem is missing",
    );
  }
  const responseSpki = parseEd25519SpkiDer(responsePubKeyPem);
  if (responseSpki === null || !bytesEqual(expectedSpki, responseSpki)) {
    throw new ReceiveInstructionTamperError(
      "PUBLIC_KEY_MISMATCH",
      "Response node_public_key_pem does not match pinned expectedNodePublicKeyPem",
    );
  }

  const operationId = asNonEmptyString(body.operation_id);
  const expectedAmountZkz = asNonEmptyString(body.expected_amount_zkz);
  const recipientWalletAddress = asNonEmptyString(body.recipient_wallet_address);
  const expiresAt = asNonEmptyString(body.expires_at);
  const nodeId = asNonEmptyString(body.node_id);
  const state = body.state;

  if (
    operationId === null ||
    expectedAmountZkz === null ||
    recipientWalletAddress === null ||
    expiresAt === null ||
    nodeId === null ||
    !isPublicState(state)
  ) {
    throw new ReceiveInstructionTamperError(
      "PAYLOAD_MISMATCH",
      "Receive instruction response is missing required fields",
    );
  }

  if (body.transfer_code !== null && typeof body.transfer_code !== "string") {
    throw new ReceiveInstructionTamperError(
      "PAYLOAD_MISMATCH",
      "Receive instruction transfer_code must be string or null",
    );
  }

  if (operationId !== options.operationId) {
    throw new ReceiveInstructionTamperError(
      "PAYLOAD_MISMATCH",
      `Response operation_id (${operationId}) does not match expected operationId (${options.operationId})`,
    );
  }

  const extracted = extractEnvelope(body.signed_expected_envelope);
  const preimageBytes = new TextEncoder().encode(extracted.preimageText);
  const signatureBytes = decodeBase64Url(extracted.signatureBase64Url);
  if (signatureBytes === null) {
    throw new ReceiveInstructionTamperError(
      "SIGNATURE_INVALID",
      "Envelope signature is not valid base64url",
    );
  }

  // Always verify cryptographic signature against the caller's pinned expectedSpki first.
  const sigValid = await verifyEd25519WebCrypto(expectedSpki, preimageBytes, signatureBytes);
  if (!sigValid) {
    throw new ReceiveInstructionTamperError(
      "SIGNATURE_INVALID",
      "Ed25519 signature verification failed against expectedNodePublicKeyPem",
    );
  }

  if (extracted.preimageSha256 !== null) {
    const computedSha = await sha256HexWebCrypto(preimageBytes);
    if (computedSha !== extracted.preimageSha256.toLowerCase()) {
      throw new ReceiveInstructionTamperError(
        "PAYLOAD_MISMATCH",
        "Envelope preimage_sha256 does not match preimage_text digest",
      );
    }
  }

  const signedOpId = asNonEmptyString(extracted.payload.operation_id);
  if (signedOpId !== options.operationId || signedOpId !== operationId) {
    throw new ReceiveInstructionTamperError(
      "PAYLOAD_MISMATCH",
      "Signed envelope operation_id does not match operationId",
    );
  }

  const signedRecipient =
    asNonEmptyString(extracted.payload.receiver_pubkey) ??
    asNonEmptyString(extracted.payload.recipient_wallet_address);
  if (signedRecipient === null || signedRecipient !== recipientWalletAddress) {
    throw new ReceiveInstructionTamperError(
      "PAYLOAD_MISMATCH",
      "Response recipient_wallet_address does not match signed envelope recipient",
    );
  }

  const signedAmount =
    asNonEmptyString(extracted.payload.amount_zkz) ??
    asNonEmptyString(extracted.payload.expected_amount_zkz);
  if (signedAmount === null || signedAmount !== expectedAmountZkz) {
    throw new ReceiveInstructionTamperError(
      "PAYLOAD_MISMATCH",
      "Response expected_amount_zkz does not match signed envelope amount",
    );
  }

  const signedNodeId = asNonEmptyString(extracted.payload.node_id);
  if (signedNodeId !== null && signedNodeId !== nodeId) {
    throw new ReceiveInstructionTamperError(
      "PAYLOAD_MISMATCH",
      "Response node_id does not match signed envelope node_id",
    );
  }

  const signedExpirySecs = asNonEmptyString(extracted.payload.expiry_unix_time_secs);
  if (signedExpirySecs !== null && /^[0-9]+$/.test(signedExpirySecs)) {
    const expectedIso = new Date(Number(signedExpirySecs) * 1000).toISOString();
    if (expectedIso !== expiresAt) {
      throw new ReceiveInstructionTamperError(
        "PAYLOAD_MISMATCH",
        "Response expires_at does not match signed envelope expiry_unix_time_secs",
      );
    }
  }

  if (
    options.expectedAmountZkz !== undefined &&
    expectedAmountZkz !== options.expectedAmountZkz
  ) {
    throw new ReceiveInstructionTamperError(
      "AMOUNT_MISMATCH",
      `Verified amount (${expectedAmountZkz}) does not match expectedAmountZkz (${options.expectedAmountZkz})`,
    );
  }

  if (
    options.expectedRecipientWalletAddress !== undefined &&
    recipientWalletAddress !== options.expectedRecipientWalletAddress
  ) {
    throw new ReceiveInstructionTamperError(
      "PAYLOAD_MISMATCH",
      "Verified recipient_wallet_address does not match expectedRecipientWalletAddress",
    );
  }

  return {
    operation_id: operationId,
    state,
    expected_amount_zkz: expectedAmountZkz,
    recipient_wallet_address: recipientWalletAddress,
    expires_at: expiresAt,
    transfer_code: (body.transfer_code as string | null) ?? null,
    node_id: nodeId,
    node_public_key_pem: responsePubKeyPem,
    signed_expected_envelope: extracted.normalizedEnvelope,
  };
}

/**
 * Fetch `GET /v1/receives/:operation_id/instruction` from `nodeBaseUrl` and
 * verify its `zp-receive-expected-v1` Ed25519 signature and bound fields
 * against `expectedNodePublicKeyPem`.
 */
export async function fetchAndVerifyReceiveInstruction(
  options: VerifyReceiveInstructionOptions,
): Promise<PublicReceiveInstructionResponse> {
  const fetchFn: FetchLike =
    options.fetchImpl ?? ((input, init) => globalThis.fetch(input, init));
  const baseUrl = options.nodeBaseUrl.replace(/\/+$/, "");
  const url = `${baseUrl}/v1/receives/${encodeURIComponent(options.operationId)}/instruction`;

  const response = await fetchFn(url, {
    method: "GET",
    headers: { Accept: "application/json" },
  });

  if (!response.ok) {
    throw await readNodeApiError(response);
  }

  let parsed: unknown;
  try {
    parsed = await response.json();
  } catch {
    throw new ReceiveInstructionTamperError(
      "PAYLOAD_MISMATCH",
      "Receive instruction HTTP response was not valid JSON",
    );
  }

  return verifyReceiveInstructionResponse(parsed, options);
}

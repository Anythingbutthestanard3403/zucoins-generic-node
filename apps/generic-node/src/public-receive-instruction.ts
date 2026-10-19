// Public receive instruction (ZTR-1335).
//
// Unauthenticated read of one receive. The operation id is the capability.
// The signed bytes are the artifact persisted at formation. This module does
// not sign anything and does not hold a private key.
//
// transfer_code plaintext is returned only when the live status is READY and
// receive_codes.code_status is RELEASED (NODE_VERIFIED ready-commit, or an
// arm that already released the code). AWAITING_ARM stays null, matching the
// ready-commit secrecy rule. A landed or expired receive also returns null.

import { createPublicKey } from "node:crypto";

import type {
  PersistedReceiveExpectedEnvelope,
  PublicReceiveInstructionResponse,
  PublicReceiveInstructionState,
} from "@zucoins/generic-node-contracts/operations";

export const RECEIVE_INSTRUCTION_RATE_WINDOW_MS = 60_000;
export const RECEIVE_INSTRUCTION_RATE_MAX_REQUESTS = 60;

export const RECEIVE_INSTRUCTION_CORS_HEADERS: Readonly<Record<string, string>> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Accept",
};

const JSON_CONTENT_TYPE = "application/json; charset=utf-8";
const ARTIFACT_PURPOSE = "zp-receive-expected-v1";
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface ReceiveInstructionSql {
  query<T extends Record<string, unknown>>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ rows: T[] }>;
}

interface InstructionRow extends Record<string, unknown> {
  readonly operation_id: string;
  readonly node_id: string;
  readonly amount_zkz: string;
  readonly admission_status: string;
  readonly live_status: string | null;
  readonly recipient_pubkey: string | null;
  readonly code_status: string | null;
  readonly transfer_code_text: string | null;
  readonly expiry_unix_time_secs: string | null;
  readonly preimage_text: string | null;
  readonly preimage_sha256: string | null;
  readonly artifact_signature: string | null;
  readonly signing_key_id: string | null;
  readonly node_public_key: string | null;
}

const LOAD_SQL = `
SELECT r.operation_id::text AS operation_id,
       r.node_id::text AS node_id,
       r.amount_zkz,
       r.status::text AS admission_status,
       o.status::text AS live_status,
       w.public_key AS recipient_pubkey,
       c.code_status::text AS code_status,
       c.transfer_code_text,
       c.expiry_unix_time_secs,
       a.preimage_text,
       a.preimage_sha256,
       a.signature AS artifact_signature,
       a.signing_key_id::text AS signing_key_id,
       k.public_key AS node_public_key
FROM receive_operations r
LEFT JOIN operations o ON o.id = r.operation_id
LEFT JOIN receive_codes c ON c.operation_id = r.operation_id
LEFT JOIN wallets w ON w.id = COALESCE(c.receiver_wallet_id, r.wallet_id)
LEFT JOIN operation_expected_artifacts a
  ON a.operation_id = r.operation_id
 AND a.purpose = '${ARTIFACT_PURPOSE}'
LEFT JOIN node_signing_keys k
  ON k.id = a.signing_key_id
 AND k.purpose = 'NODE_IDENTITY'
WHERE r.operation_id = $1::uuid
  AND r.kind = 'RECEIVE_EXTERNAL'
`;

export function receiveInstructionJsonHeaders(): Record<string, string> {
  return {
    "content-type": JSON_CONTENT_TYPE,
    ...RECEIVE_INSTRUCTION_CORS_HEADERS,
  };
}

export function receiveInstructionNotFoundBody(): string {
  return JSON.stringify({
    error: {
      code: "RECEIVE_NOT_FOUND",
      message: "Receive operation not found.",
    },
  });
}

function projectState(live: string): PublicReceiveInstructionState | null {
  switch (live) {
    case "CREATED":
      return "CREATED";
    case "READY":
      return "READY";
    case "RECEIVE_LANDED":
      return "SETTLED";
    case "EXPIRED":
      return "EXPIRED";
    default:
      return null;
  }
}

function preimagePayload(preimage: string): Record<string, unknown> | null {
  const splitAt = preimage.indexOf("\n");
  if (splitAt < 0) return null;
  try {
    const parsed: unknown = JSON.parse(preimage.slice(splitAt + 1));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

function asDigitString(value: unknown): string | null {
  return typeof value === "string" && /^[0-9]+$/.test(value) ? value : null;
}

function asNonEmpty(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function unixSecsToIso(secs: string): string | null {
  if (!/^[0-9]+$/.test(secs)) return null;
  const ms = Number(secs) * 1000;
  if (!Number.isSafeInteger(ms)) return null;
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}

function nodePublicKeyPem(padded: string): string | null {
  const raw = Buffer.from(padded, "base64url");
  if (raw.length !== 32) return null;
  const der = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
  try {
    const pem = createPublicKey({ key: der, format: "der", type: "spki" }).export({
      type: "spki",
      format: "pem",
    });
    return typeof pem === "string" && pem.includes("BEGIN PUBLIC KEY") ? pem : null;
  } catch {
    return null;
  }
}

export async function loadPublicReceiveInstruction(
  sql: ReceiveInstructionSql,
  operationId: string,
): Promise<PublicReceiveInstructionResponse | null> {
  if (!UUID_RE.test(operationId)) return null;
  const result = await sql.query<InstructionRow>(LOAD_SQL, [operationId]);
  const row = result.rows[0];
  if (row === undefined) return null;

  const state = projectState(row.live_status ?? row.admission_status);
  if (state === null) return null;
  if (
    row.preimage_text === null ||
    row.preimage_sha256 === null ||
    row.artifact_signature === null ||
    row.signing_key_id === null ||
    row.node_public_key === null
  ) {
    return null;
  }

  const payload = preimagePayload(row.preimage_text);
  const amount = asNonEmpty(row.amount_zkz) ?? asNonEmpty(payload?.amount_zkz);
  const address = asNonEmpty(row.recipient_pubkey) ?? asNonEmpty(payload?.receiver_pubkey);
  const expirySecs =
    asDigitString(row.expiry_unix_time_secs) ?? asDigitString(payload?.expiry_unix_time_secs);
  const expiresAt = expirySecs === null ? null : unixSecsToIso(expirySecs);
  const pem = nodePublicKeyPem(row.node_public_key);
  if (amount === null || address === null || expiresAt === null || pem === null) return null;

  const transferCode =
    state === "READY" && row.code_status === "RELEASED"
      ? asNonEmpty(row.transfer_code_text)
      : null;

  const envelope: PersistedReceiveExpectedEnvelope = {
    purpose: ARTIFACT_PURPOSE,
    key_id: row.signing_key_id,
    preimage_text: row.preimage_text,
    preimage_sha256: row.preimage_sha256,
    signature: row.artifact_signature,
  };

  return {
    operation_id: row.operation_id,
    state,
    expected_amount_zkz: amount,
    recipient_wallet_address: address,
    expires_at: expiresAt,
    transfer_code: transferCode,
    node_id: row.node_id,
    node_public_key_pem: pem,
    signed_expected_envelope: envelope,
  };
}

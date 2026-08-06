// Boundary conversions and row mappers for the durable reporting store. This is where
// Postgres wire types meet the node-core domain types: bigint columns arrive as string|number|
// bigint (node-postgres parses bigint as string by default), timestamptz as Date|string|number,
// and bytea as Buffer|Uint8Array|hex-string. Centralizing the coercion keeps the store body free
// of parsing noise and makes the mapping unit-testable in isolation.

import type {
  CompletedIdempotencyRecord,
  ReportingAdmissionSnapshot,
  ReportingNonceEvidence,
  ReportingPresentedKeyState,
  ReportingRegistration,
} from "@zucoins/node-core";

// ---- boundary coercion ----

export function toBigInt(value: unknown): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return BigInt(Math.trunc(value));
  if (typeof value === "string" && value.trim() !== "") return BigInt(value.trim());
  throw new Error(`cannot coerce value to bigint: ${String(value)}`);
}

export function toEpochMs(value: unknown): number {
  if (value instanceof Date) return value.getTime();
  if (typeof value === "number") return value;
  if (typeof value === "string") {
    const parsed = Date.parse(value);
    if (!Number.isNaN(parsed)) return parsed;
  }
  throw new Error(`cannot coerce value to epoch millis: ${String(value)}`);
}

export function toIsoString(value: unknown): string {
  if (typeof value === "string") return value;
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "number") return new Date(value).toISOString();
  throw new Error(`cannot coerce value to ISO timestamp: ${String(value)}`);
}

export function toText(value: unknown): string {
  if (typeof value === "string") return value;
  throw new Error(`expected text column, got: ${String(value)}`);
}

export function toNullableText(value: unknown): string | null {
  return value === null || value === undefined ? null : toText(value);
}

export function toBoolean(value: unknown): boolean {
  return value === true || value === "true";
}

export function toInteger(value: unknown): number {
  if (typeof value === "number") return Math.trunc(value);
  if (typeof value === "string") return Number.parseInt(value, 10);
  throw new Error(`cannot coerce value to integer: ${String(value)}`);
}

// bytea round-trips as Buffer (node-postgres default) but a fake client may hand back the
// Uint8Array it was given, or a Postgres hex string ('\x...'). Normalize all three to Uint8Array.
export function toUint8Array(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (typeof value === "string" && value.startsWith("\\x")) {
    const hex = value.slice(2);
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
  throw new Error(`cannot coerce value to bytea: ${String(value)}`);
}

// ---- row mappers ----

export function mapRegistrationRow(row: Record<string, unknown>): ReportingRegistration {
  return {
    reportingKeyId: toText(row.id),
    nodeId: toText(row.node_id),
    implementerId: toText(row.implementer_id),
    publicKeyEncoded: toText(row.public_key),
  };
}

const KEY_STATES: readonly ReportingPresentedKeyState[] = ["ACTIVE", "RETIRED", "REVOKED"];

function toKeyState(value: unknown): ReportingPresentedKeyState | null {
  if (typeof value === "string" && (KEY_STATES as readonly string[]).includes(value)) {
    return value as ReportingPresentedKeyState;
  }
  return null;
}

export function mapAdmissionSnapshotRow(row: Record<string, unknown>): ReportingAdmissionSnapshot {
  const presentedKeyState = toKeyState(row.presented_key_state);
  const stateChangedAt =
    row.presented_key_state_changed_at === null || row.presented_key_state_changed_at === undefined
      ? null
      : toEpochMs(row.presented_key_state_changed_at);
  return {
    restoreHold: toBoolean(row.restore_hold),
    epoch: toBigInt(row.epoch),
    authHold: toBoolean(row.auth_hold),
    currentKeyId: toNullableText(row.current_key_id),
    priorKeyId: toNullableText(row.prior_key_id),
    overlapExpiresAtMs:
      row.overlap_expires_at === null || row.overlap_expires_at === undefined
        ? null
        : toEpochMs(row.overlap_expires_at),
    successorCommittedAtMs:
      row.successor_committed_at === null || row.successor_committed_at === undefined
        ? null
        : toEpochMs(row.successor_committed_at),
    presentedKeyState,
    // A key's revocation instant is the state_changed_at of its latest (REVOKED) lifecycle
    // state row; null for a key that is not revoked (priorKeyEligible requires revokedAtMs=null).
    presentedKeyRevokedAtMs: presentedKeyState === "REVOKED" ? stateChangedAt : null,
  };
}

export function mapNonceEvidenceRow(
  row: Record<string, unknown>,
  evidence: Omit<ReportingNonceEvidence, "id" | "nonceBurnSequence" | "logicalFingerprint">,
): ReportingNonceEvidence {
  return {
    ...evidence,
    id: toText(row.id),
    nonceBurnSequence: toBigInt(row.nonce_burn_sequence),
    logicalFingerprint: toText(row.logical_fingerprint),
  };
}

export function mapCompletedIdempotencyRow(row: Record<string, unknown>): CompletedIdempotencyRecord {
  return {
    id: toText(row.id),
    nodeId: toText(row.node_id),
    implementerId: toText(row.implementer_id),
    routeId: toText(row.route_id),
    idempotencyKey: toText(row.idempotency_key),
    reportingNonceId: toText(row.reporting_nonce_id),
    childRecordId: toText(row.child_record_id),
    method: toText(row.method),
    rawTarget: toText(row.raw_target),
    bodySha256: toText(row.body_sha256),
    logicalFingerprint: toText(row.logical_fingerprint),
    responseStatus: toInteger(row.response_status),
    responseBytes: toUint8Array(row.response_bytes),
    completedAtMs: toEpochMs(row.completed_at),
  };
}

// The evidence columns are shared by the burn INSERT and its RETURNING projection; keep the column
// list and the parameter list in one place so they cannot drift apart.
export const NONCE_EVIDENCE_COLUMNS = [
  "id",
  "node_id",
  "implementer_id",
  "nonce",
  "purpose",
  "route_id",
  "request_class",
  "reporting_key_id",
  "lifecycle_epoch",
  "nonce_burn_sequence",
  "request_preimage_text",
  "request_preimage_sha256",
  "request_signature",
  "method",
  "raw_target",
  "body_sha256",
  "issued_at",
  "expires_at",
  "received_at",
  "consumed_at",
  "retention_class",
] as const;

export function nonceEvidenceParams(
  rowId: string,
  evidence: Omit<ReportingNonceEvidence, "id" | "nonceBurnSequence" | "logicalFingerprint">,
  nonceBurnSequence: bigint,
): readonly unknown[] {
  return [
    rowId,
    evidence.nodeId,
    evidence.implementerId,
    evidence.nonce,
    evidence.purpose,
    evidence.routeId,
    evidence.requestClass,
    evidence.reportingKeyId,
    evidence.lifecycleEpoch.toString(),
    nonceBurnSequence.toString(),
    evidence.requestPreimageText,
    evidence.requestPreimageSha256,
    evidence.requestSignature,
    evidence.method,
    evidence.rawTarget,
    evidence.bodySha256,
    evidence.issuedAt,
    evidence.expiresAt,
    new Date(evidence.receivedAtMs).toISOString(),
    new Date(evidence.consumedAtMs).toISOString(),
    evidence.retentionClass,
  ];
}

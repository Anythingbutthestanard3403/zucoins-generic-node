// Hashing, canonical base64url, detached Ed25519 verification, preimage builders, digest
// computation, and the canonical row comparator for the backup archive. These helpers are
// internal to the backup module — they are never re-exported
// through the package barrel, so the generic names here cannot collide with other modules'
// SHA-256 helpers.

import { createHash } from "node:crypto";
import { Buffer } from "node:buffer";

import { verifyRawEd25519 } from "../../protocol/ed25519-verify.js";
import {
  BACKUP_MANIFEST_PURPOSE,
  BACKUP_WALLET_EXPORT_PURPOSE,
} from "./format.js";
import type {
  BackupEvidenceRow,
  BackupEvidenceValue,
  BackupPrimaryKeyColumn,
} from "./types.js";

const UTF8 = new TextEncoder();

export function backupSha256HexUtf8(text: string): string {
  return createHash("sha256").update(UTF8.encode(text)).digest("hex");
}

export function backupSha256HexBytes(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function encodeBackupBase64Url(bytes: Uint8Array): string {
  const unpadded = Buffer.from(bytes).toString("base64url");
  const paddingLength = (4 - (unpadded.length % 4)) % 4;
  return unpadded + "=".repeat(paddingLength);
}

// Decode canonical padded base64url; returns null on any non-canonical or malformed input so
// callers fail closed.
export function decodeBackupBase64Url(text: string): Uint8Array | null {
  if (typeof text !== "string" || text.length === 0 || text.length % 4 !== 0) return null;
  let decoded: Buffer;
  try {
    decoded = Buffer.from(text, "base64url");
  } catch {
    return null;
  }
  if (encodeBackupBase64Url(decoded) !== text) return null;
  return new Uint8Array(decoded);
}

// Detached Ed25519 verification over the exact UTF-8 preimage bytes, taking canonical padded
// base64url public key and signature. Any failure is a verification failure, never a throw.
export function verifyBackupSignature(input: {
  readonly publicKeyBase64Url: string;
  readonly preimageText: string;
  readonly signatureBase64Url: string;
}): boolean {
  const publicKeyBytes = decodeBackupBase64Url(input.publicKeyBase64Url);
  const signatureBytes = decodeBackupBase64Url(input.signatureBase64Url);
  if (publicKeyBytes === null || signatureBytes === null) return false;
  return verifyRawEd25519({
    publicKeyBytes,
    preimageBytes: UTF8.encode(input.preimageText),
    signatureBytes,
  });
}

// Preimage builders: `purpose + "\n" + JSON.stringify(payload)`. The payload object
// must already carry its fields in the frozen sequence; a single JSON.stringify emits them
// byte-exact (the byte-exact signing rule).
export function buildWalletExportPreimageText(payloadFields1To9: object): string {
  return `${BACKUP_WALLET_EXPORT_PURPOSE}\n${JSON.stringify(payloadFields1To9)}`;
}

export function buildManifestPreimageText(manifestPayload: object): string {
  return `${BACKUP_MANIFEST_PURPOSE}\n${JSON.stringify(manifestPayload)}`;
}

// Row/table digests. row_sha256 = SHA-256(JSON.stringify(row)); table_sha256 =
// SHA-256(concat(row_sha256 …)); the empty table hashes as SHA-256 of the empty string.
export function computeBackupRowDigest(row: BackupEvidenceRow): string {
  return backupSha256HexUtf8(JSON.stringify(row));
}

export function computeBackupTableDigest(sortedRows: readonly BackupEvidenceRow[]): string {
  const concatenated = sortedRows.map((row) => computeBackupRowDigest(row)).join("");
  return backupSha256HexUtf8(concatenated);
}

export function computeBackupSettingsDigest(settingsSnapshot: object): string {
  return backupSha256HexUtf8(JSON.stringify(settingsSnapshot));
}

export function compareBackupByteSequence(a: string, b: string): number {
  const aBytes = UTF8.encode(a);
  const bBytes = UTF8.encode(b);
  const length = Math.min(aBytes.length, bBytes.length);
  for (let i = 0; i < length; i += 1) {
    const delta = (aBytes[i] ?? 0) - (bBytes[i] ?? 0);
    if (delta !== 0) return delta < 0 ? -1 : 1;
  }
  if (aBytes.length === bBytes.length) return 0;
  return aBytes.length < bBytes.length ? -1 : 1;
}

function asBigInt(value: BackupEvidenceValue): bigint | null {
  try {
    if (typeof value === "number") return BigInt(Math.trunc(value));
    if (typeof value === "string") return BigInt(value);
    return null;
  } catch {
    return null;
  }
}

function comparePrimaryKeyValue(
  kind: BackupPrimaryKeyColumn["kind"],
  a: BackupEvidenceValue,
  b: BackupEvidenceValue,
): number {
  if (kind === "integer") {
    const aInt = asBigInt(a);
    const bInt = asBigInt(b);
    if (aInt !== null && bInt !== null) {
      if (aInt < bInt) return -1;
      if (aInt > bInt) return 1;
      return 0;
    }
  }
  return compareBackupByteSequence(String(a), String(b));
}

// Canonical row sequence: lexicographic by primary-key column sequence, each column
// compared per its kind. Returns a stable comparator result; rows with equal keys compare 0.
export function compareBackupRows(
  a: BackupEvidenceRow,
  b: BackupEvidenceRow,
  primaryKey: readonly BackupPrimaryKeyColumn[],
): number {
  for (const column of primaryKey) {
    const delta = comparePrimaryKeyValue(column.kind, a[column.column] ?? null, b[column.column] ?? null);
    if (delta !== 0) return delta;
  }
  return 0;
}

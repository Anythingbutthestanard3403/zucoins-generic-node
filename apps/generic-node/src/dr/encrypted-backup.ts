// Encrypted database backup export/restore for the generic-node operational DR
// path.
// Envelope encryption: a fresh random DEK encrypts the pg_dump plaintext under
// AES-256-GCM; the DEK is itself wrapped under a KEK derived from
// BACKUP_MASTER_KEY via PBKDF2-SHA256 (600k iterations).
//
// BACKUP_MASTER_KEY is a dedicated backup secret — it is NOT the vault/signing
// key (the key-custody rule: the backup KEK lives in a separate custody domain and can
// never sign a transaction). This is the operational Postgres dump layer
// (ZBKP); the zp-node-backup-v1 archive is a separate custody ceremony
// surface and is NOT replaced by this module.
//
// ZBKP envelope layout (all fields concatenated, big-endian byte ordering):
//   magic       4   "ZBKP"
//   version     1   0x01
//   salt        32  PBKDF2 salt for the KEK
//   wrappedDEK  48  AES-256-GCM(KEK, wrapIV, DEK) = 32-byte ciphertext ‖ 16-byte tag
//   dataIV      12  GCM IV for the bulk ciphertext
//   authTag     16  GCM tag for the bulk ciphertext
//   sha256      32  SHA-256 of the plaintext (completeness check)
//   ciphertext  …   AES-256-GCM(DEK, dataIV, plaintext)
//
// The DEK-wrap IV is derived deterministically from the per-backup random salt
// (SHA-256(salt)[0..12)), so it needs no dedicated field: a fresh salt per
// backup yields a fresh (KEK, wrapIV) pair. This keeps wrappedDEK at exactly 48
// bytes and makes key rotation a pure re-wrap (see key-rotation.ts).

import { spawn, type ChildProcess } from "node:child_process";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  pbkdf2,
  randomBytes,
} from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { promisify } from "node:util";

import {
  applyDualGateForceAfterRestore,
  type ForceAuthHoldResult,
} from "./auth-hold.js";
import { withConnectedPgClient } from "./hold-db-orchestration.js";
import {
  deriveContinuitySnapshotOnClient,
  type LocalContinuitySnapshot,
} from "./markers.js";

const pbkdf2Async = promisify(pbkdf2);

export const KDF_ITERATIONS = 600_000;
export const KDF_HASH = "sha256";
export const KEY_LENGTH = 32;
export const IV_LENGTH = 12;
export const SALT_LENGTH = 32;
export const AUTH_TAG_LENGTH = 16;
export const SHA256_LENGTH = 32;
/** wrappedDEK = 32-byte encrypted DEK ‖ 16-byte GCM tag. */
export const WRAPPED_DEK_LENGTH = KEY_LENGTH + AUTH_TAG_LENGTH;

const MAGIC = Buffer.from("ZBKP");
const VERSION = 0x01;

// Field offsets (exported so callers/tests can locate fields without re-deriving).
export const OFF_VERSION = 4;
export const OFF_SALT = 5;
export const OFF_WRAPPED_DEK = OFF_SALT + SALT_LENGTH;
export const OFF_DATA_IV = OFF_WRAPPED_DEK + WRAPPED_DEK_LENGTH;
export const OFF_AUTH_TAG = OFF_DATA_IV + IV_LENGTH;
export const OFF_SHA256 = OFF_AUTH_TAG + AUTH_TAG_LENGTH;
export const HEADER_LENGTH = OFF_SHA256 + SHA256_LENGTH;

/** PBKDF2-SHA256(masterKey, salt, 600k) → 32-byte KEK. */
export function deriveKek(masterKey: string, salt: Buffer): Promise<Buffer> {
  return pbkdf2Async(masterKey, salt, KDF_ITERATIONS, KEY_LENGTH, KDF_HASH);
}

/** DEK-wrap IV = SHA-256(salt)[0..12). Deterministic per salt, no stored field. */
export function deriveWrapIv(salt: Buffer): Buffer {
  return createHash("sha256").update(salt).digest().subarray(0, IV_LENGTH);
}

function aesGcmEncrypt(
  key: Buffer,
  iv: Buffer,
  plaintext: Buffer,
): { ciphertext: Buffer; authTag: Buffer } {
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { ciphertext, authTag: cipher.getAuthTag() };
}

function aesGcmDecrypt(
  key: Buffer,
  iv: Buffer,
  authTag: Buffer,
  ciphertext: Buffer,
): Buffer {
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/** Assemble a ZBKP envelope from its parts (single writer for the byte layout). */
export function assembleEnvelope(parts: {
  salt: Buffer;
  wrappedDek: Buffer;
  dataIv: Buffer;
  authTag: Buffer;
  sha256: Buffer;
  ciphertext: Buffer;
}): Buffer {
  return Buffer.concat([
    MAGIC,
    Buffer.from([VERSION]),
    parts.salt,
    parts.wrappedDek,
    parts.dataIv,
    parts.authTag,
    parts.sha256,
    parts.ciphertext,
  ]);
}

export interface ParsedEnvelope {
  salt: Buffer;
  wrappedDek: Buffer;
  dataIv: Buffer;
  authTag: Buffer;
  sha256: Buffer;
  ciphertext: Buffer;
}

/** Validate magic/version and slice a ZBKP buffer into its fields. */
export function parseEnvelope(envelope: Buffer): ParsedEnvelope {
  if (envelope.length < HEADER_LENGTH) {
    throw new Error("backup file too small: not a valid ZBKP envelope");
  }
  if (!envelope.subarray(0, 4).equals(MAGIC)) {
    throw new Error("invalid backup: bad magic bytes");
  }
  const version = envelope[OFF_VERSION];
  if (version !== VERSION) {
    throw new Error(`unsupported backup envelope version: ${version}`);
  }
  return {
    salt: envelope.subarray(OFF_SALT, OFF_WRAPPED_DEK),
    wrappedDek: envelope.subarray(OFF_WRAPPED_DEK, OFF_DATA_IV),
    dataIv: envelope.subarray(OFF_DATA_IV, OFF_AUTH_TAG),
    authTag: envelope.subarray(OFF_AUTH_TAG, OFF_SHA256),
    sha256: envelope.subarray(OFF_SHA256, HEADER_LENGTH),
    ciphertext: envelope.subarray(HEADER_LENGTH),
  };
}

/** Wrap a DEK under a master key: fresh salt → KEK → GCM-wrap. Zeroes the KEK. */
export async function wrapDek(
  dek: Buffer,
  masterKey: string,
): Promise<{ salt: Buffer; wrappedDek: Buffer }> {
  const salt = randomBytes(SALT_LENGTH);
  const kek = await deriveKek(masterKey, salt);
  try {
    const { ciphertext, authTag } = aesGcmEncrypt(kek, deriveWrapIv(salt), dek);
    return { salt, wrappedDek: Buffer.concat([ciphertext, authTag]) };
  } finally {
    kek.fill(0);
  }
}

/** Unwrap a DEK under a master key. Zeroes the KEK; caller owns the returned DEK. */
export async function unwrapDek(
  wrappedDek: Buffer,
  salt: Buffer,
  masterKey: string,
): Promise<Buffer> {
  const kek = await deriveKek(masterKey, salt);
  try {
    const encDek = wrappedDek.subarray(0, KEY_LENGTH);
    const tag = wrappedDek.subarray(KEY_LENGTH, WRAPPED_DEK_LENGTH);
    return aesGcmDecrypt(kek, deriveWrapIv(salt), tag, encDek);
  } finally {
    kek.fill(0);
  }
}

export interface BackupResult {
  outputPath: string;
  sha256: string;
  bytesWritten: number;
  /**
   * Continuity point true of the sealed dump snapshot when export captured it
   * under the same PostgreSQL snapshot as `pg_dump` (scheduled path).
   */
  continuitySnapshot?: LocalContinuitySnapshot;
}

export interface ExportEncryptedBackupOptions {
  /**
   * When set, open a REPEATABLE READ transaction, derive continuity on that
   * connection, `pg_export_snapshot()`, and run `pg_dump --snapshot=…` so the
   * returned markers are bound to the sealed artifact (not a post-dump live re-read).
   */
  readonly continuityNodeId?: string;
}

export interface DecryptedBackup {
  plaintext: Buffer;
  sha256: string;
}

/**
 * Encrypt an in-memory plaintext buffer into a ZBKP envelope. The plaintext is
 * hashed (SHA-256) and AES-256-GCM sealed under a fresh random DEK; the DEK is
 * wrapped under the KEK. Key material is zeroed in finally blocks.
 */
export async function encryptBuffer(
  plaintext: Buffer,
  masterKey: string,
): Promise<Buffer> {
  const dek = randomBytes(KEY_LENGTH);
  const dataIv = randomBytes(IV_LENGTH);
  try {
    const { salt, wrappedDek } = await wrapDek(dek, masterKey);
    const sha256 = createHash("sha256").update(plaintext).digest();
    const { ciphertext, authTag } = aesGcmEncrypt(dek, dataIv, plaintext);
    return assembleEnvelope({ salt, wrappedDek, dataIv, authTag, sha256, ciphertext });
  } finally {
    dek.fill(0);
  }
}

/**
 * Parse and decrypt a ZBKP envelope. Verifies GCM auth (integrity — wrong key or
 * tampered ciphertext throws here) then the SHA-256 checksum (completeness).
 * The returned plaintext Buffer is the caller's responsibility to zero.
 */
export async function decryptBuffer(
  envelope: Buffer,
  masterKey: string,
): Promise<DecryptedBackup> {
  const parts = parseEnvelope(envelope);
  const dek = await unwrapDek(parts.wrappedDek, parts.salt, masterKey);
  let plaintext: Buffer;
  try {
    plaintext = aesGcmDecrypt(dek, parts.dataIv, parts.authTag, parts.ciphertext);
  } finally {
    dek.fill(0);
  }
  const actual = createHash("sha256").update(plaintext).digest();
  if (!actual.equals(parts.sha256)) {
    plaintext.fill(0);
    throw new Error("backup checksum mismatch: data corrupted or tampered");
  }
  return { plaintext, sha256: actual.toString("hex") };
}

/**
 * pg_dump a database and write an encrypted ZBKP envelope to `outputPath`. The
 * plaintext SQL is held only in memory (never written to disk) and zeroed once
 * the envelope is sealed.
 *
 * When `options.continuityNodeId` is set, continuity markers are derived on the
 * same PostgreSQL snapshot that `pg_dump --snapshot` exports — concurrent
 * writers after dump start cannot desync the paired witness from the artifact.
 */
export async function exportEncryptedBackup(
  databaseUrl: string,
  outputPath: string,
  masterKey: string,
  options: ExportEncryptedBackupOptions = {},
): Promise<BackupResult> {
  const nodeId = options.continuityNodeId?.trim();
  if (nodeId !== undefined && nodeId !== "") {
    return exportEncryptedBackupBoundToContinuity(databaseUrl, outputPath, masterKey, nodeId);
  }
  const plaintext = await runPgDump(databaseUrl);
  return sealPlaintextToPath(plaintext, outputPath, masterKey);
}

async function exportEncryptedBackupBoundToContinuity(
  databaseUrl: string,
  outputPath: string,
  masterKey: string,
  continuityNodeId: string,
): Promise<BackupResult> {
  return withConnectedPgClient(databaseUrl, async (client) => {
    // Hold one RR snapshot for both continuity derivation and pg_dump.
    await client.query("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY");
    try {
      const continuitySnapshot = await deriveContinuitySnapshotOnClient(client, continuityNodeId);
      const exported = await client.query<{ pg_export_snapshot: string }>(
        "SELECT pg_export_snapshot() AS pg_export_snapshot",
      );
      const snapshotId = exported.rows[0]?.pg_export_snapshot;
      if (snapshotId === undefined || snapshotId.trim() === "") {
        throw new Error("pg_export_snapshot returned empty id");
      }
      // pg_dump must finish while this transaction still holds the snapshot.
      const plaintext = await runPgDump(databaseUrl, snapshotId);
      const sealed = await sealPlaintextToPath(plaintext, outputPath, masterKey);
      return { ...sealed, continuitySnapshot };
    } finally {
      await client.query("ROLLBACK").catch(() => undefined);
    }
  });
}

async function sealPlaintextToPath(
  plaintext: Buffer,
  outputPath: string,
  masterKey: string,
): Promise<BackupResult> {
  try {
    const envelope = await encryptBuffer(plaintext, masterKey);
    await writeFile(outputPath, envelope);
    return {
      outputPath,
      sha256: createHash("sha256").update(plaintext).digest("hex"),
      bytesWritten: envelope.length,
    };
  } finally {
    plaintext.fill(0);
  }
}

/**
 * Resolve ONLY on a clean exit (`code === 0` with no signal). A signal-kill
 * (`code === null`, e.g. SIGKILL/OOM/SIGTERM) or any nonzero exit REJECTS.
 * A signal-killed child is truncated, not successful: treating it as success is
 * how a partial pg_dump gets sealed as a valid-looking ZBKP backup, or a rolled-
 * back psql restore reports success over an empty database. Both callers on the
 * generic-node DR path route through here so the guard lives in exactly one place.
 * Collects stderr for the rejection message.
 */
export function awaitCleanExit(child: ChildProcess, label: string): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    let stderr = "";
    let settled = false;
    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      reject(err);
    };
    child.stderr?.on("data", (d: Buffer) => {
      stderr += d.toString();
    });
    child.on("error", fail);
    child.on("close", (code, signal) => {
      if (settled) return;
      if (code === 0 && signal === null) {
        settled = true;
        resolve();
        return;
      }
      fail(
        new Error(
          `${label} did not exit cleanly (code=${code}, signal=${signal}): ${stderr.slice(0, 500)}`,
        ),
      );
    });
  });
}

/**
 * psql restore argv. `-v ON_ERROR_STOP=1` is load-bearing: without it psql exits
 * 0 even when a statement errors, and `--single-transaction` turns the trailing
 * COMMIT into a ROLLBACK — a fully-failed restore would otherwise report success
 * over an empty/rolled-back database. Exported so a unit can assert the flag.
 */
export function buildRestorePsqlArgs(databaseUrl: string): string[] {
  return ["--single-transaction", "-v", "ON_ERROR_STOP=1", "--quiet", "--dbname", databaseUrl];
}

/** Build `pg_dump` argv. Optional `snapshotId` binds the dump to an open backend snapshot. */
export function buildPgDumpArgs(databaseUrl: string, snapshotId?: string): string[] {
  const args = ["--format=plain", "--no-owner", "--no-acl"];
  if (snapshotId !== undefined && snapshotId.trim() !== "") {
    args.push(`--snapshot=${snapshotId}`);
  }
  args.push("--dbname", databaseUrl);
  return args;
}

/** Run `pg_dump` and return its full stdout. Rejects on nonzero exit or signal-kill. */
function runPgDump(databaseUrl: string, snapshotId?: string): Promise<Buffer> {
  const pgDump = spawn("pg_dump", buildPgDumpArgs(databaseUrl, snapshotId), {
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stdout: Buffer[] = [];
  pgDump.stdout.on("data", (d: Buffer) => stdout.push(d));
  return awaitCleanExit(pgDump, "pg_dump").then(() => Buffer.concat(stdout));
}

/**
 * Decrypt a ZBKP file and pipe the plaintext SQL into `psql --single-transaction`.
 * GCM auth and the SHA-256 checksum are verified BEFORE anything is applied to
 * the database. The plaintext buffer is zeroed once the restore settles.
 */
export async function restoreEncryptedBackup(
  backupPath: string,
  databaseUrl: string,
  masterKey: string,
  options: { readonly nodeId?: string } = {},
): Promise<{
  sha256: string;
  bytesRestored: number;
  restoreHold: { readonly applied: boolean; readonly nodeIds: readonly string[] };
  authHold: ForceAuthHoldResult;
}> {
  const envelope = await readFile(backupPath);
  const { plaintext, sha256 } = await decryptBuffer(envelope, masterKey);
  try {
    const psql = spawn("psql", buildRestorePsqlArgs(databaseUrl), {
      stdio: ["pipe", "pipe", "pipe"],
    });
    const exited = awaitCleanExit(psql, "psql");
    // A dead psql surfaces via awaitCleanExit's nonzero/signal close; swallow the
    // resulting stdin EPIPE so it does not throw as an unhandled stream error.
    psql.stdin.on("error", () => {});
    psql.stdin.end(plaintext);
    await exited;

    // Post-restore dual gate, fail-closed after apply, one transaction:
    // 1. force restore_hold=true even when the dump encoded a released row
    // 2. force every lifecycle head auth_hold=true (AUTH_HOLD_SET + head advance)
    // Clearing either hold alone must grant nothing (fault injection case 9).
    // Atomic so a failed auth_hold force cannot leave restore_hold forced alone.
    const { restoreHold, authHold } = await applyDualGateForceAfterRestore(
      databaseUrl,
      { nodeId: options.nodeId },
    );

    return { sha256, bytesRestored: plaintext.length, restoreHold, authHold };
  } finally {
    plaintext.fill(0);
  }
}

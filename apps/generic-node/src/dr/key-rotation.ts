// Backup key rotation for the generic-node ZBKP envelope. Re-wraps the DEK under a new
// master key WITHOUT decrypting the bulk ciphertext: only the 32-byte DEK is
// unwrapped (old KEK) and re-wrapped (new KEK). The data IV, data auth tag,
// SHA-256 checksum, and ciphertext pass through byte-for-byte, so the restored
// plaintext is identical and the envelope size is unchanged.

import { readFile, writeFile } from "node:fs/promises";

import {
  HEADER_LENGTH,
  assembleEnvelope,
  parseEnvelope,
  unwrapDek,
  wrapDek,
} from "./encrypted-backup.js";

export interface RotationResult {
  outputPath: string;
  bytesWritten: number;
}

/**
 * Re-encrypt a ZBKP envelope under `newMasterKey`. The plaintext is never
 * materialised — the DEK is unwrapped under `oldMasterKey` and re-wrapped under
 * `newMasterKey` with a fresh salt. Throws (GCM auth) if `oldMasterKey` is wrong.
 */
export async function rotateBackupKey(
  inputPath: string,
  outputPath: string,
  oldMasterKey: string,
  newMasterKey: string,
): Promise<RotationResult> {
  const envelope = await readFile(inputPath);
  const parts = parseEnvelope(envelope);

  const dek = await unwrapDek(parts.wrappedDek, parts.salt, oldMasterKey);
  let rotated: Buffer;
  try {
    const { salt, wrappedDek } = await wrapDek(dek, newMasterKey);
    rotated = assembleEnvelope({
      salt,
      wrappedDek,
      dataIv: parts.dataIv,
      authTag: parts.authTag,
      sha256: parts.sha256,
      ciphertext: parts.ciphertext,
    });
  } finally {
    dek.fill(0);
  }

  // Sanity: rotation must not change the envelope size (same field layout).
  // Checked BEFORE writing so a size mismatch never leaves a bad file on disk.
  if (rotated.length !== envelope.length || rotated.length < HEADER_LENGTH) {
    throw new Error("key rotation produced an unexpected envelope size");
  }
  await writeFile(outputPath, rotated);
  return { outputPath, bytesWritten: rotated.length };
}

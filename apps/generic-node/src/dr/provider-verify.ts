// Provider-backup verification — decrypt-check ZBKP artifacts without applying.

import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";

import { HEADER_LENGTH, decryptBuffer, parseEnvelope } from "./encrypted-backup.js";
import { BACKUP_ENVELOPE_EXTENSION } from "./policy.js";

export interface ProviderArtifactReport {
  readonly path: string;
  readonly ok: boolean;
  readonly bytes: number;
  readonly plaintextSha256?: string;
  readonly error?: string;
}

export interface ProviderVerifyReport {
  readonly ok: boolean;
  readonly checked: readonly ProviderArtifactReport[];
  readonly newestPath: string | null;
  readonly newestMtimeMs: number | null;
}

async function verifyOne(path: string, masterKey: string): Promise<ProviderArtifactReport> {
  let bytes = 0;
  try {
    const st = await stat(path);
    bytes = st.size;
    if (!st.isFile()) return { path, ok: false, bytes, error: "not_a_file" };
    if (bytes < HEADER_LENGTH) return { path, ok: false, bytes, error: "envelope_too_small" };
    const envelope = await readFile(path);
    parseEnvelope(envelope);
    const { plaintext, sha256 } = await decryptBuffer(envelope, masterKey);
    plaintext.fill(0);
    return { path, ok: true, bytes, plaintextSha256: sha256 };
  } catch (err) {
    return {
      path,
      ok: false,
      bytes,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function verifyProviderBackups(
  targetPath: string,
  masterKey: string,
): Promise<ProviderVerifyReport> {
  const st = await stat(targetPath);
  const paths: string[] = [];
  if (st.isFile()) {
    paths.push(targetPath);
  } else if (st.isDirectory()) {
    for (const name of await readdir(targetPath)) {
      if (name.endsWith(BACKUP_ENVELOPE_EXTENSION) && !name.endsWith(".partial")) {
        paths.push(join(targetPath, name));
      }
    }
  } else {
    return {
      ok: false,
      checked: [{ path: targetPath, ok: false, bytes: 0, error: "unsupported_path_type" }],
      newestPath: null,
      newestMtimeMs: null,
    };
  }

  if (paths.length === 0) {
    return {
      ok: false,
      checked: [{ path: targetPath, ok: false, bytes: 0, error: "no_backup_artifacts" }],
      newestPath: null,
      newestMtimeMs: null,
    };
  }

  const checked: ProviderArtifactReport[] = [];
  let newestPath: string | null = null;
  let newestMtimeMs: number | null = null;
  for (const p of paths) {
    checked.push(await verifyOne(p, masterKey));
    try {
      const m = (await stat(p)).mtimeMs;
      if (newestMtimeMs === null || m > newestMtimeMs) {
        newestMtimeMs = m;
        newestPath = p;
      }
    } catch {
      /* ignore */
    }
  }

  return { ok: checked.every((c) => c.ok), checked, newestPath, newestMtimeMs };
}

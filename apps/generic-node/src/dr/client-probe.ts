// Boot-time PostgreSQL client-binary probe.
//
// encrypted-backup.ts spawns `pg_dump`/`psql` unconditionally (runPgDump,
// restoreEncryptedBackup). A runtime image that is missing the
// postgresql-client package — or carries one built against the wrong major
// version — fails silently at the FIRST scheduled backup, leaving a false DR
// posture. Every composition root
// that enables the backup schedule (main.ts, stage1-main.ts) MUST call this
// probe once at boot and fail closed on a non-ok result, rather than letting
// the gap surface for the first time inside `schedule.ts`'s scheduled run.

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

/**
 * Server major version the runtime image's postgresql-client package is
 * pinned to (apps/generic-node/Dockerfile runtime stage installs
 * `postgresql16-client`; matches the deployed Postgres major used in
 * `.github/workflows/ci.yml` and the reference deployment). Bump together
 * with the Dockerfile package pin — never independently.
 */
export const EXPECTED_PG_CLIENT_MAJOR_VERSION = 16;

export interface PgClientProbeResult {
  readonly ok: boolean;
  readonly reason?: string;
  readonly pgDumpVersion?: string;
  readonly psqlVersion?: string;
}

function parseMajorVersion(versionOutput: string): number | undefined {
  // e.g. "pg_dump (PostgreSQL) 16.4" / "psql (PostgreSQL) 16.4 (Ubuntu ...)"
  const match = /\(PostgreSQL\)\s+(\d+)/.exec(versionOutput);
  if (!match) return undefined;
  const n = Number(match[1]);
  return Number.isInteger(n) ? n : undefined;
}

type BinaryProbeResult =
  | { readonly ok: true; readonly version: string }
  | { readonly ok: false; readonly reason: string };

async function probeBinary(bin: "pg_dump" | "psql"): Promise<BinaryProbeResult> {
  let stdout: string;
  try {
    ({ stdout } = await execFileAsync(bin, ["--version"]));
  } catch (err) {
    const code =
      err !== null && typeof err === "object" && "code" in err
        ? String((err as { code?: unknown }).code)
        : "";
    if (code === "ENOENT") {
      return {
        ok: false,
        reason: `${bin} not found on PATH — runtime image is missing the postgresql-client package`,
      };
    }
    return {
      ok: false,
      reason: `${bin} --version failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  const version = stdout.trim();
  const major = parseMajorVersion(version);
  if (major === undefined) {
    return { ok: false, reason: `${bin} --version output unparseable: ${JSON.stringify(version)}` };
  }
  if (major !== EXPECTED_PG_CLIENT_MAJOR_VERSION) {
    return {
      ok: false,
      reason:
        `${bin} major version ${major} does not match the pinned server major ` +
        `${EXPECTED_PG_CLIENT_MAJOR_VERSION} (${version}) — Dockerfile package pin and ` +
        `EXPECTED_PG_CLIENT_MAJOR_VERSION have drifted apart`,
    };
  }
  return { ok: true, version };
}

/**
 * Probe both `pg_dump` and `psql` for presence and pinned-major-version
 * match. Never throws — a non-ok result is the fail-closed signal; callers
 * decide how to act on it (refuse to boot / withhold readiness).
 */
export async function probePgClientBinaries(): Promise<PgClientProbeResult> {
  const [pgDump, psql] = await Promise.all([probeBinary("pg_dump"), probeBinary("psql")]);
  if (!pgDump.ok) return { ok: false, reason: pgDump.reason };
  if (!psql.ok) return { ok: false, reason: psql.reason };
  return { ok: true, pgDumpVersion: pgDump.version, psqlVersion: psql.version };
}

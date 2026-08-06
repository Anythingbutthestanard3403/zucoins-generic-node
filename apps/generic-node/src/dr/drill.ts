// Disaster-recovery drill for generic-node. Full backup → verify-no-plaintext →
// destroy → restore → verify against a throwaway database. Records RPO/RTO.

import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  exportEncryptedBackup,
  restoreEncryptedBackup,
} from "./encrypted-backup.js";

export interface DrillResult {
  passed: boolean;
  backupSha256: string;
  restoreSha256: string;
  /** Wall-clock duration of the full destroy→restore→verify cycle (RTO evidence). */
  durationMs: number;
  /**
   * Recovery-point objective realized by this drill against the protected seed
   * set. 0 means the seed set was fully recovered; post-export writes are
   * deliberately outside the window and asserted absent after restore.
   */
  rpoMs: number;
  /** Concrete data-loss statement — never a qualitative claim. */
  rpoStatement: string;
  steps: string[];
}

const SEED_PAYLOADS = ["alpha", "bravo", "charlie"] as const;

/**
 * Resolve createdb | dropdb | psql via PG_BIN / POSTGRES_BIN directory or PATH.
 */
export function resolvePgClientBinary(tool: "createdb" | "dropdb" | "psql"): string {
  const binDir = (process.env.PG_BIN ?? process.env.POSTGRES_BIN ?? "").trim();
  if (binDir.length > 0) {
    return join(binDir, tool);
  }
  return tool;
}

function execPgTool(
  tool: "createdb" | "dropdb" | "psql",
  args: readonly string[],
  options: { encoding?: "utf8"; stdio?: "ignore" },
): string {
  const bin = resolvePgClientBinary(tool);
  try {
    const out = execFileSync(bin, [...args], {
      encoding: options.encoding ?? "utf8",
      stdio: options.stdio,
    });
    return typeof out === "string" ? out : "";
  } catch (err) {
    const code =
      err !== null && typeof err === "object" && "code" in err
        ? String((err as { code?: unknown }).code)
        : "";
    if (code === "ENOENT") {
      throw new Error(
        `${tool} not found (resolved as ${JSON.stringify(bin)}). ` +
          `Set PG_BIN or POSTGRES_BIN to the directory containing PostgreSQL client ` +
          `binaries (createdb, dropdb, psql), or add that directory to PATH.`,
      );
    }
    throw err;
  }
}

function psqlSql(databaseUrl: string, statement: string): string {
  return execPgTool(
    "psql",
    ["--quiet", "--tuples-only", "--no-align", "--dbname", databaseUrl, "--command", statement],
    { encoding: "utf8" },
  ).trim();
}

/**
 * Execute a full DR drill. `templateUrl` must point at an existing maintenance
 * database (e.g. `.../postgres`) used to create/drop the throwaway drill DB;
 * `masterKey` is the backup KEK secret (BACKUP_MASTER_KEY — not the signing key).
 * Never throws: failures are captured in the returned result with `passed:false`.
 */
export async function runDrill(
  templateUrl: string,
  masterKey: string,
): Promise<DrillResult> {
  const start = Date.now();
  const steps: string[] = [];
  const drillDb = `dr_drill_${randomBytes(4).toString("hex")}`;
  // Swap only the database name (last path segment), preserving any trailing
  // query/params (e.g. `?sslmode=require`) so the drill DB connects with the
  // template's connection parameters. Host encoding is left byte-for-byte intact.
  const drillUrl = templateUrl.replace(/\/[^/?#]*(\?|#|$)/, `/${drillDb}$1`);
  const workDir = await mkdtemp(join(tmpdir(), "dr-drill-"));
  const backupPath = join(workDir, "drill-backup.zbkp");

  try {
    execPgTool("createdb", ["--maintenance-db", templateUrl, drillDb], { stdio: "ignore" });
    steps.push("created throwaway database");

    psqlSql(
      drillUrl,
      "CREATE TABLE drill_verify (id serial PRIMARY KEY, payload text NOT NULL, written_at timestamptz NOT NULL DEFAULT now()); " +
        `INSERT INTO drill_verify (payload) VALUES ${SEED_PAYLOADS.map((p) => `('${p}')`).join(", ")};`,
    );
    steps.push("seeded test data");

    const exportStartedAt = Date.now();
    const backup = await exportEncryptedBackup(drillUrl, backupPath, masterKey);
    const exportedAt = Date.now();
    steps.push(`encrypted backup exported (${backup.bytesWritten} bytes)`);

    // Post-export write: proves RPO is "state after last successful export is lost".
    psqlSql(
      drillUrl,
      "INSERT INTO drill_verify (payload) VALUES ('post-export-unrecoverable');",
    );
    steps.push("wrote post-export row (intentionally outside RPO window)");

    const raw = await readFile(backupPath);
    if (!raw.subarray(0, 4).equals(Buffer.from("ZBKP"))) {
      throw new Error("backup missing ZBKP magic header");
    }
    const asText = raw.toString("latin1");
    if (asText.includes("CREATE TABLE") || asText.includes("INSERT INTO") || asText.includes("drill_verify")) {
      throw new Error("backup contains plaintext SQL — encryption is broken");
    }
    steps.push("verified backup is encrypted (no plaintext SQL)");

    execPgTool("dropdb", ["--maintenance-db", templateUrl, drillDb], { stdio: "ignore" });
    steps.push("destroyed database (simulated disaster)");

    execPgTool("createdb", ["--maintenance-db", templateUrl, drillDb], { stdio: "ignore" });
    steps.push("recreated empty database");

    const restore = await restoreEncryptedBackup(backupPath, drillUrl, masterKey);
    steps.push(`restored from encrypted backup (${restore.bytesRestored} bytes)`);

    const count = psqlSql(drillUrl, "SELECT count(*) FROM drill_verify;");
    if (count !== String(SEED_PAYLOADS.length)) {
      throw new Error(`expected ${SEED_PAYLOADS.length} rows after restore, got ${count}`);
    }
    const payloads = psqlSql(drillUrl, "SELECT payload FROM drill_verify ORDER BY id;"); // contract-allow:order:frozen-sql-text
    if (payloads !== SEED_PAYLOADS.join("\n")) {
      throw new Error(`restored data mismatch: ${payloads}`);
    }
    const postExport = psqlSql(
      drillUrl,
      "SELECT count(*) FROM drill_verify WHERE payload = 'post-export-unrecoverable';",
    );
    if (postExport !== "0") {
      throw new Error("post-export row survived restore — RPO evidence inverted");
    }
    steps.push("verified restored data matches original (post-export row absent)");

    const rpoStatement =
      `RPO = state committed after export at t=${exportedAt} is unrecoverable from this artifact; ` +
      `seed rows (${SEED_PAYLOADS.length}) recovered; post-export row discarded as designed; ` +
      `exportStartedAt=${exportStartedAt} exportedAt=${exportedAt}.`;

    return {
      passed: true,
      backupSha256: backup.sha256,
      restoreSha256: restore.sha256,
      durationMs: Date.now() - start,
      rpoMs: 0,
      rpoStatement,
      steps,
    };
  } catch (err) {
    return {
      passed: false,
      backupSha256: "",
      restoreSha256: "",
      durationMs: Date.now() - start,
      rpoMs: -1,
      rpoStatement: "drill failed before RPO could be measured",
      steps: [...steps, `FAILED: ${err instanceof Error ? err.message : String(err)}`],
    };
  } finally {
    try {
      execPgTool("dropdb", ["--if-exists", "--maintenance-db", templateUrl, drillDb], {
        stdio: "ignore",
      });
    } catch {
      /* best-effort cleanup */
    }
    await rm(workDir, { recursive: true, force: true });
  }
}

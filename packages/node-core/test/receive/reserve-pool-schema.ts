// Disposable schema for the GN-102 reserve-pool drills.
// Applies only the slices those inserts touch. destination_state WORKER is
// committed in its own psql call before any later statement names the label.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../../src/schema");

const readSchema = (name: string): string => readFileSync(resolve(schemaDir, name), "utf8");

const blockFrom = (sql: string, header: RegExp, label: string): string => {
  const found = header.exec(sql);
  if (found === null) throw new Error(`${label}: block not found`);
  return found[0];
};

const stripDomains = (sql: string): string => sql.replace(/CREATE DOMAIN [\s\S]*?;/g, "");

export const withDatabase = (url: string, database: string): string => {
  const parsed = new URL(url);
  parsed.pathname = `/${database}`;
  return parsed.toString();
};

const psqlApply = (url: string, sql: string, singleTx: boolean): void => {
  const args = [url, "-v", "ON_ERROR_STOP=1"];
  if (singleTx) args.push("-1");
  args.push("-q", "-f", "-");
  try {
    execFileSync("psql", args, {
      input: sql,
      encoding: "utf-8",
      timeout: 60_000,
      stdio: ["pipe", "pipe", "pipe"],
    });
  } catch (err) {
    const stderr = (err as { stderr?: string }).stderr ?? "";
    throw new Error(`schema apply failed: ${stderr.trim() || "psql failed"}`);
  }
};

export const psqlMust = (url: string, sql: string): string => {
  try {
    return execFileSync("psql", [url, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql], {
      encoding: "utf-8",
      timeout: 30_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    const stderr = (err as { stderr?: string }).stderr ?? "";
    throw new Error(`psql failed: ${stderr.trim() || "unknown"}`);
  }
};

/** Base custody plus the reserve-pool slices. Caller seeds the node. */
export function applyReservePoolSchema(url: string): void {
  const registry = readSchema("node-implementer-registry.sql");
  const nodes = blockFrom(registry, /^CREATE TABLE nodes \([\s\S]*?^\);$/m, "nodes");
  const implementers = blockFrom(
    registry,
    /^CREATE TABLE implementers \([\s\S]*?^\);$/m,
    "implementers",
  );
  const operations = blockFrom(
    readSchema("operations.sql"),
    /^CREATE TABLE operations \([\s\S]*?^\);$/m,
    "operations",
  );
  psqlApply(
    url,
    [
      readSchema("base-enums-domains.sql"),
      nodes,
      implementers,
      readSchema("custody-eligibility.sql"),
      readSchema("wallet-money-capability.sql"),
      readSchema("destinations-idempotency-key.sql"),
      operations,
      readSchema("implementer-funding-wallet.sql"),
    ].join("\n"),
    true,
  );
  // ADD VALUE must commit before a later statement uses the label.
  psqlApply(url, readSchema("destination-state-worker.sql"), false);
  psqlApply(
    url,
    [
      readSchema("destination-worker-sink.sql"),
      readSchema("connector-reserve-wallets.sql"),
      readSchema("operational-stores.sql"),
      stripDomains(readSchema("audit-log.sql")),
      stripDomains(readSchema("signer-support.sql")),
    ].join("\n"),
    true,
  );
}

const NODE_PUB = `${"C".repeat(43)}=`;

export function seedReserveNode(url: string, nodeId: string): void {
  if (!/^[0-9a-f-]{36}$/i.test(nodeId)) throw new Error("node id is not a uuid");
  psqlMust(
    url,
    `INSERT INTO nodes (id, display_name, identity_public_key)
     VALUES ('${nodeId}', 'reserve-pool-node', '${NODE_PUB}')`,
  );
}

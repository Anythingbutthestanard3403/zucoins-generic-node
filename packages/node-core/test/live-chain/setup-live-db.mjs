#!/usr/bin/env node
// Provision the durable store for a live-chain acceptance run from the REAL node-core
// schema. The DDL files declare their shared domains/enums locally so they can be applied
// standalone; applied together, every file after base-enums-domains.sql must have those
// duplicate declarations stripped. Mirrors what test/*.pg.test.ts do inline.
//
//   node packages/node-core/test/live-chain/setup-live-db.mjs [database] # SEND
//   node packages/node-core/test/live-chain/setup-live-db.mjs --receive [db] # RECEIVE

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

const args = process.argv.slice(2);
const receive = args.includes("--receive");
const positional = args.filter((a) => !a.startsWith("--"));
const db =
  positional[0] ??
  (receive
    ? (process.env.RECEIVE_EXECUTE_DATABASE ?? "receive_execute_live")
    : (process.env.SEND_EXECUTE_DATABASE ?? "send_execute_live"));
const schemaDir = join(dirname(fileURLToPath(import.meta.url)), "../../src/schema");

// Dependency order: domains/enums, then registry, then the tables that reference them.
// A foreign key needs its target relation to exist EARLIER in the sequence, so
// custody-eligibility (wallets, destinations, wallet_active_leases) precedes the flow
// tables that reference them.
const SEND_FILES = [
  "base-enums-domains",
  "node-implementer-registry",
  "custody-eligibility",
  "send-external-create",
  "send-external-landing",
  "send-external-expiry",
  "operations",
  "approval-stores",
  "transaction-material",
  "submit-attempts",
  "signer-support",
];

// RECEIVE_EXTERNAL. receive-admission.sql supplies receive_operations;
// operation_transactions / submit_decisions / gateway_submit_attempts are the shared submit
// tables the ceremony's row counts are read from.
const RECEIVE_FILES = [
  "base-enums-domains",
  "node-implementer-registry",
  "custody-eligibility",
  "receive-admission",
  "operations",
  // receive_codes — durable transfer code material; FK-bound to
  // operations(id) and wallets(id), both declared earlier in this list.
  "receive-codes",
  // receive_arms — durable arm acknowledgement; FK-bound to
  // receive_codes(operation_id), nodes(id), implementers(id), reporting_request_nonces,
  // reporting_mutation_idempotency, and gateway_observations.
  "receive-arms",
  "approval-stores",
  "transaction-material",
  "submit-attempts",
  "signer-support",
];

const FILES = receive ? RECEIVE_FILES : SEND_FILES;

const psql = (database, args) =>
  execFileSync("psql", ["-d", database, "-v", "ON_ERROR_STOP=1", ...args], {
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "pipe"],
  });

function prepare(name, stripShared) {
  let sql = readFileSync(join(schemaDir, `${name}.sql`), "utf8");
  if (stripShared) {
    sql = sql
      .replace(/^CREATE DOMAIN\s+\w+\s+AS[^;]*;\s*$/gm, "")
      .replace(/^CREATE TYPE\s+\w+\s+AS[^;]*;\s*$/gm, "");
  }
  sql = sql
    .replace(/\bCREATE TABLE (?!IF NOT EXISTS)/g, "CREATE TABLE IF NOT EXISTS ")
    .replace(/\bCREATE (UNIQUE )?INDEX (?!IF NOT EXISTS)/g, (_m, u) =>
      `CREATE ${u ?? ""}INDEX IF NOT EXISTS `,
    );
  const path = join(tmpdir(), `send-execute-${name}.sql`);
  writeFileSync(path, sql, "utf8");
  return path;
}

psql("postgres", ["-qAt", "-c", `DROP DATABASE IF EXISTS "${db}" WITH (FORCE)`]);
psql("postgres", ["-qAt", "-c", `CREATE DATABASE "${db}"`]);
for (const [index, name] of FILES.entries()) {
  psql(db, ["-1", "-f", prepare(name, index > 0)]);
  process.stdout.write(`${name} applied\n`);
}
process.stdout.write(`database ${db} ready\n`);

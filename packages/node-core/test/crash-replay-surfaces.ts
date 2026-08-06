/**
 * Residual crash/replay proof harness — parsed frozen surfaces.
 *
 * Provenance (attack finding F4): the harness's constraint enforcement is derived ONLY
 * from parseTables/parseDomains over the real transaction-material.sql bytes, plus
 * vocabulary extracted from the frozen spec surface (data-model.fixture.md; no
 * shipped .sql artifact exists for those surfaces — extraction with non-trivial guards). Named
 * divergences from a live database, recorded per the synthesis: (1) no column DEFAULTs
 * applied (model stricter than Postgres); (2) no FK semantics; (3) uuid `===` compare
 * (fixtures are canonical lowercase); (4) POSIX `~` regexes evaluated via JS RegExp;
 * (5) no triggers — byte-immutability is expressed as the column-restricted update port,
 * never claimed as a database rejection.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { TRANSACTION_MATERIAL_SCHEMA_FILE } from "../src/schema/transaction-material.contract.ts";
import {
  parseDomains,
  parseTables,
  tableByName,
} from "./transaction-material-sql-parser.ts";

const here = dirname(fileURLToPath(import.meta.url));

export const DATA_MODEL_DOC = readFileSync(
  resolve(here, "data-model.fixture.md"),
  "utf8",
);

const sqlBytes = readFileSync(
  resolve(here, "../src/schema", TRANSACTION_MATERIAL_SCHEMA_FILE),
  "utf8",
);

export const MATERIAL_TABLES = parseTables(sqlBytes);
export const MATERIAL_DOMAINS = parseDomains(sqlBytes);
export const SIGN_INTENTS_TABLE = tableByName(MATERIAL_TABLES, "external_send_sign_intents");
export const ATTEMPTS_TABLE = tableByName(MATERIAL_TABLES, "operation_transactions");
export const PARTIALS_TABLE = tableByName(MATERIAL_TABLES, "external_send_partials");

export const SIGN_INTENTS_TABLE_NAME = "external_send_sign_intents";
export const PARTIALS_TABLE_NAME = "external_send_partials";
export const ATTEMPTS_TABLE_NAME = "operation_transactions";

export const docSection = (startHeading: string, endHeading: string): string => {
  const start = DATA_MODEL_DOC.indexOf(startHeading);
  if (start === -1) {
    throw new Error(`crash-replay surfaces: heading not found: ${startHeading}`);
  }
  const end = DATA_MODEL_DOC.indexOf(endHeading, start);
  if (end === -1) {
    throw new Error(`crash-replay surfaces: no ${endHeading} after ${startHeading}`);
  }
  return DATA_MODEL_DOC.slice(start, end);
};

const enumMembersOf = (body: string): string[] =>
  [...body.matchAll(/'([A-Z_]+)'/g)].map((match) => match[1]);

/** The data-model external_formation_state enum, doc-extracted with a non-trivial guard. */
export const FORMATION_ENUM_MEMBERS: readonly string[] = (() => {
  const section = docSection("## 2. Enumerations", "## 3.");
  const match = /CREATE TYPE external_formation_state AS ENUM \(\n([\s\S]*?)\);/.exec(section);
  if (match === null) {
    throw new Error("crash-replay surfaces: data-model external_formation_state enum not found");
  }
  const members = enumMembersOf(match[1]);
  if (members.length !== 6) {
    throw new Error(
      `crash-replay surfaces: expected 6 enum members, extracted ${members.length}`,
    );
  }
  return members;
})();

/** The SEND_EXTERNAL status literals of the data-model kind/status CHECK, doc-extracted. */
export const SEND_EXTERNAL_STATUSES: readonly string[] = (() => {
  const section = docSection("## 6. Operations", "## 7.");
  const match = /kind = 'SEND_EXTERNAL' AND status IN\s*\(\s*([\s\S]*?)\)/.exec(section);
  if (match === null) {
    throw new Error("crash-replay surfaces: data-model SEND_EXTERNAL status CHECK not found");
  }
  const members = enumMembersOf(match[1]);
  if (members.length !== 6) {
    throw new Error(
      `crash-replay surfaces: expected 6 SEND_EXTERNAL statuses, extracted ${members.length}`,
    );
  }
  return members;
})();

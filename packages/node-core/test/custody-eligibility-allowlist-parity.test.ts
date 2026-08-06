// Subset parity between the frozen automatic-sink allowlist
// (generic-node-contracts) and the custody-eligibility.sql MOVE_DESTINATION lease
// guard.
//
// SUBSET, not equality: the SQL layer is a structural backstop and the contract is
// product-level policy — the layers legitimately differ in role, so the SQL guard is free
// to structurally admit a wallet_state the product-level contract does not (yet) rely on.
// What must never happen is the reverse: the contract believing a wallet_state is
// automatic-sink eligible while the database would reject the lease outright. This test
// asserts allowedWalletStates ⊆ (full wallet_state enum minus SQL-denied set), i.e. every
// contract-allowed state is drawn from the SQL-admitted set — never the stronger (and
// wrong) claim that the two sets are equal. Exact-today equality over the full enum is
// separately censused in custody-eligibility.census.test.ts, which is the test that should
// break if the two layers are ever expected to move in lockstep.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CUSTODY_SCHEMA_FILE } from "../src/schema/custody-eligibility.contract.ts";
import { AUTOMATIC_SINK_CONJUNCTS } from "../../generic-node-contracts/src/custody/predicates.contract.ts";
import { parseSinkLeaseAdmittedStates, parseWalletStateEnum } from "./custody-eligibility-sql-parser.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", CUSTODY_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
// The wallet_state enum now lives only in base-enums-domains.sql —
// custody-eligibility.sql is prerequisite-bound and no longer re-declares data-model types.
const baseSql = readFileSync(resolve(here, "../src/schema", "base-enums-domains.sql"), "utf8");

describe("custody-eligibility allowlist subset parity", () => {
  it("the frozen contract's allowedWalletStates is a SUBSET of the SQL-admitted set", () => {
    const sqlAdmitted = new Set(parseSinkLeaseAdmittedStates(sql));
    const contractAllowed = AUTOMATIC_SINK_CONJUNCTS.allowedWalletStates as readonly string[];

    const notAdmittedBySql = contractAllowed.filter((state) => !sqlAdmitted.has(state));
    expect(notAdmittedBySql).toEqual([]);
  });

  it("every SQL-admitted state is drawn from the real wallet_state enum (sanity)", () => {
    const enumStates = new Set(parseWalletStateEnum(baseSql));
    const sqlAdmitted = parseSinkLeaseAdmittedStates(sql);

    const unknown = sqlAdmitted.filter((state) => !enumStates.has(state));
    expect(unknown).toEqual([]);
  });
});

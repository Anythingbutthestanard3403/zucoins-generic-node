// census: binds the frozen operation-model invariant inventory to the literal
// SQL contract text and cross-binds the SQL enum literals to the frozen operation
// vocabulary in @zucoins/generic-node-contracts (operation kinds, per-kind status
// ladders, formation-state sequence), so the truth carriers (contract inventory, SQL
// text, frozen vocabularies) cannot drift apart silently. Live-database execution is a
// schema-apply obligation, inventoried in the contract, not silently omitted.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  SCHEMA_OPERATIONS_OBLIGATIONS,
  OPERATIONS_INVARIANTS,
  OPERATIONS_MUTABILITY_REGIMES,
  OPERATIONS_SCHEMA_FILE,
} from "../src/schema/operations.contract.ts";
import { OPERATION_KINDS } from "../../generic-node-contracts/src/operations/operations.contract.ts";
import {
  MOVE_INTERNAL_STATES,
  RECEIVE_EXTERNAL_STATES,
  SEND_EXTERNAL_STATES,
} from "../../generic-node-contracts/src/operations/states.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", OPERATIONS_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

const parseEnumLiterals = (text: string, typeName: string): string[] => {
  const declaration = new RegExp(`CREATE TYPE ${typeName} AS ENUM \\(([^)]*)\\)`).exec(text);
  if (declaration === null || declaration[1] === undefined) {
    return [];
  }
  return [...declaration[1].matchAll(/'([^']+)'/g)].map((match) => match[1] ?? "");
};

// Extracts the status IN (...) list that follows a "<kind>' AND status IN" inside the
// per-kind status-ladder CHECK.
const parseKindStatusLiterals = (text: string, kind: string): string[] => {
  const check = new RegExp(`'${kind}' AND status IN\\s*\\(([^)]*)\\)`).exec(text);
  if (check === null || check[1] === undefined) {
    return [];
  }
  return [...check[1].matchAll(/'([^']+)'/g)].map((match) => match[1] ?? "");
};

describe("operations schema census (the data model, the one-in-flight-per-wallet rule)", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = OPERATIONS_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("SQL operation_kind literals equal the three frozen kinds, sequence included", () => {
    expect(parseEnumLiterals(sql, "operation_kind")).toEqual([...OPERATION_KINDS]);
  });

  it("SQL per-kind status ladders equal the frozen per-kind state sets", () => {
    expect(parseKindStatusLiterals(sql, "RECEIVE_EXTERNAL")).toEqual([
      ...RECEIVE_EXTERNAL_STATES,
    ]);
    expect(parseKindStatusLiterals(sql, "MOVE_INTERNAL")).toEqual([...MOVE_INTERNAL_STATES]);
    expect(parseKindStatusLiterals(sql, "SEND_EXTERNAL")).toEqual([...SEND_EXTERNAL_STATES]);
  });

  it("SQL external_formation_state literals are the closed six-value set", () => {
    // The SQL enum is a distinct vocabulary from the signing custody formation-state sequence
    // frozen in generic-node-contracts (FORMATION_STATES), which additionally carries
    // AWAITING_REDEMPTION; the SQL enum never does. Assert the verbatim set.
    expect(parseEnumLiterals(sql, "external_formation_state")).toEqual([
      "NOT_REQUIRED",
      "APPROVAL_PENDING",
      "APPROVED_UNSIGNED",
      "SIGNING_CLAIMED",
      "PARTIAL_PERSISTED",
      "PARTIAL_DELIVERED",
    ]);
  });

  it("SQL verification_verdict literals are the closed four-value set", () => {
    expect(parseEnumLiterals(sql, "verification_verdict")).toEqual([
      "PENDING",
      "VERIFIED",
      "REJECTED",
      "INDETERMINATE",
    ]);
  });

  it("the operation_role CHECK literals are the closed RECEIVER/SOURCE/DESTINATION set", () => {
    const roleCheck = /operation_role IN \(([^)]*)\)/.exec(sql);
    expect(roleCheck).not.toBeNull();
    const literals = [...(roleCheck?.[1] ?? "").matchAll(/'([^']+)'/g)].map(
      (match) => match[1] ?? "",
    );
    expect(literals).toEqual(["RECEIVER", "SOURCE", "DESTINATION"]);
  });

  it("idempotency is structural: per-(implementer, kind, key) uniqueness plus a request digest", () => {
    expect(sql).toContain("UNIQUE (implementer_id, kind, idempotency_key)");
    expect(sql).toContain("request_sha256 sha256_hex NOT NULL");
    expect(sql).toContain("CHECK (idempotency_key ~ '^[!-~]{16,255}$')");
  });

  it("operation identity is pinned to its node and implementer", () => {
    expect(sql).toContain("UNIQUE (id, node_id, implementer_id)");
  });

  it("parent→child spawn is structural: at most one non-null spawned_from_operation_id", () => {
    expect(sql).toContain("CREATE UNIQUE INDEX operations_one_spawn_per_parent_uidx");
    expect(sql).toContain("ON operations (spawned_from_operation_id)");
    expect(sql).toContain("WHERE spawned_from_operation_id IS NOT NULL");
  });

  it("compare-and-swap is structural: a positive row_version defaults to 1", () => {
    expect(sql).toContain("row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0)");
  });

  it("a receive discriminates on its own id and a base64url anchor; other kinds carry neither", () => {
    expect(sql).toContain("CHECK (kind <> 'RECEIVE_EXTERNAL' OR discriminator = id)");
    expect(sql).toContain("CHECK (kind <> 'RECEIVE_EXTERNAL' OR anchor ~ '^[A-Za-z0-9_-]{1,96}$')");
  });

  it("a walletless receive may be CREATED or EXPIRED, in BOTH arms that couple the two", () => {
    // Two CHECKs bind `receiver_wallet_id IS NULL` to a status -- the assignment triple and the
    // receive arm of the per-kind wallet shape. widened both so the never-assigned
    // receive at node-core step 5 has a legal terminal row.
    // Reverting either one alone puts that step back out of reach, so bind the count, not one
    // site.
    // Matched with the coupled column so the header comment's prose mention is not counted.
    expect(
      sql.match(/status IN \('CREATED','EXPIRED'\) AND receiver_wallet_id IS NULL/g) ?? [],
    ).toHaveLength(2);
    expect(sql).not.toContain("status = 'CREATED' AND receiver_wallet_id IS NULL");
    // The widening is EXPIRED only: expiry and T0 stay unrepresentable without a wallet in
    // either walletless status, and READY / RECEIVE_LANDED still need the full triple.
    expect(sql).toContain(
      "status IN ('CREATED','EXPIRED') AND receiver_wallet_id IS NULL\n" +
        "      AND expiry_unix_time_secs IS NULL AND t0_observation_id IS NULL",
    );
  });

  it("only a send forms a transaction: formation_state is required iff kind is SEND_EXTERNAL", () => {
    expect(sql).toContain("CHECK ((kind = 'SEND_EXTERNAL') = (formation_state <> 'NOT_REQUIRED'))");
  });

  it("operation_wallets binds one role per operation and one row per (operation, wallet)", () => {
    expect(sql).toContain("PRIMARY KEY (operation_id, wallet_id)");
    expect(sql).toContain("UNIQUE (operation_id, operation_role)");
  });

  it("mutation negative: dropping the idempotency uniqueness is caught", () => {
    const removed = sql.replace("UNIQUE (implementer_id, kind, idempotency_key),\n", "");
    expect(removed).not.toBe(sql);
    const missing = OPERATIONS_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("OPERATION_IDEMPOTENCY_UNIQUE_PER_IMPLEMENTER_KIND");
  });

  it("mutation negative: dropping the composite identity uniqueness is caught", () => {
    const removed = sql.replace("UNIQUE (id, node_id, implementer_id),\n", "");
    expect(removed).not.toBe(sql);
    const missing = OPERATIONS_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("OPERATION_COMPOSITE_IDENTITY_UNIQUE");
  });

  it("mutation negative: dropping the one-spawn-per-parent unique index is caught", () => {
    const removed = sql.replace(
      "CREATE UNIQUE INDEX operations_one_spawn_per_parent_uidx\n  ON operations (spawned_from_operation_id)\n  WHERE spawned_from_operation_id IS NOT NULL;\n",
      "",
    );
    expect(removed).not.toBe(sql);
    const missing = OPERATIONS_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("OPERATION_ONE_SPAWN_PER_PARENT");
  });

  it("mutation negative: reverting amount_zkz to the grammar-only domain (zero-form bypass) is caught", () => {
    // Reintroducing the earlier grammar-only zkz_amount_text domain -- whose companion
    // string `amount_zkz <> '0'` check accepted numerically-zero forms -- drops the frozen
    // OPERATION_AMOUNT_POSITIVE anchor, so the census fails.
    const removed = sql.replace(
      "amount_zkz zkz_amount_positive_text NOT NULL,",
      "amount_zkz zkz_amount_text NOT NULL,",
    );
    expect(removed).not.toBe(sql);
    const missing = OPERATIONS_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("OPERATION_AMOUNT_POSITIVE");
  });

  it("mutation negative: narrowing the walletless-receive arm back to CREATED is caught", () => {
    // Reverting the assignment-triple arm to the earlier `status = 'CREATED'` form drops the
    // frozen OPERATION_RECEIVE_ASSIGNMENT_TRIPLE anchor, so the census fails rather than
    // silently re-forbidding that terminal row.
    const narrowed = sql.replace(
      "status IN ('CREATED','EXPIRED') AND receiver_wallet_id IS NULL\n      AND expiry_unix_time_secs IS NULL",
      "status = 'CREATED' AND receiver_wallet_id IS NULL\n      AND expiry_unix_time_secs IS NULL",
    );
    expect(narrowed).not.toBe(sql);
    const missing = OPERATIONS_INVARIANTS.filter(
      (invariant) => !narrowed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("OPERATION_RECEIVE_ASSIGNMENT_TRIPLE");
  });

  it("mutation negative: dropping the per-operation role uniqueness is caught", () => {
    const removed = sql.replace("UNIQUE (operation_id, operation_role)", "");
    expect(removed).not.toBe(sql);
    const missing = OPERATIONS_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("WALLET_PARTICIPATION_ONE_ROLE_PER_OPERATION");
  });

  it("mutation negative: dropping the send-iff-formation biconditional is caught", () => {
    const removed = sql.replace(
      "CHECK ((kind = 'SEND_EXTERNAL') = (formation_state <> 'NOT_REQUIRED')),\n",
      "",
    );
    expect(removed).not.toBe(sql);
    const missing = OPERATIONS_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("OPERATION_SEND_IFF_FORMATION_REQUIRED");
  });

  it("mutation negative: dropping the CAS row_version CHECK is caught", () => {
    const removed = sql.replace(
      "row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),",
      "row_version bigint NOT NULL DEFAULT 1,",
    );
    expect(removed).not.toBe(sql);
    const missing = OPERATIONS_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("OPERATION_ROW_VERSION_CAS");
  });

  it("mutability regimes: CAS-guarded operations, one-way observation binding on operation_wallets", () => {
    const byTable = Object.fromEntries(
      OPERATIONS_MUTABILITY_REGIMES.map((regime) => [regime.table, regime]),
    );
    expect(byTable.operations?.regime).toBe("cas_guarded_status_transition");
    expect(byTable.operations?.updatableColumns).toContain("status");
    expect(byTable.operations?.updatableColumns).toContain("row_version");
    expect(byTable.operations?.updatableColumns).toContain("attention_episode");
    expect(byTable.operations?.updatableColumns).toContain("receive_release_status");
    expect(byTable.operations?.updatableColumns).not.toContain("id");
    expect(byTable.operations?.updatableColumns).not.toContain("request_sha256");
    expect(byTable.operations?.updatableColumns).not.toContain("idempotency_key");
    expect(byTable.operation_wallets?.regime).toBe("insert_then_one_way_observation_binding");
    expect(byTable.operation_wallets?.updatableColumns).toEqual([
      "t0_observation_id",
      "terminal_observation_id",
    ]);
  });

  it("live-database obligations are inventoried, including the lease-lane FK sequencing", () => {
    expect(SCHEMA_OPERATIONS_OBLIGATIONS.length).toBeGreaterThanOrEqual(8);
    for (const obligation of SCHEMA_OPERATIONS_OBLIGATIONS) {
      expect(obligation.length).toBeGreaterThan(20);
    }
    expect(
      SCHEMA_OPERATIONS_OBLIGATIONS.some((obligation) => obligation.includes("the one-in-flight-per-wallet rule")),
    ).toBe(true);
    expect(
      SCHEMA_OPERATIONS_OBLIGATIONS.some((obligation) =>
        obligation.includes("custody wallets(wallet_id) naming conflict"),
      ),
    ).toBe(true);
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });
});

// census: binds the frozen base-foundation invariant inventory to the literal SQL
// contract text, and cross-binds the five reference scalar domain predicates to the frozen
// upstream contracts in @zucoins/generic-node-contracts. base-enums-domains.sql is the one
// artifact every table-bearing schema contract depends on, and until this file existed its
// 23-entry inventory was bound to nothing — an sqlAnchor could name a statement the DDL did
// not contain, and no test would have noticed.
//
// The inventory→SQL direction alone is not sufficient: it cannot see a domain or enum ADDED
// to the DDL with no inventory row. Both directions are asserted below.
//
// Live-database execution of this DDL is proved separately, against real PostgreSQL, by
// base-enums-domains.pg.test.ts. This file is the text-level drift gate; that file is the
// behavioural one. Neither substitutes for the other.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { ZKZ_AMOUNT_CHECK_DOMAINS } from "@zucoins/generic-node-contracts/amounts";
// scalars.contract.ts is the declared OWNER of these three patterns; the copies in
// machine-manifests/schema-vocabs.contract.ts are a doc transcription that says so.
import {
  PADDED_BASE64URL_PUBKEY_PATTERN,
  PADDED_BASE64URL_SIGNATURE_PATTERN,
  SHA256_HEX_PATTERN,
} from "@zucoins/generic-node-contracts/observation";

import {
  BASE_ENUMS_DOMAINS_INVARIANTS,
  BASE_ENUMS_DOMAINS_SCHEMA_FILE,
} from "../src/schema/base-enums-domains.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", BASE_ENUMS_DOMAINS_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");

// The executable DDL with comment lines removed, so the header comments that NAME the retired
// domain in order to explain its retirement do not themselves trip the absence ratchet.
const ddl = sql
  .split("\n")
  .filter((line) => !/^\s*--/.test(line))
  .join("\n");

describe("base-enums-domains schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = BASE_ENUMS_DOMAINS_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("the inventory is non-trivial and its ids are unique", () => {
    // Guards the census itself: an emptied inventory would make the anchor check above pass
    // vacuously.
    expect(BASE_ENUMS_DOMAINS_INVARIANTS.length).toBeGreaterThanOrEqual(23);
    const ids = BASE_ENUMS_DOMAINS_INVARIANTS.map((i) => i.id);
    expect([...new Set(ids)]).toHaveLength(ids.length);
  });

  it("the two amount domains carry the frozen upstream predicates verbatim", () => {
    // Cross-package binding: the DDL predicate is compared to ZKZ_AMOUNT_CHECK_DOMAINS, not to
    // a regex re-declared here. Redeclaring it would only prove this file agrees with itself.
    for (const [domain, predicate] of Object.entries(ZKZ_AMOUNT_CHECK_DOMAINS)) {
      expect(ddl, `${domain} drifted from the frozen ZKZ_AMOUNT_CHECK_DOMAINS predicate`).toContain(
        `CREATE DOMAIN ${domain} AS text\n  CHECK (${predicate});`,
      );
    }
  });

  it("the three non-amount reference domains carry the frozen upstream patterns", () => {
    expect(ddl).toContain(`CHECK (VALUE ~ '${SHA256_HEX_PATTERN}');`);
    expect(ddl).toContain(`CHECK (length(VALUE) = 44 AND VALUE ~ '${PADDED_BASE64URL_PUBKEY_PATTERN}');`);
    expect(ddl).toContain(
      `CHECK (length(VALUE) = 88 AND VALUE ~ '${PADDED_BASE64URL_SIGNATURE_PATTERN}');`,
    );
  });

  it("the superseded unbounded zkz_amount_text domain is not declared", () => {
    // retires it; CONVENTIONS.md forbids attaching it to any column. The base
    // foundation is where it would come back from, so the ratchet lives here.
    expect(ddl).not.toContain("zkz_amount_text");
  });

  it("every domain the DDL declares has an inventory entry", () => {
    const declared = [...ddl.matchAll(/^CREATE DOMAIN (\w+) /gm)].map((m) => m[1] ?? "");
    expect(declared.length).toBeGreaterThan(0);
    const anchored = BASE_ENUMS_DOMAINS_INVARIANTS.map((i) => i.sqlAnchor).join("\n");
    const uninventoried = declared.filter((name) => !anchored.includes(`CREATE DOMAIN ${name} `));
    expect(uninventoried, "domain declared in the DDL with no inventory entry").toEqual([]);
  });

  it("every enum the DDL declares has an inventory entry", () => {
    const declared = [...ddl.matchAll(/^CREATE TYPE (\w+) AS ENUM/gm)].map((m) => m[1] ?? "");
    expect(declared.length).toBeGreaterThan(0);
    const anchored = BASE_ENUMS_DOMAINS_INVARIANTS.map((i) => i.sqlAnchor).join("\n");
    const uninventoried = declared.filter((name) => !anchored.includes(`CREATE TYPE ${name} AS ENUM`));
    expect(uninventoried, "enum declared in the DDL with no inventory entry").toEqual([]);
  });
});

// Binds the literals in src/schema/receive-admission.sql to the frozen
// contracts they are supposed to mirror, so the DDL cannot drift away from them silently.
// Two known drift modes are closed here: a hand-copied CHECK-domain predicate diverging from
// the freeze, and a status literal diverging from the frozen RECEIVE_EXTERNAL states.
// A third binds RECEIVE_QUEUE_FULL_RETRY_AFTER_SECONDS to the frozen pool-policy constant so
// the 503 Retry-After cannot silently diverge from the frozen capacity policy.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { ZKZ_AMOUNT_CHECK_DOMAINS } from "../../generic-node-contracts/src/amounts/manifest.ts";
import { RECEIVE_EXTERNAL_STATES } from "../../generic-node-contracts/src/operations/states.contract.ts";
import { RECEIVE_QUEUE_RETRY_AFTER_SECONDS } from "../../generic-node-contracts/src/pool-policy/constants.ts";
import { RECEIVE_QUEUE_FULL_RETRY_AFTER_SECONDS } from "../src/receive/admission.js";
import {
  RECEIVE_ADMISSION_INVARIANTS,
  RECEIVE_ADMISSION_SCHEMA_FILE,
} from "../src/schema/receive-admission.contract.js";

const DDL = readFileSync(
  new URL(`../src/schema/${RECEIVE_ADMISSION_SCHEMA_FILE}`, import.meta.url),
  "utf-8",
);

describe("receive-admission.sql parity with the frozen contracts", () => {
  it("carries the positive-amount predicate under the one documented substitution", () => {
    // The frozen predicate is written for a CREATE DOMAIN and reads `VALUE`; this slice
    // carries it as a column CHECK (base-enums-domains already owns the domain), so the
    // only permitted difference is the column name — same pattern as send-external-create.
    const expected = ZKZ_AMOUNT_CHECK_DOMAINS.zkz_amount_positive_text.replaceAll(
      "VALUE",
      "amount_zkz",
    );
    expect(DDL).toContain(`CONSTRAINT receive_operations_amount_positive\n    CHECK (${expected})`);
  });

  it("admits exactly the frozen RECEIVE_EXTERNAL status vocabulary", () => {
    const list = RECEIVE_EXTERNAL_STATES.map((state) => `'${state}'`).join(", ");
    expect(DDL).toContain(`CHECK (status IN (${list}))`);
  });

  it("scopes the one-in-flight-per-wallet indexes to the non-terminal states only", () => {
    // Positive allowlist, not the complement of a terminal blocklist: a status added to the
    // frozen vocabulary without touching these indexes is denied by default.
    const nonTerminal = RECEIVE_EXTERNAL_STATES.filter(
      (state) => state !== "EXPIRED" && state !== "RECEIVE_LANDED",
    );
    expect(nonTerminal).toEqual(["CREATED", "READY"]);
    const predicate = `status IN (${nonTerminal.map((state) => `'${state}'`).join(", ")})`;
    expect(DDL.split(predicate).length - 1, "both partial unique indexes share the predicate").toBe(2);
  });

  it("every inventoried invariant's SQL anchor appears verbatim in the DDL", () => {
    for (const invariant of RECEIVE_ADMISSION_INVARIANTS) {
      expect(DDL, invariant.id).toContain(invariant.sqlAnchor);
    }
  });

  it("mirrors the frozen RECEIVE_QUEUE_RETRY_AFTER_SECONDS for 503 receive_queue_full", () => {
    expect(RECEIVE_QUEUE_FULL_RETRY_AFTER_SECONDS).toBe(RECEIVE_QUEUE_RETRY_AFTER_SECONDS);
    expect(RECEIVE_QUEUE_FULL_RETRY_AFTER_SECONDS).toBe(30);
  });
});

// Binds the literals in src/schema/send-external-create.sql to the frozen
// contracts they are supposed to mirror, so the DDL cannot drift away from them silently.
// Three known drift modes are closed here: a hand-copied amount predicate diverging from the
// freeze, a status literal diverging from the frozen SEND_EXTERNAL states, and a
// non-terminal predicate that stops matching the state vocabulary it partitions.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { ZKZ_AMOUNT_CHECK_DOMAINS } from "../../generic-node-contracts/src/amounts/manifest.ts";
import { SEND_EXTERNAL_STATES } from "../../generic-node-contracts/src/operations/states.contract.ts";
import {
  SEND_EXTERNAL_CREATE_INVARIANTS,
  SEND_EXTERNAL_CREATE_SCHEMA_FILE,
} from "../src/schema/send-external-create.contract.js";

const DDL = readFileSync(
  new URL(`../src/schema/${SEND_EXTERNAL_CREATE_SCHEMA_FILE}`, import.meta.url),
  "utf-8",
);

// the state-event reference: the two states a SEND_EXTERNAL never leaves. Everything else
// in the frozen vocabulary still holds the source wallet.
const TERMINAL_STATES = ["EXTERNAL_SEND_LANDED", "REJECTED"] as const;

describe("send-external-create.sql parity with the frozen contracts", () => {
  it("carries the positive-amount predicate under the one documented substitution", () => {
    // The frozen predicate is written for a CREATE DOMAIN and reads `VALUE`; this slice
    // carries it as a column CHECK, so the only permitted difference is the column name.
    const expected = ZKZ_AMOUNT_CHECK_DOMAINS.zkz_amount_positive_text.replaceAll(
      "VALUE",
      "amount_zkz",
    );
    expect(DDL).toContain(`CONSTRAINT send_operations_amount_positive\n    CHECK (${expected})`);
  });

  it("admits exactly the frozen SEND_EXTERNAL status vocabulary", () => {
    const list = SEND_EXTERNAL_STATES.map((state) => `'${state}'`).join(", ");
    expect(DDL).toContain(`CHECK (status IN (${list}))`);
  });

  it("scopes the one-in-flight-per-wallet index by EXCLUDING the terminal states", () => {
    // The exclusion direction is the safety property: a partial index does not index a row its
    // predicate excludes, so a positive non-terminal allowlist would leave a newly added status
    // holding no wallet and silently admit the next send. Excluding the terminal pair makes an
    // unknown status unsettled, so it blocks.
    for (const state of TERMINAL_STATES) {
      expect(SEND_EXTERNAL_STATES as readonly string[], state).toContain(state);
    }
    const predicate = `WHERE status NOT IN (${TERMINAL_STATES.map((s) => `'${s}'`).join(", ")});`;
    expect(DDL).toContain(predicate);
    // Ratchet: the complement is still exactly the four states this slice reasons about, so a
    // vocabulary addition goes red here and forces a deliberate terminal/non-terminal call
    // rather than riding in on the fail-closed default unnoticed.
    const nonTerminal = SEND_EXTERNAL_STATES.filter(
      (state) => !(TERMINAL_STATES as readonly string[]).includes(state),
    );
    expect(nonTerminal).toEqual(["CREATED", "APPROVED", "AWAITING_REDEMPTION", "NEEDS_ATTENTION"]);
  });

  it("declares no send expiry column", () => {
    // The authoritative send redemption expiry lives only inside the signed inner text at
    // sign-intent formation. A column here would be a second, drifting source.
    expect(DDL).not.toMatch(/^\s*\w*expir\w*\s+(text|timestamptz|bigint|integer)\b/mi);
  });

  it("every inventoried invariant's SQL anchor appears verbatim in the DDL", () => {
    for (const invariant of SEND_EXTERNAL_CREATE_INVARIANTS) {
      expect(DDL, invariant.id).toContain(invariant.sqlAnchor);
    }
  });
});

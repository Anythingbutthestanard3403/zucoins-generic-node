/**
 * ORACLE SELF-CHECK (anti-tautology mutants, red-team amendment 1).
 *
 * An oracle that cannot be red-gone is tautological. Each block below proves the oracle's
 * verdict actually depends on (a) the expectation table content and (b) the observed value —
 * mirroring crash-replay.census.test.ts's dropped/duplicated/swapped mutants.
 *
 * TEST-ONLY.
 */
import { describe, expect, it } from "vitest";

import {
  MOVE_INTERNAL_TRANSITIONS,
  SEND_EXTERNAL_TRANSITIONS,
} from "../../generic-node-contracts/src/operations/states.contract.ts";
import {
  assertNoSecretLeak,
  assertObservedEventAllowed,
  assertObservedStateAllowed,
  classifyObservedTransition,
  isForbiddenAlias,
  reservedOracleAbsent,
  runtimeFireable,
} from "./lifecycle-fuzz-oracles.ts";

describe("transition-allowlist oracle is NOT tautological (amendment 1)", () => {
  it("positive control: a real runtime transition is ALLOWED", () => {
    expect(
      classifyObservedTransition(SEND_EXTERNAL_TRANSITIONS, {
        from: "APPROVED",
        to: "AWAITING_REDEMPTION",
      }).verdict,
    ).toBe("ALLOWED");
  });

  it("goes RED (a): deleting an allowed row from the expectation set flips ALLOWED -> UNAUTHORIZED", () => {
    const mutated = SEND_EXTERNAL_TRANSITIONS.filter(
      (row) => !(row.from === "APPROVED" && row.to === "AWAITING_REDEMPTION"),
    );
    expect(
      classifyObservedTransition(mutated, { from: "APPROVED", to: "AWAITING_REDEMPTION" }).verdict,
    ).toBe("UNAUTHORIZED_TRANSITION");
  });

  it("goes RED (b): an injected unauthorized (from,to) is UNAUTHORIZED against the real table", () => {
    expect(
      classifyObservedTransition(SEND_EXTERNAL_TRANSITIONS, {
        from: "CREATED",
        to: "EXTERNAL_SEND_LANDED",
      }).verdict,
    ).toBe("UNAUTHORIZED_TRANSITION");
  });

  it("null-from creation row is a first-class match (not coerced)", () => {
    expect(
      classifyObservedTransition(SEND_EXTERNAL_TRANSITIONS, { from: null, to: "CREATED" }).verdict,
    ).toBe("ALLOWED");
    // A non-null 'from' for the same 'to' is NOT the creation row.
    expect(
      classifyObservedTransition(SEND_EXTERNAL_TRANSITIONS, { from: "REJECTED", to: "CREATED" })
        .verdict,
    ).toBe("UNAUTHORIZED_TRANSITION");
  });

  it("event identity is checked byte-exact (EVENT_MISMATCH), and a NO_EVENT_MARKER row is not a durable event", () => {
    expect(
      classifyObservedTransition(SEND_EXTERNAL_TRANSITIONS, {
        from: "APPROVED",
        to: "AWAITING_REDEMPTION",
        event: "external_send.awaiting_redemption",
      }).verdict,
    ).toBe("ALLOWED");
    expect(
      classifyObservedTransition(SEND_EXTERNAL_TRANSITIONS, {
        from: "APPROVED",
        to: "AWAITING_REDEMPTION",
        event: "external_send.landed",
      }).verdict,
    ).toBe("EVENT_MISMATCH");
  });
});

describe("RESERVED (PROVEN_NOT_LANDED-gated) transitions are partitioned out and flagged (amendment 2)", () => {
  it("send reserved row NEEDS_ATTENTION->REJECTED fires the reserved verdict", () => {
    expect(
      classifyObservedTransition(SEND_EXTERNAL_TRANSITIONS, {
        from: "NEEDS_ATTENTION",
        to: "REJECTED",
      }).verdict,
    ).toBe("RESERVED_TRANSITION_FIRED");
  });

  it("move reserved row NEEDS_ATTENTION->CREATED fires the reserved verdict", () => {
    expect(
      classifyObservedTransition(MOVE_INTERNAL_TRANSITIONS, {
        from: "NEEDS_ATTENTION",
        to: "CREATED",
      }).verdict,
    ).toBe("RESERVED_TRANSITION_FIRED");
  });

  it("each table has exactly one reserved row, excluded from RUNTIME_FIREABLE", () => {
    expect(reservedOracleAbsent(SEND_EXTERNAL_TRANSITIONS).length).toBe(1);
    expect(reservedOracleAbsent(MOVE_INTERNAL_TRANSITIONS).length).toBe(1);
    expect(runtimeFireable(SEND_EXTERNAL_TRANSITIONS).length).toBe(
      SEND_EXTERNAL_TRANSITIONS.length - 1,
    );
  });
});

describe("forbidden-alias denylist is RAW and two-sided fail-closed (amendment 4)", () => {
  it("exact forbidden aliases and wildcard-prefix families are rejected", () => {
    expect(isForbiddenAlias("PAID")).toBe(true);
    expect(isForbiddenAlias("transfer.confirmed")).toBe(true);
    expect(isForbiddenAlias("payment.captured")).toBe(true); // wildcard family
    expect(isForbiddenAlias("refund.issued")).toBe(true);
    expect(() => assertObservedStateAllowed("PAID")).toThrow(/forbidden-alias/);
    expect(() => assertObservedEventAllowed("transfer.confirmed")).toThrow(/forbidden-alias/);
  });

  it("no normalization: matching is exact-byte, never case-folded", () => {
    expect(() => assertObservedStateAllowed("created")).toThrow(/non-member/); // exact bytes only
    expect(isForbiddenAlias("PAYMENT")).toBe(false); // uppercase is NOT folded onto the 'payment' token
    expect(isForbiddenAlias("payment")).toBe(true); // the exact node-core token IS forbidden
  });

  it("legitimate closed-set members pass both sides", () => {
    expect(() => assertObservedStateAllowed("CREATED")).not.toThrow();
    expect(() => assertObservedStateAllowed("EXTERNAL_SEND_LANDED")).not.toThrow();
    expect(() => assertObservedEventAllowed("receive.landed")).not.toThrow();
    expect(() => assertObservedEventAllowed("none; audit only")).not.toThrow();
  });
});

describe("secret-leak scanner goes RED on secret-shaped input (amendment 8)", () => {
  it("rejects secret-shaped fields and overlong blobs; accepts opaque ids", () => {
    expect(() => assertNoSecretLeak({ inner_preimage_text: "x" })).toThrow(/secret-shaped/);
    expect(() => assertNoSecretLeak({ blob: "a".repeat(80) })).toThrow(/overlong/);
    expect(() => assertNoSecretLeak({ walletId: "wallet-A", role: "SEND_SOURCE" })).not.toThrow();
  });
});

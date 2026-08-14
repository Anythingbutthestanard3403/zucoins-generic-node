// the crypto-goldens concern.2 — Census and freeze tests for the API schema vocabulary.
// Asserts exact counts and vocabulary closure for all frozen API/schema/event data.
// Governing sources: the API contract, the data-model enum vocabulary, and the state-event reference.
import { describe, expect, it } from "vitest";

import { assertClosedSet, assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import * as enumsBarrel from "../enums/index.ts";
import * as apiSchemaBarrel from "./index.ts";
import { HTTP_ERROR_STATUSES, ERROR_ENVELOPE_FIELDS, CITED_ERROR_CODES } from "./error-vocabulary.ts";
import { IMPLEMENTER_SCOPES, AUTH_CLASSES, REPORTING_HEADERS, BEARER_KEY_EXCLUSIONS } from "./auth-scopes.ts";
import { PG_ENUM_NAMES, PG_ENUMS } from "./pg-enums.ts";
import { DISCOVERY_PATH, DISCOVERY_RESPONSE_FIELDS, DISCOVERY_EXCLUSIONS } from "./discovery.ts";
import { API_SCHEMA_VERSION } from "./version.ts";
import { PUBLIC_ROUTES, ADMIN_ROUTES, RETIRED_ROUTES } from "../operations/routes.contract.ts";
import { DURABLE_EVENTS } from "../operations/events.contract.ts";
import { OPERATION_KINDS } from "../operations/operations.contract.ts";
import {
  WALLET_KEY_ORIGINS,
  WALLET_STATES,
  DESTINATION_STATES,
} from "../custody/predicates.contract.ts";
import {
  RECEIVE_EXTERNAL_TRANSITIONS,
  MOVE_INTERNAL_TRANSITIONS,
  SEND_EXTERNAL_TRANSITIONS,
} from "../operations/states.contract.ts";

describe("the crypto-goldens concern.2 API schema version metadata", () => {
  it("freezes the schema version for drift detection", () => {
    expect(API_SCHEMA_VERSION).toBe(2);
  });
});

describe("the crypto-goldens concern.2 error vocabulary census", () => {
  it("has exactly 8 HTTP error statuses (closed error vocabulary: no 403)", () => {
    expect(HTTP_ERROR_STATUSES).toHaveLength(8);
  });

  it("freezes the exact status codes in ascending sequence", () => {
    const codes = HTTP_ERROR_STATUSES.map((entry) => entry.status);
    assertFieldOrder(codes, [400, 401, 404, 409, 410, 422, 429, 503]);
  });

  it("does not enumerate 403 (scope denial is the generic 401)", () => {
    expect(HTTP_ERROR_STATUSES.map((entry) => entry.status)).not.toContain(403);
  });

  it("freezes the error envelope field names", () => {
    assertFieldOrder(ERROR_ENVELOPE_FIELDS, ["code", "message", "request_id", "details"]);
  });

  it("has exactly 4 error envelope fields", () => {
    expect(ERROR_ENVELOPE_FIELDS).toHaveLength(4);
  });

  it("freezes the cited error codes", () => {
    expect(CITED_ERROR_CODES).toHaveLength(9);
    expect(new Set(CITED_ERROR_CODES).size).toBe(CITED_ERROR_CODES.length);
  });

  it("rejects an added HTTP status (negative path)", () => {
    expectRejects(
      () => [...HTTP_ERROR_STATUSES, { status: 418, meaning: "I'm a teapot." }],
      (mutated) => expect(mutated).toHaveLength(8),
    );
  });
});

describe("the crypto-goldens concern.2 auth scope census", () => {
  it("has exactly 8 implementer scopes", () => {
    expect(IMPLEMENTER_SCOPES).toHaveLength(8);
  });

  it("freezes the implementer scopes in their canonical sequence", () => {
    assertFieldOrder(IMPLEMENTER_SCOPES, [
      "receive:create",
      "receive:read",
      "move:create",
      "move:read",
      "send:create",
      "send:read",
      "destination:create",
      "destination:read",
    ]);
  });

  it("has exactly 4 auth classes", () => {
    expect(AUTH_CLASSES).toHaveLength(4);
  });

  it("has exactly 5 reporting headers", () => {
    expect(REPORTING_HEADERS).toHaveLength(5);
  });

  it("has exactly 6 bearer key exclusions", () => {
    expect(BEARER_KEY_EXCLUSIONS).toHaveLength(6);
  });

  it("rejects a ninth scope (negative path)", () => {
    expectRejects(
      () => [...IMPLEMENTER_SCOPES, "admin:all"],
      (mutated) => expect(mutated).toHaveLength(8),
    );
  });
});

describe("the crypto-goldens concern.2 Postgres ENUM census", () => {
  it("has exactly 18 enum types", () => {
    expect(PG_ENUM_NAMES).toHaveLength(18);
  });

  it("freezes the enum names in doc sequence", () => {
    assertFieldOrder(PG_ENUM_NAMES, [
      "operation_kind",
      "operation_status",
      "wallet_key_origin",
      "wallet_state",
      "destination_state",
      "wallet_lease_role",
      "approval_method",
      "approval_challenge_status",
      "external_formation_state",
      "observer_domain",
      "observation_parse_result",
      "observation_relationship",
      "verification_verdict",
      "lineage_proof_verdict",
      "reporting_key_state",
      "reporting_key_lifecycle_event_type",
      "reporting_request_class",
      "attention_reason",
    ]);
  });

  it("every enum name has a corresponding frozen value array", () => {
    for (const name of PG_ENUM_NAMES) {
      expect(PG_ENUMS[name]).toBeDefined();
      expect(PG_ENUMS[name].length).toBeGreaterThan(0);
    }
  });

  it("operation_kind has exactly 3 values", () => {
    expect(PG_ENUMS.operation_kind).toHaveLength(3);
  });

  it("operation_status has exactly 10 values", () => {
    expect(PG_ENUMS.operation_status).toHaveLength(10);
  });

  it("wallet_key_origin has exactly 2 values", () => {
    expect(PG_ENUMS.wallet_key_origin).toHaveLength(2);
  });

  it("wallet_state has exactly 4 values", () => {
    expect(PG_ENUMS.wallet_state).toHaveLength(4);
  });

  it("destination_state has exactly 3 values", () => {
    expect(PG_ENUMS.destination_state).toHaveLength(3);
  });

  it("wallet_lease_role has exactly 5 values", () => {
    expect(PG_ENUMS.wallet_lease_role).toHaveLength(5);
  });

  it("approval_method has exactly 3 values", () => {
    expect(PG_ENUMS.approval_method).toHaveLength(3);
  });

  it("approval_challenge_status has exactly 4 values", () => {
    expect(PG_ENUMS.approval_challenge_status).toHaveLength(4);
  });

  it("external_formation_state has exactly 6 values", () => {
    expect(PG_ENUMS.external_formation_state).toHaveLength(6);
  });

  it("observer_domain has exactly 2 values", () => {
    expect(PG_ENUMS.observer_domain).toHaveLength(2);
  });

  it("observation_parse_result has exactly 7 values", () => {
    expect(PG_ENUMS.observation_parse_result).toHaveLength(7);
  });

  it("observation_relationship has exactly 10 values", () => {
    expect(PG_ENUMS.observation_relationship).toHaveLength(10);
  });

  it("verification_verdict has exactly 4 values", () => {
    expect(PG_ENUMS.verification_verdict).toHaveLength(4);
  });

  it("lineage_proof_verdict has exactly 4 values", () => {
    expect(PG_ENUMS.lineage_proof_verdict).toHaveLength(4);
  });

  it("reporting_key_state has exactly 4 values", () => {
    expect(PG_ENUMS.reporting_key_state).toHaveLength(4);
  });

  it("reporting_key_lifecycle_event_type has exactly 6 values", () => {
    expect(PG_ENUMS.reporting_key_lifecycle_event_type).toHaveLength(6);
  });

  it("reporting_request_class has exactly 2 values", () => {
    expect(PG_ENUMS.reporting_request_class).toHaveLength(2);
  });

  it("attention_reason has exactly 15 values", () => {
    expect(PG_ENUMS.attention_reason).toHaveLength(15);
  });

  it("rejects a 19th enum (negative path)", () => {
    expectRejects(
      () => [...PG_ENUM_NAMES, "new_enum"],
      (mutated) => expect(mutated).toHaveLength(18),
    );
  });

  it("no enum has duplicate values", () => {
    for (const name of PG_ENUM_NAMES) {
      const values = PG_ENUMS[name];
      expect(new Set(values).size).toBe(values.length);
    }
  });

  //  Leg A: value-pin the custody trio to the canonical lists in
  // custody/predicates.contract.ts (previously only length-guarded, so an
  // equal-length value drift would have passed uncaught).
  it("wallet_key_origin values are value-bound to WALLET_KEY_ORIGINS", () => {
    assertFieldOrder(PG_ENUMS.wallet_key_origin, WALLET_KEY_ORIGINS);
  });

  it("wallet_state values are value-bound to WALLET_STATES", () => {
    assertFieldOrder(PG_ENUMS.wallet_state, WALLET_STATES);
  });

  it("destination_state values are value-bound to DESTINATION_STATES", () => {
    assertFieldOrder(PG_ENUMS.destination_state, DESTINATION_STATES);
  });
});

/**
 *  — the completeness half of the enum freeze. The census above pins a hand-written
 * inventory; on its own it cannot notice a canonical enum this manifest never transcribed
 * (the exact defect this test was written for: the canonical data model declares 18 enums,
 * `PG_ENUMS` froze 14, and the count assertion asserted the undercount as truth). The
 * canonical CREATE TYPE universe is inlined below as a second, independently-transcribed
 * fixture — a new or edited enum fails here until it is frozen, in value AND sequence.
 */
describe("Postgres ENUM canonical-universe completeness", () => {
  // The full canonical CREATE TYPE inventory, name -> values, both in canonical sequence.
  const docEnums = new Map<string, string[]>([
    ["operation_kind", ["RECEIVE_EXTERNAL", "MOVE_INTERNAL", "SEND_EXTERNAL"]],
    ["operation_status", ["CREATED", "READY", "RECEIVE_LANDED", "INTERNAL_MOVE_LANDED", "APPROVED", "AWAITING_REDEMPTION", "EXTERNAL_SEND_LANDED", "EXPIRED", "REJECTED", "NEEDS_ATTENTION"]],
    ["wallet_key_origin", ["node_generated", "imported"]],
    ["wallet_state", ["AVAILABLE", "PINNED", "QUARANTINED", "RETIRED"]],
    ["destination_state", ["PENDING", "BLESSED", "RETIRED"]],
    ["wallet_lease_role", ["RECEIVE_WINDOW", "MOVE_SOURCE", "MOVE_DESTINATION", "SEND_SOURCE", "RECONCILIATION"]],
    ["approval_method", ["TOTP_ONLY", "TOTP_AND_DEVICE", "AUTO_POLICY"]],
    ["approval_challenge_status", ["ISSUED", "CONSUMED", "SUPERSEDED", "EXPIRED"]],
    ["external_formation_state", ["NOT_REQUIRED", "APPROVAL_PENDING", "APPROVED_UNSIGNED", "SIGNING_CLAIMED", "PARTIAL_PERSISTED", "PARTIAL_DELIVERED"]],
    ["observer_domain", ["NODE", "PLATFORM"]],
    ["observation_parse_result", ["VERIFIED_GENESIS", "VERIFIED_HEAD", "TRANSPORT_ERROR", "MALFORMED_ENVELOPE", "MALFORMED_TRANSACTION", "UNVERIFIED_SIGNATURE", "WALLET_ROLE_INVALID"]],
    ["observation_relationship", ["FIRST", "SUCCESSOR", "COMPLETE_PATH_SUCCESSOR", "DUPLICATE", "EQUIVALENT_STATE_DIFFERENT_ENVELOPE", "REGRESSION", "UNEXPLAINED_JUMP", "GENESIS_AFTER_HISTORY", "SIGNATURE_COLLISION", "NOT_APPLICABLE"]],
    ["verification_verdict", ["PENDING", "VERIFIED", "REJECTED", "INDETERMINATE"]],
    ["lineage_proof_verdict", ["LANDED_EXACT", "LANDED_COMPLETE_PATH", "INDETERMINATE", "INVARIANT_BREACH"]],
    ["reporting_key_state", ["PENDING", "ACTIVE", "RETIRED", "REVOKED"]],
    ["reporting_key_lifecycle_event_type", ["FIRST_KEY_ACTIVATED", "KEY_ROTATED", "PRIOR_KEY_RETIRED", "KEY_REVOKED", "AUTH_HOLD_SET", "AUTH_HOLD_RELEASED"]],
    ["reporting_request_class", ["READ", "MUTATION"]],
    ["attention_reason", [
      "GATEWAY_RESPONSE_INVALID",
      "GATEWAY_UNAVAILABLE_BEYOND_BUDGET",
      "UNEXPECTED_HEAD_CHANGE",
      "LINEAGE_GAP",
      "SUBMIT_OUTCOME_AMBIGUOUS",
      "SIGNING_OUTCOME_AMBIGUOUS",
      "DESTINATION_NO_LONGER_BLESSED",
      "T0_RELEASE_MISMATCH",
      "VERIFICATION_REJECTED",
      "VERIFICATION_INDETERMINATE",
      "VERIFICATION_RESOURCE_EXHAUSTED",
      "LEASE_INVARIANT_VIOLATION",
      "EXACT_BYTES_UNAVAILABLE",
      "OPERATOR_PARKED",
      "POST_EXPIRY_RECONCILING",
    ]],
  ]);

  it("the canonical enum name set equals PG_ENUM_NAMES exactly, in canonical sequence", () => {
    assertFieldOrder(PG_ENUM_NAMES, [...docEnums.keys()]);
  });

  it("every frozen enum reproduces its canonical values in canonical sequence", () => {
    for (const name of PG_ENUM_NAMES) {
      assertFieldOrder(PG_ENUMS[name], docEnums.get(name) ?? []);
    }
  });

  it("fail-first: an unfrozen canonical enum is detected as missing (the exact defect)", () => {
    expectRejects(
      () => PG_ENUM_NAMES.filter((name) => name !== "reporting_request_class"),
      (mutated) => assertFieldOrder(mutated, [...docEnums.keys()]),
    );
  });

  it("fail-first: a value drift inside a frozen enum is detected", () => {
    expectRejects(
      () => [...PG_ENUMS.reporting_request_class, "ADMIN"],
      (mutated) => assertFieldOrder(mutated, docEnums.get("reporting_request_class") ?? []),
    );
  });
});

/**
 *  — the census above pins `PG_ENUM_NAMES`/`PG_ENUMS` at 17, but the package's two
 * public export barrels (`enums/index.ts`, `api-schema/index.ts`) re-declare their own export
 * lists and nothing compared them to `PG_ENUM_NAMES`. That let a barrel undercount silently:
 * both shipped only 14 of the 17 enum constants, and `enums/index.ts`'s own docstring claimed
 * 14 was "the complete frozen Postgres ENUM surface". A gate that compares a structure to
 * itself never sees divergence between two structures meant to stay in lockstep.
 */
describe("public enum barrel completeness (enums/ and api-schema/ index.ts)", () => {
  // The barrels' export convention is the enum's PG_ENUM_NAMES entry upper-cased
  // (e.g. "reporting_key_state" -> REPORTING_KEY_STATE) — `pg-enums.ts`'s own PG_ENUMS
  // record keys follow this exact correspondence.
  const expectedExportNames = PG_ENUM_NAMES.map((name) => name.toUpperCase());

  it("enums/index.ts's non-meta exports are exactly the 18 enum constants, no more, no fewer", () => {
    const { PG_ENUM_NAMES: _names, PG_ENUMS: _map, ...enumOnlyExports } = enumsBarrel as Record<
      string,
      unknown
    >;
    assertClosedSet(Object.keys(enumOnlyExports), expectedExportNames);
  });

  it("api-schema/index.ts exports every enum constant named in PG_ENUM_NAMES", () => {
    for (const key of expectedExportNames) {
      expect(apiSchemaBarrel, `api-schema/index.ts is missing export ${key}`).toHaveProperty(key);
    }
  });

  it("each barrel export is the same object as its PG_ENUMS entry (no re-fork)", () => {
    for (const name of PG_ENUM_NAMES) {
      const key = name.toUpperCase();
      expect((enumsBarrel as Record<string, unknown>)[key]).toBe(PG_ENUMS[name]);
      expect((apiSchemaBarrel as Record<string, unknown>)[key]).toBe(PG_ENUMS[name]);
    }
  });

  it("fail-first: a barrel undercounting one enum export is detected (the exact barrel defect)", () => {
    const { REPORTING_REQUEST_CLASS: _omitted, ...barrelMissingOne } = enumsBarrel as Record<
      string,
      unknown
    >;
    expectRejects(
      () => barrelMissingOne,
      (mutated) => {
        for (const key of expectedExportNames) {
          expect(mutated, `expected barrel to still export ${key}`).toHaveProperty(key);
        }
      },
    );
  });
});

describe("the crypto-goldens concern.2 discovery endpoint census", () => {
  it("freezes the discovery path", () => {
    expect(DISCOVERY_PATH).toBe("/.well-known/zupay-node");
  });

  it("has exactly 9 response fields (includes funding wallet pin ZTR-1288)", () => {
    expect(DISCOVERY_RESPONSE_FIELDS).toHaveLength(9);
  });

  it("has exactly 5 exclusions", () => {
    expect(DISCOVERY_EXCLUSIONS).toHaveLength(5);
  });
});

describe("the crypto-goldens concern.2 route census", () => {
  it("has exactly 20 public routes", () => {
    expect(PUBLIC_ROUTES).toHaveLength(20);
  });

  it("has exactly 8 admin routes", () => {
    expect(ADMIN_ROUTES).toHaveLength(8);
  });

  it("has exactly 28 total active routes", () => {
    expect(PUBLIC_ROUTES.length + ADMIN_ROUTES.length).toBe(28);
  });

  it("has exactly 5 retired route patterns", () => {
    expect(RETIRED_ROUTES).toHaveLength(5);
  });
});

describe("the crypto-goldens concern.2 event census", () => {
  it("has exactly 9 durable events", () => {
    expect(DURABLE_EVENTS).toHaveLength(9);
  });
});

describe("the crypto-goldens concern.2 operation type census", () => {
  it("has exactly 3 operation types", () => {
    expect(OPERATION_KINDS).toHaveLength(3);
  });
});

describe("the crypto-goldens concern.2 state transition census", () => {
  it("has exactly 5 receive transitions", () => {
    expect(RECEIVE_EXTERNAL_TRANSITIONS).toHaveLength(5);
  });

  it("has exactly 5 move transitions", () => {
    expect(MOVE_INTERNAL_TRANSITIONS).toHaveLength(5);
  });

  it("has exactly 11 send transitions", () => {
    expect(SEND_EXTERNAL_TRANSITIONS).toHaveLength(11);
  });

  it("has exactly 21 total transitions across 3 operation types", () => {
    const total =
      RECEIVE_EXTERNAL_TRANSITIONS.length +
      MOVE_INTERNAL_TRANSITIONS.length +
      SEND_EXTERNAL_TRANSITIONS.length;
    expect(total).toBe(21);
  });
});

describe("the crypto-goldens concern.2 vocabulary closure", () => {
  it("all enum values are non-empty strings", () => {
    for (const name of PG_ENUM_NAMES) {
      for (const value of PG_ENUMS[name]) {
        expect(typeof value).toBe("string");
        expect(value.length).toBeGreaterThan(0);
      }
    }
  });

  it("all implementer scopes follow resource:action pattern", () => {
    for (const scope of IMPLEMENTER_SCOPES) {
      expect(scope).toMatch(/^[a-z]+:[a-z]+$/);
    }
  });

  it("all cited error codes are snake_case", () => {
    for (const code of CITED_ERROR_CODES) {
      expect(code).toMatch(/^[a-z][a-z0-9_]*$/);
    }
  });
});

import { describe, expect, it } from "vitest";

import { expectRejects } from "../testkit/freeze.ts";
import {
  IMPORT_DRAIN_DEFERRAL,
  CUTOVER_GATE,
  LAUNCH_COMMAND_SURFACE,
  SCHEMA_WRITER_SURFACE,
  FORBIDDEN_LAUNCH_CAPABILITY_VERBS,
  RUNTIME_OBLIGATIONS,
} from "./deferral.contract.ts";
import { ABSENT_CAPABILITIES } from "../operations/capabilities.contract.ts";
import {
  PUBLIC_ROUTES,
  ADMIN_ROUTES,
  RETIRED_ROUTES,
  RETIRED_ROUTES_NON_PATH_CATEGORY,
  type RouteEntry,
} from "../operations/routes.contract.ts";
import { FORBIDDEN_TERMS } from "../scan/forbidden-terms.ts";
import {
  isAvailableForReceive,
  KEY_ORIGIN_NODE_GENERATED,
  type PoolWalletDescriptor,
} from "../pool-policy/eligibility.ts";
import { SELECT_ASSIGNABLE_WALLET_SQL } from "../pool-policy/selection.ts";
import { STORAGE_RESOLUTION } from "../vault/storage.contract.ts";
import { THREAT_MATRIX } from "../vault/threat-model.contract.ts";

/** Reintroducing this path is the negative fixture for the retired admin removal-endpoint pattern. */
const REINTRODUCED_DRAIN_PATH = "/admin/v1/drains"; // contract-allow:launch-deferral-citation

const assertNoActiveRouteStartsWith = (routes: readonly RouteEntry[], prefix: string): void => {
  const collision = routes.find((route) => route.path.startsWith(prefix));
  if (collision !== undefined) {
    throw new Error(
      `active route "${collision.method} ${collision.path}" collides with a retired removal-endpoint prefix`,
    );
  }
};

describe("launch-deferral census", () => {
  it("cross-binds the capability census: WALLET_IMPORT + IMPORTED_DRAIN are absent and form the exact absent-capability key set", () => {
    expect(IMPORT_DRAIN_DEFERRAL.wallet_import).toBe("absent");
    expect(IMPORT_DRAIN_DEFERRAL.imported_drain).toBe("absent");
    expect(ABSENT_CAPABILITIES).toEqual({ WALLET_IMPORT: "absent", IMPORTED_DRAIN: "absent" });
    expect(Object.keys(ABSENT_CAPABILITIES).sort()).toEqual(["IMPORTED_DRAIN", "WALLET_IMPORT"]);
  });

  it("route census: no active route path contains either forbidden launch-capability verb as a substring (case-insensitive)", () => {
    for (const route of [...PUBLIC_ROUTES, ...ADMIN_ROUTES]) {
      for (const verb of FORBIDDEN_LAUNCH_CAPABILITY_VERBS) {
        expect(route.path.toLowerCase().includes(verb)).toBe(false);
      }
    }
  });

  it("route census: the admin removal-endpoint pattern is retired and the import-endpoint non-path category is asserted", () => {
    expect(RETIRED_ROUTES).toContain("/admin/v1/drains*"); // contract-allow:launch-deferral-citation
    expect(RETIRED_ROUTES_NON_PATH_CATEGORY).toBe("any import endpoint");
  });

  it("command census: LAUNCH_COMMAND_SURFACE is closed and no member matches a forbidden launch-capability verb", () => {
    expect(LAUNCH_COMMAND_SURFACE).toEqual([]);
    for (const command of LAUNCH_COMMAND_SURFACE) {
      for (const verb of FORBIDDEN_LAUNCH_CAPABILITY_VERBS) {
        expect(command.name.toLowerCase()).not.toContain(verb);
        expect(command.verb.toLowerCase()).not.toContain(verb);
      }
    }
  });

  it("schema-writer census: every writer permits exactly node_generated and none permits imported", () => {
    for (const writer of Object.values(SCHEMA_WRITER_SURFACE)) {
      expect(writer.permitted_key_origins).toEqual([KEY_ORIGIN_NODE_GENERATED]);
      expect(writer.permitted_key_origins).not.toContain("imported");
    }
  });

  it("cutover gate: launch accepts only node_generated, decision ref is unset, and send-source-origin exclusion is a prerequisite", () => {
    expect(CUTOVER_GATE.launch_accepts_key_origins).toEqual([KEY_ORIGIN_NODE_GENERATED]);
    expect(CUTOVER_GATE.cutover_decision_ref).toBeNull();
    expect(
      CUTOVER_GATE.cutover_prerequisites.some((item) =>
        item.includes("send-source-origin exclusion"),
      ),
    ).toBe(true);
  });

  it("imported-enum inertness cross-binds the pool-policy and vault freezes: drift in either sibling fails this census", () => {
    const importedWallet: PoolWalletDescriptor = {
      keyOrigin: "imported",
      recoveryVerifiedAt: "2026-07-19T00:00:00.000Z",
      state: "AVAILABLE",
    };
    expect(isAvailableForReceive(importedWallet)).toBe(false);
    expect(SELECT_ASSIGNABLE_WALLET_SQL).toContain(`key_origin = '${KEY_ORIGIN_NODE_GENERATED}'`);
    expect(STORAGE_RESOLUTION.migration_shim).toBe(false);
    const originFlip = THREAT_MATRIX.find((threat) => threat.id === "KEY_SMUGGLE_ORIGIN_FLIP");
    expect(originFlip).toBeDefined();
    expect(originFlip?.caught_outcome).toBe("AAD_MISMATCH");
  });

  it("lexical-gate coupling: FORBIDDEN_LAUNCH_CAPABILITY_VERBS[1] is a forbidden term but FORBIDDEN_LAUNCH_CAPABILITY_VERBS[0] intentionally is not, since underscore-joined identifiers like IMPORTED_DRAIN and WALLET_IMPORT never trip the whole-word scanner", () => {
    const forbiddenTermsAsStrings: readonly string[] = FORBIDDEN_TERMS;
    expect(
      forbiddenTermsAsStrings.includes(FORBIDDEN_LAUNCH_CAPABILITY_VERBS[1]),
      "the removal-capability verb must stay lexically forbidden so a prose citation of it is caught unmarked",
    ).toBe(true);
    expect(
      forbiddenTermsAsStrings.includes(FORBIDDEN_LAUNCH_CAPABILITY_VERBS[0]),
      "import must stay lexically unforbidden: it is ordinary ES-module vocabulary, unlike the removal verb",
    ).toBe(false);
  });

  it("RUNTIME_OBLIGATIONS: exactly three obligations, each with a nonempty owner_phase", () => {
    expect(RUNTIME_OBLIGATIONS).toHaveLength(3);
    for (const obligation of RUNTIME_OBLIGATIONS) {
      expect(obligation.owner_phase.length).toBeGreaterThan(0);
    }
  });

  it("rejects one-sided activation: wallet_import present while imported_drain stays absent (negative path)", () => {
    expectRejects(
      () => ({ ...IMPORT_DRAIN_DEFERRAL, wallet_import: "present" }),
      (mutated) => expect(mutated).toEqual(IMPORT_DRAIN_DEFERRAL),
    );
  });

  it("rejects a command named wallet-import joining the closed command surface (negative path)", () => {
    expectRejects(
      () => [...LAUNCH_COMMAND_SURFACE, { name: "wallet-import", verb: "import" }],
      (mutated) => expect(mutated).toEqual(LAUNCH_COMMAND_SURFACE),
    );
  });

  it("rejects a schema writer permitting the imported key origin (negative path)", () => {
    expectRejects(
      () => ({
        ...SCHEMA_WRITER_SURFACE,
        seed: { ...SCHEMA_WRITER_SURFACE.seed, permitted_key_origins: ["imported"] },
      }),
      (mutated) => expect(mutated).toEqual(SCHEMA_WRITER_SURFACE),
    );
  });

  it("rejects a reintroduced admin removal-endpoint route colliding with the retired pattern (negative path)", () => {
    expectRejects(
      () => [
        ...ADMIN_ROUTES,
        {
          method: "GET" as const,
          path: REINTRODUCED_DRAIN_PATH,
          authMode: "operator_session" as const,
        },
      ],
      (mutated) => assertNoActiveRouteStartsWith(mutated, REINTRODUCED_DRAIN_PATH),
    );
  });

  it("rejects a non-null cutover_decision_ref placeholder (negative path)", () => {
    expectRejects(
      () => ({ ...CUTOVER_GATE, cutover_decision_ref: "future-cutover-placeholder" }),
      (mutated) => expect(mutated.cutover_decision_ref).toBeNull(),
    );
  });
});

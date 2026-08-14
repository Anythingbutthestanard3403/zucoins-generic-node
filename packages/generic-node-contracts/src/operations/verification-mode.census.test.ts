import { describe, expect, it } from "vitest";

import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import { DURABLE_EVENTS } from "./events.contract.ts";
import {
  MOVE_INTERNAL_STATES,
  RECEIVE_EXTERNAL_STATES,
  SEND_EXTERNAL_STATES,
  FORBIDDEN_STATE_ALIASES,
} from "./states.contract.ts";
import {
  ALLOW_NODE_VERIFIED_POLICY_CHANGED_ACTION,
  ALLOW_NODE_VERIFIED_SETTING_KEY,
  DEFAULT_VERIFICATION_MODE,
  RELEASED_NODE_VERIFIED,
  VERIFICATION_MODE_ERROR_CODES,
  VERIFICATION_MODES,
} from "./verification-mode.contract.ts";

describe("verification-mode census (ZTR-1299)", () => {
  it("freezes the closed mode set INDEPENDENT | NODE_VERIFIED with INDEPENDENT default", () => {
    assertFieldOrder(VERIFICATION_MODES, ["INDEPENDENT", "NODE_VERIFIED"]);
    expect(VERIFICATION_MODES).toHaveLength(2);
    expect(DEFAULT_VERIFICATION_MODE).toBe("INDEPENDENT");
    expect(VERIFICATION_MODES).toContain(DEFAULT_VERIFICATION_MODE);
  });

  it("freezes RELEASED_NODE_VERIFIED as the node-verified lease-release status token", () => {
    expect(RELEASED_NODE_VERIFIED).toBe("RELEASED_NODE_VERIFIED");
  });

  it("freezes the operator policy key parallel to ops.auto_approve_sends", () => {
    expect(ALLOW_NODE_VERIFIED_SETTING_KEY).toBe("ops.allow_node_verified");
    expect(ALLOW_NODE_VERIFIED_POLICY_CHANGED_ACTION).toBe("ops.allow_node_verified_changed");
  });

  it("freezes verification-mode error codes with HTTP bindings (409 mismatch, 422 not allowed)", () => {
    assertFieldOrder(
      VERIFICATION_MODE_ERROR_CODES.map((e) => e.code),
      ["verification_mode_mismatch", "verification_mode_not_allowed"],
    );
    expect(VERIFICATION_MODE_ERROR_CODES).toEqual([
      {
        code: "verification_mode_mismatch",
        http: 409,
        meaning:
          "armed or verification-complete was called on an operation whose verification_mode does not admit that path.",
      },
      {
        code: "verification_mode_not_allowed",
        http: 422,
        meaning:
          "NODE_VERIFIED was requested at admission but operator policy does not allow it for the calling implementer.",
      },
    ]);
  });

  it("AC2: NODE_VERIFIED / INDEPENDENT are metadata only — absent from every state table", () => {
    const stateTables = [
      ...RECEIVE_EXTERNAL_STATES,
      ...MOVE_INTERNAL_STATES,
      ...SEND_EXTERNAL_STATES,
      ...FORBIDDEN_STATE_ALIASES,
    ];
    for (const mode of VERIFICATION_MODES) {
      expect(stateTables).not.toContain(mode);
    }
    expect(stateTables).not.toContain(RELEASED_NODE_VERIFIED);
  });

  it("AC2: durable public event set remains exactly nine; modes are not events", () => {
    expect(DURABLE_EVENTS).toHaveLength(9);
    for (const mode of VERIFICATION_MODES) {
      expect(DURABLE_EVENTS as readonly string[]).not.toContain(mode);
    }
    expect(DURABLE_EVENTS as readonly string[]).not.toContain(RELEASED_NODE_VERIFIED);
    expect(DURABLE_EVENTS as readonly string[]).not.toContain("verification_mode");
  });

  it("rejects a third mode (negative path)", () => {
    expectRejects(
      () => [...VERIFICATION_MODES, "HYBRID"],
      (mutated) => assertFieldOrder(mutated, VERIFICATION_MODES),
    );
  });
});

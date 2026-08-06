import { describe, expect, it } from "vitest";

import { assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import { PUBLIC_ROUTES } from "../operations/routes.contract.ts";
import { REPORTING_REQUEST_HEADERS } from "../reporting-tuples/request-tuple.ts";
import {
  ZP_V1_PURPOSES,
  ZP1_RECEIVE_MESSAGE_PREFIX,
  ZP1_RECEIVE_MESSAGE_PATTERN_DESCRIPTION,
  REPORTING_HEADER_NAMES,
  TOTP_HEADER_NAME,
  ZP_HEADER_FAMILY,
  ZUPAY_COMPAT_NAME,
  ZUPAYMENTS_COMPAT_NAME,
  ZUPAY_NODE_DISCOVERY_PATH,
} from "./compat-literals.contract.ts";
import { FORBIDDEN_EVENT_GLOBS } from "./forbidden-aliases.contract.ts";

describe("compat-literals census", () => {
  it("freezes the full zp-*-v1 purpose family at exactly ten values, in canonical section sequence", () => {
    assertFieldOrder(ZP_V1_PURPOSES, [
      "zp-receive-expected-v1",
      "zp-move-internal-expected-v1",
      "zp-send-external-expected-v1",
      "zp-send-external-approval-v1",
      "zp-destination-bless-v1",
      "zp-device-enrol-v1",
      "zp-report-request-v1",
      "zp-reporting-register-v1",
      "zp-node-event-v1",
      "zp-wallet-head-fingerprint-v1",
    ]);
    expect(new Set(ZP_V1_PURPOSES).size).toBe(10);
  });

  it("freezes the zp1: receive-message prefix and its construction pattern", () => {
    expect(ZP1_RECEIVE_MESSAGE_PREFIX).toBe("zp1:");
    expect(ZP1_RECEIVE_MESSAGE_PATTERN_DESCRIPTION).toBe("zp1:<discriminator>:<anchor>");
    expect(ZP1_RECEIVE_MESSAGE_PATTERN_DESCRIPTION.startsWith(ZP1_RECEIVE_MESSAGE_PREFIX)).toBe(true);
  });

  it("derives the five reporting header names from reporting-tuples unchanged (single source of truth)", () => {
    assertFieldOrder(
      REPORTING_HEADER_NAMES,
      REPORTING_REQUEST_HEADERS.map((entry) => entry.header),
    );
    assertFieldOrder(REPORTING_HEADER_NAMES, [
      "X-ZP-Reporting-Key-Id",
      "X-ZP-Reporting-Timestamp",
      "X-ZP-Reporting-Expires-At",
      "X-ZP-Reporting-Nonce",
      "X-ZP-Reporting-Signature",
    ]);
  });

  it("freezes X-ZP-TOTP and the full X-ZP-* header family at exactly six values", () => {
    expect(TOTP_HEADER_NAME).toBe("X-ZP-TOTP");
    assertFieldOrder(ZP_HEADER_FAMILY, [...REPORTING_HEADER_NAMES, "X-ZP-TOTP"]);
  });

  it("freezes the zupay/zupayments compatibility names", () => {
    expect(ZUPAY_COMPAT_NAME).toBe("zupay");
    expect(ZUPAYMENTS_COMPAT_NAME).toBe("zupayments");
  });

  it("matches the live discovery route path unchanged (single source of truth)", () => {
    const liveRoute = PUBLIC_ROUTES.find((route) => route.path === ZUPAY_NODE_DISCOVERY_PATH);
    expect(liveRoute).toBeDefined();
    expect(liveRoute?.authMode).toBe("public");
  });

  it("rejects a compat purpose reordering (negative path)", () => {
    expectRejects(
      () => [...ZP_V1_PURPOSES].reverse(),
      (mutated) => assertFieldOrder(mutated, ZP_V1_PURPOSES),
    );
  });

  it("rejects a forbidden event-glob alias smuggled into the compat purpose set (negative path)", () => {
    const forbiddenSample = FORBIDDEN_EVENT_GLOBS[1];
    expect(ZP_V1_PURPOSES as readonly string[]).not.toContain(forbiddenSample);
    expectRejects(
      () => [...ZP_V1_PURPOSES, forbiddenSample],
      (mutated) => assertFieldOrder(mutated, ZP_V1_PURPOSES),
    );
  });
});

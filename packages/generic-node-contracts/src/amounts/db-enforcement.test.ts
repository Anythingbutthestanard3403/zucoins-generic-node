import { describe, it, expect } from "vitest";
import {
  ZKZ_CHECK_DOMAIN_BY_ROLE,
  AMOUNT_WRITE_VIOLATION_POLICY,
  FOREIGN_NO_REJECT,
} from "./db-enforcement.js";
import { ZKZ_AMOUNT_CHECK_DOMAINS } from "./manifest.js";
import { AMOUNT_FIELD_ROLES, type AmountFieldRole } from "./field-roles.js";

const mappedRoles = Object.keys(ZKZ_CHECK_DOMAIN_BY_ROLE) as Array<
  keyof typeof ZKZ_CHECK_DOMAIN_BY_ROLE
>;
const domainKeys = Object.keys(ZKZ_AMOUNT_CHECK_DOMAINS);

describe("DB CHECK-domain application map (the DB-domains concern) — consumes.1 domains", () => {
  it("every mapped domain is a real .1 CHECK domain or the foreign posture", () => {
    for (const role of mappedRoles) {
      const domain = ZKZ_CHECK_DOMAIN_BY_ROLE[role];
      const valid = domain === FOREIGN_NO_REJECT || domainKeys.includes(domain);
      expect(valid, `${role} -> ${domain}`).toBe(true);
    }
  });
  it("node operation roles get the positive domain, balance roles get the balance domain", () => {
    for (const role of mappedRoles) {
      const spec = AMOUNT_FIELD_ROLES[role as AmountFieldRole];
      if (spec.authorship === "node" && spec.layer === "operation") {
        expect(ZKZ_CHECK_DOMAIN_BY_ROLE[role]).toBe("zkz_amount_positive_text");
      } else if (spec.authorship === "node" && spec.layer === "balance") {
        expect(ZKZ_CHECK_DOMAIN_BY_ROLE[role]).toBe("zkz_balance_text");
      } else {
        expect(ZKZ_CHECK_DOMAIN_BY_ROLE[role]).toBe(FOREIGN_NO_REJECT);
      }
    }
  });
  it("the API-only request role is not given a DB column domain", () => {
    expect(mappedRoles).not.toContain("request_transfer_amount");
  });
  it("every persisted node/foreign role has a domain (only request is API-only)", () => {
    for (const role of Object.keys(AMOUNT_FIELD_ROLES) as AmountFieldRole[]) {
      if (role === "request_transfer_amount") continue;
      expect(mappedRoles).toContain(role);
    }
  });
});

describe("amount write-violation policy (the DB amount-domain enforcement rule / the never-blind-retry rule)", () => {
  it("is SQLSTATE 23514 routed to operator hold, never crash-loop, never resubmit", () => {
    expect(AMOUNT_WRITE_VIOLATION_POLICY).toEqual({
      sqlstate: "23514",
      disposition: "operator_hold_quarantine",
      neverCrashLoop: true,
      neverResubmit: true,
    });
  });
});

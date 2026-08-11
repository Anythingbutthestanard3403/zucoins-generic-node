// Security headers, two-tier CSP, cookie unit, adversarial suite.
// CORS emission helpers removed (ZTR-1166) — decideAdminCors stays in admin-cors tests.
import { describe, expect, it } from "vitest";

import {
  ADMIN_CSP,
  HSTS_VALUE,
  assertSecureSessionCookie,
  buildCheckoutCsp,
  buildSessionSetCookie,
  computeSecurityHeaders,
} from "../src/http/index.js";

describe("computeSecurityHeaders per route class", () => {
  it("admin: HSTS + frame-ancestors none + XFO DENY + Permissions-Policy", () => {
    const r = computeSecurityHeaders("admin", "req-1");
    expect(r.routeClass).toBe("admin");
    expect(r.requestId).toBe("req-1");
    expect(r.headers["Strict-Transport-Security"]).toBe(HSTS_VALUE);
    expect(r.headers["Content-Security-Policy"]).toBe(ADMIN_CSP);
    expect(r.headers["Content-Security-Policy"]).toContain("frame-ancestors 'none'");
    expect(r.headers["X-Frame-Options"]).toBe("DENY");
    expect(r.headers["X-Content-Type-Options"]).toBe("nosniff");
    expect(r.headers["Referrer-Policy"]).toBe("no-referrer");
    expect(r.headers["X-Request-Id"]).toBe("req-1");
    expect(r.headers["Permissions-Policy"]).toContain("camera=()");
    expect(Object.isFrozen(r.headers)).toBe(true);
  });

  it("public_api: same framing lockdown as admin", () => {
    const r = computeSecurityHeaders("public_api");
    expect(r.headers["Content-Security-Policy"]).toContain("frame-ancestors 'none'");
    expect(r.headers["X-Frame-Options"]).toBe("DENY");
    expect(r.headers["Strict-Transport-Security"]).toBe(HSTS_VALUE);
  });

  it("checkout_embed: merchant-scoped frame-ancestors, never wildcard", () => {
    const r = computeSecurityHeaders("checkout_embed", undefined, {
      merchantFrameAncestors: ["https://merchant.example"],
    });
    const csp = r.headers["Content-Security-Policy"]!;
    expect(csp).toContain("frame-ancestors 'self' https://merchant.example");
    expect(csp).not.toContain("*");
    expect(r.headers["X-Frame-Options"]).toBeUndefined();
    expect(r.headers["Strict-Transport-Security"]).toBe(HSTS_VALUE);
  });

  it("checkout CSP builder refuses wildcard", () => {
    expect(() => buildCheckoutCsp(["*"])).toThrow(/wildcard/);
    expect(() => buildCheckoutCsp(["https://ok.example", "https://*.evil"])).toThrow(
      /wildcard/,
    );
  });
});

describe("secure session cookie attributes", () => {
  it("Set-Cookie is Host-scoped Secure HttpOnly SameSite=Strict", () => {
    const setCookie = buildSessionSetCookie("sess-abc", {
      expiresAt: Date.now() + 60_000,
    });
    expect(() => assertSecureSessionCookie(setCookie)).not.toThrow();
    expect(setCookie).toMatch(/HttpOnly/i);
    expect(setCookie).toMatch(/Secure/i);
    expect(setCookie).toMatch(/SameSite=Strict/i);
    expect(setCookie).not.toMatch(/Domain=/i);
  });
});

describe("adversarial browser-origin suite (review indicators)", () => {
  it("iframe-embedding admin route: frame-ancestors none + XFO DENY", () => {
    const admin = computeSecurityHeaders("admin");
    expect(admin.headers["Content-Security-Policy"]).toMatch(/frame-ancestors 'none'/);
    expect(admin.headers["X-Frame-Options"]).toBe("DENY");
  });

  it("checkout-embed CSP from unlisted origin is not in frame-ancestors", () => {
    const allowed = ["https://shop.merchant.example"];
    const csp = buildCheckoutCsp(allowed);
    expect(csp).not.toContain("evil.example");
    expect(csp).toContain("https://shop.merchant.example");
    expect(csp).not.toContain("*");
  });
});

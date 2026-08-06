// Security headers, two-tier CSP, CORS emission, cookie unit, adversarial suite.
import { describe, expect, it } from "vitest";

import {
  ADMIN_CORS_ALLOW_HEADERS,
  ADMIN_CSP,
  DEFAULT_ADMIN_CORS,
  HSTS_VALUE,
  NODE_SECURITY_HEADERS,
  adminCorsFromAllowlist,
  adminCorsResponseHeaders,
  assertSecureSessionCookie,
  buildCheckoutCsp,
  buildSessionSetCookie,
  computeSecurityHeaders,
  decideAdminCors,
  emitAdminCorsHeaders,
  isCheckoutFrameAllowed,
} from "../src/http/index.js";

describe("NODE_SECURITY_HEADERS admin tier constants", () => {
  it("freezes admin CSP with frame-ancestors none", () => {
    expect(ADMIN_CSP).toContain("frame-ancestors 'none'");
    expect(ADMIN_CSP).not.toContain("*");
    expect(NODE_SECURITY_HEADERS["Content-Security-Policy"]).toBe(ADMIN_CSP);
    expect(NODE_SECURITY_HEADERS["Strict-Transport-Security"]).toBe(HSTS_VALUE);
    expect(NODE_SECURITY_HEADERS["X-Frame-Options"]).toBe("DENY");
    expect(NODE_SECURITY_HEADERS["X-Content-Type-Options"]).toBe("nosniff");
    expect(NODE_SECURITY_HEADERS["Cache-Control"]).toBe("no-store");
    expect(NODE_SECURITY_HEADERS["Referrer-Policy"]).toBe("no-referrer");
    expect(Object.isFrozen(NODE_SECURITY_HEADERS)).toBe(true);
  });
});

describe("computeSecurityHeaders per route class", () => {
  it("admin: HSTS + frame-ancestors none + XFO DENY", () => {
    const r = computeSecurityHeaders("admin", "req-1");
    expect(r.routeClass).toBe("admin");
    expect(r.requestId).toBe("req-1");
    expect(r.headers["Strict-Transport-Security"]).toBe(HSTS_VALUE);
    expect(r.headers["Content-Security-Policy"]).toContain("frame-ancestors 'none'");
    expect(r.headers["X-Frame-Options"]).toBe("DENY");
    expect(r.headers["X-Request-Id"]).toBe("req-1");
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

describe("admin CORS emission (exact-origin, no reflect)", () => {
  it("adversarial reflected-origin: no ACAO, no credentials", () => {
    const cfg = adminCorsFromAllowlist(["https://node.example"]);
    const headers = adminCorsResponseHeaders(cfg, "https://evil.example");
    expect(headers["Access-Control-Allow-Origin"]).toBeUndefined();
    expect(headers["Access-Control-Allow-Credentials"]).toBeUndefined();
    expect(Object.keys(headers)).toHaveLength(0);
  });

  it("allowed origin gets exact ACAO; credentials only when configured", () => {
    const withCreds = adminCorsFromAllowlist(["https://node.example"], true);
    const h = adminCorsResponseHeaders(withCreds, "https://node.example");
    expect(h["Access-Control-Allow-Origin"]).toBe("https://node.example");
    expect(h["Access-Control-Allow-Credentials"]).toBe("true");
    for (const name of ADMIN_CORS_ALLOW_HEADERS) {
      expect(h["Access-Control-Allow-Headers"]).toContain(name);
    }

    const noCreds = adminCorsFromAllowlist(["https://node.example"], false);
    const h2 = adminCorsResponseHeaders(noCreds, "https://node.example");
    expect(h2["Access-Control-Allow-Origin"]).toBe("https://node.example");
    expect(h2["Access-Control-Allow-Credentials"]).toBeUndefined();
  });

  it("DEFAULT_ADMIN_CORS denies every origin (no cross-origin)", () => {
    expect(decideAdminCors(DEFAULT_ADMIN_CORS, "https://any.example").ok).toBe(false);
    expect(emitAdminCorsHeaders(decideAdminCors(DEFAULT_ADMIN_CORS, "https://any.example")))
      .toEqual({});
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
  it("1. reflected-origin CORS attempt fails closed", () => {
    const cfg = adminCorsFromAllowlist(["https://legit.example"]);
    const headers = adminCorsResponseHeaders(cfg, "https://attacker.example");
    expect(headers["Access-Control-Allow-Origin"]).toBeUndefined();
  });

  it("2. credentialed cross-origin fetch attempt: Allow-Credentials absent on deny", () => {
    const cfg = adminCorsFromAllowlist(["https://legit.example"], true);
    const deny = adminCorsResponseHeaders(cfg, "https://attacker.example");
    expect(deny["Access-Control-Allow-Credentials"]).toBeUndefined();
    expect(deny["Access-Control-Allow-Origin"]).toBeUndefined();
  });

  it("3. iframe-embedding admin route: frame-ancestors none + XFO DENY", () => {
    const admin = computeSecurityHeaders("admin");
    expect(admin.headers["Content-Security-Policy"]).toMatch(/frame-ancestors 'none'/);
    expect(admin.headers["X-Frame-Options"]).toBe("DENY");
  });

  it("4. checkout-embed from unlisted origin is not allowed", () => {
    const allowed = ["https://shop.merchant.example"];
    expect(isCheckoutFrameAllowed("https://evil.example", allowed)).toBe(false);
    expect(isCheckoutFrameAllowed("https://shop.merchant.example", allowed)).toBe(true);
    expect(isCheckoutFrameAllowed(undefined, allowed)).toBe(false);
    const csp = buildCheckoutCsp(allowed);
    expect(csp).not.toContain("evil.example");
    expect(csp).toContain("https://shop.merchant.example");
  });
});

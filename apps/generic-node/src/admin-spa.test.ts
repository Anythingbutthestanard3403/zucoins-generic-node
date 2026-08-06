import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { tryServeAdminSpa } from "./admin-spa.js";

function mockRes() {
  const headers: Record<string, string> = {};
  let status = 0;
  let ended = false;
  return {
    writeHead(s: number, h?: Record<string, string>) {
      status = s;
      Object.assign(headers, h ?? {});
      return this;
    },
    end() {
      ended = true;
      return this;
    },
    get status() {
      return status;
    },
    get headers() {
      return headers;
    },
    get ended() {
      return ended;
    },
  };
}

describe("tryServeAdminSpa", () => {
  it("refuses API and ops paths so /admin/v1 and /v1 are never shadowed", () => {
    const dist = mkdtempSync(join(tmpdir(), "spa-"));
    writeFileSync(join(dist, "index.html"), "<html></html>");
    for (const url of [
      "/admin/v1/me",
      "/admin/v1/login",
      "/v1/receives",
      "/health",
      "/healthz",
      "/readyz",
      "/metrics",
      "/.well-known/zupay-node",
      "/embed/cs_token",
      "/embed",
    ]) {
      const res = mockRes();
      const ok = tryServeAdminSpa({ method: "GET", url } as never, res as never, dist);
      expect(ok).toBe(false);
    }
  });

  it("serves index for SPA routes", () => {
    const dist = mkdtempSync(join(tmpdir(), "spa-"));
    writeFileSync(join(dist, "index.html"), "<!doctype html><title>zu</title>");
    // HEAD avoids stream pipe; covers SPA fallback to index.html
    const headRes = mockRes();
    const ok = tryServeAdminSpa(
      { method: "HEAD", url: "/wallets" } as never,
      headRes as never,
      dist,
    );
    expect(ok).toBe(true);
    expect(headRes.status).toBe(200);
    expect(headRes.headers["content-type"]).toContain("text/html");
  });

  it("sets CSP frame-ancestors none and X-Frame-Options DENY", () => {
    const dist = mkdtempSync(join(tmpdir(), "spa-"));
    writeFileSync(join(dist, "index.html"), "<!doctype html><title>zu</title>");
    const headRes = mockRes();
    const ok = tryServeAdminSpa(
      { method: "HEAD", url: "/recovery-ceremony" } as never,
      headRes as never,
      dist,
    );
    expect(ok).toBe(true);
    expect(headRes.headers["content-security-policy"]).toMatch(/frame-ancestors 'none'/);
    expect(headRes.headers["x-frame-options"]).toBe("DENY");
  });

});

  it("serves webmanifest with manifest MIME and no-cache", () => {
    const dist = mkdtempSync(join(tmpdir(), "spa-"));
    writeFileSync(join(dist, "index.html"), "<!doctype html><title>zu</title>");
    writeFileSync(join(dist, "manifest.webmanifest"), '{"name":"Zu Node Operator"}');
    writeFileSync(join(dist, "sw.js"), "/* shell */");
    const man = mockRes();
    expect(tryServeAdminSpa({ method: "HEAD", url: "/manifest.webmanifest" } as never, man as never, dist)).toBe(true);
    expect(man.status).toBe(200);
    expect(man.headers["content-type"]).toContain("application/manifest+json");
    expect(man.headers["cache-control"]).toBe("no-cache");
    const sw = mockRes();
    expect(tryServeAdminSpa({ method: "HEAD", url: "/sw.js" } as never, sw as never, dist)).toBe(true);
    expect(sw.status).toBe(200);
    expect(sw.headers["content-type"]).toContain("javascript");
    expect(sw.headers["cache-control"]).toBe("no-cache");
  });


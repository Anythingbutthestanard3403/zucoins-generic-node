import { IncomingMessage, ServerResponse } from "node:http";
import { Socket } from "node:net";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ADMIN_SPA_ASSET_CACHE_CONTROL,
  ADMIN_SPA_SHELL_CACHE_CONTROL,
  tryServeAdminSpa,
} from "./admin-spa.js";

/** Count header names that match `name` case-insensitively (catches dual Cache-Control keys). */
function headerNameCount(headers: Record<string, string>, name: string): number {
  const want = name.toLowerCase();
  return Object.keys(headers).filter((k) => k.toLowerCase() === want).length;
}

/** Case-aware header read (Node IncomingMessage.headers are lowercase). */
function headerGet(headers: Record<string, string>, name: string): string | undefined {
  const want = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === want) return v;
  }
  return undefined;
}

function mockRes() {
  const headers: Record<string, string> = {};
  let status = 0;
  let ended = false;
  return {
    writeHead(s: number, h?: Record<string, string>) {
      status = s;
      // Preserve exact key casing from production bag so dual case-variants are visible.
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
    expect(headerGet(headRes.headers, "content-type")).toContain("text/html");
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
    expect(headerGet(headRes.headers, "content-security-policy")).toMatch(
      /frame-ancestors 'none'/,
    );
    expect(headerGet(headRes.headers, "x-frame-options")).toBe("DENY");
  });

  it("CSP stays self-only — no third-party font hosts (ZTR-1190)", () => {
    const dist = mkdtempSync(join(tmpdir(), "spa-"));
    writeFileSync(join(dist, "index.html"), "<!doctype html><title>zu</title>");
    const headRes = mockRes();
    expect(
      tryServeAdminSpa(
        { method: "HEAD", url: "/" } as never,
        headRes as never,
        dist,
      ),
    ).toBe(true);
    const csp = headerGet(headRes.headers, "content-security-policy") ?? "";
    expect(csp).toMatch(/style-src 'self' 'unsafe-inline'/);
    expect(csp).not.toMatch(/fonts\.googleapis\.com|fonts\.gstatic\.com/);
    // No font-src host allowlist; default-src 'self' covers fonts if self-hosted later.
    expect(csp).not.toMatch(/font-src[^;]*https?:/);
  });

  it("serves webmanifest with manifest MIME and no-cache", () => {
    const dist = mkdtempSync(join(tmpdir(), "spa-"));
    writeFileSync(join(dist, "index.html"), "<!doctype html><title>zu</title>");
    writeFileSync(join(dist, "manifest.webmanifest"), '{"name":"Zu Node Operator"}');
    writeFileSync(join(dist, "sw.js"), "/* shell */");
    const man = mockRes();
    expect(
      tryServeAdminSpa(
        { method: "HEAD", url: "/manifest.webmanifest" } as never,
        man as never,
        dist,
      ),
    ).toBe(true);
    expect(man.status).toBe(200);
    expect(headerGet(man.headers, "content-type")).toContain("application/manifest+json");
    expect(headerNameCount(man.headers, "cache-control")).toBe(1);
    expect(headerGet(man.headers, "cache-control")).toBe(ADMIN_SPA_SHELL_CACHE_CONTROL);
    const sw = mockRes();
    expect(
      tryServeAdminSpa({ method: "HEAD", url: "/sw.js" } as never, sw as never, dist),
    ).toBe(true);
    expect(sw.status).toBe(200);
    expect(headerGet(sw.headers, "content-type")).toContain("javascript");
    expect(headerNameCount(sw.headers, "cache-control")).toBe(1);
    expect(headerGet(sw.headers, "cache-control")).toBe(ADMIN_SPA_SHELL_CACHE_CONTROL);
  });

  it("one Cache-Control key: shell exactly no-cache, asset exactly immutable", () => {
    const dist = mkdtempSync(join(tmpdir(), "spa-"));
    writeFileSync(join(dist, "index.html"), "<!doctype html><title>zu</title>");
    mkdirSync(join(dist, "assets"), { recursive: true });
    writeFileSync(join(dist, "assets", "app.deadbeef.js"), "export {};");
    writeFileSync(join(dist, "manifest.webmanifest"), '{"name":"Zu"}');
    writeFileSync(join(dist, "sw.js"), "/* sw */");

    const shell = mockRes();
    expect(
      tryServeAdminSpa({ method: "HEAD", url: "/" } as never, shell as never, dist),
    ).toBe(true);
    expect(headerNameCount(shell.headers, "Cache-Control")).toBe(1);
    expect(headerGet(shell.headers, "Cache-Control")).toBe(ADMIN_SPA_SHELL_CACHE_CONTROL);
    expect(headerGet(shell.headers, "Cache-Control")).not.toMatch(/no-store/);

    const asset = mockRes();
    expect(
      tryServeAdminSpa(
        { method: "HEAD", url: "/assets/app.deadbeef.js" } as never,
        asset as never,
        dist,
      ),
    ).toBe(true);
    expect(headerNameCount(asset.headers, "cache-control")).toBe(1);
    expect(headerGet(asset.headers, "cache-control")).toBe(ADMIN_SPA_ASSET_CACHE_CONTROL);
    expect(headerGet(asset.headers, "cache-control")).not.toMatch(/no-store/);
  });

  it("Node ServerResponse wire headers: one Cache-Control line, exact values", () => {
    // ServerResponse.writeHead serializes every object key as its own header line.
    // Dual case variants { Cache-Control, cache-control } become two lines on the wire;
    // fetch/undici then joins them to "no-store, no-cache" (review B D1). Assert the
    // serialized block (res._header) — no listen/fetch (package network guard).
    const dist = mkdtempSync(join(tmpdir(), "spa-http-"));
    writeFileSync(join(dist, "index.html"), "<!doctype html><title>zu</title>");
    writeFileSync(join(dist, "app.abc123.js"), "console.log(1)");

    type Outgoing = ServerResponse & { readonly _header: string | null };

    function wireHeader(url: string): string {
      const socket = new Socket();
      socket.write = () => true;
      socket.end = (() => socket) as typeof socket.end;
      const req = new IncomingMessage(socket);
      req.method = "HEAD";
      req.url = url;
      const res = new ServerResponse(req) as Outgoing;
      expect(tryServeAdminSpa(req, res, dist)).toBe(true);
      expect(res.statusCode).toBe(200);
      expect(typeof res._header).toBe("string");
      return res._header as string;
    }

    function cacheControlLines(block: string): string[] {
      return block
        .split("\r\n")
        .filter((line) => /^cache-control:/i.test(line))
        .map((line) => line.slice(line.indexOf(":") + 1).trim());
    }

    // Sink fidelity: dual case keys produce two wire lines (D1 reproduction shape).
    {
      const socket = new Socket();
      socket.write = () => true;
      socket.end = (() => socket) as typeof socket.end;
      const req = new IncomingMessage(socket);
      const res = new ServerResponse(req) as Outgoing;
      res.writeHead(200, {
        "Cache-Control": "no-store",
        "cache-control": "no-cache",
      });
      expect(cacheControlLines(res._header as string)).toEqual(["no-store", "no-cache"]);
    }

    const shellLines = cacheControlLines(wireHeader("/"));
    expect(shellLines).toEqual([ADMIN_SPA_SHELL_CACHE_CONTROL]);

    const assetLines = cacheControlLines(wireHeader("/app.abc123.js"));
    expect(assetLines).toEqual([ADMIN_SPA_ASSET_CACHE_CONTROL]);
  });
});

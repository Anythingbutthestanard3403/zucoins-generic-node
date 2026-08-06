// GET /embed/:token on generic-node — co-locates pin keys (discovery) with embed host.

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  EMBED_PERMISSIONS_POLICY,
  injectBootstrap,
  tryServeEmbed,
} from "./embed-spa.js";

function mockRes() {
  const headers: Record<string, string> = {};
  let status = 0;
  let body = "";
  let ended = false;
  return {
    headersSent: false,
    writeHead(s: number, h?: Record<string, string>) {
      status = s;
      Object.assign(headers, h ?? {});
      this.headersSent = true;
      return this;
    },
    end(chunk?: string | Buffer) {
      if (chunk !== undefined) body = typeof chunk === "string" ? chunk : chunk.toString("utf8");
      ended = true;
      return this;
    },
    get status() {
      return status;
    },
    get headers() {
      return headers;
    },
    get body() {
      return body;
    },
    get ended() {
      return ended;
    },
  };
}

function shellDist(): string {
  const dist = mkdtempSync(join(tmpdir(), "embed-"));
  writeFileSync(
    join(dist, "index.html"),
    "<!doctype html><html><head><title>embed</title></head><body><div id=\"root\"></div></body></html>",
  );
  return dist;
}

describe("tryServeEmbed", () => {
  it("ignores non-embed paths", () => {
    const dist = shellDist();
    const res = mockRes();
    expect(
      tryServeEmbed({ method: "GET", url: "/.well-known/zupay-node" } as never, res as never, {
        distRoot: dist,
      }),
    ).toBe(false);
    expect(
      tryServeEmbed({ method: "GET", url: "/admin/v1/me" } as never, res as never, {
        distRoot: dist,
      }),
    ).toBe(false);
  });

  it("serves HTML with bootstrap + embed CSP on GET /embed/:token", async () => {
    const dist = shellDist();
    const res = mockRes();
    const ok = tryServeEmbed(
      { method: "GET", url: "/embed/cs_test_token" } as never,
      res as never,
      {
        distRoot: dist,
        merchantFrameAncestors: ["https://shop.example"],
      },
    );
    expect(ok).toBe(true);
    // async write
    await new Promise((r) => setTimeout(r, 20));
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toContain("text/html");
    expect(res.headers["permissions-policy"]).toBe(EMBED_PERMISSIONS_POLICY);
    expect(res.headers["content-security-policy"]).toMatch(/frame-ancestors/);
    expect(res.headers["content-security-policy"]).toContain("https://shop.example");
    expect(res.body).toContain('id="zp-bootstrap"');
    expect(res.body).toContain("cs_test_token");
    expect(res.body).toContain("<div id=\"root\">");
  });

  it("404 when resolveToken returns null (no enumeration body)", async () => {
    const dist = shellDist();
    const res = mockRes();
    tryServeEmbed({ method: "GET", url: "/embed/cs_missing" } as never, res as never, {
      distRoot: dist,
      resolveToken: async () => null,
    });
    await new Promise((r) => setTimeout(r, 20));
    expect(res.status).toBe(404);
    expect(res.body).toBe("");
  });

  it("500 when embed build is missing", () => {
    const empty = mkdtempSync(join(tmpdir(), "embed-empty-"));
    const res = mockRes();
    const ok = tryServeEmbed(
      { method: "GET", url: "/embed/cs_x" } as never,
      res as never,
      { distRoot: empty },
    );
    expect(ok).toBe(true);
    expect(res.status).toBe(500);
    expect(res.body).toBe("embed build missing");
  });
});

describe("injectBootstrap", () => {
  it("escapes literal < in JSON so </script> cannot break out", () => {
    const shell = "<html><head></head><body></body></html>";
    const html = injectBootstrap(shell, {
      session_id: "sess_<script>",
      order_id: "ord_1",
      allowed_parent_origins: [],
    });
    expect(html).not.toMatch(/<script id="zp-bootstrap"[^>]*>.*<script/s);
    expect(html).toContain("\\u003C");
    const m = html.match(/id="zp-bootstrap"[^>]*>([^<]+)</);
    expect(m).not.toBeNull();
    const parsed = JSON.parse(m![1]!) as { session_id: string };
    expect(parsed.session_id).toBe("sess_<script>");
  });
});

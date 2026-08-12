import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = join(dirname(fileURLToPath(import.meta.url)), "../../public");

describe("shell service worker contract", () => {
  const sw = readFileSync(join(root, "sw.js"), "utf8");
  const manifest = JSON.parse(readFileSync(join(root, "manifest.webmanifest"), "utf8")) as {
    name: string;
    short_name: string;
    start_url: string;
    display: string;
    icons: unknown[];
  };

  it("manifest is installable shape on node origin", () => {
    expect(manifest.name).toMatch(/Zu Node/i);
    expect(manifest.short_name).toMatch(/Zu Node/i);
    expect(manifest.start_url).toBe("/");
    expect(manifest.display).toBe("standalone");
    expect(manifest.icons.length).toBeGreaterThanOrEqual(2);
  });

  it("SW marks admin APIs and health as network-only", () => {
    expect(sw).toContain('pathname.startsWith("/admin/v1")');
    expect(sw).toContain('pathname.startsWith("/v1")');
    expect(sw).toContain('pathname.startsWith("/health")');
    expect(sw).toMatch(/isNetworkOnlyPath/);
    // Must not put JSON into durable cache
    expect(sw).toContain("isJsonLike");
    expect(sw).toMatch(/Never durable-caches authenticated JSON|never durable-cache/i);
  });

  it("SW only same-origin and shell asset caching", () => {
    expect(sw).toContain("url.origin !== self.location.origin");
    expect(sw).toContain("SHELL_CACHE");
    // ZTR-1252: versioned cache name (token stamped at build), not fixed v1.
    expect(sw).toContain("__SHELL_CACHE_BUILD_ID__");
    expect(sw).toContain(' "zu-node-shell-" + SHELL_CACHE_BUILD_ID');
    expect(sw).not.toMatch(/const SHELL_CACHE = "zu-node-shell-v1"/);
  });

  it("SW refuses to cache HTML under script/style URLs (ZTR-1252)", () => {
    expect(sw).toContain("isHtmlLike");
    expect(sw).toContain("isCacheableShellResponse");
    expect(sw).toContain("isUsableCachedResponse");
    expect(sw).toMatch(/javascript/);
    expect(sw).toMatch(/text\/css/);
  });

  it("activate purges other zu-node-* caches", () => {
    expect(sw).toMatch(/k\.startsWith\("zu-node-"\)/);
    expect(sw).toContain("caches.delete");
  });
});

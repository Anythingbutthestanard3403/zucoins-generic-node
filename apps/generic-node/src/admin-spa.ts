// Serves the built @zucoins/generic-node-ui SPA (apps/generic-node/admin/dist).
// Mounted last among non-API paths so /admin/v1, /v1, health, metrics stay authoritative.
// Mirrors apps/node admin-dist static mount without pulling Hono serveStatic.

import { createReadStream, existsSync, statSync } from "node:fs";
import { extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import type { IncomingMessage, ServerResponse } from "node:http";

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".map": "application/json",
  ".webmanifest": "application/manifest+json; charset=utf-8",
};

export function resolveAdminSpaDist(): string | null {
  const here = fileURLToPath(new URL(".", import.meta.url));
  // dist/ dev: apps/generic-node/dist -> ../admin/dist
  // nested:apps/generic-node/src compiled beside admin
  const candidates = [
    resolve(here, "../admin/dist"),
    resolve(here, "../../admin/dist"),
    resolve(process.cwd(), "admin/dist"),
    resolve(process.cwd(), "apps/generic-node/admin/dist"),
  ];
  for (const c of candidates) {
    if (existsSync(join(c, "index.html"))) return c;
  }
  return null;
}

function safeJoin(root: string, reqPath: string): string | null {
  let cleaned: string;
  try {
    cleaned = decodeURIComponent(reqPath.split("?")[0] ?? "/");
  } catch {
    // Malformed percent-escape (URIError from e.g. "/%zz") — not servable,
    // same verdict as a traversal attempt. Total function: never throws into
    // the synchronous dispatch closure (ZTR-1185).
    return null;
  }
  const rel = cleaned === "/" ? "index.html" : cleaned.replace(/^\/+/, "");
  const full = normalize(join(root, rel));
  if (!full.startsWith(root.endsWith(sep) ? root : root + sep) && full !== root) {
    return null;
  }
  return full;
}

/**
 * Attempt to serve SPA assets. Returns true if the response was written.
 */
export function tryServeAdminSpa(
  request: IncomingMessage,
  response: ServerResponse,
  distRoot: string,
): boolean {
  const method = (request.method ?? "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") return false;

  const rawUrl = request.url ?? "/";
  const pathname = rawUrl.split(/[?#]/, 1)[0] ?? "/";

  // API, ops, and embed paths — never SPA
  if (
    pathname.startsWith("/admin/v1") ||
    pathname.startsWith("/v1") ||
    pathname.startsWith("/health") ||
    pathname === "/healthz" ||
    pathname === "/readyz" ||
    pathname === "/metrics" ||
    pathname.startsWith("/.well-known") ||
    pathname.startsWith("/embed/") ||
    pathname === "/embed"
  ) {
    return false;
  }

  let filePath = safeJoin(distRoot, pathname === "/" ? "/index.html" : pathname);
  if (!filePath) {
    response.writeHead(400).end();
    return true;
  }

  if (!existsSync(filePath) || statSync(filePath).isDirectory()) {
    // client-side route → index.html
    filePath = join(distRoot, "index.html");
    if (!existsSync(filePath)) return false;
  }

  const ext = extname(filePath);
  const type = MIME[ext] ?? "application/octet-stream";
  const stat = statSync(filePath);
  const noCache =
    ext === ".html" ||
    ext === ".webmanifest" ||
    filePath.endsWith(`${sep}sw.js`) ||
    filePath.endsWith("/sw.js");
  response.writeHead(200, {
    "content-type": type,
    "content-length": stat.size,
    "cache-control": noCache ? "no-cache" : "public, max-age=31536000, immutable",
    "x-content-type-options": "nosniff",
    // Admin security gates: no framing; restrictive CSP on Operator PWA.
    "content-security-policy":
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
  });
  if (method === "HEAD") {
    response.end();
    return true;
  }
  createReadStream(filePath).pipe(response);
  return true;
}

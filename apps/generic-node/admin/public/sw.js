/* Zu Node operator PWA — shell-only service worker.
 *
 * Precaches HTML/CSS/JS/icons for offline shell paint.
 * NEVER durable-caches authenticated JSON (balances, approvals, session).
 * Admin/public money APIs and health probes are network-only.
 * Does not touch cookies, CSP, or response bodies that embed secrets.
 */
/* eslint-disable no-restricted-globals */
const SHELL_CACHE = "zu-node-shell-v1";
const PRECACHE = [
  "/",
  "/index.html",
  "/manifest.webmanifest",
  "/icons/icon-32.png",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
];

/** Paths that must never enter any Cache Storage. */
function isNetworkOnlyPath(pathname) {
  return (
    pathname.startsWith("/admin/v1") ||
    pathname.startsWith("/v1") ||
    pathname.startsWith("/health") ||
    pathname === "/healthz" ||
    pathname === "/readyz" ||
    pathname === "/metrics" ||
    pathname.startsWith("/.well-known") ||
    pathname === "/sw.js"
  );
}

function isShellAssetPath(pathname) {
  if (pathname === "/" || pathname === "/index.html") return true;
  if (pathname === "/manifest.webmanifest") return true;
  if (pathname.startsWith("/icons/")) return true;
  if (pathname.startsWith("/assets/")) return true;
  // Vite-hashed entry chunks at root are uncommon; still allow hashed static.
  return /\.(?:js|css|png|svg|ico|woff2|webp|map)$/.test(pathname);
}

function isJsonLike(response) {
  const ct = (response.headers.get("content-type") || "").toLowerCase();
  return ct.includes("application/json") || ct.includes("+json");
}

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(SHELL_CACHE)
      .then((cache) => cache.addAll(PRECACHE))
      .then(() => self.skipWaiting())
      .catch(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((k) => k.startsWith("zu-node-") && k !== SHELL_CACHE)
            .map((k) => caches.delete(k)),
        ),
      )
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET" && req.method !== "HEAD") return;

  const url = new URL(req.url);
  // Same-origin only — never intercept cross-origin (fonts CDN etc.).
  if (url.origin !== self.location.origin) return;

  if (isNetworkOnlyPath(url.pathname)) {
    // Network-only: do not read or write Cache Storage for API/health.
    event.respondWith(fetch(req));
    return;
  }

  const accept = req.headers.get("accept") || "";
  const isNavigation =
    req.mode === "navigate" ||
    (req.destination === "document" && accept.includes("text/html"));

  if (isNavigation) {
    // Network-first shell HTML; offline falls back to cached index only.
    event.respondWith(
      fetch(req)
        .then(async (res) => {
          if (res.ok && !isJsonLike(res)) {
            const cache = await caches.open(SHELL_CACHE);
            // Store a clone of the HTML shell only.
            void cache.put("/index.html", res.clone());
          }
          return res;
        })
        .catch(async () => {
          const cache = await caches.open(SHELL_CACHE);
          const hit =
            (await cache.match(req)) ||
            (await cache.match("/index.html")) ||
            (await cache.match("/"));
          if (hit) return hit;
          return new Response(
            "<!doctype html><title>Zu Node offline</title><p>Node unreachable. Reconnect to load the operator console.</p>",
            { status: 503, headers: { "content-type": "text/html; charset=utf-8" } },
          );
        }),
    );
    return;
  }

  if (!isShellAssetPath(url.pathname)) {
    // Unknown same-origin path: network only (no cache write).
    event.respondWith(fetch(req));
    return;
  }

  // Shell static assets: cache-first after a successful non-JSON network put.
  event.respondWith(
    caches.open(SHELL_CACHE).then(async (cache) => {
      const cached = await cache.match(req);
      if (cached && !isJsonLike(cached)) return cached;
      try {
        const res = await fetch(req);
        if (res.ok && !isJsonLike(res)) {
          // Only cache opaque-safe shell bytes — never JSON bodies.
          void cache.put(req, res.clone());
        }
        return res;
      } catch (err) {
        if (cached) return cached;
        throw err;
      }
    }),
  );
});

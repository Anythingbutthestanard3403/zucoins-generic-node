// Serves the node-origin embed (widget dist-embed assets) at
// GET /embed/:token on the same origin that publishes
// /.well-known/zupay-node with expected_artifact_public_keys.
//
// Co-locates the pin source and the embed host so EmbedApp's default
// verifyArtifactForEmbed (same-origin discovery fetch) can verify against the
// node's own pinned keys. generic-node is the production pin path.
//
// Single-file shell (vite-plugin-singlefile): one HTML document, no asset
// mount.

import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { IncomingMessage, ServerResponse } from "node:http";

import {
  buildCheckoutCsp,
  computeSecurityHeaders,
} from "@zucoins/node-core";

/** Permissions-Policy complementary to parent iframe clipboard-write. */
export const EMBED_PERMISSIONS_POLICY = "clipboard-write=(self)";

const EMBED_PATH_RE = /^\/embed\/([^/]+)\/?$/;

export function resolveEmbedDist(): string | null {
  const here = fileURLToPath(new URL(".", import.meta.url));
  const candidates = [
    // apps/generic-node/src or dist → monorepo packages/widget/dist-embed
    resolve(here, "../../../packages/widget/dist-embed"),
    resolve(here, "../../../../packages/widget/dist-embed"),
    resolve(process.cwd(), "packages/widget/dist-embed"),
    resolve(process.cwd(), "../packages/widget/dist-embed"),
  ];
  for (const c of candidates) {
    if (existsSync(join(c, "index.html"))) return c;
  }
  return null;
}

export interface EmbedBootstrapPayload {
  readonly session_id: string;
  readonly order_id: string;
  readonly allowed_parent_origins: readonly string[];
}

/**
 * Escape every literal "<" so a hostile session_id/order_id cannot break out
 * of the JSON script block (same discipline as apps/node embed-route).
 */
export function injectBootstrap(shellHtml: string, payload: EmbedBootstrapPayload): string {
  const json = JSON.stringify(payload).replace(/</g, "\\u003C");
  const script = `<script id="zp-bootstrap" type="application/json">${json}</script>`;
  return shellHtml.replace("</head>", `${script}</head>`);
}

export interface EmbedServeDeps {
  /** Built embed shell directory (packages/widget/dist-embed). */
  readonly distRoot: string;
  /**
   * Resolve a token to session identifiers for #zp-bootstrap. Return null for
   * unknown/expired — caller gets a uniform 404 (no enumeration oracle).
   * When omitted, bootstrap uses the URL token as both session_id and order_id
   * (shell still loads; terminal postMessages stay empty-id safe).
   */
  readonly resolveToken?: (
    token: string,
  ) =>
    | { sessionId: string; orderId: string }
    | null
    | Promise<{ sessionId: string; orderId: string } | null>;
  /** Embedding-site frame-ancestors allow-list (embed CSP). Empty → 'self' only. */
  readonly merchantFrameAncestors?: readonly string[];
}

/**
 * Attempt to serve GET /embed/:token. Returns true when the response was written.
 */
export function tryServeEmbed(
  request: IncomingMessage,
  response: ServerResponse,
  deps: EmbedServeDeps,
): boolean {
  const method = (request.method ?? "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") return false;

  const rawUrl = request.url ?? "/";
  const pathname = rawUrl.split(/[?#]/, 1)[0] ?? "/";
  const match = EMBED_PATH_RE.exec(pathname);
  if (match === null) return false;

  const token = match[1] ?? "";
  if (token.length === 0) return false;

  const shellPath = join(deps.distRoot, "index.html");
  if (!existsSync(shellPath)) {
    response.writeHead(500, {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
    });
    response.end("embed build missing");
    return true;
  }

  // Async resolve when a resolver is supplied; write once ready.
  void (async () => {
    try {
      let sessionId = token;
      let orderId = token;
      if (deps.resolveToken !== undefined) {
        const resolved = await deps.resolveToken(token);
        if (resolved === null) {
          response.writeHead(404, {
            "content-type": "text/plain; charset=utf-8",
            "cache-control": "no-store",
          });
          response.end();
          return;
        }
        sessionId = resolved.sessionId;
        orderId = resolved.orderId;
      }

      const shell = readFileSync(shellPath, "utf8");
      const html = injectBootstrap(shell, {
        session_id: sessionId,
        order_id: orderId,
        allowed_parent_origins: [...(deps.merchantFrameAncestors ?? [])],
      });

      const sec = computeSecurityHeaders("checkout_embed", undefined, {
        merchantFrameAncestors: deps.merchantFrameAncestors ?? [],
      });
      const headers: Record<string, string> = {
        ...sec.headers,
        "content-type": "text/html; charset=utf-8",
        "content-length": String(Buffer.byteLength(html, "utf8")),
        "permissions-policy": EMBED_PERMISSIONS_POLICY,
        // CSP already set by computeSecurityHeaders; reinforce frame policy.
        "content-security-policy": buildCheckoutCsp(deps.merchantFrameAncestors ?? []),
      };

      if (method === "HEAD") {
        response.writeHead(200, headers);
        response.end();
        return;
      }
      response.writeHead(200, headers);
      response.end(html);
    } catch {
      if (!response.headersSent) {
        response.writeHead(500, {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "no-store",
        });
        response.end("embed serve failed");
      }
    }
  })();

  return true;
}

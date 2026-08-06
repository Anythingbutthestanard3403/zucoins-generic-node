/**
 * API-key authenticator + scope-enforcement primitive.
 *
 * Relocated off frozen apps/node. Accepts a drizzle-shaped
 * select/update handle (the alphabet's fakeDb) so the fail-closed-before-DB and
 * no-update-on-reject postures stay observable without a DB or Hono runtime.
 */
import { verifyPassword } from "../../src/http/password.js";
import { errorBody } from "./errors.js";
import {
  type ApiKeyKind,
  KEY_SCHEME_PREFIX,
  kindForToken,
  lookupPrefix,
  sha256Matches,
} from "./keygen.js";
import type { GateContext, GateHandler, GateNext } from "./middleware-gates.js";

export interface AuthenticatedApiKey {
  id: string;
  kind: ApiKeyKind;
}

export const SESSION_KEY_KINDS = ["SITE", "ACTION"] as const;
export const REPORTING_KEY_KINDS = ["REPORTING", "ACTION"] as const;
export const ACTION_KEY_KINDS = ["ACTION"] as const;

/** Drizzle-shaped query surface the alphabet fakeDb implements. */
export interface ApiKeyDb {
  select: (shape?: unknown) => {
    from: (table?: unknown) => {
      where: (clause?: unknown) => Promise<readonly { id: string; kind: string; keyHash: string }[]>;
    };
  };
  update: (table?: unknown) => {
    set: (values: unknown) => {
      where: (clause?: unknown) => Promise<unknown>;
    };
  };
}

function extractBearerToken(header: string | undefined): string | null {
  if (!header) return null;
  const match = /^Bearer\s+(.+)$/.exec(header);
  return match ? match[1].trim() : null;
}

export async function authenticateApiKey(
  db: ApiKeyDb,
  token: string,
): Promise<AuthenticatedApiKey | null> {
  const kind = kindForToken(token);
  if (!kind) return null;
  if (token.startsWith(`${KEY_SCHEME_PREFIX[kind]}test_`)) return null;

  const prefix = lookupPrefix(token);
  const candidates = await db
    .select({ id: "id", kind: "kind", keyHash: "keyHash" })
    .from("api_keys")
    .where(`key_prefix=${prefix}`);

  for (const candidate of candidates) {
    const matches =
      candidate.kind === "SITE"
        ? await verifyPassword(token, candidate.keyHash)
        : sha256Matches(token, candidate.keyHash);
    if (matches) {
      return { id: candidate.id, kind: candidate.kind as ApiKeyKind };
    }
  }
  return null;
}

export function verifyApiKey(db: ApiKeyDb, allowed: readonly ApiKeyKind[]): GateHandler {
  return async (c: GateContext, next: GateNext) => {
    const token = extractBearerToken(c.req.header("authorization"));
    if (!token) {
      return c.json(errorBody("invalid_api_key", "missing or invalid api key"), 401);
    }

    const key = await authenticateApiKey(db, token);
    if (!key || !allowed.includes(key.kind)) {
      return c.json(errorBody("invalid_api_key", "missing or invalid api key"), 401);
    }

    await db.update("api_keys").set({ lastUsedAt: new Date() }).where(`id=${key.id}`);
    c.set("apiKeyId", key.id);
    c.set("apiKeyKind", key.kind);
    await next();
  };
}

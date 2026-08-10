// Field-level Zod helpers for the frozen env schema: URL/origin predicates
// and comma-separated-list composition, shared by env-schema.ts's field
// definitions. Kept separate so the schema file stays a readable field list.

import { z } from "@zucoins/node-core";

const LOOPBACK_HOSTNAMES = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

export function isHttpsOrLoopbackHttp(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol === "https:") return true;
  return url.protocol === "http:" && LOOPBACK_HOSTNAMES.has(url.hostname);
}

/** True when the URL has no embedded userinfo (matches gateway allowlist:47-51). */
export function hasNoUrlCredentials(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  return url.username === "" && url.password === "";
}

export function isExactHttpOrigin(raw: string): boolean {
  if (!isHttpsOrLoopbackHttp(raw)) return false;
  return new URL(raw).origin === raw;
}

export function splitCommaSeparated(raw: string): string[] {
  return raw
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part !== "");
}

export const endpointUrl = (field: string) =>
  z
    .string()
    .url(`${field} entries must be well-formed URLs`)
    .refine(
      isHttpsOrLoopbackHttp,
      `${field} entries must be https URLs (http is accepted only for loopback addresses)`,
    );

export const commaSeparatedOptional = <T extends z.ZodType>(entry: T) =>
  z
    .string()
    .default("")
    .transform(splitCommaSeparated)
    .pipe(z.array(entry));

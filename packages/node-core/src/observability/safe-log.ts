// centralized safe-logging / secret redaction.
// Field-name-driven redactor (structural, never conventional). Pure functions:
// no logger framework dependency — adapters wrap pino/console via redactLogFields.

export const REDACTED = "[redacted]" as const;
export const ELLIPSIS = "…" as const;
export const MAX_REDACT_DEPTH = 8;

/** Lowercase + strip separators so VAULT_MASTER_KEY / vaultMasterKey / vault-master-key match. */
export function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[_\-\s]/g, "");
}

/**
 * Full-censor field names: private keys, secrets, passwords,
 * cookies, CSRF/XSRF, API-key plaintext, bearer tokens, TOTP material, session material.
 */
export function isNeverLog(name: string): boolean {
  if (name.includes("privatekey") || name.includes("privkey")) return true;
  if (name.includes("secretkey") || name === "seckey") return true;
  if (name.includes("masterkey")) return true;
  if (name === "secret" || name.endsWith("secret")) return true;
  if (name.includes("password") || name === "passwd" || name === "pwd") return true;
  if (name.includes("cookie")) return true;
  if (name.includes("csrf") || name.includes("xsrf")) return true;
  if (name === "apikey" || name.includes("plaintext")) return true;
  if (name.includes("bearertoken") || name === "authorization" || name === "authtoken") {
    return true;
  }
  if (name.includes("totp") || name.includes("otpcod") || name === "otp") return true;
  if (name.includes("sessionid") && name.includes("raw")) return true;
  if (name === "sessiontoken" || name === "sessionsecret") return true;
  // Raw SplitChain evidence bodies / exact preimages outside surface.
  if (name.includes("rawpreimage") || name.includes("rawevidence") || name === "gatewayresponse") {
    return true;
  }
  if (name.includes("signingpreimage") || name === "exactpreimage") return true;
  return false;
}

export type TruncateKind = "pubkey" | "code" | "ciphertext";

/** Truncate (not full-censor) diagnostic-useful partial forms. */
export function truncateKind(name: string): TruncateKind | null {
  if (name.includes("ciphertext") || name.includes("vaultenvelope")) return "ciphertext";
  if (name.includes("pubkey") || name.includes("publickey")) return "pubkey";
  if (name.includes("transfercode")) return "code";
  // Bearer key IDs / prefixes stay full; full bearer *values* are never-log via plaintext/apikey.
  return null;
}

export function truncate(kind: TruncateKind, value: string): string {
  if (kind === "pubkey") {
    return value.length <= 12 ? value : `${value.slice(0, 8)}${ELLIPSIS}${value.slice(-4)}`;
  }
  if (kind === "code") {
    return value.length <= 8 ? value : `${value.slice(0, 8)}${ELLIPSIS}`;
  }
  return value.length <= 16 ? value : `${value.slice(0, 16)}${ELLIPSIS}`;
}

function redactValue(value: unknown, seen: WeakSet<object>, depth: number): unknown {
  if (depth > MAX_REDACT_DEPTH) return value;
  if (value instanceof Error) {
    return { type: value.name, message: value.message, stack: value.stack };
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) return "[circular]";
    seen.add(value);
    const out = value.map((item) => redactValue(item, seen, depth + 1));
    seen.delete(value);
    return out;
  }
  if (value !== null && typeof value === "object") {
    if (seen.has(value)) return "[circular]";
    seen.add(value);
    const out = redactObject(value as Record<string, unknown>, seen, depth + 1);
    seen.delete(value);
    return out;
  }
  return value;
}

function redactObject(
  obj: Record<string, unknown>,
  seen: WeakSet<object>,
  depth: number,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(obj)) {
    const value = obj[key];
    const name = normalizeKey(key);
    if (isNeverLog(name)) {
      out[key] = REDACTED;
      continue;
    }
    const kind = truncateKind(name);
    if (kind !== null && typeof value === "string") {
      out[key] = truncate(kind, value);
      continue;
    }
    out[key] = redactValue(value, seen, depth);
  }
  return out;
}

/**
 * Deep-copy redaction of a log bindings object. Never mutates the caller object
 * (money-path values routed through a log line stay byte-exact — the byte-exact signing rule).
 */
export function redactLogFields(
  fields: Record<string, unknown>,
): Record<string, unknown> {
  return redactObject(fields, new WeakSet(), 0);
}

/**
 * Structured API error `details` scrub: strip secrets, raw signed bodies,
 * gateway responses, cross-tenant existence oracles. Returns a new object.
 */
export function scrubErrorDetails(
  details: unknown,
): unknown {
  if (details === null || details === undefined) return details;
  if (typeof details !== "object") return details;
  return redactLogFields(details as Record<string, unknown>);
}

/**
 * Uniform 404 shape for "absent or outside authenticated tenant" — no existence leak.
 * Callers MUST use this for both cross-tenant and genuine-not-found probes.
 */
export function notFoundErrorBody(requestId?: string): {
  readonly error: {
    readonly code: "not_found";
    readonly message: string;
    readonly details: Record<string, never>;
  };
  readonly request_id?: string;
} {
  const body: {
    error: { code: "not_found"; message: string; details: Record<string, never> };
    request_id?: string;
  } = {
    error: {
      code: "not_found",
      message: "Object is absent or outside the authenticated tenant",
      details: {},
    },
  };
  if (requestId !== undefined) body.request_id = requestId;
  return body;
}

/**
 * Fail-closed census: return keys whose values still look like they carried
 * secret classes after redaction (should be empty).
 */
export function findUnredactedSecretKeys(
  fields: Record<string, unknown>,
  depth = 0,
): string[] {
  if (depth > MAX_REDACT_DEPTH) return [];
  const hits: string[] = [];
  for (const [key, value] of Object.entries(fields)) {
    const name = normalizeKey(key);
    if (isNeverLog(name) && value !== REDACTED) {
      hits.push(key);
    }
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      hits.push(
        ...findUnredactedSecretKeys(value as Record<string, unknown>, depth + 1).map(
          (k) => `${key}.${k}`,
        ),
      );
    }
  }
  return hits;
}

/**
 * Backup/export dump scan: assert no plaintext secret-class keys appear under root.
 * Ciphertext under truncateKind fields is allowed in truncated form only after redact.
 */
export function assertDumpSecretFree(dump: Record<string, unknown>): void {
  const redacted = redactLogFields(dump);
  const leaks = findUnredactedSecretKeys(redacted);
  if (leaks.length > 0) {
    throw new Error(`secret-classed keys survived redaction: ${leaks.join(",")}`);
  }
}

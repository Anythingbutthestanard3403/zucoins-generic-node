// centralized safe-logging / secret redaction.
// Field-name-driven redactor (structural, never conventional). Pure functions:
// no logger framework dependency — adapters wrap pino/console via redactLogFields.

export const REDACTED = "[redacted]" as const;
export const ELLIPSIS = "…" as const;
export const MAX_REDACT_DEPTH = 8;
/**
 * Emitted in place of anything nested past MAX_REDACT_DEPTH. Distinct from
 * REDACTED on purpose: REDACTED means "inspected and censored", this means
 * "never inspected", and assertDumpSecretFree refuses to certify the latter.
 */
export const MAX_DEPTH_MARKER = "[max-depth]" as const;

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
  // Recovery-pack PIN and sealed blob field names (ZTR-1171). password ≠ passcode.
  if (name.includes("passcode") || name === "pin" || name.endsWith("pin")) return true;
  if (name.includes("packfile")) return true;
  if (name.includes("cookie")) return true;
  if (name.includes("csrf") || name.includes("xsrf")) return true;
  if (name === "apikey" || name.includes("plaintext")) return true;
  if (name.includes("bearertoken") || name === "authorization" || name === "authtoken") {
    return true;
  }
  if (name.includes("totp") || name.includes("otpcod") || name === "otp") return true;
  if (name.includes("sessionid") && name.includes("raw")) return true;
  if (name === "sessiontoken" || name === "sessionsecret") return true;
  // Subscription handle plaintext (`sh_…`) — returned once on create; never log.
  // Covers subscription_handle / subscriptionHandle / subscriptionHandlePlaintext.
  if (name.includes("subscriptionhandle")) return true;
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

/**
 * `key=value` / `key: value` assignments inside **free text** — a log message,
 * an `Error.message`, a formatted failure cause. The key class stops at
 * whitespace and quotes, so a JSON fragment (`"password":"…"`) never matches:
 * structured payloads are redacted by field name through redactLogFields.
 *
 * The value class deliberately consumes `"` and `'`. It has to. Free text
 * arrives truncated — the runtime listener cuts a cause at 200 characters —
 * so `pwd="secret` with no closing quote is the ordinary shape, not the exotic
 * one, and a class that stopped at the opening quote emitted the plaintext.
 *
 * That is safe only because this scrubber is never run over serialized JSON.
 * A quote-consuming class run across a JSON line eats string terminators; a
 * quote-avoiding one leaks truncated values. One pattern cannot do both jobs,
 * so it only does this one — redactValue scrubs each string *before*
 * serialization and the logger adapter re-redacts a JSON line structurally
 * rather than textually (apps/generic-node/src/boot/safe-logger.ts).
 *
 * `]` is not a terminator, which is what makes the scrub idempotent: the class
 * consumes `[redacted]` whole, so a second pass rewrites it to itself. Stopping
 * at `]` instead both grew a `]` per pass and let `pwd=[redacted]still-secret`
 * — a value the caller controls — keep its tail.
 */
const TEXT_ASSIGNMENT = /([A-Za-z0-9_.-]{1,64})(\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;)}]+)/g;

/**
 * URL userinfo with a password (`scheme://user:pass@host`). The whole userinfo
 * segment is censored. Delimiters:
 * - last `@` before the host (passwords may themselves contain `@`, e.g. `P@ssw0rd`)
 * - a `:` required inside userinfo so username-only forms (`scheme://user@host`)
 *   and path forms that happen to contain `@` (pnpm `file:///…/pkg@1.2.3`) are
 *   left alone: the former is uncommon in free-text diagnostics, the latter is
 *   ordinary stack material that must not be chewed.
 * - `/ ? #` are excluded from the userinfo class so the greedy last-`@` stop is
 *   authority-scoped: a Windows `file:///C:/…/vitest@3.2.7` frame and a real
 *   credential URL followed by a path `@` (`…@host/path/pkg@1.2.3`) must not
 *   let path material extend the match past the authority boundary.
 * Greedy `*` on a class that permits `@` (but not `/ ? #`) makes the engine
 * take the rightmost authority `@` that still leaves a `:` in userinfo —
 * first-`@` stop would leak the password tail
 * (`postgres://u:P@ssw0rd@h` → `…[redacted]@ssw0rd@h`).
 */
const TEXT_URL_USERINFO = /([A-Za-z][A-Za-z0-9+.-]*:\/\/)([^\s"'<>/?#]*:[^\s"'<>/?#]*)@/g;

/**
 * Candidate bare tokens for the high-entropy pass. Length floor is deliberate:
 * ordinary prose words and short ids stay under it; the entropy gate below
 * still rejects long pure-decimal / pure-lowercase runs. `/` is deliberately
 * excluded so filesystem paths and URL path segments are not chewed as tokens
 * (stack frames must stay readable).
 */
const BARE_TOKEN_CANDIDATE = /\b([A-Za-z0-9_+=.-]{24,})\b/g;

/**
 * True when a bare token is secret-shaped enough to censor without a field
 * name: long hex, mixed-case+digit material, or base64/base64url-like runs.
 * Pure decimal and ordinary lowercase identifiers stay put so prose and
 * money-path decimal strings are not chewed.
 */
export function isHighEntropyToken(token: string): boolean {
  if (token.length < 24) return false;
  if (token === REDACTED) return false;
  // Pure digits — amounts, counters, timestamps — are not secret-shaped.
  if (/^\d+$/.test(token)) return false;
  // Standard UUID form is an identifier operators need in diagnostics, not a secret.
  if (
    /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(
      token,
    )
  ) {
    return false;
  }
  const hexBody = token.replace(/-/g, "");
  // 32+ continuous hex (raw key material / hashes). Hyphenated UUIDs already returned.
  if (/^[0-9a-fA-F]+$/.test(hexBody) && hexBody.length >= 32 && !token.includes("-")) return true;
  const hasLower = /[a-z]/.test(token);
  const hasUpper = /[A-Z]/.test(token);
  const hasDigit = /[0-9]/.test(token);
  // Mixed case + digit is the ordinary shape of an API key / random secret.
  if (hasLower && hasUpper && hasDigit) return true;
  // Base64 / base64url alphabet: require an uppercase class so long lowercase
  // identifiers (`postgresql-connection-string-name…`) are not chewed.
  if (
    /^[A-Za-z0-9_+=/-]+$/.test(token) &&
    token.length >= 28 &&
    hasUpper &&
    (hasLower || hasDigit)
  ) {
    return true;
  }
  return false;
}

/**
 * Free-text counterpart of the field-name redactor, for strings that were
 * already formatted before anyone could redact them structurally — log
 * messages, `Error.message`, `Error.stack`.
 *
 * Three passes, each idempotent and ordered so later passes cannot undo earlier
 * ones: URL userinfo → never-log assignments → bare high-entropy tokens.
 */
export function scrubText(text: string): string {
  const withUrls = text.replace(TEXT_URL_USERINFO, (_m, scheme: string) => `${scheme}${REDACTED}@`);
  const withAssignments = withUrls.replace(
    TEXT_ASSIGNMENT,
    (match, key: string, separator: string) =>
      isNeverLog(normalizeKey(key)) ? `${key}${separator}${REDACTED}` : match,
  );
  return withAssignments.replace(BARE_TOKEN_CANDIDATE, (token) =>
    isHighEntropyToken(token) ? REDACTED : token,
  );
}

function redactValue(value: unknown, seen: WeakSet<object>, depth: number): unknown {
  // Fail-closed, like every other decision in this file: past the recursion
  // bound emit the marker, never the caller's value. Returning the raw subtree
  // here made the depth limit a secret-shaped hole — the inputs that exceed
  // eight levels (wrapped driver errors, nested config) are the ones worth
  // worrying about.
  if (depth > MAX_REDACT_DEPTH) return MAX_DEPTH_MARKER;
  if (value instanceof Error) {
    // `stack` repeats `message` and can carry formatter-injected argument
    // values; `message` itself is where drivers and crypto quote the offending
    // input. Both go through the same never-log rules as a field name would.
    return {
      type: value.name,
      message: scrubText(value.message),
      stack: value.stack === undefined ? undefined : scrubText(value.stack),
    };
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
  // Free text held in an ordinarily-named field — a formatted cause, a driver
  // message someone copied into `detail` — carries assignments no field-name
  // rule can see. Scrub it here, before the caller serializes: that is what
  // makes the emitted JSON both clean and parseable, because nobody has to run
  // a text pattern across the serialized line afterwards.
  if (typeof value === "string") return scrubText(value);
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
 * Fail-closed census: return the paths of values this scan will not certify —
 * a secret-classed key that is not REDACTED, or a subtree the redactor stopped
 * at (MAX_DEPTH_MARKER), which was never inspected at all.
 *
 * Depth-unlimited by design. Sharing MAX_REDACT_DEPTH with the redactor made
 * the census blind over exactly the range the redactor leaked, so the two
 * defects cancelled each other's detection and the assertion came back green.
 * Cycles are handled by `seen` instead; arrays are walked as index-keyed
 * objects, so `rows.0.private_key` is reachable.
 */
export function findUnredactedSecretKeys(
  fields: Record<string, unknown>,
  seen: WeakSet<object> = new WeakSet(),
): string[] {
  const hits: string[] = [];
  for (const [key, value] of Object.entries(fields)) {
    const name = normalizeKey(key);
    if (isNeverLog(name) && value !== REDACTED) {
      hits.push(key);
    }
    if (value === MAX_DEPTH_MARKER) {
      hits.push(key);
      continue;
    }
    if (value !== null && typeof value === "object") {
      if (seen.has(value)) continue;
      seen.add(value);
      hits.push(
        ...findUnredactedSecretKeys(value as Record<string, unknown>, seen).map(
          (k) => `${key}.${k}`,
        ),
      );
      seen.delete(value);
    }
  }
  return hits;
}

/**
 * Backup/export dump scan: assert no plaintext secret-class keys appear under root.
 * Ciphertext under truncateKind fields is allowed in truncated form only after redact.
 *
 * A dump nested past MAX_REDACT_DEPTH is refused rather than passed: the
 * redactor stopped there, so no evidence exists either way, and certifying
 * bytes that were never read is the green assertion this census exists to
 * prevent. Flatten the dump or raise MAX_REDACT_DEPTH deliberately.
 */
export function assertDumpSecretFree(dump: Record<string, unknown>): void {
  const redacted = redactLogFields(dump);
  const leaks = findUnredactedSecretKeys(redacted);
  if (leaks.length > 0) {
    throw new Error(`dump failed the secret census (uncensored or uninspected): ${leaks.join(",")}`);
  }
}

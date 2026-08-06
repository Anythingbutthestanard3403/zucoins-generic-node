/**
 * HTTP + authorization surface fuzzer: INDEPENDENT REFERENCE ORACLES.
 *
 * Each oracle is a small, obviously-correct REFERENCE implementation of the
 * documented behaviour the suite is verifying — the EXPECTATION set the product
 * code is measured against, never a re-export of it. The anti-tautology proof
 * (http-auth-fuzz-oracle-selfcheck.test.ts) red-goes every oracle so a verdict
 * that cannot fail cannot be trusted.
 *
 * matrix, SHA-256 hash-at-rest), no test-mode keys. The frozen ERROR_CODES
 * enum is the contract the envelope oracle checks conformance against (reached by
 * relative source import so the suite has no built-dist dependency).
 *
 * Deterministic: pinned seed + numRuns, no Date.now()/Math.random() in generated
 * values. TEST-ONLY.
 */
import { createHash } from "node:crypto";

// Frozen error-code → http-status vocabulary for the v1-compatible HTTP error
// envelope. Inlined committed fixture: additive-only, never change an existing
// code's http value. The envelope oracle below fails any response whose code is
// outside this enum or whose status disagrees with the code's frozen mapping.
export const ERROR_CODES = [
  { code: "validation_error", http: 400 },
  { code: "code_malformed", http: 400 },
  { code: "invalid_api_key", http: 401 },
  { code: "invalid_reporting_key", http: 401 },
  { code: "invalid_credentials", http: 401 },
  { code: "totp_required", http: 401 },
  { code: "totp_invalid", http: 401 },
  { code: "challenge_invalid", http: 401 },
  { code: "pool_exhausted_hard", http: 402 },
  { code: "insufficient_treasury_balance", http: 402 },
  { code: "password_change_required", http: 403 },
  { code: "session_not_found", http: 404 },
  { code: "wallet_not_found", http: 404 },
  { code: "not_found", http: 404 },
  { code: "invalid_token", http: 404 },
  { code: "idempotency_conflict", http: 409 },
  { code: "session_not_open", http: 409 },
  { code: "session_not_cancellable", http: 409 },
  { code: "session_still_open", http: 409 },
  { code: "treasury_busy", http: 409 },
  { code: "sweep_not_retryable", http: 409 },
  { code: "node_not_registered", http: 409 },
  { code: "slug_taken", http: 409 },
  { code: "cannot_reduce_below_floor", http: 409 },
  { code: "delivery_not_replayable", http: 409 },
  { code: "session_expired", http: 410 },
  { code: "payload_too_large", http: 413 },
  { code: "amount_out_of_bounds", http: 422 },
  { code: "amount_mismatch", http: 422 },
  { code: "session_ref_mismatch", http: 422 },
  { code: "receiver_mismatch", http: 422 },
  { code: "chain_link_invalid", http: 422 },
  { code: "backup_invalid", http: 422 },
  { code: "vault_plaintext_rejected", http: 422 },
  { code: "node_discovery_invalid", http: 422 },
  { code: "account_locked", http: 423 },
  { code: "rate_limited", http: 429 },
  { code: "internal_error", http: 500 },
  { code: "consolidation_not_landed", http: 500 },
  { code: "consolidation_unconfirmed", http: 500 },
  { code: "gateway_unreachable", http: 503 },
  { code: "node_halted", http: 503 },
] as const satisfies readonly { code: string; http: number }[];

export type ErrorCode = (typeof ERROR_CODES)[number]["code"];

// ---------------------------------------------------------------------------
// Determinism knobs — committed literals. Every fc.assert cites these.
// ---------------------------------------------------------------------------
export const FUZZ_SEED = 0xa383f1 as const;
export const FUZZ_NUM_RUNS = 500 as const;

// ---------------------------------------------------------------------------
// Documented rate-limit model: 5 failures in a rolling 15-min
// window lock the (IP, username) pair for a flat 15 min — no escalation.
// ---------------------------------------------------------------------------
export const DOCUMENTED_LOCK_THRESHOLD = 5 as const;
export const DOCUMENTED_LOCK_WINDOW_MS = 15 * 60 * 1000;
export const DOCUMENTED_LOCK_DURATION_MS = 15 * 60 * 1000;

// ---------------------------------------------------------------------------
// Documented key-scheme prefixes. SITE shares `sk_` with the
// site-key-auth middleware; REPORTING/ACTION hash-at-rest with SHA-256.
// ---------------------------------------------------------------------------
export type DocumentedKind = "SITE" | "REPORTING" | "ACTION";

export const DOCUMENTED_SCHEME_PREFIX: Readonly<Record<DocumentedKind, string>> = Object.freeze({
  SITE: "sk_",
  REPORTING: "rk_",
  ACTION: "ak_",
});

/** A stored candidate key, modelled at the granularity the verifier sees after
 *  its prefix lookup + active-filter: identity, kind, non-secret prefix, hash. */
export interface ReferenceCandidate {
  id: string;
  kind: DocumentedKind;
  keyPrefix: string;
  keyHash: string;
}

// ---------------------------------------------------------------------------
// Scheme classification — exact prefix, no case fold.
// ---------------------------------------------------------------------------
export function referenceKindForToken(token: string): DocumentedKind | null {
  if (token.startsWith(DOCUMENTED_SCHEME_PREFIX.SITE)) return "SITE";
  if (token.startsWith(DOCUMENTED_SCHEME_PREFIX.REPORTING)) return "REPORTING";
  if (token.startsWith(DOCUMENTED_SCHEME_PREFIX.ACTION)) return "ACTION";
  return null;
}

/** Non-secret lookup prefix: the first 15 bytes (the API reference / A.8). */
export function referenceLookupPrefix(token: string): string {
  return token.slice(0, 15);
}

/** SHA-256 hex digest — the REPORTING/ACTION hash-at-rest. */
export function referenceSha256Hex(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/** No test-mode key variants: `<scheme>test_…` is refused before any DB
 *  statement. Mirrors the product's exact `${prefix}test_` guard. */
export function isDocumentedTestKey(token: string): boolean {
  for (const prefix of Object.values(DOCUMENTED_SCHEME_PREFIX)) {
    if (token.startsWith(`${prefix}test_`)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Authentication + scope. Authenticate first, then authorize: a
// real-but-wrong-scope key is denied identically to an unknown key (no scope
// oracle). Fails CLOSED (null) for unclassifiable and test-mode tokens before
// any candidate is consulted. Models the SHA-256 (REPORTING/ACTION) surface; the
// SITE/bcrypt branch is exercised against the real product in the negatives suite.
// ---------------------------------------------------------------------------
export function referenceAuthenticate(
  token: string,
  candidates: readonly ReferenceCandidate[],
): ReferenceCandidate | null {
  const kind = referenceKindForToken(token);
  if (kind === null) return null; // unclassifiable → fail closed
  if (isDocumentedTestKey(token)) return null; // documented test key → fail closed before DB
  const prefix = referenceLookupPrefix(token);
  const digest = referenceSha256Hex(token);
  for (const candidate of candidates) {
    if (candidate.keyPrefix === prefix && candidate.keyHash === digest) return candidate;
  }
  return null;
}

/** Scope matrix: a key's kind must be among the surface's allowed
 *  kinds. null kind (unauthenticated) is never allowed. */
export function referenceScopeAllows(
  kind: DocumentedKind | null,
  allowed: readonly DocumentedKind[],
): boolean {
  return kind !== null && allowed.includes(kind);
}

// ---------------------------------------------------------------------------
// ReferenceLockout — executable spec of the documented flat per-(IP, username)
// model. The clock is injected (nowMs) so the suite can drive it
// step-for-step against the real in-memory module under a faked clock. Username
// is lower-cased and a missing IP collapses to one sentinel bucket; a tripped
// pair is never re-counted (flat lock, no escalation); after the window elapses
// the counter is forgotten.
// ---------------------------------------------------------------------------
interface RefWindow {
  count: number;
  windowStartMs: number;
  lockedUntilMs: number | null;
}

export class ReferenceLockout {
  readonly #windows = new Map<string, RefWindow>();

  #key(ip: string | null, username: string): string {
    return `${ip ?? "unknown"}|${username.toLowerCase()}`;
  }

  registerFailure(ip: string | null, username: string, nowMs: number): { tripped: boolean; count: number } {
    const key = this.#key(ip, username);
    const entry = this.#windows.get(key);

    // An active lock is a no-op trip: the pair stays locked and the counter is
    // not advanced (flat lock — never escalated by further failures).
    if (entry?.lockedUntilMs != null && entry.lockedUntilMs > nowMs) {
      return { tripped: true, count: entry.count };
    }

    if (!entry || nowMs - entry.windowStartMs >= DOCUMENTED_LOCK_WINDOW_MS) {
      // First failure, or the prior window (incl. any expired lock) has fully
      // elapsed → a fresh flat window; the prior count is forgotten.
      const tripped = DOCUMENTED_LOCK_THRESHOLD <= 1;
      this.#windows.set(key, {
        count: 1,
        windowStartMs: nowMs,
        lockedUntilMs: tripped ? nowMs + DOCUMENTED_LOCK_DURATION_MS : null,
      });
      return { tripped, count: 1 };
    }

    entry.count += 1;
    const tripped = entry.count >= DOCUMENTED_LOCK_THRESHOLD;
    if (tripped && entry.lockedUntilMs == null) {
      entry.lockedUntilMs = nowMs + DOCUMENTED_LOCK_DURATION_MS;
    }
    return { tripped, count: entry.count };
  }

  isLocked(ip: string | null, username: string, nowMs: number): boolean {
    const entry = this.#windows.get(this.#key(ip, username));
    return entry?.lockedUntilMs != null && entry.lockedUntilMs > nowMs;
  }

  clear(ip: string | null, username: string): void {
    this.#windows.delete(this.#key(ip, username));
  }
}

// ---------------------------------------------------------------------------
// Request-shape oracles — the documented login / confirm-TOTP shapes
// the real Zod schemas must accept exactly (strict: unknown keys reject).
// ---------------------------------------------------------------------------
const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** loginSchema: `{ username: 1–256, password: 1–1024, totp?: ≤16 }`, strict. */
export function referenceLoginValid(value: unknown): boolean {
  if (!isPlainObject(value)) return false;
  const keys = Object.keys(value);
  for (const key of keys) {
    if (key !== "username" && key !== "password" && key !== "totp") return false;
  }
  const { username, password, totp } = value;
  if (typeof username !== "string" || username.length < 1 || username.length > 256) return false;
  if (typeof password !== "string" || password.length < 1 || password.length > 1024) return false;
  if (totp !== undefined && (typeof totp !== "string" || totp.length > 16)) return false;
  return true;
}

/** confirmTotpSchema: `{ totp: /^\d{6}$/ }`, strict — exactly one six-digit code. */
export function referenceConfirmTotpValid(value: unknown): boolean {
  if (!isPlainObject(value)) return false;
  const keys = Object.keys(value);
  if (keys.length !== 1 || keys[0] !== "totp") return false;
  return typeof value.totp === "string" && /^\d{6}$/.test(value.totp);
}

// ---------------------------------------------------------------------------
// Error-envelope oracle: `{ error: { code, message, param?,
// request_id, doc_url } }` with `code` ∈ the frozen ERROR_CODES enum and the http
// status matching the code's frozen mapping. Throws on any contract violation.
// ---------------------------------------------------------------------------
const CODE_HTTP: ReadonlyMap<string, number> = new Map(
  ERROR_CODES.map((entry) => [entry.code, entry.http]),
);

export function assertEnvelopeContract(body: unknown, http?: number): void {
  const error = (body as { error?: unknown } | null)?.error;
  if (!isPlainObject(error)) {
    throw new Error("envelope contract violation: missing error object");
  }
  const { code, message, request_id, doc_url } = error as Record<string, unknown>;
  if (typeof code !== "string" || !CODE_HTTP.has(code)) {
    throw new Error(`envelope contract violation: code ${String(code)} outside the frozen enum`);
  }
  if (typeof message !== "string") {
    throw new Error("envelope contract violation: missing message");
  }
  if (typeof request_id !== "string") {
    throw new Error("envelope contract violation: missing request_id");
  }
  if (typeof doc_url !== "string") {
    throw new Error("envelope contract violation: missing doc_url");
  }
  if ("param" in error && typeof (error as { param?: unknown }).param !== "string") {
    throw new Error("envelope contract violation: param must be a string when present");
  }
  if (http !== undefined) {
    const expected = CODE_HTTP.get(code as ErrorCode)!;
    if (http !== expected) {
      throw new Error(
        `envelope contract violation: http status ${http} does not match code ${code} (expected ${expected})`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Secret-leak scanner — runs over anything fast-check may serialize on failure
// (bearer tokens, lockout actions, envelopes). Key-aware: a secret-shaped FIELD
// NAME (totp/password/csrf/…) or an overlong opaque value (a base64 key/preimage)
// fails closed. Generated fuzz objects carry only short opaque ids and the
// envelope's known-safe fields, so this always passes = regression guard.
// ---------------------------------------------------------------------------
const SECRET_KEY =
  /totp|password|passwd|csrf|\bsecret\b|private_?key|seed_?byte|\bseed\b|preimage|mnemonic|credential|signing_?key|api_?key_?plain/i;
const HARD_SECRET_VALUE = /-----BEGIN|PRIVATE KEY/i;
const OVERLONG_VALUE = 128;

function scanString(value: string): void {
  if (HARD_SECRET_VALUE.test(value)) {
    throw new Error("secret-shaped value reachable in serialized fuzz object");
  }
  if (value.length >= OVERLONG_VALUE) {
    throw new Error(`overlong (${value.length}-char) string reachable — possible key/preimage leak`);
  }
}

function scan(value: unknown): void {
  if (typeof value === "string") {
    scanString(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) scan(item);
    return;
  }
  if (isPlainObject(value)) {
    for (const [key, item] of Object.entries(value)) {
      if (SECRET_KEY.test(key)) {
        throw new Error(`secret-shaped field "${key}" reachable in serialized fuzz object`);
      }
      scan(item);
    }
  }
}

export function assertNoSecretLeak(value: unknown): void {
  scan(value);
}

/**
 * HTTP + authorization surface fuzzer: ACTION ALPHABET + drivers.
 *
 * Drives the relocated node-core auth SUT (test/auth-sut + src/http/ip-lockout)
 * with no database and no network — no frozen apps/node imports :
 *   - the bearer/scope decision (verifyApiKey + authenticateApiKey) runs against
 *     a fake drizzle handle that returns a fixed active-key store and records
 *     every statement, so the fail-closed-before-DB and no-update-on-reject
 *     postures are observable;
 *   - the context gates (requireCsrf / requireTotpConfirmed /
 *     requirePasswordChanged / requireCsrfUnlessActionKey) run against a minimal
 *     Context stub — only Hono plumbing is stubbed, the decision logic is real;
 *   - the rate limiter (ip-lockout) is the real in-memory module under a faked
 *     clock, compared step-for-step with the ReferenceLockout executable spec.
 *
 * SITE keys use bcrypt (async, ~10^2 ms); the hot store is ACTION+REPORTING
 * (SHA-256, fast). The SITE bcrypt path is exercised once in the negatives suite.
 *
 * TEST-ONLY. No Date.now()/Math.random() in generated values; tokens are built
 * deterministically and the clock is injected.
 */
import fc from "fast-check";

import {
  ACTION_KEY_KINDS,
  clearIpFailures,
  confirmTotpSchema,
  isIpPairLocked,
  kindForToken,
  loginSchema,
  lookupPrefix,
  registerIpFailure,
  requireCsrf,
  requireCsrfUnlessActionKey,
  requirePasswordChanged,
  requireTotpConfirmed,
  sha256Hex,
  verifyApiKey,
  _resetIpLockoutForTests,
  type GateContext,
  type GateHandler,
} from "./auth-sut/index.js";
import {
  DOCUMENTED_SCHEME_PREFIX,
  DOCUMENTED_LOCK_WINDOW_MS,
  referenceAuthenticate,
  referenceKindForToken,
  referenceScopeAllows,
  type DocumentedKind,
  type ReferenceCandidate,
} from "./http-auth-fuzz-oracles.js";

// ---------------------------------------------------------------------------
// Minimal Context stub — implements only the surface the gates touch.
// ---------------------------------------------------------------------------
export interface CtxRecord {
  json?: { body: unknown; status: number };
  nextCalled: boolean;
}

export interface StubCtx {
  c: unknown;
  next: () => Promise<void>;
  recorded: CtxRecord;
  vars: Map<string, unknown>;
}

export function makeCtx(
  headers: Record<string, string | undefined>,
  vars: Record<string, unknown>,
): StubCtx {
  const store = new Map(Object.entries(vars));
  const hmap = new Map(
    Object.entries(headers)
      .filter(([, v]) => v !== undefined)
      .map(([k, v]) => [k.toLowerCase(), v as string]),
  );
  const recorded: CtxRecord = { nextCalled: false };
  const c = {
    req: { header: (n: string) => hmap.get(n.toLowerCase()) },
    get: (k: string) => store.get(k),
    set: (k: string, v: unknown) => {
      store.set(k, v);
    },
    json: (body: unknown, status = 200) => {
      recorded.json = { body, status };
      return { body, status };
    },
  };
  const next = async () => {
    recorded.nextCalled = true;
  };
  return { c, next, recorded, vars: store };
}

// ---------------------------------------------------------------------------
// Fake drizzle handle for authenticateApiKey / verifyApiKey. Returns a fixed
// active-key store (modelling the post-filter candidate set) and counts
// statements so the fail-closed-before-DB posture is observable.
// ---------------------------------------------------------------------------
export interface DbSpy {
  selects: number;
  updates: number;
}

export interface StoredKey {
  id: string;
  kind: DocumentedKind;
  token: string;
  keyPrefix: string;
  keyHash: string;
}

export function fakeDb(rows: readonly { id: string; kind: string; keyHash: string }[], spy: DbSpy) {
  return {
    select: () => {
      spy.selects += 1;
      return { from: () => ({ where: () => Promise.resolve(rows) }) };
    },
    update: () => ({
      set: () => ({
        where: () => {
          spy.updates += 1;
          return Promise.resolve();
        },
      }),
    }),
  };
}

// ---------------------------------------------------------------------------
// Deterministic key fixtures. The hot store is ACTION + REPORTING (SHA-256).
// ---------------------------------------------------------------------------
export function actionKey(token: string, id = "key-action"): StoredKey {
  return { id, kind: "ACTION", token, keyPrefix: token.slice(0, 15), keyHash: sha256Hex(token) };
}
export function reportingKey(token: string, id = "key-reporting"): StoredKey {
  return { id, kind: "REPORTING", token, keyPrefix: token.slice(0, 15), keyHash: sha256Hex(token) };
}

export const STORE_ACTION_TOKEN = `${DOCUMENTED_SCHEME_PREFIX.ACTION}${"A".repeat(40)}`;
export const STORE_REPORTING_TOKEN = `${DOCUMENTED_SCHEME_PREFIX.REPORTING}${"R".repeat(40)}`;
export const HOT_STORE: readonly StoredKey[] = [
  actionKey(STORE_ACTION_TOKEN),
  reportingKey(STORE_REPORTING_TOKEN),
];

const toCandidate = (k: StoredKey): ReferenceCandidate => ({
  id: k.id,
  kind: k.kind,
  keyPrefix: k.keyPrefix,
  keyHash: k.keyHash,
});

// ---------------------------------------------------------------------------
// verifyApiKey driver — presents an Authorization header to the real middleware
// over the fake store; returns the decision + statement spy.
// ---------------------------------------------------------------------------
export interface VerifyResult {
  status: number | undefined;
  body: unknown;
  nextCalled: boolean;
  apiKeyKind: unknown;
  spy: DbSpy;
}

export async function driveVerifyApiKey(
  headerValue: string | undefined,
  store: readonly StoredKey[] = HOT_STORE,
): Promise<VerifyResult> {
  const spy: DbSpy = { selects: 0, updates: 0 };
  const db = fakeDb(
    store.map(({ id, kind, keyHash }) => ({ id, kind, keyHash })),
    spy,
  );
  const ctx = makeCtx({ authorization: headerValue }, {});
  const mw: GateHandler = verifyApiKey(db, ACTION_KEY_KINDS);
  await mw(ctx.c as GateContext, ctx.next);
  return {
    status: ctx.recorded.json?.status,
    body: ctx.recorded.json?.body,
    nextCalled: ctx.recorded.nextCalled,
    apiKeyKind: ctx.vars.get("apiKeyKind"),
    spy,
  };
}

/** The reference decision for a presented token over the same store. `kind` is
 *  the token's classified scheme kind (independent of authentication) so the
 *  suite can assert the fail-closed-before-DB posture for unclassifiable /
 *  test-mode tokens. */
export function referenceVerifyDecision(
  presentedToken: string,
  store: readonly StoredKey[] = HOT_STORE,
): { authenticates: boolean; kind: DocumentedKind | null } {
  const kind = referenceKindForToken(presentedToken);
  const authed = referenceAuthenticate(presentedToken, store.map(toCandidate));
  const allowed = referenceScopeAllows(authed?.kind ?? null, ["ACTION"]);
  return { authenticates: authed !== null && allowed, kind };
}

// ---------------------------------------------------------------------------
// Context-gate drivers (no DB).
// ---------------------------------------------------------------------------
export async function driveCsrfGate(provided: string | undefined, expected: string) {
  const ctx = makeCtx({ "x-csrf-token": provided }, { sessionCsrfToken: expected });
  await requireCsrf()(ctx.c as GateContext, ctx.next);
  return ctx.recorded;
}

export async function driveCsrfUnlessActionKey(
  authMode: string | undefined,
  provided: string | undefined,
  expected: string,
) {
  const ctx = makeCtx(
    { "x-csrf-token": provided },
    { authMode, sessionCsrfToken: expected },
  );
  await requireCsrfUnlessActionKey()(ctx.c as GateContext, ctx.next);
  return ctx.recorded;
}

export async function driveTotpGate(mustEnrolTotp: boolean) {
  const ctx = makeCtx({}, { authUser: { id: "u", role: "admin", mustEnrolTotp, mustChangePassword: false } });
  await requireTotpConfirmed()(ctx.c as GateContext, ctx.next);
  return ctx.recorded;
}

export async function drivePasswordGate(mustChangePassword: boolean) {
  const ctx = makeCtx({}, { authUser: { id: "u", role: "admin", mustEnrolTotp: false, mustChangePassword } });
  await requirePasswordChanged()(ctx.c as GateContext, ctx.next);
  return ctx.recorded;
}

// ---------------------------------------------------------------------------
// Rate-limiter driver — resets the real module's global state, then applies one
// action under the injected clock. The reference runs in lockstep.
// ---------------------------------------------------------------------------
export type LockoutOp = "fail" | "check" | "clear";
export interface LockoutAction {
  ip: string | null;
  username: string;
  op: LockoutOp;
  advanceMs: number;
}

export const IP_ARBITRARY: fc.Arbitrary<string | null> = fc.oneof(
  fc.constant(null),
  fc.constantFrom("10.0.0.1", "10.0.0.2", "192.168.1.9"),
);

// Mixed-case usernames exercise the documented lower-case fold.
export const USERNAME_ARBITRARY: fc.Arbitrary<string> = fc.constantFrom(
  "admin",
  "Admin",
  "ADMIN",
  "operator",
  "Operator",
);

export const lockoutActionArb: fc.Arbitrary<LockoutAction> = fc.record({
  ip: IP_ARBITRARY,
  username: USERNAME_ARBITRARY,
  op: fc.constantFrom<LockoutOp>("fail", "check", "clear"),
  // Advances that straddle the 15-min window boundary are the interesting case.
  advanceMs: fc.oneof(
    fc.integer({ min: 0, max: 1000 }),
    fc.integer({ min: 14 * 60 * 1000, max: 16 * 60 * 1000 }),
    fc.integer({ min: 30 * 60 * 1000, max: 60 * 60 * 1000 }),
  ),
});

/** Deterministic sequence guaranteeing the lockout coverage floor: five in-window
 *  failures on one null-IP, mixed-case username bucket (trips the flat lock and
 *  exercises the case fold + null-IP sentinel), then a check past the window
 *  (exercises window expiry / counter reset). */
export const LOCKOUT_TRIP_ACTIONS: readonly LockoutAction[] = [
  { ip: null, username: "Admin", op: "fail", advanceMs: 100 },
  { ip: null, username: "admin", op: "fail", advanceMs: 100 },
  { ip: null, username: "ADMIN", op: "fail", advanceMs: 100 },
  { ip: null, username: "Admin", op: "fail", advanceMs: 100 },
  { ip: null, username: "admin", op: "fail", advanceMs: 100 },
  { ip: null, username: "admin", op: "check", advanceMs: DOCUMENTED_LOCK_WINDOW_MS + 1000 },
];

export interface LockoutStepObservation {
  op: LockoutOp;
  ip: string | null;
  username: string;
  nowMs: number;
  real: { tripped?: boolean; count?: number; locked: boolean };
  ref: { tripped?: boolean; count?: number; locked: boolean };
}

// ---------------------------------------------------------------------------
// Arbitraries — bearer grammar, token bodies, JSON shapes, login inputs.
// ---------------------------------------------------------------------------
const BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const tokenBodyArb = fc.string({
  unit: fc.constantFrom(...BASE64URL.split("")),
  minLength: 1,
  maxLength: 64,
});

/** A scheme-prefixed token whose kind ranges over ACTION/REPORTING/SITE/unknown. */
export const bearerTokenArb: fc.Arbitrary<string> = fc.oneof(
  tokenBodyArb.map((b) => `${DOCUMENTED_SCHEME_PREFIX.ACTION}${b}`),
  tokenBodyArb.map((b) => `${DOCUMENTED_SCHEME_PREFIX.REPORTING}${b}`),
  tokenBodyArb.map((b) => `${DOCUMENTED_SCHEME_PREFIX.SITE}${b}`),
  tokenBodyArb.map((b) => `xx_${b}`), // unknown scheme
  tokenBodyArb.map((b) => `${DOCUMENTED_SCHEME_PREFIX.ACTION}test_${b}`), // test_-prefixed key
  tokenBodyArb.map((b) => `${DOCUMENTED_SCHEME_PREFIX.REPORTING}test_${b}`),
  fc.constant(""), // empty token
);

/** Well-formed `Bearer <token>` headers — the presented token is unambiguous.
 *  Explicit constants guarantee the coverage cases (valid ACTION auth, wrong
 *  scope, test-mode key, unknown key) fire on every run; the grammar variants
 *  add breadth. */
const NON_STORED_ACTION_TOKEN = `${DOCUMENTED_SCHEME_PREFIX.ACTION}${"Z".repeat(40)}`;
const TEST_ACTION_TOKEN = `${DOCUMENTED_SCHEME_PREFIX.ACTION}test_${"x".repeat(20)}`;

export const wellFormedBearerArb: fc.Arbitrary<{ header: string; token: string }> = fc.oneof(
  // Coverage constants.
  fc.constant({ header: `Bearer ${STORE_ACTION_TOKEN}`, token: STORE_ACTION_TOKEN }),
  fc.constant({ header: `Bearer ${STORE_REPORTING_TOKEN}`, token: STORE_REPORTING_TOKEN }),
  fc.constant({ header: `Bearer ${TEST_ACTION_TOKEN}`, token: TEST_ACTION_TOKEN }),
  fc.constant({ header: `Bearer ${NON_STORED_ACTION_TOKEN}`, token: NON_STORED_ACTION_TOKEN }),
  // Grammar breadth.
  bearerTokenArb.map((t) => ({ header: `Bearer ${t}`, token: t })),
  bearerTokenArb.map((t) => ({ header: `Bearer  ${t}`, token: t })), // multiple spaces
  bearerTokenArb.map((t) => ({ header: `Bearer\t${t}`, token: t })), // tab separator
  bearerTokenArb.map((t) => ({ header: `Bearer ${t} `, token: t })), // trailing space (trimmed)
);

/** Headers that are NOT the documented `Bearer <token>` grammar. */
export const malformedHeaderArb: fc.Arbitrary<string> = fc.oneof(
  tokenBodyArb.map((b) => `bearer ${b}`), // wrong case
  tokenBodyArb.map((b) => `Basic ${b}`), // wrong scheme
  tokenBodyArb.map((b) => b), // bare token, no scheme
  fc.constant("Bearer"), // scheme only
  fc.constant("Bearer "), // scheme + space, no token
  tokenBodyArb.map((b) => `Bearer${b}`), // no separator
  fc.constant(""),
);

/** Arbitrary JSON-ish values for content-type / shape confusion. */
export const jsonValueArb: fc.Arbitrary<unknown> = fc.oneof(
  fc.constant(null),
  fc.boolean(),
  fc.integer(),
  fc.double({ noNaN: true }),
  fc.string(),
  fc.constant([]),
  fc.array(fc.integer(), { maxLength: 3 }),
  fc.record({ username: fc.string(), password: fc.string() }),
  fc.record({ username: fc.integer(), password: fc.string() }), // wrong field type
  fc.record({ username: fc.string(), password: fc.string(), extra: fc.string() }), // extra key
  fc.record({
    username: fc.string({ minLength: 1, maxLength: 300 }),
    password: fc.string({ minLength: 1, maxLength: 1100 }),
  }),
  fc.record({ username: fc.string(), password: fc.string(), totp: fc.string({ maxLength: 20 }) }),
);

/** Login bodies spanning valid and invalid shapes (drives the real Zod schema). */
export const loginInputArb: fc.Arbitrary<unknown> = fc.oneof(
  fc.record({
    username: fc.string({ minLength: 1, maxLength: 256 }),
    password: fc.string({ minLength: 1, maxLength: 1024 }),
  }),
  fc.record({
    username: fc.string({ minLength: 1, maxLength: 256 }),
    password: fc.string({ minLength: 1, maxLength: 1024 }),
    totp: fc.string({ maxLength: 16 }),
  }),
  jsonValueArb,
);

// ---------------------------------------------------------------------------
// Real-schema drivers (pure Zod).
// ---------------------------------------------------------------------------
export const driveLoginSchema = (value: unknown) => loginSchema.safeParse(value).success;
export const driveConfirmTotpSchema = (value: unknown) => confirmTotpSchema.safeParse(value).success;

// Re-exports the suites use directly.
export {
  kindForToken,
  lookupPrefix,
  sha256Hex,
  registerIpFailure,
  isIpPairLocked,
  clearIpFailures,
  _resetIpLockoutForTests,
};

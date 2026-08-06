// Structural operation-route authentication composition.
//
// Production must never mount the money-path operation surface with always-true
// authenticate/authorizeScope hooks. Auth bindings and fail-closed stores are
// registered by identity in module-private WeakSets at factory construction
// only the factory return values pass is*/assert*. Spread-copies (even with a
// stolen enumerable bit) are not in the set and are refused. createOperationRouter
// refuses any unregistered pair and refuses a live store paired with reject-all
// auth. Sequencing is load-bearing: a real OperationRouteStore may only ride with
// a concrete tenant-bound implementer-bearer authenticator.
//
// 15.
// createImplementerBearerAuth (static key set) and
// createImplementerBearerAuthFromService (CredentialService / sql-store path)
// both produce the implementer_bearer kind that may ride with a live store.
// Production main mounts the service-backed binder so unauthenticated /v1 is
// 401 before any future money-opening store can.

import { createHash, timingSafeEqual } from "node:crypto";

import type { PipelineConfig, PipelineRequest } from "./pipeline.js";
import type { OperationRouteStore } from "./routes/operation-routes.js";
import {
  credentialResolverFromService,
  extractImplementerBearer,
  type AuthPrincipal,
  type CredentialResolver,
  type CredentialValidationService,
} from "./tenant-middleware.js";

// Identity registries — not copyable via spread / getOwnPropertySymbols.
const issuedOperationAuthBindings = new WeakSet<object>();
const issuedFailClosedOperationStores = new WeakSet<object>();

// Compile-time nominal marks only. Never placed on runtime objects (enumerable
// Symbol brands were stealable via `{...factory, authenticate: => true }`).
declare const operationAuthBrand: unique symbol;
declare const failClosedStoreBrand: unique symbol;

export class OperationRouterCompositionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OperationRouterCompositionError";
  }
}

export type OperationAuthKind = "reject_all" | "implementer_bearer";

type Authenticate = PipelineConfig["authenticate"];
type AuthorizeScope = PipelineConfig["authorizeScope"];

interface BrandedOperationAuthBase {
  readonly kind: OperationAuthKind;
  readonly authenticate: Authenticate;
  readonly authorizeScope: AuthorizeScope;
  readonly [operationAuthBrand]: true;
}

/** Reject every caller — safe default while the operation engine is unwired. */
export interface RejectAllOperationAuth extends BrandedOperationAuthBase {
  readonly kind: "reject_all";
}

/**
 * Concrete implementer-bearer authenticator: tenant-bound key lookup,
 * revocation, and per-scope authorization. The only auth kind permitted to
 * coexist with a live (non-fail-closed) OperationRouteStore.
 */
export interface ImplementerBearerOperationAuth extends BrandedOperationAuthBase {
  readonly kind: "implementer_bearer";
  /**
   * Credential resolver that binds AuthPrincipal into PipelineContext via
   * runValidationPipeline's resolveCredential hook. Production
   * createOperationRouter installs this — legacy boolean hooks alone never
   * write principal / idempotencyTenantId.
   */
  readonly resolveCredential: CredentialResolver;
}

export type OperationAuthBinding = RejectAllOperationAuth | ImplementerBearerOperationAuth;

export interface FailClosedOperationStore extends OperationRouteStore {
  readonly [failClosedStoreBrand]: true;
}

export function isOperationAuthBinding(value: unknown): value is OperationAuthBinding {
  if (value === null || typeof value !== "object") return false;
  if (!issuedOperationAuthBindings.has(value)) return false;
  const candidate = value as OperationAuthBinding;
  if (typeof candidate.authenticate !== "function" || typeof candidate.authorizeScope !== "function") {
    return false;
  }
  if (candidate.kind === "reject_all") return true;
  if (candidate.kind === "implementer_bearer") {
    const withResolver = candidate as ImplementerBearerOperationAuth;
    return (
      typeof withResolver.resolveCredential === "object" &&
      withResolver.resolveCredential !== null &&
      typeof withResolver.resolveCredential.resolve === "function"
    );
  }
  return false;
}

export function isFailClosedOperationStore(
  store: OperationRouteStore,
): store is FailClosedOperationStore {
  return (
    store !== null &&
    typeof store === "object" &&
    issuedFailClosedOperationStores.has(store)
  );
}

/**
 * Fail-closed OperationRouteStore: every method rejects. Identity registration
 * marks it so the router may pair it with reject-all auth (auth fails first →
 * 401; store is unreachable for money). A plain object store is treated as live.
 */
export function createFailClosedOperationStore(): FailClosedOperationStore {
  const reject = (): Promise<never> =>
    Promise.reject(new Error("operation engine store is not yet wired — fail-closed"));
  const store = Object.freeze({
    createReceive: reject,
    getReceive: reject,
    createInternalMove: reject,
    getInternalMove: reject,
    createExternalSend: reject,
    getExternalSend: reject,
  });
  issuedFailClosedOperationStores.add(store);
  return store as unknown as FailClosedOperationStore;
}

/** Always-deny authenticator. Safe with a fail-closed store; refused with a live store. */
export function createRejectAllOperationAuth(): RejectAllOperationAuth {
  const auth = Object.freeze({
    kind: "reject_all" as const,
    authenticate: (): boolean => false,
    authorizeScope: (): boolean => false,
  });
  issuedOperationAuthBindings.add(auth);
  return auth as unknown as RejectAllOperationAuth;
}

/** One enrolled implementer bearer key. Plaintext is never logged. */
export interface ImplementerBearerKey {
  /** Full bearer token including the `ik_` prefix. */
  readonly token: string;
  /** Tenant / implementer id bound to this key — never taken from the request body. */
  readonly implementerId: string;
  /** Granted scopes from the closed IMPLEMENTER_SCOPES vocabulary. */
  readonly scopes: readonly string[];
  /** When true the key is treated as revoked (auth fails closed). */
  readonly revoked?: boolean;
}

export interface ImplementerBearerAuthOptions {
  readonly keys: readonly ImplementerBearerKey[];
}

interface ResolvedPrincipal {
  readonly implementerId: string;
  readonly scopes: ReadonlySet<string>;
}

function sha256(text: string): Buffer {
  return createHash("sha256").update(text, "utf8").digest();
}

function parseBearerToken(authorization: string | undefined): string | null {
  if (authorization === undefined) return null;
  // Single-space Bearer grammar; anything else is malformed → unauthenticated.
  if (!authorization.startsWith("Bearer ")) return null;
  const token = authorization.slice("Bearer ".length);
  if (token.length === 0 || token.includes(" ") || /\s/.test(token)) return null;
  // implementer keys are `ik_…`.
  if (!token.startsWith("ik_")) return null;
  return token;
}

/**
 * Build a concrete tenant-bound implementer-bearer authenticator.
 * Missing / malformed / unknown / revoked credentials → authenticate false (401).
 * Present credential lacking the route scope → authorizeScope false (401; phantom 403 collapsed to 401).
 */
export function createImplementerBearerAuth(
  options: ImplementerBearerAuthOptions,
): ImplementerBearerOperationAuth {
  if (!Array.isArray(options.keys) || options.keys.length === 0) {
    throw new OperationRouterCompositionError(
      "implementer bearer auth requires at least one enrolled key",
    );
  }

  // Index by token hash so the hot path never retains plaintext beyond compare.
  const byHash = new Map<string, { hash: Buffer; principal: ResolvedPrincipal; revoked: boolean }>();
  for (const key of options.keys) {
    if (typeof key.token !== "string" || !key.token.startsWith("ik_")) {
      throw new OperationRouterCompositionError(
        "implementer bearer key token must be a non-empty ik_… string",
      );
    }
    if (typeof key.implementerId !== "string" || key.implementerId.length === 0) {
      throw new OperationRouterCompositionError(
        "implementer bearer key must bind a non-empty implementerId",
      );
    }
    if (!Array.isArray(key.scopes)) {
      throw new OperationRouterCompositionError(
        "implementer bearer key must declare a scopes array",
      );
    }
    const digest = sha256(key.token);
    byHash.set(digest.toString("hex"), {
      hash: digest,
      principal: {
        implementerId: key.implementerId,
        scopes: new Set(key.scopes),
      },
      revoked: key.revoked === true,
    });
  }

  // Shared lookup used by both the legacy boolean hooks and resolveCredential.
  // Timing-safe scan over the enrolled set; never short-circuits on first match.
  function lookupPrincipal(token: string): AuthPrincipal | null {
    const presented = sha256(token);
    let match: { principal: ResolvedPrincipal; revoked: boolean } | undefined;
    for (const entry of byHash.values()) {
      if (timingSafeEqual(presented, entry.hash)) {
        match = entry;
        // Continue scanning so compare work stays closer to constant across the set.
      }
    }
    if (match === undefined || match.revoked) return null;
    return {
      implementerId: match.principal.implementerId,
      scopes: [...match.principal.scopes],
    };
  }

  // Per-request resolved principal: authorizeScope runs in the same turn as
  // authenticate for a given request object identity (legacy boolean path).
  const resolved = new WeakMap<object, ResolvedPrincipal>();

  const authenticate: Authenticate = (request: PipelineRequest): boolean => {
    const token = parseBearerToken(request.headers["authorization"]);
    if (token === null) return false;
    const principal = lookupPrincipal(token);
    if (principal === null) return false;
    resolved.set(request, {
      implementerId: principal.implementerId,
      scopes: new Set(principal.scopes),
    });
    return true;
  };

  const authorizeScope: AuthorizeScope = (request, scope): boolean => {
    const principal = resolved.get(request);
    if (principal === undefined) return false;
    if (scope === null) return true;
    return principal.scopes.has(scope);
  };

  // Production path: bind AuthPrincipal into PipelineContext.
  const resolveCredential: CredentialResolver = {
    async resolve(bearerKey) {
      if (typeof bearerKey !== "string" || !bearerKey.startsWith("ik_")) return null;
      return lookupPrincipal(bearerKey);
    },
  };

  const auth = Object.freeze({
    kind: "implementer_bearer" as const,
    authenticate,
    authorizeScope,
    resolveCredential,
  });
  issuedOperationAuthBindings.add(auth);
  return auth as unknown as ImplementerBearerOperationAuth;
}

/**
 * Build a concrete implementer-bearer authenticator backed by CredentialService
 * (or any CredentialValidationService). Production main mounts this so /v1 uses
 * the real validate path (hash lookup, revoke/expiry/grace, phantom 403 collapsed to 401 scope
 * collapse) rather than reject-all. An empty store still 401s every caller
 * safe with the fail-closed operation store, and composition-ready for a live
 * money-opening store (implementer_bearer may pair; reject_all may not).
 */
export function createImplementerBearerAuthFromService(
  service: CredentialValidationService,
): ImplementerBearerOperationAuth {
  if (
    service === null ||
    typeof service !== "object" ||
    typeof service.validate !== "function"
  ) {
    throw new OperationRouterCompositionError(
      "implementer bearer auth from service requires a CredentialValidationService",
    );
  }

  const resolveCredential = credentialResolverFromService(service);

  // Legacy boolean hooks: same collapse as resolveCredential. Production
  // createOperationRouter installs resolveCredential and prefers that path;
  // hooks remain correct if a caller omits the resolver.
  const resolved = new WeakMap<object, AuthPrincipal>();

  const authenticate: Authenticate = async (request: PipelineRequest): Promise<boolean> => {
    const token = extractImplementerBearer(request.headers);
    if (token === null) return false;
    const principal = await resolveCredential.resolve(token);
    if (principal === null) return false;
    resolved.set(request, principal);
    return true;
  };

  const authorizeScope: AuthorizeScope = (request, scope): boolean => {
    const principal = resolved.get(request);
    if (principal === undefined) return false;
    if (scope === null) return true;
    return principal.scopes.includes(scope);
  };

  const auth = Object.freeze({
    kind: "implementer_bearer" as const,
    authenticate,
    authorizeScope,
    resolveCredential,
  });
  issuedOperationAuthBindings.add(auth);
  return auth as unknown as ImplementerBearerOperationAuth;
}

/**
 * Composition gate shared by createOperationRouter. Callers that build the
 * production listener must go through the same rule: a live store demands
 * implementer-bearer auth; reject-all may only pair with a fail-closed store.
 */
export function assertOperationAuthComposition(
  store: OperationRouteStore,
  auth: unknown,
): asserts auth is OperationAuthBinding {
  if (!isOperationAuthBinding(auth)) {
    throw new OperationRouterCompositionError(
      "operation auth must be created via createRejectAllOperationAuth, createImplementerBearerAuth, or createImplementerBearerAuthFromService — unbranded/permissive authenticate hooks are refused",
    );
  }
  const storeIsFailClosed = isFailClosedOperationStore(store);
  if (!storeIsFailClosed && auth.kind === "reject_all") {
    throw new OperationRouterCompositionError(
      "reject-all operation auth cannot coexist with a live operation store — wire createImplementerBearerAuth before mounting a real store",
    );
  }
  // reject_all + fail-closed store: OK (auth denies; store unreachable for money).
  // implementer_bearer + any store: OK (concrete tenant-bound auth).
}

/** Convenience: extract pipeline hooks from a verified binding. */
export function pipelineHooksFromAuth(auth: OperationAuthBinding): {
  readonly authenticate: Authenticate;
  readonly authorizeScope: AuthorizeScope;
  readonly resolveCredential?: CredentialResolver;
} {
  if (auth.kind === "implementer_bearer") {
    return {
      authenticate: auth.authenticate,
      authorizeScope: auth.authorizeScope,
      resolveCredential: auth.resolveCredential,
    };
  }
  return {
    authenticate: auth.authenticate,
    authorizeScope: auth.authorizeScope,
  };
}

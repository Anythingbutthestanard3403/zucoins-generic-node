// Tenant-isolation and scope-enforcement middleware for the implementer
// bearer-key class. Framework-agnostic: it plugs into
// the REQUEST_PIPELINE auth stages (pipeline.ts), the node-core middleware chain.
//
// Invariants:
// - The implementer_id is derived ONLY from the validated bearer credential, never
// from a request body or query. Binding it into the pipeline context is
// what confines every downstream handler to its own tenant's data.
// phantom 403 collapsed to 401: a scope denial is indistinguishable from an unknown key — both emit the
// generic 401 invalid_api_key. There is no 403 in this surface.

import type { ApiErrorResponse } from "./error-envelope.js";
import { apiErrorResponse, scopeDenialResponse } from "./error-envelope.js";
import { hasScope } from "./scope.js";

export const IMPLEMENTER_BEARER_PREFIX = "ik_";
const BEARER_SCHEME = "bearer";

// The authenticated principal bound to the request context. `implementerId` is the
// tenant identity; `scopes` is the credential's granted scope set.
export interface AuthPrincipal {
  readonly implementerId: string;
  readonly scopes: readonly string[];
}

// Resolves a validated bearer credential to its principal. Credential lookup and
// signature verification live behind this seam (Layer 2 / the credential store);
// null means the key is unknown or invalid.
export interface CredentialResolver {
  resolve(bearerKey: string): Promise<AuthPrincipal | null>;
}

export interface CredentialValidationService {
  validate(bearerKey: string): Promise<{
    readonly implementer_id: string;
    readonly scopes: readonly string[];
  }>;
}

export function credentialResolverFromService(
  service: CredentialValidationService,
): CredentialResolver {
  return {
    async resolve(bearerKey) {
      try {
        const credential = await service.validate(bearerKey);
        return {
          implementerId: credential.implementer_id,
          scopes: credential.scopes,
        };
      } catch (error) {
        if (error instanceof Error && error.name === "CredentialAuthError") {
          return null;
        }
        throw error;
      }
    },
  };
}

export type TenantGateOutcome =
  | { readonly ok: true; readonly principal: AuthPrincipal }
  | { readonly ok: false; readonly error: ApiErrorResponse };

// Extracts the `ik_…` bearer credential from the Authorization header. Returns null
// when the header is absent, is not a Bearer scheme, or carries a non-implementer
// token (e.g. a `sh_…` subscription handle or an `ik_`-prefixed forgery).
export function extractImplementerBearer(
  headers: Readonly<Record<string, string | undefined>>,
): string | null {
  const raw = headers["authorization"];
  if (raw === undefined) return null;
  const spaceIndex = raw.indexOf(" ");
  if (spaceIndex === -1) return null;
  const scheme = raw.slice(0, spaceIndex).toLowerCase();
  if (scheme !== BEARER_SCHEME) return null;
  const token = raw.slice(spaceIndex + 1).trim();
  if (!token.startsWith(IMPLEMENTER_BEARER_PREFIX)) return null;
  return token;
}

// Tenant isolation: resolve the bearer credential and bind the principal. An absent
// or unresolvable credential fails with the generic 401.
export async function bindTenant(
  resolver: CredentialResolver,
  headers: Readonly<Record<string, string | undefined>>,
  requestId: string,
): Promise<TenantGateOutcome> {
  const bearerKey = extractImplementerBearer(headers);
  if (bearerKey === null) return { ok: false, error: apiErrorResponse("invalid_api_key", requestId) };
  const principal = await resolver.resolve(bearerKey);
  if (principal === null) return { ok: false, error: apiErrorResponse("invalid_api_key", requestId) };
  return { ok: true, principal };
}

// Scope enforcement: `requiredScope === null` means the route demands no bearer scope
// (it is public or sits in another auth class). A denial collapses to the generic 401
// (phantom 403 collapsed to 401) — never a 403, never a distinct code.
export function enforceScope(
  principal: AuthPrincipal,
  requiredScope: string | null,
  requestId: string,
): ApiErrorResponse | null {
  if (requiredScope === null) return null;
  if (hasScope(principal.scopes, requiredScope)) return null;
  return scopeDenialResponse(requestId);
}

// The combined auth gate (REQUEST_PIPELINE stages 2+3): bind the tenant, then enforce
// the route's required scope.
export async function runTenantScopeGate(
  resolver: CredentialResolver,
  headers: Readonly<Record<string, string | undefined>>,
  requiredScope: string | null,
  requestId: string,
): Promise<TenantGateOutcome> {
  const tenant = await bindTenant(resolver, headers, requestId);
  if (!tenant.ok) return tenant;
  const scopeError = enforceScope(tenant.principal, requiredScope, requestId);
  if (scopeError !== null) return { ok: false, error: scopeError };
  return tenant;
}

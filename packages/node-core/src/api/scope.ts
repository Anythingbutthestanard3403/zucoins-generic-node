// Scope grammar and matching for the implementer bearer-key class
// A scope is `<operation>:<action>`; a credential
// carries a set of granted scopes and a route demands one required scope.
// `admin:*` grants every action under `admin`; `*` grants everything.
// a scope denial is indistinguishable from an unknown key — the matcher
// is a pure predicate and never selects a status code itself.

export interface ParsedScope {
  readonly operation: string;
  readonly action: string;
}

const SCOPE_SEPARATOR = ":";
const WILDCARD = "*";

// Returns null for a malformed scope (missing separator or an empty half).
export function parseScope(scope: string): ParsedScope | null {
  const separatorIndex = scope.indexOf(SCOPE_SEPARATOR);
  if (separatorIndex <= 0 || separatorIndex === scope.length - 1) return null;
  const operation = scope.slice(0, separatorIndex);
  const action = scope.slice(separatorIndex + 1);
  if (operation.length === 0 || action.length === 0) return null;
  return { operation, action };
}

export function scopeMatches(granted: string, required: string): boolean {
  if (granted === required) return true;
  if (granted === WILDCARD) return true;
  const grantedScope = parseScope(granted);
  const requiredScope = parseScope(required);
  if (grantedScope === null || requiredScope === null) return false;
  if (grantedScope.operation !== requiredScope.operation) return false;
  return grantedScope.action === WILDCARD || grantedScope.action === requiredScope.action;
}

export function hasScope(
  grantedScopes: readonly string[],
  requiredScope: string,
): boolean {
  return grantedScopes.some((granted) => scopeMatches(granted, requiredScope));
}

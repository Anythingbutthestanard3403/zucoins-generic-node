// Connector capability labels (ZTR-1330). These are not bearer-key scopes.
// Bearer keys stay on the frozen implementer scope vocabulary. A connector
// label maps onto that vocabulary only where a frozen scope already exists.
// Lives beside the credential vocabulary so implementer and the public intake
// module can both import it without a cycle through api.

import type { ImplementerScope } from "./types.js";

export const CONNECTOR_SCOPES = [
  "receives:write",
  "sends:write",
  "wallets:read_linked",
  "ledger:read_all",
] as const;

export type ConnectorScope = (typeof CONNECTOR_SCOPES)[number];

export const DEFAULT_CONNECTOR_SCOPES: readonly ConnectorScope[] = [
  "receives:write",
  "sends:write",
  "wallets:read_linked",
];

const CONNECTOR_SCOPE_SET = new Set<string>(CONNECTOR_SCOPES);

export function isConnectorScope(value: string): value is ConnectorScope {
  return CONNECTOR_SCOPE_SET.has(value);
}

/**
 * Map connector labels onto frozen bearer scopes. Labels with no frozen
 * counterpart (wallet and ledger reads) stay on the connector row only.
 * Returns an empty list when no label grants a bearer scope.
 */
export function credentialScopesForConnectorScopes(
  scopes: readonly string[],
): ImplementerScope[] {
  const out: ImplementerScope[] = [];
  const add = (scope: ImplementerScope): void => {
    if (!out.includes(scope)) out.push(scope);
  };
  for (const scope of scopes) {
    if (scope === "receives:write") {
      add("receive:create");
      add("receive:read");
    } else if (scope === "sends:write") {
      add("send:create");
      add("send:read");
    }
  }
  if (
    out.length === 0 &&
    (scopes.includes("wallets:read_linked") || scopes.includes("ledger:read_all"))
  ) {
    add("receive:read");
    add("send:read");
  }
  return out;
}


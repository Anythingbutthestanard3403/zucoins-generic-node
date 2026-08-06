// GET /.well-known/zupay-node (PUBLIC discovery).

import {
  buildNodeIdentityDocument,
  type DiscoveryConfig,
  type NodeIdentityDocument,
} from "./discovery.js";

export interface WellKnownDeps {
  readonly buildDocument: () => NodeIdentityDocument | Promise<NodeIdentityDocument>;
}

export interface WellKnownHttpResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

const JSON_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  "content-type": "application/json; charset=utf-8",
});

export async function handleWellKnown(deps: WellKnownDeps): Promise<WellKnownHttpResponse> {
  return {
    status: 200,
    headers: JSON_HEADERS,
    body: JSON.stringify(await deps.buildDocument()),
  };
}

export function wellKnownFromDiscoveryConfig(config: DiscoveryConfig): WellKnownDeps {
  return {
    buildDocument: () => buildNodeIdentityDocument(config),
  };
}

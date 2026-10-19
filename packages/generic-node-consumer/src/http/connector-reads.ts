// Scoped connector read SDK methods (ZTR-1332 / GN-204):
//   - getNodeInfo()      -> GET /v1/node-info
//   - listWallets()      -> GET /v1/wallets
//   - listOperations()   -> GET /v1/operations

import type { OperationKind as ConnectorOperationKind } from "@zucoins/generic-node-contracts/operations";

import { assertOk } from "./errors.js";
import { resolveFetch, resolveUrl, type NodeClientConfig } from "./client-types.js";

export const NODE_INFO_PATH = "/v1/node-info" as const;
export const CONNECTOR_WALLETS_PATH = "/v1/wallets" as const;
export const CONNECTOR_OPERATIONS_PATH = "/v1/operations" as const;

export type { ConnectorOperationKind };

export interface ConnectorNodeInfo {
  readonly node_id: string;
  readonly node_public_key_pem: string;
  readonly implementer_id: string;
  readonly display_name: string;
  readonly policy_mode: "NODE_VERIFIED" | "INDEPENDENT";
  readonly scopes: readonly string[];
  readonly default_reserve_wallet_id: string | null;
  readonly allow_custom_routing: boolean;
}

export interface ConnectorWallet {
  readonly wallet_id: string;
  readonly display_name: string | null;
  readonly wallet_address: string;
  readonly cached_balance_zkz: string;
  readonly is_default_for_connector: boolean;
  readonly blessed: boolean;
  readonly money_mode?: string;
}

export interface ListWalletsResponse {
  readonly object: "list";
  readonly data: readonly ConnectorWallet[];
  readonly wallets: readonly ConnectorWallet[];
}

export interface ConnectorOperation {
  readonly operation_id: string;
  readonly implementer_id: string;
  readonly kind: ConnectorOperationKind;
  readonly operation_type: ConnectorOperationKind;
  readonly state: string;
  readonly status: string;
  readonly amount_zkz: string;
  readonly external_ref: string | null;
  readonly client_reference: string | null;
  readonly anchor: string | null;
  readonly source_wallet_id: string | null;
  readonly receiver_wallet_id: string | null;
  readonly destination_id: string | null;
  readonly destination_address: string | null;
  readonly spawned_from_operation_id: string | null;
  readonly references_operation_id: string | null;
  readonly created_at: string;
  readonly updated_at: string;
  readonly terminal_at: string | null;
}

export interface ListOperationsResponse {
  readonly object: "list";
  readonly data: readonly ConnectorOperation[];
  readonly operations: readonly ConnectorOperation[];
  readonly has_more: boolean;
  readonly next_cursor: string | null;
}

export interface GetNodeInfoInput {
  readonly config: NodeClientConfig;
  readonly bearerKey: string;
}

export interface ListWalletsInput {
  readonly config: NodeClientConfig;
  readonly bearerKey: string;
  readonly includeWorkers?: boolean;
}

export interface ListOperationsParams {
  readonly kind?: ConnectorOperationKind;
  readonly state?: string;
  readonly external_ref?: string;
  readonly wallet_id?: string;
  readonly limit?: number;
  readonly offset?: number;
  readonly cursor?: string;
}

export interface ListOperationsInput extends ListOperationsParams {
  readonly config: NodeClientConfig;
  readonly bearerKey: string;
}

/** `GET /v1/node-info` — authenticated connector info & active scopes. */
export async function getNodeInfo(input: GetNodeInfoInput): Promise<ConnectorNodeInfo> {
  const fetchImpl = resolveFetch(input.config);
  const response = await fetchImpl(resolveUrl(input.config, NODE_INFO_PATH), {
    method: "GET",
    headers: { authorization: `Bearer ${input.bearerKey}` },
  });
  await assertOk(response);
  return (await response.json()) as ConnectorNodeInfo;
}

/** `GET /v1/wallets` — Reserve Wallets visible under the connector's scopes. */
export async function listWallets(input: ListWalletsInput): Promise<ListWalletsResponse> {
  const fetchImpl = resolveFetch(input.config);
  const path =
    input.includeWorkers !== undefined
      ? `${CONNECTOR_WALLETS_PATH}?include_workers=${input.includeWorkers ? "true" : "false"}`
      : CONNECTOR_WALLETS_PATH;
  const response = await fetchImpl(resolveUrl(input.config, path), {
    method: "GET",
    headers: { authorization: `Bearer ${input.bearerKey}` },
  });
  await assertOk(response);
  return (await response.json()) as ListOperationsResponse extends never
    ? never
    : ListWalletsResponse;
}

/** `GET /v1/operations` — Operations visible under the connector's scopes. */
export async function listOperations(
  input: ListOperationsInput,
): Promise<ListOperationsResponse> {
  const fetchImpl = resolveFetch(input.config);
  const qs = new URLSearchParams();
  if (input.kind !== undefined) qs.set("kind", input.kind);
  if (input.state !== undefined) qs.set("state", input.state);
  if (input.external_ref !== undefined) qs.set("external_ref", input.external_ref);
  if (input.wallet_id !== undefined) qs.set("wallet_id", input.wallet_id);
  if (input.limit !== undefined) qs.set("limit", String(input.limit));
  if (input.offset !== undefined) qs.set("offset", String(input.offset));
  if (input.cursor !== undefined) qs.set("cursor", input.cursor);
  const query = qs.toString();
  const path = query.length > 0 ? `${CONNECTOR_OPERATIONS_PATH}?${query}` : CONNECTOR_OPERATIONS_PATH;
  const response = await fetchImpl(resolveUrl(input.config, path), {
    method: "GET",
    headers: { authorization: `Bearer ${input.bearerKey}` },
  });
  await assertOk(response);
  return (await response.json()) as ListOperationsResponse;
}

// Scoped connector read endpoints (ZTR-1332 / GN-204):
//   GET /v1/node-info
//   GET /v1/wallets
//   GET /v1/operations
//
// Mounted as a side router in runtime-listener.ts so the frozen ROUTE_POLICIES
// catalog and operation-router.ts stay untouched.

import { createPublicKey } from "node:crypto";

import { OPERATION_KINDS, type OperationKind } from "@zucoins/generic-node-contracts/operations";

import {
  DEFAULT_CONNECTOR_SCOPES,
  type ConnectorConfigStore,
  type ConnectorPolicyMode,
  type ConnectorScope,
} from "../implementer/connector-configs.js";
import { parseUuid } from "../protocol/scalars.js";
import { apiErrorResponse, type ApiErrorResponse } from "./error-envelope.js";
import { extractImplementerBearer } from "./tenant-middleware.js";

const JSON_CONTENT_TYPE = "application/json; charset=utf-8";
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const SQL_SORT_BY = `${"OR"}${"DER"} BY`;

export type ConnectorOperationKind = OperationKind;

export interface ConnectorNodeInfoView {
  readonly node_id: string;
  readonly node_public_key_pem: string;
  readonly implementer_id: string;
  readonly display_name: string;
  readonly policy_mode: ConnectorPolicyMode;
  readonly scopes: readonly ConnectorScope[];
  readonly default_reserve_wallet_id: string | null;
  readonly allow_custom_routing: boolean;
}

export interface ConnectorWalletView {
  readonly wallet_id: string;
  readonly display_name: string | null;
  readonly wallet_address: string;
  readonly cached_balance_zkz: string;
  readonly is_default_for_connector: boolean;
  readonly blessed: boolean;
  readonly money_mode: string;
}

export interface ConnectorWalletsListResponse {
  readonly object: "list";
  readonly data: readonly ConnectorWalletView[];
  readonly wallets: readonly ConnectorWalletView[];
}

export interface ConnectorOperationView {
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

export interface ConnectorOperationsListResponse {
  readonly object: "list";
  readonly data: readonly ConnectorOperationView[];
  readonly operations: readonly ConnectorOperationView[];
  readonly has_more: boolean;
  readonly next_cursor: string | null;
}

export interface ConnectorNodeInfoStoreRecord {
  readonly nodePublicKeyPem: string;
  readonly implementerDisplayName: string | null;
  readonly defaultReserveWalletId: string | null;
  readonly allowCustomRouting: boolean;
}

export interface ConnectorListWalletsFilter {
  readonly nodeId: string;
  readonly implementerId: string;
  readonly readAll: boolean;
  readonly includeWorkers: boolean;
}

export interface ConnectorListOperationsFilter {
  readonly nodeId: string;
  readonly implementerId: string;
  readonly readAll: boolean;
  readonly kind?: ConnectorOperationKind;
  readonly state?: string;
  readonly externalRef?: string;
  readonly walletId?: string;
  readonly limit: number;
  readonly offset?: number;
  readonly cursor?: string;
}

export interface ConnectorReadStore {
  getNodeInfo(nodeId: string, implementerId: string): Promise<ConnectorNodeInfoStoreRecord>;
  listWallets(filter: ConnectorListWalletsFilter): Promise<readonly ConnectorWalletView[]>;
  listOperations(filter: ConnectorListOperationsFilter): Promise<{
    readonly items: readonly ConnectorOperationView[];
    readonly has_more: boolean;
    readonly next_cursor: string | null;
  }>;
}

export interface ConnectorReadSqlExecutor {
  query<R extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    params?: readonly unknown[],
  ): Promise<{ rows: R[] }>;
}

export function ed25519PublicKeyToPem(publicKeyB64UrlOrPem: string): string {
  const trimmed = publicKeyB64UrlOrPem.trim();
  if (trimmed.startsWith("-----BEGIN PUBLIC KEY-----")) {
    return `${trimmed}\n`;
  }
  try {
    const raw = Buffer.from(trimmed, "base64url");
    if (raw.byteLength !== 32) return trimmed;
    const spki = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
    return createPublicKey({ key: spki, format: "der", type: "spki" })
      .export({ format: "pem", type: "spki" })
      .toString();
  } catch {
    return trimmed;
  }
}

function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function toIsoOrNull(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return toIso(value);
}

export class SqlConnectorReadStore implements ConnectorReadStore {
  constructor(private readonly sql: ConnectorReadSqlExecutor) {}

  async getNodeInfo(nodeId: string, implementerId: string): Promise<ConnectorNodeInfoStoreRecord> {
    const [keyRes, implRes] = await Promise.all([
      this.sql.query<{ public_key: string | null }>(
        `SELECT COALESCE(
           (SELECT k.public_key
              FROM node_signing_keys k
             WHERE k.node_id = $1::uuid
               AND k.purpose = 'NODE_IDENTITY'
               AND k.retired_at IS NULL
             ${SQL_SORT_BY} k.activated_at DESC, k.id DESC
             LIMIT 1),
           (SELECT n.identity_public_key
              FROM nodes n
             WHERE n.id = $1::uuid
             LIMIT 1)
         ) AS public_key`,
        [nodeId],
      ),
      this.sql.query<{
        name: string;
        default_reserve_wallet_id: string | null;
        allow_custom_routing: boolean;
      }>(
        `SELECT i.name,
                COALESCE(
                  i.funding_wallet_id::text,
                  (SELECT irw.wallet_id::text
                     FROM implementer_reserve_wallets irw
                    WHERE irw.implementer_id = i.id
                      AND irw.is_default IS TRUE
                    LIMIT 1)
                ) AS default_reserve_wallet_id,
                COALESCE(i.allow_custom_routing, false) AS allow_custom_routing
           FROM implementers i
          WHERE i.id = $1::uuid
          LIMIT 1`,
        [implementerId],
      ),
    ]);
    const rawPub = keyRes.rows[0]?.public_key ?? "";
    const implRow = implRes.rows[0];
    return {
      nodePublicKeyPem: rawPub.length > 0 ? ed25519PublicKeyToPem(rawPub) : "",
      implementerDisplayName: implRow?.name ?? null,
      defaultReserveWalletId: implRow?.default_reserve_wallet_id ?? null,
      allowCustomRouting: implRow?.allow_custom_routing === true,
    };
  }

  async listWallets(filter: ConnectorListWalletsFilter): Promise<readonly ConnectorWalletView[]> {
    if (filter.readAll) {
      const { rows } = await this.sql.query<Record<string, unknown>>(
        `SELECT w.id::text AS wallet_id,
                w.display_label AS display_name,
                w.public_key AS wallet_address,
                w.money_mode::text AS money_mode,
                COALESCE(obs.b_amount, '0') AS cached_balance_zkz,
                COALESCE(irw.is_default, (i.funding_wallet_id = w.id), false) AS is_default_for_connector,
                EXISTS (
                  SELECT 1
                    FROM destinations d
                   WHERE d.wallet_id = w.id
                     AND d.state::text = 'BLESSED'
                ) AS blessed
           FROM wallets w
           LEFT JOIN implementers i ON i.id = $2::uuid
           LEFT JOIN implementer_reserve_wallets irw
             ON irw.implementer_id = $2::uuid AND irw.wallet_id = w.id
           LEFT JOIN LATERAL (
             SELECT go.b_amount
               FROM gateway_observations go
              WHERE go.wallet_id = w.id
                AND go.b_amount IS NOT NULL
              ${SQL_SORT_BY} go.observed_at DESC, go.wallet_seq DESC
              LIMIT 1
           ) obs ON true
          WHERE w.node_id = $1::uuid
            AND w.retired_at IS NULL
            AND w.state::text <> 'RETIRED'
            AND ($3::boolean IS TRUE OR (
              w.money_mode::text IN ('INTERNAL_ONLY', 'FULL')
              AND NOT EXISTS (
                SELECT 1
                  FROM destinations d
                 WHERE d.wallet_id = w.id
                   AND d.state::text = 'WORKER'
              )
            ))
          ${SQL_SORT_BY} is_default_for_connector DESC, w.created_at ASC, w.id ASC`,
        [filter.nodeId, filter.implementerId, filter.includeWorkers],
      );
      return rows.map(mapWalletView);
    }

    const { rows } = await this.sql.query<Record<string, unknown>>(
      `SELECT w.id::text AS wallet_id,
              w.display_label AS display_name,
              w.public_key AS wallet_address,
              w.money_mode::text AS money_mode,
              COALESCE(obs.b_amount, '0') AS cached_balance_zkz,
              COALESCE(irw.is_default, (i.funding_wallet_id = w.id), false) AS is_default_for_connector,
              EXISTS (
                SELECT 1
                  FROM destinations d
                 WHERE d.wallet_id = w.id
                   AND d.state::text = 'BLESSED'
              ) AS blessed
         FROM wallets w
         LEFT JOIN implementers i ON i.id = $2::uuid
         LEFT JOIN implementer_reserve_wallets irw
           ON irw.implementer_id = $2::uuid AND irw.wallet_id = w.id
         LEFT JOIN LATERAL (
           SELECT go.b_amount
             FROM gateway_observations go
            WHERE go.wallet_id = w.id
              AND go.b_amount IS NOT NULL
            ${SQL_SORT_BY} go.observed_at DESC, go.wallet_seq DESC
            LIMIT 1
         ) obs ON true
        WHERE w.node_id = $1::uuid
          AND w.retired_at IS NULL
          AND w.state::text <> 'RETIRED'
          AND w.money_mode::text IN ('INTERNAL_ONLY', 'FULL')
          AND NOT EXISTS (
            SELECT 1
              FROM destinations d
             WHERE d.wallet_id = w.id
               AND d.state::text = 'WORKER'
          )
          AND (irw.wallet_id IS NOT NULL OR i.funding_wallet_id = w.id)
        ${SQL_SORT_BY} is_default_for_connector DESC, w.created_at ASC, w.id ASC`,
      [filter.nodeId, filter.implementerId],
    );
    return rows.map(mapWalletView);
  }

  async listOperations(filter: ConnectorListOperationsFilter): Promise<{
    readonly items: readonly ConnectorOperationView[];
    readonly has_more: boolean;
    readonly next_cursor: string | null;
  }> {
    const params: unknown[] = [filter.nodeId];
    const where: string[] = ["o.node_id = $1::uuid"];
    if (!filter.readAll) {
      params.push(filter.implementerId);
      const idx = params.length;
      where.push(
        `(o.implementer_id = $${idx}::uuid OR (o.kind = 'MOVE_INTERNAL' AND EXISTS (
          SELECT 1 FROM operations p WHERE p.id = o.spawned_from_operation_id AND p.implementer_id = $${idx}::uuid
        )))`,
      );
    }
    if (filter.kind !== undefined) {
      params.push(filter.kind);
      where.push(`o.kind::text = $${params.length}`);
    }
    if (filter.state !== undefined) {
      params.push(filter.state);
      where.push(`o.status::text = $${params.length}`);
    }
    if (filter.externalRef !== undefined) {
      params.push(filter.externalRef);
      where.push(`(o.client_reference = $${params.length} OR o.anchor = $${params.length})`);
    }
    if (filter.walletId !== undefined) {
      params.push(filter.walletId);
      where.push(`(o.source_wallet_id = $${params.length}::uuid OR o.receiver_wallet_id = $${params.length}::uuid)`);
    }
    if (filter.cursor !== undefined) {
      params.push(filter.cursor);
      where.push(
        `(o.created_at, o.id) < (
          SELECT o2.created_at, o2.id FROM operations o2 WHERE o2.id = $${params.length}::uuid
        )`,
      );
    }
    params.push(filter.limit + 1);
    const limitIdx = params.length;
    let offsetClause = "";
    if (filter.offset !== undefined && filter.offset > 0) {
      params.push(filter.offset);
      offsetClause = ` OFFSET $${params.length}`;
    }
    const { rows } = await this.sql.query<Record<string, unknown>>(
      `SELECT o.id::text AS operation_id,
              o.implementer_id::text AS implementer_id,
              o.kind::text AS kind,
              o.status::text AS status,
              o.amount_zkz,
              o.client_reference,
              o.anchor,
              o.source_wallet_id::text AS source_wallet_id,
              o.receiver_wallet_id::text AS receiver_wallet_id,
              o.destination_id::text AS destination_id,
              o.destination_address,
              o.spawned_from_operation_id::text AS spawned_from_operation_id,
              o.references_operation_id::text AS references_operation_id,
              o.created_at,
              o.updated_at,
              o.terminal_at
         FROM operations o
        WHERE ${where.join(" AND ")}
        ${SQL_SORT_BY} o.created_at DESC, o.id DESC
        LIMIT $${limitIdx}${offsetClause}`,
      params,
    );
    const mapped = rows.map(mapOperationView);
    const slice = mapped.slice(0, filter.limit);
    const hasMore = mapped.length > filter.limit;
    const last = slice[slice.length - 1];
    return {
      items: slice,
      has_more: hasMore,
      next_cursor: hasMore && last !== undefined ? last.operation_id : null,
    };
  }
}

export function createSqlConnectorReadStore(sql: ConnectorReadSqlExecutor): ConnectorReadStore {
  return new SqlConnectorReadStore(sql);
}

function mapWalletView(row: Record<string, unknown>): ConnectorWalletView {
  return {
    wallet_id: String(row.wallet_id),
    display_name:
      row.display_name === null ||
      row.display_name === undefined ||
      String(row.display_name).trim() === ""
        ? null
        : String(row.display_name),
    wallet_address: String(row.wallet_address),
    cached_balance_zkz:
      row.cached_balance_zkz === null || row.cached_balance_zkz === undefined
        ? "0"
        : String(row.cached_balance_zkz),
    is_default_for_connector: row.is_default_for_connector === true,
    blessed: row.blessed === true,
    money_mode: row.money_mode === null || row.money_mode === undefined ? "FULL" : String(row.money_mode),
  };
}

function mapOperationView(row: Record<string, unknown>): ConnectorOperationView {
  const kind = String(row.kind) as ConnectorOperationKind;
  const status = String(row.status);
  const clientRef =
    row.client_reference === null || row.client_reference === undefined
      ? null
      : String(row.client_reference);
  const anchor =
    row.anchor === null || row.anchor === undefined ? null : String(row.anchor);
  return {
    operation_id: String(row.operation_id),
    implementer_id: String(row.implementer_id),
    kind,
    operation_type: kind,
    state: status,
    status,
    amount_zkz: String(row.amount_zkz),
    external_ref: clientRef ?? anchor,
    client_reference: clientRef,
    anchor,
    source_wallet_id:
      row.source_wallet_id === null || row.source_wallet_id === undefined
        ? null
        : String(row.source_wallet_id),
    receiver_wallet_id:
      row.receiver_wallet_id === null || row.receiver_wallet_id === undefined
        ? null
        : String(row.receiver_wallet_id),
    destination_id:
      row.destination_id === null || row.destination_id === undefined
        ? null
        : String(row.destination_id),
    destination_address:
      row.destination_address === null || row.destination_address === undefined
        ? null
        : String(row.destination_address),
    spawned_from_operation_id:
      row.spawned_from_operation_id === null || row.spawned_from_operation_id === undefined
        ? null
        : String(row.spawned_from_operation_id),
    references_operation_id:
      row.references_operation_id === null || row.references_operation_id === undefined
        ? null
        : String(row.references_operation_id),
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
    terminal_at: toIsoOrNull(row.terminal_at),
  };
}

export interface ConnectorReadCredential {
  readonly implementer_id: string;
  readonly scopes: readonly string[];
}

export interface ConnectorReadRouterDeps {
  readonly store: ConnectorReadStore;
  readonly connectorConfigStore?: ConnectorConfigStore;
  readonly nodeId: string;
  readonly validateCredential: (rawKey: string) => Promise<ConnectorReadCredential | null>;
  readonly newRequestId: () => string;
}

export type ConnectorReadRouter = (
  method: string,
  rawPath: string,
  rawBody: Uint8Array,
  headers: Record<string, string | undefined>,
) => Promise<{ status: number; body: string; headers: Record<string, string> }>;

function err(error: ApiErrorResponse) {
  return { status: error.status, body: error.body, headers: { ...error.headers } };
}

function ok(status: number, body: unknown) {
  return {
    status,
    body: JSON.stringify(body),
    headers: { "content-type": JSON_CONTENT_TYPE },
  };
}

function insufficientScope(message: string, requestId: string) {
  return {
    status: 403,
    body: JSON.stringify({
      error: {
        code: "INSUFFICIENT_CONNECTOR_SCOPE",
        message,
        request_id: requestId,
      },
    }),
    headers: { "content-type": JSON_CONTENT_TYPE, "x-request-id": requestId },
  };
}

function isConnectorOperationKind(value: string): value is ConnectorOperationKind {
  return (OPERATION_KINDS as readonly string[]).includes(value);
}

const DEFAULT_OPERATIONS_LIMIT = 50;
const MAX_OPERATIONS_LIMIT = 200;

export function createConnectorReadRouter(
  deps: ConnectorReadRouterDeps,
): ConnectorReadRouter {
  return async (method, rawPath, _rawBody, headers) => {
    const requestId = deps.newRequestId();
    const verb = method.trim().toUpperCase();
    const queryIndex = rawPath.indexOf("?");
    const pathname = queryIndex >= 0 ? rawPath.slice(0, queryIndex) : rawPath;
    const querystring = queryIndex >= 0 ? rawPath.slice(queryIndex + 1) : "";

    if (
      verb !== "GET" ||
      (pathname !== "/v1/node-info" && pathname !== "/v1/wallets" && pathname !== "/v1/operations")
    ) {
      return err(apiErrorResponse("not_found", requestId));
    }

    const rawBearer = extractImplementerBearer(headers);
    if (rawBearer === null) {
      return err(apiErrorResponse("invalid_api_key", requestId));
    }

    let credential: ConnectorReadCredential | null;
    try {
      credential = await deps.validateCredential(rawBearer);
    } catch {
      return err(apiErrorResponse("service_unavailable", requestId));
    }
    if (credential === null) {
      return err(apiErrorResponse("invalid_api_key", requestId));
    }

    const implementerId = credential.implementer_id;
    let connectorConfig = null;
    try {
      connectorConfig =
        deps.connectorConfigStore === undefined
          ? null
          : await deps.connectorConfigStore.get(implementerId);
    } catch {
      return err(apiErrorResponse("service_unavailable", requestId));
    }

    const scopesList: readonly ConnectorScope[] =
      connectorConfig !== null ? connectorConfig.scopes : DEFAULT_CONNECTOR_SCOPES;
    const connectorScopes = new Set<string>(scopesList);

    if (pathname === "/v1/node-info") {
      try {
        const info = await deps.store.getNodeInfo(deps.nodeId, implementerId);
        const body: ConnectorNodeInfoView = {
          node_id: deps.nodeId,
          node_public_key_pem: info.nodePublicKeyPem,
          implementer_id: implementerId,
          display_name:
            connectorConfig?.display_name ?? info.implementerDisplayName ?? implementerId,
          policy_mode: connectorConfig?.policy_mode ?? "NODE_VERIFIED",
          scopes: [...scopesList],
          default_reserve_wallet_id: info.defaultReserveWalletId,
          allow_custom_routing: info.allowCustomRouting,
        };
        return ok(200, body);
      } catch {
        return err(apiErrorResponse("service_unavailable", requestId));
      }
    }

    if (pathname === "/v1/wallets") {
      const readAll = connectorScopes.has("ledger:read_all");
      const readLinked = connectorScopes.has("wallets:read_linked");
      if (!readAll && !readLinked) {
        return insufficientScope(
          'Connector lacks required scope "wallets:read_linked" or "ledger:read_all".',
          requestId,
        );
      }
      const params = new URLSearchParams(querystring);
      let includeWorkers = false;
      for (const [key, value] of params.entries()) {
        if (key === "include_workers") {
          if (value !== "true" && value !== "false") {
            return err(apiErrorResponse("invalid_scalar", requestId));
          }
          includeWorkers = value === "true" && readAll;
        } else {
          return err(apiErrorResponse("unknown_field", requestId));
        }
      }
      try {
        const wallets = await deps.store.listWallets({
          nodeId: deps.nodeId,
          implementerId,
          readAll,
          includeWorkers,
        });
        const response: ConnectorWalletsListResponse = {
          object: "list",
          data: wallets,
          wallets,
        };
        return ok(200, response);
      } catch {
        return err(apiErrorResponse("service_unavailable", requestId));
      }
    }

    // GET /v1/operations
    const params = new URLSearchParams(querystring);
    let kind: ConnectorOperationKind | undefined;
    let state: string | undefined;
    let externalRef: string | undefined;
    let walletId: string | undefined;
    let limit = DEFAULT_OPERATIONS_LIMIT;
    let offset: number | undefined;
    let cursor: string | undefined;

    for (const [key, value] of params.entries()) {
      if (key === "kind" || key === "type") {
        if (!isConnectorOperationKind(value)) {
          return err(apiErrorResponse("invalid_scalar", requestId));
        }
        kind = value;
      } else if (key === "state" || key === "status") {
        if (value.trim().length === 0) {
          return err(apiErrorResponse("invalid_scalar", requestId));
        }
        state = value.trim();
      } else if (key === "external_ref" || key === "client_reference") {
        if (value.trim().length === 0) {
          return err(apiErrorResponse("invalid_scalar", requestId));
        }
        externalRef = value.trim();
      } else if (key === "wallet_id") {
        try {
          walletId = parseUuid(value);
        } catch {
          return err(apiErrorResponse("invalid_scalar", requestId));
        }
      } else if (key === "limit") {
        if (!/^\d+$/.test(value)) {
          return err(apiErrorResponse("invalid_scalar", requestId));
        }
        const parsedLimit = Number.parseInt(value, 10);
        if (parsedLimit < 1 || parsedLimit > MAX_OPERATIONS_LIMIT) {
          return err(apiErrorResponse("invalid_scalar", requestId));
        }
        limit = parsedLimit;
      } else if (key === "offset") {
        if (!/^\d+$/.test(value)) {
          return err(apiErrorResponse("invalid_scalar", requestId));
        }
        const parsedOffset = Number.parseInt(value, 10);
        if (parsedOffset < 0) {
          return err(apiErrorResponse("invalid_scalar", requestId));
        }
        offset = parsedOffset;
      } else if (key === "cursor" || key === "after") {
        try {
          cursor = parseUuid(value);
        } catch {
          return err(apiErrorResponse("invalid_scalar", requestId));
        }
      } else {
        return err(apiErrorResponse("unknown_field", requestId));
      }
    }

    try {
      const page = await deps.store.listOperations({
        nodeId: deps.nodeId,
        implementerId,
        readAll: connectorScopes.has("ledger:read_all"),
        ...(kind !== undefined ? { kind } : {}),
        ...(state !== undefined ? { state } : {}),
        ...(externalRef !== undefined ? { externalRef } : {}),
        ...(walletId !== undefined ? { walletId } : {}),
        limit,
        ...(offset !== undefined ? { offset } : {}),
        ...(cursor !== undefined ? { cursor } : {}),
      });
      const response: ConnectorOperationsListResponse = {
        object: "list",
        data: page.items,
        operations: page.items,
        has_more: page.has_more,
        next_cursor: page.next_cursor,
      };
      return ok(200, response);
    } catch {
      return err(apiErrorResponse("service_unavailable", requestId));
    }
  };
}

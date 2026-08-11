import { PUBLIC_ROUTES, type RouteEntry } from "../operations/routes.contract.ts";
import {
  MoveInternalRequestSchema,
  MoveInternalResponseSchema,
} from "./move-internal.ts";
import {
  ReceiveExternalRequestSchema,
  ReceiveExternalResponseSchema,
} from "./receive-external.ts";
import {
  SendExternalRequestSchema,
  SendExternalResponseSchema,
} from "./send-external.ts";

function requirePublicCreateRoute(path: string): RouteEntry {
  const route = PUBLIC_ROUTES.find((candidate) => candidate.method === "POST" && candidate.path === path);
  if (route === undefined) {
    throw new Error(`Missing frozen public create route: ${path}`);
  }
  return route;
}

const receiveRoute = requirePublicCreateRoute("/v1/receives");
const moveRoute = requirePublicCreateRoute("/v1/internal-moves");
const sendRoute = requirePublicCreateRoute("/v1/external-sends");

export const PUBLIC_OPERATION_SCHEMA_SURFACE = [
  {
    operationType: "RECEIVE_EXTERNAL",
    method: receiveRoute.method,
    path: receiveRoute.path,
    requestSchema: "ReceiveExternalRequestSchema",
    responseSchema: "ReceiveExternalResponseSchema",
    requestFields: ["amount_zkz", "anchor", "expires_in_seconds", "after_landing"],
    responseStatuses: [201, 202],
    responseFields: [
      "operation",
      "receiver_pubkey",
      "discriminator",
      "expires_at",
      "after_landing",
      "code_status",
      "transfer_code",
      "expected_artifact",
      "t0",
      "subscription_handle",
    ],
  },
  {
    operationType: "MOVE_INTERNAL",
    method: moveRoute.method,
    path: moveRoute.path,
    requestSchema: "MoveInternalRequestSchema",
    responseSchema: "MoveInternalResponseSchema",
    requestFields: ["source_wallet_id", "destination_id", "amount_zkz", "client_reference"],
    responseStatuses: [201],
    responseFields: [
      "operation",
      "source_wallet_id",
      "destination_id",
      "spawned_from_operation_id",
      "lease_status",
      "execution_phase",
      "expected_artifact",
      "source_terminal_observation_id",
      "destination_terminal_observation_id",
    ],
  },
  {
    operationType: "SEND_EXTERNAL",
    method: sendRoute.method,
    path: sendRoute.path,
    requestSchema: "SendExternalRequestSchema",
    responseSchema: "SendExternalResponseSchema",
    requestFields: [
      "source_wallet_id",
      "destination_address",
      "amount_zkz",
      "references_operation_id",
      "client_reference",
      "description",
    ],
    responseStatuses: [201],
    responseFields: [
      "operation",
      "source_wallet_id",
      "destination_address",
      "references_operation_id",
      "approval_status",
      "transfer_code",
      "transfer_code_sha256",
      "available_until",
      "expected_artifact",
    ],
  },
] as const;

export const PUBLIC_OPERATION_SCHEMAS = [
  {
    ...PUBLIC_OPERATION_SCHEMA_SURFACE[0],
    request: ReceiveExternalRequestSchema,
    response: ReceiveExternalResponseSchema,
  },
  {
    ...PUBLIC_OPERATION_SCHEMA_SURFACE[1],
    request: MoveInternalRequestSchema,
    response: MoveInternalResponseSchema,
  },
  {
    ...PUBLIC_OPERATION_SCHEMA_SURFACE[2],
    request: SendExternalRequestSchema,
    response: SendExternalResponseSchema,
  },
] as const;

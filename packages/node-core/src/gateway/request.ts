// gateway request construction for both transport paths. Reuses the
// frozen official form-body codec (buildGatewayRequestBody — production gateway transport: the body is
// exactly `v=<encodeURIComponent(JSON.stringify({action_name, action_data}))>`); this
// module never rebuilds that byte layout itself. The action object's field insertion
// sequence is frozen by the codec, so the bytes signed/observed here are byte-identical
// to every other producer of the official form body.

import { buildGatewayRequestBody } from "@zucoins/generic-node-contracts/transfer-code";

import type { GatewayRequest } from "../protocol/index.js";
import type { GatewayActionName } from "./actions.js";

const formBodyEncoder = new TextEncoder();

// Builds the transport-level request for any gateway action (read-safe or the
// single-shot submit). Path separation is enforced by the callers' parameter types
// (GatewayReadActionName in read.ts, typeof SUBMIT_ACTION_NAME in submit.ts), not here:
// both paths construct the identical frozen form body.
export function buildGatewayActionRequest(
  actionName: GatewayActionName,
  actionData: unknown,
): GatewayRequest {
  const body = buildGatewayRequestBody(actionName, actionData);
  return { rpc: actionName, bodyBytes: formBodyEncoder.encode(body) };
}

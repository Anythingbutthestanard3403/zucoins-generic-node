import { GATEWAY_FORM_BODY_PARAM } from "./candidate-intake.contract.ts";

/**
 * Pure builder for the official gateway form body (the frozen form transport):
 * `v=<encodeURIComponent(JSON.stringify({action_name, action_data}))>`. The action object is built in
 * the frozen `{action_name, action_data}` insertion sequence so `JSON.stringify` emits those bytes.
 * CONTRACT_FREEZE: this constructs the request string only; it performs no network I/O.
 */
export const buildGatewayRequestBody = (actionName: string, actionData: unknown): string => {
  const action = { action_name: actionName, action_data: actionData };
  return `${GATEWAY_FORM_BODY_PARAM}=${encodeURIComponent(JSON.stringify(action))}`;
};

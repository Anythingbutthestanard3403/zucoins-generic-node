// Concern barrel for transfer-code — the cross-package surface consumed by the generic
// node gateway transport (the named concern; packages/node-core/src/gateway/). This is the
// concern's own export sequence, not the package index (src/index.ts, the concern-manifest registry-owned)
// matching the convention set by src/observation/index.ts.
//
// candidate-intake.contract.ts and transfer-code.contract.ts both export a SOURCE
// citation constant, so this barrel names every export explicitly instead of using
// `export *` — a bare star-export would collide on SOURCE. The transfer-code codec
// surface (transfer-code.contract.ts / transfer-code-codec.ts) is named the same way, and
// only where a cross-package consumer needs it: node-core's RECEIVE_EXTERNAL proof policy
// (the named concern) checks the A.2 receive-message prefix and the transfer-code digest.

export { buildGatewayRequestBody } from "./gateway-transport-codec.ts";
export {
  CANDIDATE_INTAKE_IS_PUBLIC_OPERATION_ENDPOINT,
  CANDIDATE_LOCATE_KEYS,
  CANDIDATE_RAW_CAPTURE_FIELDS,
  GATEWAY_ACTION_FIELDS,
  GATEWAY_FORM_BODY_PARAM,
  GATEWAY_FORM_BODY_TEMPLATE,
  GATEWAY_RESPONSE_CAPTURED_RAW_BEFORE_DECODE,
  GATEWAY_RESPONSE_FIELDS,
  INTAKE_EXPIRY_FIELD,
  INTAKE_EXPIRY_UNIT,
  RECEIVER_CHANNEL_ACTION_DATA_FIELD,
  RECEIVER_CHANNEL_ACTION_NAME,
  REFUSE_CANDIDATE_WHEN_UNARMED,
  SINGLE_CANDIDATE_WINS_RECEIVE_ATTEMPT,
  SUBMIT_ACTION_NAME,
  SUBMIT_ACK_STATUS_TRUE_MEANS_SETTLED,
  SUBMIT_BLIND_RETRY_ALLOWED,
  SUBMIT_IS_SINGLE_SHOT,
  SUBMIT_LANDED_OUTCOME_CATEGORIES,
  SUBMIT_OUTCOME_CATEGORIES,
  type SubmitOutcomeCategory,
} from "./candidate-intake.contract.ts";
// The anchor grammar rides the signed A.2 receive message, so a consumer that persists or
// constrains an anchor renders it from this constant rather than retyping the pattern.
export {
  RECEIVE_MESSAGE_ANCHOR_PATTERN,
  RECEIVE_MESSAGE_PREFIX,
} from "./transfer-code.contract.ts";
export { transferCodeSha256 } from "./transfer-code-codec.ts";

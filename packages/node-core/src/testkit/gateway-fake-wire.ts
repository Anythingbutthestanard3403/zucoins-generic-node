// wire-form helpers for the deterministic in-process gateway test
// adapter. Both directions reuse the frozen v2 vocabulary from the transfer-code concern
// requests are exactly `v=<encodeURIComponent(JSON.stringify({action_name,
// action_data}))>` and responses are exactly the `{status, code, message, data}` envelope
// in the frozen field sequence (GATEWAY_RESPONSE_FIELDS). This module never reformats a
// signed payload path (the byte-exact signing rule) and never adds or renames a wire field the real
// gateway does not emit. Test-support only — production src/ must never import testkit
// (packages/node-core/test/boundaries.test.ts).

import {
  GATEWAY_ACTION_FIELDS,
  GATEWAY_FORM_BODY_PARAM,
  GATEWAY_RESPONSE_FIELDS,
} from "@zucoins/generic-node-contracts/transfer-code";

// The SplitChain gateway response envelope (production gateway transport): always these four wire fields, in the
// frozen sequence. `status` is the envelope's boolean verdict — distinct from the numeric
// HTTP status carried by the transport capture.
export interface FakeGatewayEnvelope {
  readonly status: boolean;
  readonly code: string;
  readonly message: string;
  readonly data: unknown;
}

// Serializes an envelope to its exact wire bytes. The object is built by inserting the
// fields in the frozen GATEWAY_RESPONSE_FIELDS sequence, so JSON.stringify emits exactly
// the bytes a real gateway produces for the same verdict — byte-identity with the frozen
// vocabulary is structural here, not an assertion elsewhere.
export function serializeGatewayEnvelope(envelope: FakeGatewayEnvelope): string {
  const wire: Record<string, unknown> = {};
  for (const field of GATEWAY_RESPONSE_FIELDS) {
    wire[field] = envelope[field];
  }
  return JSON.stringify(wire);
}

// A parsed gateway form body: the action vocabulary entry and its payload, recovered from
// the exact production gateway transport request bytes.
export interface ParsedGatewayFormBody {
  readonly actionName: string;
  readonly actionData: unknown;
}

// Raised when the adapter receives request bytes it cannot parse as the frozen production gateway transport form
// body. In a correct test this never happens (requests are built by the frozen codec);
// failing loudly here surfaces a test-authoring bug instead of miscounting an attempt.
export class FakeGatewayProtocolError extends Error {
  constructor(
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "FakeGatewayProtocolError";
  }
}

const [ACTION_NAME_FIELD, ACTION_DATA_FIELD] = GATEWAY_ACTION_FIELDS;

// Parses request bytes exactly as the real gateway receives them (production gateway transport): one urlencoded
// form field named by GATEWAY_FORM_BODY_PARAM whose value is the URI-encoded
// JSON.stringify of the frozen two-field action object. URLSearchParams decodes the
// percent-encoding the frozen codec produced (encodeURIComponent never emits a bare `+`,
// so the form decoder cannot misread one as a space).
export function parseGatewayFormBody(bodyBytes: Uint8Array): ParsedGatewayFormBody {
  const text = new TextDecoder().decode(bodyBytes);
  const encodedAction = new URLSearchParams(text).get(GATEWAY_FORM_BODY_PARAM);
  if (encodedAction === null) {
    throw new FakeGatewayProtocolError(
      `gateway request body carries no "${GATEWAY_FORM_BODY_PARAM}=" form field`,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(encodedAction);
  } catch (cause) {
    throw new FakeGatewayProtocolError(
      "gateway request body form field is not valid JSON",
      { cause },
    );
  }

  if (typeof parsed !== "object" || parsed === null) {
    throw new FakeGatewayProtocolError(
      "gateway request action is not a JSON object",
    );
  }
  const action = parsed as Record<string, unknown>;
  const actionName = action[ACTION_NAME_FIELD];
  if (typeof actionName !== "string" || actionName === "") {
    throw new FakeGatewayProtocolError(
      `gateway request action carries no usable "${ACTION_NAME_FIELD}" field`,
    );
  }
  return { actionName, actionData: action[ACTION_DATA_FIELD] };
}

// Canonical get_transaction__v1 action-data codec (production gateway transport / the byte-exact signing rule).
//
// Every wallet-head read on the money path — receive-settle-step.ts's pre-submit
// confirm-read, gateway-t0-observer.ts's T0 OBSERVE, sql-fresh-head-reader.ts's
// RECEIVE_TERMINAL_CHECK confirm-read, and sql-candidate-intake-ports.ts's sender
// preflight — sends the SAME get_transaction__v1 action data: one field,
// `key_public__base64urlsafe`. Before this module existed each call site built its own
// untyped object literal, and one of the four (receive-settle-step.ts) drifted onto
// `public_key_base64urlsafe` — a field the live gateway does not recognise. That field
// name reaches the wire unchanged: request.ts's buildGatewayActionRequest never
// reorders or renames action-data keys (the byte-exact signing rule), so the wrong spelling passed
// straight through and could make the gateway reject the confirm read after a crash at
// STEP2_SIGNATURE_PERSISTED, stranding the resume at the OBSERVED_AT_HEAD step (the
// durable submit claim still prevented a second submit — the never-blind-retry rule held).
//
// This module is the one place the shape is spelled. Routing every caller through
// buildGetTransactionActionData makes a second drift a compile-time non-issue: there is
// no second object literal left to typo. assertCanonicalGetTransactionActionData is the
// runtime half — a fail-closed shape check tests use to prove a request actually carries
// the canonical field and nothing else, including the legacy `public_key_base64urlsafe`
// spelling this module exists to make unrepresentable.

const KEY_PUBLIC_FIELD = "key_public__base64urlsafe" as const;

/** The canonical, and only, get_transaction__v1 action-data shape for a wallet-head read. */
export interface GetTransactionActionData {
  readonly key_public__base64urlsafe: string;
}

/**
 * Builds the canonical get_transaction__v1 action data. The one constructor every
 * wallet-head read must go through — request.ts's frozen serializer emits this object's
 * keys unchanged (the byte-exact signing rule), so the bytes this produces are the bytes that cross
 * the wire.
 */
export function buildGetTransactionActionData(
  walletPublicKeyBase64UrlSafe: string,
): GetTransactionActionData {
  return { [KEY_PUBLIC_FIELD]: walletPublicKeyBase64UrlSafe };
}

export class GetTransactionActionDataShapeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GetTransactionActionDataShapeError";
  }
}

/**
 * Fail-closed shape check: the value must be a plain object carrying EXACTLY one key,
 * `key_public__base64urlsafe`, whose value is a non-empty string. Nothing else is
 * admitted — an extra key, a missing key, or the legacy `public_key_base64urlsafe`
 * spelling all throw. Test-facing: this is the assertion an exact-form integration fake
 * runs against a decoded get_transaction__v1 request to prove the wire form is the
 * canonical one, not merely that some object arrived.
 */
export function assertCanonicalGetTransactionActionData(
  actionData: unknown,
): asserts actionData is GetTransactionActionData {
  if (typeof actionData !== "object" || actionData === null || Array.isArray(actionData)) {
    throw new GetTransactionActionDataShapeError(
      "get_transaction__v1 action data must be a plain object",
    );
  }
  const keys = Object.keys(actionData as Record<string, unknown>);
  if (keys.length !== 1 || keys[0] !== KEY_PUBLIC_FIELD) {
    throw new GetTransactionActionDataShapeError(
      `get_transaction__v1 action data must carry exactly the "${KEY_PUBLIC_FIELD}" field; got [${keys.join(", ")}]`,
    );
  }
  const value = (actionData as Record<string, unknown>)[KEY_PUBLIC_FIELD];
  if (typeof value !== "string" || value.length === 0) {
    throw new GetTransactionActionDataShapeError(
      `get_transaction__v1 action data's "${KEY_PUBLIC_FIELD}" must be a non-empty string`,
    );
  }
}

// canonical get_transaction__v1 action-data codec. Proves the builder produces
// exactly the wire shape the byte-exact signing rule's frozen serializer expects, and that the shape
// assertion is a real fail-closed drift guard: it rejects the defect this codec exists to
// make unrepresentable (the legacy `public_key_base64urlsafe` field name that shipped at
// receive-settle-step.ts's confirm-read), plus every other way an
// action-data object could stop being the canonical one.
import { describe, expect, it } from "vitest";

import { buildGatewayActionRequest } from "./request.js";
import {
  GetTransactionActionDataShapeError,
  assertCanonicalGetTransactionActionData,
  buildGetTransactionActionData,
} from "./action-data.js";

const WALLET_KEY = "wallet-public-key-base64url";

describe("get_transaction__v1 canonical action-data codec", () => {
  it("builds exactly one field, the canonical key_public__base64urlsafe spelling", () => {
    const actionData = buildGetTransactionActionData(WALLET_KEY);
    expect(actionData).toEqual({ key_public__base64urlsafe: WALLET_KEY });
    expect(Object.keys(actionData)).toEqual(["key_public__base64urlsafe"]);
  });

  it("the built action data reaches the wire unchanged — the byte-exact signing rule byte-exactness", () => {
    const request = buildGatewayActionRequest(
      "get_transaction__v1",
      buildGetTransactionActionData(WALLET_KEY),
    );
    const body = new TextDecoder().decode(request.bodyBytes);
    const decoded = JSON.parse(decodeURIComponent(body.slice(body.indexOf("=") + 1))) as {
      action_name: string;
      action_data: unknown;
    };
    expect(decoded.action_name).toBe("get_transaction__v1");
    expect(decoded.action_data).toEqual({ key_public__base64urlsafe: WALLET_KEY });
    // The exact encoded fragment a wire-level (form-decoding) fake matches against — proves
    // the canonical field name, not just an equivalent re-parsed object.
    expect(body).toContain(encodeURIComponent(`"key_public__base64urlsafe":"${WALLET_KEY}"`));
  });

  it("accepts the canonical shape and nothing else", () => {
    expect(() =>
      assertCanonicalGetTransactionActionData({ key_public__base64urlsafe: WALLET_KEY }),
    ).not.toThrow();
  });

  it("rejects the exact legacy defect this codec fixes (regression guard)", () => {
    expect(() =>
      assertCanonicalGetTransactionActionData({ public_key_base64urlsafe: WALLET_KEY }),
    ).toThrow(GetTransactionActionDataShapeError);
  });

  it("rejects an extra key alongside the canonical one", () => {
    expect(() =>
      assertCanonicalGetTransactionActionData({
        key_public__base64urlsafe: WALLET_KEY,
        extra: "field",
      }),
    ).toThrow(GetTransactionActionDataShapeError);
  });

  it("rejects a missing, empty, non-string, null, or non-object action data", () => {
    expect(() => assertCanonicalGetTransactionActionData({})).toThrow(
      GetTransactionActionDataShapeError,
    );
    expect(() =>
      assertCanonicalGetTransactionActionData({ key_public__base64urlsafe: "" }),
    ).toThrow(GetTransactionActionDataShapeError);
    expect(() =>
      assertCanonicalGetTransactionActionData({ key_public__base64urlsafe: 12345 }),
    ).toThrow(GetTransactionActionDataShapeError);
    expect(() => assertCanonicalGetTransactionActionData(null)).toThrow(
      GetTransactionActionDataShapeError,
    );
    expect(() => assertCanonicalGetTransactionActionData(undefined)).toThrow(
      GetTransactionActionDataShapeError,
    );
    expect(() => assertCanonicalGetTransactionActionData("not-an-object")).toThrow(
      GetTransactionActionDataShapeError,
    );
    expect(() => assertCanonicalGetTransactionActionData([WALLET_KEY])).toThrow(
      GetTransactionActionDataShapeError,
    );
  });
});

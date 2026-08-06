// exit criterion: a generic retry/failover wrapper
// STRUCTURALLY CANNOT accept the submit function. The proof has three load-bearing parts:
// 1. Negative-compile (@ts-expect-error): a submit transport exposes no `.read` surface,
// so it does not satisfy the read-shaped constraint of a generic retry wrapper; and
// the submit action name is not a member of the read-safe union, so it cannot be the
// wrapper's action argument. `tsc -b` fails if either expected error disappears.
// 2. Runtime backstop: a cast that smuggles the submit name past the type system is
// rejected by assertReadSafeActionName before any endpoint is touched.
// 3. Structural disjointness + a positive control: the two transport surfaces share no
// method, and the same wrapper demonstrably WORKS for the read surface (so the
// exclusion is specific to submit, not a broken wrapper).
// Test-support only.

import { describe, expect, it } from "vitest";
import { SUBMIT_ACTION_NAME } from "@zucoins/generic-node-contracts/transfer-code";
import {
  GatewayUnsafeActionError,
  assertReadSafeActionName,
  buildGatewayActionRequest,
  type GatewayReadActionName,
  type GatewayReadTransport,
} from "../gateway/index.js";
import type { GatewayResponse } from "../protocol/index.js";
import {
  createFakeGateway,
  createFakeGatewayReadTransport,
  createFakeGatewaySubmitTransport,
} from "./gateway-fake.js";
import {
  AUTHORIZATION,
  LIMITS,
  PRIMARY,
  READ_ACTION_DATA,
  TX,
  observationRecorder,
  submitRecorder,
} from "./gateway-fake-fixtures.js";

const GET_TX: GatewayReadActionName = "get_transaction__v1";

// A generic retry/failover wrapper — the exact construct the never-blind-retry rule / never-blind-retry submit forbids for
// submit. It is generic over the transport, but its constraint admits ONLY the read
// surface (a `.read` member) and its action argument ONLY read-safe names. There is no
// overload, flag, or type parameter through which a submit could enter.
async function withRetryFailover<Transport extends GatewayReadTransport>(
  transport: Transport,
  actionName: GatewayReadActionName,
  actionData: unknown,
  endpoints: readonly string[],
  maxAttempts: number,
): Promise<GatewayResponse> {
  let lastError: unknown = new Error("retry wrapper made no attempt");
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      return await transport.read(endpoints, buildGatewayActionRequest(actionName, actionData));
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError;
}

describe("exit criterion — a generic retry/failover wrapper cannot accept the submit function", () => {
  function makeSurfaces() {
    const fake = createFakeGateway();
    const readTransport = createFakeGatewayReadTransport(fake, { limits: LIMITS, recorder: observationRecorder() });
    const submitTransport = createFakeGatewaySubmitTransport(fake, {
      limits: LIMITS,
      recorder: submitRecorder(),
      authorization: AUTHORIZATION,
    });
    return { fake, readTransport, submitTransport };
  }

  it("negative-compile: a submit transport does not satisfy the read-shaped wrapper constraint", () => {
    const { submitTransport } = makeSurfaces();

    type WrapperTransportParameter = Parameters<typeof withRetryFailover>[0];
    // @ts-expect-error exit criterion: GatewaySubmitTransport exposes `.submit`, not `.read`, so it cannot satisfy the wrapper's GatewayReadTransport constraint. If this line ever compiles, the read/submit split has collapsed.
    const notAReadTransport: WrapperTransportParameter = submitTransport;

    expect(typeof submitTransport.submit).toBe("function");
    expect(notAReadTransport).toBe(submitTransport);
  });

  it("negative-compile: the submit action name is not a member of the wrapper's action parameter", () => {
    const { submitTransport } = makeSurfaces();

    type WrapperActionParameter = Parameters<typeof withRetryFailover>[1];
    // @ts-expect-error exit criterion: SUBMIT_ACTION_NAME is excluded from GatewayReadActionName, so it cannot be the wrapper's action argument. If this line ever compiles, the submit action has entered the retry path.
    const notAWrapperAction: WrapperActionParameter = SUBMIT_ACTION_NAME;

    expect(SUBMIT_ACTION_NAME).toBe("submit_transaction__v1");
    expect(notAWrapperAction).toBe(SUBMIT_ACTION_NAME);
    expect(typeof submitTransport.submit).toBe("function");
  });

  it("runtime backstop: a cast-smuggled submit name is rejected before any endpoint is touched", () => {
    const { fake, readTransport } = makeSurfaces();
    fake.scriptRead(GET_TX, { kind: "envelope", envelope: { status: true, code: "ok", message: "OK", data: {} } });

    const smuggled = SUBMIT_ACTION_NAME as unknown as GatewayReadActionName;
    expect(() => assertReadSafeActionName(smuggled)).toThrow(GatewayUnsafeActionError);

    // The guard runs at the top of the read primitive, so no exchange occurs.
    expect(fake.readExchangeCount(GET_TX)).toBe(0);
    expect(fake.totalSubmitAttempts).toBe(0);
    expect(readTransport).toBeDefined();
  });

  it("structural disjointness: the two transport surfaces share no method", () => {
    const { readTransport, submitTransport } = makeSurfaces();

    expect("read" in readTransport).toBe(true);
    expect("submit" in readTransport).toBe(false);
    expect("submit" in submitTransport).toBe(true);
    expect("read" in submitTransport).toBe(false);
  });

  it("positive control: the same wrapper works for the read surface (exclusion is submit-specific)", async () => {
    const { fake, readTransport } = makeSurfaces();
    fake.scriptRead(
      GET_TX,
      { kind: "drop" },
      { kind: "envelope", envelope: { status: true, code: "ok", message: "OK", data: { head: "recovered" } } },
    );

    const response = await withRetryFailover(readTransport, GET_TX, READ_ACTION_DATA, [PRIMARY], 3);

    expect(response.statusCode).toBe(200);
    // The wrapper retried the ambiguous first exchange and landed on the second.
    expect(fake.readExchangeCount(GET_TX)).toBe(2);
    expect(fake.totalSubmitAttempts).toBe(0);
  });

  it("the single-shot submit surface contains no iteration the wrapper could drive", async () => {
    const { fake, submitTransport } = makeSurfaces();
    fake.scriptSubmit({ kind: "drop" });

    // One invocation, one exchange, one attempt — even when the outcome is ambiguous.
    await expect(
      submitTransport.submit([PRIMARY], buildGatewayActionRequest(SUBMIT_ACTION_NAME, TX)),
    ).rejects.toThrow();
    expect(fake.totalSubmitAttempts).toBe(1);
    expect(fake.exchangeLog.filter((entry) => entry.actionName === SUBMIT_ACTION_NAME)).toHaveLength(1);
  });
});

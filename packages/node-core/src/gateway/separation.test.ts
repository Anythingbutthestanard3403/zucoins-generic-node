// the structural read/submit separation guarantee (the never-blind-retry rule /
// never-blind-retry submit), mirroring the retired v1 FailoverSafeActionName fixture
// (packages/splitchain/src/failover.ts, reference-only). Three independent layers:
// 1. type-level exclusion — the submit literal does not type-check in the read
// primitive's parameter position (negative-compile fixtures via @ts-expect-error,
// enforced by tsc: if the exclusion ever breaks, the directive becomes "unused"
// and the build fails);
// 2. runtime guard — a cast bypass (`as unknown as`) is rejected before any endpoint
// is touched;
// 3. source structure — the single-shot module contains no iteration construct and
// the two paths never import each other (the shared low-level exchange in
// capture.ts is the only common dependency, by design).
import { SUBMIT_ACTION_NAME } from "@zucoins/generic-node-contracts/transfer-code";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { READ_SAFE_ACTION_NAMES, GatewayUnsafeActionError, type GatewayReadActionName } from "./actions.js";
import { readGatewayAction } from "./read.js";
import { submitGatewayActionOnce } from "./submit.js";
import { sha256Hex, type GatewayExchangeTransport } from "./capture.js";
import { fingerprintEndpoint } from "./client.js";
import type { GatewayLimits } from "./types.js";

describe("type-level exclusion — negative compile fixtures (the never-blind-retry rule, layer 1)", () => {
  it("the submit literal is not assignable to the read-safe union", () => {
    // @ts-expect-error — submit_transaction__v1 is deliberately absent from GatewayReadActionName
    const notReadSafe: GatewayReadActionName = SUBMIT_ACTION_NAME;
    expect(notReadSafe).toBe(SUBMIT_ACTION_NAME);
  });

  it("the submit literal is not assignable to the read primitive's parameter position", () => {
    type ReadActionParameter = Parameters<typeof readGatewayAction>[0];
    // @ts-expect-error — readGatewayAction's first parameter excludes the submit action
    const notAReadParameter: ReadActionParameter = SUBMIT_ACTION_NAME;
    expect(notAReadParameter).toBe(SUBMIT_ACTION_NAME);
  });

  it("the read-safe union is exactly the five read-safe actions, submit absent", () => {
    // Suffixed push literals transcribed from wallet 200.6 (ZTR-1152). This assertion
    // pins OUR OUTPUT only — the host's acceptance is verified by the boot-lane push
    // action-vocabulary probe, not by this suite.
    expect(READ_SAFE_ACTION_NAMES).toEqual([
      "get_transaction__v1",
      "push_notification__subscribe__v1__tos2d5b5md",
      "push_notification__has_subscription_for_public_key_base64urlsafe__v1__jxqlqcj5zv",
      "push_notification__send_to_public_key_base64urlsafe__v1__jc34lsh7ps",
      "push_notification__get_app_server_public_key__v1__nozleh4wul",
    ]);
    expect(READ_SAFE_ACTION_NAMES as readonly string[]).not.toContain(SUBMIT_ACTION_NAME);
  });
});

describe("runtime guard — cast bypass rejected before any endpoint is touched (layer 2)", () => {
  const LIMITS: GatewayLimits = {
    readTimeoutMs: 1_000,
    maxRequestBytes: 1_024,
    maxResponseBytes: 1_024,
  };

  it("readGatewayAction rejects the submit action forced through a cast", async () => {
    const touched: string[] = [];
    const exchange: GatewayExchangeTransport = {
      exchange: async (endpoint) => {
        touched.push(endpoint);
        return {
          endpoint,
          endpointFingerprint: fingerprintEndpoint(endpoint),
          requestBytes: Uint8Array.from([]),
          requestSha256: sha256Hex(Uint8Array.from([])),
          responseBytes: Uint8Array.from([]),
          responseSha256: sha256Hex(Uint8Array.from([])),
          statusCode: 200,
        };
      },
    };
    const bypassed = SUBMIT_ACTION_NAME as unknown as GatewayReadActionName;
    await expect(
      readGatewayAction(bypassed, {}, {
        endpoints: ["https://gateway-a.invalid/"],
        limits: LIMITS,
        recorder: { recordObservation: async () => undefined },
        exchange,
      }),
    ).rejects.toBeInstanceOf(GatewayUnsafeActionError);
    expect(touched.length).toBe(0);
  });
});

describe("source structure — the paths cannot reach each other (layer 3)", () => {
  const submitSource = readFileSync(fileURLToPath(new URL("./submit.ts", import.meta.url)), "utf8");
  const readSource = readFileSync(fileURLToPath(new URL("./read.ts", import.meta.url)), "utf8");

  it("the single-shot module contains no iteration construct", () => {
    expect(submitSource).not.toMatch(/\bfor\s*\(/);
    expect(submitSource).not.toMatch(/\bwhile\s*\(/);
    expect(submitSource).not.toMatch(/\bdo\s*\{/);
  });

  it("neither path imports the other — the shared exchange is the only common dependency", () => {
    expect(submitSource).not.toContain('from "./read.js"');
    expect(readSource).not.toContain('from "./submit.js"');
    expect(submitSource).toContain('from "./capture.js"');
    expect(readSource).toContain('from "./capture.js"');
  });

  it("the single-shot module cannot branch on operation kind — no kind literal appears", () => {
    expect(submitSource).not.toContain("SEND_EXTERNAL");
    expect(submitSource).not.toContain("MOVE_INTERNAL");
    expect(submitSource).not.toContain("RECEIVE_EXTERNAL");
  });

  it("every shot requires an explicit submit decision authorization (arity backstop)", () => {
    expect(submitGatewayActionOnce.length).toBe(4);
  });
});

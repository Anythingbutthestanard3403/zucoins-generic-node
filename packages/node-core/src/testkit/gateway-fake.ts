// the canonical deterministic in-process fake SplitChain gateway for
// test entrypoints. One instance is a pure function of its script — ZERO network access
// the only surface is a GatewayFetchFn for the frozen exchange transport
// (capture.ts), never a listening server. Requests are parsed exactly as the real
// gateway receives them (production gateway transport; via gateway-fake-wire.ts) and responses are exactly the
// frozen `{status, code, message, data}` envelope — the adapter never emits a wire field
// the real gateway does not.
//
// Scripting is keyed by action_name and covers the full vocabulary: all five read-safe
// actions and submit_transaction__v1 (the submit literal comes from the frozen
// transfer-code concern, never re-declared). Per action the script is a queue of
// outcomes; each exchange consumes the next entry and the FINAL entry is sticky (it
// keeps serving once the queue is empty), so a steady state needs one entry and a
// failure budget needs exactly that many. An action with NO script fails closed.
//
// The never-blind-retry rule surfaces: `submitAttemptCountForKey` / `totalSubmitAttempts` mirror the
// gateway-side view of gateway_submit_attempts so tests assert "exactly one
// submit attempt, ever" — including under injected lag, drops, and timeouts, where the
// attempt STILL counts (a missing response does not prove the POST did not land). The
// submit surface is single-shot by construction: it wraps the production single-shot
// primitive, which contains no iteration construct; the read surface wraps the bounded
// read primitive and is the ONLY surface a retry schedule may touch.
//
// Test-support only — production src/ must never import testkit (, enforced by
// packages/node-core/test/boundaries.test.ts).

import { SUBMIT_ACTION_NAME } from "@zucoins/generic-node-contracts/transfer-code";

import {
  READ_SAFE_ACTION_NAMES,
  assertReadSafeActionName,
  createGatewayExchangeTransport,
  createGatewayReadCredentials,
  createGatewayReadTransport,
  createGatewaySubmitCredentials,
  createSingleShotSubmitTransport,
  sha256Hex,
  type GatewayFetchFn,
  type GatewayFetchInit,
  type GatewayFetchResponse,
  type GatewayLimits,
  type GatewayReadActionName,
  type GatewayReadTransport,
  type GatewaySubmitTransport,
  type NowIsoFn,
  type ObservationRecorder,
  type SleepFn,
  type SubmitAttemptRecorder,
  type SubmitAuthorization,
} from "../gateway/index.js";
import type { GatewayReadTransportOptions, SingleShotSubmitTransportOptions } from "../gateway/index.js";
import {
  parseGatewayFormBody,
  serializeGatewayEnvelope,
  type FakeGatewayEnvelope,
} from "./gateway-fake-wire.js";

// One scripted exchange outcome. `envelope` serves the frozen wire envelope (HTTP status
// defaults to 200); `empty-body` serves a head-only success (status line + headers, zero
// body bytes); `raw-body` serves arbitrary non-envelope bytes (malformed-body paths);
// `drop` severs the connection mid-exchange (the exchange's effect is unknown — the
// attempt STILL counts); `timeout` never responds (the caller's abort signal ends the
// exchange); `lag` delays, then resolves the wrapped outcome.
export type FakeGatewayScriptedOutcome =
  | { readonly kind: "envelope"; readonly envelope: FakeGatewayEnvelope; readonly httpStatus?: number }
  | { readonly kind: "empty-body"; readonly httpStatus: number }
  | { readonly kind: "raw-body"; readonly httpStatus: number; readonly body: string }
  | { readonly kind: "drop" }
  | { readonly kind: "timeout" }
  | { readonly kind: "lag"; readonly delayMs: number; readonly then: FakeGatewayScriptedOutcome };

// The crash-injection points, modeled as scripted gateway-side
// states: each names where the node dies relative to the single shot, which fixes what
// the gateway observes (nothing / an attempt with no response / an accepted landing).
export const SUBMIT_CRASH_HOLD_POINTS = [
  "before-signed-bytes-persist",
  "after-persist-before-submit",
  "during-submit-no-response",
  "after-acceptance-before-local-ack",
  "after-local-ack-before-event-emission",
  "during-reconciliation",
  "before-outbox-delivery",
  "after-outbox-delivery",
] as const;

export type SubmitCrashHoldPoint = (typeof SUBMIT_CRASH_HOLD_POINTS)[number];

// The gateway-side acceptance verdict served at the acceptance hold points: a 2xx
// status:true acknowledgement — receipt only, never a settlement verdict (C-09).
export const SUBMIT_ACK_ENVELOPE: FakeGatewayEnvelope = Object.freeze({
  status: true,
  code: "ok",
  message: "OK",
  data: Object.freeze({}),
});

// The wallet identity a submit attempt is counted under: the frozen v2 inner's sender
// public key when the action_data carries one. Pure and defensive: anything else yields
// null and the caller falls back to the request-body digest (below).
export function walletKeyForSubmitActionData(actionData: unknown): string | null {
  if (typeof actionData !== "object" || actionData === null) {
    return null;
  }
  const inner = (actionData as { inner?: unknown }).inner;
  if (typeof inner !== "object" || inner === null) {
    return null;
  }
  const key = (inner as { step_1_key_public__base64urlsafe?: unknown }).step_1_key_public__base64urlsafe;
  if (typeof key !== "string" || key === "") {
    return null;
  }
  return key;
}

// One exchange the fake observed, in arrival sequence — the assertion surface for
// "exactly one submit attempt, ever" and for wire-form byte-identity checks.
export interface FakeGatewayExchangeEntry {
  readonly actionName: string;
  readonly endpoint: string;
  readonly requestBytes: Uint8Array;
  readonly actionData: unknown;
  readonly outcomeKind: FakeGatewayScriptedOutcome["kind"];
}

// Raised when an exchange targets an action with no scripted outcome at all. Fail-closed
// so an unscripted action surfaces as a test-authoring bug, never as a silent success.
export class FakeGatewayScriptExhaustedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FakeGatewayScriptExhaustedError";
  }
}

// Injectable lag seam: resolves after `ms`, or rejects the moment the exchange's abort
// signal fires — whichever comes first. Tests pin determinism; production of the fake
// (i.e. its default) uses the real timer.
export type FakeGatewayDelayFn = (ms: number, signal: AbortSignal) => Promise<void>;

const defaultDelay: FakeGatewayDelayFn = async (ms, signal) => {
  await new Promise<void>((resolve, reject) => {
    if (signal.aborted) {
      reject(signal.reason instanceof Error ? signal.reason : new Error("exchange aborted"));
      return;
    }
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(signal.reason instanceof Error ? signal.reason : new Error("exchange aborted"));
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal.addEventListener("abort", onAbort, { once: true });
  });
};

// Never resolves on its own: rejects only when the caller's abort signal fires — the
// bare-timeout outcome (the exchange's effect stays unknown, the never-blind-retry rule territory).
async function awaitAbort(signal: AbortSignal): Promise<never> {
  await new Promise<never>((_resolve, reject) => {
    if (signal.aborted) {
      reject(signal.reason instanceof Error ? signal.reason : new Error("exchange aborted"));
      return;
    }
    signal.addEventListener(
      "abort",
      () => reject(signal.reason instanceof Error ? signal.reason : new Error("exchange aborted")),
      { once: true },
    );
  });
  throw new Error("unreachable");
}

export interface FakeGatewayOptions {
  readonly delay?: FakeGatewayDelayFn;
}

export interface FakeGateway {
  // The injectable transport — hand to createGatewayExchangeTransport as fetchFn.
  readonly fetch: GatewayFetchFn;

  // Queue outcomes for one read-safe action (append; the final entry is sticky).
  scriptRead(actionName: GatewayReadActionName, ...outcomes: FakeGatewayScriptedOutcome[]): void;
  // Queue outcomes for submit_transaction__v1 (append; the final entry is sticky).
  scriptSubmit(...outcomes: FakeGatewayScriptedOutcome[]): void;
  // Script the gateway-side state at one crash-injection point.
  scriptSubmitHoldPoint(point: SubmitCrashHoldPoint): void;
  // Drop every script and counter — one instance per scenario is still the norm.
  reset(): void;

  // Gateway-side truth. totalSubmitAttempts counts EVERY submit POST that reached the
  // fake — including drops, lags, and timeouts (a missing response does not prove the
  // POST did not land). submitAttemptCountForKey keys by the sender wallet public key,
  // falling back to `digest:<sha256 of the exact request bytes>` when the action_data
  // carries no wallet identity — the per-unique-signed-body view.
  readonly totalSubmitAttempts: number;
  submitAttemptCountForKey(key: string): number;
  readExchangeCount(actionName: GatewayReadActionName): number;
  readonly exchangeLog: readonly FakeGatewayExchangeEntry[];

  // The fake's chain: a submit accepted with a 2xx status:true envelope lands under its
  // wallet key, so reconciliation reads and landing assertions have a gateway-side truth
  // to check against (head-only — the latest accepted submission per wallet).
  headOf(walletKey: string): unknown;
  landedCountForKey(walletKey: string): number;
}

export function createFakeGateway(options: FakeGatewayOptions = {}): FakeGateway {
  const delay = options.delay ?? defaultDelay;
  const readScripts = new Map<string, FakeGatewayScriptedOutcome[]>();
  const submitScript: FakeGatewayScriptedOutcome[] = [];
  const submitAttemptsByKey = new Map<string, number>();
  const readCountsByAction = new Map<string, number>();
  const landedByKey = new Map<string, unknown[]>();
  const log: FakeGatewayExchangeEntry[] = [];
  let totalSubmitAttempts = 0;

  function nextOutcome(actionName: string): FakeGatewayScriptedOutcome {
    const queue = actionName === SUBMIT_ACTION_NAME ? submitScript : readScripts.get(actionName);
    if (queue === undefined || queue.length === 0) {
      throw new FakeGatewayScriptExhaustedError(
        `fake gateway has no scripted outcome for action ${actionName}`,
      );
    }
    const outcome = queue.length === 1 ? queue[0] : queue.shift();
    if (outcome === undefined) {
      throw new FakeGatewayScriptExhaustedError(
        `fake gateway script for action ${actionName} is exhausted`,
      );
    }
    return outcome;
  }

  async function serve(
    outcome: FakeGatewayScriptedOutcome,
    signal: AbortSignal,
    actionName: string,
    actionData: unknown,
  ): Promise<GatewayFetchResponse> {
    switch (outcome.kind) {
      case "lag": {
        await delay(outcome.delayMs, signal);
        return await serve(outcome.then, signal, actionName, actionData);
      }
      case "envelope": {
        const status = outcome.httpStatus ?? 200;
        if (actionName === SUBMIT_ACTION_NAME && status >= 200 && status < 300 && outcome.envelope.status) {
          const key = walletKeyForSubmitActionData(actionData) ?? "anonymous";
          const landed = landedByKey.get(key) ?? [];
          landed.push(actionData);
          landedByKey.set(key, landed);
        }
        return toFetchResponse(status, serializeGatewayEnvelope(outcome.envelope));
      }
      case "empty-body":
        return toFetchResponse(outcome.httpStatus, "");
      case "raw-body":
        return toFetchResponse(outcome.httpStatus, outcome.body);
      case "drop":
        throw new TypeError("fake gateway: connection severed before a response was produced");
      case "timeout":
        return await awaitAbort(signal);
    }
  }

  const fetch: GatewayFetchFn = async (endpoint, init: GatewayFetchInit) => {
    const parsed = parseGatewayFormBody(init.body);
    const { actionName, actionData } = parsed;
    if (actionName !== SUBMIT_ACTION_NAME) {
      assertReadSafeActionName(actionName);
    }

    if (actionName === SUBMIT_ACTION_NAME) {
      totalSubmitAttempts += 1;
      const key = walletKeyForSubmitActionData(actionData) ?? `digest:${sha256Hex(init.body)}`;
      submitAttemptsByKey.set(key, (submitAttemptsByKey.get(key) ?? 0) + 1);
    } else {
      readCountsByAction.set(actionName, (readCountsByAction.get(actionName) ?? 0) + 1);
    }

    const outcome = nextOutcome(actionName);
    log.push({ actionName, endpoint, requestBytes: init.body, actionData, outcomeKind: outcome.kind });
    return await serve(outcome, init.signal, actionName, actionData);
  };

  function scriptRead(
    actionName: GatewayReadActionName,
    ...outcomes: FakeGatewayScriptedOutcome[]
  ): void {
    assertReadSafeActionName(actionName);
    const queue = readScripts.get(actionName) ?? [];
    queue.push(...outcomes);
    readScripts.set(actionName, queue);
  }

  function scriptSubmit(...outcomes: FakeGatewayScriptedOutcome[]): void {
    submitScript.push(...outcomes);
  }

  function scriptSubmitHoldPoint(point: SubmitCrashHoldPoint): void {
    switch (point) {
      case "before-signed-bytes-persist":
      case "after-persist-before-submit":
        // The crash precedes the POST: the gateway observes nothing to script.
        return;
      case "during-submit-no-response":
        scriptSubmit({ kind: "drop" });
        return;
      case "after-acceptance-before-local-ack":
      case "after-local-ack-before-event-emission":
      case "before-outbox-delivery":
      case "after-outbox-delivery":
        scriptSubmit({ kind: "envelope", envelope: SUBMIT_ACK_ENVELOPE });
        return;
      case "during-reconciliation":
        // The gateway is unreadable for the whole reconciliation: one sticky drop per
        // read-safe action serves every read of the schedule.
        for (const actionName of READ_SAFE_ACTION_NAMES) {
          scriptRead(actionName, { kind: "drop" });
        }
        return;
    }
  }

  function reset(): void {
    readScripts.clear();
    submitScript.length = 0;
    submitAttemptsByKey.clear();
    readCountsByAction.clear();
    landedByKey.clear();
    log.length = 0;
    totalSubmitAttempts = 0;
  }

  return {
    fetch,
    scriptRead,
    scriptSubmit,
    scriptSubmitHoldPoint,
    reset,
    get totalSubmitAttempts(): number {
      return totalSubmitAttempts;
    },
    submitAttemptCountForKey: (key) => submitAttemptsByKey.get(key) ?? 0,
    readExchangeCount: (actionName) => {
      assertReadSafeActionName(actionName);
      return readCountsByAction.get(actionName) ?? 0;
    },
    get exchangeLog(): readonly FakeGatewayExchangeEntry[] {
      return [...log];
    },
    headOf: (walletKey) => {
      const landed = landedByKey.get(walletKey);
      return landed === undefined ? undefined : landed[landed.length - 1];
    },
    landedCountForKey: (walletKey) => landedByKey.get(walletKey)?.length ?? 0,
  };
}

function toFetchResponse(status: number, body: string): GatewayFetchResponse {
  const bytes = new TextEncoder().encode(body);
  const buffer = bytes.buffer as ArrayBuffer;
  return {
    status,
    arrayBuffer: async () => buffer,
  };
}

// The separated read surface over the fake: the production bounded read primitive with
// the fake's fetch as its only wire. Retry lives HERE and only here — bounded, jittered,
// ambiguity-only.
export interface FakeGatewayReadTransportOptions {
  readonly limits: GatewayLimits;
  readonly recorder: ObservationRecorder;
  readonly sleep?: SleepFn;
  readonly jitter?: () => number;
  readonly nowIso?: NowIsoFn;
  readonly maxAttempts?: number;
}

export function createFakeGatewayReadTransport(
  fake: FakeGateway,
  options: FakeGatewayReadTransportOptions,
): GatewayReadTransport {
  const transportOptions: GatewayReadTransportOptions = {
    ...options,
    credentials: createGatewayReadCredentials(),
    exchange: createGatewayExchangeTransport({ limits: options.limits, fetchFn: fake.fetch }),
  };
  return createGatewayReadTransport(transportOptions);
}

// The separated submit surface over the fake: the production single-shot primitive with
// the fake's fetch as its only wire. Contains no iteration construct — a retry schedule
// is structurally inexpressible through it (the never-blind-retry rule).
export interface FakeGatewaySubmitTransportOptions {
  readonly limits: GatewayLimits;
  readonly recorder: SubmitAttemptRecorder;
  readonly authorization: SubmitAuthorization;
  readonly nowIso?: NowIsoFn;
}

export function createFakeGatewaySubmitTransport(
  fake: FakeGateway,
  options: FakeGatewaySubmitTransportOptions,
): GatewaySubmitTransport {
  const transportOptions: SingleShotSubmitTransportOptions = {
    ...options,
    credentials: createGatewaySubmitCredentials(),
    exchange: createGatewayExchangeTransport({ limits: options.limits, fetchFn: fake.fetch }),
  };
  return createSingleShotSubmitTransport(transportOptions);
}

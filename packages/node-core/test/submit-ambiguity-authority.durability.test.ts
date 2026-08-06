// Durability half: kill-process/resume network-call counting (D1)
// and concurrent-worker race (D2). Governing: the data model; operation flows
// operations recovery; node-core; the test plan
// the never-blind-retry rule.
//
// What this file measures: outbound gateway POSTs across a crashed worker and a FRESH
// resumed worker for the same (operation_id, transaction_attempt_no). Total network-call
// count must be in {0, 1}, never 2. Losing concurrent claims must not create a second
// attempt or touch the transport.
//
// Production entry points exercised (not fakes of the claim logic):
//   - executeMoveSubmitClaim (MOVE_INTERNAL)
//   - receiveSubmitOnce (RECEIVE_EXTERNAL)
//   - createFakeGateway wire counter (gateway-side view of gateway_submit_attempts)
//
// Real-Postgres UNIQUE arbitration is in submit-ambiguity-authority.pg.test.ts and the
// landed sibling test/submit-decision-claim-store.pg.test.ts (229). The in-memory
// claim stores here are fixtures so the WIRE count is observable; they model the same
// uniqueness key the DDL freezes.

import { randomUUID } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  SUBMIT_ACTION_NAME,
  buildGatewayRequestBody,
} from "@zucoins/generic-node-contracts/transfer-code";

import {
  executeMoveSubmitClaim,
  type MoveSubmitClaim,
  type MoveSubmitClaimStore,
} from "../src/core/move-submit-claim.js";
import {
  receiveSubmitOnce,
  type SubmitClaimStore,
} from "../src/core/receive-submit-once.js";
import { createGatewayExchangeTransport } from "../src/gateway/capture.js";
import type { SubmitAuthorization } from "../src/gateway/submit.js";
import type { GatewayLimits } from "../src/gateway/types.js";
import type { GatewayRequest } from "../src/protocol/index.js";
import type { SubmitClaim } from "../src/protocol/reconcile/submit-authority.js";
import {
  LIMITS,
  PRIMARY,
  TX,
  WALLET_KEY,
  submitRecorder,
} from "../src/testkit/gateway-fake-fixtures.js";
import {
  SUBMIT_ACK_ENVELOPE,
  SUBMIT_CRASH_HOLD_POINTS,
  createFakeGateway,
  type FakeGateway,
  type SubmitCrashHoldPoint,
} from "../src/testkit/gateway-fake.js";

const SHORT_TIMEOUT: GatewayLimits = {
  readTimeoutMs: 20,
  maxRequestBytes: 4_096,
  maxResponseBytes: 4_096,
};

// Exact form body the production single-shot path POSTs — action_name must be
// submit_transaction__v1 so the fake gateway's wire counter registers the attempt.
const RECEIVE_REQUEST: GatewayRequest = {
  rpc: SUBMIT_ACTION_NAME,
  bodyBytes: new TextEncoder().encode(
    buildGatewayRequestBody(SUBMIT_ACTION_NAME, {
      // Nested so walletKeyForSubmitActionData (gateway-fake.ts) keys the attempt by WALLET_KEY.
      inner: { step_1_key_public__base64urlsafe: WALLET_KEY },
      step_1_signature: "sig-zkz",
    }),
  ),
};

function makeMoveClaimStore(): MoveSubmitClaimStore & { readonly mints: number } {
  const claims = new Map<string, MoveSubmitClaim>();
  let mints = 0;
  return {
    get mints() {
      return mints;
    },
    claimSubmitOnce: async (claim) => {
      const key = `${claim.operationId}#${claim.transactionAttemptNo}`;
      const existing = claims.get(key);
      if (existing !== undefined) {
        await Promise.resolve();
        return { claim: existing, minted: false };
      }
      claims.set(key, claim);
      mints += 1;
      await Promise.resolve();
      return { claim, minted: true };
    },
  };
}

function makeReceiveClaimStore(): SubmitClaimStore & {
  readonly claims: SubmitClaim[];
  readonly mints: number;
  seed(claim: { attemptId: string; operationId: string; transactionAttemptNo: number }): void;
} {
  const byKey = new Map<string, SubmitClaim & { operationId: string; transactionAttemptNo: number }>();
  const claims: SubmitClaim[] = [];
  let mints = 0;
  return {
    claims,
    get mints() {
      return mints;
    },
    seed(claim) {
      const key = `${claim.operationId}#${claim.transactionAttemptNo}`;
      const full = { ...claim, claimedAt: "2026-01-01T00:00:00.000Z" };
      byKey.set(key, full);
      claims.push(full);
    },
    claimSubmitOnce: async (claim) => {
      const key = `${claim.operationId}#${claim.transactionAttemptNo}`;
      const existing = byKey.get(key);
      if (existing !== undefined) {
        await Promise.resolve();
        return { claim: existing, minted: false };
      }
      byKey.set(key, claim);
      claims.push(claim);
      mints += 1;
      await Promise.resolve();
      return { claim, minted: true };
    },
  };
}

interface MoveRun {
  readonly fake: FakeGateway;
  readonly store: MoveSubmitClaimStore & { readonly mints: number };
  readonly authorization: SubmitAuthorization;
}

function newMoveRun(): MoveRun {
  return {
    fake: createFakeGateway(),
    store: makeMoveClaimStore(),
    authorization: {
      submitDecisionId: randomUUID(),
      operationId: randomUUID(),
      transactionAttemptNo: 1,
    },
  };
}

async function driveMove(run: MoveRun, limits: GatewayLimits = LIMITS): Promise<boolean> {
  const result = await executeMoveSubmitClaim({
    authorization: run.authorization,
    signedTransaction: TX,
    claimStore: run.store,
    submit: {
      endpoint: PRIMARY,
      limits,
      recorder: submitRecorder(),
      exchange: createGatewayExchangeTransport({ limits, fetchFn: run.fake.fetch }),
    },
  });
  return result.executed;
}

interface ReceiveRun {
  readonly fake: FakeGateway;
  readonly store: ReturnType<typeof makeReceiveClaimStore>;
  readonly authorization: SubmitAuthorization;
  readonly attemptId: string;
}

function newReceiveRun(): ReceiveRun {
  return {
    fake: createFakeGateway(),
    store: makeReceiveClaimStore(),
    authorization: {
      submitDecisionId: randomUUID(),
      operationId: randomUUID(),
      transactionAttemptNo: 1,
    },
    attemptId: randomUUID(),
  };
}

async function driveReceive(run: ReceiveRun, limits: GatewayLimits = LIMITS): Promise<void> {
  await receiveSubmitOnce({
    receiveAttemptId: run.attemptId,
    signedRequest: RECEIVE_REQUEST,
    authorization: run.authorization,
    submitOptions: {
      endpoint: PRIMARY,
      limits,
      recorder: submitRecorder(),
      exchange: createGatewayExchangeTransport({ limits, fetchFn: run.fake.fetch }),
    },
    claimStore: run.store,
  });
}

function assertWireAtMostOne(fake: FakeGateway, label: string): number {
  const posts = fake.totalSubmitAttempts;
  expect(posts, label).toBeLessThanOrEqual(1);
  expect(fake.submitAttemptCountForKey(WALLET_KEY), `${label}/wallet`).toBeLessThanOrEqual(1);
  return posts;
}

const PRE_SUBMIT_HOLD_POINTS: readonly SubmitCrashHoldPoint[] = [
  "before-signed-bytes-persist",
  "after-persist-before-submit",
];

const ackOnce = (fake: FakeGateway): void => {
  fake.scriptSubmit({ kind: "envelope", envelope: SUBMIT_ACK_ENVELOPE });
};

describe("D1 — kill/resume network-call count (MOVE_INTERNAL)", () => {
  async function crashThenRecover(point: SubmitCrashHoldPoint): Promise<number> {
    const run = newMoveRun();
    const reachedTheWire = !PRE_SUBMIT_HOLD_POINTS.includes(point);

    if (reachedTheWire) {
      run.fake.scriptSubmitHoldPoint(point);
      if (point === "during-reconciliation") {
        ackOnce(run.fake);
      }
      await driveMove(run);
    } else if (point === "after-persist-before-submit") {
      await run.store.claimSubmitOnce({
        attemptId: run.authorization.submitDecisionId,
        claimedAt: "2026-07-26T00:00:00.000Z",
        operationId: run.authorization.operationId,
        transactionAttemptNo: run.authorization.transactionAttemptNo,
      });
    }

    ackOnce(run.fake);
    await driveMove(run);

    return assertWireAtMostOne(run.fake, `crash:${point}`);
  }

  it("before-signed-bytes-persist — nothing claimed: recovery makes the ONE shot", async () => {
    expect(await crashThenRecover("before-signed-bytes-persist")).toBe(1);
  });

  it("after-persist-before-submit — claim spent: recovery sends NOTHING", async () => {
    expect(await crashThenRecover("after-persist-before-submit")).toBe(0);
  });

  it.each([
    "during-submit-no-response",
    "after-acceptance-before-local-ack",
    "after-local-ack-before-event-emission",
    "during-reconciliation",
    "before-outbox-delivery",
    "after-outbox-delivery",
  ] as const)("%s — shot already happened; recovery never repeats it", async (point) => {
    expect(await crashThenRecover(point)).toBe(1);
  });

  it("every hold point is covered and none exceeds one POST", async () => {
    const ledger = new Map<string, number>();
    for (const point of SUBMIT_CRASH_HOLD_POINTS) {
      ledger.set(point, await crashThenRecover(point));
    }
    expect(ledger.size).toBe(SUBMIT_CRASH_HOLD_POINTS.length);
    expect(Math.max(...ledger.values())).toBe(1);
  });

  it("INDETERMINATE (5xx) is one POST — ambiguity authorizes no second call after resume", async () => {
    const run = newMoveRun();
    run.fake.scriptSubmit({
      kind: "envelope",
      httpStatus: 503,
      envelope: { status: false, code: "unavailable", message: "unavailable", data: {} },
    });
    await driveMove(run);
    ackOnce(run.fake);
    await driveMove(run);
    expect(assertWireAtMostOne(run.fake, "indeterminate-resume")).toBe(1);
  });

  it("timeout is one POST — deadline expiry is not non-landing proof for a second shot", async () => {
    const run = newMoveRun();
    run.fake.scriptSubmit({ kind: "timeout" });
    await driveMove(run, SHORT_TIMEOUT);
    ackOnce(run.fake);
    await driveMove(run, SHORT_TIMEOUT);
    expect(assertWireAtMostOne(run.fake, "timeout-resume")).toBe(1);
  });
});

describe("D1 — kill/resume network-call count (RECEIVE_EXTERNAL)", () => {
  it("happy path: one ACK is one POST; resume under durable claim posts nothing more", async () => {
    const run = newReceiveRun();
    ackOnce(run.fake);
    await driveReceive(run);
    expect(run.fake.totalSubmitAttempts).toBe(1);

    ackOnce(run.fake);
    await driveReceive(run);
    expect(assertWireAtMostOne(run.fake, "receive-resume")).toBe(1);
  });

  it("crash after claim, before exchange: resume posts zero (claim already spent)", async () => {
    const run = newReceiveRun();
    run.store.seed({
      attemptId: run.attemptId,
      operationId: run.authorization.operationId,
      transactionAttemptNo: run.authorization.transactionAttemptNo,
    });

    ackOnce(run.fake);
    await driveReceive(run);

    expect(assertWireAtMostOne(run.fake, "receive-claim-only")).toBe(0);
    expect(run.fake.totalSubmitAttempts).toBe(0);
  });

  it("INDETERMINATE mid-flight: one POST across crash and resume", async () => {
    const run = newReceiveRun();
    run.fake.scriptSubmit({
      kind: "envelope",
      httpStatus: 503,
      envelope: { status: false, code: "unavailable", message: "unavailable", data: {} },
    });
    await driveReceive(run);
    expect(run.fake.totalSubmitAttempts).toBe(1);

    ackOnce(run.fake);
    await driveReceive(run);
    expect(assertWireAtMostOne(run.fake, "receive-indeterminate-resume")).toBe(1);
  });

  it("drop (severed connection): one POST — missing response is not non-landing authority", async () => {
    const run = newReceiveRun();
    run.fake.scriptSubmit({ kind: "drop" });
    await driveReceive(run);
    ackOnce(run.fake);
    await driveReceive(run);
    expect(assertWireAtMostOne(run.fake, "receive-drop-resume")).toBe(1);
  });
});

describe("D2 — concurrent-worker race (exactly one submit row/POST)", () => {
  it("eight MOVE workers racing one attempt produce exactly ONE POST", async () => {
    const run = newMoveRun();
    ackOnce(run.fake);

    const executed = await Promise.all(Array.from({ length: 8 }, () => driveMove(run)));

    expect(executed.filter(Boolean)).toHaveLength(1);
    expect(run.store.mints).toBe(1);
    expect(assertWireAtMostOne(run.fake, "race:move-eight")).toBe(1);
  });

  it("a MOVE worker that lost the claim never touches the transport", async () => {
    const run = newMoveRun();
    ackOnce(run.fake);
    await driveMove(run);
    const afterWinner = run.fake.totalSubmitAttempts;

    expect(await driveMove(run)).toBe(false);
    expect(run.fake.totalSubmitAttempts).toBe(afterWinner);
    expect(assertWireAtMostOne(run.fake, "race:move-loser")).toBe(1);
  });

  it("eight RECEIVE workers racing one attempt produce exactly ONE POST", async () => {
    // receiveSubmitOnce's seam is a single arbitrated claimSubmitOnce. The store
    // double below is the same atomic mint MOVE uses — no separate claimExists/persistClaim.
    const run = newReceiveRun();
    ackOnce(run.fake);

    await Promise.all(Array.from({ length: 8 }, () => driveReceive(run)));

    expect(run.store.mints).toBe(1);
    expect(assertWireAtMostOne(run.fake, "race:receive-eight")).toBe(1);
  });

  it("two distinct operations proceed concurrently without either being suppressed", async () => {
    const a = newMoveRun();
    const b = newMoveRun();
    ackOnce(a.fake);
    ackOnce(b.fake);
    await Promise.all([driveMove(a), driveMove(b)]);
    expect(assertWireAtMostOne(a.fake, "race:distinct-a")).toBe(1);
    expect(assertWireAtMostOne(b.fake, "race:distinct-b")).toBe(1);
  });
});

describe("SEND_EXTERNAL and MOVE_INTERNAL structural bounds", () => {
  // Real structural discharge of "SEND cannot insert submit rows" (not a kind-string tautology).
  // Mirrors submit-write-path.guard.test.ts: literal text scan of the SEND surface
  // so a future SEND submit orchestrator that reaches either factory fails closed here.
  it("SEND_EXTERNAL production surface never reaches either submit write-path factory", () => {
    const here = fileURLToPath(new URL(".", import.meta.url));
    const srcRoot = resolve(here, "../src");
    // Construct call-site needles dynamically so this file is not itself a false positive for
    // submit-write-path.guard.test.ts (which scans for the literal `makeX(` text).
    const factoryNames = ["makeSubmitDecisionClaimStore", "makeSubmitAttemptRecorder"] as const;
    const moduleMarkers = [
      "submit-decision-claim-store",
      "gateway_submit_attempts",
      "submit_decisions",
    ] as const;

    function listTsFiles(dir: string): string[] {
      return (readdirSync(dir, { recursive: true }) as string[])
        .map((entry) => join(dir, entry))
        .filter((file) => extname(file) === ".ts" && statSync(file).isFile())
        .filter((file) => !file.endsWith(".test.ts"));
    }

    const sendRoots = [resolve(srcRoot, "send"), resolve(srcRoot, "protocol/reconcile")];
    const sendFiles = sendRoots.flatMap((root) =>
      listTsFiles(root).filter((file) => {
        const base = relative(srcRoot, file).toLowerCase();
        return base.includes("send") || base.endsWith("reconcile/send.ts");
      }),
    );
    // Also pin the reconcile SEND module and prove core/ has no send-submit-claim module.
    const sendReconcile = resolve(srcRoot, "protocol/reconcile/send.ts");
    const targets = [...new Set([...sendFiles, sendReconcile])];
    expect(targets.length).toBeGreaterThan(0);

    for (const file of targets) {
      const text = readFileSync(file, "utf8");
      for (const name of factoryNames) {
        const call = `${name}(`;
        expect(text, `${relative(srcRoot, file)} must not contain ${call}`).not.toContain(call);
      }
      for (const marker of moduleMarkers) {
        expect(text, `${relative(srcRoot, file)} must not contain ${marker}`).not.toContain(marker);
      }
    }

    const coreFiles = readdirSync(resolve(srcRoot, "core")).filter((entry) => entry.endsWith(".ts"));
    expect(coreFiles).toContain("move-submit-claim.ts");
    expect(coreFiles).toContain("receive-submit-once.ts");
    // signing custody's bar is "SEND_EXTERNAL has no node submit function in its type graph", not "no
    // core/ filename says send" — SEND_EXTERNAL owns core/send-form-and-sign.ts and
    // core/send-crash-recovery.ts. What must stay unrepresentable is a SEND-named
    // submit/claim module, and — the substantive half — any SEND-named core module reaching a
    // submit write path at all, whatever it is called.
    const sendCoreFiles = coreFiles.filter((entry) => entry.toLowerCase().includes("send"));
    expect(
      sendCoreFiles.filter((entry) => /submit|claim/i.test(entry)),
      "core/ must carry no SEND-named submit-claim module",
    ).toEqual([]);
    for (const entry of sendCoreFiles) {
      const text = readFileSync(resolve(srcRoot, "core", entry), "utf8");
      for (const name of factoryNames) {
        expect(text, `core/${entry} must not contain ${name}(`).not.toContain(`${name}(`);
      }
      for (const marker of moduleMarkers) {
        expect(text, `core/${entry} must not contain ${marker}`).not.toContain(marker);
      }
    }

    // This durability suite itself must not import a SEND submit orchestrator.
    const selfText = readFileSync(fileURLToPath(import.meta.url), "utf8");
    expect(selfText).not.toMatch(/from ["'].*send.*submit/i);
    expect(selfText).toContain("executeMoveSubmitClaim");
    expect(selfText).toContain("receiveSubmitOnce");
  });

  it("MOVE_INTERNAL authorization is fixed at transactionAttemptNo=1; a second attempt is unrepresentable at the seam", async () => {
    const run = newMoveRun();
    expect(run.authorization.transactionAttemptNo).toBe(1);
    ackOnce(run.fake);
    await driveMove(run);

    ackOnce(run.fake);
    expect(await driveMove(run)).toBe(false);
    expect(assertWireAtMostOne(run.fake, "move-no-second-attempt")).toBe(1);
  });
});

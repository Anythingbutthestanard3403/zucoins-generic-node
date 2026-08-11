/**
 * degraded-mode fault-injection acceptance suite.
 *
 * Proves fail-closed money admission, metrics, and alerts under
 * real production seams (not test-local composers or hand-stamped gauges).
 *
 * Production surfaces (wired call sites — not test-local composers):
 *   signUnderLease({ assertMoneyAdmitted, assertCanOperate, assertWalletMaySign }),
 *   captureReceiveT0({ assertMoneyAdmitted }),
 *   handleGetStateSnapshot (DEFAULT_STATE_SNAPSHOT_CAPTURE_TIMEOUT_MS),
 *   runDeterministicBootRecovery → stopMoneyEngines,
 *   shouldStartMoneyWorkersAfterRecovery (boot-lane money-workers gate),
 *   executeMoveSubmitClaim/claimSubmitOnce under injected faults,
 *   evaluateReadinessFromProbes/readinessHttp, createStorageBackpressure,
 *   createGatedSigner/createHaltGate, createEndpointFailoverService,
 *   classifyRelationship + applyAnomalyAction + isSigningHalted,
 *   snapshotFromPoolPressure/applySnapshot, createMetricsHooks.
 *
 */

import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { evaluateReadinessFromProbes, readinessHttp } from "../src/api/health.js";
import {
  handleGetStateSnapshot,
  DEFAULT_STATE_SNAPSHOT_CAPTURE_TIMEOUT_MS,
} from "../src/api/state-snapshot.js";
import {
  assertNewMoneyWorkAdmitted,
  MoneyAdmissionRefusedError,
  shouldStartMoneyWorkersAfterRecovery,
} from "../src/core/money-admission.js";
import {
  createMoneyPathAdmissionPortsFromRuntime,
  createMoneySignerBoundaryDeps,
  createMoneyCaptureReceiveT0Params,
} from "../src/money-path-admission.js";
import {
  createMetricsHooks,
  createNodeMetrics,
  renderMetrics,
  type NodeMetrics,
  type OperationalMetricsSnapshot,
} from "../src/core/metrics.js";
import { snapshotFromPoolPressure } from "../src/core/metrics-snapshot.js";
import {
  executeMoveSubmitClaim,
  type MoveSubmitClaim,
  type MoveSubmitClaimStore,
} from "../src/core/move-submit-claim.js";
import { NodeCoreReadinessState } from "../src/core/readiness-state.js";
import {
  MoneyPathGatesMissingError,
  NotSignerLeaderError,
  signUnderLease,
  WalletSigningHaltedError,
  type ActiveLeaseRecord,
  type SignerAuditEntry,
  type SignerBoundaryDeps,
  type WalletSigningCapability,
} from "../src/core/signer-boundary.js";
import {
  runDeterministicBootRecovery,
  type BootRecoveryActions,
  type BootRecoveryStore,
  type OperationPhaseEvidence,
  type ActiveLeaseRow,
  type KeyCorrespondenceRow,
} from "../src/workers/boot-recovery.js";
import { captureReceiveT0, type SqlExecutor } from "../src/receive/t0-capture.js";
import type { AnomalyRecorder, EndpointDisagreementAnomaly } from "../src/gateway/anomaly.js";
import {
  GatewayTransportAmbiguityError,
  sha256Hex,
  type GatewayExchangeCapture,
  type GatewayExchangeTransport,
} from "../src/gateway/capture.js";
import { fingerprintEndpoint } from "../src/gateway/client.js";
import {
  createEndpointFailoverService,
  GatewayEndpointHaltError,
  type EndpointFailoverEvent,
  type EndpointFailoverRecorder,
} from "../src/gateway/failover.js";
import type { ReadGatewayRequestOptions } from "../src/gateway/read.js";
import type {
  GatewayObservationRecord,
  ObservationRecorder,
  SubmitAttemptRecorder,
} from "../src/gateway/records.js";
import type { GatewayLimits } from "../src/gateway/types.js";
import {
  classifyRelationship,
  establishesOrdinaryHead,
  type VerifiedSemanticState,
} from "../src/observation/classifier.js";
import {
  applyAnomalyAction,
  InMemoryAnomalyQuarantineStore,
  isSigningHalted,
  planActionForRelationship,
  type QuarantineOperationSnapshot,
  type QuarantineWalletSnapshot,
} from "../src/observation/quarantine.js";
import {
  createGatedSigner,
  createGatedWorker,
  createHaltGate,
  createSafetyAlertEvaluator,
  createStorageBackpressure,
  deriveSafetyAlertReadings,
  emptySafetyAlertMetricInput,
  OperationsHaltedError,
  OperatorHaltError,
  type AlertNotification,
  type SafetyAlertMetricInput,
  type StorageBackpressure,
} from "../src/operator/index.js";
import { InMemoryImplementerEventLog } from "../src/reporting/implementer-event-log.js";
import {
  createSnapshotService,
  InMemorySnapshotStore,
  SnapshotCaptureTimeoutError,
  type SnapshotStateReader,
} from "../src/reporting/snapshot-service.js";
import {
  SignerLeadership,
  tryAcquireSignerLeadership,
  type LeadershipLockClient,
  type LeadershipLockPool,
} from "../src/workers/leadership.js";
import { registerPgRequiredGuard } from "./pg-required-guard.ts";

const VERSION = "0.0.0-fixture";
const FIXED_TIME = "2026-07-27T12:00:00.000Z";
const now = () => FIXED_TIME;

const ENDPOINT_A = "https://gateway-a.invalid/";
const ENDPOINT_B = "https://gateway-b.invalid/";

const LIMITS: GatewayLimits = {
  readTimeoutMs: 1_000,
  maxRequestBytes: 1_024,
  maxResponseBytes: 1_024,
};

const BODY_OK = Uint8Array.from([1, 2, 3]);
const BODY_DIFF = Uint8Array.from([9, 9, 9]);

const PREIMAGE_TEXT = '{"rpc":"step_1","n":1}';
const PREIMAGE_SHA = createHash("sha256").update(PREIMAGE_TEXT, "utf8").digest("hex");

// ─── readiness / metrics / alerts (fault-derived) ───────────────────────────

function healthyReadiness(budget = 3): NodeCoreReadinessState {
  const state = new NodeCoreReadinessState({ observationFailureBudget: budget });
  state.markSchemaMigrated();
  state.setVaultAvailable(true);
  state.recordObservationReadSuccess();
  state.setLeadershipHeld(true);
  // Money admission is fail-closed on event signer until arm (ZTR-1221).
  state.setEventSignerAvailable(true);
  return state;
}

function processStampsFromFault(args: {
  readonly readiness: NodeCoreReadinessState;
  readonly databaseReachable: boolean;
  readonly backpressure: StorageBackpressure;
  readonly haltEngaged: boolean;
  readonly poolCapTotal?: number;
}): OperationalMetricsSnapshot {
  const bp = args.backpressure.snapshot();
  const storagePressure = bp.global.state === "CRITICAL" || bp.global.state === "HALTED";
  args.readiness.setStoragePressure(storagePressure);
  args.readiness.setHalted(args.haltEngaged);
  const refreshed = args.readiness.snapshot();
  const verdict = evaluateReadinessFromProbes(refreshed, args.databaseReachable);
  return snapshotFromPoolPressure(
    {
      availableWalletCount: 0,
      capCount: 0,
      capUtilizationPercent: 0,
      poolCapTotal: args.poolCapTotal ?? 1,
      pinnedWalletCount: 0,
      queueDepth: 0,
      oldestQueuedAgeSecs: 0,
      oldestReceiveLeaseAgeSecs: 0,
    },
    {
      storagePressure,
      signerLeadershipHeld: refreshed.leadershipLockHeld,
      haltEngaged: args.haltEngaged,
      readinessReady: verdict.ready,
      observationDegraded: refreshed.observationDegraded,
      poolCapTotal: args.poolCapTotal ?? 1,
    },
  );
}

function applyDerivedMetrics(
  metrics: NodeMetrics,
  args: Parameters<typeof processStampsFromFault>[0],
): OperationalMetricsSnapshot {
  const snap = processStampsFromFault(args);
  metrics.applySnapshot(snap);
  return snap;
}

function evaluateAlertsFromFault(input: SafetyAlertMetricInput): AlertNotification[] {
  const evaluator = createSafetyAlertEvaluator();
  const readings = deriveSafetyAlertReadings(input);
  return evaluator.evaluateAll(readings);
}

function alertInputFromFault(args: {
  readonly readiness: NodeCoreReadinessState;
  readonly backpressure: StorageBackpressure;
  readonly endpointDisagreementCount?: number;
  readonly invariantBreachCount?: number;
  readonly duplicateSubmitRejectionCount?: number;
  readonly regressionCount?: number;
  readonly pathGapCount?: number;
  readonly signerInFlightAmbiguous?: 0 | 1;
}): SafetyAlertMetricInput {
  const stamps = args.readiness.snapshot();
  const bp = args.backpressure.snapshot();
  return {
    ...emptySafetyAlertMetricInput(),
    storageUtilization: bp.global.utilization,
    signerLeadershipHeld: stamps.leadershipLockHeld ? 1 : 0,
    endpointDisagreementCount: args.endpointDisagreementCount ?? 0,
    invariantBreachCount: args.invariantBreachCount ?? 0,
    duplicateSubmitRejectionCount: args.duplicateSubmitRejectionCount ?? 0,
    regressionCount: args.regressionCount ?? 0,
    pathGapCount: args.pathGapCount ?? 0,
    signerInFlightAmbiguous: args.signerInFlightAmbiguous ?? 0,
  };
}

function makeCapability(
  walletId = "11111111-1111-4111-8111-111111111111",
  operationId = "22222222-2222-4222-8222-222222222222",
  epoch = 1n,
): WalletSigningCapability {
  return {
    walletId,
    operationId,
    leaseEpoch: epoch,
    purpose: "SPLITCHAIN_STEP_1",
    preimageText: PREIMAGE_TEXT,
    expectedPreimageSha256: PREIMAGE_SHA,
  };
}

function makeLease(cap: WalletSigningCapability): ActiveLeaseRecord {
  return {
    walletId: cap.walletId,
    operationId: cap.operationId,
    epoch: cap.leaseEpoch,
    role: "SEND_SOURCE",
    lifecycle: "ACTIVE",
  };
}

/**
 * Production deps via createMoneyPathAdmissionPortsFromRuntime —
 * the SAME factory apps/generic-node main.ts wires (not a test-only gate).
 * Faults inject into readiness/backpressure/quarantine; ports always present.
 */
function makeProductionSignDeps(args: {
  readonly readiness: NodeCoreReadinessState;
  readonly databaseReachable: boolean;
  readonly backpressure: StorageBackpressure;
  readonly leadership: SignerLeadership;
  readonly vault: { calls: number };
  readonly audit?: SignerAuditEntry[];
  readonly lease?: ActiveLeaseRecord;
  /** When set, assertWalletMaySign consults isSigningHalted on this store. */
  readonly quarantineStore?: InMemoryAnomalyQuarantineStore;
}): SignerBoundaryDeps {
  const audit = args.audit ?? [];
  const capLease = args.lease;
  const ports = createMoneyPathAdmissionPortsFromRuntime({
    snapshotReadiness: () => args.readiness.snapshot(),
    isDatabaseReachable: () => args.databaseReachable,
    backpressure: args.backpressure,
    getWallet:
      args.quarantineStore === undefined
        ? undefined
        : (walletId) => args.quarantineStore!.getWallet(walletId),
  });
  return createMoneySignerBoundaryDeps(
    {
      leadership: args.leadership,
      leaseReader: {
        readActiveLease: async (walletId: string) => {
          if (capLease !== undefined) {
            return capLease.walletId === walletId ? capLease : null;
          }
          return {
            walletId,
            operationId: "22222222-2222-4222-8222-222222222222",
            epoch: 1n,
            role: "SEND_SOURCE" as const,
            lifecycle: "ACTIVE" as const,
          };
        },
      },
      vaultSigner: {
        sign: async () => {
          args.vault.calls += 1;
          return "sig-bytes";
        },
      },
      auditLog: {
        append: async (entry: SignerAuditEntry) => {
          audit.push(entry);
        },
      },
      now: () => FIXED_TIME,
    },
    ports,
  );
}

/** Production pre_sign: halt-gated signUnderLease with money/storage/wallet ports. */
async function productionPreSign(args: {
  readonly readiness: NodeCoreReadinessState;
  readonly databaseReachable: boolean;
  readonly backpressure: StorageBackpressure;
  readonly leadership: SignerLeadership;
  readonly halt: ReturnType<typeof createHaltGate>;
  readonly capability: WalletSigningCapability;
  readonly vault: { calls: number };
  readonly audit?: SignerAuditEntry[];
  readonly lease?: ActiveLeaseRecord;
  readonly quarantineStore?: InMemoryAnomalyQuarantineStore;
}): Promise<"signed" | "refused"> {
  try {
    const deps = makeProductionSignDeps({
      readiness: args.readiness,
      databaseReachable: args.databaseReachable,
      backpressure: args.backpressure,
      leadership: args.leadership,
      vault: args.vault,
      audit: args.audit,
      lease: args.lease ?? makeLease(args.capability),
      quarantineStore: args.quarantineStore,
    });
    const gated = createGatedSigner(args.halt, {
      sign: async (cap: WalletSigningCapability) => {
        const result = await signUnderLease(deps, cap);
        return result.signature;
      },
    });
    await gated.sign(args.capability);
    return "signed";
  } catch (err) {
    if (
      err instanceof MoneyAdmissionRefusedError ||
      err instanceof OperationsHaltedError ||
      err instanceof OperatorHaltError ||
      err instanceof NotSignerLeaderError ||
      err instanceof WalletSigningHaltedError
    ) {
      return "refused";
    }
    throw err;
  }
}

function expectNotLeader(fn: () => unknown): void {
  expect(fn).toThrow(NotSignerLeaderError);
}

// ─── gateway helpers ────────────────────────────────────────────────────────

type ScriptStep =
  | { readonly kind: "capture"; readonly status: number; readonly body: Uint8Array }
  | { readonly kind: "ambiguous" };

function scriptedExchange(script: readonly ScriptStep[]): {
  readonly touched: string[];
  readonly exchange: GatewayExchangeTransport;
} {
  const touched: string[] = [];
  let index = 0;
  const exchange: GatewayExchangeTransport = {
    exchange: async (endpoint, request) => {
      touched.push(endpoint);
      const step = script[index];
      index += 1;
      if (step === undefined) {
        throw new Error("exchange script exhausted");
      }
      if (step.kind === "ambiguous") {
        throw new GatewayTransportAmbiguityError("scripted ambiguity", new Error("transport"));
      }
      const capture: GatewayExchangeCapture = {
        endpoint,
        endpointFingerprint: fingerprintEndpoint(endpoint),
        requestBytes: request.bodyBytes,
        requestSha256: sha256Hex(request.bodyBytes),
        responseBytes: step.body,
        responseSha256: sha256Hex(step.body),
        statusCode: step.status,
      };
      return capture;
    },
  };
  return { touched, exchange };
}

function recordingObserver(): {
  readonly records: GatewayObservationRecord[];
  readonly recorder: ObservationRecorder;
} {
  const records: GatewayObservationRecord[] = [];
  return {
    records,
    recorder: {
      recordObservation: async (record) => {
        records.push(record);
      },
    },
  };
}

function recordingAnomaly(): {
  readonly anomalies: EndpointDisagreementAnomaly[];
  readonly recorder: AnomalyRecorder;
} {
  const anomalies: EndpointDisagreementAnomaly[] = [];
  return {
    anomalies,
    recorder: {
      recordDisagreement: async (anomaly) => {
        anomalies.push(anomaly);
      },
    },
  };
}

function recordingFailover(): {
  readonly events: EndpointFailoverEvent[];
  readonly recorder: EndpointFailoverRecorder;
} {
  const events: EndpointFailoverEvent[] = [];
  return {
    events,
    recorder: {
      recordFailover: async (event) => {
        events.push(event);
      },
    },
  };
}

const readOptions = (
  exchange: GatewayExchangeTransport,
  recorder: ObservationRecorder,
): ReadGatewayRequestOptions => ({
  endpoints: [ENDPOINT_A, ENDPOINT_B],
  limits: LIMITS,
  recorder,
  exchange,
  sleep: async () => {},
  jitter: () => 0,
  maxAttempts: 2,
});

const attemptKey = (claim: MoveSubmitClaim): string =>
  `${claim.operationId}#${claim.transactionAttemptNo}`;

function makeClaimStore(): MoveSubmitClaimStore & {
  readonly mints: number;
  readonly uniquenessRejections: number;
} {
  const claims = new Map<string, MoveSubmitClaim>();
  let mints = 0;
  let uniquenessRejections = 0;
  return {
    get mints() {
      return mints;
    },
    get uniquenessRejections() {
      return uniquenessRejections;
    },
    claimSubmitOnce: async (claim) => {
      const key = attemptKey(claim);
      const existing = claims.get(key);
      if (existing !== undefined) {
        uniquenessRejections += 1;
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

// ─── test-plan classifier fixtures ───────────────────────────────────────────

const head = (
  sSignature: string,
  pSignature: string,
  semanticFingerprint: string,
): VerifiedSemanticState => ({
  isGenesis: false,
  sSignature,
  pSignature,
  semanticFingerprint,
});

const STATE_A = head("sigA", "", "fpA");
const STATE_B = head("sigB", "sigA", "fpB");
const STATE_C = head("sigC", "sigB", "fpC");
const STATE_A_EQUIV = head("sigA", "", "fpA");
const STATE_A_COLLISION = head("sigA", "", "fpCollision");
const STATE_JUMP = head("sigZ", "sigUnrelated", "fpZ");
const GENESIS: VerifiedSemanticState = {
  isGenesis: true,
  sSignature: "",
  pSignature: "",
  semanticFingerprint: "fpGen",
};

function classify(
  prior: VerifiedSemanticState | null,
  next: VerifiedSemanticState,
  history: readonly string[],
  priorHistoryHasNonGenesis = history.some((s) => s.length > 0),
) {
  return classifyRelationship({
    prior,
    next,
    priorHistoryHasNonGenesis,
    acceptedStateSignatureHistory: history,
  });
}

function seedLeasedWallet(
  store: InMemoryAnomalyQuarantineStore,
  walletId: string,
  leaseId: string,
  opId: string,
): void {
  const wallet: QuarantineWalletSnapshot = {
    walletId,
    state: "PINNED",
    quarantineReason: null,
    activeLeaseId: leaseId,
    signingHalted: false,
  };
  const op: QuarantineOperationSnapshot = {
    operationId: opId,
    walletId,
    kind: "SEND_EXTERNAL",
    status: "AWAITING_REDEMPTION",
    attentionRequired: false,
    attentionReason: null,
    attentionEpisode: 0,
  };
  store.seedWallet(wallet);
  store.seedOperation(op);
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. GATEWAY — recovery
// ═══════════════════════════════════════════════════════════════════════════


describe("production factory fail-closed (composition)", () => {
  it("createMoneyPathAdmissionPortsFromRuntime refuses observation-degraded without test-local lambdas", () => {
    const readiness = healthyReadiness(1);
    readiness.recordObservationReadFailure();
    const ports = createMoneyPathAdmissionPortsFromRuntime({
      snapshotReadiness: () => readiness.snapshot(),
      isDatabaseReachable: () => true,
      backpressure: createStorageBackpressure(),
    });
    // Object-literal production assigns (same shape as apps/generic-node main).
    const gates = {
      assertMoneyAdmitted: ports.assertMoneyAdmitted,
      assertCanOperate: ports.assertCanOperate,
      assertWalletMaySign: ports.assertWalletMaySign,
    };
    expect(() => gates.assertMoneyAdmitted()).toThrow(MoneyAdmissionRefusedError);
  });

  it("signUnderLease without money gates throws MoneyPathGatesMissingError (omit never admits)", () => {
    const leadership = new SignerLeadership();
    leadership.markAcquired();
    expect(() =>
      signUnderLease(
        {
          leadership,
          leaseReader: { readActiveLease: async () => null },
          vaultSigner: { sign: async () => "x" },
          auditLog: { append: async () => undefined },
        },
        makeCapability(),
      ),
    ).toThrow(MoneyPathGatesMissingError);
  });
});


describe("gateway degraded mode", () => {
  it("exhausting the observation failure budget flips readiness to degraded/503 and blocks new T0", async () => {
    const readiness = healthyReadiness(2);
    const backpressure = createStorageBackpressure();
    const leadership = new SignerLeadership();
    leadership.markAcquired();
    const halt = createHaltGate("RUNNING");
    const metrics = createNodeMetrics();
    const hooks = createMetricsHooks(metrics);
    const vault = { calls: 0 };
    const capability = makeCapability();
    const lease = makeLease(capability);

    expect(
      await productionPreSign({
        readiness,
        databaseReachable: true,
        backpressure,
        leadership,
        halt,
        capability,
        vault,
        lease,
      }),
    ).toBe("signed");
    const vaultAfterOk = vault.calls;

    readiness.recordObservationReadFailure();
    hooks.onT0ReadFailure();
    readiness.recordObservationReadFailure();
    hooks.onT0ReadFailure();

    const stamps = readiness.snapshot();
    expect(stamps.observationReadCapable).toBe(false);
    expect(stamps.observationDegraded).toBe(true);
    const verdict = evaluateReadinessFromProbes(stamps, true);
    expect(verdict.ready).toBe(false);
    expect(verdict.status).toBe("degraded");
    const http = await readinessHttp({
      version: VERSION,
      getState: () => readiness.snapshot(),
      pingDb: async () => {},
      now,
    });
    expect(http.statusCode).toBe(503);
    expect((http.body as { status: string }).status).toBe("degraded");

    const snap = applyDerivedMetrics(metrics, {
      readiness,
      databaseReachable: true,
      backpressure,
      haltEngaged: false,
    });
    expect(snap.observationDegraded).toBe(1);
    expect(snap.readinessReady).toBe(0);
    expect(metrics.observationDegraded.get({})).toBe(1);
    expect(metrics.t0ReadFailures.get({})).toBe(2);

    expect(
      await productionPreSign({
        readiness,
        databaseReachable: true,
        backpressure,
        leadership,
        halt,
        capability,
        vault,
        lease,
      }),
    ).toBe("refused");
    expect(vault.calls).toBe(vaultAfterOk);
    expect(() => assertNewMoneyWorkAdmitted(readiness.snapshot(), true)).toThrow(
      MoneyAdmissionRefusedError,
    );
  });

  it("a single validated read success clears degraded and re-opens admission", async () => {
    const readiness = healthyReadiness(1);
    readiness.recordObservationReadFailure();
    expect(evaluateReadinessFromProbes(readiness.snapshot(), true).status).toBe("degraded");
    readiness.recordObservationReadSuccess();
    expect(evaluateReadinessFromProbes(readiness.snapshot(), true).ready).toBe(true);

    const leadership = new SignerLeadership();
    leadership.markAcquired();
    const vault = { calls: 0 };
    const capability = makeCapability();
    expect(
      await productionPreSign({
        readiness,
        databaseReachable: true,
        backpressure: createStorageBackpressure(),
        leadership,
        halt: createHaltGate("RUNNING"),
        capability,
        vault,
        lease: makeLease(capability),
      }),
    ).toBe("signed");
    expect(vault.calls).toBe(1);
  });

  it("negative: degraded mode never mutates durable lease/op rows in quarantine store", async () => {
    const store = new InMemoryAnomalyQuarantineStore();
    seedLeasedWallet(store, "w-gw", "lease-gw", "op-gw");
    const before = await store.getWallet("w-gw");
    expect(before?.activeLeaseId).toBe("lease-gw");

    const readiness = healthyReadiness(1);
    readiness.recordObservationReadFailure();
    const leadership = new SignerLeadership();
    leadership.markAcquired();
    const vault = { calls: 0 };
    const capability = makeCapability("w-gw", "op-gw", 1n);
    // Production sign path under observation-degraded — must refuse AND leave store intact.
    expect(
      await productionPreSign({
        readiness,
        databaseReachable: true,
        backpressure: createStorageBackpressure(),
        leadership,
        halt: createHaltGate("RUNNING"),
        capability,
        vault,
        lease: makeLease(capability),
        quarantineStore: store,
      }),
    ).toBe("refused");
    expect(vault.calls).toBe(0);

    const after = await store.getWallet("w-gw");
    expect(after?.activeLeaseId).toBe(before?.activeLeaseId);
    expect(after?.state).toBe("PINNED");
    expect((await store.getOperation("op-gw"))?.status).toBe("AWAITING_REDEMPTION");
  });

  it("captureReceiveT0 refuses via production assertMoneyAdmitted when observation degraded", async () => {
    const readiness = healthyReadiness(1);
    readiness.recordObservationReadFailure();
    let observeCalls = 0;
    let queryCalls = 0;
    const db: SqlExecutor = {
      query: async () => {
        queryCalls += 1;
        return { rows: [] };
      },
    };
    const ports = createMoneyPathAdmissionPortsFromRuntime({
      snapshotReadiness: () => readiness.snapshot(),
      isDatabaseReachable: () => true,
      backpressure: createStorageBackpressure(),
    });
    await expect(
      captureReceiveT0(
        db,
        createMoneyCaptureReceiveT0Params(
          {
            operationId: "op-t0",
            walletId: "w-t0",
            observer: {
              observe: async () => {
                observeCalls += 1;
                return { kind: "INDETERMINATE", detail: "should-not-run" };
              },
            },
          },
          ports,
        ),
      ),
    ).rejects.toBeInstanceOf(MoneyAdmissionRefusedError);
    expect(observeCalls).toBe(0);
    expect(queryCalls).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. DATABASE
// ═══════════════════════════════════════════════════════════════════════════

describe("database degraded mode", () => {
  it("DB probe failure reports not_ready/503 and freezes new money admission", async () => {
    const readiness = healthyReadiness();
    const backpressure = createStorageBackpressure();
    const leadership = new SignerLeadership();
    leadership.markAcquired();
    const metrics = createNodeMetrics();
    const vault = { calls: 0 };
    const capability = makeCapability();

    const verdict = evaluateReadinessFromProbes(readiness.snapshot(), false);
    expect(verdict.ready).toBe(false);
    expect(verdict.status).toBe("not_ready");
    expect(verdict.failing).toContain("database_reachable");
    const http = await readinessHttp({
      version: VERSION,
      getState: () => readiness.snapshot(),
      pingDb: async () => {
        throw new Error("ECONNREFUSED");
      },
      now,
    });
    expect(http.statusCode).toBe(503);
    expect((http.body as { status: string }).status).toBe("not_ready");

    const snap = applyDerivedMetrics(metrics, {
      readiness,
      databaseReachable: false,
      backpressure,
      haltEngaged: false,
    });
    expect(snap.readinessReady).toBe(0);

    expect(
      await productionPreSign({
        readiness,
        databaseReachable: false,
        backpressure,
        leadership,
        halt: createHaltGate("RUNNING"),
        capability,
        vault,
        lease: makeLease(capability),
      }),
    ).toBe("refused");
    expect(vault.calls).toBe(0);
  });

  it("negative: DB blip does not release leases or advance durable op status", async () => {
    const store = new InMemoryAnomalyQuarantineStore();
    seedLeasedWallet(store, "w-db", "lease-db", "op-db");
    const beforeLease = (await store.getWallet("w-db"))!.activeLeaseId;
    const beforeStatus = (await store.getOperation("op-db"))!.status;

    const readiness = healthyReadiness();
    const leadership = new SignerLeadership();
    leadership.markAcquired();
    const vault = { calls: 0 };
    const capability = makeCapability("w-db", "op-db", 1n);
    expect(
      await productionPreSign({
        readiness,
        databaseReachable: false,
        backpressure: createStorageBackpressure(),
        leadership,
        halt: createHaltGate("RUNNING"),
        capability,
        vault,
        lease: makeLease(capability),
        quarantineStore: store,
      }),
    ).toBe("refused");
    expect(vault.calls).toBe(0);

    expect((await store.getWallet("w-db"))!.activeLeaseId).toBe(beforeLease);
    expect((await store.getOperation("op-db"))!.status).toBe(beforeStatus);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. DISK / STORAGE
// ═══════════════════════════════════════════════════════════════════════════

describe("disk / storage-pressure degraded mode", () => {
  it("CRITICAL utilization halts operations, stamps storage_pressure metric, fires P0 alert", async () => {
    const readiness = healthyReadiness();
    const backpressure = createStorageBackpressure();
    const leadership = new SignerLeadership();
    leadership.markAcquired();
    const metrics = createNodeMetrics();
    const vault = { calls: 0 };
    const capability = makeCapability();

    expect(backpressure.recordGlobalSample(0.97)).toBe("CRITICAL");
    expect(() => backpressure.assertCanOperate()).toThrow(OperationsHaltedError);

    const snap = applyDerivedMetrics(metrics, {
      readiness,
      databaseReachable: true,
      backpressure,
      haltEngaged: false,
    });
    expect(snap.storagePressure).toBe(1);
    expect(metrics.storagePressure.get({})).toBe(1);

    const notes = evaluateAlertsFromFault(alertInputFromFault({ readiness, backpressure }));
    expect(notes.some((n) => n.signal === "storage_pressure" && n.severity === "P0")).toBe(true);

    expect(
      await productionPreSign({
        readiness,
        databaseReachable: true,
        backpressure,
        leadership,
        halt: createHaltGate("RUNNING"),
        capability,
        vault,
        lease: makeLease(capability),
      }),
    ).toBe("refused");
    expect(vault.calls).toBe(0);
  });

  it("negative: PRESSURE refuses new evidence but still permits in-flight operate band", () => {
    const backpressure = createStorageBackpressure();
    backpressure.recordGlobalSample(0.92); // default pressure=0.9, critical=0.95
    expect(backpressure.globalState()).toBe("PRESSURE");
    expect(() => backpressure.assertCanAcceptEvidence()).toThrow();
    expect(() => backpressure.assertCanOperate()).not.toThrow();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. SIGNER — recovery
// ═══════════════════════════════════════════════════════════════════════════

describe("signer leadership loss", () => {
  it("leadership loss mid-operation refuses signUnderLease; durable phase intact; non-gating readiness", async () => {
    const readiness = healthyReadiness();
    const backpressure = createStorageBackpressure();
    const leadership = new SignerLeadership();
    leadership.markAcquired();
    const metrics = createNodeMetrics();
    const vault = { calls: 0 };
    const audit: SignerAuditEntry[] = [];
    const capability = makeCapability();
    const lease = makeLease(capability);
    // Mutable durable phase fixture (production ActiveLeaseRecord fields).
    const durableLease: ActiveLeaseRecord = { ...lease };

    const store = new InMemoryAnomalyQuarantineStore();
    seedLeasedWallet(store, capability.walletId, "lease-sig", capability.operationId);
    const phaseBefore = (await store.getOperation(capability.operationId))!.status;

    const deps = makeProductionSignDeps({
      readiness,
      databaseReachable: true,
      backpressure,
      leadership,
      vault,
      audit,
      lease: durableLease,
      quarantineStore: store,
    });
    await signUnderLease(deps, capability);
    expect(vault.calls).toBe(1);

    leadership.markLost("connection end");
    readiness.setLeadershipHeld(false);

    // Leadership is NON-gating for ready conjunction.
    const verdict = evaluateReadinessFromProbes(readiness.snapshot(), true);
    expect(verdict.ready).toBe(true);
    expect(verdict.checks.find((c) => c.name === "signer_leadership")).toMatchObject({
      ready: false,
      gating: false,
    });

    const snap = applyDerivedMetrics(metrics, {
      readiness,
      databaseReachable: true,
      backpressure,
      haltEngaged: false,
    });
    expect(snap.signerLeadershipHeld).toBe(0);

    const notes = evaluateAlertsFromFault(alertInputFromFault({ readiness, backpressure }));
    expect(notes.some((n) => n.signal === "signer_loss")).toBe(true);

    expectNotLeader(() => signUnderLease(deps, capability));
    expect(vault.calls).toBe(1);

    // Durable phase intact.
    expect(durableLease.lifecycle).toBe("ACTIVE");
    expect(durableLease.epoch).toBe(capability.leaseEpoch);
    expect((await store.getOperation(capability.operationId))!.status).toBe(phaseBefore);
    expect((await store.getWallet(capability.walletId))!.activeLeaseId).toBe("lease-sig");
  });

  it("negative: a non-leader alternate instance never reaches the vault", () => {
    const leadership = new SignerLeadership();
    const vault = { calls: 0 };
    const readiness = healthyReadiness();
    const backpressure = createStorageBackpressure();
    const deps = makeProductionSignDeps({
      readiness,
      databaseReachable: true,
      backpressure,
      leadership,
      vault,
    });
    expectNotLeader(() => signUnderLease(deps, makeCapability()));
    expect(vault.calls).toBe(0);
  });

  it("halt gate + leadership loss: gated signer refuses; in-flight process stays permeable", async () => {
    const halt = createHaltGate("RUNNING");
    let signCalls = 0;
    const gated = createGatedSigner(halt, {
      sign: async (req: string) => {
        signCalls += 1;
        return `sig-${req}`;
      },
    });
    await gated.sign("a");
    expect(signCalls).toBe(1);
    halt.engage();
    await expect(gated.sign("b")).rejects.toBeInstanceOf(OperatorHaltError);
    expect(signCalls).toBe(1);

    const worker = createGatedWorker(halt, {
      claim: async () => "job",
      process: async (c: string) => `done-${c}`,
    });
    expect(await worker.claim()).toBeNull();
    expect(await worker.process("in-flight")).toBe("done-in-flight");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. REPORTING — recovery
// ═══════════════════════════════════════════════════════════════════════════

describe("reporting degraded mode (snapshot/read timeout)", () => {
  it("snapshot captureTimeoutMs fails the pull without altering durable watermark or money state", async () => {
    const log = new InMemoryImplementerEventLog();
    await log.append({
      implementerId: "impl-1",
      eventId: "e1",
      eventType: "receive.ready",
      proofRepresentation: '{"implementer_seq":"1"}',
      createdAt: FIXED_TIME,
    });
    const watermarkBefore = await log.watermark("impl-1");

    const hangingReader: SnapshotStateReader = {
      readState: () => new Promise(() => {}),
    };
    const store = new InMemorySnapshotStore();

    // Production HTTP binder — DEFAULT_STATE_SNAPSHOT_CAPTURE_TIMEOUT_MS is applied
    // when captureTimeoutMs is omitted; override short for the hang.
    expect(DEFAULT_STATE_SNAPSHOT_CAPTURE_TIMEOUT_MS).toBeGreaterThan(0);
    const response = await handleGetStateSnapshot(
      {
        log,
        reader: hangingReader,
        store,
        nowMs: () => Date.parse(FIXED_TIME),
        newRequestId: () => "req-snap-timeout",
        captureTimeoutMs: 40,
      },
      "impl-1",
      "req-snap-timeout",
    );
    expect(response.status).toBe(503);
    expect(await log.watermark("impl-1")).toBe(watermarkBefore);
    expect(await store.latest("impl-1")).toBeNull();

    // Direct service path still raises the typed timeout for composition callers.
    const service = createSnapshotService({
      log,
      reader: hangingReader,
      store,
      captureTimeoutMs: 40,
      nowMs: () => Date.parse(FIXED_TIME),
    });
    await expect(service.capture("impl-1")).rejects.toBeInstanceOf(SnapshotCaptureTimeoutError);

    // Money path independent of reporting hang.
    const readiness = healthyReadiness();
    const leadership = new SignerLeadership();
    leadership.markAcquired();
    const vault = { calls: 0 };
    const capability = makeCapability();
    expect(
      await productionPreSign({
        readiness,
        databaseReachable: true,
        backpressure: createStorageBackpressure(),
        leadership,
        halt: createHaltGate("RUNNING"),
        capability,
        vault,
        lease: makeLease(capability),
      }),
    ).toBe("signed");
    expect(vault.calls).toBe(1);
  });

  it("negative: reporting timeout does not mint submit claims", async () => {
    const claimStore = makeClaimStore();
    const log = new InMemoryImplementerEventLog();
    await log.append({
      implementerId: "impl-mint",
      eventId: "e1",
      eventType: "receive.ready",
      proofRepresentation: "{}",
      createdAt: FIXED_TIME,
    });
    const hangingReader: SnapshotStateReader = {
      readState: () => new Promise(() => {}),
    };
    const response = await handleGetStateSnapshot(
      {
        log,
        reader: hangingReader,
        store: new InMemorySnapshotStore(),
        nowMs: () => Date.parse(FIXED_TIME),
        newRequestId: () => "req-no-mint",
        captureTimeoutMs: 30,
      },
      "impl-mint",
      "req-no-mint",
    );
    expect(response.status).toBe(503);
    // Reporting failure must not have crossed the submit-claim boundary.
    expect(claimStore.mints).toBe(0);
    expect(claimStore.uniquenessRejections).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 6. CALLBACK / OUTBOX
// ═══════════════════════════════════════════════════════════════════════════

describe("callback / outbox delivery failure (conditional)", () => {
  it("SSE/live-notify delivery failure never rolls back the durable event append", async () => {
    const log = new InMemoryImplementerEventLog();
    await log.append({
      implementerId: "impl-cb",
      eventId: "evt-1",
      eventType: "receive.ready",
      proofRepresentation: '{"implementer_seq":"1"}',
      createdAt: FIXED_TIME,
    });
    const unsub = log.subscribe("impl-cb", () => {
      throw new Error("SSE fanout failed");
    });
    await log.append({
      implementerId: "impl-cb",
      eventId: "evt-2",
      eventType: "receive.landed",
      proofRepresentation: '{"implementer_seq":"2"}',
      createdAt: FIXED_TIME,
    });
    unsub();
    expect(await log.watermark("impl-cb")).toBe(2n);
    const page = await log.readEvents("impl-cb", 0n, 10);
    expect(page.events).toHaveLength(2);
  });

  it("negative: delivery failure does not mint a second submit claim", async () => {
    const claimStore = makeClaimStore();
    const first = await claimStore.claimSubmitOnce({
      attemptId: "a1",
      claimedAt: FIXED_TIME,
      operationId: "op-cb",
      transactionAttemptNo: 1,
    });
    expect(first.minted).toBe(true);
    const second = await claimStore.claimSubmitOnce({
      attemptId: "a2",
      claimedAt: FIXED_TIME,
      operationId: "op-cb",
      transactionAttemptNo: 1,
    });
    expect(second.minted).toBe(false);
    expect(claimStore.mints).toBe(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 7. ENDPOINT DISAGREEMENT + test-plan
// ═══════════════════════════════════════════════════════════════════════════

describe("endpoint disagreement", () => {
  it("cross-endpoint disagreement halts stream, records anomaly, fires alert; further reads refuse (no T0)", async () => {
    const observer = recordingObserver();
    const anomalies = recordingAnomaly();
    const failovers = recordingFailover();
    const { exchange, touched } = scriptedExchange([
      { kind: "capture", status: 200, body: BODY_OK },
      { kind: "ambiguous" },
      { kind: "capture", status: 200, body: BODY_DIFF },
    ]);
    const service = createEndpointFailoverService({
      endpoints: [ENDPOINT_A, ENDPOINT_B],
      observerId: "obs-disagree",
      anomalyRecorder: anomalies.recorder,
      recorder: failovers.recorder,
    });
    const opts = readOptions(exchange, observer.recorder);
    const metrics = createNodeMetrics();
    const hooks = createMetricsHooks(metrics);

    expect((await service.read("get_transaction__v1", {}, opts)).verificationStatus).toBe(
      "ACCEPTED",
    );
    expect((await service.read("get_transaction__v1", {}, opts)).verificationStatus).toBe(
      "INDETERMINATE",
    );
    expect(service.isHalted()).toBe(true);
    expect(anomalies.anomalies).toHaveLength(1);
    expect(failovers.events).toHaveLength(0);
    expect(touched).toContain(ENDPOINT_A);
    expect(touched).toContain(ENDPOINT_B);

    hooks.onObservationAnomaly("other");
    expect(metrics.observationAnomalies.get({ kind: "other" })).toBe(1);

    const readiness = healthyReadiness();
    const backpressure = createStorageBackpressure();
    const notes = evaluateAlertsFromFault(
      alertInputFromFault({
        readiness,
        backpressure,
        endpointDisagreementCount: anomalies.anomalies.length,
      }),
    );
    expect(notes.some((n) => n.signal === "endpoint_disagreement")).toBe(true);

    // Production stream halt: further observation (T0 path) refuses.
    await expect(service.read("get_transaction__v1", {}, opts)).rejects.toBeInstanceOf(
      GatewayEndpointHaltError,
    );
  });

  it("test-plan minimum sequences feed recovery classifications into metrics/alerts", async () => {
    const metrics = createNodeMetrics();
    const hooks = createMetricsHooks(metrics);
    const readiness = healthyReadiness();
    const backpressure = createStorageBackpressure();
    let regressions = 0;
    let pathGaps = 0;

    // A,A equivalent envelope
    {
      const r = classify(STATE_A, STATE_A_EQUIV, ["sigA"]);
      expect(r.relationship).toBe("EQUIVALENT_STATE_DIFFERENT_ENVELOPE");
      expect(establishesOrdinaryHead(r)).toBe(false);
    }

    // A,B successor
    {
      const r = classify(STATE_A, STATE_B, ["sigA"]);
      expect(r.relationship).toBe("SUCCESSOR");
      expect(establishesOrdinaryHead(r)).toBe(true);
    }

    // A,B,C,A regression
    {
      const history: string[] = [];
      expect(classify(null, STATE_A, history).relationship).toBe("FIRST");
      history.push(STATE_A.sSignature);
      expect(classify(STATE_A, STATE_B, history).relationship).toBe("SUCCESSOR");
      history.push(STATE_B.sSignature);
      expect(classify(STATE_B, STATE_C, history).relationship).toBe("SUCCESSOR");
      history.push(STATE_C.sSignature);
      const rReg = classify(STATE_C, STATE_A, history);
      expect(rReg.relationship).toBe("REGRESSION");
      hooks.onObservationAnomaly("REGRESSION");
      regressions += 1;
    }

    // genesis after history
    {
      expect(classify(STATE_A, GENESIS, ["sigA"], true).relationship).toBe("GENESIS_AFTER_HISTORY");
      hooks.onObservationAnomaly("GENESIS_AFTER_HISTORY");
    }

    // signature collision (contradiction)
    {
      expect(classify(STATE_A, STATE_A_COLLISION, ["sigA"]).relationship).toBe(
        "SIGNATURE_COLLISION",
      );
      hooks.onObservationAnomaly("SIGNATURE_COLLISION");
    }

    // identical-anomaly-twice sticky
    {
      const p1 = planActionForRelationship("REGRESSION");
      const p2 = planActionForRelationship("REGRESSION");
      expect(p1.signingHalted).toBe(true);
      expect(p2.signingHalted).toBe(true);
    }

    // unrelated-gap / non-head jump
    {
      const r = classify(STATE_A, STATE_JUMP, ["sigA"]);
      expect(establishesOrdinaryHead(r)).toBe(false);
      hooks.onObservationAnomaly("UNEXPLAINED_JUMP");
      pathGaps += 1;
    }

    // A,B endpoint disagreement
    let disagreements = 0;
    {
      const anomalies = recordingAnomaly();
      const { exchange } = scriptedExchange([
        { kind: "capture", status: 200, body: BODY_OK },
        { kind: "ambiguous" },
        { kind: "capture", status: 200, body: BODY_DIFF },
      ]);
      const service = createEndpointFailoverService({
        endpoints: [ENDPOINT_A, ENDPOINT_B],
        anomalyRecorder: anomalies.recorder,
      });
      const opts = readOptions(exchange, recordingObserver().recorder);
      await service.read("get_transaction__v1", {}, opts);
      await service.read("get_transaction__v1", {}, opts);
      expect(service.isHalted()).toBe(true);
      disagreements = anomalies.anomalies.length;
    }

    expect(metrics.observationAnomalies.get({ kind: "REGRESSION" })).toBeGreaterThanOrEqual(1);
    expect(metrics.observationAnomalies.get({ kind: "GENESIS_AFTER_HISTORY" })).toBe(1);
    expect(metrics.observationAnomalies.get({ kind: "SIGNATURE_COLLISION" })).toBe(1);
    expect(metrics.observationAnomalies.get({ kind: "UNEXPLAINED_JUMP" })).toBe(1);

    const notes = evaluateAlertsFromFault(
      alertInputFromFault({
        readiness,
        backpressure,
        regressionCount: regressions,
        pathGapCount: pathGaps,
        endpointDisagreementCount: disagreements,
      }),
    );
    expect(notes.some((n) => n.signal === "regression")).toBe(true);
    expect(notes.some((n) => n.signal === "endpoint_disagreement")).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// ISOLATED LANES
// ═══════════════════════════════════════════════════════════════════════════

describe("isolated lanes", () => {
  it("anomaly quarantine on wallet A leaves wallet B money path free", async () => {
    const store = new InMemoryAnomalyQuarantineStore();
    // Wallet ids must match sign capability walletId for assertWalletMaySign lookup.
    const walletA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const walletB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const opA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
    const opB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1";
    seedLeasedWallet(store, walletA, "lease-A", opA);
    seedLeasedWallet(store, walletB, "lease-B", opB);

    const plan = planActionForRelationship("REGRESSION");
    expect(plan.signingHalted).toBe(true);
    const applied = await applyAnomalyAction(store, {
      plan,
      walletId: walletA,
      operationId: opA,
    });
    expect(applied.wallet?.signingHalted).toBe(true);
    expect(isSigningHalted((await store.getWallet(walletA))!)).toBe(true);
    expect((await store.getWallet(walletA))!.activeLeaseId).toBe("lease-A");
    expect(isSigningHalted((await store.getWallet(walletB))!)).toBe(false);

    const readiness = healthyReadiness();
    const leadership = new SignerLeadership();
    leadership.markAcquired();
    const halt = createHaltGate("RUNNING");
    const backpressure = createStorageBackpressure();

    // A: production signUnderLease → assertWalletMaySign → WalletSigningHaltedError.
    const vaultA = { calls: 0 };
    const capA = makeCapability(walletA, opA, 1n);
    expect(
      await productionPreSign({
        readiness,
        databaseReachable: true,
        backpressure,
        leadership,
        halt,
        capability: capA,
        vault: vaultA,
        lease: makeLease(capA),
        quarantineStore: store,
      }),
    ).toBe("refused");
    expect(vaultA.calls).toBe(0);

    // B: same production path signs.
    const vaultB = { calls: 0 };
    const capB = makeCapability(walletB, opB, 1n);
    expect(
      await productionPreSign({
        readiness,
        databaseReachable: true,
        backpressure,
        leadership,
        halt,
        capability: capB,
        vault: vaultB,
        lease: makeLease(capB),
        quarantineStore: store,
      }),
    ).toBe("signed");
    expect(vaultB.calls).toBe(1);

    // Lease rows untouched for both.
    expect((await store.getWallet(walletA))!.activeLeaseId).toBe("lease-A");
    expect((await store.getWallet(walletB))!.activeLeaseId).toBe("lease-B");

    const notes = evaluateAlertsFromFault(
      alertInputFromFault({
        readiness,
        backpressure,
        regressionCount: 1,
        invariantBreachCount: 0,
      }),
    );
    expect(notes.some((n) => n.signal === "regression")).toBe(true);
    expect(notes.some((n) => n.signal === "invariant_breach")).toBe(false);
  });

  it("global INVARIANT_BREACH does not start money engines (boot recovery gate)", async () => {
    // Production boot recovery: signer audit without exact preimage → INVARIANT_BREACH
    // → actions.stopMoneyEngines (no test-side halt.engage).
    const moneyEnginesStopped: string[] = [];
    const leadership = new SignerLeadership();
    leadership.markAcquired();

    const op: OperationPhaseEvidence = {
      operationId: "recv-breach-1",
      kind: "RECEIVE_EXTERNAL",
      status: "READY",
      attentionRequired: false,
      rowVersion: 1,
      leaseEpoch: 1,
      submitBoundaryRecorded: false,
      signerAuditIndicatesCall: true,
      exactPreimagePersisted: false,
      signaturePersisted: false,
      formationComplete: false,
      leasedWalletIds: ["w-recv"],
      requiredRoles: ["RECEIVE_WINDOW"],
    };
    const lease: ActiveLeaseRow = {
      walletId: "w-recv",
      operationId: "recv-breach-1",
      leaseGroupId: "lg-1",
      role: "RECEIVE_WINDOW",
      epoch: 1,
      walletState: "PINNED",
      lastHeartbeatAtMs: Date.now(),
    };
    const key: KeyCorrespondenceRow = {
      walletId: "w-recv",
      storedPublicKey: "pk",
      derivedPublicKey: "pk",
    };

    const store: BootRecoveryStore = {
      listActiveLeases: async () => [lease],
      listNonterminalOperations: async () => [op],
      listLeaseGroupOperations: async () => [
        { leaseGroupId: "lg-1", operationId: "recv-breach-1" },
      ],
      listKeyCorrespondence: async () => [key],
      listObservationCursors: async () => [],
      readRawResponseBytes: async () => null,
      listQueuedReceiveOperationIds: async () => [],
    };
    const actions: BootRecoveryActions = {
      quarantineWallet: async () => {},
      repairWalletState: async () => {},
      setAttention: async () => {},
      resumeAuthorized: async () => {},
      seedReconcileCursor: async () => {},
      rebuildReceiveAdmissionQueue: async () => {},
      stopMoneyEngines: async (reason) => {
        moneyEnginesStopped.push(reason);
      },
    };

    const report = await runDeterministicBootRecovery({ leadership, store, actions });
    expect(report.invariantBreach).toBe(true);
    expect(report.ready).toBe(false);
    expect(moneyEnginesStopped.length).toBeGreaterThanOrEqual(1);
    expect(moneyEnginesStopped[0]).toMatch(/invariant breach/i);

    // Production start gate (wired in apps/generic-node boot-lane) refuses.
    expect(shouldStartMoneyWorkersAfterRecovery(report)).toBe(false);
    expect(
      shouldStartMoneyWorkersAfterRecovery({ ready: true, invariantBreach: false }),
    ).toBe(true);

    const readiness = healthyReadiness();
    const backpressure = createStorageBackpressure();
    const notes = evaluateAlertsFromFault(
      alertInputFromFault({
        readiness,
        backpressure,
        invariantBreachCount: report.invariantBreach ? 1 : 0,
      }),
    );
    expect(notes.some((n) => n.signal === "invariant_breach" && n.severity === "P0")).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// NO DOUBLE SUBMIT
// ═══════════════════════════════════════════════════════════════════════════

describe("no double submit / no second partial across crash points", () => {
  it("claimSubmitOnce + executeMoveSubmitClaim mint ≤1 and one gateway POST across failure classes", async () => {
    const RESPONSE_BYTES = new TextEncoder().encode('{"status":true}');
    const baseAuth = {
      submitDecisionId: "11111111-1111-4111-8111-111111111111",
      operationId: "22222222-2222-4222-8222-222222222222",
      transactionAttemptNo: 1,
    };

    type FailureClass = "gateway" | "signer" | "halt" | "disk";

    async function runClass(cls: FailureClass): Promise<void> {
      const claimStore = makeClaimStore();
      const touched: string[] = [];
      const exchange: GatewayExchangeTransport = {
        exchange: async (endpoint, request) => {
          touched.push(endpoint);
          if (cls === "gateway" && touched.length > 1) {
            throw new GatewayTransportAmbiguityError(
              "injected gateway fault on retry",
              new Error("transport"),
            );
          }
          return {
            endpoint,
            endpointFingerprint: sha256Hex(new TextEncoder().encode(endpoint)),
            requestBytes: request.bodyBytes,
            requestSha256: sha256Hex(request.bodyBytes),
            responseBytes: RESPONSE_BYTES,
            responseSha256: sha256Hex(RESPONSE_BYTES),
            statusCode: 200,
          };
        },
      };
      const recorder: SubmitAttemptRecorder & { records: unknown[] } = {
        records: [],
        recordSubmitAttempt: async (record) => {
          recorder.records.push(record);
        },
      };
      const options = {
        authorization: baseAuth,
        signedTransaction: { inner: "move-inner", step_1_signature: "sig" },
        claimStore,
        submit: {
          endpoint: ENDPOINT_A,
          limits: LIMITS,
          recorder,
          exchange,
          nowIso: () => FIXED_TIME,
        },
      };

      // First shot wins the mint and POSTs once.
      const first = await executeMoveSubmitClaim(options);
      expect(first.executed, cls).toBe(true);
      expect(claimStore.mints, cls).toBe(1);
      expect(touched.length, cls).toBe(1);

      // Inject the named failure class at the durable phase boundary AFTER the
      // first submit claim is durable — then prove retry cannot second-submit.
      const readiness = healthyReadiness(1);
      const leadership = new SignerLeadership();
      leadership.markAcquired();
      const halt = createHaltGate("RUNNING");
      const backpressure = createStorageBackpressure();
      const vault = { calls: 0 };
      const capability = makeCapability();

      if (cls === "signer") {
        leadership.markLost("injected signer loss after first submit");
      } else if (cls === "halt") {
        halt.engage();
      } else if (cls === "disk") {
        expect(backpressure.recordGlobalSample(0.97)).toBe("CRITICAL");
      } else if (cls === "gateway") {
        readiness.recordObservationReadFailure(); // observation budget exhausted
      }

      // Production pre_sign under the injected fault must refuse.
      const pre = await productionPreSign({
        readiness,
        databaseReachable: true,
        backpressure,
        leadership,
        halt,
        capability,
        vault,
        lease: makeLease(capability),
      });
      // gateway/signer/halt/disk all refuse new money work on the production path
      expect(pre, cls).toBe("refused");
      expect(vault.calls, cls).toBe(0);

      // Retry submit for the SAME attempt — claim uniqueness refuses second mint/POST.
      const second = await executeMoveSubmitClaim({
        ...options,
        authorization: {
          ...baseAuth,
          // same attempt key; different decision id still collides on (op, attemptNo)
          submitDecisionId: "33333333-3333-4333-8333-333333333333",
        },
      });
      expect(second.executed, cls).toBe(false);
      expect(claimStore.mints, cls).toBe(1);
      expect(touched.length, `${cls} posts`).toBe(1);
      expect(claimStore.uniquenessRejections, cls).toBeGreaterThanOrEqual(1);

      const notes = evaluateAlertsFromFault({
        ...emptySafetyAlertMetricInput(),
        duplicateSubmitRejectionCount: claimStore.uniquenessRejections,
      });
      expect(
        notes.some((n) => n.signal === "duplicate_submit_attempt" && n.severity === "P0"),
        cls,
      ).toBe(true);
    }

    for (const cls of ["gateway", "signer", "halt", "disk"] as const) {
      await runClass(cls);
    }
  });

  it("pre_sign refusal under injected failures never double-mints submit claims", async () => {
    const claimStore = makeClaimStore();
    const readiness = healthyReadiness(2);
    const leadership = new SignerLeadership();
    leadership.markAcquired();
    const vault = { calls: 0 };
    const capability = makeCapability();

    expect(
      await productionPreSign({
        readiness,
        databaseReachable: true,
        backpressure: createStorageBackpressure(),
        leadership,
        halt: createHaltGate("RUNNING"),
        capability,
        vault,
        lease: makeLease(capability),
      }),
    ).toBe("signed");
    const mint = await claimStore.claimSubmitOnce({
      attemptId: randomUUID(),
      claimedAt: FIXED_TIME,
      operationId: "op-once",
      transactionAttemptNo: 1,
    });
    expect(mint.minted).toBe(true);

    // Fail all gates — re-admission refused.
    readiness.recordObservationReadFailure();
    readiness.recordObservationReadFailure();
    expect(
      await productionPreSign({
        readiness,
        databaseReachable: false,
        backpressure: createStorageBackpressure(),
        leadership: new SignerLeadership(),
        halt: createHaltGate("HALTED"),
        capability,
        vault: { calls: 0 },
        lease: makeLease(capability),
      }),
    ).toBe("refused");

    const again = await claimStore.claimSubmitOnce({
      attemptId: randomUUID(),
      claimedAt: FIXED_TIME,
      operationId: "op-once",
      transactionAttemptNo: 1,
    });
    expect(again.minted).toBe(false);
    expect(claimStore.mints).toBe(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// METRICS SECRET-SCAN
// ═══════════════════════════════════════════════════════════════════════════

describe("metrics contain no secrets under degraded modes", () => {
  it("rendered registry after fault-derived stamps has no key/preimage/TOTP material", async () => {
    const metrics = createNodeMetrics();
    const hooks = createMetricsHooks(metrics);
    hooks.onT0ReadFailure();
    hooks.onObservationAnomaly("REGRESSION");
    hooks.onObservationAnomaly("GENESIS_AFTER_HISTORY");
    hooks.onSubmit("ok");

    const readiness = healthyReadiness(1);
    readiness.recordObservationReadFailure();
    const backpressure = createStorageBackpressure();
    backpressure.recordGlobalSample(0.97);
    readiness.setLeadershipHeld(false);
    applyDerivedMetrics(metrics, {
      readiness,
      databaseReachable: false,
      backpressure,
      haltEngaged: true,
    });

    const body = await renderMetrics(metrics);
    for (const banned of [
      "private",
      "preimage",
      "totp",
      "seed",
      "mnemonic",
      "BEGIN ",
      "sk_",
      "password",
    ]) {
      expect(body.toLowerCase()).not.toContain(banned.toLowerCase());
    }
    expect(body).toContain("gn_observation_degraded");
    expect(body).toContain("gn_signer_leadership_held");
    expect(body).toContain("gn_storage_pressure");
    expect(body).toContain("gn_readiness_ready");
  });
});

describe("money-admission production gate", () => {
  it("refuses each gating failure with a closed code", () => {
    const base = healthyReadiness().snapshot();
    expect(() => assertNewMoneyWorkAdmitted(base, true)).not.toThrow();
    expect(() =>
      assertNewMoneyWorkAdmitted({ ...base, observationReadCapable: false }, true),
    ).toThrow(/observation_not_read_capable/);
    expect(() => assertNewMoneyWorkAdmitted(base, false)).toThrow(/database_unreachable/);
    expect(() =>
      assertNewMoneyWorkAdmitted({ ...base, vaultKeyRingLoaded: false }, true),
    ).toThrow(/vault_unavailable/);
    expect(() =>
      assertNewMoneyWorkAdmitted({ ...base, eventSignerAvailable: false }, true),
    ).toThrow(/event_signer_unavailable/);
  });

  it("default NodeCoreReadinessState (no ensure) refuses money even when other gates open (ZTR-1221)", () => {
    const state = new NodeCoreReadinessState({ observationFailureBudget: 3 });
    state.markSchemaMigrated();
    state.setVaultAvailable(true);
    state.recordObservationReadSuccess();
    state.setLeadershipHeld(true);
    // eventSignerAvailable remains default false
    expect(state.snapshot().eventSignerAvailable).toBe(false);
    expect(() => assertNewMoneyWorkAdmitted(state.snapshot(), true)).toThrow(
      /event_signer_unavailable/,
    );
    state.setEventSignerAvailable(true);
    expect(() => assertNewMoneyWorkAdmitted(state.snapshot(), true)).not.toThrow();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// test-plan REAL-DB (from original suite — production tryAcquire + signUnderLease)
// ═══════════════════════════════════════════════════════════════════════════

const databaseUrl = process.env.TEST_DATABASE_URL;
// Set true only at the END of a successful live-block beforeAll. The PG_REQUIRED
// guard (registered AFTER the live describe, matching leadership.pg.test.ts) reads
// this flag — registering it earlier makes the guard `it` run before beforeAll, so
// liveReady is still false and the guard fails even when the live block fully runs.
let liveReady = false;

function pgEnv(): NodeJS.ProcessEnv {
  const url = databaseUrl;
  if (url === undefined) throw new Error("TEST_DATABASE_URL required");
  const parsed = new URL(url);
  return {
    ...process.env,
    PGHOST: parsed.hostname,
    PGPORT: parsed.port || "5432",
    PGUSER: decodeURIComponent(parsed.username),
    PGPASSWORD: decodeURIComponent(parsed.password),
    PGDATABASE: parsed.pathname.replace(/^\//, ""),
    PGSSLMODE: "disable",
  };
}

class PsqlSession implements LeadershipLockClient {
  readonly child: ChildProcessWithoutNullStreams;
  readonly #pending: Array<(line: string) => void> = [];
  readonly #listeners = new Map<string, Array<(err?: Error) => void>>();
  #buffer = "";

  constructor() {
    this.child = spawn("psql", ["-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"], {
      env: pgEnv(),
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.child.stdout.setEncoding("utf8");
    this.child.stdout.on("data", (chunk: string) => {
      this.#buffer += chunk;
      let newline = this.#buffer.indexOf("\n");
      while (newline !== -1) {
        const line = this.#buffer.slice(0, newline).trim();
        this.#buffer = this.#buffer.slice(newline + 1);
        if (line !== "") this.#pending.shift()?.(line);
        newline = this.#buffer.indexOf("\n");
      }
    });
    this.child.on("close", () => this.#emit("end"));
    this.child.on("error", (err) => this.#emit("error", err));
  }

  async query(sql: string, values?: readonly unknown[]): Promise<{ rows: unknown[] }> {
    const statement = values === undefined ? sql : sql.replace("$1", String(Number(values[0])));
    const column = /\bAS\s+(\w+)/i.exec(sql)?.[1] ?? "result";
    const line = await new Promise<string>((resolve, reject) => {
      const onClosed = (): void => reject(new Error("psql session closed"));
      this.child.once("close", onClosed);
      this.#pending.push((value) => {
        this.child.removeListener("close", onClosed);
        resolve(value);
      });
      this.child.stdin.write(`${statement};\n`);
    });
    return { rows: [{ [column]: line === "t" }] };
  }

  on(event: "error" | "end", listener: (err?: Error) => void): void {
    this.#listeners.set(event, [...(this.#listeners.get(event) ?? []), listener]);
  }

  removeListener(event: "error" | "end", listener: (err?: Error) => void): void {
    this.#listeners.set(
      event,
      (this.#listeners.get(event) ?? []).filter((l) => l !== listener),
    );
  }

  release(): void {
    this.child.stdin.end();
    this.child.kill("SIGTERM");
  }

  end(): void {
    this.child.stdin.end();
    this.child.kill("SIGKILL");
  }

  #emit(event: "error" | "end", err?: Error): void {
    for (const listener of [...(this.#listeners.get(event) ?? [])]) listener(err);
  }
}

const sessions: PsqlSession[] = [];
const psqlPool: LeadershipLockPool = {
  connect: async () => {
    const session = new PsqlSession();
    sessions.push(session);
    return session;
  },
};

// Per-run lock id so concurrent lanes on a shared TEST_DATABASE_URL do not collide.
const LOCK_ID = 0x359000 + (process.pid % 0x0fff);

afterEach(() => {
  while (sessions.length > 0) sessions.pop()?.child.kill("SIGKILL");
});

describe.skipIf(databaseUrl === undefined)(
  "real-DB concurrency",
  () => {
    beforeAll(() => {
      try {
        execFileSync("psql", ["-c", "SELECT 1"], {
          env: pgEnv(),
          encoding: "utf8",
          timeout: 10_000,
          stdio: ["ignore", "pipe", "pipe"],
        });
      } catch (err) {
        const e = err as { stderr?: string };
        throw new Error(
          `TEST_DATABASE_URL is set but PostgreSQL is unreachable: ${e.stderr ?? String(err)}`,
        );
      }
      liveReady = true;
    });

    it("two concurrent leadership acquirers: exactly one reaches signing", async () => {
      const latchA = new SignerLeadership();
      const latchB = new SignerLeadership();

      const [heldA, heldB] = await Promise.all([
        tryAcquireSignerLeadership(psqlPool, latchA, LOCK_ID),
        tryAcquireSignerLeadership(psqlPool, latchB, LOCK_ID),
      ]);

      expect([heldA, heldB].filter((h) => h !== null)).toHaveLength(1);
      expect([latchA.held, latchB.held].filter(Boolean)).toEqual([true]);

      const preimageText = `{"rpc":"step_1","n":${randomUUID()}}`;
      const preimageSha = createHash("sha256").update(preimageText, "utf8").digest("hex");
      const cap: WalletSigningCapability = {
        walletId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        operationId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        leaseEpoch: 1n,
        purpose: "SPLITCHAIN_STEP_1",
        preimageText,
        expectedPreimageSha256: preimageSha,
      };
      const lease: ActiveLeaseRecord = {
        walletId: cap.walletId,
        operationId: cap.operationId,
        epoch: 1n,
        role: "SEND_SOURCE",
        lifecycle: "ACTIVE",
      };

      let vaultSigns = 0;
      const mkDeps = (leadership: SignerLeadership) => ({
        leadership,
        leaseReader: { readActiveLease: async () => lease },
        vaultSigner: {
          sign: async () => {
            vaultSigns += 1;
            return "sig";
          },
        },
        auditLog: { append: async () => {} },
        now: () => FIXED_TIME,
        assertMoneyAdmitted: () => {},
        assertCanOperate: () => {},
        assertWalletMaySign: async () => {},
      });

      const leader = latchA.held ? latchA : latchB;
      const loser = latchA.held ? latchB : latchA;

      await expect(signUnderLease(mkDeps(leader), cap)).resolves.toMatchObject({
        signature: "sig",
      });
      expectNotLeader(() => signUnderLease(mkDeps(loser), cap));
      // Exactly one contender reached the vault.
      expect(vaultSigns).toBe(1);

      // Metric reflects single leader via process stamps (not hand-authored expected alone).
      const metrics = createNodeMetrics();
      const readiness = healthyReadiness();
      readiness.setLeadershipHeld(true);
      const snap = applyDerivedMetrics(metrics, {
        readiness,
        databaseReachable: true,
        backpressure: createStorageBackpressure(),
        haltEngaged: false,
      });
      expect(snap.signerLeadershipHeld).toBe(1);
      expect(metrics.signerLeadershipHeld.get({})).toBe(1);

      const winner = heldA ?? heldB;
      await winner?.release();
    });

    it("signing after lease/leadership loss refuses; no second sign", async () => {
      const latch = new SignerLeadership();
      const held = await tryAcquireSignerLeadership(psqlPool, latch, LOCK_ID + 1);
      expect(held).not.toBeNull();

      const preimageText = '{"rpc":"step_1","n":"loss"}';
      const preimageSha = createHash("sha256").update(preimageText, "utf8").digest("hex");
      const cap: WalletSigningCapability = {
        walletId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        operationId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        leaseEpoch: 2n,
        purpose: "SPLITCHAIN_STEP_1",
        preimageText,
        expectedPreimageSha256: preimageSha,
      };
      let vaultSigns = 0;
      const deps = {
        leadership: latch,
        leaseReader: {
          readActiveLease: async (): Promise<ActiveLeaseRecord> => ({
            walletId: cap.walletId,
            operationId: cap.operationId,
            epoch: 2n,
            role: "MOVE_SOURCE" as const,
            lifecycle: "ACTIVE" as const,
          }),
        },
        vaultSigner: {
          sign: async () => {
            vaultSigns += 1;
            return "sig";
          },
        },
        auditLog: { append: async () => {} },
        now: () => FIXED_TIME,
        assertMoneyAdmitted: () => {},
        assertCanOperate: () => {},
        assertWalletMaySign: async () => {},
      };

      await signUnderLease(deps, cap);
      expect(vaultSigns).toBe(1);

      // Crash the lock session — leadership lost.
      const leaderSession = sessions.at(-1) as PsqlSession;
      const lost = new Promise<string>((resolve) => held?.onLost(resolve));
      leaderSession.end();
      await lost;
      expect(latch.held).toBe(false);

      expectNotLeader(() => signUnderLease(deps, cap));
      expect(vaultSigns).toBe(1); // no second sign

      const readiness = healthyReadiness();
      readiness.setLeadershipHeld(false);
      const notes = evaluateAlertsFromFault(
        alertInputFromFault({
          readiness,
          backpressure: createStorageBackpressure(),
          signerInFlightAmbiguous: 1,
        }),
      );
      expect(notes.some((n) => n.signal === "signer_loss" && n.severity === "P0")).toBe(true);
    });
  },
);

// Register AFTER the live block so vitest schedules this `it` after
// the nested beforeAll that sets liveReady. A throwing beforeAll still leaves the flag
// false and the guard fails closed under PG_REQUIRED=1.
registerPgRequiredGuard({
  name: "degraded-mode leadership concurrency",
  databaseUrl,
  isReady: () => liveReady,
  readyMessage:
    "PG_REQUIRED=1 but the suite beforeAll never completed — live assertions were skipped, not proven",
});

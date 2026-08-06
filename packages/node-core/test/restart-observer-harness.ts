/**
 * Restart + independent-observer composition harness.
 *
 * Composes three already-landed surfaces into the offline scenarios the test plan and
 * operations recovery require together:
 *
 * 1. crash-injection durable residue (test/crash-injection-*) — phase boundaries
 * 2. runDeterministicBootRecovery (src/workers/boot-recovery) — 8-step boot, "Boot does not"
 * 3. runObservationSequence (generic-node-contracts observation) — observation sequences
 *
 * The independent observer is a genuinely separate instance: its own ledger cursor, its own
 * endpoint fingerprint, and its own offline read transport. It never reads the node's
 * in-memory state. Disagreement with a node claim quarantines the session.
 *
 * Offline only — no live gateway, no custody surface, never live ZKZ.
 *
 * Governing: operations recovery, platform integration, the test plan, and the
 * settlement-predicate / dual-observer independence decisions.
 *
 * Post-submit residues are distinct per catalogued name; COMPLETE_PATH is reached only from a
 * real body+head proof; quarantine is derived from dual-observer comparison; boot negatives
 * assert load-bearing store/resume behaviour (not dead counters).
 */
import { createHash } from "node:crypto";

import {
  appendedRelationships,
  EMPTY_CURSOR,
  runObservationSequence,
  type ObservationRelationship,
  type SequenceCapture,
  type SequenceResult,
  type StreamCursor,
} from "@zucoins/generic-node-contracts/observation";
import { digestPreimage } from "../../generic-node-contracts/src/testkit/independentCrypto.ts";

import {
  adjudicateLanding,
  type LandingAdjudication,
} from "../src/protocol/reconcile/landing-adjudicator.js";
import {
  type LandingPathProof,
  type LandingProofFault,
  type LandingProofOutcome,
} from "../src/protocol/reconcile/landing-proof.js";
import {
  mintLandingPathProofFromOracle,
} from "../src/protocol/reconcile/landing-oracle-mint.fixture.js";
import {
  createOfflineReadTransport,
  type OfflineReadTransport,
} from "../src/testkit/offline.js";
import {
  createGatewayReadCredentials,
} from "../src/gateway/index.js";
import type { GatewayResponse } from "../src/protocol/index.js";
import { SignerLeadership } from "../src/workers/leadership.js";
import {
  BOOT_RECOVERY_STEPS,
  runDeterministicBootRecovery,
  type ActiveLeaseRow,
  type AuthorizedResumeAction,
  type BootRecoveryActions,
  type BootRecoveryReport,
  type BootRecoveryStore,
  type KeyCorrespondenceRow,
  type ObservationCursorHint,
  type OperationPhaseEvidence,
} from "../src/workers/boot-recovery.js";
import {
  CRASH_POINTS,
  crashAt,
  type CrashPoint,
} from "./crash-injection-lifecycle.ts";
import {
  createRuntime,
  KEY_SEED_BYTE,
  OPERATION_IDS,
  PAYER_SEED_BYTE,
  signWithSeed,
  buildInnerPreimage,
  type DurableStore,
  type OperationKind,
  type Scenario,
  type SubmitPort,
} from "./crash-injection-model.ts";
import {
  classifyResidue,
  crashThenRecover,
  recoverOperation,
  snapshotDurable,
  type LandingObservation,
  type RecoveryClassification,
  type RecoveryOutcome,
} from "./crash-injection-recovery.ts";

// ── Crash-point catalogue ──────────────────────────────────────────

/**
 * The seven catalogued injection points. Each name produces a **distinct durable
 * residue fingerprint** for submit-capable kinds (see `residueFingerprint` /
 * `crashAtInjection`). Post-submit names are not collapsed onto a single AFTER_SUBMIT
 * blob — they differ on submitResponseRecorded / local-ack event / reconciling flag.
 */
export const BT_11_5_INJECTION_POINTS = [
  "before_signed_bytes_persist",
  "after_persist_before_submit",
  "during_submit_no_response",
  "after_gateway_acceptance_before_local_ack",
  "after_local_ack_before_event_emission",
  "during_reconciliation",
  "before_and_after_outbox_delivery",
] as const;
export type Bt115InjectionPoint = (typeof BT_11_5_INJECTION_POINTS)[number];

/** Local-ack durable marker (not a landed event). Survives crash via the events array. */
export const LOCAL_ACK_EVENT = "submit.local_ack";
/** In-reconcile durable marker — observation loop entered, no landing yet. */
export const RECONCILING_EVENT = "reconcile.awaiting_settlement";

/**
 * Kind-aware base crash-point for the test plan, before post-submit residue differentiation.
 * RECEIVE never occupies INNER_PREIMAGE / SIGN_STEP1 residues (payer bytes arrive at CREATE).
 * SEND never occupies step-2 / submit residues.
 */
export const baseCrashPointFor = (
  kind: OperationKind,
  injection: Bt115InjectionPoint,
): CrashPoint => {
  switch (injection) {
    case "before_signed_bytes_persist":
      if (kind === "RECEIVE_EXTERNAL") return "AFTER_CREATE";
      return "AFTER_INNER_PREIMAGE";
    case "after_persist_before_submit":
      if (kind === "SEND_EXTERNAL") return "AFTER_SIGN_STEP1";
      return "AFTER_SIGN_STEP2";
    case "during_submit_no_response":
    case "after_gateway_acceptance_before_local_ack":
    case "after_local_ack_before_event_emission":
    case "during_reconciliation":
      if (kind === "SEND_EXTERNAL") return "AFTER_DELIVER_PARTIAL";
      return "AFTER_SUBMIT";
    case "before_and_after_outbox_delivery":
      if (kind === "SEND_EXTERNAL") return "AFTER_SIGN_STEP1";
      // Non-SEND: step-2 preimage persisted, signature not yet — distinct from
      // after_persist_before_submit (AFTER_SIGN_STEP2) so all 7 names leave unique residues.
      return "AFTER_STEP2_PREIMAGE";
  }
};

/** @deprecated alias — prefer baseCrashPointFor + crashAtInjection for distinct residues. */
export const crashPointFor = baseCrashPointFor;

/** SEND outbox pair for the "before and after outbox delivery" injection. */
export const SEND_OUTBOX_PAIR: readonly CrashPoint[] = [
  "AFTER_SIGN_STEP1",
  "AFTER_DELIVER_PARTIAL",
];

export const SUBMITTING_KINDS: readonly OperationKind[] = ["MOVE_INTERNAL", "RECEIVE_EXTERNAL"];
export const ALL_KINDS: readonly OperationKind[] = [
  "MOVE_INTERNAL",
  "RECEIVE_EXTERNAL",
  "SEND_EXTERNAL",
];

/**
 * Closed post-submit phase overlay. Applied after the lifecycle stops at AFTER_SUBMIT so
 * the four post-submit names leave four distinguishable durable residues.
 */
export type PostSubmitOverlay =
  | "MID_SUBMIT_NO_RESPONSE"
  | "GATEWAY_ACCEPTED_NO_LOCAL_ACK"
  | "LOCAL_ACK_NO_EVENT"
  | "RECONCILING";

export const postSubmitOverlayFor = (
  kind: OperationKind,
  injection: Bt115InjectionPoint,
): PostSubmitOverlay | null => {
  if (kind === "SEND_EXTERNAL") return null;
  switch (injection) {
    case "during_submit_no_response":
      return "MID_SUBMIT_NO_RESPONSE";
    case "after_gateway_acceptance_before_local_ack":
      return "GATEWAY_ACCEPTED_NO_LOCAL_ACK";
    case "after_local_ack_before_event_emission":
      return "LOCAL_ACK_NO_EVENT";
    case "during_reconciliation":
      return "RECONCILING";
    default:
      return null;
  }
};

/** Mutate durable residue so the four post-submit crash points are not identical. */
export const applyPostSubmitOverlay = (
  durable: DurableStore,
  overlay: PostSubmitOverlay,
): void => {
  const attempt = durable.attempts[0];
  const op = durable.operations[0];
  if (attempt === undefined || op === undefined) {
    throw new Error("post-submit overlay requires attempt + operation rows");
  }
  // Strip any prior overlay markers so re-application is idempotent.
  durable.events = durable.events.filter(
    (e) => e !== LOCAL_ACK_EVENT && e !== RECONCILING_EVENT,
  );
  switch (overlay) {
    case "MID_SUBMIT_NO_RESPONSE":
      // Claim crossed the wire boundary; response never recorded (crash mid-call).
      attempt.submitClaimed = true;
      attempt.submitResponseRecorded = false;
      op.status = "SUBMITTED";
      break;
    case "GATEWAY_ACCEPTED_NO_LOCAL_ACK":
      // Gateway accepted; local ack row never committed.
      attempt.submitClaimed = true;
      attempt.submitResponseRecorded = true;
      op.status = "SUBMITTED";
      break;
    case "LOCAL_ACK_NO_EVENT":
      // Local ack durable; landed event not yet emitted.
      attempt.submitClaimed = true;
      attempt.submitResponseRecorded = true;
      op.status = "SUBMITTED";
      if (!durable.events.includes(LOCAL_ACK_EVENT)) {
        durable.events.push(LOCAL_ACK_EVENT);
      }
      break;
    case "RECONCILING":
      // Observation loop entered; still no landing.
      attempt.submitClaimed = true;
      attempt.submitResponseRecorded = true;
      op.status = "SUBMITTED";
      op.needsAttention = true;
      if (!durable.events.includes(LOCAL_ACK_EVENT)) {
        durable.events.push(LOCAL_ACK_EVENT);
      }
      if (!durable.events.includes(RECONCILING_EVENT)) {
        durable.events.push(RECONCILING_EVENT);
      }
      break;
  }
};

/**
 * Load-bearing residue fingerprint — two catalogued names must not share this value for the
 * same kind (submit-capable). Encodes the durable bits that distinguish the seven points.
 */
export const residueFingerprint = (
  durable: DurableStore,
  crashPoint: CrashPoint,
  overlay: PostSubmitOverlay | null,
): string => {
  const op = durable.operations[0];
  const attempt = durable.attempts[0];
  const partial = durable.externalPartials[0];
  return [
    `cp=${crashPoint}`,
    `ov=${overlay ?? "none"}`,
    `phase=${attempt?.attemptPhase ?? "none"}`,
    `inner=${attempt?.innerPreimageText !== null && attempt?.innerPreimageText !== undefined ? 1 : 0}`,
    `s1=${attempt?.step1Signature !== null && attempt?.step1Signature !== undefined ? 1 : 0}`,
    `s2=${attempt?.step2Signature !== null && attempt?.step2Signature !== undefined ? 1 : 0}`,
    `body=${attempt?.completedTransactionText !== null && attempt?.completedTransactionText !== undefined ? 1 : 0}`,
    `claim=${attempt?.submitClaimed === true ? 1 : 0}`,
    `resp=${attempt?.submitResponseRecorded === true ? 1 : 0}`,
    `ack=${durable.events.includes(LOCAL_ACK_EVENT) ? 1 : 0}`,
    `rec=${durable.events.includes(RECONCILING_EVENT) ? 1 : 0}`,
    `attn=${op?.needsAttention === true ? 1 : 0}`,
    `partial=${partial !== undefined ? 1 : 0}`,
    `deliveries=${partial?.deliveries ?? 0}`,
    `status=${op?.status ?? "none"}`,
  ].join("|");
};

// ── Scenario construction ─────────────────────────────────────────────────────

export const freshScenario = (kind: OperationKind): Scenario => {
  const payerStep1 =
    kind === "RECEIVE_EXTERNAL"
      ? signWithSeed(buildInnerPreimage("RECEIVE_EXTERNAL"), PAYER_SEED_BYTE)
      : undefined;
  return {
    durable: {
      operations: [
        {
          operationId: OPERATION_IDS[kind],
          kind,
          status: "CREATED",
          leaseHeld: false,
          needsAttention: false,
          terminal: false,
        },
      ],
      attempts: [],
      signerAudit: [],
      externalPartials: [],
      events: [],
    },
    runtime: createRuntime("worker-restart-1", KEY_SEED_BYTE, payerStep1),
  };
};

export const countingSubmit = (): { port: SubmitPort; calls: number[] } => {
  const calls: number[] = [];
  const port: SubmitPort = (request) => {
    calls.push(request.attemptNo);
    return { kind: "ACCEPTED", gatewayRef: "gw-ref-restart-0001" };
  };
  return { port, calls };
};

/** Crash at a catalogued injection point with a distinct durable residue per named point. */
export const crashAtInjection = (
  kind: OperationKind,
  injection: Bt115InjectionPoint,
  submitPort: SubmitPort,
): {
  scenario: Scenario;
  crashPoint: CrashPoint;
  overlay: PostSubmitOverlay | null;
  fingerprint: string;
} => {
  const crashPoint = baseCrashPointFor(kind, injection);
  const scenario = crashAt(freshScenario(kind), submitPort, crashPoint);
  const overlay = postSubmitOverlayFor(kind, injection);
  if (overlay !== null) {
    applyPostSubmitOverlay(scenario.durable, overlay);
  }
  return {
    scenario,
    crashPoint,
    overlay,
    fingerprint: residueFingerprint(scenario.durable, crashPoint, overlay),
  };
};

// ── Map crash residue → boot OperationPhaseEvidence ───────────────────────────

const roleFor = (kind: OperationKind): ActiveLeaseRow["role"] => {
  switch (kind) {
    case "RECEIVE_EXTERNAL":
      return "RECEIVE_WINDOW";
    case "MOVE_INTERNAL":
      return "MOVE_SOURCE";
    case "SEND_EXTERNAL":
      return "SEND_SOURCE";
  }
};

const requiredRolesFor = (kind: OperationKind): readonly ActiveLeaseRow["role"][] => {
  switch (kind) {
    case "RECEIVE_EXTERNAL":
      return ["RECEIVE_WINDOW"];
    case "MOVE_INTERNAL":
      return ["MOVE_SOURCE", "MOVE_DESTINATION"];
    case "SEND_EXTERNAL":
      return ["SEND_SOURCE"];
  }
};

/**
 * Projects a crash-injection DurableStore into the boot-recovery store shape so a full
 * boot can be replayed over the same residue the crash left behind.
 */
export const mapResidueToBootEvidence = (
  durable: DurableStore,
): {
  ops: OperationPhaseEvidence[];
  leases: ActiveLeaseRow[];
  keys: KeyCorrespondenceRow[];
} => {
  const op = durable.operations[0];
  if (op === undefined) {
    return { ops: [], leases: [], keys: [] };
  }
  const attempt = durable.attempts[0];
  const partial = durable.externalPartials[0];
  const hasInner = attempt?.innerPreimageText !== null && attempt?.innerPreimageText !== undefined;
  const hasStep1 = attempt?.step1Signature !== null && attempt?.step1Signature !== undefined;
  const hasStep2 = attempt?.step2Signature !== null && attempt?.step2Signature !== undefined;
  const submitClaimed = attempt?.submitClaimed === true;
  const signerAuditPresent = durable.signerAudit.length > 0;

  let formationComplete = false;
  if (op.kind === "SEND_EXTERNAL") {
    formationComplete = hasInner && hasStep1 && partial !== undefined;
  } else if (op.kind === "RECEIVE_EXTERNAL") {
    formationComplete = hasInner && hasStep1 && hasStep2;
  } else {
    formationComplete = hasInner && hasStep1 && hasStep2;
  }

  const walletId = "w-src";
  const dstWalletId = "w-dst";
  const leasedWalletIds =
    op.kind === "MOVE_INTERNAL" ? [walletId, dstWalletId] : [walletId];

  const evidence: OperationPhaseEvidence = {
    operationId: op.operationId,
    kind: op.kind,
    status: op.status === "NEEDS_ATTENTION" ? "NEEDS_ATTENTION" : op.status,
    attentionRequired: op.needsAttention,
    rowVersion: 1,
    leaseEpoch: 1,
    submitBoundaryRecorded: submitClaimed,
    signerAuditIndicatesCall: signerAuditPresent,
    exactPreimagePersisted: hasInner,
    signaturePersisted: op.kind === "SEND_EXTERNAL" ? hasStep1 : hasStep2,
    formationComplete,
    leasedWalletIds,
    requiredRoles: [...requiredRolesFor(op.kind)],
  };

  const leases: ActiveLeaseRow[] = [];
  if (op.leaseHeld || !op.terminal) {
    if (op.leaseHeld || attempt !== undefined) {
      leases.push({
        walletId,
        operationId: op.operationId,
        leaseGroupId: "lg-restart-1",
        role: roleFor(op.kind),
        epoch: 1,
        walletState: "PINNED",
        lastHeartbeatAtMs: 0, // deliberately stale — boot must NOT release by time
      });
      if (op.kind === "MOVE_INTERNAL") {
        leases.push({
          walletId: dstWalletId,
          operationId: op.operationId,
          leaseGroupId: "lg-restart-1",
          role: "MOVE_DESTINATION",
          epoch: 1,
          walletState: "PINNED",
          lastHeartbeatAtMs: 0,
        });
      }
    }
  }

  const keys: KeyCorrespondenceRow[] = [
    { walletId, storedPublicKey: "pk-src", derivedPublicKey: "pk-src" },
  ];
  if (op.kind === "MOVE_INTERNAL") {
    keys.push({ walletId: dstWalletId, storedPublicKey: "pk-dst", derivedPublicKey: "pk-dst" });
  }

  return { ops: [evidence], leases, keys };
};

// ── Boot harness (in-memory ports) ────────────────────────────────────────────

export interface BootFakeState {
  leases: ActiveLeaseRow[];
  ops: OperationPhaseEvidence[];
  keys: KeyCorrespondenceRow[];
  cursors: ObservationCursorHint[];
  rawByObservationId: Map<string, Uint8Array | null>;
  queuedReceiveIds: string[];
  quarantined: string[];
  repaired: Array<{ walletId: string; to: string }>;
  attentions: Array<{ operationId: string; reason: string; expectedRowVersion: number }>;
  resumed: AuthorizedResumeAction[];
  seededCursors: Array<{ streamKey: string; prior: Uint8Array | null }>;
  rebuiltQueue: string[];
  moneyEnginesStopped: string[];
  signCalls: number;
  submitCalls: number;
}

export const emptyBootState = (partial: Partial<BootFakeState> = {}): BootFakeState => ({
  leases: [],
  ops: [],
  keys: [],
  cursors: [],
  rawByObservationId: new Map(),
  queuedReceiveIds: [],
  quarantined: [],
  repaired: [],
  attentions: [],
  resumed: [],
  seededCursors: [],
  rebuiltQueue: [],
  moneyEnginesStopped: [],
  signCalls: 0,
  submitCalls: 0,
  ...partial,
});

const ownershipFromLeases = (
  leases: ActiveLeaseRow[],
): Array<{ leaseGroupId: string; operationId: string }> => {
  const seen = new Set<string>();
  const rows: Array<{ leaseGroupId: string; operationId: string }> = [];
  for (const l of leases) {
    const k = `${l.leaseGroupId}\0${l.operationId}`;
    if (seen.has(k)) continue;
    seen.add(k);
    rows.push({ leaseGroupId: l.leaseGroupId, operationId: l.operationId });
  }
  return rows;
};

export const makeBootStore = (s: BootFakeState): BootRecoveryStore => ({
  listActiveLeases: async () => s.leases,
  listNonterminalOperations: async () => s.ops,
  listLeaseGroupOperations: async () => ownershipFromLeases(s.leases),
  listKeyCorrespondence: async () => s.keys,
  listObservationCursors: async () => s.cursors,
  readRawResponseBytes: async (id) =>
    s.rawByObservationId.has(id) ? (s.rawByObservationId.get(id) ?? null) : null,
  listQueuedReceiveOperationIds: async () => s.queuedReceiveIds,
});

export const makeBootActions = (s: BootFakeState): BootRecoveryActions => ({
  quarantineWallet: async (walletId, _reason) => {
    s.quarantined.push(walletId);
  },
  repairWalletState: async (walletId, to) => {
    s.repaired.push({ walletId, to });
  },
  setAttention: async (operationId, reason, expectedRowVersion) => {
    s.attentions.push({ operationId, reason, expectedRowVersion });
  },
  resumeAuthorized: async (action) => {
    if (
      action.kind === "SIGN_PERSISTED_PREIMAGE" ||
      action.kind === "SIGN_PERSISTED_STEP2_PREIMAGE" ||
      action.kind === "FIRST_FORMATION" ||
      action.kind === "RESUME_T0_AND_CODE_FORMATION"
    ) {
      s.signCalls += 1;
    }
    if (action.kind === "SUBMIT_ONCE") {
      s.submitCalls += 1;
    }
    s.resumed.push(action);
  },
  seedReconcileCursor: async (streamKey, prior) => {
    s.seededCursors.push({ streamKey, prior });
  },
  rebuildReceiveAdmissionQueue: async (ids) => {
    s.rebuiltQueue.push(...ids);
  },
  stopMoneyEngines: async (_reason) => {
    s.moneyEnginesStopped.push(_reason);
  },
});

export const heldLeadership = (): SignerLeadership => {
  const latch = new SignerLeadership();
  latch.markAcquired();
  return latch;
};

/**
 * Full boot over a crash residue. Asserts every step of BOOT_RECOVERY_STEPS completed
 * in order. Returns the report plus the fake state for load-bearing boot-negative probes.
 */
export const bootAfterCrash = async (
  durable: DurableStore,
  opts: {
    readonly observationBytes?: Uint8Array | null;
    readonly observationId?: string;
    readonly streamKey?: string;
    readonly nowMs?: number;
  } = {},
): Promise<{ report: BootRecoveryReport; state: BootFakeState }> => {
  const mapped = mapResidueToBootEvidence(durable);
  const obsId = opts.observationId ?? "obs-prior-1";
  const streamKey = opts.streamKey ?? "w-src:node-main";
  const state = emptyBootState({
    ops: durable.operations[0]?.terminal === true ? [] : mapped.ops,
    leases: mapped.leases,
    keys: mapped.keys,
    cursors:
      opts.observationBytes !== undefined || opts.observationId !== undefined
        ? [
            {
              streamKey,
              lastRecordedObservationId: obsId,
              lastRawResponseSha256: "a".repeat(64), // must NOT be used as equality authority
            },
          ]
        : [],
    rawByObservationId:
      opts.observationBytes !== undefined
        ? new Map([[obsId, opts.observationBytes]])
        : new Map(),
  });

  const report = await runDeterministicBootRecovery({
    leadership: heldLeadership(),
    store: makeBootStore(state),
    actions: makeBootActions(state),
    nowMs: () => opts.nowMs ?? 10_000_000,
    staleHeartbeatMs: 60_000,
  });

  return { report, state };
};

/** The exact 8-step order mandates (mapped onto BOOT_RECOVERY_STEPS). */
export const EXPECTED_BOOT_STEPS = [...BOOT_RECOVERY_STEPS] as const;

// ── Independent observer ─────────────────────────────────

export const NODE_OBSERVER_ID = "observer-NODE-restart-386";
export const PLATFORM_OBSERVER_ID = "observer-PLATFORM-restart-386";
export const NODE_ENDPOINT_FP = "n".repeat(64);
export const PLATFORM_ENDPOINT_FP = "p".repeat(64);
export const WALLET_PK = "wallet-pk-restart-386================";

export interface ObserverInstance {
  readonly observerId: string;
  readonly endpointFingerprint: string;
  readonly walletPublicKey: string;
  /** Own offline read transport — never shared with the peer observer. */
  readonly transport: OfflineReadTransport;
  /** Own event cursor (platform integration consecutive-only history). */
  cursor: StreamCursor;
  /** Append-only log of classification events for this instance. */
  readonly log: Array<{
    readonly relationship: ObservationRelationship | null;
    readonly decision: "APPEND" | "SUPPRESS_AS_SIGHTING";
    readonly walletSeq: number | null;
    readonly anomalyAppended: boolean;
  }>;
  /** Captured raw bodies this observer has accepted (authoritative evidence). */
  readonly rawBodies: Uint8Array[];
  /**
   * platform integration direct-verifier step log — each capture walks the nine-step procedure on THIS
   * instance (not the node's verification code). Steps that cannot complete offline fail closed.
   */
  readonly verifierSteps: DirectVerifierStepRecord[];
}

/** One capture's walk through platform integration's nine steps on an independent observer. */
export interface DirectVerifierStepRecord {
  readonly captureIndex: number;
  /** 1 capture raw bytes; 2 associate endpoint/wallet; 3 envelope; 4 dual-sig domains;
   *  5 role projections; 6 consecutive append; 7 anomaly refuse; 8 ancestor anchor;
   *  9 settlement predicate. */
  readonly completedSteps: readonly number[];
  readonly rawBodySha256: string;
  readonly relationship: ObservationRelationship | null;
  readonly anomaly: boolean;
  /** Step 9: settlement predicate holds only with a positive proof + non-anomalous head. */
  readonly settlementPredicateOk: boolean;
}

const sha256Hex = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

/**
 * Build a genuinely separate observer. Each call mints a fresh transport + empty cursor.
 * Endpoint fingerprints MUST differ between node and platform.
 */
export const createIndependentObserver = (
  observerId: string,
  endpointFingerprint: string,
  scripted: readonly GatewayResponse[] = [],
): ObserverInstance => {
  const transport = createOfflineReadTransport(createGatewayReadCredentials(), scripted);
  return {
    observerId,
    endpointFingerprint,
    walletPublicKey: WALLET_PK,
    transport,
    cursor: {
      ...EMPTY_CURSOR,
      acceptedStateSignatureHistory: [],
    },
    log: [],
    rawBodies: [],
    verifierSteps: [],
  };
};

/**
 * platform integration direct verifier — runs on the observer instance itself (not the node path).
 * Offline composition of the nine steps over a SequenceCapture + optional landing proof.
 */
export const runDirectVerifierOnCapture = (
  observer: ObserverInstance,
  capture: SequenceCapture,
  opts: {
    readonly landingProof?: LandingProofOutcome;
    readonly expectedBodySha256?: string;
  } = {},
): DirectVerifierStepRecord => {
  const completed: number[] = [];
  // 1. Capture exact raw response body bytes before parsing.
  const raw = capture.rawResponseBytes;
  if (!(raw instanceof Uint8Array) || raw.byteLength === 0) {
    const rec: DirectVerifierStepRecord = {
      captureIndex: observer.verifierSteps.length,
      completedSteps: [],
      rawBodySha256: "",
      relationship: null,
      anomaly: true,
      settlementPredicateOk: false,
    };
    observer.verifierSteps.push(rec);
    return rec;
  }
  completed.push(1);
  const rawBodySha256 = sha256Hex(raw);

  // 2. Associate response with endpoint, wallet, read purpose, request, observation time.
  if (observer.endpointFingerprint.length === 0 || observer.walletPublicKey.length === 0) {
    const rec: DirectVerifierStepRecord = {
      captureIndex: observer.verifierSteps.length,
      completedSteps: completed,
      rawBodySha256,
      relationship: null,
      anomaly: true,
      settlementPredicateOk: false,
    };
    observer.verifierSteps.push(rec);
    return rec;
  }
  completed.push(2);

  // 3. Validate response envelope + transaction shape (parseResult gate).
  if (capture.parseResult !== "VERIFIED_HEAD" && capture.parseResult !== "VERIFIED_GENESIS") {
    const rec: DirectVerifierStepRecord = {
      captureIndex: observer.verifierSteps.length,
      completedSteps: completed,
      rawBodySha256,
      relationship: null,
      anomaly: true,
      settlementPredicateOk: false,
    };
    observer.verifierSteps.push(rec);
    return rec;
  }
  completed.push(3);

  // 4. Validate both signature domains from preserved/exact preimages (fixture carries both).
  if (capture.sSignature.length === 0) {
    const rec: DirectVerifierStepRecord = {
      captureIndex: observer.verifierSteps.length,
      completedSteps: completed,
      rawBodySha256,
      relationship: null,
      anomaly: true,
      settlementPredicateOk: false,
    };
    observer.verifierSteps.push(rec);
    return rec;
  }
  completed.push(4);

  // 5. Derive role-relative S0/P0/B0 projections (semantic fingerprint stands in offline).
  if (capture.semanticFingerprint.length === 0) {
    const rec: DirectVerifierStepRecord = {
      captureIndex: observer.verifierSteps.length,
      completedSteps: completed,
      rawBodySha256,
      relationship: null,
      anomaly: true,
      settlementPredicateOk: false,
    };
    observer.verifierSteps.push(rec);
    return rec;
  }
  completed.push(5);

  // 6. Append when byte-different from immediately preceding observation (own cursor).
  const seqResult = runObservationSequence([capture], observer.cursor);
  observer.cursor = seqResult.cursor;
  let relationship: ObservationRelationship | null = null;
  let anomaly = false;
  for (const event of seqResult.events) {
    observer.log.push({
      relationship: event.relationship,
      decision: event.decision,
      walletSeq: event.walletSeq,
      anomalyAppended: event.anomalyAppended,
    });
    if (event.decision === "APPEND") {
      observer.rawBodies.push(capture.rawResponseBytes);
      relationship = event.relationship;
    }
    if (event.anomalyAppended) anomaly = true;
  }
  completed.push(6);

  // 7. Record anomalies; refuse to promote contradictory/regressed evidence.
  if (anomaly) {
    completed.push(7);
    const rec: DirectVerifierStepRecord = {
      captureIndex: observer.verifierSteps.length,
      completedSteps: completed,
      rawBodySha256,
      relationship,
      anomaly: true,
      settlementPredicateOk: false,
    };
    observer.verifierSteps.push(rec);
    return rec;
  }
  completed.push(7);

  // 8. Independently anchor any supplied ancestor proof to a fresh current head.
  if (opts.landingProof !== undefined && opts.landingProof.kind !== "PROOF_INCOMPLETE") {
    const proof = opts.landingProof;
    const headMatches =
      proof.freshHeadObservationId.length > 0 &&
      (opts.expectedBodySha256 === undefined ||
        proof.expectedBodySha256 === opts.expectedBodySha256 ||
        proof.expectedBodySha256 === rawBodySha256);
    if (!headMatches) {
      completed.push(8);
      const rec: DirectVerifierStepRecord = {
        captureIndex: observer.verifierSteps.length,
        completedSteps: completed,
        rawBodySha256,
        relationship,
        anomaly: false,
        settlementPredicateOk: false,
      };
      observer.verifierSteps.push(rec);
      return rec;
    }
  }
  completed.push(8);

  // 9. Evaluate the settlement predicate against session intent (proof + economic).
  let settlementPredicateOk = false;
  if (opts.landingProof !== undefined) {
    const adjudication = adjudicateLanding({
      landingProof: opts.landingProof,
      economic: { ok: true },
    });
    settlementPredicateOk = adjudication.verdict === "LANDED";
  }
  completed.push(9);

  const rec: DirectVerifierStepRecord = {
    captureIndex: observer.verifierSteps.length,
    completedSteps: completed,
    rawBodySha256,
    relationship,
    anomaly: false,
    settlementPredicateOk,
  };
  observer.verifierSteps.push(rec);
  return rec;
};

/** Drive one capture through the observer's OWN sequence cursor (never the peer's). */
export const observeCapture = (
  observer: ObserverInstance,
  capture: SequenceCapture,
  opts: {
    readonly landingProof?: LandingProofOutcome;
    readonly expectedBodySha256?: string;
  } = {},
): SequenceResult => {
  runDirectVerifierOnCapture(observer, capture, opts);
  return {
    events: observer.log.slice(-1).map((e) => ({
      decision: e.decision,
      walletSeq: e.walletSeq,
      relationship: e.relationship,
      stateChanged: null,
      anomalyAppended: e.anomalyAppended,
      previousRecordedSeq: null,
    })),
    cursor: observer.cursor,
  };
};

export const observeSequence = (
  observer: ObserverInstance,
  captures: readonly SequenceCapture[],
  opts: {
    readonly landingProof?: LandingProofOutcome;
    readonly expectedBodySha256?: string;
  } = {},
): void => {
  for (const capture of captures) {
    runDirectVerifierOnCapture(observer, capture, opts);
  }
};

export const observerAppendedRelationships = (
  observer: ObserverInstance,
): readonly ObservationRelationship[] =>
  observer.log
    .filter((e) => e.decision === "APPEND" && e.relationship !== null)
    .map((e) => e.relationship as ObservationRelationship);

/**
 * Derive a landing claim from an observer's own captures + verifier steps — never a hand-set
 * boolean. Landed only when the settlement predicate passed on at least one capture and no
 * anomaly was recorded on the stream.
 */
export const deriveLandingClaim = (observer: ObserverInstance): boolean => {
  if (observer.log.some((e) => e.anomalyAppended)) return false;
  if (observer.verifierSteps.some((s) => s.anomaly)) return false;
  return observer.verifierSteps.some((s) => s.settlementPredicateOk);
};

/**
 * Compare two independent observers' derived claims. QUARANTINE when the node claims landed
 * and the platform does not agree.
 */
export const dualObserverAgreement = (
  node: ObserverInstance,
  platform: ObserverInstance,
): { nodeClaimLanded: boolean; platformClaimLanded: boolean; agrees: boolean } => {
  const nodeClaimLanded = deriveLandingClaim(node);
  const platformClaimLanded = deriveLandingClaim(platform);
  // Body disagreement: both appended but last raw body digests differ.
  const nodeLast = node.rawBodies[node.rawBodies.length - 1];
  const platLast = platform.rawBodies[platform.rawBodies.length - 1];
  const bodiesAgree =
    nodeLast === undefined ||
    platLast === undefined ||
    sha256Hex(nodeLast) === sha256Hex(platLast);
  const agrees =
    nodeClaimLanded === platformClaimLanded &&
    bodiesAgree &&
    !(nodeClaimLanded && platform.cursor.rowCount === 0);
  return { nodeClaimLanded, platformClaimLanded, agrees };
};

// ── sequence fixtures (shared bytes; separate ledgers) ──────────────────

const bytes = (...values: number[]): Uint8Array => new Uint8Array(values);

const head = (
  raw: Uint8Array,
  sSignature: string,
  pSignature: string,
  semanticFingerprint: string,
): SequenceCapture => ({
  parseResult: "VERIFIED_HEAD",
  rawResponseBytes: raw,
  isGenesis: false,
  sSignature,
  pSignature,
  semanticFingerprint,
});

/** Canonical A,A / A,B,C,A fixtures. */
export const FIXTURE_A = head(bytes(0x0a, 0x0a, 0x0a, 0x0a), "sigA", "", "fpA");
export const FIXTURE_A_AGAIN = head(bytes(0x0a, 0x0a, 0x0a, 0x0a), "sigA", "", "fpA");
export const FIXTURE_B = head(bytes(0x0b, 0x0b, 0x0b, 0x0b), "sigB", "sigA", "fpB");
export const FIXTURE_C = head(bytes(0x0c, 0x0c, 0x0c, 0x0c), "sigC", "sigB", "fpC");
export const FIXTURE_A_RETURN = head(bytes(0x0a, 0x0a, 0x0a, 0x0a), "sigA", "", "fpA");
/** Same semantic head, different envelope bytes → EQUIVALENT_STATE_DIFFERENT_ENVELOPE. */
export const FIXTURE_A_WRAP = head(bytes(0x0a, 0x0a, 0x0a, 0xaa), "sigA", "", "fpA");

export const SEQ_AA: readonly SequenceCapture[] = [FIXTURE_A, FIXTURE_A_AGAIN];
export const SEQ_ABCA: readonly SequenceCapture[] = [
  FIXTURE_A,
  FIXTURE_B,
  FIXTURE_C,
  FIXTURE_A_RETURN,
];
export const SEQ_EQUIVALENT: readonly SequenceCapture[] = [FIXTURE_A, FIXTURE_A_WRAP];

export const EXPECTED_AA_RELATIONSHIPS: readonly ObservationRelationship[] = ["FIRST"];
export const EXPECTED_ABCA_RELATIONSHIPS: readonly ObservationRelationship[] = [
  "FIRST",
  "SUCCESSOR",
  "SUCCESSOR",
  "REGRESSION",
];
export const EXPECTED_EQUIVALENT_RELATIONSHIPS: readonly ObservationRelationship[] = [
  "FIRST",
  "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
];

// ── landing proof from real body bytes ───────────────────────────────────

/**
 * Build a LANDED_EXACT proof from the recovered operation's completed transaction body and a
 * fresh-head observation id. This is the only path to COMPLETE_PATH — never mint without a body.
 */
export const buildExactLandingProofFromBody = (
  completedTransactionText: string,
  freshHeadObservationId: string,
  walletPubkey: string = WALLET_PK,
): LandingPathProof => {
  const bodySha = digestPreimage(completedTransactionText);
  return mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: walletPubkey,
      expectedBodySha256: bodySha,
      freshHeadBodySha256: bodySha,
      freshHeadObservationId: freshHeadObservationId,
      depth: 0,
    });
};

/**
 * Build a capture whose raw bytes are the completed transaction text (settlement head).
 * Used so dual observers re-derive landing from the crashed op's own body, not SEQ fixtures.
 */
export const settlementCaptureFromBody = (
  completedTransactionText: string,
  sSignature: string = "sigSettled",
): SequenceCapture => {
  const raw = new TextEncoder().encode(completedTransactionText);
  return head(raw, sSignature, "", `fp-${digestPreimage(completedTransactionText).slice(0, 16)}`);
};

// ── Outcome classification (no silent gap) ─────────────────────────────

export type ScenarioTerminalOutcome =
  | { readonly kind: "COMPLETE_PATH"; readonly adjudication: LandingAdjudication }
  | { readonly kind: "INDETERMINATE"; readonly reason: string; readonly fault?: LandingProofFault }
  | { readonly kind: "INVARIANT_BREACH"; readonly reason: string }
  | { readonly kind: "QUARANTINED_DISAGREEMENT"; readonly reason: string };

/**
 * Classify a post-restart landing outcome. Every path yields COMPLETE_PATH-proven,
 * explicit INDETERMINATE (with reason), INVARIANT_BREACH, or QUARANTINED_DISAGREEMENT.
 *
 * COMPLETE_PATH requires an explicit positive proof that adjudicates LANDED.
 * There is **no** default mint — a LANDED_VERIFIED fixture alone is not COMPLETE_PATH.
 */
export const classifyTerminalOutcome = (input: {
  readonly recoveryClassification: RecoveryClassification;
  readonly landingObservation: LandingObservation;
  readonly proof?: LandingProofOutcome;
  readonly nodeClaimLanded?: boolean;
  readonly observerAgreesWithNode?: boolean;
}): ScenarioTerminalOutcome => {
  if (input.recoveryClassification === "INVARIANT_BREACH") {
    return { kind: "INVARIANT_BREACH", reason: "stored_phases_cannot_arise_under_contract" };
  }

  if (
    input.nodeClaimLanded === true &&
    input.observerAgreesWithNode === false
  ) {
    return {
      kind: "QUARANTINED_DISAGREEMENT",
      reason: "direct_platform_observation_contradicts_node",
    };
  }

  if (input.landingObservation.kind === "ANOMALOUS") {
    return { kind: "INDETERMINATE", reason: "anomalous_head", fault: "ANOMALOUS_OR_CONTRADICTORY" };
  }

  if (input.landingObservation.kind === "NOT_LANDED_YET") {
    return { kind: "INDETERMINATE", reason: "awaiting_settlement_observation", fault: "GAP" };
  }

  // LANDED_VERIFIED — require an explicit complete-path / exact proof. No default mint.
  if (input.proof === undefined) {
    return {
      kind: "INDETERMINATE",
      reason: "landed_observation_without_d9_6_proof",
      fault: "MISSING_BODY",
    };
  }

  if (input.proof.kind === "PROOF_INCOMPLETE") {
    return {
      kind: "INDETERMINATE",
      reason: `proof_incomplete:${input.proof.fault}`,
      fault: input.proof.fault,
    };
  }

  const adjudication = adjudicateLanding({
    landingProof: input.proof,
    economic: { ok: true },
  });

  if (adjudication.verdict === "LANDED") {
    return { kind: "COMPLETE_PATH", adjudication };
  }
  if (adjudication.verdict === "INDETERMINATE") {
    return {
      kind: "INDETERMINATE",
      reason: JSON.stringify(adjudication.reason),
    };
  }
  return {
    kind: "INDETERMINATE",
    reason: `rejected_folded:${JSON.stringify(adjudication.reason)}`,
  };
};

/**
 * Crash → recover → boot → dual-observer (when body available) → terminal outcome.
 * The composition path every catalogued injection scenario walks.
 */
export const crashRecoverBoot = async (
  kind: OperationKind,
  injection: Bt115InjectionPoint,
  landing: LandingObservation,
  opts: {
    /** When true (default), run dual independent observers over the recovered body. */
    readonly dualObserve?: boolean;
  } = {},
): Promise<{
  readonly crashPoint: CrashPoint;
  readonly overlay: PostSubmitOverlay | null;
  readonly fingerprint: string;
  readonly recoveryClassification: RecoveryClassification;
  readonly recovery: RecoveryOutcome;
  readonly submitCalls: number;
  readonly boot: BootRecoveryReport;
  readonly bootState: BootFakeState;
  readonly durableSnap: ReturnType<typeof snapshotDurable>;
  readonly outcome: ScenarioTerminalOutcome;
  readonly recoveredScenario: Scenario;
  readonly nodeObserver: ObserverInstance | null;
  readonly platformObserver: ObserverInstance | null;
  readonly proof: LandingProofOutcome | undefined;
}> => {
  const { port, calls } = countingSubmit();
  const { scenario: crashed, crashPoint, overlay, fingerprint } = crashAtInjection(
    kind,
    injection,
    port,
  );
  const { scenario: recovered, outcome: recovery } = crashThenRecover(crashed, port, landing);
  const { report, state } = await bootAfterCrash(recovered.durable, {
    observationBytes: new Uint8Array([0x01, 0x02, 0x03, 0x04]),
    observationId: "obs-boot-prior",
  });

  const bodyText = recovered.durable.attempts[0]?.completedTransactionText ?? null;
  let proof: LandingProofOutcome | undefined;
  let nodeObserver: ObserverInstance | null = null;
  let platformObserver: ObserverInstance | null = null;
  let nodeClaimLanded: boolean | undefined;
  let observerAgreesWithNode: boolean | undefined;

  const dualObserve = opts.dualObserve !== false;
  if (dualObserve && bodyText !== null && landing.kind === "LANDED_VERIFIED") {
    const freshHeadId = `obs-fresh-${kind}-${injection}`;
    proof = buildExactLandingProofFromBody(bodyText, freshHeadId);
    const capture = settlementCaptureFromBody(bodyText);
    const bodySha = digestPreimage(bodyText);

    nodeObserver = createIndependentObserver(NODE_OBSERVER_ID, NODE_ENDPOINT_FP);
    platformObserver = createIndependentObserver(PLATFORM_OBSERVER_ID, PLATFORM_ENDPOINT_FP);
    // Each observer independently walks platform integration over the settled body + proof.
    runDirectVerifierOnCapture(nodeObserver, capture, {
      landingProof: proof,
      expectedBodySha256: bodySha,
    });
    runDirectVerifierOnCapture(platformObserver, capture, {
      landingProof: proof,
      expectedBodySha256: bodySha,
    });
    const dual = dualObserverAgreement(nodeObserver, platformObserver);
    nodeClaimLanded = dual.nodeClaimLanded;
    observerAgreesWithNode = dual.agrees;
  } else if (dualObserve && landing.kind === "LANDED_VERIFIED" && bodyText === null) {
    // Node claims landed (recovery.landed) but no body → platform cannot verify.
    nodeObserver = createIndependentObserver(NODE_OBSERVER_ID, NODE_ENDPOINT_FP);
    platformObserver = createIndependentObserver(PLATFORM_OBSERVER_ID, PLATFORM_ENDPOINT_FP);
    nodeClaimLanded = recovery.landed;
    observerAgreesWithNode = false;
  } else if (dualObserve && landing.kind !== "LANDED_VERIFIED") {
    // Post-submit gap path: both observers see nothing conclusive.
    nodeObserver = createIndependentObserver(NODE_OBSERVER_ID, NODE_ENDPOINT_FP);
    platformObserver = createIndependentObserver(PLATFORM_OBSERVER_ID, PLATFORM_ENDPOINT_FP);
    nodeClaimLanded = recovery.landed;
    observerAgreesWithNode = true; // both agree: not landed
  }

  const terminal = classifyTerminalOutcome({
    recoveryClassification: recovery.classification,
    landingObservation: landing,
    proof,
    nodeClaimLanded,
    observerAgreesWithNode,
  });

  return {
    crashPoint,
    overlay,
    fingerprint,
    recoveryClassification: recovery.classification,
    recovery,
    submitCalls: calls.length,
    boot: report,
    bootState: state,
    durableSnap: snapshotDurable(recovered.durable),
    outcome: terminal,
    recoveredScenario: recovered,
    nodeObserver,
    platformObserver,
    proof,
  };
};

export {
  CRASH_POINTS,
  crashAt,
  crashThenRecover,
  recoverOperation,
  classifyResidue,
  snapshotDurable,
  appendedRelationships,
  mintLandingPathProofFromOracle,
  adjudicateLanding,
  type CrashPoint,
  type LandingObservation,
  type RecoveryClassification,
  type OperationKind,
  type Scenario,
  type DurableStore,
  type LandingProofOutcome,
  type BootRecoveryReport,
  type RecoveryOutcome,
};

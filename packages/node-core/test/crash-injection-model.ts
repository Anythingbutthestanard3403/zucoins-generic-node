/**
 * Phase-by-phase crash-injection harness — model core + fixtures.
 *
 * Models all three operation kinds, each with the durable phase boundaries and the recovery
 * rules its own flow defines:
 *
 *   MOVE_INTERNAL    formation -> submit -> landing. The node forms both steps and submits
 *                    exactly once.
 *   RECEIVE_EXTERNAL the inner preimage and step-1 signature arrive PAYER-SIGNED and are
 *                    durable at acceptance; the node only counter-signs step 2 and submits.
 *                    Receive has NO rebuild path — the node may never construct inner bytes
 *                    for it, so a residue missing them is INVARIANT_BREACH, never a
 *                    re-formation.
 *   SEND_EXTERNAL    formation-only: the node forms a partial and delivers it, and never
 *                    reaches a submit port at all. Recovery delivers the EXACT persisted
 *                    code; it may not re-sign, re-form, or mint a replacement partial.
 *
 * CRASH AXIOM (enforced mechanically by crashAndRecover in crash-injection-lifecycle.ts):
 * all volatile state is lost on a crash; every committed write survives; every uncommitted
 * write is discarded. A kill inside lifecycle step N leaves only the durable residue of the
 * steps before it. The durable store is plain JSON; recovery reads only that JSON.
 *
 * Invariants exercised here: one in-flight transaction per wallet — the source lease
 * is held continuously from creation and is never released by an ambiguous recovery;
 * (3) byte-exact signing — recovery re-signs ONLY the identical persisted preimage;
 * (4) never blind-retry a submit — once a durable submit claim exists, recovery reconciles
 * by observation and never invokes the submit port again. Offline fixtures only; no custody
 * surface, never live ZKZ.
 */
import {
  keypairFromSeedByte,
  signPreimage,
} from "../../generic-node-contracts/src/testkit/independentCrypto.ts";

export type OperationStatus =
  | "CREATED"
  | "READY"
  | "SUBMITTED"
  | "LANDED"
  | "NEEDS_ATTENTION";

/** The frozen 5-value `operation_transactions.attempt_phase` enum. Crash
 *  points map onto the transitions between these values. */
export type AttemptPhase =
  | "INNER_PREIMAGE_PERSISTED"
  | "STEP1_SIGNATURE_PERSISTED"
  | "STEP2_PREIMAGE_PERSISTED"
  | "STEP2_SIGNATURE_PERSISTED"
  | "SETTLED_BODY_PERSISTED";

export type OperationKind = "MOVE_INTERNAL" | "RECEIVE_EXTERNAL" | "SEND_EXTERNAL";

export interface OperationRow {
  readonly operationId: string;
  readonly kind: OperationKind;
  status: OperationStatus;
  leaseHeld: boolean;
  needsAttention: boolean;
  terminal: boolean;
}

export interface AttemptRow {
  readonly operationId: string;
  readonly attemptNo: 1;
  attemptPhase: AttemptPhase;
  innerPreimageText: string | null;
  innerSha256: string | null;
  step1Signature: string | null;
  step2PreimageText: string | null;
  step2PreimageSha256: string | null;
  step2Signature: string | null;
  completedTransactionText: string | null;
  completedTransactionSha256: string | null;
  submitClaimed: boolean;
  submitResponseRecorded: boolean;
}

export interface SignerAuditEntry {
  readonly operationId: string;
  readonly step: 1 | 2;
  readonly preimageSha256: string;
  readonly signature: string;
}

/** `external_send_partials`: at most one partial per approval. The code is
 *  formed once and frozen; delivery and re-delivery carry those exact bytes. */
export interface ExternalPartialRow {
  readonly operationId: string;
  readonly code: string;
  readonly codeSha256: string;
  deliveries: number;
}

export interface DurableStore {
  operations: OperationRow[];
  attempts: AttemptRow[];
  signerAudit: SignerAuditEntry[];
  externalPartials: ExternalPartialRow[];
  events: string[];
}

export interface VolatileState {
  innerPreimageText?: string;
  step1Signature?: string;
  step2PreimageText?: string;
  step2Signature?: string;
  completedTransactionText?: string;
  partialCode?: string;
  submitOutcome?: SubmitOutcome;
}

export interface EffectLog {
  leaseAcquisitions: number;
  leaseReleases: number;
  signerCalls: Array<{ operationId: string; step: 1 | 2; preimageText: string; signature: string }>;
  submitCalls: Array<{ operationId: string; attemptNo: number }>;
  operationCreations: number;
  attemptCreations: number;
  /** Every minting of an external-send partial. More than one per approval is the forbidden
   * "mint a replacement partial" action. */
  partialMints: string[];
  /** Every delivery/re-delivery, carrying the exact bytes handed to the delivery path. */
  partialDeliveries: Array<{ operationId: string; code: string }>;
  statusTransitions: Array<{ operationId: string; from: OperationStatus; to: OperationStatus }>;
  needsAttentionMarks: string[];
  landings: string[];
  eventsEmitted: string[];
}

export interface Runtime {
  readonly workerId: string;
  readonly seedByte: number;
  /** The payer's step-1 signature on an inbound RECEIVE_EXTERNAL. It is an external input the
   *  payer re-presents, not node-formed state, so it survives a crash the way the inbound
   *  message does — the node still cannot produce it, which is what "no rebuild path" means. */
  readonly payerStep1Signature?: string;
  volatile: VolatileState;
  readonly log: EffectLog;
}

export interface Scenario {
  durable: DurableStore;
  runtime: Runtime;
}

/** The gateway submit port. A crash/timeout is modeled by an outcome the recovery pass can
 *  observe; the port is the ONLY way a submit call is recorded, so "never blind-retry" is
 *  measurable as "at most one submit call per attempt across crash + recovery". */
export type SubmitOutcome =
  | { readonly kind: "ACCEPTED"; readonly gatewayRef: string }
  | { readonly kind: "NO_RESPONSE" }
  | { readonly kind: "REJECTED"; readonly reason: string };

export type SubmitPort = (request: {
  operationId: string;
  attemptNo: number;
  completedTransactionText: string;
}) => SubmitOutcome;

export const emptyEffectLog = (): EffectLog => ({
  leaseAcquisitions: 0,
  leaseReleases: 0,
  signerCalls: [],
  submitCalls: [],
  operationCreations: 0,
  attemptCreations: 0,
  partialMints: [],
  partialDeliveries: [],
  statusTransitions: [],
  needsAttentionMarks: [],
  landings: [],
  eventsEmitted: [],
});

export const createRuntime = (
  workerId: string,
  seedByte: number,
  payerStep1Signature?: string,
): Runtime => ({
  workerId,
  seedByte,
  payerStep1Signature,
  volatile: {},
  log: emptyEffectLog(),
});

// ---------------------------------------------------------------------------
// Fixtures — deterministic, offline-only.
// ---------------------------------------------------------------------------

export const OPERATION_ID = "0c100000-0000-4000-8000-0000000000a1";
export const SOURCE_WALLET_ID = "0a100000-0000-4000-8000-0000000000b2";
export const DESTINATION_WALLET_ID = "0a100000-0000-4000-8000-0000000000c3";
export const LEASE_GROUP_ID = "0a1e0000-0000-4000-8000-0000000000d4";
export const GATEWAY_REF = "gw-ref-0001";
export const KEY_SEED_BYTE = 0x5e;
/** A key the node does not hold. RECEIVE_EXTERNAL step-1 signatures are produced with it, so
 *  "the node never signed step 1 of a receive" is checkable rather than asserted. */
export const PAYER_SEED_BYTE = 0x91;
export const AMOUNT_ZKZ = "10";
export const EXPIRY_SECS = "1800000300";

/** One distinct operation id per kind, so a per-kind scenario is independently addressable. */
export const OPERATION_IDS: Record<OperationKind, string> = {
  MOVE_INTERNAL: OPERATION_ID,
  RECEIVE_EXTERNAL: "0c100000-0000-4000-8000-0000000000a2",
  SEND_EXTERNAL: "0c100000-0000-4000-8000-0000000000a3",
};

/** Byte-exact inner preimage (the byte-exact signing rule): JSON.stringify of ordered fields, built once
 *  and never reformatted. Recovery re-signs these exact persisted bytes. */
export const buildInnerPreimage = (
  kind: OperationKind = "MOVE_INTERNAL",
  operationId: string = OPERATION_IDS[kind],
): string =>
  JSON.stringify({
    kind,
    operation_id: operationId,
    source_wallet: SOURCE_WALLET_ID,
    destination_wallet: DESTINATION_WALLET_ID,
    amount_zkz: AMOUNT_ZKZ,
    expiry_unix_time_secs: EXPIRY_SECS,
  });

/** The external-send partial code: the frozen inner bytes plus the node's step-1 signature,
 *  assembled by template literal and never reparsed. Formed once per approval and frozen —
 * recovery delivers these exact bytes and may not re-form them. */
export const buildPartialCode = (innerPreimageText: string, step1Signature: string): string =>
  `{"partial":${innerPreimageText},"step_1_signature":"${step1Signature}"}`;

/** The completed transaction embeds the inner preimage verbatim plus both signatures; it is
 *  assembled by template literal, never by parsing/reserializing the inner bytes. */
export const buildCompletedTransactionText = (
  innerPreimageText: string,
  step1Signature: string,
  step2Signature: string,
): string =>
  `{"inner":${innerPreimageText},"step_1_signature":"${step1Signature}","step_2_signature":"${step2Signature}"}`;

export const makeAttemptRow = (operationId: string): AttemptRow => ({
  operationId,
  attemptNo: 1,
  attemptPhase: "INNER_PREIMAGE_PERSISTED",
  innerPreimageText: null,
  innerSha256: null,
  step1Signature: null,
  step2PreimageText: null,
  step2PreimageSha256: null,
  step2Signature: null,
  completedTransactionText: null,
  completedTransactionSha256: null,
  submitClaimed: false,
  submitResponseRecorded: false,
});

export const signWithSeed = (preimageText: string, seedByte: number): string =>
  signPreimage(preimageText, keypairFromSeedByte(seedByte).privateKey);

export const findOperation = (durable: DurableStore, operationId: string): OperationRow => {
  const row = durable.operations.find((candidate) => candidate.operationId === operationId);
  if (row === undefined) {
    throw new Error(`crash-injection model: unknown operation ${operationId}`);
  }
  return row;
};

export const attemptFor = (durable: DurableStore, operationId: string): AttemptRow | undefined =>
  durable.attempts.find((candidate) => candidate.operationId === operationId);

export const partialFor = (
  durable: DurableStore,
  operationId: string,
): ExternalPartialRow | undefined =>
  durable.externalPartials.find((candidate) => candidate.operationId === operationId);

export const countOperations = (durable: DurableStore): number => durable.operations.length;

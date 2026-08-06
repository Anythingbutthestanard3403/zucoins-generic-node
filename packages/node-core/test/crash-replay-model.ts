/**
 * Residual crash/replay proof harness — model core.
 *
 * CRASH AXIOM (stated, and enforced mechanically by crash-replay-driver.ts): all volatile
 * state is lost on a crash; every committed write survives; every uncommitted write is
 * discarded. A kill inside DB-TX-N is equivalent to the end of DB-TX-(N-1). The durable
 * store below is plain JSON; `crashAndRecover` performs JSON.parse(JSON.stringify(durable))
 * after rolling back every pending (uncommitted) claim and constructs a brand-new recovery
 * runtime, so "only durable survives" is mechanical, never discipline. The axiom itself is
 * assumed, not proven, here; it is recorded as a live-DB obligation in
 * crash-replay-obligations.ts.
 *
 * Per-wallet exclusion belongs to the lease lane (wallet_active_leases,
 * custody-eligibility.sql) — the one-in-flight-per-wallet rule rides on that lane and is never
 * claimed from the surfaces modeled here. The model exposes NO submit port: the node
 * never submits SEND_EXTERNAL.
 */
import { FORMATION_TRANSITIONS } from "../../generic-node-contracts/src/approval/sign-intent.contract.ts";
import { TRANSACTION_MATERIAL_MUTABILITY_REGIMES } from "../src/schema/transaction-material.contract.ts";
import type { ParsedTable } from "./transaction-material-sql-parser.ts";
import {
  simulateInsert,
  validateRowAgainstTable,
  type InsertVerdict,
  type RowValues,
} from "./transaction-material-model.ts";
import {
  FORMATION_ENUM_MEMBERS,
  MATERIAL_DOMAINS,
  SEND_EXTERNAL_STATUSES,
} from "./crash-replay-surfaces.ts";

export type { RowValues };

/** The harness's own stored rows are mutated in place (one-way attempt completion, partial
 *  delivery-counter updates). RowValues is read-only, so the durable store carries this
 *  mutable record; a MutableRow is assignable to RowValues wherever a validator reads it. */
export type MutableRow = Record<string, string | number | null>;

/** Every protocol seconds value is an integer-SECONDS string — never ms, never a
 *  bare JS number at a compare site. */
export type UnixSecsString = string;

// BOTH constants below are census-bound by crash-replay.census.test.ts, which pins each
// against its frozen literal (`SEND_REDEMPTION_WINDOW_SECS=300`,
// `SEND_PARTIAL_AGING_MARGIN_SECS=3600`)
// — a pin<->source drift reddens there. NEVER import the equal-valued T1 approval-challenge
// window (TIMER_SEPARATION separates the timers; the 300s equality is the trap — the census
// binds by NAME with an `=`-anchored pattern, so it can never latch onto the `≈`-flagged
// APPROVAL_CHALLENGE_FRESHNESS_SECS in the same row).
export const SEND_REDEMPTION_WINDOW_SECS = 300;
export const SEND_PARTIAL_AGING_MARGIN_SECS = 3600;

const SECONDS_STRING_RE = /^-?\d+$/;

export const secsValue = (secs: UnixSecsString): number => {
  if (!SECONDS_STRING_RE.test(secs)) {
    throw new Error(`crash-replay model: not an integer-seconds string: ${secs}`);
  }
  return Number(secs);
};

export const secsString = (value: number): UnixSecsString => {
  if (!Number.isInteger(value)) {
    throw new Error(`crash-replay model: refusing non-integer seconds: ${value}`);
  }
  return String(value);
};

export const addSecs = (base: UnixSecsString, delta: number): UnixSecsString =>
  secsString(secsValue(base) + delta);

export const timestampFromSecs = (secs: UnixSecsString): string =>
  new Date(secsValue(secs) * 1000).toISOString();

// Boundary-convention pins (deliberate strictness where the spec is silent — recovery says
// "has passed" without pinning > vs >=). Isolated named predicates, documented as judgment
// pins: `now >= t2` is FAIL-CLOSED for the pre-delivery gate; the aging margin additionally
// requires positive non-landing proof before any terminalization, so the pin is safe.
export const isPastRedemptionExpiry = (now: UnixSecsString, t2: UnixSecsString): boolean =>
  secsValue(now) >= secsValue(t2);

export const agingMarginElapsed = (now: UnixSecsString, t2: UnixSecsString): boolean =>
  secsValue(now) >= secsValue(t2) + SEND_PARTIAL_AGING_MARGIN_SECS;

// ---------------------------------------------------------------------------
// Durable store, volatile runtime, effect log.
// ---------------------------------------------------------------------------

export interface OperationRow {
  readonly operationId: string;
  readonly kind: "SEND_EXTERNAL";
  status: string;
  formationState: string;
  needsAttention: boolean;
  terminal: boolean;
  leaseHeld: boolean;
  approvalConsumed: boolean;
  readonly approvalId: string;
}

export interface SignerAuditEntry {
  readonly operationId: string;
  readonly preimageSha256: string;
  readonly signature: string;
}

export interface DeliveryEntry {
  readonly operationId: string;
  readonly deliveredAtSecs: UnixSecsString;
  readonly transferCodeSha256: string;
}

export interface DurableStore {
  operations: OperationRow[];
  signIntents: MutableRow[];
  attempts: MutableRow[];
  partials: MutableRow[];
  signerAudit: SignerAuditEntry[];
  deliveries: DeliveryEntry[];
}

export interface PendingClaim {
  readonly workerId: string;
  readonly operationId: string;
  readonly previousFormationState: string;
}

export interface VolatileDb {
  pendingClaims: PendingClaim[];
  innerText?: string;
  signature?: string;
  transferCodeText?: string;
}

export interface EffectLog {
  leaseAcquisitions: number;
  leaseReleases: number;
  signerCalls: Array<{ operationId: string; preimageText: string; signature: string }>;
  insertAttempts: Array<{
    table: string;
    operationId: string;
    committed: boolean;
    violations: readonly string[];
  }>;
  deliveriesServed: Array<{
    operationId: string;
    transferCodeText: string;
    transferCodeSha256: string;
  }>;
  operationTransitions: Array<{ operationId: string; from: string; to: string }>;
  formationTransitions: Array<{ operationId: string; from: string; to: string }>;
  needsAttentionMarks: string[];
  terminalizations: string[];
  refusals: string[];
}

export interface Runtime {
  readonly workerId: string;
  readonly seedByte: number;
  volatileDb: VolatileDb;
  readonly log: EffectLog;
}

export interface Scenario {
  durable: DurableStore;
  runtime: Runtime;
}

export const emptyEffectLog = (): EffectLog => ({
  leaseAcquisitions: 0,
  leaseReleases: 0,
  signerCalls: [],
  insertAttempts: [],
  deliveriesServed: [],
  operationTransitions: [],
  formationTransitions: [],
  needsAttentionMarks: [],
  terminalizations: [],
  refusals: [],
});

export const createRuntime = (workerId: string, seedByte: number): Runtime => ({
  workerId,
  seedByte,
  volatileDb: { pendingClaims: [] },
  log: emptyEffectLog(),
});

export const findOperation = (durable: DurableStore, operationId: string): OperationRow => {
  const row = durable.operations.find((candidate) => candidate.operationId === operationId);
  if (row === undefined) {
    throw new Error(`crash-replay model: unknown operation ${operationId}`);
  }
  return row;
};

export const stringField = (row: MutableRow, column: string): string => {
  const value = row[column];
  if (typeof value !== "string") {
    throw new Error(`crash-replay model: expected string column ${column}`);
  }
  return value;
};

export const signIntentFor = (
  durable: DurableStore,
  operationId: string,
): MutableRow | undefined => durable.signIntents.find((row) => row["operation_id"] === operationId);

export const partialFor = (
  durable: DurableStore,
  operationId: string,
): MutableRow | undefined => durable.partials.find((row) => row["operation_id"] === operationId);

/** Reads the redemption expiry (T2) OUT of the persisted preimage — parse-to-read for the
 *  delivery/expiry gate only; the bytes themselves are never re-derived from the parse. */
export const expiryFromPersistedPreimage = (intentRow: MutableRow): UnixSecsString => {
  const parsed: unknown = JSON.parse(stringField(intentRow, "inner_preimage_text"));
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("crash-replay model: persisted preimage is not a JSON object");
  }
  const expiry = (parsed as Record<string, unknown>)["redemption_expiry"];
  if (typeof expiry !== "string" || !SECONDS_STRING_RE.test(expiry)) {
    throw new Error(
      "crash-replay model: persisted preimage carries no integer-seconds redemption_expiry",
    );
  }
  return expiry;
};

// ---------------------------------------------------------------------------
// Write ports — every durable mutation flows through one of these.
// ---------------------------------------------------------------------------

export const commitInsert = (
  scenario: Scenario,
  table: ParsedTable,
  rows: MutableRow[],
  row: MutableRow,
  tableName: string,
  operationId: string,
): InsertVerdict => {
  const verdict = simulateInsert(rows, row, table, MATERIAL_DOMAINS);
  scenario.runtime.log.insertAttempts.push({
    table: tableName,
    operationId,
    committed: verdict.committed,
    violations: verdict.violations,
  });
  if (verdict.committed) {
    rows.push(row);
  }
  return verdict;
};

export const mustCommit = (verdict: InsertVerdict, context: string): void => {
  if (!verdict.committed) {
    throw new Error(
      `crash-replay model: ${context} unexpectedly rejected: ${verdict.violations.join(", ")}`,
    );
  }
};

/** Harness-local typed refusal vocabulary (deliberately NOT a frozen surface). */
export const REFUSAL_UPDATE_COLUMN = "UPDATE_COLUMN_NOT_UPDATABLE";
export const REFUSAL_STATUS = "STATUS_NOT_PERMITTED_FOR_SEND_EXTERNAL";
export const REFUSAL_CAS_LOST = "SIGNING_CLAIM_CAS_LOST";
export const REFUSAL_CAS_BLOCKED = "SIGNING_CLAIM_BLOCKED_BEHIND_UNCOMMITTED";
export const REFUSAL_DELIVERY_EXPIRED = "DELIVERY_REFUSED_PAST_REDEMPTION_EXPIRY";

export type UpdateOutcome =
  | { readonly applied: true }
  | { readonly applied: false; readonly refusedColumn: string };

/** The ONLY update path in the model: column-restricted per the frozen mutability regime
 *  of the table, post-update row revalidated against the parsed CHECKs/domains. A column
 *  outside the regime's updatableColumns is a typed refusal with zero side effects. */
export const applyRegimeUpdate = (
  scenario: Scenario,
  tableName: string,
  rows: MutableRow[],
  table: ParsedTable,
  operationId: string,
  updates: Readonly<Record<string, string | number>>,
): UpdateOutcome => {
  const regime = TRANSACTION_MATERIAL_MUTABILITY_REGIMES.find(
    (candidate) => candidate.table === tableName,
  );
  if (regime === undefined) {
    throw new Error(`crash-replay model: no frozen regime for ${tableName}`);
  }
  for (const column of Object.keys(updates)) {
    if (!regime.updatableColumns.includes(column)) {
      scenario.runtime.log.refusals.push(`${REFUSAL_UPDATE_COLUMN}:${tableName}.${column}`);
      return { applied: false, refusedColumn: column };
    }
  }
  const row = rows.find((candidate) => candidate["operation_id"] === operationId);
  if (row === undefined) {
    throw new Error(`crash-replay model: no ${tableName} row for ${operationId}`);
  }
  const before = { ...row };
  Object.assign(row, updates);
  const violations = validateRowAgainstTable(table, MATERIAL_DOMAINS, row);
  if (violations.length > 0) {
    Object.assign(row, before);
    throw new Error(
      `crash-replay model: post-update ${tableName} row violates: ${violations.join(", ")}`,
    );
  }
  return { applied: true };
};

export const applyOperationStatus = (
  scenario: Scenario,
  operationId: string,
  next: string,
): boolean => {
  if (!SEND_EXTERNAL_STATUSES.includes(next)) {
    scenario.runtime.log.refusals.push(`${REFUSAL_STATUS}:${next}`);
    return false;
  }
  const row = findOperation(scenario.durable, operationId);
  scenario.runtime.log.operationTransitions.push({ operationId, from: row.status, to: next });
  row.status = next;
  row.needsAttention = next === "NEEDS_ATTENTION";
  row.terminal = next === "REJECTED" || next === "EXTERNAL_SEND_LANDED";
  return true;
};

/** A formation transition must be one of the frozen FORMATION_TRANSITIONS pairs whose both
 * ends live in the doc-extracted enum (the frozen PARTIAL_DELIVERED ->
 *  AWAITING_REDEMPTION pair is realized as the operations.status transition — the recorded
 *  5-vs-6 vocabulary divergence — never as a formation_state value). */
export const transitionFormation = (
  scenario: Scenario,
  operationId: string,
  next: string,
): void => {
  const row = findOperation(scenario.durable, operationId);
  const pair = FORMATION_TRANSITIONS.find(
    (transition) => transition.from === row.formationState && transition.to === next,
  );
  if (pair === undefined || !FORMATION_ENUM_MEMBERS.includes(next)) {
    throw new Error(
      `crash-replay model: illegal formation transition ${row.formationState} -> ${next}`,
    );
  }
  scenario.runtime.log.formationTransitions.push({
    operationId,
    from: row.formationState,
    to: next,
  });
  row.formationState = next;
};

/** Count-exact closed-set coverage check; the self-checking mutants feed it a dropped set. */
export const assertCountExactCoverage = (
  fed: readonly string[],
  frozen: readonly string[],
  label: string,
): void => {
  const missing = frozen.filter((member) => !fed.includes(member));
  const extra = fed.filter((member) => !frozen.includes(member));
  if (missing.length > 0 || extra.length > 0 || fed.length !== frozen.length) {
    throw new Error(
      `${label}: coverage mismatch — missing=[${missing.join(",")}] extra=[${extra.join(",")}]`,
    );
  }
};

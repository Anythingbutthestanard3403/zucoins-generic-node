/**
 * lifecycle/recovery sequence fuzzer: INDEPENDENT ORACLES.
 *
 * These oracles check PROSE-DERIVED runtime output (the reconcile classifiers and the
 * crash-replay `recoverOperation`, which per its own header never imports the frozen decision
 * table) against the frozen the state/event reference transition tables and closed vocabularies as the
 * EXPECTATION set. The transition oracle takes the table as an argument so the self-check
 * meta-test (lifecycle-fuzz-oracle-selfcheck.test.ts) can feed a mutated expectation set and
 * prove the oracle reddens — a tautological oracle cannot be red-gone, so that test is the
 * anti-tautology proof (red-team amendment 1).
 *
 * NO NORMALIZATION (amendment 4): every identity comparison here is exact-byte. No
 * toUpperCase/toLowerCase/trim/normalize. `from === null` creation rows are first-class.
 *
 * TEST-ONLY. Frozen tables reached by direct relative source import (the exports map lacks the
 * `./operations/states` subpath and there is no built dist/); this mirrors the crash-replay
 * harness's own cross-package test imports.
 */
import {
  FORBIDDEN_STATE_ALIASES,
  NO_EVENT_MARKERS,
  PROVEN_NOT_LANDED_ORACLE_REQUIRED,
  RECEIVE_EXTERNAL_STATES,
  MOVE_INTERNAL_STATES,
  SEND_EXTERNAL_STATES,
  type StateTransition,
} from "../../generic-node-contracts/src/operations/states.contract.ts";
import {
  DURABLE_EVENTS,
  FORBIDDEN_EVENT_ALIASES,
} from "../../generic-node-contracts/src/operations/events.contract.ts";
import { RECONCILE_CLASSIFICATION_KINDS } from "../src/protocol/reconcile/index.js";

// ---------------------------------------------------------------------------
// Determinism knobs — committed literals (amendment 9). Every fc.assert cites these.
// ---------------------------------------------------------------------------
export const FUZZ_SEED = 0x5a382 as const;
export const FUZZ_NUM_RUNS = 500 as const;

// ---------------------------------------------------------------------------
// RUNTIME_FIREABLE vs RESERVED_ORACLE_ABSENT partition (amendment 2).
// A transition whose precondition is PROVEN_NOT_LANDED_ORACLE_REQUIRED cannot fire at launch
// (no generic PROVEN_NOT_LANDED oracle). Observed runtime transitions are checked against
// RUNTIME_FIREABLE; any RESERVED transition FIRING is a hard fail.
// ---------------------------------------------------------------------------
export type FrozenTable = readonly StateTransition<string>[];

export const isReserved = (row: StateTransition<string>): boolean =>
  row.precondition === PROVEN_NOT_LANDED_ORACLE_REQUIRED;

export const runtimeFireable = (table: FrozenTable): FrozenTable =>
  table.filter((row) => !isReserved(row));

export const reservedOracleAbsent = (table: FrozenTable): FrozenTable =>
  table.filter((row) => isReserved(row));

// ---------------------------------------------------------------------------
// Transition-allowlist oracle (JC4). (from,to) is a key in all three frozen tables (verified);
// event, when supplied, must byte-equal the row's declared event. A NO_EVENT_MARKER row emits
// ZERO durable public events (checked by the caller against DURABLE_EVENTS).
// ---------------------------------------------------------------------------
export interface ObservedTransition {
  readonly from: string | null;
  readonly to: string;
  readonly event?: string | null;
}

export type TransitionVerdict =
  | "ALLOWED"
  | "UNAUTHORIZED_TRANSITION"
  | "RESERVED_TRANSITION_FIRED"
  | "EVENT_MISMATCH";

export interface TransitionResult {
  readonly verdict: TransitionVerdict;
  readonly expectedEvent?: string | null;
}

export function classifyObservedTransition(
  table: FrozenTable,
  observed: ObservedTransition,
): TransitionResult {
  // from === null (creation "—") is a first-class case; never coerced.
  const matches = table.filter((row) => row.from === observed.from && row.to === observed.to);
  if (matches.length === 0) {
    return { verdict: "UNAUTHORIZED_TRANSITION" };
  }
  const row = matches[0];
  if (isReserved(row)) {
    return { verdict: "RESERVED_TRANSITION_FIRED", expectedEvent: row.event };
  }
  if (observed.event !== undefined && observed.event !== row.event) {
    return { verdict: "EVENT_MISMATCH", expectedEvent: row.event };
  }
  return { verdict: "ALLOWED", expectedEvent: row.event };
}

/** Whether the matched row's declared event is a no-durable-event marker. */
export const isNoEventMarker = (event: string | null | undefined): boolean =>
  typeof event === "string" && (NO_EVENT_MARKERS as readonly string[]).includes(event);

/** A durable public event name (∈ the closed 9-set). */
export const isDurableEvent = (event: string | null | undefined): boolean =>
  typeof event === "string" && (DURABLE_EVENTS as readonly string[]).includes(event);

// ---------------------------------------------------------------------------
// Forbidden-alias denylist (state/event + node-core) — RAW values, no normalization,
// exact member OR exact structural prefix (wildcard families). Two-sided fail-closed.
// ---------------------------------------------------------------------------

// node-core rules "Forbidden Layer-1 vocabulary" (verbatim tokens).
export const NODE_CORE_9_FORBIDDEN = [
  "payment",
  "checkout",
  "refund",
  "paid",
  "finalised",
  "fulfilled",
  "treasury settlement",
  "transfer.confirmed",
  "transfer.finalised",
  "sweep.settled",
  "outbound.settled",
] as const;

// state/event wildcard families (`reservation.*`, `payment.*`, `checkout.*`, `refund.*`) that
// the enumerated *_ALIASES constants do not spell out member-by-member.
export const FORBIDDEN_ALIAS_PREFIXES = ["reservation.", "payment.", "checkout.", "refund."] as const;

const EXACT_FORBIDDEN: readonly string[] = [
  ...FORBIDDEN_STATE_ALIASES,
  ...FORBIDDEN_EVENT_ALIASES,
  ...NODE_CORE_9_FORBIDDEN,
];

/** RAW exact-or-prefix forbidden-alias test. No case folding, no trimming. */
export function isForbiddenAlias(name: string): boolean {
  if (EXACT_FORBIDDEN.includes(name)) return true;
  for (const prefix of FORBIDDEN_ALIAS_PREFIXES) {
    if (name.startsWith(prefix)) return true;
  }
  return false;
}

export const ALLOWED_OPERATION_STATES: readonly string[] = [
  ...RECEIVE_EXTERNAL_STATES,
  ...MOVE_INTERNAL_STATES,
  ...SEND_EXTERNAL_STATES,
];

export const ALLOWED_EVENT_NAMES: readonly string[] = [...DURABLE_EVENTS, ...NO_EVENT_MARKERS];

/** Two-sided fail-closed (amendment 4): a public operation-state name is bad if it is a
 *  forbidden alias OR not an exact member of the allowed closed set. Throws on violation. */
export function assertObservedStateAllowed(name: string): void {
  if (isForbiddenAlias(name)) {
    throw new Error(`forbidden-alias state observed: ${name}`);
  }
  if (!ALLOWED_OPERATION_STATES.includes(name)) {
    throw new Error(`non-member operation state observed: ${name}`);
  }
}

export function assertObservedEventAllowed(name: string): void {
  if (isForbiddenAlias(name)) {
    throw new Error(`forbidden-alias event observed: ${name}`);
  }
  if (!ALLOWED_EVENT_NAMES.includes(name)) {
    throw new Error(`non-member event observed: ${name}`);
  }
}

// ---------------------------------------------------------------------------
// Classification closure (JC1) — reconcile output kind ∈ the 5-member closed set. Referenced by
// import; the static enum guard lives in lifecycle-fuzz.test.ts.
// ---------------------------------------------------------------------------
export const isReconcileClassificationKind = (kind: string): boolean =>
  (RECONCILE_CLASSIFICATION_KINDS as readonly string[]).includes(kind);

// ---------------------------------------------------------------------------
// Secret-leak scanner (amendment 8) — runs over anything fast-check may serialize on failure
// (Action programs / state objects). Fail-closed on secret-shaped fields or overlong opaque
// blobs. Generated actions carry only short opaque ids, so this always passes = regression guard.
// ---------------------------------------------------------------------------
const SECRET_SHAPED =
  /-----BEGIN|PRIVATE KEY|private_?key|\bsecret\b|\btotp\b|seed_?byte|inner_preimage|preimage_text|redemption_expiry|step_1_signature|transfer_code_text/i;

export function assertNoSecretLeak(value: unknown): void {
  const serialized = JSON.stringify(value) ?? "";
  if (SECRET_SHAPED.test(serialized)) {
    throw new Error(`secret-shaped field reachable in serialized fuzz object`);
  }
  // No opaque id in the Action alphabet exceeds this; a long base64 key/signature would.
  for (const match of serialized.matchAll(/"([^"]{61,})"/g)) {
    throw new Error(`overlong (${match[1].length}-char) string reachable — possible key/preimage leak`);
  }
}

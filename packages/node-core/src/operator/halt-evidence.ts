// Halt evidence: the append-only audit trail over the operator halt, and the ONLY way to
// mutate halt state (kind-scoped operator halt: every toggle writes an `admin.halt.engaged`/`admin.halt.
// disengaged` audit row;: a row for every engage/disengage ATTEMPT AND
// OUTCOME, including the failed and rejected ones). The durable halt state (HaltStore)
// stays the single source of truth for fail-closed gating; this layer records every
// attempt against it.
//
// Ordering is load-bearing and asymmetric on purpose: the durable write comes FIRST, the
// live gate flip second, the evidence append LAST. A crash or an evidence-sink failure
// after the write leaves the durable record authoritative (the next boot's
// restoreHaltState converges the gate) — an audit gap is a logged omission, never an
// un-halted node. Recording never gates or discards in-flight work; the wrappers in
// halt-gate.ts own admission (the one-in-flight-per-wallet rule).

import { z } from "zod";

import {
  HALTED,
  MISSING_HALT_RECORD_DEFAULT,
  RUNNING,
  type HaltGate,
  type HaltState,
  type HaltStore,
} from "./halt.js";

/** What the operator asked for. Present tense: an ATTEMPT, not necessarily a transition. */
export const HALT_EVIDENCE_ACTIONS = ["ENGAGE", "DISENGAGE"] as const;
export type HaltEvidenceAction = (typeof HALT_EVIDENCE_ACTIONS)[number];

/**
 * What the attempt did.
 * APPLIED — the durable state changed.
 * NO_OP — already in the requested state; nothing was written (the live gate is still
 * converged to durable truth). The attempt is recorded, the STATE is not.
 * REJECTED — refused by the caller's authorization check; store and gate untouched.
 */
export const HALT_EVIDENCE_OUTCOMES = ["APPLIED", "NO_OP", "REJECTED"] as const;
export type HaltEvidenceOutcome = (typeof HALT_EVIDENCE_OUTCOMES)[number];

// One immutable audit row — `{engaged, reason, actor, time}` plus the outcome
// that distinguishes an applied toggle from a no-op or a refusal. `at` is epoch
// milliseconds; `reason` is an opaque non-secret operator note (never a key or a secret).
export interface HaltEvidenceRecord {
  readonly action: HaltEvidenceAction;
  readonly outcome: HaltEvidenceOutcome;
  readonly reason: string;
  readonly actor: string;
  readonly at: number;
}

// Append-only evidence port. entries returns a defensive copy so the trail cannot be
// mutated through a handed-out reference.
export interface HaltEvidenceRecorder {
  append(record: HaltEvidenceRecord): Promise<void>;
  entries(): Promise<readonly HaltEvidenceRecord[]>;
}

export function createInMemoryHaltEvidenceRecorder(): HaltEvidenceRecorder {
  const records: HaltEvidenceRecord[] = [];
  return {
    append: async (record) => {
      records.push(record);
    },
    entries: async () => records.slice(),
  };
}

/**
 * Durable backing for the trail. persistence contract is ONE durable record —
 * the node's existing settings KV row — with NO schema migration
 * (`HALT_PERSISTENCE.storage === "single-durable-record"`), so the trail is one opaque
 * JSON string in one record, exactly like the halt state beside it. The port stays
 * string-shaped so the concrete KV binding remains the app's, mirroring HaltStore.
 */
export interface HaltEvidenceStore {
  read(): Promise<string | null>;
  write(value: string): Promise<void>;
}

export class HaltEvidenceCorruptError extends Error {
  constructor(detail: string) {
    super(`halt evidence trail is corrupt: ${detail}`);
    this.name = "HaltEvidenceCorruptError";
  }
}

// ponytail: the whole trail lives in one record, so it is capped at the newest N and every
// append rewrites the record (O(n) bytes per append, last-write-wins between concurrent
// writers). Adequate for a TOTP-gated human toggle; move to a real append-only audit_log
// table — which costs the schema migration kind-scoped operator halt avoids — if volume or concurrency bites.
export const HALT_EVIDENCE_MAX_RECORDS = 500;

const evidenceRecordSchema = z.object({
  action: z.enum(HALT_EVIDENCE_ACTIONS),
  outcome: z.enum(HALT_EVIDENCE_OUTCOMES),
  reason: z.string(),
  actor: z.string(),
  at: z.number(),
});

const evidenceTrailSchema = z.array(evidenceRecordSchema);

function parseTrail(raw: string): HaltEvidenceRecord[] {
  let decoded: unknown;
  try {
    decoded = JSON.parse(raw);
  } catch {
    throw new HaltEvidenceCorruptError("record is not valid JSON");
  }
  const parsed = evidenceTrailSchema.safeParse(decoded);
  if (!parsed.success) {
    throw new HaltEvidenceCorruptError(
      parsed.error.issues[0]?.message ?? "record is not a trail of evidence rows",
    );
  }
  return parsed.data;
}

// Durable recorder over the single-record store. A missing record is an empty trail (a
// node that was never toggled); a CORRUPT record throws rather than reading as empty —
// silently returning [] would make a damaged audit trail indistinguishable from a clean
// one. Throwing is safe here precisely because evidence is appended after the durable halt
// write, so it can never un-halt the node.
export function createDurableHaltEvidenceRecorder(
  store: HaltEvidenceStore,
): HaltEvidenceRecorder {
  const readTrail = async (): Promise<HaltEvidenceRecord[]> => {
    const raw = await store.read();
    return raw === null ? [] : parseTrail(raw);
  };

  return {
    append: async (record) => {
      const trail = [...(await readTrail()), record];
      await store.write(JSON.stringify(trail.slice(-HALT_EVIDENCE_MAX_RECORDS)));
    },
    entries: readTrail,
  };
}

export class HaltToggleRejectedError extends Error {
  readonly action: HaltEvidenceAction;

  constructor(action: HaltEvidenceAction) {
    super(`operator halt ${action.toLowerCase()} was rejected`);
    this.name = "HaltToggleRejectedError";
    this.action = action;
  }
}

/**
 * One operator attempt. `actor` is mandatory — an audit row that cannot name who acted is
 * not an audit row. `authorize` is the caller's gate (kind-scoped operator halt requires engage and disengage
 * to be gated exactly as strongly, `HALT_TOGGLE_AUTH`): supplying it here rather than
 * checking before the call is what makes a refusal recordable at all.
 */
export interface HaltToggleRequest {
  readonly actor: string;
  readonly reason?: string;
  readonly now?: () => number;
  readonly authorize?: () => boolean | Promise<boolean>;
}

const UNKNOWN_ACTOR = "unknown";

const DEFAULT_REASON: Readonly<Record<HaltEvidenceAction, string>> = {
  ENGAGE: "operator halt engaged",
  DISENGAGE: "operator halt disengaged",
};

async function record(
  recorder: HaltEvidenceRecorder,
  action: HaltEvidenceAction,
  outcome: HaltEvidenceOutcome,
  request: HaltToggleRequest,
): Promise<void> {
  const now = request.now ?? Date.now;
  await recorder.append({
    action,
    outcome,
    reason: request.reason ?? DEFAULT_REASON[action],
    // A blank actor is normalised, never refused: rejecting the attempt over bad audit
    // metadata would let a formatting problem block an emergency engage.
    actor: request.actor.trim() === "" ? UNKNOWN_ACTOR : request.actor,
    at: now(),
  });
}

// The one halt-state mutation path. Every exit — applied, no-op, rejected — appends
// exactly one record before returning or throwing, so `packages/node-core` has no
// un-audited way to change halt state.
async function applyHalt(
  target: HaltState,
  store: HaltStore,
  gate: HaltGate,
  recorder: HaltEvidenceRecorder,
  request: HaltToggleRequest,
): Promise<HaltState> {
  const action: HaltEvidenceAction = target === HALTED ? "ENGAGE" : "DISENGAGE";

  // (1) Authorization first, so a refused attempt is recorded even when the durable store
  // is unreachable. A THROWN check is a rejection too: an audit trail that omits the
  // attempts which failed at the gate is precisely the one an incident review needs.
  if (request.authorize !== undefined) {
    let authorized: boolean;
    try {
      authorized = await request.authorize();
    } catch (error) {
      await record(recorder, action, "REJECTED", request);
      throw error;
    }
    if (!authorized) {
      await record(recorder, action, "REJECTED", request);
      throw new HaltToggleRejectedError(action);
    }
  }

  const flip = target === HALTED ? () => gate.engage() : () => gate.release();
  // a null read must agree with restoreHaltState's fail-closed boot default
  // (HALTED), not RUNNING — otherwise a fresh node's first disengage computes
  // current === target === RUNNING, takes the NO_OP branch below, and never persists
  // anything, so the very next restart re-halts it.
  const current = (await store.read()) ?? MISSING_HALT_RECORD_DEFAULT;

  // (2) Already in the requested state: the durable record is left alone so repeated
  // toggles never double-count STATE, but the attempt is still recorded and the live
  // gate is converged to durable truth.
  if (current === target) {
    flip();
    await record(recorder, action, "NO_OP", request);
    return target;
  }

  // (3) Durable write BEFORE the live flip; evidence appended after both.
  await store.write(target);
  flip();
  await record(recorder, action, "APPLIED", request);
  return target;
}

/** Idempotent, audited engage. */
export async function engageHalt(
  store: HaltStore,
  gate: HaltGate,
  recorder: HaltEvidenceRecorder,
  request: HaltToggleRequest,
): Promise<HaltState> {
  return await applyHalt(HALTED, store, gate, recorder, request);
}

/** Idempotent, audited disengage — the exact mirror of engageHalt (same code path, so
 * "equally gated and audited" holds structurally, not by inspection). */
export async function disengageHalt(
  store: HaltStore,
  gate: HaltGate,
  recorder: HaltEvidenceRecorder,
  request: HaltToggleRequest,
): Promise<HaltState> {
  return await applyHalt(RUNNING, store, gate, recorder, request);
}

/**
 * Crash-safe audited toggle. The durable record is the source of truth: the next state is
 * the inverse of the persisted one (a missing record counts as HALTED, agreeing with
 * restoreHaltState's fail-closed boot default — — so the first toggle on a fresh
 * node disengages), and it dispatches to the symmetric engage/disengage so the trail
 * records the actual direction attempted.
 */
export async function toggleHalt(
  store: HaltStore,
  gate: HaltGate,
  recorder: HaltEvidenceRecorder,
  request: HaltToggleRequest,
): Promise<HaltState> {
  const current = (await store.read()) ?? MISSING_HALT_RECORD_DEFAULT;
  return current === HALTED
    ? await disengageHalt(store, gate, recorder, request)
    : await engageHalt(store, gate, recorder, request);
}

// Proof-access expiry — the verification-material access gate for the generic node.
//
// This module deliberately builds NO purge/delete lifecycle. The two
// concepts are kept strictly separate and are never conflated:
// * proof-access expiry — this module. It time-boxes ONE endpoint's exposure. Once
// `verification_material_available_until` (= terminal_at + window) passes, the endpoint
// returns 410; access is revoked. NO row is ever removed, mutated, archived, or purged.
// * evidence permanence — canonical ledger containers, signature preimages, passing
// wallet-state observations, and anomaly sightings are PERMANENT. Their
// immutability is enforced at the database trigger level, not here.
//
// The module is a pure decision surface: no storage, no clock ownership, no Map, no lifecycle
// state machine, and — by construction — no function that could delete or mutate a row. `nowMs`
// and the persisted `verification_material_available_until` are supplied by the caller; nothing
// is derived from the wall clock at read time except the caller's injected `nowMs`.

import {
  type OperationKind,
  type ReceiveExternalState,
  type MoveInternalState,
  type SendExternalState,
} from "@zucoins/generic-node-contracts/operations";

// Server proof access is available until
// `verification_material_available_until`, default terminal plus 30 days." Kept in ms because
// every input to this module is a millisecond epoch; the canonical seconds form lives in the
// app config (apps/generic-node PROOF_ACCESS_WINDOW_DEFAULT_SECONDS), which node-core may not
// import across the package boundary.
export const DEFAULT_PROOF_ACCESS_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

// The landed-terminal status per operation kind. This is the ONLY status at which verification
// material is ready to be served: a receive that landed, a move that landed, a send that landed.
// The values are typed against the frozen per-kind state unions (states.contract.ts), so a rename
// of any canonical landed status fails this module at compile time — the vocabulary is consumed,
// never redeclared.
const LANDED_TERMINAL_STATUS: {
  readonly RECEIVE_EXTERNAL: ReceiveExternalState;
  readonly MOVE_INTERNAL: MoveInternalState;
  readonly SEND_EXTERNAL: SendExternalState;
} = {
  RECEIVE_EXTERNAL: "RECEIVE_LANDED",
  MOVE_INTERNAL: "INTERNAL_MOVE_LANDED",
  SEND_EXTERNAL: "EXTERNAL_SEND_LANDED",
};

// The coarse access verdict: NOT_READY → 409
// verification_material_not_ready (pre-terminal, material not yet available); ACCESSIBLE → 200;
// EXPIRED → 410 verification_material_expired. There is intentionally no PURGED verdict: expiry
// revokes access, it never deletes.
export const PROOF_ACCESS_VERDICTS = ["NOT_READY", "ACCESSIBLE", "EXPIRED"] as const;

export type ProofAccessVerdict = (typeof PROOF_ACCESS_VERDICTS)[number];

export interface ProofAccessQuery {
  readonly kind: OperationKind;
  // The operation's current Layer-1 status (per states.contract.ts). Material is served only at
  // the kind's landed-terminal status; every other status is pre-terminal and yields 409.
  readonly status: string;
  // The persisted `operations.verification_material_available_until` as a millisecond epoch, or
  // null while the operation is not (yet) at a landed terminal — an in-flight, ambiguous,
  // awaiting-redemption, pinned, needs-attention, or expired-unclaimed operation has no window
  // and no time-based deletion path, and its evidence is never expired away.
  readonly verificationMaterialAvailableUntilMs: number | null;
  readonly nowMs: number;
}

// The HTTP projection of each verdict, byte-aligned with the frozen error-envelope codes
// (packages/node-core/src/api/error-envelope.ts): verification_material_not_ready (409) and
// verification_material_expired (410).
export const PROOF_ACCESS_HTTP: {
  readonly [V in ProofAccessVerdict]: { readonly http: 200 | 409 | 410; readonly code: string | null };
} = {
  NOT_READY: { http: 409, code: "verification_material_not_ready" },
  ACCESSIBLE: { http: 200, code: null },
  EXPIRED: { http: 410, code: "verification_material_expired" },
};

export interface VerificationMaterialAccess {
  readonly verdict: ProofAccessVerdict;
  readonly http: 200 | 409 | 410;
  readonly code: string | null;
}

// True only for the kind's landed-terminal status. Pre-terminal statuses (CREATED, READY,
// APPROVED, AWAITING_REDEMPTION, NEEDS_ATTENTION, REJECTED, EXPIRED) are all false: verification
// material is never served before a positive landing.
export function isLandedTerminalStatus(kind: OperationKind, status: string): boolean {
  return LANDED_TERMINAL_STATUS[kind] === status;
}

// `verification_material_available_until` is written at the landed terminal
// as `terminal_at + window`. This is the single derivation the persistence path uses when it
// writes the column; it is intentionally pure so the (downstream) operation-transition writer
// and this gate agree on the exact value.
export function verificationMaterialAvailableUntilMs(
  terminalAtMs: number,
  windowMs: number = DEFAULT_PROOF_ACCESS_WINDOW_MS,
): number {
  if (!Number.isFinite(terminalAtMs)) {
    throw new RangeError("terminalAtMs must be a finite millisecond epoch");
  }
  if (!Number.isFinite(windowMs) || windowMs < 0) {
    throw new RangeError("windowMs must be a non-negative, finite duration");
  }
  return terminalAtMs + windowMs;
}

// The access decision for one operation. Pure: same inputs always yield the same verdict, and no
// row is read, written, deleted, or mutated. Never serves a pre-terminal operation.
export function decideProofAccess(query: ProofAccessQuery): ProofAccessVerdict {
  // Pre-terminal: material is not yet available. Return 409 before consulting any window — a
  // stray non-null window on a non-landed row must never open access (defence in depth against
  // the "serves material pre-terminal" defect this slice closes).
  if (!isLandedTerminalStatus(query.kind, query.status)) {
    return "NOT_READY";
  }
  const until = query.verificationMaterialAvailableUntilMs;
  // Landed but the column is unpopulated — treat as not ready rather than silently accessible.
  if (until === null) {
    return "NOT_READY";
  }
  // Fail closed on non-finite clock/column. In JS, `NaN >= x` is false and would fall through
  // to ACCESSIBLE — serving proof material after a corrupted until or a broken clock. Same class
  // as scope-gate fail-open: malformed input must never open access. Producer
  // (verificationMaterialAvailableUntilMs) throws RangeError; the consumer gate fails closed to
  // EXPIRED so the HTTP surface returns 410 rather than 500 / ACCESSIBLE.
  if (!Number.isFinite(query.nowMs) || !Number.isFinite(until)) {
    return "EXPIRED";
  }
  // "Available until X": accessible strictly before X; at or after X the window has passed.
  if (query.nowMs >= until) {
    return "EXPIRED";
  }
  return "ACCESSIBLE";
}

// The full access response for the verification-material endpoint: the verdict plus its frozen
// HTTP status and error code. A caller (the HTTP handler, wired downstream once the generic-node
// request surface exists) returns 409/200/410 directly from this.
export function resolveVerificationMaterialAccess(query: ProofAccessQuery): VerificationMaterialAccess {
  const verdict = decideProofAccess(query);
  const projection = PROOF_ACCESS_HTTP[verdict];
  return { verdict, http: projection.http, code: projection.code };
}

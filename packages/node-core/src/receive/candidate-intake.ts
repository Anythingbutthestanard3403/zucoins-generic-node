// Capture and verify candidate partial.
//
// Steps 1–7 (through the STEP1_SIGNATURE_PERSISTED DB-TX), the write-time mirror of the
// receiver-verification predicate set, and the receive economic delta over the canonical
// Receive message; the byte-exact signing rule (byte-exact signing) and 5 (no keys).
//
// This is the pre-co-sign gate. Every invalid or indeterminate candidate fails BEFORE any
// co-sign / signer invocation. Downstream stages assume everything that
// reaches them has already passed every check here. Co-sign itself is out of scope.
//
// Ordering discipline (lifted as pattern only from v1 verify.ts — field names/bounds re-derived
// from v2 specs, never from v1 primitives): cheap local checks run before the network-bound
// sender-preflight OBSERVE so a bad amount/schema never costs a gateway round-trip.
//
// Module lives under receive/ (not protocol/): JSON.parse of a foreign candidate is a receive-
// adapter concern. protocol/ forbids ad-hoc JSON.parse (source-safety ratchet).
//
// Driver-agnostic: composition root injects locate / capture / observe / persist ports.

import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import {
  compareAmounts,
  inspectForeignAmount,
  subtractAmounts,
  validateOperationAmount,
} from "@zucoins/generic-node-contracts/amounts";

import type { SplitChainInnerV2 } from "../protocol/inner.js";
import { narrowSplitChainInner } from "../protocol/inner-shape.js";
import { verifyRawEd25519 } from "../protocol/ed25519-verify.js";
import {
  InvalidScalarError,
  parseEd25519Signature,
  parseWalletPublicKey,
} from "../protocol/scalars.js";
import { buildReceiveMessage, RECEIVE_MESSAGE_PREFIX } from "../protocol/receive-transfer-code.js";
import { isReceiveUnexpired } from "./arm-mutation.js";

// ── Observation / phase literals ──────────────────────────────────────────────────

/** Observation role. */
export const RECEIVE_SENDER_PREFLIGHT_ROLE = "RECEIVE_SENDER_PREFLIGHT" as const;

/** Terminal phase for this slice. */
export const CANDIDATE_INTAKE_PHASE = "STEP1_SIGNATURE_PERSISTED" as const;

/** Exact capture fields (CANDIDATE_RAW_CAPTURE_FIELDS). */
export const CANDIDATE_CAPTURE_FIELDS = ["inner_preimage_text", "step_1_signature"] as const;

// ── Rejection vocabulary ────────────────────────────────────────────────────────────────────

/**
 * Closed set of determinate rejection reasons. Each maps to one invalid class in the ticket's
 * exhaustive negative-vector list. Indeterminate sender-preflight is its own reason so ops can
 * tell "couldn't observe" from "observed and disagreed".
 */
export type CandidateIntakeRejectionReason =
  | "OPERATION_NOT_FOUND"
  | "UNARMED"
  | "NOT_READY"
  | "EXPIRED"
  | "ATTENTION_SET"
  | "LEASE_NOT_OWNED"
  | "MALFORMED_PREIMAGE"
  | "BAD_SCHEMA"
  | "WRONG_KEY_ROLE"
  | "BAD_MESSAGE"
  | "MALFORMED_SIGNATURE"
  | "SIGNATURE_INVALID"
  | "RECEIVER_LINK_MISMATCH"
  | "RECEIVER_DELTA_MISMATCH"
  | "SENDER_PREFLIGHT_INDETERMINATE"
  | "SENDER_PREFLIGHT_LINK_MISMATCH"
  | "SENDER_PREFLIGHT_DELTA_MISMATCH"
  | "ALREADY_CLAIMED"
  | "STATE_CHANGED"
  | "INVALID_OPERATION_AMOUNT";

export class CandidateIntakeError extends Error {
  readonly code = "CANDIDATE_INTAKE_REJECTED";

  constructor(
    readonly reason: CandidateIntakeRejectionReason,
    message?: string,
  ) {
    super(message ?? `candidate intake rejected (${reason})`);
    this.name = "CandidateIntakeError";
  }
}

// ── Ports ───────────────────────────────────────────────────────────────────────────────────

/** Locate keys (CANDIDATE_LOCATE_KEYS). */
export interface CandidateLocateKeys {
  readonly receiverPubkey: string;
  readonly discriminator: string;
  readonly expiry: string;
}

/** Issuance T0 projection (S0/P0/B0). Comparing inbound previous link to P0 is FORBIDDEN. */
export interface ReceiverT0Projection {
  readonly S0: string;
  readonly P0: string;
  readonly B0: string;
  readonly observationId: string;
}

/**
 * Armed READY receive the candidate is trying to attach to. `armed` is true only when the
 * withheld code has been released (AWAITING_ARM→RELEASED).
 */
export interface LocatedReceive {
  readonly operationId: string;
  readonly amountZkz: string;
  readonly discriminator: string;
  readonly anchor: string;
  readonly expiryUnixTimeSecs: string;
  readonly receiverPubkey: string;
  readonly receiverWalletId: string;
  readonly state: string;
  readonly armed: boolean;
  readonly attentionRequired: boolean;
  readonly leaseOwned: boolean;
  readonly receiverT0: ReceiverT0Projection;
}

export interface LocateReceivePort {
  locate(keys: CandidateLocateKeys): Promise<LocatedReceive | null>;
  /**
   * Step-6 recheck under the same consistency boundary the claim will use. Returns null when
   * the operation disappeared mid-flight.
   */
  recheck(operationId: string): Promise<LocatedReceive | null>;
}

/**
 * Step-2 raw capture. Invoked BEFORE any JSON.parse so the exact payer bytes are retained even
 * if a later gate rejects. Composition may write an audit row, a side buffer, or a test probe.
 */
export interface CandidateRawCapture {
  readonly innerPreimageText: string;
  readonly step1Signature: string;
  readonly capturedAt: string;
}

export interface CandidateRawCapturePort {
  captureRaw(input: {
    readonly innerPreimageText: string;
    readonly step1Signature: string;
  }): CandidateRawCapture | Promise<CandidateRawCapture>;
}

/** Sender-preflight observation outcome. */
export type SenderPreflightObservation =
  | {
      readonly kind: "VERIFIED";
      readonly observationId: string;
      readonly S: string;
      readonly P: string;
      readonly B: string;
    }
  | { readonly kind: "INDETERMINATE"; readonly detail: string }
  | { readonly kind: "UNVERIFIED"; readonly detail: string };

export interface SenderPreflightObserver {
  observe(
    senderPubkey: string,
    role: typeof RECEIVE_SENDER_PREFLIGHT_ROLE,
  ): Promise<SenderPreflightObservation>;
}

/**
 * Validation manifest persisted with the winning candidate. Every predicate
 * that reached the DB-TX is recorded true; `receiver_link_compared_to` freezes the S0 rule so a
 * future accidental P0 comparison cannot silently ship.
 */
export interface CandidateValidationManifest {
  readonly schema_version_ok: true;
  readonly key_roles_ok: true;
  readonly expiry_ok: true;
  readonly message_discriminator_anchor_ok: true;
  readonly step1_signature_ok: true;
  readonly receiver_s0_link_ok: true;
  readonly receiver_delta_ok: true;
  readonly sender_preflight_s_link_ok: true;
  readonly sender_preflight_delta_ok: true;
  readonly operation_recheck_ok: true;
  /** MUST be the literal "S0". Comparing to P0 is a v1 defect (C-traceability T0 predecessor rule). */
  readonly receiver_link_compared_to: "S0";
  readonly receiver_link_compared_to_p0: false;
}

export interface PersistWinningCandidateInput {
  readonly operationId: string;
  readonly innerPreimageText: string;
  readonly innerSha256: string;
  readonly step1Signature: string;
  readonly validationManifest: CandidateValidationManifest;
  readonly senderObservationId: string;
  readonly senderPubkey: string;
  readonly formedAt: string;
}

export type PersistWinningCandidateResult =
  | { readonly ok: true; readonly attemptPhase: typeof CANDIDATE_INTAKE_PHASE }
  | { readonly ok: false; readonly reason: "ALREADY_CLAIMED" | "STATE_CHANGED" };

/**
 * Single-winner DB-TX. Exactly one candidate may claim the unique
 * receive-attempt slot; a second insert against the same operation_id must lose.
 */
export interface CandidatePersistPort {
  claimAndPersist(input: PersistWinningCandidateInput): Promise<PersistWinningCandidateResult>;
}

/**
 * Signer boundary probe. Candidate intake MUST NEVER invoke the signer — this port exists so
 * tests can assert zero calls. Production composition leaves it as a throwing stub or omits it.
 */
export interface CandidateIntakeSignerProbe {
  sign(_preimageId: string): Promise<never>;
}

export interface CandidateIntakeClock {
  nowMs(): number;
  nowIso(): string;
}

export interface CandidateIntakeDeps {
  readonly locate: LocateReceivePort;
  readonly capture: CandidateRawCapturePort;
  readonly observeSender: SenderPreflightObserver;
  readonly persist: CandidatePersistPort;
  readonly clock: CandidateIntakeClock;
  /** Optional — when present, any call is a hard failure (must stay at zero invocations). */
  readonly signer?: CandidateIntakeSignerProbe;
}

// ── Wire input ──────────────────────────────────────────────────────────────────────────────

/**
 * Internal protocol-adapter payload (NOT a public money-operation endpoint — F opening
 * line / CANDIDATE_INTAKE_IS_PUBLIC_OPERATION_ENDPOINT = false). The SplitChain-compatible
 * receiver channel delivers these exact two capture fields plus the locate keys.
 */
export interface CandidateIntakeRequest {
  readonly locate: CandidateLocateKeys;
  /** Exact payer-signed inner preimage text — captured before parse. */
  readonly inner_preimage_text: string;
  /** Exact payer step-1 Ed25519 signature (padded base64url). */
  readonly step_1_signature: string;
}

export interface CandidateIntakeSuccess {
  readonly ok: true;
  readonly operationId: string;
  readonly attemptPhase: typeof CANDIDATE_INTAKE_PHASE;
  readonly innerPreimageText: string;
  readonly innerSha256: string;
  readonly step1Signature: string;
  readonly validationManifest: CandidateValidationManifest;
  readonly senderObservationId: string;
  readonly capturedAt: string;
}

export type CandidateIntakeResult = CandidateIntakeSuccess;

// ── Ed25519 verify (explicit encoding gate before raw verify) ────────────────────────────

/**
 * Verify step-1 over the EXACT captured inner text (the byte-exact signing rule). Encoding is validated via
 * parseEd25519Signature / parseWalletPublicKey BEFORE crypto so a wrong-length sig is
 * MALFORMED_SIGNATURE (reachable), not collapsed into SIGNATURE_INVALID.
 */
function verifyStep1OverExactText(
  innerPreimageText: string,
  signatureText: string,
  publicKeyText: string,
): "ok" | "MALFORMED_SIGNATURE" | "SIGNATURE_INVALID" {
  let signature: string;
  let publicKey: string;
  try {
    signature = parseEd25519Signature(signatureText);
    publicKey = parseWalletPublicKey(publicKeyText);
  } catch (error) {
    if (error instanceof InvalidScalarError) return "MALFORMED_SIGNATURE";
    throw error;
  }
  try {
    const valid = verifyRawEd25519({
      publicKeyBytes: Buffer.from(publicKey, "base64url"),
      preimageBytes: Buffer.from(innerPreimageText, "utf8"),
      signatureBytes: Buffer.from(signature, "base64url"),
    });
    return valid ? "ok" : "SIGNATURE_INVALID";
  } catch {
    return "MALFORMED_SIGNATURE";
  }
}

// ── Inner shape (compose shared narrow; receive ↛ verifier boundary) ───────────────────
//
// JSON.parse stays here (protocol forbids ad-hoc parse). After capture, the parsed
// object is handed to protocol/narrowSplitChainInner — the same foreign-scalar gate the
// uses (unix_time_secs, amounts without throw-on-non-string, expiry, message limits, keys).
// Role literals map to WRONG_KEY_ROLE; every other closed-shape / scalar failure is BAD_SCHEMA
// or MALFORMED_PREIMAGE. Never surface raw TypeError from amount inspectors.

type NarrowResult =
  | { readonly ok: true; readonly inner: SplitChainInnerV2 }
  | { readonly ok: false; readonly reason: "MALFORMED_PREIMAGE" | "BAD_SCHEMA" | "WRONG_KEY_ROLE" };

/**
 * Parse + narrow the captured inner text. Signature verification uses the captured string, not
 * a re-serialized object — this parse is field extraction only (the byte-exact signing rule).
 */
function narrowCapturedInner(innerPreimageText: string): NarrowResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(innerPreimageText);
  } catch {
    return { ok: false, reason: "MALFORMED_PREIMAGE" };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { ok: false, reason: "MALFORMED_PREIMAGE" };
  }

  const narrowing = narrowSplitChainInner(parsed as Readonly<Record<string, unknown>>);
  if (!narrowing.ok) {
    const { rejection } = narrowing;
    // Role literals (fields 5–6) are their own intake rejection class.
    if (
      rejection.reason === "unexpected_inner_shape" &&
      (rejection.detail.includes("step_1_signer") || rejection.detail.includes("step_2_signer"))
    ) {
      return { ok: false, reason: "WRONG_KEY_ROLE" };
    }
    // Shape + foreign-scalar failures (incl. NON_STRING amounts / unix_time_secs) → BAD_SCHEMA.
    return { ok: false, reason: "BAD_SCHEMA" };
  }
  return { ok: true, inner: narrowing.inner };
}

// ── Message / expiry ────────────────────────────────────────────────────────────────────────

function checkMessageDiscriminatorAnchor(
  inner: SplitChainInnerV2,
  operation: LocatedReceive,
): boolean {
  // A.2: exact literal "zp1:" + discriminator + ":" + anchor — no whitespace/normalization.
  let expected: string;
  try {
    expected = buildReceiveMessage(operation.discriminator, operation.anchor);
  } catch {
    return false;
  }
  if (inner.message !== expected) return false;
  // Defence: prefix + split must also round-trip the operation UUID discriminator.
  if (!expected.startsWith(RECEIVE_MESSAGE_PREFIX)) return false;
  return true;
}

function checkExactDelta(
  minuend: string,
  subtrahend: string,
  expected: string,
): boolean {
  const a = inspectForeignAmount(minuend);
  const b = inspectForeignAmount(subtrahend);
  if (!a.wellFormed || !b.wellFormed) return false;
  const delta = subtractAmounts(minuend, subtrahend);
  return compareAmounts(delta, expected) === 0;
}

function assertOperationGate(op: LocatedReceive, nowMs: number): void {
  if (!op.armed) throw new CandidateIntakeError("UNARMED");
  if (op.state !== "READY") throw new CandidateIntakeError("NOT_READY");
  if (!isReceiveUnexpired(op.expiryUnixTimeSecs, nowMs)) throw new CandidateIntakeError("EXPIRED");
  if (op.attentionRequired) throw new CandidateIntakeError("ATTENTION_SET");
  if (!op.leaseOwned) throw new CandidateIntakeError("LEASE_NOT_OWNED");
}

// ── Service ─────────────────────────────────────────────────────────────────────────────────

export interface CandidateIntakeService {
  /**
   * Run for one candidate. Throws CandidateIntakeError on every reject path.
   * Never calls the signer. On success the unique receive-attempt slot is held at
   * STEP1_SIGNATURE_PERSISTED with the validation manifest and sender observation id.
   */
  intake(request: CandidateIntakeRequest): Promise<CandidateIntakeResult>;
}

export function createCandidateIntakeService(deps: CandidateIntakeDeps): CandidateIntakeService {
  async function intake(request: CandidateIntakeRequest): Promise<CandidateIntakeResult> {
    // ── Step 1: locate by receiver pubkey, discriminator, expiry, active lease ──────────
    const located = await deps.locate.locate(request.locate);
    if (located === null) throw new CandidateIntakeError("OPERATION_NOT_FOUND");
    // Refuse unarmed before any capture/parse work beyond the locate.
    if (!located.armed) throw new CandidateIntakeError("UNARMED");

    // ── Step 2: capture exact bytes BEFORE any parse ────────────────────────────────────
    // The capture port is the instrumentation point the byte-capture test hooks: it MUST
    // run to completion before JSON.parse below. Rejected candidates still leave a capture
    // record so exact bytes are not lost to a later gate failure.
    const captured = await deps.capture.captureRaw({
      innerPreimageText: request.inner_preimage_text,
      step1Signature: request.step_1_signature,
    });

    // ── Step 3: schema/version, key roles, expiry, message, step-1 sig over exact text ──
    const narrowed = narrowCapturedInner(captured.innerPreimageText);
    if (!narrowed.ok) throw new CandidateIntakeError(narrowed.reason);
    const inner = narrowed.inner;

    // Operation amount is PositiveZkzAmount; candidate step amounts may be zero (canonical ZKZ amount contract).
    const amountCheck = validateOperationAmount(located.amountZkz);
    if (!amountCheck.ok) throw new CandidateIntakeError("INVALID_OPERATION_AMOUNT");

    // the inner's expiry is PAYER-CONTROLLED — real wallets compute their own when
    // building the partial rather than echoing the one the node put in the transfer code (observed
    // live: node issued 1785470676, wallet returned 1785470688). Requiring byte-equality here
    // rejected every genuine payment as EXPIRED. The node's OWN frozen expiry is the only // contract-allow:payment:frozen structural vocabulary
    // authority over whether this receive is still open, and it is checked below; v1
    // (apps/node/src/pipeline) never reads the payer's inner expiry at all.
    // Byte-exactness is untouched — step_2 is still co-signed over the exact captured inner text.
    if (!isReceiveUnexpired(located.expiryUnixTimeSecs, deps.clock.nowMs())) {
      throw new CandidateIntakeError("EXPIRED");
    }

    if (!checkMessageDiscriminatorAnchor(inner, located)) {
      throw new CandidateIntakeError("BAD_MESSAGE");
    }

    // Receiver key on the inner must be the reserved operation receiver.
    if (inner.step_2_key_public__base64urlsafe !== located.receiverPubkey) {
      throw new CandidateIntakeError("WRONG_KEY_ROLE");
    }

    const sigResult = verifyStep1OverExactText(
      captured.innerPreimageText,
      captured.step1Signature,
      inner.step_1_key_public__base64urlsafe,
    );
    if (sigResult === "MALFORMED_SIGNATURE") {
      throw new CandidateIntakeError("MALFORMED_SIGNATURE");
    }
    if (sigResult === "SIGNATURE_INVALID") {
      throw new CandidateIntakeError("SIGNATURE_INVALID");
    }

    // ── Step 4: receiver side vs issuance T0 — S0 only, never P0 ────────────────────────
    // C-traceability "T0 predecessor rule": comparing inbound previous link to T0.P0 (or
    // omitting B0) is a corrected v1 defect. Correct comparison is against S0.
    if (inner.previous_step_2_state_signature !== located.receiverT0.S0) {
      throw new CandidateIntakeError(
        "RECEIVER_LINK_MISMATCH",
        "inner.previous_step_2_state_signature does not equal receiver_T0.S0",
      );
    }
    // Explicit non-use of P0: even when P0 happens to equal the previous link (genesis both
    // empty), the compared-to field recorded in the manifest is S0. A mistaken P0-only
    // implementation is locked out by the negative-vector test that sets P0==link, S0!=link.
    if (
      !checkExactDelta(
        inner.step_2_state.amount,
        located.receiverT0.B0,
        located.amountZkz,
      )
    ) {
      throw new CandidateIntakeError(
        "RECEIVER_DELTA_MISMATCH",
        "inner.step_2_state.amount - receiver_T0.B0 != operation.amount_zkz",
      );
    }

    // ── Step 5: OBSERVE sender preflight (ONLY after all local/cheap checks pass) ───────
    const senderPubkey = inner.step_1_key_public__base64urlsafe;
    const preflight = await deps.observeSender.observe(senderPubkey, RECEIVE_SENDER_PREFLIGHT_ROLE);
    if (preflight.kind !== "VERIFIED") {
      throw new CandidateIntakeError(
        "SENDER_PREFLIGHT_INDETERMINATE",
        `sender preflight ${preflight.kind}: ${preflight.detail}`,
      );
    }
    if (inner.previous_step_1_state_signature !== preflight.S) {
      throw new CandidateIntakeError(
        "SENDER_PREFLIGHT_LINK_MISMATCH",
        "inner.previous_step_1_state_signature does not equal sender_preflight.S",
      );
    }
    if (!checkExactDelta(preflight.B, inner.step_1_state.amount, located.amountZkz)) {
      throw new CandidateIntakeError(
        "SENDER_PREFLIGHT_DELTA_MISMATCH",
        "sender_preflight.B - inner.step_1_state.amount != operation.amount_zkz",
      );
    }

    // ── Step 6: recheck READY / armed / unexpired / attention-clear / lease-owned ────────
    const rechecked = await deps.locate.recheck(located.operationId);
    if (rechecked === null) throw new CandidateIntakeError("OPERATION_NOT_FOUND");
    assertOperationGate(rechecked, deps.clock.nowMs());

    const validationManifest: CandidateValidationManifest = {
      schema_version_ok: true,
      key_roles_ok: true,
      expiry_ok: true,
      message_discriminator_anchor_ok: true,
      step1_signature_ok: true,
      receiver_s0_link_ok: true,
      receiver_delta_ok: true,
      sender_preflight_s_link_ok: true,
      sender_preflight_delta_ok: true,
      operation_recheck_ok: true,
      receiver_link_compared_to: "S0",
      receiver_link_compared_to_p0: false,
    };

    const innerSha256 = createHash("sha256")
      .update(captured.innerPreimageText, "utf8")
      .digest("hex");

    // ── Step 7: DB-TX — single-winner persist at STEP1_SIGNATURE_PERSISTED ──────────────
    // Signer is never reached on this path. If a probe is installed, we deliberately do
    // not call it; tests assert call count stays zero across every vector.
    const formedAt = deps.clock.nowIso();
    const persisted = await deps.persist.claimAndPersist({
      operationId: rechecked.operationId,
      innerPreimageText: captured.innerPreimageText,
      innerSha256,
      step1Signature: captured.step1Signature,
      validationManifest,
      senderObservationId: preflight.observationId,
      senderPubkey,
      formedAt,
    });
    if (!persisted.ok) {
      throw new CandidateIntakeError(
        persisted.reason === "ALREADY_CLAIMED" ? "ALREADY_CLAIMED" : "STATE_CHANGED",
      );
    }

    return {
      ok: true,
      operationId: rechecked.operationId,
      attemptPhase: CANDIDATE_INTAKE_PHASE,
      innerPreimageText: captured.innerPreimageText,
      innerSha256,
      step1Signature: captured.step1Signature,
      validationManifest,
      senderObservationId: preflight.observationId,
      capturedAt: captured.capturedAt,
    };
  }

  return { intake };
}

// ── In-memory test doubles ──────────────────────────────────────────────────────────────────

export interface InMemoryCaptureRecord extends CandidateRawCapture {
  readonly sequence: number;
}

export function createInMemoryRawCapturePort(clock: CandidateIntakeClock): {
  readonly port: CandidateRawCapturePort;
  readonly records: InMemoryCaptureRecord[];
} {
  const records: InMemoryCaptureRecord[] = [];
  return {
    records,
    port: {
      captureRaw(input) {
        const rec: InMemoryCaptureRecord = {
          innerPreimageText: input.innerPreimageText,
          step1Signature: input.step1Signature,
          capturedAt: clock.nowIso(),
          sequence: records.length,
        };
        records.push(rec);
        return rec;
      },
    },
  };
}

export interface InMemoryPersistedCandidate extends PersistWinningCandidateInput {
  readonly attemptPhase: typeof CANDIDATE_INTAKE_PHASE;
}

export function createInMemoryCandidatePersistPort(): {
  readonly port: CandidatePersistPort;
  readonly rows: Map<string, InMemoryPersistedCandidate>;
} {
  const rows = new Map<string, InMemoryPersistedCandidate>();
  return {
    rows,
    port: {
      async claimAndPersist(input) {
        if (rows.has(input.operationId)) {
          return { ok: false, reason: "ALREADY_CLAIMED" };
        }
        const row: InMemoryPersistedCandidate = {
          ...input,
          attemptPhase: CANDIDATE_INTAKE_PHASE,
        };
        rows.set(input.operationId, row);
        return { ok: true, attemptPhase: CANDIDATE_INTAKE_PHASE };
      },
    },
  };
}

export function createFixedClock(nowMs: number): CandidateIntakeClock {
  return {
    nowMs: () => nowMs,
    nowIso: () => new Date(nowMs).toISOString(),
  };
}

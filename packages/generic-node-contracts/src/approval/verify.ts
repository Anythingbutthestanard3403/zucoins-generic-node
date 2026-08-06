/**
 * Pure, stateless verifiers and lookups for the approval concern. No DB, no keys, no
 * network — CONTRACT_FREEZE-legal. Three surfaces:
 *   1. `verifyApprovalPreimage` — enforce the A.4.1 byte contract on the approval tuple's exact
 *      preimage (field sequence, types, literal purpose/version, expiry > issue, digest).
 *   2. `verifyApprovalDeviceSignature` — verify the OPTIONAL additive device signature over the
 *      exact preimage bytes (it never replaces the mandatory TOTP).
 *   3. `recoveryActionFor` — the frozen crash-matrix lookup.
 * Plus `hasSuiteDomainPrefix`, which the reproduction proof uses to show a suite preimage can
 * never be re-read as a prefix-less SplitChain preimage (approval-preimage isolation).
 */
import { digestPreimage } from "./approval-digest.ts";
import { validateOperationAmount } from "../amounts/index.ts";
import {
  APPROVAL_PURPOSE,
  APPROVAL_TUPLE,
  type ApprovalFieldType,
} from "./approval-tuple.contract.ts";
import {
  CRASH_MATRIX,
  INVARIANT_BREACH_PREDICATE,
  type CrashDurableState,
  type CrashMatrixRow,
  type RecoveryAction,
} from "./crash-recovery.contract.ts";

/** The approval API/storage envelope. The device signature is OPTIONAL additive hardening; a
 *  TOTP-only approval carries none (A.9 vector 13). */
export interface ApprovalEnvelope {
  readonly preimage_text: string;
  readonly preimage_sha256: string;
  readonly device_signature?: string;
  readonly device_key_id?: string;
}

/**
 *  CONTRACT_FREEZE amendment: the Ed25519 crypto the OPTIONAL device-signature verifier
 * needs, DEPENDENCY-INJECTED via an in-package callback interface (the frozen
 * `RegisterProofCallbacks` pattern, `reporting-auth/verifier.ts`). Declared HERE — the concern that
 * owns the verifier owns the interface, the caller injects the implementation — so the generic-core scan concern stays
 * intact (never declared in node-core and imported). Only `verifyApprovalDeviceSignature` takes it;
 * the pure structural `verifyApprovalPreimage` needs only the accept-set-free SHA-256 digest, which
 * is the non-testkit `./approval-digest.ts` helper (no DI needed for a deterministic hash). The
 * injected default (`testkit/suiteVerificationCrypto.ts`) MUST stay the wallet's `libsodium-wrappers`
 * family so the Ed25519 accept-set is identical to Appendix A.
 */
export interface ApprovalDeviceVerificationCrypto {
  /** Resolves when the underlying crypto (e.g. libsodium) is initialised. */
  readonly ready: () => Promise<void>;
  /**
   * Verify a padded URL-safe base64 detached Ed25519 signature over the exact UTF-8 bytes of
   * `preimageText`, under the padded URL-safe base64 public key. The implementation owns full
   * point/subgroup validation and canonical-S enforcement (wallet libsodium accept-set).
   */
  readonly verifyPreimageSignature: (input: {
    readonly preimageText: string;
    readonly signatureB64Url: string;
    readonly publicKeyB64Url: string;
  }) => boolean;
}

export const APPROVAL_VERIFY_REJECT_REASONS = [
  "malformed_preimage",
  "payload_purpose_mismatch",
  "field_sequence_mismatch",
  "canonical_version_invalid",
  "field_value_invalid",
  "expiry_not_after_issue",
  "expiry_window_exceeded",
  "non_canonical_serialization",
  "digest_mismatch",
] as const;
export type ApprovalVerifyRejectReason = (typeof APPROVAL_VERIFY_REJECT_REASONS)[number];

export type ApprovalVerifyResult =
  | { readonly ok: true; readonly purpose: typeof APPROVAL_PURPOSE; readonly digest: string }
  | { readonly ok: false; readonly reason: ApprovalVerifyRejectReason; readonly detail?: string };

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PADDED_KEY_RE = /^[A-Za-z0-9\-_]{43}=$/;
// RFC 3339 UTC with exactly three fractional digits and a literal Z (A.1.1 rule 3).
const TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

// Approval-challenge freshness, in the uniform 300s ceremony-window class shared with
// transfer-code matching: `expires_at` is at most this many seconds after the SIGNED `issued_at`. A.9's
// "more than 300 seconds after the signed issued_at" is strict, so exactly +300s is legal — the
// committed A.8 golden is itself the +300.000s boundary case. Sibling: reporting-auth's
// REPORTING_KEY_ENROL_WINDOW_SECS (the directly-analogous reporting-key enrolment ceremony).
const APPROVAL_CHALLENGE_FRESHNESS_WINDOW_SECS = 300;

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const isValidSourceSelector = (value: unknown): boolean => {
  if (!isPlainObject(value)) return false;
  const keys = Object.keys(value);
  if (keys.length !== 2 || keys[0] !== "kind" || keys[1] !== "wallet_id") return false;
  return value.kind === "WALLET_ID" && typeof value.wallet_id === "string" && UUID_RE.test(value.wallet_id);
};

const isValueValidForType = (type: ApprovalFieldType, value: unknown): boolean => {
  switch (type) {
    case "purpose_literal":
      return value === APPROVAL_PURPOSE;
    case "canonical_version_literal":
      return value === 1;
    case "uuid":
    case "operation_uuid":
      return typeof value === "string" && UUID_RE.test(value);
    case "uuid_nullable":
      return value === null || (typeof value === "string" && UUID_RE.test(value));
    case "ed25519_pubkey_padded":
    case "external_address_padded":
      return typeof value === "string" && PADDED_KEY_RE.test(value);
    case "zkz_amount_positive":
      // the amounts-grammar freeze / the amounts concern strictly-positive canonical-text domain (`zkz_amount_positive_text`).
      // Numeric positivity + canonical re-emission, NOT a `regex && value !== '0'` gate: that
      // string form leaks '0.00'/'0.0' (mathematically zero) and non-canonical '2.50' (the amounts-grammar freeze
      // hardening addendum, clause 1).
      return typeof value === "string" && validateOperationAmount(value).ok;
    case "canonical_timestamp":
      return typeof value === "string" && TIMESTAMP_RE.test(value);
    case "source_selector_object":
      return isValidSourceSelector(value);
    default:
      return false;
  }
};

const reject = (reason: ApprovalVerifyRejectReason, detail?: string): ApprovalVerifyResult => ({
  ok: false,
  reason,
  detail,
});

/** `true` iff `text` begins with the exact suite domain-separation prefix (`purpose` + LF). A
 *  prefix-less SplitChain native preimage (A.1.2) never satisfies this, so the two byte spaces
 *  are disjoint — the frozen approval-preimage isolation (A.9 vector 15). */
export const hasSuiteDomainPrefix = (text: string): boolean => text.startsWith(`${APPROVAL_PURPOSE}\n`);

/**
 * Verify one approval preimage against the A.4.1 byte contract. Pure and fail-closed: the FIRST
 * failing check returns its reason. Does not check any signature — the device signature is
 * optional and handled by `verifyApprovalDeviceSignature`; the mandatory gate (TOTP) is not a
 * signature and is out of the byte contract entirely.
 */
export const verifyApprovalPreimage = (envelope: ApprovalEnvelope): ApprovalVerifyResult => {
  const newlineIndex = envelope.preimage_text.indexOf("\n");
  if (newlineIndex === -1) {
    return reject("malformed_preimage", "no domain-separation prefix");
  }
  const prefix = envelope.preimage_text.slice(0, newlineIndex);
  const payloadJson = envelope.preimage_text.slice(newlineIndex + 1);

  if (prefix !== APPROVAL_PURPOSE) {
    return reject("payload_purpose_mismatch", `prefix ${prefix}`);
  }

  let payload: unknown;
  try {
    payload = JSON.parse(payloadJson);
  } catch {
    return reject("malformed_preimage", "payload is not valid JSON");
  }
  if (!isPlainObject(payload)) {
    return reject("malformed_preimage", "payload is not a JSON object");
  }

  if (payload.purpose !== prefix) {
    return reject("payload_purpose_mismatch", "prefix purpose != payload purpose");
  }

  const actualFieldSequence = Object.keys(payload);
  const frozenFieldSequence = APPROVAL_TUPLE.fields.map((f) => f.name);
  if (
    actualFieldSequence.length !== frozenFieldSequence.length ||
    actualFieldSequence.some((name, i) => name !== frozenFieldSequence[i])
  ) {
    return reject("field_sequence_mismatch", actualFieldSequence.join(","));
  }

  if (payload.canonical_version !== 1) {
    return reject("canonical_version_invalid", String(payload.canonical_version));
  }

  for (const field of APPROVAL_TUPLE.fields) {
    if (!isValueValidForType(field.type, payload[field.name])) {
      return reject("field_value_invalid", field.name);
    }
  }

  // A.4.1: expires_at is strictly later than issued_at. The fixed timestamp format sorts
  // lexicographically into chronological sequence, so a string comparison suffices.
  if (!((payload.expires_at as string) > (payload.issued_at as string))) {
    return reject("expiry_not_after_issue");
  }

  // A.9 upper bound: expires_at is at most 300 seconds after the SIGNED
  // issued_at (the approval-challenge freshness class of the two-timer separation). Both operands are in-tuple signed
  // timestamps already validated as canonical RFC3339-ms above, so this measures the SIGNED
  // window, never receipt time, and — living inside this preimage verifier — runs before any
  // device-signature check (window before Ed25519). `> WINDOW*1000` is strict, so the
  // +300.000s boundary is accepted; a NaN delta (a range-invalid timestamp that still matched
  // the structural format) fails closed here.
  if (
    !(
      Date.parse(payload.expires_at as string) - Date.parse(payload.issued_at as string) <=
      APPROVAL_CHALLENGE_FRESHNESS_WINDOW_SECS * 1000
    )
  ) {
    return reject("expiry_window_exceeded");
  }

  // Canonical-serialization gate ("rebuild the exact approval tuple and compare its
  // preimage/digest to the displayed/persisted value"). A TOTP-only approval carries no signature,
  // so this — not a signature — is what rejects appended newline/BOM/whitespace (A.9 vector 8) and
  // any non-canonical spacing: the exact bytes must equal purpose + LF + JSON.stringify(payload).
  if (envelope.preimage_text !== `${APPROVAL_PURPOSE}\n${JSON.stringify(payload)}`) {
    return reject("non_canonical_serialization");
  }

  if (digestPreimage(envelope.preimage_text) !== envelope.preimage_sha256) {
    return reject("digest_mismatch");
  }

  return { ok: true, purpose: APPROVAL_PURPOSE, digest: envelope.preimage_sha256 };
};

/**
 * Verify the OPTIONAL additive device Ed25519 signature over the exact approval preimage bytes.
 * Returns `false` when no device signature is present, when the byte contract fails, or when the
 * signature does not verify under the supplied device public key (including a cross-purpose
 * signature computed over different bytes; A.9 vector 10). A `true` here is additive hardening
 * ONLY — it never substitutes for the mandatory fresh TOTP (A.9 vector 14).
 */
export const verifyApprovalDeviceSignature = async (
  envelope: ApprovalEnvelope,
  devicePublicKeyB64: string,
  crypto: ApprovalDeviceVerificationCrypto,
): Promise<boolean> => {
  if (envelope.device_signature === undefined) {
    return false;
  }
  if (!verifyApprovalPreimage(envelope).ok) {
    return false;
  }
  await crypto.ready();
  try {
    return crypto.verifyPreimageSignature({
      preimageText: envelope.preimage_text,
      signatureB64Url: envelope.device_signature,
      publicKeyB64Url: devicePublicKeyB64,
    });
  } catch {
    return false;
  }
};

const assertNeverState = (value: never): never => {
  throw new Error(`unhandled crash durable state: ${JSON.stringify(value)}`);
};

/**
 * The frozen crash-matrix lookup: given a durable state a crash left behind, return its one allowed
 * recovery action and one forbidden action. Total over the closed `CrashDurableState` set.
 */
export const recoveryActionFor = (state: CrashDurableState): CrashMatrixRow => {
  const row = CRASH_MATRIX.find((r) => r.durableState === state);
  if (row === undefined) {
    return assertNeverState(state as never);
  }
  return row;
};

/** Durable evidence a recovery pass reads for the `APPROVAL_CONSUMED_NO_SIGN_INTENT` row. */
export interface ApprovalConsumedNoSignIntentEvidence {
  readonly signerAuditShowsSigningCall: boolean;
  readonly persistedPreimageRecordAvailable: boolean;
  readonly persistedPreimageRecordContradictory: boolean;
}

/**
 * The frozen breach predicate for the `APPROVAL_CONSUMED_NO_SIGN_INTENT` row:
 * given the durable evidence a recovery pass reads (no persisted sign-intent row is the row's own
 * precondition), decide between this row's ordinary table action
 * (`ACQUIRE_READ_FRESH_PERSIST_FIRST_SIGN_INTENT`) and `INVARIANT_BREACH_PREDICATE`'s action
 * (`NEEDS_ATTENTION_PRESERVE_LEASE_EVIDENCE`). Total and pure; never first-forms, re-signs, or
 * releases a lease on breach.
 */
export const classifyApprovalConsumedNoSignIntent = (
  evidence: ApprovalConsumedNoSignIntentEvidence,
): RecoveryAction => {
  const breach =
    evidence.signerAuditShowsSigningCall ||
    !evidence.persistedPreimageRecordAvailable ||
    evidence.persistedPreimageRecordContradictory;
  if (breach) {
    return INVARIANT_BREACH_PREDICATE.action;
  }
  return recoveryActionFor("APPROVAL_CONSUMED_NO_SIGN_INTENT").recovery;
};

export const SOURCE =
  "approval byte-contract verifiers; crash-matrix lookup; approval-tuple freeze; canonical amount bound; two-timer separation; 300s ceremony window" as const;

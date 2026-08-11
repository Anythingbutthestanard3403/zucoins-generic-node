// approval-challenge issue/refresh and the guarded TOTP-consuming
// approve mutation for SEND_EXTERNAL.
//
// exact partial only.
//
// Eight-step sequence (verbatim):
// 1. authenticate session/action key and CSRF as applicable (HTTP layer);
// 2. parse and validate the whole request before inspecting a TOTP;
// 3. lock the operation and approval nonce rows;
// 4. rebuild the exact approval tuple and compare its preimage/digest;
// 5. require operation status, source selector, destination, amount, reference,
// nonce, and expiry unchanged;
// 6. verify a fresh TOTP and atomically reserve its (node_id,timestep);
// 7. mark the approval consumed and transition the operation in that same TX;
// 8. never restore the timestep if signing, persistence, or delivery later fails
// (only after the step 6–7 TX has committed; a CAS miss inside the TX rolls back).
//
// Rebuild-and-compare (step 4) is the substitution-attack close: the node re-derives
// the 12-field zp-send-external-approval-v1 preimage from the locked operation row via
// the frozen suite builder — it never trusts a client-supplied tuple. TOTP is
// authentication of the mutation, never a signature over the tuple.
// The optional device signature is the only cryptographic signature this module
// verifies, and only over the persisted preimage bytes.
//
// Single-use TOTP is DB-enforced by operation_approvals_totp_single_use. This
// module never uses an in-memory Map as the replay arbiter. Concurrent approves that
// share a timestep collide on that UNIQUE index; the loser is a generic factor failure.
//
// Error responses never reveal which factor failed (CSRF / session / device / TOTP /
// stale version / preimage / expiry). Internal outcomes keep distinct codes for tests
// and logging; the HTTP adapter collapses them to one opaque envelope.
//
// Dependency direction: this module lives under send/ and must not import http/ (node-core
// boundary graph). TOTP matching uses the shared totp/ leaf (same primitive as http/totp-chain).

import { randomUUID } from "node:crypto";

import type { DeviceKeyStore } from "../device/store.js";
import type { EnrolledDeviceKey } from "../device/types.js";
import { verifyDetachedEd25519 } from "../reporting/ed25519.js";
import { parsePositiveZkzAmount } from "../protocol/amounts.js";
import { parseUuid, parseWalletPublicKey } from "../protocol/scalars.js";
import { buildSendExternalApproval } from "../protocol/suite/builders.js";
import { matchTotp, type TotpConfig } from "../totp/match.js";
import type { TotpBurnStore } from "../totp/burn-store.js";
import {
  enforceDualControlOperators,
  type DualControlMode,
} from "./dual-control-policy.js";
import type { ApprovalChallengeIssuerStore } from "./challenge-issuer-store.js";
// Decision CAS lives inside ApprovalChallengeStore.commitApprovalMutation so
// consume + insert + CREATED→APPROVED are one transactional unit (step 7).
// Global (node_id,timestep) claim also hits TotpBurnStore so enrol-confirm burns
// block SEND approve (and money reject/bless share that same channel).

// T1 approval-challenge freshness window (A.9 / suite windowSeconds for this purpose).
// Inclusive 300s ceiling — the A.8 golden is itself the +300.000s boundary.
export const APPROVAL_CHALLENGE_FRESHNESS_MS = 300_000 as const;

export const APPROVAL_PURPOSE = "zp-send-external-approval-v1" as const;
export const APPROVAL_CANONICAL_VERSION = 1 as const;

export const SEND_APPROVAL_CHALLENGE_ROUTE =
  "/admin/v1/external-sends/:operation_id/approval-challenge" as const;
export const SEND_APPROVE_ROUTE = "/admin/v1/external-sends/:operation_id/approve" as const;

// Opaque factor-failure envelope. Every non-success path the HTTP layer may surface
// collapses to this single shape so body-diffing across failure modes reveals nothing.
// Status is 401 (never 403): authorization/factor refusal is not a scope oracle, and the
// frozen OPERATOR_SESSION authFailureStatus is 401 (ZTR-1191).
export const APPROVAL_FACTOR_FAILURE_CODE = "approval_rejected" as const;
// Factor failures are authentication-class (wrong TOTP, bad device sig, stale
// challenge). 401 matches OPERATOR_SESSION never-403 and lets the SPA treat the
// envelope as a re-promptable step-up challenge (ZTR-1194 / ZTR-1191). Body stays opaque.
export const APPROVAL_FACTOR_FAILURE_HTTP_STATUS = 401 as const;
// Doc 01 §4.2: deployment-policy denial stays distinguishable by *code* (and long copy).
// HTTP status is still 401 — never-403 for authorization/policy refusal on OPERATOR_SESSION
// (ZTR-1191 Option 2). Carve-out 403s are origin/password-posture only.
export const APPROVAL_POLICY_DENIAL_HTTP_STATUS = 401 as const;

// Deployment-policy denial. Doc 01 §4.2 requires optional node policy to stay
// distinguishable from protocol validity, so a dual-control refusal carries its own
// code. It is not a hole in the envelope above: it discloses that this deployment's
// policy refused this approver, never which authentication factor failed.
export const APPROVAL_POLICY_DENIAL_CODE = "same_operator_both_sides" as const;

export type ApprovalChallengeStatus = "ISSUED" | "CONSUMED" | "SUPERSEDED" | "EXPIRED";
export type ApprovalMethod = "TOTP_ONLY" | "TOTP_AND_DEVICE";

/** TOTP config for external-send approval — same shape as the shared matcher. */
export type ApprovalTotpConfig = TotpConfig;

export interface ApprovalChallenge {
  readonly id: string;
  readonly nodeId: string;
  readonly operationId: string;
  readonly status: ApprovalChallengeStatus;
  readonly purpose: typeof APPROVAL_PURPOSE;
  readonly canonicalVersion: typeof APPROVAL_CANONICAL_VERSION;
  readonly nonce: string;
  readonly preimageText: string;
  readonly preimageSha256: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly supersededBy: string | null;
}

export interface OperationApproval {
  readonly id: string;
  readonly nodeId: string;
  readonly operationId: string;
  readonly challengeId: string;
  readonly challengeStatus: "CONSUMED";
  readonly method: ApprovalMethod;
  readonly purpose: typeof APPROVAL_PURPOSE;
  readonly canonicalVersion: typeof APPROVAL_CANONICAL_VERSION;
  readonly preimageText: string;
  readonly preimageSha256: string;
  readonly deviceKeyId: string | null;
  readonly deviceSignature: string | null;
  readonly totpTimestep: number;
  readonly consumedAt: string;
}

export interface ApprovalOperationSnapshot {
  readonly operationId: string;
  readonly nodeId: string;
  readonly status: string;
  readonly rowVersion: number;
  readonly sourceWalletId: string;
  readonly sourcePubkey: string;
  readonly destinationAddress: string;
  readonly amountZkz: string;
  readonly referencesOperationId: string | null;
}

/** Result of the atomic step 6–7 / step 6 mutation. */
export type CommitApprovalMutationResult =
  | { readonly kind: "APPLIED"; readonly rowVersion: number }
  | { readonly kind: "CHALLENGE_NOT_ISSUED" }
  | { readonly kind: "TOTP_REPLAY" }
  | { readonly kind: "APPROVAL_EXISTS" }
  | { readonly kind: "OPERATION_CONFLICT" };

export interface ApprovalChallengeStore {
  findIssuedByOperation(operationId: string): Promise<ApprovalChallenge | null>;
  findByNonce(nonce: string): Promise<ApprovalChallenge | null>;
  insertIssued(challenge: ApprovalChallenge, supersedeId: string | null): Promise<void>;
  /**
   * Atomically: claim (node_id, totp_timestep) + consume challenge + insert
   * operation_approvals + CREATED→APPROVED CAS. All-or-nothing — a CAS miss MUST
   * leave no approval row, challenge still ISSUED, and timestep unburned.
   * Step 8 (never restore timestep) applies only after this returns APPLIED.
   */
  commitApprovalMutation(
    challengeId: string,
    approval: OperationApproval,
    expectedRowVersion: number,
  ): Promise<CommitApprovalMutationResult>;
}

export type UniqueViolationKind =
  | "challenge_one_issued"
  | "challenge_nonce"
  | "totp_timestep"
  | "approval_operation"
  | "approval_challenge"
  | "unknown";

export class ApprovalStoreUniqueViolation extends Error {
  readonly code = "APPROVAL_UNIQUE_VIOLATION" as const;
  constructor(readonly kind: UniqueViolationKind) {
    super(`approval store unique violation: ${kind}`);
    this.name = "ApprovalStoreUniqueViolation";
  }
}

export type ApprovalRejectReason =
  | "operation_not_found"
  | "operation_not_created"
  | "challenge_not_found"
  | "challenge_not_issued"
  | "challenge_expired"
  | "preimage_mismatch"
  | "row_version_mismatch"
  | "totp_invalid"
  | "totp_replay"
  | "device_required"
  | "device_forbidden"
  | "device_unknown"
  | "device_revoked"
  | "device_signature_invalid"
  | "request_invalid"
  | "operation_conflict"
  | "approval_exists"
  /** Two-human dual control: same admin_operator on challenge and approve. */
  | "same_operator_both_sides";

export const APPROVAL_REJECT_REASONS: readonly ApprovalRejectReason[] = [
  "operation_not_found",
  "operation_not_created",
  "challenge_not_found",
  "challenge_not_issued",
  "challenge_expired",
  "preimage_mismatch",
  "row_version_mismatch",
  "totp_invalid",
  "totp_replay",
  "device_required",
  "device_forbidden",
  "device_unknown",
  "device_revoked",
  "device_signature_invalid",
  "request_invalid",
  "operation_conflict",
  "approval_exists",
  "same_operator_both_sides",
] as const;

export interface ApprovalChallengeResponse {
  readonly operation_id: string;
  readonly row_version: number;
  readonly purpose: typeof APPROVAL_PURPOSE;
  readonly canonical_version: typeof APPROVAL_CANONICAL_VERSION;
  readonly nonce: string;
  readonly preimage_text: string;
  readonly preimage_sha256: string;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly source_selector: { readonly kind: "WALLET_ID"; readonly wallet_id: string };
  readonly source_pubkey: string;
  readonly destination_address: string;
  readonly amount_zkz: string;
  readonly references_operation_id: string | null;
}

export interface ApproveSuccessResponse {
  readonly operation_id: string;
  readonly status: "APPROVED";
  readonly row_version: number;
  readonly approval_id: string;
  readonly method: ApprovalMethod;
  readonly consumed_at: string;
}

export type IssueChallengeOutcome =
  | {
      readonly outcome: "ISSUED";
      readonly challenge: ApprovalChallenge;
      readonly rowVersion: number;
      readonly response: ApprovalChallengeResponse;
    }
  | { readonly outcome: "REJECTED"; readonly reason: ApprovalRejectReason };

export type ApproveOutcome =
  | {
      readonly outcome: "APPROVED";
      readonly approval: OperationApproval;
      readonly rowVersion: number;
      readonly response: ApproveSuccessResponse;
    }
  | { readonly outcome: "REJECTED"; readonly reason: ApprovalRejectReason };

export function toOpaqueApprovalFailure(reason: ApprovalRejectReason): {
  readonly code: typeof APPROVAL_FACTOR_FAILURE_CODE | typeof APPROVAL_POLICY_DENIAL_CODE;
  readonly httpStatus:
    | typeof APPROVAL_FACTOR_FAILURE_HTTP_STATUS
    | typeof APPROVAL_POLICY_DENIAL_HTTP_STATUS;
} {
  // Policy denial is distinguishable by code (§4.2); HTTP status is 401 for both
  // policy and factor paths so OPERATOR_SESSION never-403 holds (ZTR-1191). Factor
  // reasons still collapse to one opaque envelope so body-diffing cannot reveal
  // which factor failed (ZTR-1194).
  if (reason === APPROVAL_POLICY_DENIAL_CODE) {
    return {
      code: APPROVAL_POLICY_DENIAL_CODE,
      httpStatus: APPROVAL_POLICY_DENIAL_HTTP_STATUS,
    };
  }
  return {
    code: APPROVAL_FACTOR_FAILURE_CODE,
    httpStatus: APPROVAL_FACTOR_FAILURE_HTTP_STATUS,
  };
}

export function toCanonicalTimestamp(ms: number): string {
  return new Date(ms).toISOString();
}

export interface BuildApprovalPreimageInput {
  readonly nodeId: string;
  readonly operationId: string;
  readonly sourceWalletId: string;
  readonly sourcePubkey: string;
  readonly destinationAddress: string;
  readonly amountZkz: string;
  readonly referencesOperationId: string | null;
  readonly nonce: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export function buildApprovalPreimage(input: BuildApprovalPreimageInput): {
  readonly preimageText: string;
  readonly preimageSha256: string;
} {
  const built = buildSendExternalApproval({
    node_id: parseUuid(input.nodeId),
    operation_id: parseUuid(input.operationId),
    source_selector: { kind: "WALLET_ID", wallet_id: parseUuid(input.sourceWalletId) },
    source_pubkey: parseWalletPublicKey(input.sourcePubkey),
    destination_address: parseWalletPublicKey(input.destinationAddress),
    amount_zkz: parsePositiveZkzAmount(input.amountZkz),
    references_operation_id:
      input.referencesOperationId === null ? null : parseUuid(input.referencesOperationId),
    nonce: parseUuid(input.nonce),
    issued_at: input.issuedAt,
    expires_at: input.expiresAt,
  });
  return { preimageText: built.preimageText, preimageSha256: built.sha256 };
}

function toChallengeResponse(
  challenge: ApprovalChallenge,
  op: ApprovalOperationSnapshot,
): ApprovalChallengeResponse {
  return {
    operation_id: op.operationId,
    row_version: op.rowVersion,
    purpose: APPROVAL_PURPOSE,
    canonical_version: APPROVAL_CANONICAL_VERSION,
    nonce: challenge.nonce,
    preimage_text: challenge.preimageText,
    preimage_sha256: challenge.preimageSha256,
    issued_at: challenge.issuedAt,
    expires_at: challenge.expiresAt,
    source_selector: { kind: "WALLET_ID", wallet_id: op.sourceWalletId },
    source_pubkey: op.sourcePubkey,
    destination_address: op.destinationAddress,
    amount_zkz: op.amountZkz,
    references_operation_id: op.referencesOperationId,
  };
}

export interface IssueChallengeDeps {
  readonly challengeStore: ApprovalChallengeStore;
  readonly loadOperation: (operationId: string) => Promise<ApprovalOperationSnapshot | null>;
  readonly generateId?: () => string;
  readonly nowMs?: () => number;
  readonly freshnessMs?: number;
}

export async function issueOrRefreshApprovalChallenge(
  operationId: string,
  deps: IssueChallengeDeps,
): Promise<IssueChallengeOutcome> {
  const op = await deps.loadOperation(operationId);
  if (op === null) return { outcome: "REJECTED", reason: "operation_not_found" };
  if (op.status !== "CREATED") return { outcome: "REJECTED", reason: "operation_not_created" };

  const now = deps.nowMs?.() ?? Date.now();
  const freshness = deps.freshnessMs ?? APPROVAL_CHALLENGE_FRESHNESS_MS;
  const generateId = deps.generateId ?? randomUUID;

  const existing = await deps.challengeStore.findIssuedByOperation(operationId);

  const nonce = generateId();
  const issuedAt = toCanonicalTimestamp(now);
  const expiresAt = toCanonicalTimestamp(now + freshness);

  let preimage;
  try {
    preimage = buildApprovalPreimage({
      nodeId: op.nodeId,
      operationId: op.operationId,
      sourceWalletId: op.sourceWalletId,
      sourcePubkey: op.sourcePubkey,
      destinationAddress: op.destinationAddress,
      amountZkz: op.amountZkz,
      referencesOperationId: op.referencesOperationId,
      nonce,
      issuedAt,
      expiresAt,
    });
  } catch {
    return { outcome: "REJECTED", reason: "request_invalid" };
  }

  const challenge: ApprovalChallenge = {
    id: generateId(),
    nodeId: op.nodeId,
    operationId: op.operationId,
    status: "ISSUED",
    purpose: APPROVAL_PURPOSE,
    canonicalVersion: APPROVAL_CANONICAL_VERSION,
    nonce,
    preimageText: preimage.preimageText,
    preimageSha256: preimage.preimageSha256,
    issuedAt,
    expiresAt,
    supersededBy: null,
  };

  try {
    await deps.challengeStore.insertIssued(challenge, existing?.id ?? null);
  } catch (err) {
    if (err instanceof ApprovalStoreUniqueViolation) {
      const winner = await deps.challengeStore.findIssuedByOperation(operationId);
      if (winner !== null) {
        return {
          outcome: "ISSUED",
          challenge: winner,
          rowVersion: op.rowVersion,
          response: toChallengeResponse(winner, op),
        };
      }
      return { outcome: "REJECTED", reason: "operation_conflict" };
    }
    throw err;
  }

  return {
    outcome: "ISSUED",
    challenge,
    rowVersion: op.rowVersion,
    response: toChallengeResponse(challenge, op),
  };
}

export interface ApproveRequest {
  readonly operationId: string;
  readonly challengeNonce: string;
  readonly expectedRowVersion: number;
  readonly preimageSha256: string;
  readonly deviceKeyId: string | null;
  readonly deviceSignature: string | null;
  readonly totpCode: string;
  /**
   * Approving admin_operators.id (session user). Required when dual-control
   * policy is two_human; ignored in single_operator mode.
   */
  readonly approverOperatorId?: string | null;
}

export interface ApproveDeps {
  readonly challengeStore: ApprovalChallengeStore;
  readonly loadOperation: (operationId: string) => Promise<ApprovalOperationSnapshot | null>;
  readonly deviceStore: DeviceKeyStore;
  readonly totpConfig: ApprovalTotpConfig;
  /**
   * Global single-use (node_id, timestep) registry shared with enrol confirm and
   * runGuardedAdminMutation money paths. Claimed on match, before approval CAS —
   * burn-on-fail (destination binding); a later CAS miss does not restore the step.
   */
  readonly totpBurnStore: TotpBurnStore;
  readonly requireDeviceSignature: boolean;
  readonly generateId?: () => string;
  readonly nowMs?: () => number;
  /**
   * Dual-control policy. When omitted, single_operator (no distinctness check).
   */
  readonly dualControlMode?: DualControlMode;
  /**
   * Issuer of the current ISSUED challenge. When omitted and mode is two_human,
   * approve fails closed.
   */
  readonly challengeIssuerStore?: ApprovalChallengeIssuerStore;
}

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const PADDED_SIG_RE = /^[A-Za-z0-9_-]{86}==$/;
const TOTP_CODE_RE = /^\d{6}$/;

function decodePaddedBase64Url(value: string): Uint8Array | null {
  try {
    const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

export async function approveExternalSend(
  request: ApproveRequest,
  deps: ApproveDeps,
): Promise<ApproveOutcome> {
  // step 2: parse and validate the whole request before inspecting a TOTP
  if (!Number.isInteger(request.expectedRowVersion) || request.expectedRowVersion < 1) {
    return { outcome: "REJECTED", reason: "request_invalid" };
  }
  if (!SHA256_HEX_RE.test(request.preimageSha256)) {
    return { outcome: "REJECTED", reason: "request_invalid" };
  }
  if (typeof request.challengeNonce !== "string" || request.challengeNonce.length === 0) {
    return { outcome: "REJECTED", reason: "request_invalid" };
  }
  try {
    parseUuid(request.challengeNonce);
    parseUuid(request.operationId);
  } catch {
    return { outcome: "REJECTED", reason: "request_invalid" };
  }
  if (!TOTP_CODE_RE.test(request.totpCode)) {
    return { outcome: "REJECTED", reason: "request_invalid" };
  }

  const hasDeviceId = request.deviceKeyId !== null;
  const hasDeviceSig = request.deviceSignature !== null;
  if (hasDeviceId !== hasDeviceSig) {
    return { outcome: "REJECTED", reason: "request_invalid" };
  }
  if (deps.requireDeviceSignature) {
    if (!hasDeviceId || !hasDeviceSig) {
      return { outcome: "REJECTED", reason: "device_required" };
    }
  } else if (hasDeviceId || hasDeviceSig) {
    return { outcome: "REJECTED", reason: "device_forbidden" };
  }
  if (hasDeviceId) {
    try {
      parseUuid(request.deviceKeyId!);
    } catch {
      return { outcome: "REJECTED", reason: "request_invalid" };
    }
    if (!PADDED_SIG_RE.test(request.deviceSignature!)) {
      return { outcome: "REJECTED", reason: "request_invalid" };
    }
  }

  const now = deps.nowMs?.() ?? Date.now();
  const generateId = deps.generateId ?? randomUUID;

  // step 3: lock the operation and approval nonce rows
  const op = await deps.loadOperation(request.operationId);
  if (op === null) return { outcome: "REJECTED", reason: "operation_not_found" };
  if (op.status !== "CREATED") return { outcome: "REJECTED", reason: "operation_not_created" };
  if (op.rowVersion !== request.expectedRowVersion) {
    return { outcome: "REJECTED", reason: "row_version_mismatch" };
  }

  const challenge = await deps.challengeStore.findByNonce(request.challengeNonce);
  if (challenge === null) return { outcome: "REJECTED", reason: "challenge_not_found" };
  if (challenge.operationId !== op.operationId || challenge.nodeId !== op.nodeId) {
    return { outcome: "REJECTED", reason: "challenge_not_found" };
  }
  if (challenge.status !== "ISSUED") {
    return { outcome: "REJECTED", reason: "challenge_not_issued" };
  }
  if (now >= Date.parse(challenge.expiresAt)) {
    return { outcome: "REJECTED", reason: "challenge_expired" };
  }

  // steps 4–5: rebuild exact tuple from locked operation; compare digest
  let rebuilt;
  try {
    rebuilt = buildApprovalPreimage({
      nodeId: op.nodeId,
      operationId: op.operationId,
      sourceWalletId: op.sourceWalletId,
      sourcePubkey: op.sourcePubkey,
      destinationAddress: op.destinationAddress,
      amountZkz: op.amountZkz,
      referencesOperationId: op.referencesOperationId,
      nonce: challenge.nonce,
      issuedAt: challenge.issuedAt,
      expiresAt: challenge.expiresAt,
    });
  } catch {
    return { outcome: "REJECTED", reason: "request_invalid" };
  }

  if (
    rebuilt.preimageSha256 !== challenge.preimageSha256 ||
    rebuilt.preimageText !== challenge.preimageText ||
    rebuilt.preimageSha256 !== request.preimageSha256
  ) {
    return { outcome: "REJECTED", reason: "preimage_mismatch" };
  }

  // Two-human dual control — distinct admin_operator on challenge vs approve.
  {
    const mode = deps.dualControlMode ?? "single_operator";
    if (mode === "two_human") {
      const issuer =
        deps.challengeIssuerStore !== undefined
          ? await deps.challengeIssuerStore.findIssuer(request.operationId)
          : null;
      const check = enforceDualControlOperators(
        mode,
        issuer,
        request.approverOperatorId ?? "",
      );
      if (!check.ok) {
        return { outcome: "REJECTED", reason: "same_operator_both_sides" };
      }
    }
  }

  let method: ApprovalMethod = "TOTP_ONLY";
  let deviceKey: EnrolledDeviceKey | null = null;
  if (hasDeviceId) {
    method = "TOTP_AND_DEVICE";
    deviceKey = deps.deviceStore.findById(request.deviceKeyId!);
    if (deviceKey === null || deviceKey.nodeId !== op.nodeId) {
      return { outcome: "REJECTED", reason: "device_unknown" };
    }
    if (deviceKey.revokedAt !== null) {
      return { outcome: "REJECTED", reason: "device_revoked" };
    }
    const active = deps.deviceStore.findActiveByNodeAndPublicKey(op.nodeId, deviceKey.publicKey);
    if (active === null) {
      return { outcome: "REJECTED", reason: "device_revoked" };
    }
    const sigBytes = decodePaddedBase64Url(request.deviceSignature!);
    const pubBytes = decodePaddedBase64Url(deviceKey.publicKey);
    if (sigBytes === null || pubBytes === null || pubBytes.length !== 32 || sigBytes.length !== 64) {
      return { outcome: "REJECTED", reason: "device_signature_invalid" };
    }
    const valid = verifyDetachedEd25519({
      publicKeyBytes: pubBytes,
      preimageText: challenge.preimageText,
      signatureBytes: sigBytes,
    });
    if (!valid) {
      return { outcome: "REJECTED", reason: "device_signature_invalid" };
    }
  }

  // step 6: match TOTP then claim global burn registry (shared with enrol confirm).
  // operation_approvals unique remains the per-approve durable arbiter inside the CAS.
  const totpMatch = matchTotp(deps.totpConfig, { code: request.totpCode, nowMs: now });
  if (!totpMatch.ok) {
    return { outcome: "REJECTED", reason: "totp_invalid" };
  }
  try {
    const claimed = await deps.totpBurnStore.claim(op.nodeId, totpMatch.timestep);
    if (!claimed) {
      return { outcome: "REJECTED", reason: "totp_replay" };
    }
  } catch {
    // Store down → fail closed (opaque factor failure at the HTTP adapter).
    return { outcome: "REJECTED", reason: "totp_invalid" };
  }

  const consumedAt = toCanonicalTimestamp(now);
  const approval: OperationApproval = {
    id: generateId(),
    nodeId: op.nodeId,
    operationId: op.operationId,
    challengeId: challenge.id,
    challengeStatus: "CONSUMED",
    method,
    purpose: APPROVAL_PURPOSE,
    canonicalVersion: APPROVAL_CANONICAL_VERSION,
    preimageText: challenge.preimageText,
    preimageSha256: challenge.preimageSha256,
    deviceKeyId: deviceKey?.id ?? null,
    deviceSignature: hasDeviceSig ? request.deviceSignature : null,
    totpTimestep: totpMatch.timestep,
    consumedAt,
  };

  // steps 6–7: one atomic unit — claim timestep + consume + insert + CREATED→APPROVED.
  // On any non-APPLIED result the store rolls back (no orphan approval, challenge ISSUED,
  // timestep unburned). Step 8 burn-no-restore applies only after APPLIED returns.
  const mutation = await deps.challengeStore.commitApprovalMutation(
    challenge.id,
    approval,
    request.expectedRowVersion,
  );
  if (mutation.kind === "TOTP_REPLAY") {
    return { outcome: "REJECTED", reason: "totp_replay" };
  }
  if (mutation.kind === "CHALLENGE_NOT_ISSUED") {
    return { outcome: "REJECTED", reason: "challenge_not_issued" };
  }
  if (mutation.kind === "APPROVAL_EXISTS") {
    return { outcome: "REJECTED", reason: "approval_exists" };
  }
  if (mutation.kind === "OPERATION_CONFLICT") {
    return { outcome: "REJECTED", reason: "operation_conflict" };
  }

  return {
    outcome: "APPROVED",
    approval,
    rowVersion: mutation.rowVersion,
    response: {
      operation_id: op.operationId,
      status: "APPROVED",
      row_version: mutation.rowVersion,
      approval_id: approval.id,
      method,
      consumed_at: consumedAt,
    },
  };
}

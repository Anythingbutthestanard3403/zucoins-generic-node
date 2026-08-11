// operator_session(_totp[_device]) admin dispatcher for the eight frozen admin
// routes under /admin/v1/*. Session+CSRF via gateMoneyMutation; TOTP-required mutations
// via runGuardedAdminMutation or approveExternalSend (shared TotpBurnStore claim).
// Inventory GETs (wallets, operations ledger, destinations mirror, audit)
// ride the same session gate; not frozen into ROUTE_POLICIES (SPA extension; login/me peers).
//
// Lives in apps/generic-node so http/ never imports send/ or device/ (boundary graph).

import {
  ApproveBody,
  BlessBody,
  RecoveryActionsBody,
  RejectBody,
  TotpConsumptionLog,
  approveExternalSend,
  buildDeviceEnrol,
  CredentialError,
  CredentialService,
  disengageHalt,
  engageHalt,
  executeAttentionRetraction,
  executeOperatorPark,
  gateMoneyMutation,
  handleAdminChangePassword,
  handleAdminConfirmTotp,
  handleAdminEnrolTotp,
  handleAdminLogin,
  handleAdminLogout,
  handleAdminMe,
  handleGetRecovery,
  handleNeedsAttention,
  handleRecoveryAction,
  NeedsAttentionQuerySchema,
  IMPLEMENTER_SCOPES,
  issueEnrollmentChallenge,
  issueOrRefreshApprovalChallenge,
  NoopDeviceRevocationSideEffects,
  rejectSendOperation,
  resolveOperatorTotpConfig,
  revokeDevice,
  runGuardedAdminMutation,
  verifyAndEnrolGenesisDevice,
  type AdminAuthAudit,
  type AdminSessionService,
  type AdminUserStore,
  type ApprovalChallengeStore,
  type ApprovalOperationSnapshot,
  type AttentionRetractionStore,
  type OperatorParkStore,
  type AuthRequest,
  type AuthHttpResult,
  type BreakGlassAuthorityStore,
  type CreateCredentialResult,
  type CsrfConfig,
  type DestinationService,
  type DeviceRevocationAuditLog,
  type DeviceRevocationSideEffects,
  InMemoryEnrollmentAuditLog,
  InMemoryDeviceRevocationAuditLog,
  type EnrollmentAuditLog,
  type EnrollmentChallengeStore,
  type HaltEvidenceRecorder,
  type HaltGate,
  type HaltStore,
  type ImplementerScope,
  type OperatorHaltStore,
  type RecoveryActionAuthContext,
  type RecoveryActionStore,
  type RecoveryInspectionStore,
  type SendDecisionStore,
  type StoredCredential,
  type TotpBurnStore,
  type TotpConfig,
  ipForDb,
  resolveClientIp,
  trustProxyOptionsFromEnv,
  consumeLoginAttempt,
  LOGIN_RATE_WINDOW_MS,
  extractSessionIdFromCookie,
  requireSessionCsrf,
  // Second-device enrol, dual-control policy, operator push
  APPROVAL_FACTOR_FAILURE_HTTP_STATUS,
  APPROVAL_POLICY_DENIAL_CODE,
  APPROVAL_FACTOR_FAILURE_CODE,
  DUAL_CONTROL_COPY,
  DEVICE_SIGNATURE_POLICY_COPY,
  combineDeviceSignatureRequirement,
  issueSecondDeviceCeremony,
  bindSecondDevicePublicKey,
  authorizeSecondDeviceEnrol,
  completeSecondDeviceEnrol,
  peekSecondDeviceCeremony,
  assertSafeSecondDeviceQr,
  buildOperatorPushPayload,
  assertOperatorPushPayloadSafe,
  isValidOperatorPushP256dh,
  isValidOperatorPushAuth,
  operatorPushEndpointFingerprint,
  notifyOperatorsPendingAttention,
  noopOperatorPushSender,
  type DualControlMode,
  type DualControlPolicyPort,
  type DeviceSignaturePolicyMode,
  type DeviceSignaturePolicyPort,
  type ApprovalChallengeIssuerStore,
  type SecondDeviceCeremonyStore,
  type OperatorPushSubscriptionStore,
  type OperatorPushSubscription,
  type OperatorPushSender,
} from "@zucoins/node-core";

import {
  createEmptyAdminInventoryStore,
  isAuditActorKind,
  isDestinationState,
  isOperationKind,
  isWalletKeyOrigin,
  isWalletState,
  type AdminInventoryStore,
} from "./admin-inventory/index.js";
import {
  buildEffectiveConfig,
  serializeEffectiveConfig,
  type BuildEffectiveConfigInput,
  type EffectiveConfigDto,
} from "./config/effective-config.js";
import {
  type AdminIdempotencyFingerprint,
  type AdminIdempotencyStore,
  sha256HexUtf8 as adminIdempotencySha256,
} from "./ops/admin-idempotency.js";
import {
  checkAdminIdempotency,
  RECOVERY_CEREMONY_START_BODY_FINGERPRINT,
  structuralBodyFingerprint,
} from "./ops/admin-idempotency-guard.js";

/** Structural body fingerprint — create body carries passcode; never hash it. */
const RECOVERY_PACK_CREATE_BODY_FINGERPRINT = structuralBodyFingerprint(
  "admin_recovery_pack_create",
);
/** Prove body carries pack bytes + passcode — structural sentinel only. */
const RECOVERY_PACK_PROVE_BODY_FINGERPRINT = structuralBodyFingerprint(
  "admin_recovery_pack_prove",
);
import type {
  AtomicAdminMutationAction,
  AtomicAdminMutationInput,
  AtomicAdminMutationResult,
} from "./ops/atomic-admin-mutation.js";
// type-only import (erased by tsc): keeps admin-router free of a value edge
// into the reporting ceremony while typing the injected service. See the reach census.
import type {
  ReportingCredentialIssueResult,
  ReportingCredentialRecoverResult,
  ReportingCredentialService,
  ReportingKeyListing,
} from "./reporting-credential-service.js";
import {
  buildReadinessChecklist,
  type ReadinessSignals,
} from "./admin-readiness.js";
import {
  assertLabPayloadSecretFree,
  runLabReceive,
  type LabReceivePorts,
} from "./lab-receive.js";
import {
  buildAdminErrorBody,
  buildAdminLabReceiveErrorBody,
  coerceAdminErrorCode,
  type AdminErrorCode,
} from "@zucoins/generic-node-contracts/admin-auth-errors";
import {
  ceremonyJobToWire,
  getCeremonyJob,
  getLatestCeremonyJob,
  isCeremonyRunning,
  isCeremonyUserLocked,
  registerCeremonyAttempt,
  startCeremonyJob,
  MIN_MASTER_KEY_CHARS,
  type CeremonyJobSnapshot,
} from "./ops/admin-recovery-ceremony.js";
import {
  createMemoryRecoveryPackLockoutStore,
  clearProveFailures,
  isProveLocked,
  recordProveFailure,
  type RecoveryPackLockoutStore,
} from "./ops/recovery-pack-lockout.js";
import {
  createRecoveryPack,
  isAcceptableRecoverySecretShape,
  openRecoveryPack,
  peekPackContentSha256,
  reissueRecoveryPack,
  RecoveryPackError,
  RECOVERY_PACK_FORMAT,
  RECOVERY_PACK_SECRET_MAX_CHARS,
} from "./ops/recovery-pack.js";
import { createMemorySetupStateStore, type SetupStateStore } from "./setup-state-store.js";
import {
  applyDurableSealInPlace,
  durableSealFromBootstrap,
  type VaultMasterSealStore,
} from "./setup-vault-master-seal-store.js";
import {
  acknowledgeOfflineBackup,
  createVirginVaultMasterState,
  generateShowOnce,
  refuseSecondReveal,
  statusFromState,
  vaultReadyForSetup,
  VaultMasterError,
  type VaultMasterBootstrapState,
} from "./setup-vault-master.js";
import {
  applyPwaInstalledEvidence,
  applySetupPatch,
  applyTypedDeviceBreakGlass,
  assertSetupSecretFree,
  buildSetupStateView,
  DEVICE_BREAK_GLASS_PHRASE,
  isAllowBrowserTabSetup,
  isDeviceBreakGlassActive,
  isSetupAckWizardLegacyEnabled,
  mirrorDeviceEnrolledFlag,
  SetupPatchError,
  type SetupLiveSignals,
} from "./setup-wizard.js";


// Structural device-key surface used by list/enrol/revoke + approve dual-control.
// Production wires SqlDeviceKeyStore; tests use InMemoryDeviceKeyStore.
type DeviceKeyStoreLike = {
  readonly findById: (id: string) => { readonly id: string; readonly nodeId: string; readonly publicKey: string; readonly label: string; readonly enrolledAt: string; readonly revokedAt: string | null } | null;
  readonly listActiveByNode?: (nodeId: string) => readonly {
    readonly id: string;
    readonly label: string;
    readonly enrolledAt: string;
    readonly publicKey?: string;
    readonly revokedAt?: string | null;
  }[];
  readonly insert?: (deviceKey: {
    readonly id: string;
    readonly nodeId: string;
    readonly publicKey: string;
    readonly label: string;
    readonly enrolledAt: string;
    readonly revokedAt: string | null;
  }) => void;
  readonly revoke?: (id: string, revokedAt: string) => void;
  readonly findActiveByNodeAndPublicKey?: (
    nodeId: string,
    publicKey: string,
  ) => { readonly id: string; readonly publicKey: string; readonly revokedAt: string | null } | null;
  readonly findByNodeAndPublicKey?: (
    nodeId: string,
    publicKey: string,
  ) => { readonly id: string; readonly publicKey: string; readonly revokedAt: string | null } | null;
  readonly insertDurable?: (deviceKey: {
    readonly id: string;
    readonly nodeId: string;
    readonly publicKey: string;
    readonly label: string;
    readonly enrolledAt: string;
    readonly revokedAt: string | null;
  }) => Promise<void>;
  readonly revokeDurable?: (id: string, revokedAt: string) => Promise<void>;
  readonly refreshNode?: (nodeId: string) => Promise<void>;
};

// Local body parse (zod is not an apps/generic-node production dependency).
type ParseOk<T> = { readonly ok: true; readonly body: T };
type ParseFail = {
  readonly ok: false;
  readonly status: 400;
  readonly code: string;
  readonly message: string;
};

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function parseApproveBody(raw: unknown): ParseOk<ReturnType<typeof ApproveBody.parse>> | ParseFail {
  const r = ApproveBody.safeParse(raw);
  if (!r.success) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "request body failed validation" };
  }
  return { ok: true, body: r.data };
}

function parseRejectBody(raw: unknown): ParseOk<ReturnType<typeof RejectBody.parse>> | ParseFail {
  const r = RejectBody.safeParse(raw);
  if (!r.success) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "request body failed validation" };
  }
  return { ok: true, body: r.data };
}

function parseRecoveryBody(
  raw: unknown,
): ParseOk<ReturnType<typeof RecoveryActionsBody.parse>> | ParseFail {
  const r = RecoveryActionsBody.safeParse(raw);
  if (!r.success) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "request body failed validation" };
  }
  return { ok: true, body: r.data };
}

function parseGenesisEnrolBody(
  raw: unknown,
): ParseOk<{
  label: string;
  new_device_key_id: string;
  new_device_public_key: string;
  new_device_pop_signature: string;
  challenge_nonce: string;
}> | ParseFail {
  if (!isRecord(raw)) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "body required" };
  }
  const label = raw.label;
  const new_device_key_id = raw.new_device_key_id;
  const new_device_public_key = raw.new_device_public_key;
  const new_device_pop_signature = raw.new_device_pop_signature;
  const challenge_nonce = raw.challenge_nonce;
  if (
    typeof label !== "string" ||
    typeof new_device_key_id !== "string" ||
    typeof new_device_public_key !== "string" ||
    typeof new_device_pop_signature !== "string" ||
    typeof challenge_nonce !== "string" ||
    label.length === 0 ||
    new_device_key_id.length === 0 ||
    new_device_public_key.length === 0 ||
    new_device_pop_signature.length === 0 ||
    challenge_nonce.length === 0
  ) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "genesis enrol fields required" };
  }
  return {
    ok: true,
    body: {
      label,
      new_device_key_id,
      new_device_public_key,
      new_device_pop_signature,
      challenge_nonce,
    },
  };
}

function parseDeviceRevokeBody(
  raw: unknown,
): ParseOk<{
  authorizing_device_key_id: string;
  authorizing_device_signature: string;
}> | ParseFail {
  if (!isRecord(raw)) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "body required" };
  }
  const authorizing_device_key_id = raw.authorizing_device_key_id;
  const authorizing_device_signature = raw.authorizing_device_signature;
  if (
    typeof authorizing_device_key_id !== "string" ||
    typeof authorizing_device_signature !== "string" ||
    authorizing_device_key_id.length === 0 ||
    authorizing_device_signature.length === 0
  ) {
    return {
      ok: false,
      status: 400,
      code: "invalid_scalar",
      message: "authorizing_device_key_id and authorizing_device_signature required",
    };
  }
  return {
    ok: true,
    body: { authorizing_device_key_id, authorizing_device_signature },
  };
}

function parseBlessBody(raw: unknown): ParseOk<ReturnType<typeof BlessBody.parse>> | ParseFail {
  const r = BlessBody.safeParse(raw);
  if (!r.success) {
    const issue = r.error.issues[0];
    const code = issue?.code === "unrecognized_keys" ? "unknown_field" : "invalid_scalar";
    return {
      ok: false,
      status: 400,
      code,
      message: code === "unknown_field" ? "unknown field" : "request body failed validation",
    };
  }
  return { ok: true, body: r.data };
}

function parseRetireBody(raw: unknown): ParseOk<Record<string, never>> | ParseFail {
  if (raw === undefined || raw === null) return { ok: true, body: {} };
  if (!isRecord(raw) || Object.keys(raw).length > 0) {
    return { ok: false, status: 400, code: "unknown_field", message: "empty body required" };
  }
  return { ok: true, body: {} };
}

// POST /admin/v1/operations/:operation_id/attention-retraction body.
// {reason: string, expected_row_version: number, superseded_by?: string}
function parseAttentionRetractionBody(
  raw: unknown,
): ParseOk<{ reason: string; expected_row_version: number; superseded_by: string | null }> | ParseFail {
  if (!isRecord(raw)) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "body required" };
  }
  if (typeof raw.reason !== "string" || raw.reason.length === 0) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "reason non-empty string required" };
  }
  if (raw.reason.length > 2000) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "reason max 2000 chars" };
  }
  if (typeof raw.expected_row_version !== "number" || !Number.isInteger(raw.expected_row_version)) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "expected_row_version integer required" };
  }
  let supersededBy: string | null = null;
  if (raw.superseded_by !== undefined && raw.superseded_by !== null) {
    if (typeof raw.superseded_by !== "string" || raw.superseded_by.length === 0) {
      return { ok: false, status: 400, code: "invalid_scalar", message: "superseded_by must be a non-empty string" };
    }
    if (raw.superseded_by.length > 200) {
      return { ok: false, status: 400, code: "invalid_scalar", message: "superseded_by max 200 chars" };
    }
    supersededBy = raw.superseded_by;
  }
  const known = new Set(["reason", "expected_row_version", "superseded_by"]);
  for (const key of Object.keys(raw)) {
    if (!known.has(key)) {
      return { ok: false, status: 400, code: "unknown_field", message: `unknown field: ${key}` };
    }
  }
  return {
    ok: true,
    body: { reason: raw.reason, expected_row_version: raw.expected_row_version, superseded_by: supersededBy },
  };
}

// POST /admin/v1/operations/:operation_id/operator-park body (ZTR-1147).
// {note: string, expected_row_version: number}
function parseOperatorParkBody(
  raw: unknown,
): ParseOk<{ note: string; expected_row_version: number }> | ParseFail {
  if (!isRecord(raw)) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "body required" };
  }
  if (typeof raw.note !== "string" || raw.note.trim().length === 0) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "note non-empty string required" };
  }
  if (raw.note.length > 2000) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "note max 2000 chars" };
  }
  if (typeof raw.expected_row_version !== "number" || !Number.isInteger(raw.expected_row_version)) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "expected_row_version integer required" };
  }
  const known = new Set(["note", "expected_row_version"]);
  for (const key of Object.keys(raw)) {
    if (!known.has(key)) {
      return { ok: false, status: 400, code: "unknown_field", message: `unknown field: ${key}` };
    }
  }
  return {
    ok: true,
    body: { note: raw.note.trim(), expected_row_version: raw.expected_row_version },
  };
}


function parseHaltBody(
  raw: unknown,
): ParseOk<{ engaged: boolean; reason: string | null }> | ParseFail {
  if (!isRecord(raw)) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "body required" };
  }
  if (typeof raw.engaged !== "boolean") {
    return { ok: false, status: 400, code: "invalid_scalar", message: "engaged boolean required" };
  }
  let reason: string | null = null;
  if (raw.reason !== undefined && raw.reason !== null) {
    if (typeof raw.reason !== "string") {
      return { ok: false, status: 400, code: "invalid_scalar", message: "reason must be string" };
    }
    if (raw.reason.length > 500) {
      return { ok: false, status: 400, code: "invalid_scalar", message: "reason max 500 chars" };
    }
    reason = raw.reason;
  }
  const known = new Set(["engaged", "reason"]);
  for (const key of Object.keys(raw)) {
    if (!known.has(key)) {
      return { ok: false, status: 400, code: "unknown_field", message: `unknown field: ${key}` };
    }
  }
  return { ok: true, body: { engaged: raw.engaged, reason } };
}

function parseDeviceSignaturePolicyBody(
  raw: unknown,
): ParseOk<{ mode: DeviceSignaturePolicyMode }> | ParseFail {
  if (!isRecord(raw)) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "body required" };
  }
  if (raw.mode !== "required" && raw.mode !== "optional") {
    return {
      ok: false,
      status: 400,
      code: "invalid_scalar",
      message: "mode must be required or optional",
    };
  }
  const known = new Set(["mode"]);
  for (const key of Object.keys(raw)) {
    if (!known.has(key)) {
      return { ok: false, status: 400, code: "unknown_field", message: `unknown field: ${key}` };
    }
  }
  return { ok: true, body: { mode: raw.mode } };
}

function parseDualControlPolicyBody(
  raw: unknown,
): ParseOk<{ mode: DualControlMode }> | ParseFail {
  if (!isRecord(raw)) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "body required" };
  }
  if (raw.mode !== "single_operator" && raw.mode !== "two_human") {
    return {
      ok: false,
      status: 400,
      code: "invalid_scalar",
      message: "mode must be single_operator or two_human",
    };
  }
  const known = new Set(["mode"]);
  for (const key of Object.keys(raw)) {
    if (!known.has(key)) {
      return { ok: false, status: 400, code: "unknown_field", message: `unknown field: ${key}` };
    }
  }
  return { ok: true, body: { mode: raw.mode } };
}

const KNOWN_SCOPES = new Set<string>(IMPLEMENTER_SCOPES);

// Review rework: validate a path `:id` is a canonical lowercase UUID BEFORE the TOTP
// is burned. A non-UUID reaching the store after the guarded mutation 500s AND consumes
// the operator's valid code — validate the fully decoded request first.
const LOWER_UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * POST /admin/v1/api-keys body. Scopes default to the full implementer scope set
 * (parity with the genesis bootstrap credential) and must be a non-empty subset of
 * the closed IMPLEMENTER_SCOPES vocabulary. An explicit empty array is rejected.
 */
function parseIssueApiKeyBody(
  raw: unknown,
): ParseOk<{ readonly scopes: readonly ImplementerScope[] }> | ParseFail {
  if (!isRecord(raw)) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "body required" };
  }
  let scopesRaw: readonly unknown[] | undefined;
  if (raw.scopes !== undefined && raw.scopes !== null) {
    if (!Array.isArray(raw.scopes)) {
      return { ok: false, status: 400, code: "invalid_scalar", message: "scopes must be an array" };
    }
    scopesRaw = raw.scopes;
  }
  let scopes: ImplementerScope[];
  if (scopesRaw === undefined) {
    scopes = [...IMPLEMENTER_SCOPES];
  } else {
    if (scopesRaw.length === 0) {
      return { ok: false, status: 400, code: "invalid_scalar", message: "scopes must be non-empty" };
    }
    scopes = [];
    for (const s of scopesRaw) {
      if (typeof s !== "string" || !KNOWN_SCOPES.has(s)) {
        return { ok: false, status: 400, code: "invalid_scalar", message: `unknown scope: ${String(s)}` };
      }
      scopes.push(s as ImplementerScope);
    }
    scopes = [...new Set(scopes)];
  }
  const known = new Set(["scopes"]);
  for (const key of Object.keys(raw)) {
    if (!known.has(key)) {
      return { ok: false, status: 400, code: "unknown_field", message: `unknown field: ${key}` };
    }
  }
  return { ok: true, body: { scopes } };
}

function parseRevokeApiKeyBody(
  raw: unknown,
): ParseOk<Record<string, never>> | ParseFail {
  if (!isRecord(raw)) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "body required" };
  }
  for (const key of Object.keys(raw)) {
    return { ok: false, status: 400, code: "unknown_field", message: `unknown field: ${key}` };
  }
  return { ok: true, body: {} };
}

/** List projection — never the raw key or the hash. last_used_at is null (no schema column). */
function toApiKeyListing(row: StoredCredential): {
  readonly id: string;
  readonly prefix: string;
  readonly scopes: readonly ImplementerScope[];
  readonly status: string;
  readonly key_version: number;
  readonly issued_at: string;
  readonly expires_at: string | null;
  readonly revoked_at: string | null;
  readonly last_used_at: null;
} {
  return {
    id: row.id,
    prefix: row.public_prefix,
    scopes: row.scopes,
    status: row.status,
    key_version: row.key_version,
    issued_at: row.issued_at,
    expires_at: row.expires_at,
    revoked_at: row.revoked_at,
    last_used_at: null,
  };
}

/** Issue response — the full secret is returned exactly once, never persisted, never logged. */
function toApiKeyIssueResult(created: CreateCredentialResult): {
  readonly id: string;
  readonly raw_key: string;
  readonly prefix: string;
  readonly scopes: readonly ImplementerScope[];
  readonly key_version: number;
  readonly issued_at: string;
  readonly expires_at: string | null;
} {
  return {
    id: created.credential_id,
    raw_key: created.raw_key,
    prefix: created.public_prefix,
    scopes: created.scopes,
    key_version: created.key_version,
    issued_at: created.issued_at,
    expires_at: created.expires_at,
  };
}

// POST /admin/v1/reporting-keys body — the node mints the keypair, so the
// request carries no fields (parity with the empty-body revoke). An explicit unknown field
// is rejected rather than ignored.
function parseIssueReportingKeyBody(
  raw: unknown,
): ParseOk<Record<string, never>> | ParseFail {
  if (raw === undefined || raw === null) return { ok: true, body: {} };
  if (!isRecord(raw) || Object.keys(raw).length > 0) {
    return { ok: false, status: 400, code: "unknown_field", message: "empty body required" };
  }
  return { ok: true, body: {} };
}

/** List projection — the public identity allowlist plus derived status; no private half. */
function toReportingKeyListing(row: ReportingKeyListing): {
  readonly id: string;
  readonly node_id: string;
  readonly implementer_id: string;
  readonly public_key: string;
  readonly registered_at: string;
  readonly status: string;
} {
  return {
    id: row.id,
    node_id: row.node_id,
    implementer_id: row.implementer_id,
    public_key: row.public_key,
    registered_at: row.registered_at,
    status: row.status,
  };
}

/** Issue response — the raw private seed is returned exactly once, never persisted, never logged. */
function toReportingKeyIssueResult(issued: ReportingCredentialIssueResult): {
  readonly id: string;
  readonly key_id: string;
  readonly public_key: string;
  readonly raw_private_key: string;
  readonly registered_at: string;
} {
  return {
    id: issued.id,
    key_id: issued.key_id,
    public_key: issued.public_key,
    raw_private_key: issued.raw_private_key,
    registered_at: issued.registered_at,
  };
}

function toReportingKeyRecoverResult(issued: ReportingCredentialRecoverResult): ReportingCredentialRecoverResult {
  return {
    object: "reporting_key_recovered",
    id: issued.id,
    key_id: issued.key_id,
    public_key: issued.public_key,
    raw_private_key: issued.raw_private_key,
    registered_at: issued.registered_at,
    superseded_key_id: issued.superseded_key_id,
    implementer_id: issued.implementer_id,
    implementer_raw_key: issued.implementer_raw_key,
    implementer_key_prefix: issued.implementer_key_prefix,
  };
}

/** POST /admin/v1/reporting-keys/recover-lost body. */
function parseRecoverLostReportingKeyBody(
  raw: unknown,
): ParseOk<{ lost_key_id: string }> | ParseFail {
  if (!isRecord(raw)) {
    return { ok: false, status: 400, code: "validation_error", message: "body must be a JSON object" };
  }
  const keys = Object.keys(raw);
  if (keys.length !== 1 || keys[0] !== "lost_key_id") {
    return {
      ok: false,
      status: 400,
      code: "unknown_field",
      message: "body must be exactly { lost_key_id }",
    };
  }
  const id = raw.lost_key_id;
  if (typeof id !== "string" || !LOWER_UUID_RE.test(id)) {
    return {
      ok: false,
      status: 400,
      code: "validation_error",
      message: "lost_key_id must be a canonical uuid",
    };
  }
  return { ok: true, body: { lost_key_id: id } };
}

function haltWire(
  engaged: boolean,
  display: {
    readonly reason: string | null;
    readonly updatedAt: string | null;
    readonly updatedBy: string | null;
  },
): {
  engaged: boolean;
  reason: string | null;
  updated_at: string | null;
  updated_by: string | null;
} {
  return {
    engaged,
    reason: display.reason,
    updated_at: display.updatedAt,
    updated_by: display.updatedBy,
  };
}

/**
 * POST /admin/v1/recovery-ceremony/start body (Mode A).
 * Master key ONLY in this body — never query/headers. Unknown fields rejected.
 * Body is validated before TOTP burn.
 */
/**
 * POST /admin/v1/recovery-pack/create body.
 * Generate-only seal (ZTR-1220 r6): callers must NOT supply `recovery_secret`.
 * The node draws a CSPRNG Crockford×26 secret, seals the pack, and returns the
 * secret once on the live response (stripped from the durable idempotency row).
 * Master source is one of: `vault_master_key`, pending show-once plaintext, or a
 * `from_pack` re-issue (`from_pack` + `from_pack_secret`, which never exposes the
 * master). `from_pack_secret` is the *existing* pack open secret, not the seal key.
 */
function parseRecoveryPackCreateBody(
  raw: unknown,
): ParseOk<{
  readonly vault_master_key?: string;
  readonly from_pack?: string;
  readonly from_pack_secret?: string;
  readonly allow_legacy_v1?: boolean;
}> | ParseFail {
  if (!isRecord(raw)) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "body required" };
  }
  const known = new Set([
    "recovery_secret",
    "vault_master_key",
    "from_pack",
    "from_pack_secret",
    "allow_legacy_v1",
  ]);
  for (const key of Object.keys(raw)) {
    if (!known.has(key)) {
      return { ok: false, status: 400, code: "unknown_field", message: `unknown field: ${key}` };
    }
  }
  // Generate-only: any caller-supplied recovery_secret is refused (weak or strong).
  if (raw.recovery_secret !== undefined && raw.recovery_secret !== null) {
    return {
      ok: false,
      status: 400,
      code: "caller_supplied_recovery_secret",
      message:
        "recovery_secret must not be supplied — create is generate-only; the node seals under a CSPRNG secret and returns it once",
    };
  }
  let master: string | undefined;
  if (raw.vault_master_key !== undefined && raw.vault_master_key !== null) {
    if (typeof raw.vault_master_key !== "string" || raw.vault_master_key.length < MIN_MASTER_KEY_CHARS) {
      return {
        ok: false,
        status: 400,
        code: "invalid_scalar",
        message: `vault_master_key must be at least ${MIN_MASTER_KEY_CHARS} characters when provided`,
      };
    }
    master = raw.vault_master_key;
  }
  let fromPack: string | undefined;
  let fromPackSecret: string | undefined;
  if (raw.from_pack !== undefined && raw.from_pack !== null) {
    if (typeof raw.from_pack !== "string" || raw.from_pack.length === 0) {
      return { ok: false, status: 400, code: "invalid_scalar", message: "from_pack must be the pack file JSON" };
    }
    // Bound upload size (~256 KiB) — pack is small JSON.
    if (raw.from_pack.length > 256 * 1024) {
      return { ok: false, status: 400, code: "invalid_scalar", message: "from_pack too large" };
    }
    if (typeof raw.from_pack_secret !== "string" || !isAcceptableRecoverySecretShape(raw.from_pack_secret)) {
      return {
        ok: false,
        status: 400,
        code: "invalid_scalar",
        message: "from_pack_secret required with from_pack",
      };
    }
    fromPack = raw.from_pack;
    fromPackSecret = raw.from_pack_secret;
  } else if (raw.from_pack_secret !== undefined) {
    return {
      ok: false,
      status: 400,
      code: "invalid_scalar",
      message: "from_pack_secret requires from_pack",
    };
  }
  if (master !== undefined && fromPack !== undefined) {
    return {
      ok: false,
      status: 400,
      code: "invalid_scalar",
      message: "supply vault_master_key or from_pack, not both",
    };
  }
  if (raw.allow_legacy_v1 !== undefined && typeof raw.allow_legacy_v1 !== "boolean") {
    return { ok: false, status: 400, code: "invalid_scalar", message: "allow_legacy_v1 must be a boolean" };
  }
  return {
    ok: true,
    body: {
      ...(master === undefined ? {} : { vault_master_key: master }),
      ...(fromPack === undefined ? {} : { from_pack: fromPack, from_pack_secret: fromPackSecret }),
      ...(raw.allow_legacy_v1 === true ? { allow_legacy_v1: true } : {}),
    },
  };
}

/**
 * POST /admin/v1/recovery-pack/prove body.
 * pack_file: UTF-8 JSON string of the download envelope (or base64 of those bytes).
 * pack_file_b64: optional alternate encoding.
 */
function parseRecoveryPackProveBody(
  raw: unknown,
): ParseOk<{
  readonly recovery_secret: string;
  readonly packFileUtf8: string;
  readonly allow_legacy_v1: boolean;
}> | ParseFail {
  if (!isRecord(raw)) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "body required" };
  }
  const known = new Set(["recovery_secret", "pack_file", "pack_file_b64", "allow_legacy_v1"]);
  for (const key of Object.keys(raw)) {
    if (!known.has(key)) {
      return { ok: false, status: 400, code: "unknown_field", message: `unknown field: ${key}` };
    }
  }
  // No entropy floor on the open path — a legacy v1 pack legitimately carries a
  // digit passcode, and refusing to open it would strand the operator holding one.
  const secret = raw.recovery_secret;
  if (typeof secret !== "string" || !isAcceptableRecoverySecretShape(secret)) {
    return {
      ok: false,
      status: 400,
      code: "invalid_scalar",
      message: `recovery_secret must be 1–${RECOVERY_PACK_SECRET_MAX_CHARS} characters`,
    };
  }
  if (raw.allow_legacy_v1 !== undefined && typeof raw.allow_legacy_v1 !== "boolean") {
    return { ok: false, status: 400, code: "invalid_scalar", message: "allow_legacy_v1 must be a boolean" };
  }
  let packFileUtf8: string | null = null;
  if (typeof raw.pack_file === "string" && raw.pack_file.length > 0) {
    packFileUtf8 = raw.pack_file;
  } else if (typeof raw.pack_file_b64 === "string" && raw.pack_file_b64.length > 0) {
    try {
      packFileUtf8 = Buffer.from(raw.pack_file_b64, "base64").toString("utf8");
    } catch {
      return {
        ok: false,
        status: 400,
        code: "invalid_scalar",
        message: "pack_file_b64 is not valid base64",
      };
    }
  }
  if (packFileUtf8 === null || packFileUtf8.length === 0) {
    return {
      ok: false,
      status: 400,
      code: "invalid_scalar",
      message: "pack_file or pack_file_b64 required",
    };
  }
  // Bound upload size (~256 KiB) — pack is small JSON.
  if (packFileUtf8.length > 256 * 1024) {
    return {
      ok: false,
      status: 400,
      code: "invalid_scalar",
      message: "pack file too large",
    };
  }
  return {
    ok: true,
    body: { recovery_secret: secret, packFileUtf8, allow_legacy_v1: raw.allow_legacy_v1 === true },
  };
}

function parseCeremonyStartBody(
  raw: unknown,
): ParseOk<{
  readonly vault_master_key: string;
  readonly archive_epoch_master_key?: string;
}> | ParseFail {
  if (!isRecord(raw)) {
    return { ok: false, status: 400, code: "invalid_scalar", message: "body required" };
  }
  const known = new Set(["vault_master_key", "archive_epoch_master_key"]);
  for (const key of Object.keys(raw)) {
    if (!known.has(key)) {
      return { ok: false, status: 400, code: "unknown_field", message: `unknown field: ${key}` };
    }
  }
  const mk = raw.vault_master_key;
  if (typeof mk !== "string" || mk.length === 0) {
    return {
      ok: false,
      status: 400,
      code: "invalid_scalar",
      message: "vault_master_key string required",
    };
  }
  if (mk.length < MIN_MASTER_KEY_CHARS) {
    return {
      ok: false,
      status: 400,
      code: "invalid_scalar",
      message: `vault_master_key must be at least ${MIN_MASTER_KEY_CHARS} characters`,
    };
  }
  let archive: string | undefined;
  if (raw.archive_epoch_master_key !== undefined && raw.archive_epoch_master_key !== null) {
    if (typeof raw.archive_epoch_master_key !== "string") {
      return {
        ok: false,
        status: 400,
        code: "invalid_scalar",
        message: "archive_epoch_master_key must be string",
      };
    }
    if (raw.archive_epoch_master_key.length < MIN_MASTER_KEY_CHARS) {
      return {
        ok: false,
        status: 400,
        code: "invalid_scalar",
        message: `archive_epoch_master_key must be at least ${MIN_MASTER_KEY_CHARS} characters`,
      };
    }
    archive = raw.archive_epoch_master_key;
  }
  return {
    ok: true,
    body:
      archive === undefined
        ? { vault_master_key: mk }
        : { vault_master_key: mk, archive_epoch_master_key: archive },
  };
}

export interface AdminRouteDeps {
  readonly sessions: AdminSessionService;
  readonly userStore: AdminUserStore;
  readonly csrf: CsrfConfig;
  /**
   * Lab process-level TOTP only (ADMIN_TOTP_LAB_MODE). Per-operator enrol
   * secrets take precedence via userStore.
   */
  readonly totp: TotpConfig;
  readonly totpLog: TotpBurnStore;
  readonly nodeId: string;
  readonly challengeStore: ApprovalChallengeStore;
  readonly loadOperation: (operationId: string) => Promise<ApprovalOperationSnapshot | null>;
  readonly sendDecisionStore: SendDecisionStore;
  readonly deviceStore: DeviceKeyStoreLike | null;
  /** Node-origin enrollment challenges for device enrol (A.4.3). */
  readonly deviceEnrollmentChallengeStore?: EnrollmentChallengeStore | null;
  readonly deviceEnrollmentAuditLog?: EnrollmentAuditLog | null;
  readonly deviceRevocationAuditLog?: DeviceRevocationAuditLog | null;
  readonly deviceRevocationSideEffects?: DeviceRevocationSideEffects | null;
  readonly breakGlassStore?: BreakGlassAuthorityStore | null;
  /**
   * Dual-control policy. When omitted on money approve / challenge / GET,
   * fail closed to two_human (never silently single_operator — ZTR-1214 D2).
   */
  readonly dualControlPolicy?: DualControlPolicyPort;
  /**
   * Additive device-signature policy for external-send approval (doc 07 §17.10).
   * When omitted, approvals fail closed and require a device signature.
   */
  readonly deviceSignaturePolicy?: DeviceSignaturePolicyPort;
  /** Records which admin_operator issued the approval challenge (two_human). */
  readonly challengeIssuerStore?: ApprovalChallengeIssuerStore;
  /** Second-device QR enrolment. When omitted, enrol routes 503. */
  readonly secondDeviceEnrol?: {
    readonly enrollmentChallengeStore: EnrollmentChallengeStore;
    readonly ceremonyStore: SecondDeviceCeremonyStore;
    readonly auditLog: EnrollmentAuditLog;
    readonly nodeOrigin: string;
  };
  /** Optional operator Web Push. Separate from wallet push_subscriptions. */
  readonly operatorPush?: {
    readonly store: OperatorPushSubscriptionStore;
    readonly sender?: OperatorPushSender;
    /**
     * Seal push subscription auth at rest. Required for usable delivery when a
     * sender is later configured. When omitted, subscribe fails closed (503).
     */
    readonly sealAuth: (authPlaintext: string) => string;
    /**
     * VAPID application-server public key (URL-safe base64) for browser
     * PushManager.subscribe. When null/omitted, Enable is unavailable in the SPA.
     */
    readonly vapidPublicKey?: string | null;
  };
  readonly recoveryStore: RecoveryInspectionStore;
  readonly recoveryActionStore: RecoveryActionStore;
  /** Audited attention-flag retraction. Omitted routes fail closed (503). */
  readonly attentionRetractionStore?: AttentionRetractionStore;
  readonly operatorParkStore?: OperatorParkStore;
  readonly destinationService: DestinationService;
  /** Inventory reads; empty when omitted. */
  readonly inventoryStore?: AdminInventoryStore;
  readonly newRequestId: () => string;
  readonly nowMs?: () => number;
  /** Optional audit sink — never receives TOTP secrets. */
  readonly audit?: AdminAuthAudit;
  /**
   * Operator halt — live gate + durable store + evidence trail.
   * When omitted, GET/POST /admin/v1/halt fail closed (503).
   */
  readonly halt?: {
    readonly gate: HaltGate;
    readonly store: OperatorHaltStore | HaltStore;
    readonly evidence: HaltEvidenceRecorder;
    /** Called after a successful engage/disengage so readiness/metrics stay in sync. */
    readonly onToggle?: (engaged: boolean) => void;
  };
  /**
   * Implementer API key management — issue/list/revoke over the
   * CredentialService bound to the custody pool. When omitted (tests), the
   * /admin/v1/api-keys routes fail closed (503). The implementer id is the
   * single non-retired row the genesis bootstrap seeded; resolved per-call so
   * a reseed after retirement is honoured without a restart.
   */
  readonly credentialService?: CredentialService;
  readonly resolveImplementerId?: () => Promise<string | null>;
  /**
   * REQUIRED admin-mutation idempotency. Routes check for a completed row before
   * the TOTP burn; the shared executor commits child effects and exact response bytes together.
   * Missing production wiring fails closed with idempotency_unavailable.
   */
  readonly adminIdempotencyStore?: AdminIdempotencyStore;
  readonly atomicAdminMutation?: <TAbort>(
    input: AtomicAdminMutationInput,
    action: AtomicAdminMutationAction<AdminMutationTxPorts, TAbort>,
  ) => Promise<AtomicAdminMutationResult<TAbort>>;
  /**
   * Reporting credential management — issue/list over the custody pool. When
   * omitted (tests), GET/POST /admin/v1/reporting-keys fail closed (503). Issue node-mints
   * the credential and returns the raw private seed once; list is public-only.
   */
  readonly reportingCredentialService?: ReportingCredentialService;
  /**
   * Optional probes for GET /admin/v1/readiness (Home checklist).
   * Each field is secret-free; missing fields surface as status "unknown".
   */
  readonly readinessProbe?: {
    readonly nodeStatus?: () =>
      | Promise<"ready" | "degraded" | "not_ready" | null>
      | "ready"
      | "degraded"
      | "not_ready"
      | null;
    readonly breakGlassActive?: () => Promise<boolean | null> | boolean | null;
    readonly backupStatus?: () => {
      readonly enabled: boolean;
      readonly ownership?: "owner" | "standby" | "disabled";
      readonly rpoBreached: boolean;
      readonly lastSuccessAt: string | null;
      readonly consecutiveFailures: number;
    } | null;
  };
  /**
   * Secret-safe effective config for GET /admin/v1/settings.
   * When omitted the route fails closed (503) — never invents identity.
   */
  readonly effectiveConfig?: BuildEffectiveConfigInput | (() => BuildEffectiveConfigInput);
  /**
   * Lab receive — capped create+ARM. When omitted, POST /admin/v1/lab/receive
   * fails closed (503). Never bypasses readiness gates.
   */
  readonly labReceive?: Pick<LabReceivePorts, "operationStore" | "reportingHandle" | "readyWaitMs" | "readyPollMs">;
  /**
   * Mode A in-process recovery ceremony. When omitted,
   * POST/GET recovery-ceremony routes fail closed (503). Master key never
   * reaches this dep's type surface — only the runner closure holds it.
   */
  readonly recoveryCeremonyRunner?: {
    readonly databaseUrl: string;
    readonly liveSql: import("pg").Pool;
  };
  /**
   * Recovery pack prove lockout store. When omitted, process-local
   * in-memory counters (tests / single-process). Production wires SQL.
   */
  readonly recoveryPackLockoutStore?: RecoveryPackLockoutStore;
  /**
   * Optional audit sink for pack create/prove digests only (pack_content_sha256,
   * operator id, timestamp). Never passcode / master / key fingerprint.
   */
  readonly recoveryPackAudit?: (event: {
    readonly kind: "pack_create" | "pack_prove_ok" | "pack_prove_fail";
    readonly operator_id: string;
    readonly pack_content_sha256: string | null;
    readonly at: string;
    readonly verified_wallet_count?: number;
    readonly recovery_verification_id?: string | null;
    /** Digest of the pack a re-issue replaced — the destruction trail for v1 artifacts. */
    readonly previous_pack_content_sha256?: string;
    /** Sealed payload version that was opened (1 = superseded digit-passcode pack). */
    readonly pack_version?: 1 | 2;
  }) => void | Promise<void>;
  /**
   * Durable operator setup wizard flags. When omitted, in-memory store.
   * Secret-free JSON only.
   */
  readonly setupStateStore?: SetupStateStore;
  /**
   * Vault master bootstrap singleton (show-once). When omitted, virgin
   * in-memory state — generate still works but does not survive restart.
   */
  readonly vaultMasterBootstrap?: VaultMasterBootstrapState;
  /**
   * Durable vault master seal store (fingerprint + phase only — never raw key).
   * When omitted, seal is process-local.
   */
  readonly vaultMasterSealStore?: VaultMasterSealStore;
  /**
   * BACKUP_MASTER_KEY / KEK for ≠ check against vault master. Never returned in
   * API responses. Distinct from the vault master.
   */
  readonly backupMasterKey?: string | null;
  /**
   * Optional live signals for the setup wizard (device enrolled, recovery count,
   * reporting key, receive pack). Secret-free only.
   */
  readonly setupSignals?: () =>
    | Promise<Partial<SetupLiveSignals>>
    | Partial<SetupLiveSignals>;
}

export interface AdminMutationTxPorts {
  readonly challengeStore: ApprovalChallengeStore;
  readonly loadOperation: (operationId: string) => Promise<ApprovalOperationSnapshot | null>;
  readonly sendDecisionStore: SendDecisionStore;
  readonly destinationService: DestinationService;
  readonly halt?: AdminRouteDeps["halt"];
  readonly credentialService: CredentialService;
  /**
   * TX-scoped device-signature policy (ZTR-1143). Mutation writes MUST use this
   * port so node_settings + audit_log commit/roll back with the admin mutation TX.
   * Approve-path reads may still use deps.deviceSignaturePolicy (fail-closed).
   */
  readonly deviceSignaturePolicy?: DeviceSignaturePolicyPort;
  /**
   * TX-scoped dual-control policy (ZTR-1214). Mutation writes MUST use this port
   * so node_settings + audit_log commit/roll back with the admin mutation TX.
   * GET/approve reads may still use deps.dualControlPolicy.
   */
  readonly dualControlPolicy?: DualControlPolicyPort;
}

export interface AdminRouterResponse {
  readonly status: number;
  readonly body: string;
  readonly headers: Record<string, string>;
}

export type AdminRouter = (
  method: string,
  rawPath: string,
  rawBody: Uint8Array,
  headers: Record<string, string | undefined>,
  /** Socket peer address, supplied by the transport. Never client-settable. */
  remoteAddress?: string | null,
) => Promise<AdminRouterResponse>;

const JSON_HEADERS: Record<string, string> = {
  "content-type": "application/json; charset=utf-8",
};

function fail(
  status: number,
  code: string,
  message: string,
  requestId: string,
  extraHeaders: Record<string, string> = {},
): AdminRouterResponse {
  // ZTR-1196: canonical admin envelope (details: {}) + frozen ADMIN_ERROR_CODES.
  // extraHeaders forward auth-handler headers (e.g. retry-after on 429); JSON content-type wins.
  const frozen: AdminErrorCode = coerceAdminErrorCode(code);
  return {
    status,
    body: buildAdminErrorBody(frozen, message, requestId),
    headers: { ...JSON_HEADERS, ...extraHeaders, ...JSON_HEADERS },
  };
}

function ok(
  status: number,
  body: unknown,
  extraHeaders: Record<string, string> = {},
): AdminRouterResponse {
  return {
    status,
    body: typeof body === "string" ? body : JSON.stringify(body),
    headers: { ...JSON_HEADERS, ...extraHeaders },
  };
}

function buildAuthRequest(
  headers: Record<string, string | undefined>,
  method: string,
  path: string,
): AuthRequest {
  return {
    method,
    path,
    headers: {
      ...headers,
      cookie: headers["cookie"] ?? "",
    },
  };
}

function decodeBody(rawBody: Uint8Array): unknown {
  if (rawBody.byteLength === 0) return {};
  return JSON.parse(Buffer.from(rawBody).toString("utf8"));
}

function authFail(
  gate: Extract<Awaited<ReturnType<typeof gateMoneyMutation>>, { ok: false }>,
  requestId: string,
): AdminRouterResponse {
  const body = gate.result.body as { error?: { code?: string; message?: string } };
  return fail(
    gate.result.status,
    body.error?.code ?? "invalid_credentials",
    body.error?.message ?? "authentication required",
    requestId,
  );
}

function fromAuthResult(result: AuthHttpResult, requestId: string): AdminRouterResponse {
  // Auth handlers historically omitted request_id/details. Non-2xx bodies are
  // re-rendered through the admin envelope so every error matches the frozen schema.
  // Handler headers (retry-after, etc.) are merged; JSON content-type is forced via fail().
  if (result.status >= 400) {
    const body = result.body as { error?: { code?: string; message?: string } };
    return fail(
      result.status,
      body.error?.code ?? "internal_error",
      body.error?.message ?? "request failed",
      requestId,
      result.headers,
    );
  }
  return {
    status: result.status,
    body: JSON.stringify(result.body),
    headers: { ...result.headers },
  };
}

/**
 * The one call site every REQUIRED admin POST mutation routes through. Runs
 * strictly before TOTP/nonce burn (called before runGuardedAdminMutation / the money-mutation
 * gate). A missing/malformed key is 400; a completed row with a matching fingerprint short-
 * circuits as a replay; a mismatched fingerprint is a 409 conflict. On `ok: true` the caller
 * proceeds to the shared atomic child-effect + completed-response transaction.
 */
async function idempotencyGate(input: {
  readonly store: AdminIdempotencyStore | undefined;
  readonly nodeId: string;
  readonly routeId: string;
  readonly headers: Record<string, string | undefined>;
  readonly verb: string;
  readonly rawPath: string;
  readonly rawBody: Uint8Array;
  readonly requestId: string;
  /**
   * Override fingerprint body digest. Key-bearing routes MUST pass a structural
   * sentinel so the master-key body is never hashed into durable storage.
   */
  readonly bodySha256?: string;
}): Promise<
  | { readonly ok: true; readonly idemKey: string; readonly fingerprint: AdminIdempotencyFingerprint }
  | { readonly ok: false; readonly response: AdminRouterResponse }
> {
  if (input.store === undefined) {
    return {
      ok: false,
      response: fail(503, "idempotency_unavailable", "required idempotency store unavailable", input.requestId),
    };
  }
  const check = await checkAdminIdempotency({
    store: input.store,
    nodeId: input.nodeId,
    routeId: input.routeId,
    idemKeyHeader: input.headers["idempotency-key"],
    method: input.verb,
    rawTarget: input.rawPath,
    rawBody: input.rawBody,
    bodySha256: input.bodySha256,
  });
  if (check.outcome === "missing_key") {
    return {
      ok: false,
      response: fail(400, "invalid_idempotency_key", "Idempotency-Key (16-255 visible ASCII) required", input.requestId),
    };
  }
  if (check.outcome === "replay") {
    return {
      ok: false,
      response: {
        status: check.status,
        body: check.bodyBytes.toString("utf8"),
        headers: { ...JSON_HEADERS, "idempotency-replayed": "true" },
      },
    };
  }
  if (check.outcome === "conflict") {
    return {
      ok: false,
      response: fail(409, "idempotency_conflict", "Idempotency-Key reused with a different request", input.requestId),
    };
  }
  return { ok: true, idemKey: check.idemKey, fingerprint: check.fingerprint };
}

async function runRequiredAdminMutation(input: {
  readonly deps: AdminRouteDeps;
  readonly nodeId: string;
  readonly routeId: string;
  readonly idemKey: string;
  readonly fingerprint: AdminIdempotencyFingerprint;
  readonly requestId: string;
  readonly action: AtomicAdminMutationAction<AdminMutationTxPorts, AdminRouterResponse>;
}): Promise<AdminRouterResponse> {
  const executor = input.deps.atomicAdminMutation;
  if (executor === undefined) {
    return fail(503, "idempotency_unavailable", "required atomic idempotency transaction unavailable", input.requestId);
  }
  try {
    const result = await executor(
      {
        nodeId: input.nodeId,
        routeId: input.routeId,
        idempotencyKey: input.idemKey,
        fingerprint: input.fingerprint,
      },
      input.action,
    );
    if (result.outcome === "aborted") return result.response;
    if (result.outcome === "conflict") {
      return fail(409, "idempotency_conflict", "Idempotency-Key reused with a different request", input.requestId);
    }
    return {
      status: result.status,
      body: result.responseBytes.toString("utf8"),
      headers: {
        ...JSON_HEADERS,
        ...(result.outcome === "replay" ? { "idempotency-replayed": "true" } : {}),
      },
    };
  } catch {
    return fail(503, "idempotency_unavailable", "required atomic idempotency transaction failed", input.requestId);
  }
}

function parseQuery(rawPath: string): URLSearchParams {
  const qIndex = rawPath.indexOf("?");
  return new URLSearchParams(qIndex >= 0 ? rawPath.slice(qIndex + 1) : "");
}

function parseLimit(q: URLSearchParams): number | undefined {
  if (!q.has("limit")) return undefined;
  const n = Number(q.get("limit"));
  return Number.isFinite(n) ? n : undefined;
}

function parseBool(raw: string | null): boolean | undefined {
  if (raw === null || raw === "") return undefined;
  if (raw === "true" || raw === "1") return true;
  if (raw === "false" || raw === "0") return false;
  return undefined;
}

function labTotpOrNull(totp: TotpConfig): TotpConfig | null {
  // Zero-filled fail-closed placeholders must never authenticate.
  if (totp.secret.length < 16) return null;
  let nonzero = false;
  for (const b of totp.secret) {
    if (b !== 0) {
      nonzero = true;
      break;
    }
  }
  return nonzero ? totp : null;
}

/**
 * Client IP for admin lockout + session provenance on login / confirm-TOTP.
 *
 * Default (no TRUST_PROXY_HOPS): socket peer only — never X-Forwarded-For.
 * A client-settable header would let an attacker rotate the per-(IP, username)
 * lockout key per request. This is the ZTR-1192 login rule, applied to both
 * routes so they share one pair identity (ZTR-1210).
 *
 * Proxied deployments: set TRUST_PROXY_HOPS (non-empty). Then
 * trustProxyOptionsFromEnv + resolveClientIp peel the rightmost trusted hop
 * from X-Forwarded-For; socket peer remains the fallback (directExposure) so a
 * missing/short XFF still keys on the connecting peer rather than "unknown".
 */
export function resolveAdminLockoutIp(
  headers: Record<string, string | undefined>,
  remoteAddress: string | null | undefined,
  env: {
    readonly TRUST_PROXY_HOPS?: string;
    readonly TRUST_PROXY_DIRECT_EXPOSURE?: string;
  } = process.env,
): string | null {
  const rawHops = env.TRUST_PROXY_HOPS;
  const proxyTrustEnabled = typeof rawHops === "string" && rawHops.trim() !== "";
  if (!proxyTrustEnabled) {
    return ipForDb(remoteAddress ?? null);
  }
  const { trustedHops } = trustProxyOptionsFromEnv({
    TRUST_PROXY_HOPS: rawHops,
    TRUST_PROXY_DIRECT_EXPOSURE: env.TRUST_PROXY_DIRECT_EXPOSURE,
  });
  // Lockout always wants a stable identity: peel XFF when present, else socket.
  // TRUST_PROXY_DIRECT_EXPOSURE is accepted for parity with the net helper but
  // does not gate the socket fallback here — a lockout keyed on "unknown" for
  // every client behind a mis-set hop count is worse than collapsing onto the
  // proxy address (the same ceiling ZTR-1192 documented for unwired proxy).
  return ipForDb(
    resolveClientIp(headers["x-forwarded-for"] ?? null, {
      trustedHops,
      directExposure: true,
      socketPeer: remoteAddress ?? null,
    }),
  );
}

export function createAdminRouter(deps: AdminRouteDeps): AdminRouter {
  const sessions = deps.sessions;
  const csrf = deps.csrf;
  const totp = deps.totp;
  const totpLog = deps.totpLog;
  const nodeId = deps.nodeId;
  const inventory = deps.inventoryStore ?? createEmptyAdminInventoryStore();
  const newRequestId = deps.newRequestId;
  const nowMs = deps.nowMs ?? (() => Date.now());
  const setupStateStore = deps.setupStateStore ?? createMemorySetupStateStore();
  const vaultMasterBootstrap = deps.vaultMasterBootstrap ?? createVirginVaultMasterState();
  const vaultMasterSealStore = deps.vaultMasterSealStore;
  const backupMasterKey = deps.backupMasterKey ?? null;

  async function persistVaultSeal(): Promise<void> {
    if (!vaultMasterSealStore) return;
    const seal = durableSealFromBootstrap(vaultMasterBootstrap);
    if (!seal) return;
    await vaultMasterSealStore.save(nodeId, seal);
  }

  /** Once-per-process hydrate from durable seal before any vault/setup mutation. */
  let vaultSealHydrate: Promise<void> | null = null;
  async function ensureVaultSealHydrated(): Promise<void> {
    if (!vaultMasterSealStore) return;
    if (vaultSealHydrate === null) {
      vaultSealHydrate = (async () => {
        const seal = await vaultMasterSealStore.load(nodeId);
        if (seal) applyDurableSealInPlace(vaultMasterBootstrap, seal);
      })();
    }
    await vaultSealHydrate;
  }

  async function resolveSetupSignals(
    sessionUser: {
      readonly mustChangePassword: boolean;
      readonly mustEnrolTotp: boolean;
    },
    flagsForPwa?: { readonly pwa_installed_at: string | null },
  ): Promise<SetupLiveSignals> {
    const extra: Partial<SetupLiveSignals> = deps.setupSignals ? await deps.setupSignals() : {};

    // Server-derived device evidence — prefer live store over ack flags.
    let deviceEnrolled = extra.deviceEnrolled;
    if (deviceEnrolled === undefined) {
      const store = deps.deviceStore;
      if (store !== null && typeof store.listActiveByNode === "function") {
        try {
          if (typeof store.refreshNode === "function") {
            await store.refreshNode(nodeId);
          }
          deviceEnrolled = store.listActiveByNode(nodeId).length > 0;
        } catch {
          deviceEnrolled = undefined;
        }
      }
    }

    // Server-derived recovery-verified inventory.
    let recoveryVerifiedEligibleCount = extra.recoveryVerifiedEligibleCount;
    if (recoveryVerifiedEligibleCount === undefined) {
      try {
        const page = await inventory.listWallets(nodeId, {
          recovery_verified: true,
          key_origin: "node_generated",
          state: "AVAILABLE",
          limit: 50,
        });
        recoveryVerifiedEligibleCount = page.data.length;
      } catch {
        recoveryVerifiedEligibleCount = null;
      }
    }

    let reportingKeyActive = extra.reportingKeyActive;
    if (reportingKeyActive === undefined && deps.reportingCredentialService !== undefined) {
      try {
        const rows = await deps.reportingCredentialService.list();
        reportingKeyActive = rows.some((r) => String(r.status).toUpperCase() === "ACTIVE");
      } catch {
        reportingKeyActive = null;
      }
    }

    // Vault configured / sealed with offline ack is a live fact for complete.
    const vaultLiveReady = vaultReadyForSetup(vaultMasterBootstrap);
    const vaultConfigured =
      extra.vaultConfigured ??
      (vaultMasterBootstrap.phase === "configured" ||
        vaultMasterBootstrap.phase === "sealed" ||
        vaultLiveReady);

    const allowBrowserTab =
      extra.allowBrowserTabSetup === true || isAllowBrowserTabSetup();
    const durable =
      typeof flagsForPwa?.pwa_installed_at === "string" && flagsForPwa.pwa_installed_at.length > 0;
    return {
      mustChangePassword: sessionUser.mustChangePassword,
      mustEnrolTotp: sessionUser.mustEnrolTotp,
      deviceEnrolled,
      recoveryVerifiedEligibleCount,
      reportingKeyActive,
      vaultConfigured,
      receivePackEnabled: extra.receivePackEnabled,
      allowBrowserTabSetup: allowBrowserTab,
      // Never invent from w3_pwa_ack — durable column or lab bypass only.
      pwaInstalled: durable || extra.pwaInstalled === true || allowBrowserTab,
    };
  }

  /**
   * Setup-wizard gate: session + CSRF only. Must remain reachable while
   * mustChangePassword / mustEnrolTotp are still true (W0–W2).
   */
  async function gateSetupSession(
    authReqLocal: AuthRequest,
    verbLocal: string,
  ): Promise<
    | { readonly ok: true; readonly user: import("@zucoins/node-core").AdminUser }
    | { readonly ok: false; readonly response: AdminRouterResponse }
  > {
    const sessionId = extractSessionIdFromCookie(authReqLocal.headers["cookie"] ?? "");
    if (sessionId === null) {
      return {
        ok: false,
        response: fail(401, "invalid_credentials", "authentication required", newRequestId()),
      };
    }
    const validated = await sessions.validateSession(sessionId);
    if (!validated.ok) {
      return {
        ok: false,
        response: fail(401, "invalid_credentials", "authentication required", newRequestId()),
      };
    }
    if (verbLocal !== "GET" && verbLocal !== "HEAD" && verbLocal !== "OPTIONS") {
      const csrfCheck = requireSessionCsrf(validated.session, authReqLocal);
      if (!csrfCheck.ok) {
        return {
          ok: false,
          response: fail(401, "invalid_credentials", "authentication required", newRequestId()),
        };
      }
    }
    return { ok: true, user: validated.user };
  }

  return async (method, rawPath, rawBody, headers, remoteAddress) => {
    const verb = method.trim().toUpperCase();
    const pathname = (rawPath.split(/[?#]/, 1)[0] ?? rawPath).replace(/\/+$/u, "") || "/";
    const requestId = newRequestId();
    const authReq = buildAuthRequest(headers, verb, pathname);

    // Session bootstrap (not frozen in ROUTE_POLICIES — login is CSRF-exempt).
    if (verb === "POST" && pathname === "/admin/v1/login") {
      // Volume throttle sits HERE — one pre-decode chokepoint — so malformed JSON
      // bodies spend the same per-IP budget as well-formed ones (ZTR-1218). A second
      // limiter instance would violate ZTR-1201 AC5; handleAdminLogin must not
      // re-consume.
      // Rate-limit key remains socket-peer only (ZTR-1192 / ZTR-1201 / ZTR-1218 AC3);
      // lockout/session IP below uses resolveAdminLockoutIp (ZTR-1210) and may peel
      // XFF only when TRUST_PROXY_HOPS is set.
      const loginRateIp = ipForDb(remoteAddress ?? null);
      if (!consumeLoginAttempt(loginRateIp)) {
        return fail(429, "rate_limited", "too many login attempts", requestId, {
          "retry-after": String(LOGIN_RATE_WINDOW_MS / 1000),
        });
      }
      try {
        const body = decodeBody(rawBody) as { username?: string; password?: string };
        // Shared lockout IP (login + confirm-TOTP). Default = socket peer;
        // TRUST_PROXY_HOPS enables resolveClientIp — see resolveAdminLockoutIp.
        const result = await handleAdminLogin(
          {
            userStore: deps.userStore,
            sessions,
            ip: resolveAdminLockoutIp(headers, remoteAddress),
            userAgent: headers["user-agent"] ?? null,
          },
          { username: body.username ?? "", password: body.password ?? "" },
        );
        return fromAuthResult(result, requestId);
      } catch {
        return fail(400, "validation_error", "invalid login body", requestId);
      }
    }
    if (verb === "GET" && pathname === "/admin/v1/me") {
      try {
        return fromAuthResult(await handleAdminMe(sessions, authReq), requestId);
      } catch {
        return fail(503, "service_unavailable", "session lookup unavailable", requestId);
      }
    }
    if (verb === "POST" && pathname === "/admin/v1/logout") {
      try {
        return fromAuthResult(await handleAdminLogout(sessions, authReq), requestId);
      } catch {
        return fail(503, "service_unavailable", "logout unavailable", requestId);
      }
    }
    if (verb === "POST" && pathname === "/admin/v1/password") {
      try {
        const body = decodeBody(rawBody) as {
          current_password?: string;
          new_password?: string;
        };
        const result = await handleAdminChangePassword(
          { userStore: deps.userStore, sessions, csrf },
          authReq,
          {
            current_password: body.current_password ?? "",
            new_password: body.new_password ?? "",
          },
        );
        return fromAuthResult(result, requestId);
      } catch {
        return fail(400, "validation_error", "invalid password body", requestId);
      }
    }
    if (verb === "POST" && pathname === "/admin/v1/enrol-totp") {
      try {
        const body = decodeBody(rawBody) as { password?: string };
        const result = await handleAdminEnrolTotp(
          {
            userStore: deps.userStore,
            sessions,
            csrf,
            audit: deps.audit,
          },
          authReq,
          { password: body.password ?? "" },
        );
        return fromAuthResult(result, requestId);
      } catch {
        return fail(400, "validation_error", "invalid enrol body", requestId);
      }
    }
    if (verb === "POST" && pathname === "/admin/v1/confirm-totp") {
      try {
        const body = decodeBody(rawBody) as { totp?: string };
        const result = await handleAdminConfirmTotp(
          {
            userStore: deps.userStore,
            sessions,
            totpLog,
            nodeId,
            csrf,
            audit: deps.audit,
            ip: resolveAdminLockoutIp(headers, remoteAddress),
            userAgent: headers["user-agent"] ?? null,
            nowMs,
          },
          authReq,
          { totp: body.totp ?? "" },
        );
        return fromAuthResult(result, requestId);
      } catch {
        return fail(400, "validation_error", "invalid confirm body", requestId);
      }
    }

    {
      const m = pathname.match(/^\/admin\/v1\/external-sends\/([^/]+)\/approval-challenge$/);
      if (verb === "GET" && m) {
        const gate = await gateMoneyMutation(sessions, authReq, { userStore: deps.userStore, csrf, labTotp: labTotpOrNull(totp) });
        if (!gate.ok) return authFail(gate, requestId);
        try {
          const outcome = await issueOrRefreshApprovalChallenge(m[1]!, {
            challengeStore: deps.challengeStore,
            loadOperation: deps.loadOperation,
            nowMs,
          });
          if (outcome.outcome === "REJECTED") {
            return fail(404, "not_found", "operation not found or not in CREATED state", requestId);
          }
          // Record which admin_operator issued the challenge.
          if (deps.challengeIssuerStore !== undefined) {
            await deps.challengeIssuerStore.recordIssuer(
              m[1]!,
              outcome.challenge.id,
              gate.user.id,
            );
          }
          // Fail-soft operator push — never blocks challenge issue.
          if (deps.operatorPush !== undefined) {
            try {
              const payload = buildOperatorPushPayload({
                attentionType: "send_pending_approval",
                deepLinkPath: `/transfers/${m[1]!}`,
                summary: "Outgoing send needs approval",
                operationId: m[1]!,
              });
              await notifyOperatorsPendingAttention(
                {
                  store: deps.operatorPush.store,
                  sender: deps.operatorPush.sender ?? noopOperatorPushSender,
                  nodeId,
                },
                payload,
              );
            } catch {
              /* fail-soft: inbox remains authoritative */
            }
          }
          {
            // Missing port fails closed to two_human (peer device-sig → required).
            let mode: DualControlMode = "two_human";
            if (deps.dualControlPolicy !== undefined) {
              try {
                mode = await deps.dualControlPolicy.getMode();
              } catch {
                mode = "two_human";
              }
            }
            const copy = DUAL_CONTROL_COPY[mode];
            return ok(200, {
              ...outcome.response,
              dual_control: {
                mode,
                short: copy.short,
                approve_hint: copy.approve_hint,
                challenge_issuer_operator_id: gate.user.id,
              },
            });
          }
        } catch {
          return fail(503, "service_unavailable", "approval challenge unavailable", requestId);
        }
      }
    }

    if (verb === "GET" && pathname === "/admin/v1/operations/needs-attention") {
      const gate = await gateMoneyMutation(sessions, authReq, { userStore: deps.userStore, csrf, labTotp: labTotpOrNull(totp) });
      if (!gate.ok) return authFail(gate, requestId);
      // Wire the declared NeedsAttentionQuerySchema (route-schemas) before the store —
      // hand Number()/as-never bypass let NaN LIMIT reach Postgres as a 503 (ZTR-1198).
      const q = parseQuery(rawPath);
      const parsed = NeedsAttentionQuerySchema.safeParse(Object.fromEntries(q.entries()));
      if (!parsed.success) {
        const issue = parsed.error.issues[0];
        const code = issue?.code === "unrecognized_keys" ? "unknown_field" : "invalid_scalar";
        const message =
          code === "unknown_field"
            ? "The request contains an unrecognized field."
            : "A field value does not satisfy its canonical scalar constraint.";
        return fail(400, code, message, requestId);
      }
      try {
        const result = await handleNeedsAttention(deps.recoveryStore, parsed.data);
        return ok(200, result);
      } catch {
        return fail(503, "service_unavailable", "recovery inspection unavailable", requestId);
      }
    }

    {
      const m = pathname.match(/^\/admin\/v1\/operations\/([^/]+)\/recovery$/);
      if (verb === "GET" && m) {
        const gate = await gateMoneyMutation(sessions, authReq, { userStore: deps.userStore, csrf, labTotp: labTotpOrNull(totp) });
        if (!gate.ok) return authFail(gate, requestId);
        try {
          const outcome = await handleGetRecovery(deps.recoveryStore, m[1]!);
          if (outcome.status === "not_found") {
            return fail(404, "not_found", "operation not found", requestId);
          }
          return ok(200, outcome.body);
        } catch {
          return fail(503, "service_unavailable", "recovery detail unavailable", requestId);
        }
      }
    }

    // --- inventory GETs (session+CSRF via gateMoneyMutation; no TOTP on reads) ---

    if (verb === "GET" && pathname === "/admin/v1/wallets") {
      const gate = await gateMoneyMutation(sessions, authReq, { csrf, labTotp: labTotpOrNull(totp) });
      if (!gate.ok) return authFail(gate, requestId);
      const q = parseQuery(rawPath);
      const stateRaw = q.get("state");
      const originRaw = q.get("key_origin");
      if (stateRaw !== null && stateRaw !== "" && !isWalletState(stateRaw)) {
        return fail(400, "validation_error", "invalid state filter", requestId);
      }
      if (originRaw !== null && originRaw !== "" && !isWalletKeyOrigin(originRaw)) {
        return fail(400, "validation_error", "invalid key_origin filter", requestId);
      }
      const recoveryRaw = q.get("recovery_verified");
      const recoveryParsed =
        recoveryRaw === null || recoveryRaw === "" ? undefined : parseBool(recoveryRaw);
      if (recoveryRaw !== null && recoveryRaw !== "" && recoveryParsed === undefined) {
        return fail(400, "validation_error", "recovery_verified must be true or false", requestId);
      }
      try {
        const page = await inventory.listWallets(nodeId, {
          state: stateRaw && isWalletState(stateRaw) ? stateRaw : undefined,
          key_origin: originRaw && isWalletKeyOrigin(originRaw) ? originRaw : undefined,
          recovery_verified: recoveryParsed,
          limit: parseLimit(q),
          after: q.get("after") ?? q.get("starting_after") ?? undefined,
        });
        return ok(200, page);
      } catch {
        return fail(503, "service_unavailable", "wallet inventory unavailable", requestId);
      }
    }

    {
      const m = pathname.match(/^\/admin\/v1\/wallets\/([^/]+)$/);
      if (verb === "GET" && m) {
        const gate = await gateMoneyMutation(sessions, authReq, { csrf, labTotp: labTotpOrNull(totp) });
        if (!gate.ok) return authFail(gate, requestId);
        try {
          const wallet = await inventory.getWallet(nodeId, decodeURIComponent(m[1]!));
          if (wallet === null) {
            return fail(404, "not_found", "wallet not found", requestId);
          }
          return ok(200, wallet);
        } catch {
          return fail(503, "service_unavailable", "wallet detail unavailable", requestId);
        }
      }
    }

    if (verb === "GET" && pathname === "/admin/v1/operations") {
      const gate = await gateMoneyMutation(sessions, authReq, { csrf, labTotp: labTotpOrNull(totp) });
      if (!gate.ok) return authFail(gate, requestId);
      const q = parseQuery(rawPath);
      const kindRaw = q.get("kind") ?? q.get("operation_type");
      if (kindRaw !== null && kindRaw !== "" && !isOperationKind(kindRaw)) {
        return fail(400, "validation_error", "invalid kind filter", requestId);
      }
      const attentionRaw = q.get("attention_required");
      const attentionParsed =
        attentionRaw === null || attentionRaw === "" ? undefined : parseBool(attentionRaw);
      if (attentionRaw !== null && attentionRaw !== "" && attentionParsed === undefined) {
        return fail(400, "validation_error", "attention_required must be true or false", requestId);
      }
      try {
        const page = await inventory.listOperations(nodeId, {
          kind: kindRaw && isOperationKind(kindRaw) ? kindRaw : undefined,
          status: q.get("status") ?? undefined,
          attention_required: attentionParsed,
          limit: parseLimit(q),
          after: q.get("after") ?? q.get("starting_after") ?? undefined,
        });
        return ok(200, page);
      } catch {
        return fail(503, "service_unavailable", "operation inventory unavailable", requestId);
      }
    }

    {
      // Detail aggregate — must not steal /recovery or /recovery-actions or needs-attention.
      const m = pathname.match(/^\/admin\/v1\/operations\/([^/]+)$/);
      if (verb === "GET" && m && m[1] !== "needs-attention") {
        const gate = await gateMoneyMutation(sessions, authReq, { csrf, labTotp: labTotpOrNull(totp) });
        if (!gate.ok) return authFail(gate, requestId);
        try {
          const op = await inventory.getOperation(nodeId, decodeURIComponent(m[1]!));
          if (op === null) {
            return fail(404, "not_found", "operation not found", requestId);
          }
          return ok(200, op);
        } catch {
          return fail(503, "service_unavailable", "operation detail unavailable", requestId);
        }
      }
    }

    if (verb === "GET" && pathname === "/admin/v1/destinations") {
      const gate = await gateMoneyMutation(sessions, authReq, { csrf, labTotp: labTotpOrNull(totp) });
      if (!gate.ok) return authFail(gate, requestId);
      const q = parseQuery(rawPath);
      const stateRaw = q.get("state");
      if (stateRaw !== null && stateRaw !== "" && !isDestinationState(stateRaw)) {
        return fail(400, "validation_error", "invalid state filter", requestId);
      }
      try {
        const page = await inventory.listDestinations(nodeId, {
          state: stateRaw && isDestinationState(stateRaw) ? stateRaw : undefined,
          limit: parseLimit(q),
          after: q.get("after") ?? undefined,
        });
        return ok(200, page);
      } catch {
        return fail(503, "service_unavailable", "destination inventory unavailable", requestId);
      }
    }

    if (verb === "GET" && pathname === "/admin/v1/audit") {
      const gate = await gateMoneyMutation(sessions, authReq, { csrf, labTotp: labTotpOrNull(totp) });
      if (!gate.ok) return authFail(gate, requestId);
      const q = parseQuery(rawPath);
      const actorRaw = q.get("actor_kind");
      if (actorRaw !== null && actorRaw !== "" && !isAuditActorKind(actorRaw)) {
        return fail(400, "validation_error", "invalid actor_kind filter", requestId);
      }
      try {
        const page = await inventory.listAudit(nodeId, {
          actor_kind: actorRaw && isAuditActorKind(actorRaw) ? actorRaw : undefined,
          action: q.get("action") ?? undefined,
          // Id keyset — unified with wallets/ops (`after` ≡ `starting_after` ≡ next_cursor).
          after: q.get("after") ?? q.get("starting_after") ?? undefined,
          created_after: q.get("created_after") ?? undefined,
          created_before: q.get("created_before") ?? q.get("before") ?? undefined,
          limit: parseLimit(q),
        });
        return ok(200, page);
      } catch {
        return fail(503, "service_unavailable", "audit inventory unavailable", requestId);
      }
    }

    // GET /admin/v1/device-keys — active enrolled key metadata for
    // destination blessing / SPA Devices. Public keys never cross this seam.
    if (verb === "GET" && pathname === "/admin/v1/device-keys") {
      const gate = await gateMoneyMutation(sessions, authReq, {
        userStore: deps.userStore,
        csrf,
        labTotp: labTotpOrNull(totp),
      });
      if (!gate.ok) return authFail(gate, requestId);
      const store = deps.deviceStore;
      if (store === null || typeof store.listActiveByNode !== "function") {
        return fail(503, "service_unavailable", "device key inventory not wired", requestId);
      }
      try {
        if (typeof store.refreshNode === "function") {
          await store.refreshNode(nodeId);
        }
        const keys = store.listActiveByNode(nodeId).map((key) => ({
          id: key.id,
          label: key.label,
          enrolled_at: key.enrolledAt,
        }));
        return ok(200, { keys });
      } catch {
        return fail(503, "service_unavailable", "device key inventory unavailable", requestId);
      }
    }


    // --- Dual-control policy ---
    if (verb === "GET" && pathname === "/admin/v1/dual-control-policy") {
      const gate = await gateMoneyMutation(sessions, authReq, { userStore: deps.userStore, csrf, labTotp: labTotpOrNull(totp) });
      if (!gate.ok) return authFail(gate, requestId);
      // Fail closed when the port is absent or unreadable: surface two_human
      // (never single_operator — ZTR-1214 D2; peer device-sig GET → required).
      let mode: DualControlMode = "two_human";
      if (deps.dualControlPolicy !== undefined) {
        try {
          mode = await deps.dualControlPolicy.getMode();
        } catch {
          mode = "two_human";
        }
      }
      const copy = DUAL_CONTROL_COPY[mode];
      return ok(200, {
        mode,
        short: copy.short,
        long: copy.long,
        approve_hint: copy.approve_hint,
      });
    }

    // --- Additive device-signature policy (doc 07 §17.10 / ZTR-1143) ---
    if (verb === "GET" && pathname === "/admin/v1/device-signature-policy") {
      const gate = await gateMoneyMutation(sessions, authReq, {
        userStore: deps.userStore,
        csrf,
        labTotp: labTotpOrNull(totp),
      });
      if (!gate.ok) return authFail(gate, requestId);
      // Fail closed when the port is absent or unreadable: surface required.
      let mode: DeviceSignaturePolicyMode = "required";
      if (deps.deviceSignaturePolicy !== undefined) {
        try {
          mode = await deps.deviceSignaturePolicy.getMode();
        } catch {
          mode = "required";
        }
      }
      const copy = DEVICE_SIGNATURE_POLICY_COPY[mode];
      return ok(200, {
        mode,
        requires_device_signature: mode === "required",
        short: copy.short,
        long: copy.long,
        approve_hint: copy.approve_hint,
      });
    }

    // --- Second-device QR enrolment peek ---
    if (verb === "GET" && pathname.startsWith("/admin/v1/device-enrol/")) {
      const gate = await gateMoneyMutation(sessions, authReq, { userStore: deps.userStore, csrf, labTotp: labTotpOrNull(totp) });
      if (!gate.ok) return authFail(gate, requestId);
      if (deps.secondDeviceEnrol === undefined) {
        return fail(503, "service_unavailable", "second-device enrolment not wired", requestId);
      }
      const challengeId = pathname.slice("/admin/v1/device-enrol/".length).split("/")[0] ?? "";
      if (!challengeId) {
        return fail(400, "invalid_request", "challenge_id required", requestId);
      }
      const peek = peekSecondDeviceCeremony(
        deps.secondDeviceEnrol.ceremonyStore,
        challengeId,
        nowMs(),
      );
      if (peek === null) {
        return fail(404, "not_found", "enrolment challenge not found", requestId);
      }
      return ok(200, peek);
    }

    // --- Operator push subscription list ---
    if (verb === "GET" && pathname === "/admin/v1/operator-push/subscriptions") {
      const gate = await gateMoneyMutation(sessions, authReq, {
        userStore: deps.userStore,
        csrf,
        labTotp: labTotpOrNull(totp),
      });
      if (!gate.ok) return authFail(gate, requestId);
      if (deps.operatorPush === undefined) {
        return ok(200, {
          opt_in: false,
          wired: false,
          note: "Operator push is optional and separate from wallet receiver push. Inbox remains source of truth.",
          vapid_public_key: null,
          subscriptions: [],
        });
      }
      const subs = deps.operatorPush.store.listByOperator(nodeId, gate.user.id).map((s) => ({
        id: s.id,
        endpoint_fingerprint: operatorPushEndpointFingerprint(s.endpoint),
        created_at: s.createdAt,
        user_agent: s.userAgent,
      }));
      return ok(200, {
        opt_in: true,
        wired: true,
        note: "Operator push is optional and separate from wallet receiver push. Deny/skip still uses the manual inbox.",
        vapid_public_key: deps.operatorPush.vapidPublicKey ?? null,
        subscriptions: subs,
      });
    }

    // POST /admin/v1/device-keys/enrollment-challenge — issue node-origin
    // challenge for genesis (or subsequent) device enrol. Session+CSRF; no TOTP
    // on issue (consume path burns TOTP). 300s window.
    if (verb === "POST" && pathname === "/admin/v1/device-keys/enrollment-challenge") {
      const gate = await gateMoneyMutation(sessions, authReq, {
        userStore: deps.userStore,
        csrf,
        labTotp: labTotpOrNull(totp),
      });
      if (!gate.ok) return authFail(gate, requestId);
      const challengeStore = deps.deviceEnrollmentChallengeStore ?? null;
      if (challengeStore === null) {
        return fail(503, "service_unavailable", "device enrollment not wired", requestId);
      }
      try {
        if (
          "refreshNode" in challengeStore &&
          typeof (challengeStore as { refreshNode?: (n: string) => Promise<void> }).refreshNode === "function"
        ) {
          await (challengeStore as { refreshNode: (n: string) => Promise<void> }).refreshNode(nodeId);
        }
        // Capture prior ISSUED (if any) before issue mutates it to SUPERSEDED.
        const priorIssued = challengeStore.findIssuedByNode(nodeId);
        const issued = issueEnrollmentChallenge(challengeStore, {
          nodeId,
          nowMs: nowMs(),
        });
        if (!issued.ok) {
          return fail(400, "validation_error", issued.detail, requestId);
        }
        const ch = issued.challenge;
        const durable = challengeStore as {
          insertDurable?: (c: typeof ch) => Promise<void>;
          updateDurable?: (c: typeof ch) => Promise<void>;
        };
        if (typeof durable.insertDurable === "function") {
          await durable.insertDurable(ch);
        }
        if (priorIssued !== null && typeof durable.updateDurable === "function") {
          const superseded = challengeStore.findByNonce(priorIssued.nonce);
          if (superseded !== null) {
            await durable.updateDurable(superseded);
          }
        }
        return ok(200, {
          nonce: ch.nonce,
          issued_at: ch.issuedAt,
          expires_at: ch.expiresAt,
          purpose: "zp-device-enrol-v1",
          canonical_version: 1,
          node_id: nodeId,
        });
      } catch {
        return fail(503, "service_unavailable", "device enrollment challenge unavailable", requestId);
      }
    }

    // GET /admin/v1/api-keys — list implementer credentials (id/prefix/scopes/status;
    // never the raw key or hash). Session+CSRF; no TOTP on reads (parity with wallets/destinations).
    if (verb === "GET" && pathname === "/admin/v1/api-keys") {
      const gate = await gateMoneyMutation(sessions, authReq, {
        userStore: deps.userStore,
        csrf,
        labTotp: labTotpOrNull(totp),
      });
      if (!gate.ok) return authFail(gate, requestId);
      if (deps.credentialService === undefined || deps.resolveImplementerId === undefined) {
        return fail(503, "service_unavailable", "api key management not wired", requestId);
      }
      try {
        const implementerId = await deps.resolveImplementerId();
        if (implementerId === null) {
          return ok(200, { keys: [] });
        }
        const rows = await deps.credentialService.list(implementerId);
        return ok(200, { keys: rows.map(toApiKeyListing) });
      } catch {
        return fail(503, "service_unavailable", "api key list unavailable", requestId);
      }
    }

    // GET /admin/v1/reporting-keys — list reporting credentials (the public
    // identity allowlist + derived lifecycle status; never the private seed, which the node
    // does not persist). Session+CSRF; no TOTP on reads (parity with api-keys / wallets).
    if (verb === "GET" && pathname === "/admin/v1/reporting-keys") {
      const gate = await gateMoneyMutation(sessions, authReq, {
        userStore: deps.userStore,
        csrf,
        labTotp: labTotpOrNull(totp),
      });
      if (!gate.ok) return authFail(gate, requestId);
      if (deps.reportingCredentialService === undefined) {
        return fail(503, "service_unavailable", "reporting credential management not wired", requestId);
      }
      try {
        const rows = await deps.reportingCredentialService.list();
        return ok(200, { keys: rows.map(toReportingKeyListing) });
      } catch {
        return fail(503, "service_unavailable", "reporting credential inventory unavailable", requestId);
      }
    }

    // GET /admin/v1/readiness — secret-free Home checklist.
    // Session+CSRF like other inventory GETs; no TOTP on read.
    if (verb === "GET" && pathname === "/admin/v1/readiness") {
      const gate = await gateMoneyMutation(sessions, authReq, {
        csrf,
        labTotp: labTotpOrNull(totp),
      });
      if (!gate.ok) return authFail(gate, requestId);
      try {
        const signals = await collectReadinessSignals(deps, gate.user.id, nodeId, nowMs);
        const body = buildReadinessChecklist(signals, new Date(nowMs()).toISOString());
        return ok(200, body);
      } catch {
        return fail(503, "service_unavailable", "readiness checklist unavailable", requestId);
      }
    }

    // GET halt — live engagement is the gate; reason from durable display.
    if (verb === "GET" && pathname === "/admin/v1/halt") {
      const gate = await gateMoneyMutation(sessions, authReq, {
        userStore: deps.userStore,
        csrf,
        labTotp: labTotpOrNull(totp),
      });
      if (!gate.ok) return authFail(gate, requestId);
      if (deps.halt === undefined) {
        return fail(503, "service_unavailable", "operator halt not wired", requestId);
      }
      try {
        const display =
          "readDisplay" in deps.halt.store &&
          typeof (deps.halt.store as OperatorHaltStore).readDisplay === "function"
            ? await (deps.halt.store as OperatorHaltStore).readDisplay()
            : {
                engaged: deps.halt.gate.isHalted(),
                reason: null as string | null,
                updatedAt: null as string | null,
                updatedBy: null as string | null,
              };
        return ok(
          200,
          haltWire(deps.halt.gate.isHalted(), {
            reason: display.reason,
            updatedAt: display.updatedAt,
            updatedBy: display.updatedBy,
          }),
        );
      } catch {
        return fail(503, "service_unavailable", "operator halt unavailable", requestId);
      }
    }

    // GET /admin/v1/settings — secret-safe effective config.
    // Session+CSRF via gateMoneyMutation; no TOTP on reads. Explicit allowlist only.
    if (verb === "GET" && pathname === "/admin/v1/settings") {
      const gate = await gateMoneyMutation(sessions, authReq, { csrf, labTotp: labTotpOrNull(totp) });
      if (!gate.ok) return authFail(gate, requestId);
      if (deps.effectiveConfig === undefined) {
        return fail(503, "service_unavailable", "effective config not wired", requestId);
      }
      try {
        const input =
          typeof deps.effectiveConfig === "function"
            ? deps.effectiveConfig()
            : deps.effectiveConfig;
        const dto: EffectiveConfigDto = buildEffectiveConfig(input);
        return ok(200, serializeEffectiveConfig(dto));
      } catch {
        return fail(503, "service_unavailable", "effective config unavailable", requestId);
      }
    }

    // --- Mode A recovery ceremony status ---
    if (verb === "GET" && pathname === "/admin/v1/recovery-ceremony/status") {
      if (deps.recoveryCeremonyRunner === undefined) {
        return fail(503, "service_unavailable", "recovery ceremony not wired", requestId);
      }
      const gate = await gateMoneyMutation(sessions, authReq, {
        userStore: deps.userStore,
        csrf,
        labTotp: labTotpOrNull(totp),
      });
      if (!gate.ok) return authFail(gate, requestId);
      const q = parseQuery(rawPath);
      const id = q.get("ceremony_id");
      let job: CeremonyJobSnapshot | null = null;
      if (id !== null && id.length > 0) {
        job = getCeremonyJob(id);
      } else {
        job = getLatestCeremonyJob();
      }
      if (job === null) {
        return ok(200, {
          ceremony_id: null,
          status: "idle",
          stage: null,
          progress: [],
          summary: null,
          error: null,
          started_at: null,
          finished_at: null,
          in_flight: isCeremonyRunning(),
        });
      }
      return ok(200, { ...ceremonyJobToWire(job), in_flight: isCeremonyRunning() });
    }

    // mid-enrol). Secret-free setup_state only; vault generate returns key once.

    if (verb === "GET" && pathname === "/admin/v1/setup-state") {
      const gate = await gateSetupSession(authReq, verb);
      if (!gate.ok) return fail(401, "invalid_credentials", "authentication required", requestId);
      try {
        await ensureVaultSealHydrated();
        const user = gate.user;
        const flags = await setupStateStore.get(nodeId);
        const signals = await resolveSetupSignals(
          {
            mustChangePassword: user.mustChangePassword,
            mustEnrolTotp: user.mustEnrolTotp,
          },
          flags,
        );
        // Reflect vault bootstrap into W5 without storing the key.
        let merged = flags;
        if (vaultReadyForSetup(vaultMasterBootstrap) && (!flags.w5_vault_ready || !flags.w5_offline_backup_ack)) {
          merged = {
            ...flags,
            w5_vault_ready: true,
            w5_offline_backup_ack: vaultMasterBootstrap.offlineBackupAcked || flags.w5_offline_backup_ack,
          };
        }
        // Mirror live device inventory into durable flag (server-derived only).
        if (signals.deviceEnrolled === true) {
          const mirrored = mirrorDeviceEnrolledFlag(merged, true);
          if (mirrored !== merged) {
            await setupStateStore.put(nodeId, mirrored);
            merged = mirrored;
          }
        }
        const view = buildSetupStateView(
          merged,
          signals,
          new Date(nowMs()).toISOString(),
          isSetupAckWizardLegacyEnabled(),
        );
        const body = {
          ...view,
          device_break_glass_active: isDeviceBreakGlassActive(merged, signals),
        };
        assertSetupSecretFree(body);
        return ok(200, body);
      } catch {
        return fail(503, "service_unavailable", "setup state unavailable", requestId);
      }
    }

    if (verb === "PATCH" && pathname === "/admin/v1/setup-state") {
      const gate = await gateSetupSession(authReq, verb);
      if (!gate.ok) return fail(401, "invalid_credentials", "authentication required", requestId);
      try {
        await ensureVaultSealHydrated();
        const body = decodeBody(rawBody) as Record<string, unknown>;
        if (body === null || typeof body !== "object" || Array.isArray(body)) {
          return fail(400, "validation_error", "setup-state body must be an object", requestId);
        }
        const user = gate.user;
        const current = await setupStateStore.get(nodeId);
        const signals = await resolveSetupSignals(
          {
            mustChangePassword: user.mustChangePassword,
            mustEnrolTotp: user.mustEnrolTotp,
          },
          current,
        );
        // Default strips ack-only fakes; lab may restore via env.
        const legacy = isSetupAckWizardLegacyEnabled();
        const next = applySetupPatch(
          current,
          signals,
          body,
          new Date(nowMs()).toISOString(),
          legacy,
        );
        await setupStateStore.put(nodeId, next);
        const view = buildSetupStateView(next, signals, new Date(nowMs()).toISOString(), legacy);
        const out = {
          ...view,
          device_break_glass_active: isDeviceBreakGlassActive(next, signals),
        };
        assertSetupSecretFree(out);
        return ok(200, out);
      } catch (ex) {
        if (ex instanceof SetupPatchError) {
          const status =
            ex.code === "ceremony_blocked" ? 422 : ex.code === "conflict" ? 409 : 400;
          return fail(status, ex.code === "ceremony_blocked" ? "operation_not_armable" : ex.code, ex.message, requestId);
        }
        return fail(400, "validation_error", "invalid setup-state body", requestId);
      }
    }

    // Durable PWA install evidence (enum only — not ack).
    if (verb === "POST" && pathname === "/admin/v1/setup/pwa-installed") {
      const gate = await gateSetupSession(authReq, verb);
      if (!gate.ok) return fail(401, "invalid_credentials", "authentication required", requestId);
      try {
        await ensureVaultSealHydrated();
        const body = decodeBody(rawBody) as Record<string, unknown>;
        if (body === null || typeof body !== "object" || Array.isArray(body)) {
          return fail(400, "validation_error", "pwa-installed body must be an object", requestId);
        }
        const user = gate.user;
        if (user.mustChangePassword || user.mustEnrolTotp) {
          return fail(
            409,
            "conflict",
            "complete password and TOTP before recording PWA install",
            requestId,
          );
        }
        const current = await setupStateStore.get(nodeId);
        const next = applyPwaInstalledEvidence(current, body, new Date(nowMs()).toISOString());
        await setupStateStore.put(nodeId, next);
        const signals = await resolveSetupSignals(
          {
            mustChangePassword: user.mustChangePassword,
            mustEnrolTotp: user.mustEnrolTotp,
          },
          next,
        );
        const legacy = isSetupAckWizardLegacyEnabled();
        const view = buildSetupStateView(next, signals, new Date(nowMs()).toISOString(), legacy);
        const out = {
          ...view,
          device_break_glass_active: isDeviceBreakGlassActive(next, signals),
        };
        assertSetupSecretFree(out);
        return ok(200, out);
      } catch (ex) {
        if (ex instanceof SetupPatchError) {
          return fail(400, ex.code, ex.message, requestId);
        }
        return fail(400, "validation_error", "invalid pwa-installed body", requestId);
      }
    }


    // POST /admin/v1/setup-state/device-break-glass — typed BREAK GLASS.
    // Session+CSRF; requires exact phrase; audits via enrollment audit log.
    if (verb === "POST" && pathname === "/admin/v1/setup-state/device-break-glass") {
      const gate = await gateSetupSession(authReq, verb);
      if (!gate.ok) return fail(401, "invalid_credentials", "authentication required", requestId);
      try {
        await ensureVaultSealHydrated();
        const body = decodeBody(rawBody) as { phrase?: unknown };
        const phrase = typeof body.phrase === "string" ? body.phrase : "";
        const user = gate.user;
        const current = await setupStateStore.get(nodeId);
        const signals = await resolveSetupSignals(
          {
            mustChangePassword: user.mustChangePassword,
            mustEnrolTotp: user.mustEnrolTotp,
          },
          current,
        );
        const next = applyTypedDeviceBreakGlass(
          current,
          signals,
          phrase,
          new Date(nowMs()).toISOString(),
          isSetupAckWizardLegacyEnabled(),
        );
        await setupStateStore.put(nodeId, next);
        // Audit — never logs the phrase body as a secret-class field; action name is enough.
        const auditLog = deps.deviceEnrollmentAuditLog ?? new InMemoryEnrollmentAuditLog();
        auditLog.append({
          outcome: "ENROLLED",
          code: "OK",
          nodeId,
          challengeId: null,
          challengeNonce: null,
          authorizingKeyId: null,
          authorizingPublicKey: null,
          newDeviceKeyId: null,
          newDevicePublicKey: null,
          detail: `device_break_glass:operator=${user.id};phrase=${DEVICE_BREAK_GLASS_PHRASE}`,
          at: new Date(nowMs()).toISOString(),
        });
        const view = buildSetupStateView(
          next,
          signals,
          new Date(nowMs()).toISOString(),
          isSetupAckWizardLegacyEnabled(),
        );
        const out = {
          ...view,
          device_break_glass_active: isDeviceBreakGlassActive(next, signals),
        };
        assertSetupSecretFree(out);
        return ok(200, out);
      } catch (ex) {
        if (ex instanceof SetupPatchError) {
          const status = ex.code === "conflict" ? 409 : 400;
          return fail(status, ex.code, ex.message, requestId);
        }
        return fail(400, "validation_error", "invalid device-break-glass body", requestId);
      }
    }

    if (verb === "GET" && pathname === "/admin/v1/vault-master") {
      const gate = await gateSetupSession(authReq, verb);
      if (!gate.ok) return fail(401, "invalid_credentials", "authentication required", requestId);
      try {
        await ensureVaultSealHydrated();
        const status = statusFromState(vaultMasterBootstrap);
        assertSetupSecretFree(status);
        return ok(200, status);
      } catch {
        return fail(503, "service_unavailable", "vault master status unavailable", requestId);
      }
    }

    if (verb === "POST" && pathname === "/admin/v1/vault-master/generate") {
      const gate = await gateSetupSession(authReq, verb);
      if (!gate.ok) return fail(401, "invalid_credentials", "authentication required", requestId);
      try {
        await ensureVaultSealHydrated();
        // Second generate is refused — show-once.
        if (vaultMasterBootstrap.phase !== "virgin") {
          refuseSecondReveal(vaultMasterBootstrap);
        }
        const result = generateShowOnce(vaultMasterBootstrap, { backupMasterKey });
        // Durable seal (fingerprint only) so restart cannot re-issue plaintext.
        await persistVaultSeal();
        // Response intentionally carries master_key once. Not logged.
        return ok(200, result);
      } catch (ex) {
        if (ex instanceof VaultMasterError) {
          const status =
            ex.code === "backup_kek_collision"
              ? 422
              : ex.code === "already_generated" ||
                  ex.code === "already_sealed" ||
                  ex.code === "configured_env"
                ? 409
                : 400;
          return fail(status, ex.code, ex.message, requestId);
        }
        return fail(400, "validation_error", "vault master generate failed", requestId);
      }
    }

    if (verb === "POST" && pathname === "/admin/v1/vault-master/ack-offline") {
      const gate = await gateSetupSession(authReq, verb);
      if (!gate.ok) return fail(401, "invalid_credentials", "authentication required", requestId);
      try {
        await ensureVaultSealHydrated();
        const body = decodeBody(rawBody) as { offline_backup_ack?: boolean };
        if (body.offline_backup_ack !== true) {
          return fail(400, "validation_error", "offline_backup_ack must be true", requestId);
        }
        const result = acknowledgeOfflineBackup(vaultMasterBootstrap, {
          backupMasterKey,
          ack: true,
        });
        await persistVaultSeal();
        // Promote W5 flags secret-free.
        const current = await setupStateStore.get(nodeId);
        await setupStateStore.put(nodeId, {
          ...current,
          w5_vault_ready: true,
          w5_offline_backup_ack: true,
        });
        assertSetupSecretFree(result);
        return ok(200, result);
      } catch (ex) {
        if (ex instanceof VaultMasterError) {
          const status =
            ex.code === "backup_kek_collision"
              ? 422
              : ex.code === "already_sealed" || ex.code === "not_pending"
                ? 409
                : 400;
          return fail(status, ex.code, ex.message, requestId);
        }
        return fail(400, "validation_error", "vault master ack failed", requestId);
      }
    }


    if (verb !== "POST") {
      return fail(404, "not_found", "admin route not found", requestId);
    }

    let parsedBody: unknown;
    try {
      parsedBody = decodeBody(rawBody);
    } catch {
      return fail(400, "validation_error", "invalid JSON body", requestId);
    }

    // POST /admin/v1/device-signature-policy — guarded mutation (fresh TOTP + audit).
    // Placed after body decode (POST-only gate); never request-body policy for approve.
    if (verb === "POST" && pathname === "/admin/v1/device-signature-policy") {
      // Writable surface must exist on deps (process-level); the actual write uses the
      // TX-bound port from portsFor so ROLLBACK undoes settings+audit with the mutation.
      if (deps.deviceSignaturePolicy === undefined || deps.deviceSignaturePolicy.setMode === undefined) {
        return fail(503, "service_unavailable", "device-signature policy not writable", requestId);
      }
      const routeId = "admin_device_signature_policy";
      const idem = await idempotencyGate({
        store: deps.adminIdempotencyStore,
        nodeId,
        routeId,
        headers,
        verb,
        rawPath,
        rawBody,
        requestId,
      });
      if (!idem.ok) return idem.response;
      return runRequiredAdminMutation({
        deps,
        nodeId,
        routeId,
        idemKey: idem.idemKey,
        fingerprint: idem.fingerprint,
        requestId,
        action: async (ports) => {
          const policyPort = ports.deviceSignaturePolicy;
          if (policyPort === undefined || policyPort.setMode === undefined) {
            return {
              outcome: "abort" as const,
              response: fail(503, "service_unavailable", "transactional device-signature policy not wired", requestId),
            };
          }
          const guarded = await runGuardedAdminMutation({
            sessions,
            request: authReq,
            csrf,
            totp: labTotpOrNull(totp),
            userStore: deps.userStore,
            totpLog,
            nodeId,
            rawBody: parsedBody,
            validateBody: parseDeviceSignaturePolicyBody,
            nowMs: nowMs(),
            mutate: async ({ body, user }) => {
              await policyPort.setMode!(body.mode, {
                actorId: user.id,
                nodeId,
              });
              const mode = body.mode;
              const copy = DEVICE_SIGNATURE_POLICY_COPY[mode];
              return {
                mode,
                requires_device_signature: mode === "required",
                short: copy.short,
                long: copy.long,
                approve_hint: copy.approve_hint,
              };
            },
          });
          if (!guarded.ok) {
            return {
              outcome: "abort" as const,
              response: fail(guarded.status, guarded.code, guarded.message, requestId),
            };
          }
          return {
            outcome: "commit" as const,
            status: 200,
            responseBody: guarded.result,
          };
        },
      });
    }

    // POST /admin/v1/dual-control-policy — guarded mutation (fresh TOTP + audit). ZTR-1214.
    if (verb === "POST" && pathname === "/admin/v1/dual-control-policy") {
      if (deps.dualControlPolicy === undefined || deps.dualControlPolicy.setMode === undefined) {
        return fail(503, "service_unavailable", "dual-control policy not writable", requestId);
      }
      const routeId = "admin_dual_control_policy";
      const idem = await idempotencyGate({
        store: deps.adminIdempotencyStore,
        nodeId,
        routeId,
        headers,
        verb,
        rawPath,
        rawBody,
        requestId,
      });
      if (!idem.ok) return idem.response;
      return runRequiredAdminMutation({
        deps,
        nodeId,
        routeId,
        idemKey: idem.idemKey,
        fingerprint: idem.fingerprint,
        requestId,
        action: async (ports) => {
          const policyPort = ports.dualControlPolicy;
          if (policyPort === undefined || policyPort.setMode === undefined) {
            return {
              outcome: "abort" as const,
              response: fail(503, "service_unavailable", "transactional dual-control policy not wired", requestId),
            };
          }
          const guarded = await runGuardedAdminMutation({
            sessions,
            request: authReq,
            csrf,
            totp: labTotpOrNull(totp),
            userStore: deps.userStore,
            totpLog,
            nodeId,
            rawBody: parsedBody,
            validateBody: parseDualControlPolicyBody,
            nowMs: nowMs(),
            mutate: async ({ body, user }) => {
              await policyPort.setMode!(body.mode, {
                actorId: user.id,
                nodeId,
              });
              const mode = body.mode;
              const copy = DUAL_CONTROL_COPY[mode];
              return {
                mode,
                short: copy.short,
                long: copy.long,
                approve_hint: copy.approve_hint,
              };
            },
          });
          if (!guarded.ok) {
            return {
              outcome: "abort" as const,
              response: fail(guarded.status, guarded.code, guarded.message, requestId),
            };
          }
          return {
            outcome: "commit" as const,
            status: 200,
            responseBody: guarded.result,
          };
        },
      });
    }

    // --- Mode A recovery ceremony start ---
    // POST: session+CSRF+fresh TOTP; master key only in body; digests-only response.
    // CLI break-glass remains (run-recovery-ceremony.js).
    if (verb === "POST" && pathname === "/admin/v1/recovery-ceremony/start") {
      if (deps.recoveryCeremonyRunner === undefined) {
        return fail(503, "service_unavailable", "recovery ceremony not wired", requestId);
      }
      const runner = deps.recoveryCeremonyRunner;
      // Rate-limit / lockout before TOTP (failed starts still consume TOTP once past gate).
      // We need the session first to key lockout — use a pre-check via gateMoneyMutation
      // only for session+CSRF (no TOTP on gateMoneyMutation), then runGuarded burns TOTP.
      const preGate = await gateMoneyMutation(sessions, authReq, {
        userStore: deps.userStore,
        csrf,
        labTotp: labTotpOrNull(totp),
      });
      if (!preGate.ok) return authFail(preGate, requestId);
      if (isCeremonyUserLocked(preGate.user.id, nowMs())) {
        return fail(
          429,
          "rate_limited",
          "recovery ceremony temporarily locked — try again later",
          requestId,
        );
      }
      if (isCeremonyRunning()) {
        return fail(
          409,
          "ceremony_in_flight",
          "a recovery ceremony is already running",
          requestId,
        );
      }
      // Idempotency-Key REQUIRED. Body carries vault_master_key — the no-key-hash rule forbids
      // hashing that body (hash-of-master-key oracle). Fingerprint uses a structural
      // sentinel; replay identity is the Idempotency-Key (+ method/target) only.
      const routeId = "admin_recovery_ceremony_start";
      const idem = await idempotencyGate({
        store: deps.adminIdempotencyStore,
        nodeId,
        routeId,
        headers,
        verb,
        rawPath,
        rawBody,
        requestId,
        bodySha256: RECOVERY_CEREMONY_START_BODY_FINGERPRINT,
      });
      if (!idem.ok) return idem.response;

      // Count attempt before TOTP so lockout trips even when TOTP is missing/wrong.
      registerCeremonyAttempt(preGate.user.id, nowMs());

      return runRequiredAdminMutation({
        deps,
        nodeId,
        routeId,
        idemKey: idem.idemKey,
        fingerprint: idem.fingerprint,
        requestId,
        action: async () => {
          const guarded = await runGuardedAdminMutation({
            sessions,
            request: authReq,
            csrf,
            totp: labTotpOrNull(totp),
            userStore: deps.userStore,
            totpLog,
            nodeId,
            rawBody: parsedBody,
            validateBody: parseCeremonyStartBody,
            nowMs: nowMs(),
            mutate: async ({ body, user }) => {
              // Drop body references to key after startCeremonyJob captures them.
              const job = startCeremonyJob({
                databaseUrl: runner.databaseUrl,
                liveSql: runner.liveSql,
                nodeId,
                vaultMasterKey: body.vault_master_key,
                archiveEpochMasterKey: body.archive_epoch_master_key,
                verifierIdentity: `admin:${user.id}`,
                userId: user.id,
                now: () => new Date(nowMs()),
              });
              return { ...ceremonyJobToWire(job), in_flight: true };
            },
          });
          if (!guarded.ok) {
            return {
              outcome: "abort",
              response: fail(guarded.status, guarded.code, guarded.message, requestId),
            };
          }
          return { outcome: "commit", status: 202, responseBody: guarded.result };
        },
      });
    }

    // --- Recovery pack create ---
    // POST: session+CSRF+fresh TOTP; body passcode (+ optional master when sealed);
    // response application/octet-stream once. Audit pack_content_sha256 only.
    if (pathname === "/admin/v1/recovery-pack/create") {
      const preGate = await gateMoneyMutation(sessions, authReq, {
        userStore: deps.userStore,
        csrf,
        labTotp: labTotpOrNull(totp),
      });
      if (!preGate.ok) return authFail(preGate, requestId);

      const routeId = "admin_recovery_pack_create";
      const idem = await idempotencyGate({
        store: deps.adminIdempotencyStore,
        nodeId,
        routeId,
        headers,
        verb,
        rawPath,
        rawBody,
        requestId,
        bodySha256: RECOVERY_PACK_CREATE_BODY_FINGERPRINT,
      });
      if (!idem.ok) return idem.response;

      return runRequiredAdminMutation({
        deps,
        nodeId,
        routeId,
        idemKey: idem.idemKey,
        fingerprint: idem.fingerprint,
        requestId,
        action: async () => {
          const guarded = await runGuardedAdminMutation({
            sessions,
            request: authReq,
            csrf,
            totp: labTotpOrNull(totp),
            userStore: deps.userStore,
            totpLog,
            nodeId,
            rawBody: parsedBody,
            validateBody: parseRecoveryPackCreateBody,
            nowMs: nowMs(),
            mutate: async ({ body, user }) => {
              // Generate-only seal: node draws the secret. Re-issue opens an
              // existing pack server-side so the operator never handles master.
              let built: ReturnType<typeof createRecoveryPack>;
              let previousPackSha: string | null = null;
              if (body.from_pack !== undefined && body.from_pack_secret !== undefined) {
                try {
                  const reissued = reissueRecoveryPack({
                    fileBytes: body.from_pack,
                    secret: body.from_pack_secret,
                    allowLegacyV1: body.allow_legacy_v1 === true,
                  });
                  previousPackSha = reissued.previousPackContentSha256;
                  built = reissued;
                } catch (err) {
                  if (err instanceof RecoveryPackError && err.code === "caller_supplied_secret") {
                    throw Object.assign(new Error(err.message), {
                      code: "caller_supplied_recovery_secret",
                      status: 400,
                    });
                  }
                  const code =
                    err instanceof RecoveryPackError && err.code === "legacy_pack_v1"
                      ? "legacy_pack_v1"
                      : "from_pack_unreadable";
                  throw Object.assign(
                    new Error(
                      code === "legacy_pack_v1"
                        ? (err as RecoveryPackError).message
                        : "from_pack could not be opened with from_pack_secret",
                    ),
                    { code, status: 400 },
                  );
                }
              } else {
                // Resolve master: body override → pending show-once plaintext.
                // Never re-read sealed/configured plaintext (show-once wiped).
                let master: string | null =
                  body.vault_master_key !== undefined ? body.vault_master_key : null;
                if (master === null && vaultMasterBootstrap.pendingPlaintext !== null) {
                  master = vaultMasterBootstrap.pendingPlaintext;
                }
                if (master === null || master.length < MIN_MASTER_KEY_CHARS) {
                  throw Object.assign(
                    new Error(
                      "vault master key required — provide vault_master_key, from_pack, or create pack while show-once plaintext is still pending ack",
                    ),
                    { code: "vault_master_unavailable", status: 422 },
                  );
                }
                try {
                  built = createRecoveryPack({
                    vaultMasterKey: master,
                  });
                } catch (err) {
                  if (err instanceof RecoveryPackError && err.code === "caller_supplied_secret") {
                    throw Object.assign(new Error(err.message), {
                      code: "caller_supplied_recovery_secret",
                      status: 400,
                    });
                  }
                  throw err;
                }
              }
              const at = new Date(nowMs()).toISOString();
              try {
                await deps.recoveryPackAudit?.({
                  kind: "pack_create",
                  operator_id: user.id,
                  pack_content_sha256: built.envelope.pack_content_sha256,
                  at,
                  ...(previousPackSha === null
                    ? {}
                    : { previous_pack_content_sha256: previousPackSha }),
                });
              } catch {
                // audit must not block download
              }
              // Live response carries recovery_secret once so the SPA can show it.
              // Durable idempotency row MUST strip it — seal key + pack must never
              // land together in a replayable store row.
              return {
                object: "recovery_pack_create",
                format: RECOVERY_PACK_FORMAT,
                pack_content_sha256: built.envelope.pack_content_sha256,
                previous_pack_content_sha256: previousPackSha,
                filename: `zp-node-recovery-pack-${built.envelope.pack_content_sha256.slice(0, 12)}.json`,
                pack_file_b64: built.fileBytes.toString("base64"),
                content_type: "application/octet-stream",
                recovery_secret: built.secret,
              };
            },
          });
          if (!guarded.ok) {
            if (guarded.reason === "mutation_threw" && guarded.error !== undefined) {
              const err = guarded.error as { status?: number; code?: string; message?: string };
              return {
                outcome: "abort",
                response: fail(
                  typeof err.status === "number" ? err.status : 400,
                  err.code ?? "validation_error",
                  err.message ?? "recovery pack create failed",
                  requestId,
                ),
              };
            }
            return {
              outcome: "abort",
              response: fail(guarded.status, guarded.code, guarded.message, requestId),
            };
          }
          // Show-once: first response includes recovery_secret; durable row strips it.
          const live = guarded.result as Record<string, unknown>;
          const { recovery_secret: _omitSecret, ...durable } = live;
          return {
            outcome: "commit",
            status: 200,
            responseBody: live,
            durableResponseBody: durable,
          };
        },
      });
    }

    // --- Recovery pack prove ---
    // POST: session+CSRF+fresh TOTP; upload file + passcode; decrypt → ceremony engine.
    // Only ceremony writes recovery_verified_at. 5 fails → 15 min lock.
    if (pathname === "/admin/v1/recovery-pack/prove") {
      if (deps.recoveryCeremonyRunner === undefined) {
        return fail(503, "service_unavailable", "recovery ceremony not wired", requestId);
      }
      const runner = deps.recoveryCeremonyRunner;
      const lockoutStore =
        deps.recoveryPackLockoutStore ?? createMemoryRecoveryPackLockoutStore();

      const preGate = await gateMoneyMutation(sessions, authReq, {
        userStore: deps.userStore,
        csrf,
        labTotp: labTotpOrNull(totp),
      });
      if (!preGate.ok) return authFail(preGate, requestId);

      const lockSnap = await lockoutStore.load(nodeId, preGate.user.id);
      if (isProveLocked(lockSnap, nowMs())) {
        return fail(
          429,
          "rate_limited",
          "recovery pack prove temporarily locked — try again later",
          requestId,
        );
      }
      if (isCeremonyRunning()) {
        return fail(
          409,
          "ceremony_in_flight",
          "a recovery ceremony is already running",
          requestId,
        );
      }

      const routeId = "admin_recovery_pack_prove";
      const idem = await idempotencyGate({
        store: deps.adminIdempotencyStore,
        nodeId,
        routeId,
        headers,
        verb,
        rawPath,
        rawBody,
        requestId,
        bodySha256: RECOVERY_PACK_PROVE_BODY_FINGERPRINT,
      });
      if (!idem.ok) return idem.response;

      return runRequiredAdminMutation({
        deps,
        nodeId,
        routeId,
        idemKey: idem.idemKey,
        fingerprint: idem.fingerprint,
        requestId,
        action: async () => {
          const guarded = await runGuardedAdminMutation({
            sessions,
            request: authReq,
            csrf,
            totp: labTotpOrNull(totp),
            userStore: deps.userStore,
            totpLog,
            nodeId,
            rawBody: parsedBody,
            validateBody: parseRecoveryPackProveBody,
            nowMs: nowMs(),
            mutate: async ({ body, user }) => {
              // Re-check lock inside mutate (race with concurrent proves).
              const snapNow = await lockoutStore.load(nodeId, user.id);
              if (isProveLocked(snapNow, nowMs())) {
                throw Object.assign(
                  new Error("recovery pack prove temporarily locked — try again later"),
                  { code: "rate_limited", status: 429 },
                );
              }
              if (isCeremonyRunning()) {
                throw Object.assign(new Error("a recovery ceremony is already running"), {
                  code: "ceremony_in_flight",
                  status: 409,
                });
              }

              const packSha = peekPackContentSha256(body.packFileUtf8);
              let opened;
              try {
                opened = openRecoveryPack({
                  fileBytes: body.packFileUtf8,
                  secret: body.recovery_secret,
                  allowLegacyV1: body.allow_legacy_v1,
                });
              } catch (err) {
                // A v1 payload is only reachable with the correct secret, so naming
                // it is no decrypt oracle — and it must not burn a lockout attempt.
                if (err instanceof RecoveryPackError && err.code === "legacy_pack_v1") {
                  throw Object.assign(new Error(err.message), {
                    code: "legacy_pack_v1",
                    status: 400,
                  });
                }
                await recordProveFailure(lockoutStore, nodeId, user.id, nowMs());
                try {
                  await deps.recoveryPackAudit?.({
                    kind: "pack_prove_fail",
                    operator_id: user.id,
                    pack_content_sha256: packSha,
                    at: new Date(nowMs()).toISOString(),
                  });
                } catch {
                  /* ignore */
                }
                // Generic error — no decrypt oracle.
                const lockedAfter = isProveLocked(
                  await lockoutStore.load(nodeId, user.id),
                  nowMs(),
                );
                throw Object.assign(
                  new Error(
                    lockedAfter
                      ? "recovery pack prove temporarily locked — try again later"
                      : "recovery pack prove failed",
                  ),
                  {
                    code: lockedAfter ? "rate_limited" : "prove_failed",
                    status: lockedAfter ? 429 : 400,
                  },
                );
              }

              // Success path: start ceremony with decrypted master; engine sole stamp writer.
              const masterHolder = { value: opened.vault_master_key };
              try {
                const job = startCeremonyJob({
                  databaseUrl: runner.databaseUrl,
                  liveSql: runner.liveSql,
                  nodeId,
                  vaultMasterKey: masterHolder.value,
                  verifierIdentity: `admin:${user.id}:recovery-pack`,
                  userId: user.id,
                  now: () => new Date(nowMs()),
                });
                await clearProveFailures(lockoutStore, nodeId, user.id, nowMs());
                try {
                  await deps.recoveryPackAudit?.({
                    kind: "pack_prove_ok",
                    operator_id: user.id,
                    pack_content_sha256: packSha,
                    at: new Date(nowMs()).toISOString(),
                    recovery_verification_id: job.ceremony_id,
                    pack_version: opened.v,
                  });
                } catch {
                  /* ignore */
                }
                // Digests only — never master / passcode.
                return {
                  object: "recovery_pack_prove",
                  accepted: true,
                  ceremony_id: job.ceremony_id,
                  recovery_verification_id: job.ceremony_id,
                  // Wallet count unknown until ceremony finishes; client polls status.
                  verified_wallet_count: null,
                  status: job.status,
                  in_flight: true,
                  // 1 means the operator just proved a superseded pack — the SPA
                  // turns this into the re-issue-and-destroy prompt.
                  pack_version: opened.v,
                };
              } finally {
                masterHolder.value = "";
              }
            },
          });
          if (!guarded.ok) {
            if (guarded.reason === "mutation_threw" && guarded.error !== undefined) {
              const err = guarded.error as { status?: number; code?: string; message?: string };
              return {
                outcome: "abort",
                response: fail(
                  typeof err.status === "number" ? err.status : 400,
                  err.code ?? "prove_failed",
                  err.message ?? "recovery pack prove failed",
                  requestId,
                ),
              };
            }
            return {
              outcome: "abort",
              response: fail(guarded.status, guarded.code, guarded.message, requestId),
            };
          }
          return { outcome: "commit", status: 202, responseBody: guarded.result };
        },
      });
    }

    // POST /admin/v1/lab/receive — capped lab RECEIVE + ARM.
    // Session + CSRF + fresh TOTP via runGuardedAdminMutation. Cap + gates in runLabReceive.
    if (pathname === "/admin/v1/lab/receive") {
      if (deps.labReceive === undefined) {
        return fail(503, "service_unavailable", "lab receive not wired", requestId);
      }
      const labPorts = deps.labReceive;
      const guarded = await runGuardedAdminMutation({
        sessions,
        request: authReq,
        csrf,
        totp: labTotpOrNull(totp),
        userStore: deps.userStore,
        totpLog,
        nodeId,
        rawBody: parsedBody,
        validateBody: (raw: unknown) => {
          if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
            return {
              ok: false as const,
              status: 400 as const,
              code: "validation_error",
              message: "invalid JSON body",
            };
          }
          return { ok: true as const, body: raw as Record<string, unknown> };
        },
        nowMs: nowMs(),
        mutate: async ({ body, user }) => {
          const result = await runLabReceive(
            {
              nodeId,
              nowMs,
              resolveImplementerId: deps.resolveImplementerId ?? (async () => null),
              operationStore: labPorts.operationStore,
              reportingHandle: labPorts.reportingHandle,
              collectSignals: async () =>
                collectReadinessSignals(deps, user.id, nodeId, nowMs),
              readyWaitMs: labPorts.readyWaitMs,
              readyPollMs: labPorts.readyPollMs,
            },
            {
              amount_zkz: body.amount_zkz,
              reporting_key_id: body.reporting_key_id,
              reporting_private_seed_hex: body.reporting_private_seed_hex,
              idempotency_key: body.idempotency_key,
            },
          );
          if (!result.ok) {
            throw Object.assign(new Error(result.message), {
              code: result.code,
              status: result.status,
              checklist_links: result.checklist_links,
              operation_id: result.operation_id,
            });
          }
          assertLabPayloadSecretFree(result.body);
          return result.body;
        },
      });
      if (!guarded.ok) {
        const errObj =
          guarded.reason === "mutation_threw" && guarded.error !== undefined
            ? (guarded.error as {
                status?: number;
                code?: string;
                message?: string;
                checklist_links?: unknown;
                operation_id?: string;
              })
            : null;
        if (errObj && typeof errObj.status === "number" && typeof errObj.code === "string") {
          // ZTR-1196: named lab-receive sibling envelope (checklist_links/operation_id).
          return {
            status: errObj.status,
            body: buildAdminLabReceiveErrorBody(
              coerceAdminErrorCode(errObj.code),
              errObj.message ?? guarded.message,
              requestId,
              {
                checklist_links: errObj.checklist_links,
                operation_id: errObj.operation_id,
              },
            ),
            headers: { ...JSON_HEADERS },
          };
        }
        return fail(guarded.status, guarded.code, guarded.message, requestId);
      }
      return ok(201, guarded.result);
    }

    {
      const m = pathname.match(/^\/admin\/v1\/external-sends\/([^/]+)\/approve$/);
      if (m) {
        const routeId = "admin_external_send_approve";
        const idem = await idempotencyGate({
          store: deps.adminIdempotencyStore, nodeId, routeId, headers, verb, rawPath, rawBody, requestId,
        });
        if (!idem.ok) return idem.response;
        return runRequiredAdminMutation({
          deps, nodeId, routeId, idemKey: idem.idemKey,
          fingerprint: idem.fingerprint, requestId,
          action: async (ports) => {
            const gate = await gateMoneyMutation(sessions, authReq, { userStore: deps.userStore, csrf, labTotp: labTotpOrNull(totp) });
            if (!gate.ok) return { outcome: "abort", response: authFail(gate, requestId) };
            const lived = parseApproveBody(parsedBody);
            if (!lived.ok) return { outcome: "abort", response: fail(lived.status, lived.code, lived.message, requestId) };
            const totpHeader = headers["x-zp-totp"];
            if (typeof totpHeader !== "string" || totpHeader.length === 0) {
              return { outcome: "abort", response: fail(401, "invalid_credentials", "authentication required", requestId) };
            }
            const body = lived.body;
            const totpConfig = await resolveOperatorTotpConfig(deps.userStore, gate.user.id, labTotpOrNull(totp));
            if (totpConfig === null) return { outcome: "abort", response: fail(401, "invalid_credentials", "authentication required", requestId) };
            // Missing / unreadable dual-control port fails closed to two_human
            // (never single_operator — ZTR-1214 D2; peer device-sig → require).
            let dualMode: DualControlMode = "two_human";
            if (deps.dualControlPolicy !== undefined) {
              try {
                dualMode = await deps.dualControlPolicy.getMode();
              } catch {
                dualMode = "two_human";
              }
            }
            // Server policy OR volunteered request — never the request body alone (ZTR-1143).
            // Unreadable / missing policy fails closed (require).
            let policyRequiresDevice = true;
            if (deps.deviceSignaturePolicy !== undefined) {
              try {
                policyRequiresDevice = await deps.deviceSignaturePolicy.requiresDeviceSignature();
              } catch {
                policyRequiresDevice = true;
              }
            }
            const requestSuppliedDevice =
              body.device_key_id !== null && body.device_signature !== null;
            const requireDeviceSignature = combineDeviceSignatureRequirement(
              policyRequiresDevice,
              requestSuppliedDevice,
            );
            const outcome = await approveExternalSend({
              operationId: m[1]!, challengeNonce: body.challenge_nonce,
              expectedRowVersion: body.expected_row_version, preimageSha256: body.preimage_sha256,
              deviceKeyId: body.device_key_id, deviceSignature: body.device_signature, totpCode: totpHeader,
              approverOperatorId: gate.user.id,
            }, {
              challengeStore: ports.challengeStore, loadOperation: ports.loadOperation,
              deviceStore: deps.deviceStore as never, totpConfig, totpBurnStore: totpLog,
              requireDeviceSignature, nowMs,
              dualControlMode: dualMode,
              challengeIssuerStore: deps.challengeIssuerStore,
            });
            if (outcome.outcome === "REJECTED") {
              // Doc 01 §4.2: a POLICY refusal stays distinguishable from protocol
              // invalidity. Every other reason keeps the single opaque envelope so
              // no authentication factor is disclosed.
              if (outcome.reason === APPROVAL_POLICY_DENIAL_CODE) {
                return {
                  outcome: "abort",
                  response: fail(
                    APPROVAL_FACTOR_FAILURE_HTTP_STATUS,
                    APPROVAL_POLICY_DENIAL_CODE,
                    DUAL_CONTROL_COPY.two_human.long,
                    requestId,
                  ),
                };
              }
              return {
                outcome: "abort",
                response: fail(
                  APPROVAL_FACTOR_FAILURE_HTTP_STATUS,
                  APPROVAL_FACTOR_FAILURE_CODE,
                  "approval rejected",
                  requestId,
                ),
              };
            }
            if (deps.challengeIssuerStore !== undefined) {
              await deps.challengeIssuerStore.clear(m[1]!);
            }
            return { outcome: "commit", status: 200, responseBody: outcome.response };
          },
        });
      }
    }

    {
      const m = pathname.match(/^\/admin\/v1\/external-sends\/([^/]+)\/reject$/);
      if (m) {
        const routeId = "admin_external_send_reject";
        const idem = await idempotencyGate({
          store: deps.adminIdempotencyStore, nodeId, routeId, headers, verb, rawPath, rawBody, requestId,
        });
        if (!idem.ok) return idem.response;
        return runRequiredAdminMutation({
          deps, nodeId, routeId, idemKey: idem.idemKey,
          fingerprint: idem.fingerprint, requestId,
          action: async (ports) => {
            const guarded = await runGuardedAdminMutation({
              sessions,
              request: authReq,
              csrf,
              totp: labTotpOrNull(totp),
              userStore: deps.userStore,
              totpLog,
              nodeId,
              rawBody: parsedBody,
              validateBody: parseRejectBody,
              nowMs: nowMs(),
              mutate: async ({ body }) => {
                const outcome = await rejectSendOperation(
                  { operationId: m[1]!, expectedRowVersion: body.expected_row_version },
                  ports.sendDecisionStore,
                );
                if (outcome.outcome === "CONFLICT") {
                  throw Object.assign(new Error("operation conflict"), {
                    code: "operation_version_conflict",
                    status: 409,
                  });
                }
                return { operation_id: m[1]!, status: "REJECTED", row_version: outcome.rowVersion };
              },
            });
            if (!guarded.ok) {
              return { outcome: "abort", response: fail(guarded.status, guarded.code, guarded.message, requestId) };
            }
            return { outcome: "commit", status: 200, responseBody: guarded.result };
          },
        });
      }
    }

    {
      const m = pathname.match(/^\/admin\/v1\/destinations\/([^/]+)\/bless$/);
      if (m) {
        const routeId = "admin_destination_bless";
        const idem = await idempotencyGate({
          store: deps.adminIdempotencyStore, nodeId, routeId, headers, verb, rawPath, rawBody, requestId,
        });
        if (!idem.ok) return idem.response;
        return runRequiredAdminMutation({
          deps, nodeId, routeId, idemKey: idem.idemKey,
          fingerprint: idem.fingerprint, requestId,
          action: async (ports) => {
            const guarded = await runGuardedAdminMutation({
              sessions, request: authReq, csrf, totp: labTotpOrNull(totp),
              userStore: deps.userStore, totpLog, nodeId, rawBody: parsedBody,
              validateBody: parseBlessBody, nowMs: nowMs(),
              mutate: async ({ body }) => {
                const outcome = await ports.destinationService.bless({
                  nodeId: nodeId as never, destinationId: m[1]! as never,
                  nonce: body.nonce as never, issuedAt: body.issued_at,
                  expiresAt: body.expires_at, deviceSignature: body.device_signature,
                  deviceKeyId: body.device_key_id as never,
                });
                if (outcome.status === "not_found") throw Object.assign(new Error("not found"), { code: "not_found", status: 404 });
                if (outcome.status === "authorization_rejected" || outcome.status === "invalid_transition") {
                  // Opaque rejection — does not distinguish key_origin / signature / transition
                  // (ZTR-1170; wallet_not_node_generated collapsed in destination.bless).
                  throw Object.assign(new Error(outcome.status), {
                    code: "approval_rejected",
                    status: APPROVAL_FACTOR_FAILURE_HTTP_STATUS,
                  });
                }
                return outcome.destination;
              },
            });
            if (!guarded.ok) {
              // Surface mutate-thrown status/code (authorization_rejected → 401 approval_rejected;
              // not_found → 404). runGuardedAdminMutation otherwise collapses mutation_threw to 500.
              const nestedStatus =
                guarded.reason === "mutation_threw" &&
                guarded.error !== undefined &&
                typeof guarded.error === "object" &&
                guarded.error !== null &&
                "status" in guarded.error &&
                typeof (guarded.error as { status: unknown }).status === "number"
                  ? (guarded.error as { status: number }).status
                  : guarded.status;
              const nestedCode =
                guarded.reason === "mutation_threw" &&
                guarded.error !== undefined &&
                typeof guarded.error === "object" &&
                guarded.error !== null &&
                "code" in guarded.error &&
                typeof (guarded.error as { code: unknown }).code === "string"
                  ? (guarded.error as { code: string }).code
                  : guarded.code;
              return {
                outcome: "abort",
                response: fail(nestedStatus, nestedCode, guarded.message, requestId),
              };
            }
            return { outcome: "commit", status: 200, responseBody: guarded.result };
          },
        });
      }
    }

    {
      const m = pathname.match(/^\/admin\/v1\/destinations\/([^/]+)\/retire$/);
      if (m) {
        const routeId = "admin_destination_retire";
        const idem = await idempotencyGate({
          store: deps.adminIdempotencyStore, nodeId, routeId, headers, verb, rawPath, rawBody, requestId,
        });
        if (!idem.ok) return idem.response;
        return runRequiredAdminMutation({
          deps, nodeId, routeId, idemKey: idem.idemKey,
          fingerprint: idem.fingerprint, requestId,
          action: async (ports) => {
            const gate = await gateMoneyMutation(sessions, authReq, { userStore: deps.userStore, csrf, labTotp: labTotpOrNull(totp) });
            if (!gate.ok) return { outcome: "abort", response: authFail(gate, requestId) };
            const lived = parseRetireBody(parsedBody);
            if (!lived.ok) return { outcome: "abort", response: fail(lived.status, lived.code, lived.message, requestId) };
            const outcome = await ports.destinationService.retire({ nodeId: nodeId as never, destinationId: m[1]! as never });
            if (outcome.status === "not_found") return { outcome: "abort", response: fail(404, "not_found", "destination not found", requestId) };
            if (outcome.status === "invalid_transition") return { outcome: "abort", response: fail(409, "operation_version_conflict", "invalid transition", requestId) };
            return { outcome: "commit", status: 200, responseBody: outcome.destination };
          },
        });
      }
    }

    {
      const m = pathname.match(/^\/admin\/v1\/operations\/([^/]+)\/recovery-actions$/);
      if (m) {
        // Same REQUIRED-idempotency shape as approve/reject/bless/retire: the shared gate
        // is authoritative at the HTTP boundary. It owns key grammar (^[!-~]{16,255}$),
        // the completed-row lookup, the fingerprint compare, and the
        // `idempotency-replayed` header — none of which the DB CHECK on
        // operations.idempotency_key can answer as a 400 instead of a write failure.
        //
        // executeRecoveryAction's own lookupIdempotency/storeIdempotency
        // (operator/recovery-actions.ts) stays as the *effect*-level de-dup and is
        // deliberately NOT folded into the gate's transaction: the recovery mutation keeps
        // its own SERIALIZABLE tx (operations/sql-recovery-store.ts, schema CONVENTIONS.md
        // money-path rule) rather than joining the executor's READ COMMITTED one. So the
        // effect can commit before the completed row does; on that crash window the store
        // replays the effect and the gate records the same bytes under the key.
        const routeId = "admin_operation_recovery_actions";
        const idem = await idempotencyGate({
          store: deps.adminIdempotencyStore, nodeId, routeId, headers, verb, rawPath, rawBody, requestId,
        });
        if (!idem.ok) return idem.response;
        return runRequiredAdminMutation({
          deps, nodeId, routeId, idemKey: idem.idemKey,
          fingerprint: idem.fingerprint, requestId,
          action: async () => {
            const guarded = await runGuardedAdminMutation({
              sessions,
              request: authReq,
              csrf,
              totp: labTotpOrNull(totp),
              userStore: deps.userStore,
              totpLog,
              nodeId,
              rawBody: parsedBody,
              validateBody: parseRecoveryBody,
              nowMs: nowMs(),
              mutate: async ({ body, user, timestep }) => {
                const auth: RecoveryActionAuthContext = {
                  operatorId: user.id,
                  totpTimestep: timestep,
                  csrfValidated: true,
                  idempotencyKey: idem.idemKey,
                };
                const result = await handleRecoveryAction(
                  deps.recoveryActionStore,
                  m[1]!,
                  body,
                  auth,
                );
                if (!result.ok) {
                  throw Object.assign(new Error(result.reason), {
                    code: result.code,
                    status: result.status,
                  });
                }
                return result.body;
              },
            });
            if (!guarded.ok) {
              const nestedStatus =
                guarded.reason === "mutation_threw" &&
                guarded.error !== undefined &&
                typeof guarded.error === "object" &&
                guarded.error !== null &&
                "status" in guarded.error &&
                typeof (guarded.error as { status: unknown }).status === "number"
                  ? (guarded.error as { status: number }).status
                  : guarded.status;
              const nestedCode =
                guarded.reason === "mutation_threw" &&
                guarded.error !== undefined &&
                typeof guarded.error === "object" &&
                guarded.error !== null &&
                "code" in guarded.error &&
                typeof (guarded.error as { code: unknown }).code === "string"
                  ? (guarded.error as { code: string }).code
                  : guarded.code;
              return {
                outcome: "abort",
                response: fail(nestedStatus, nestedCode, guarded.message, requestId),
              };
            }
            return { outcome: "commit", status: 200, responseBody: guarded.result };
          },
        });
      }
    }

    // --- attention-retraction POST (session+CSRF+fresh TOTP) ---
    // Audited operator retraction of a false-positive attention_required flag — distinct
    // from recovery-actions (that catalog only ever says "the flag was real, do X about
    // it"; this route says "the flag was never real"). See operator/attention-retraction.ts.
    {
      const m = pathname.match(/^\/admin\/v1\/operations\/([^/]+)\/attention-retraction$/);
      if (m) {
        if (deps.attentionRetractionStore === undefined) {
          return fail(503, "service_unavailable", "attention retraction not wired", requestId);
        }
        const store = deps.attentionRetractionStore;
        const operationId = m[1]!;
        const guarded = await runGuardedAdminMutation({
          sessions,
          request: authReq,
          csrf,
          totp: labTotpOrNull(totp),
          userStore: deps.userStore,
          totpLog,
          nodeId,
          rawBody: parsedBody,
          validateBody: parseAttentionRetractionBody,
          nowMs: nowMs(),
          mutate: async ({ body, user }) => {
            const outcome = await executeAttentionRetraction(store, {
              operationId,
              reason: body.reason,
              supersededBy: body.superseded_by,
              expectedRowVersion: body.expected_row_version,
              actorId: user.id,
              csrfValidated: true,
            });
            if (outcome.status === "rejected") {
              const status =
                outcome.reason === "operation_not_found" ? 404 :
                outcome.reason === "conflict" ? 409 :
                outcome.reason === "not_flagged" ? 422 : 401;
              throw Object.assign(new Error(outcome.reason), {
                code: outcome.reason,
                status,
              });
            }
            return outcome.body;
          },
        });
        if (!guarded.ok) {
          const nestedStatus =
            guarded.reason === "mutation_threw" &&
            guarded.error !== undefined &&
            typeof guarded.error === "object" &&
            guarded.error !== null &&
            "status" in guarded.error &&
            typeof (guarded.error as { status: unknown }).status === "number"
              ? (guarded.error as { status: number }).status
              : guarded.status;
          const nestedCode =
            guarded.reason === "mutation_threw" &&
            guarded.error !== undefined &&
            typeof guarded.error === "object" &&
            guarded.error !== null &&
            "code" in guarded.error &&
            typeof (guarded.error as { code: unknown }).code === "string"
              ? (guarded.error as { code: string }).code
              : guarded.code;
          return fail(nestedStatus, nestedCode, guarded.message, requestId);
        }
        return ok(200, guarded.result);
      }
    }

    
    // --- operator-park POST (session+CSRF+fresh TOTP) — OPERATOR_PARKED (ZTR-1147) ---
    {
      const m = pathname.match(/^\/admin\/v1\/operations\/([^/]+)\/operator-park$/);
      if (m) {
        if (deps.operatorParkStore === undefined) {
          return fail(503, "service_unavailable", "operator park not wired", requestId);
        }
        const store = deps.operatorParkStore;
        const operationId = m[1]!;
        const guarded = await runGuardedAdminMutation({
          sessions,
          request: authReq,
          csrf,
          totp: labTotpOrNull(totp),
          userStore: deps.userStore,
          totpLog,
          nodeId,
          rawBody: parsedBody,
          validateBody: parseOperatorParkBody,
          nowMs: nowMs(),
          mutate: async ({ body, user }) => {
            const outcome = await executeOperatorPark(store, {
              operationId,
              note: body.note,
              expectedRowVersion: body.expected_row_version,
              actorId: user.id,
              csrfValidated: true,
            });
            if (outcome.status === "rejected") {
              const status =
                outcome.reason === "operation_not_found" ? 404 :
                outcome.reason === "conflict" ? 409 :
                outcome.reason === "already_flagged" || outcome.reason === "note_required" ? 422 : 401;
              throw Object.assign(new Error(outcome.reason), {
                code: outcome.reason,
                status,
              });
            }
            return outcome.body;
          },
        });
        if (!guarded.ok) {
          const nestedStatus =
            guarded.reason === "mutation_threw" &&
            guarded.error !== undefined &&
            typeof guarded.error === "object" &&
            guarded.error !== null &&
            "status" in guarded.error &&
            typeof (guarded.error as { status: unknown }).status === "number"
              ? (guarded.error as { status: number }).status
              : guarded.status;
          const nestedCode =
            guarded.reason === "mutation_threw" &&
            guarded.error !== undefined &&
            typeof guarded.error === "object" &&
            guarded.error !== null &&
            "code" in guarded.error &&
            typeof (guarded.error as { code: unknown }).code === "string"
              ? (guarded.error as { code: string }).code
              : guarded.code;
          return fail(nestedStatus, nestedCode, guarded.message, requestId);
        }
        return ok(200, guarded.result);
      }
    }

// --- operator halt POST (session+CSRF+fresh TOTP) ---

    if (verb === "POST" && pathname === "/admin/v1/halt") {
      if (deps.halt === undefined) {
        return fail(503, "service_unavailable", "operator halt not wired", requestId);
      }
      const liveHaltPorts = deps.halt;
      const routeId = "admin_halt";
      const idem = await idempotencyGate({
        store: deps.adminIdempotencyStore, nodeId, routeId, headers, verb, rawPath, rawBody, requestId,
      });
      if (!idem.ok) return idem.response;
      return runRequiredAdminMutation({
        deps, nodeId, routeId, idemKey: idem.idemKey,
        fingerprint: idem.fingerprint, requestId,
        action: async (ports) => {
          const haltPorts = ports.halt;
          if (haltPorts === undefined) return { outcome: "abort", response: fail(503, "service_unavailable", "transactional halt not wired", requestId) };
          const guarded = await runGuardedAdminMutation({
            sessions, request: authReq, csrf, totp: labTotpOrNull(totp),
            userStore: deps.userStore, totpLog, nodeId, rawBody: parsedBody,
            validateBody: parseHaltBody, nowMs: nowMs(),
            mutate: async ({ body, user }) => {
              const metaReason = body.reason;
              const actor = user.id;
              const writeStore: HaltStore = {
                read: () => haltPorts.store.read(),
                write: async (state) => {
                  if ("writeWithMeta" in haltPorts.store && typeof (haltPorts.store as OperatorHaltStore).writeWithMeta === "function") {
                    await (haltPorts.store as OperatorHaltStore).writeWithMeta(state, { reason: metaReason, actor });
                  } else await haltPorts.store.write(state);
                },
              };
              if (body.engaged) await engageHalt(writeStore, haltPorts.gate, haltPorts.evidence, { actor, reason: metaReason ?? undefined });
              else await disengageHalt(writeStore, haltPorts.gate, haltPorts.evidence, { actor, reason: metaReason ?? undefined });
              const display = "readDisplay" in haltPorts.store && typeof (haltPorts.store as OperatorHaltStore).readDisplay === "function"
                ? await (haltPorts.store as OperatorHaltStore).readDisplay()
                : { engaged: haltPorts.gate.isHalted(), reason: metaReason, updatedAt: new Date(nowMs()).toISOString(), updatedBy: actor };
              return haltWire(haltPorts.gate.isHalted(), { reason: display.reason, updatedAt: display.updatedAt, updatedBy: display.updatedBy });
            },
          });
          if (!guarded.ok) return { outcome: "abort", response: fail(guarded.status, guarded.code, guarded.message, requestId) };
          return {
            outcome: "commit", status: 200, responseBody: guarded.result,
            afterCommit: () => {
              if (JSON.parse(JSON.stringify(guarded.result)).engaged === true) liveHaltPorts.gate.engage();
              else liveHaltPorts.gate.release();
              liveHaltPorts.onToggle?.(liveHaltPorts.gate.isHalted());
            },
          };
        },
      });
    }

    // POST /admin/v1/api-keys — issue a new implementer bearer key.
    // Session+CSRF+fresh TOTP via runGuardedAdminMutation (parity with halt). The full
    // raw key is returned exactly once in the response body; it is never persisted in
    // plaintext and never logged. The audit row is written atomically by SqlCredentialStore.
    if (verb === "POST" && pathname === "/admin/v1/api-keys") {
      if (deps.credentialService === undefined || deps.resolveImplementerId === undefined) {
        return fail(503, "service_unavailable", "api key management not wired", requestId);
      }
      const routeId = "admin_api_keys_issue";
      const idem = await idempotencyGate({
        store: deps.adminIdempotencyStore, nodeId, routeId, headers, verb, rawPath, rawBody, requestId,
      });
      if (!idem.ok) return idem.response;
      const resolveImplementerId = deps.resolveImplementerId;
      return runRequiredAdminMutation({
        deps, nodeId, routeId, idemKey: idem.idemKey,
        fingerprint: idem.fingerprint, requestId,
        action: async (ports) => {
          const guarded = await runGuardedAdminMutation({
            sessions, request: authReq, csrf, totp: labTotpOrNull(totp),
            userStore: deps.userStore, totpLog, nodeId, rawBody: parsedBody,
            validateBody: parseIssueApiKeyBody, nowMs: nowMs(),
            mutate: async ({ body, session }) => {
              const implementerId = await resolveImplementerId();
              if (implementerId === null) throw new CredentialError("no active implementer", "CREDENTIAL_NOT_FOUND");
              const created = await ports.credentialService.create(implementerId, body.scopes, null, session.sessionId);
              return toApiKeyIssueResult(created);
            },
          });
          if (!guarded.ok) {
            return { outcome: "abort", response: fail(guarded.status, guarded.code, guarded.message, requestId) };
          }
          return { outcome: "commit", status: 200, responseBody: guarded.result };
        },
      });
    }

    // POST /admin/v1/reporting-keys — node-mint the first ACTIVE reporting
    // credential (first-key ceremony). Session+CSRF+fresh TOTP via
    // runGuardedAdminMutation (parity with api-keys issue). The raw private seed is returned
    // exactly once in the response body; the node persists public material only and never
    // logs the seed. A current key already ACTIVE fails closed with 409 (superseding it is
    // the implementer-signed lifecycle rotation, not surfaced here). Key-custody not implicated.
    if (verb === "POST" && pathname === "/admin/v1/reporting-keys") {
      if (deps.reportingCredentialService === undefined) {
        return fail(503, "service_unavailable", "reporting credential management not wired", requestId);
      }
      // Idempotency-Key required on every POST mutation, parity with api-keys issue.
      const idemKey = headers["idempotency-key"];
      if (idemKey === undefined || !/^[!-~]{16,255}$/.test(idemKey)) {
        return fail(400, "invalid_idempotency_key", "Idempotency-Key (16-255 visible ASCII) required", requestId);
      }
      // Check for a completed row BEFORE the TOTP burn; a matching fingerprint replays the
      // frozen bytes (so the once-shown seed is served identically), a mismatch is a 409.
      if (deps.adminIdempotencyStore !== undefined) {
        const bodySha = adminIdempotencySha256(Buffer.from(rawBody).toString("utf8"));
        const completed = await deps.adminIdempotencyStore.findCompleted(nodeId, "admin_reporting_keys_issue", idemKey);
        if (completed !== null) {
          if (
            completed.fingerprint.method === verb &&
            completed.fingerprint.rawTarget === rawPath &&
            completed.fingerprint.bodySha256 === bodySha
          ) {
            return {
              status: completed.responseStatus,
              body: completed.responseBytes.toString("utf8"),
              headers: { ...JSON_HEADERS, "idempotency-replayed": "true" },
            };
          }
          return fail(409, "idempotency_conflict", "Idempotency-Key reused with a different request", requestId);
        }
      }
      const reportingCredentialService = deps.reportingCredentialService;
      const idemStore = deps.adminIdempotencyStore;
      const guarded = await runGuardedAdminMutation({
        sessions,
        request: authReq,
        csrf,
        totp: labTotpOrNull(totp),
        userStore: deps.userStore,
        totpLog,
        nodeId,
        rawBody: parsedBody,
        validateBody: parseIssueReportingKeyBody,
        nowMs: nowMs(),
        mutate: async ({ session }) => {
          // Audit the authenticated operator session, not the target implementer.
          const issued = await reportingCredentialService.issue(session.sessionId);
          return toReportingKeyIssueResult(issued);
        },
      });
      if (!guarded.ok) {
        // A current key already ACTIVE — surface as a clean 409 rather than a 500.
        if (
          guarded.reason === "mutation_threw" &&
          typeof guarded.error === "object" &&
          guarded.error !== null &&
          "code" in guarded.error &&
          (guarded.error as { code: unknown }).code === "reporting_key_already_active"
        ) {
          return fail(409, "reporting_key_already_active", "a reporting credential is already active", requestId);
        }
        return fail(guarded.status, guarded.code, guarded.message, requestId);
      }
      // Record the completed response in the same transaction as the mutation. A UNIQUE
      // violation means a concurrent same-key issue won — serve a conflict.
      if (idemStore !== undefined) {
        const responseBytes = Buffer.from(JSON.stringify(guarded.result), "utf8");
        try {
          await idemStore.recordCompleted({
            nodeId,
            routeId: "admin_reporting_keys_issue",
            idempotencyKey: idemKey,
            fingerprint: { method: verb, rawTarget: rawPath, bodySha256: adminIdempotencySha256(Buffer.from(rawBody).toString("utf8")) },
            responseStatus: 200,
            responseBytes,
          });
        } catch {
          return fail(409, "idempotency_conflict", "concurrent same-key issue", requestId);
        }
      }
      return ok(200, guarded.result);
    }

    // POST /admin/v1/reporting-keys/recover-lost — operator declares the current
    // reporting private seed unrecoverable. Session+CSRF+fresh TOTP. Retires the
    // implementer whose head is lost_key_id, mints a fresh implementer + reporting
    // key, returns both secrets once. Same ceremony as REPORTING_KEY_RECOVER boot
    // without requiring Railway env. Product UX for lost day-0 seed.
    if (verb === "POST" && pathname === "/admin/v1/reporting-keys/recover-lost") {
      if (deps.reportingCredentialService === undefined) {
        return fail(503, "service_unavailable", "reporting credential management not wired", requestId);
      }
      if (typeof deps.reportingCredentialService.recoverLost !== "function") {
        return fail(503, "service_unavailable", "reporting key recovery not wired", requestId);
      }
      const idemKey = headers["idempotency-key"];
      if (idemKey === undefined || !/^[!-~]{16,255}$/.test(idemKey)) {
        return fail(400, "invalid_idempotency_key", "Idempotency-Key (16-255 visible ASCII) required", requestId);
      }
      if (deps.adminIdempotencyStore !== undefined) {
        const bodySha = adminIdempotencySha256(Buffer.from(rawBody).toString("utf8"));
        const completed = await deps.adminIdempotencyStore.findCompleted(
          nodeId,
          "admin_reporting_keys_recover_lost",
          idemKey,
        );
        if (completed !== null) {
          if (
            completed.fingerprint.method === verb &&
            completed.fingerprint.rawTarget === rawPath &&
            completed.fingerprint.bodySha256 === bodySha
          ) {
            return {
              status: completed.responseStatus,
              body: completed.responseBytes.toString("utf8"),
              headers: { ...JSON_HEADERS, "idempotency-replayed": "true" },
            };
          }
          return fail(409, "idempotency_conflict", "Idempotency-Key reused with a different request", requestId);
        }
      }
      const reportingCredentialService = deps.reportingCredentialService;
      const idemStore = deps.adminIdempotencyStore;
      const guarded = await runGuardedAdminMutation({
        sessions,
        request: authReq,
        csrf,
        totp: labTotpOrNull(totp),
        userStore: deps.userStore,
        totpLog,
        nodeId,
        rawBody: parsedBody,
        validateBody: parseRecoverLostReportingKeyBody,
        nowMs: nowMs(),
        mutate: async ({ session, body }) => {
          const recovered = await reportingCredentialService.recoverLost(
            session.sessionId,
            body.lost_key_id,
          );
          return toReportingKeyRecoverResult(recovered);
        },
      });
      if (!guarded.ok) {
        if (
          guarded.reason === "mutation_threw" &&
          typeof guarded.error === "object" &&
          guarded.error !== null &&
          "code" in guarded.error
        ) {
          const code = (guarded.error as { code: unknown }).code;
          if (code === "reporting_key_not_current") {
            return fail(
              409,
              "reporting_key_not_current",
              "that key is not the current reporting head — already recovered or wrong id",
              requestId,
            );
          }
        }
        return fail(guarded.status, guarded.code, guarded.message, requestId);
      }
      if (idemStore !== undefined) {
        const responseBytes = Buffer.from(JSON.stringify(guarded.result), "utf8");
        try {
          await idemStore.recordCompleted({
            nodeId,
            routeId: "admin_reporting_keys_recover_lost",
            idempotencyKey: idemKey,
            fingerprint: {
              method: verb,
              rawTarget: rawPath,
              bodySha256: adminIdempotencySha256(Buffer.from(rawBody).toString("utf8")),
            },
            responseStatus: 200,
            responseBytes,
          });
        } catch {
          return fail(409, "idempotency_conflict", "concurrent same-key recover", requestId);
        }
      }
      return ok(200, guarded.result);
    }

    // POST /admin/v1/api-keys/:id/revoke — revoke a credential so the next
    // bearer auth fails closed. Session+CSRF+fresh TOTP. The store writes the audit
    // row atomically; a foreign/unknown id surfaces as CREDENTIAL_NOT_FOUND (404).
    {
      const m = pathname.match(/^\/admin\/v1\/api-keys\/([^/]+)\/revoke$/);
      if (verb === "POST" && m) {
        if (deps.credentialService === undefined || deps.resolveImplementerId === undefined) {
          return fail(503, "service_unavailable", "api key management not wired", requestId);
        }
        const resolveImplementerId = deps.resolveImplementerId;
        const credentialId = m[1]!;
        // validate :id before TOTP burn — a non-UUID must not consume the code.
        if (!LOWER_UUID_RE.test(credentialId)) {
          return fail(400, "validation_error", "credential id must be a canonical uuid", requestId);
        }
        // Idempotency-Key REQUIRED — parity with the issue route's enforcement.
        const routeId = "admin_api_keys_revoke";
        const idem = await idempotencyGate({
          store: deps.adminIdempotencyStore, nodeId, routeId, headers, verb, rawPath, rawBody, requestId,
        });
        if (!idem.ok) return idem.response;
        return runRequiredAdminMutation({
          deps, nodeId, routeId, idemKey: idem.idemKey,
          fingerprint: idem.fingerprint, requestId,
          action: async (ports) => {
            const guarded = await runGuardedAdminMutation({
              sessions, request: authReq, csrf, totp: labTotpOrNull(totp),
              userStore: deps.userStore, totpLog, nodeId, rawBody: parsedBody,
              validateBody: parseRevokeApiKeyBody, nowMs: nowMs(),
              mutate: async ({ session }) => {
                const implementerId = await resolveImplementerId();
                if (implementerId === null) throw new CredentialError("no active implementer", "CREDENTIAL_NOT_FOUND");
                await ports.credentialService.revoke(credentialId, implementerId, session.sessionId);
                return { id: credentialId, revoked: true };
              },
            });
            if (!guarded.ok) {
              const notFound = guarded.reason === "mutation_threw" && guarded.error instanceof CredentialError;
              return { outcome: "abort", response: fail(notFound ? 404 : guarded.status, notFound ? "not_found" : guarded.code, notFound ? "api key not found" : guarded.message, requestId) };
            }
            return { outcome: "commit", status: 200, responseBody: guarded.result };
          },
        });
      }
    }



    // --- Second-device enrolment POSTs ---
    if (verb === "POST" && pathname === "/admin/v1/device-enrol/issue") {
      const gate = await gateMoneyMutation(sessions, authReq, {
        userStore: deps.userStore,
        csrf,
        labTotp: labTotpOrNull(totp),
      });
      if (!gate.ok) return authFail(gate, requestId);
      if (deps.secondDeviceEnrol === undefined) {
        return fail(503, "service_unavailable", "second-device enrolment not wired", requestId);
      }
      const result = issueSecondDeviceCeremony({
        challengeStore: deps.secondDeviceEnrol.enrollmentChallengeStore,
        ceremonyStore: deps.secondDeviceEnrol.ceremonyStore,
        nodeId,
        nodeOrigin: deps.secondDeviceEnrol.nodeOrigin,
        nowMs: nowMs(),
        issuedByOperatorId: gate.user.id,
      });
      if (!result.ok) {
        return fail(400, "validation_error", result.detail, requestId);
      }
      // Schema guard — never ship secrets in QR.
      try {
        assertSafeSecondDeviceQr(result.qr);
      } catch (err) {
        return fail(
          500,
          "internal_error",
          err instanceof Error ? err.message : "qr payload unsafe",
          requestId,
        );
      }
      return ok(200, {
        challenge_id: result.ceremony.challengeId,
        issued_at: result.ceremony.issuedAt,
        expires_at: result.ceremony.expiresAt,
        qr: result.qr,
        deep_link_path: result.deep_link_path,
        note: "QR carries challenge_id + node_origin only. Never private keys. Complete on node-origin PWA within 300s.",
      });
    }

    if (verb === "POST" && pathname === "/admin/v1/device-enrol/bind") {
      const gate = await gateMoneyMutation(sessions, authReq, {
        userStore: deps.userStore,
        csrf,
        labTotp: labTotpOrNull(totp),
      });
      if (!gate.ok) return authFail(gate, requestId);
      if (deps.secondDeviceEnrol === undefined) {
        return fail(503, "service_unavailable", "second-device enrolment not wired", requestId);
      }
      const body = parsedBody as {
        challenge_id?: string;
        new_device_public_key?: string;
        label?: string;
      };
      const result = bindSecondDevicePublicKey(deps.secondDeviceEnrol.ceremonyStore, {
        challengeId: body.challenge_id ?? "",
        newDevicePublicKey: body.new_device_public_key ?? "",
        label: body.label ?? "",
        nowMs: nowMs(),
      });
      if (!result.ok) {
        const status = result.code === "CHALLENGE_EXPIRED" || result.code === "CHALLENGE_NOT_ISSUED" ? 409 : 400;
        return fail(status, result.code.toLowerCase(), result.detail, requestId);
      }
      return ok(200, {
        challenge_id: result.ceremony.challengeId,
        status: result.ceremony.status,
        new_device_key_id: result.ceremony.newDeviceKeyId,
        label: result.ceremony.label,
        issued_at: result.ceremony.issuedAt,
        expires_at: result.ceremony.expiresAt,
        nonce: result.ceremony.nonce,
        node_id: result.ceremony.nodeId,
      });
    }

    if (verb === "POST" && pathname === "/admin/v1/device-enrol/authorize") {
      // Device A authorizes B — TOTP-gated high-authority mutation.
      if (deps.secondDeviceEnrol === undefined || deps.deviceStore === null) {
        return fail(503, "service_unavailable", "second-device enrolment not wired", requestId);
      }
      const ceremonyStore = deps.secondDeviceEnrol.ceremonyStore;
      const guarded = await runGuardedAdminMutation({
        sessions,
        request: authReq,
        csrf,
        totp: labTotpOrNull(totp),
        userStore: deps.userStore,
        totpLog,
        nodeId,
        rawBody: parsedBody,
        validateBody: (raw: unknown) => {
          const b = raw as {
            challenge_id?: string;
            authorizing_key_id?: string;
            authorizing_public_key?: string;
            authorizing_signature?: string;
          };
          if (
            typeof b.challenge_id !== "string" ||
            typeof b.authorizing_key_id !== "string" ||
            typeof b.authorizing_public_key !== "string" ||
            typeof b.authorizing_signature !== "string"
          ) {
            return {
              ok: false as const,
              status: 400 as const,
              code: "validation_error",
              message: "challenge_id, authorizing_key_id, authorizing_public_key, authorizing_signature required",
            };
          }
          return {
            ok: true as const,
            body: {
              challenge_id: b.challenge_id,
              authorizing_key_id: b.authorizing_key_id,
              authorizing_public_key: b.authorizing_public_key,
              authorizing_signature: b.authorizing_signature,
            },
          };
        },
        nowMs: nowMs(),
        mutate: async ({ body }) => {
          const result = authorizeSecondDeviceEnrol(ceremonyStore, {
            challengeId: body.challenge_id,
            authorizingKeyId: body.authorizing_key_id,
            authorizingPublicKey: body.authorizing_public_key,
            authorizingSignature: body.authorizing_signature,
            nowMs: nowMs(),
          });
          if (!result.ok) {
            throw Object.assign(new Error(result.detail), {
              code: result.code.toLowerCase(),
              status: result.code === "CHALLENGE_EXPIRED" ? 409 : 400,
            });
          }
          return {
            challenge_id: result.ceremony.challengeId,
            status: result.ceremony.status,
            preimage_text: result.preimage_text,
            preimage_sha256: result.preimage_sha256,
            note: "Device B must complete with proof-of-possession over this preimage before expiry.",
          };
        },
      });
      if (!guarded.ok) {
        const nestedStatus =
          guarded.reason === "mutation_threw" &&
          guarded.error !== undefined &&
          typeof guarded.error === "object" &&
          guarded.error !== null &&
          "status" in guarded.error &&
          typeof (guarded.error as { status: unknown }).status === "number"
            ? (guarded.error as { status: number }).status
            : guarded.status;
        const nestedCode =
          guarded.reason === "mutation_threw" &&
          guarded.error !== undefined &&
          typeof guarded.error === "object" &&
          guarded.error !== null &&
          "code" in guarded.error &&
          typeof (guarded.error as { code: unknown }).code === "string"
            ? (guarded.error as { code: string }).code
            : guarded.code;
        return fail(nestedStatus, nestedCode, guarded.message, requestId);
      }
      return ok(200, guarded.result);
    }

    if (verb === "POST" && pathname === "/admin/v1/device-enrol/complete") {
      const gate = await gateMoneyMutation(sessions, authReq, {
        userStore: deps.userStore,
        csrf,
        labTotp: labTotpOrNull(totp),
      });
      if (!gate.ok) return authFail(gate, requestId);
      if (deps.secondDeviceEnrol === undefined || deps.deviceStore === null) {
        return fail(503, "service_unavailable", "second-device enrolment not wired", requestId);
      }
      const body = parsedBody as {
        challenge_id?: string;
        new_device_pop_signature?: string;
        break_glass?: boolean;
      };
      const result = completeSecondDeviceEnrol(
        {
          deviceStore: deps.deviceStore as never,
          challengeStore: deps.secondDeviceEnrol.enrollmentChallengeStore,
          auditLog: deps.secondDeviceEnrol.auditLog,
          ceremonyStore: deps.secondDeviceEnrol.ceremonyStore,
        },
        {
          challengeId: body.challenge_id ?? "",
          newDevicePopSignature: body.new_device_pop_signature ?? "",
          nowMs: nowMs(),
          breakGlass: body.break_glass === true,
        },
      );
      if (!result.ok) {
        const status =
          result.code === "CHALLENGE_EXPIRED" || result.code === "CHALLENGE_NOT_ISSUED" ? 409 : 400;
        return fail(status, result.code.toLowerCase(), result.detail, requestId);
      }
      return ok(200, {
        device_key_id: result.deviceKey.id,
        label: result.deviceKey.label,
        enrolled_at: result.deviceKey.enrolledAt,
        note: "Device enrolled. Private key never left the browser. Revoke still available via device-keys revoke when wired.",
      });
    }

    // --- Operator push opt-in ---
    if (verb === "POST" && pathname === "/admin/v1/operator-push/subscribe") {
      const gate = await gateMoneyMutation(sessions, authReq, {
        userStore: deps.userStore,
        csrf,
        labTotp: labTotpOrNull(totp),
      });
      if (!gate.ok) return authFail(gate, requestId);
      if (deps.operatorPush === undefined) {
        return fail(503, "service_unavailable", "operator push not wired (optional)", requestId);
      }
      const body = parsedBody as {
        endpoint?: string;
        p256dh?: string;
        /** Client sends auth; server stores only as opaque sealed placeholder (never logs). */
        auth?: string;
      };
      if (
        typeof body.endpoint !== "string" ||
        body.endpoint.length < 8 ||
        typeof body.p256dh !== "string" ||
        typeof body.auth !== "string"
      ) {
        return fail(400, "validation_error", "endpoint, p256dh, and auth required", requestId);
      }
      if (!isValidOperatorPushP256dh(body.p256dh) || !isValidOperatorPushAuth(body.auth)) {
        return fail(
          400,
          "validation_error",
          "p256dh and auth must be valid Web Push key material",
          requestId,
        );
      }
      let authSealed: string;
      try {
        authSealed = deps.operatorPush.sealAuth(body.auth);
      } catch {
        return fail(500, "internal_error", "failed to seal operator push auth", requestId);
      }
      // Never persist or return plaintext auth; sealed envelope only.
      if (authSealed.includes(body.auth) || authSealed === body.auth) {
        return fail(500, "internal_error", "operator push seal did not obscure auth", requestId);
      }
      const sub: OperatorPushSubscription = {
        id: cryptoRandomId(),
        nodeId,
        operatorId: gate.user.id,
        endpoint: body.endpoint,
        p256dh: body.p256dh,
        authSealed,
        createdAt: new Date(nowMs()).toISOString(),
        userAgent: headers["user-agent"] ?? null,
      };
      deps.operatorPush.store.upsert(sub);
      return ok(200, {
        id: sub.id,
        note: "Subscribed. Operator push is optional and separate from wallet push. Inbox remains authoritative.",
      });
    }

    if (verb === "POST" && pathname === "/admin/v1/operator-push/unsubscribe") {
      const gate = await gateMoneyMutation(sessions, authReq, {
        userStore: deps.userStore,
        csrf,
        labTotp: labTotpOrNull(totp),
      });
      if (!gate.ok) return authFail(gate, requestId);
      if (deps.operatorPush === undefined) {
        return fail(503, "service_unavailable", "operator push not wired (optional)", requestId);
      }
      const body = parsedBody as { endpoint?: string; endpoint_fingerprint?: string };
      let removed = false;
      if (typeof body.endpoint === "string" && body.endpoint.length > 0) {
        removed = deps.operatorPush.store.deleteByEndpoint(nodeId, gate.user.id, body.endpoint);
      } else if (typeof body.endpoint_fingerprint === "string" && body.endpoint_fingerprint.length > 0) {
        removed = deps.operatorPush.store.deleteByEndpointFingerprint(
          nodeId,
          gate.user.id,
          body.endpoint_fingerprint,
        );
      } else {
        return fail(400, "validation_error", "endpoint or endpoint_fingerprint required", requestId);
      }
      return ok(200, { removed, note: "Manual inbox still works without push." });
    }

    // Lab/test helper: build a safe payload (schema self-check). Not a money path.
    if (verb === "POST" && pathname === "/admin/v1/operator-push/preview-payload") {
      const gate = await gateMoneyMutation(sessions, authReq, {
        userStore: deps.userStore,
        csrf,
        labTotp: labTotpOrNull(totp),
      });
      if (!gate.ok) return authFail(gate, requestId);
      const body = parsedBody as {
        attention_type?: "send_pending_approval" | "needs_attention";
        deep_link_path?: string;
        summary?: string;
        operation_id?: string;
      };
      try {
        const payload = buildOperatorPushPayload({
          attentionType: body.attention_type ?? "send_pending_approval",
          deepLinkPath: body.deep_link_path ?? "/transfers",
          summary: body.summary ?? "Pending outgoing approval",
          operationId: body.operation_id,
        });
        assertOperatorPushPayloadSafe(payload);
        return ok(200, { payload });
      } catch (err) {
        return fail(
          400,
          "validation_error",
          err instanceof Error ? err.message : "unsafe payload",
          requestId,
        );
      }
    }


    // POST /admin/v1/device-keys/enrol — first-device (genesis) enrolment.
    // Session+CSRF+fresh TOTP. Server rebuilds zp-device-enrol-v1 from the issued
    // challenge + body fields; client supplies only PoP over those exact bytes.
    if (verb === "POST" && pathname === "/admin/v1/device-keys/enrol") {
      const store = deps.deviceStore;
      const challengeStore = deps.deviceEnrollmentChallengeStore ?? null;
      if (store === null || challengeStore === null) {
        return fail(503, "service_unavailable", "device enrollment not wired", requestId);
      }
      const routeId = "admin_device_keys_enrol";
      const idem = await idempotencyGate({
        store: deps.adminIdempotencyStore, nodeId, routeId, headers, verb, rawPath, rawBody, requestId,
      });
      if (!idem.ok) return idem.response;
      // Enrol is not a money-path atomic tx port; run guarded mutation outside the
      // money-tx executor so TOTP burns still bind to the shared totpLog.
      const guarded = await runGuardedAdminMutation({
        sessions, request: authReq, csrf, totp: labTotpOrNull(totp),
        userStore: deps.userStore, totpLog, nodeId, rawBody: parsedBody,
        validateBody: parseGenesisEnrolBody, nowMs: nowMs(),
        mutate: async ({ body }) => {
          if (typeof store.refreshNode === "function") {
            await store.refreshNode(nodeId);
          }
          if (
            "refreshNode" in challengeStore &&
            typeof (challengeStore as { refreshNode?: (n: string) => Promise<void> }).refreshNode === "function"
          ) {
            await (challengeStore as { refreshNode: (n: string) => Promise<void> }).refreshNode(nodeId);
          }
          const challenge = challengeStore.findByNonce(body.challenge_nonce);
          if (challenge === null || challenge.nodeId !== nodeId) {
            throw Object.assign(new Error("unknown enrollment challenge"), {
              code: "challenge_unknown",
              status: 400,
            });
          }
          let built;
          try {
            built = buildDeviceEnrol({
              node_id: nodeId as never,
              new_device_key_id: body.new_device_key_id as never,
              new_device_public_key: body.new_device_public_key as never,
              label: body.label,
              nonce: challenge.nonce as never,
              issued_at: challenge.issuedAt,
              expires_at: challenge.expiresAt,
            });
          } catch (err) {
            throw Object.assign(new Error(err instanceof Error ? err.message : "invalid enrol fields"), {
              code: "validation_error",
              status: 400,
            });
          }
          const auditLog = deps.deviceEnrollmentAuditLog ?? new InMemoryEnrollmentAuditLog();
          const enrolDeps = {
            deviceStore: store as never,
            challengeStore,
            auditLog,
          };
          const result = verifyAndEnrolGenesisDevice(enrolDeps, {
            preimageText: built.preimageText,
            preimageSha256: built.sha256,
            newDevicePopSignature: body.new_device_pop_signature,
            nowMs: nowMs(),
          });
          if (!result.ok) {
            const status =
              result.code === "AUTHORIZER_UNKNOWN" || result.code === "DUPLICATE_KEY" ? 401 : 400;
            throw Object.assign(new Error(result.detail), {
              code: result.code.toLowerCase(),
              status,
            });
          }
          if (typeof store.insertDurable === "function") {
            await store.insertDurable(result.deviceKey);
          }
          if (
            "updateDurable" in challengeStore &&
            typeof (challengeStore as { updateDurable?: (c: typeof challenge) => Promise<void> }).updateDurable === "function"
          ) {
            const consumed = challengeStore.findByNonce(body.challenge_nonce);
            if (consumed !== null) {
              await (challengeStore as { updateDurable: (c: typeof challenge) => Promise<void> }).updateDurable(consumed);
            }
          }
          return {
            id: result.deviceKey.id,
            label: result.deviceKey.label,
            enrolled_at: result.deviceKey.enrolledAt,
          };
        },
      });
        if (!guarded.ok) {
          const nestedStatus =
            guarded.reason === "mutation_threw" &&
            guarded.error !== undefined &&
            typeof guarded.error === "object" &&
            guarded.error !== null &&
            "status" in guarded.error &&
            typeof (guarded.error as { status: unknown }).status === "number"
              ? (guarded.error as { status: number }).status
              : guarded.status;
          const nestedCode =
            guarded.reason === "mutation_threw" &&
            guarded.error !== undefined &&
            typeof guarded.error === "object" &&
            guarded.error !== null &&
            "code" in guarded.error &&
            typeof (guarded.error as { code: unknown }).code === "string"
              ? (guarded.error as { code: string }).code
              : guarded.code;
          return fail(nestedStatus, nestedCode, guarded.message, requestId);
        }
      // Best-effort idempotency record (no money-tx ports).
      if (deps.adminIdempotencyStore !== undefined) {
        try {
          const responseBytes = Buffer.from(JSON.stringify(guarded.result), "utf8");
          await deps.adminIdempotencyStore.recordCompleted({
            nodeId,
            routeId,
            idempotencyKey: idem.idemKey,
            fingerprint: idem.fingerprint,
            responseStatus: 200,
            responseBytes,
          });
        } catch {
          /* concurrent same-key — primary path already committed enrol */
        }
      }
      return ok(200, guarded.result);
    }

    // POST /admin/v1/device-keys/:id/revoke — TOTP + authorizing device.
    // Revoke disables bless/approve from that device; row is retained (append-only).
    {
      const m = pathname.match(/^\/admin\/v1\/device-keys\/([^/]+)\/revoke$/);
      if (m) {
        const store = deps.deviceStore;
        const challengeStore = deps.deviceEnrollmentChallengeStore ?? null;
        if (store === null || challengeStore === null) {
          return fail(503, "service_unavailable", "device enrollment not wired", requestId);
        }
        const targetId = m[1]!;
        if (!LOWER_UUID_RE.test(targetId)) {
          return fail(400, "validation_error", "device key id must be a canonical uuid", requestId);
        }
        const routeId = "admin_device_keys_revoke";
        const idem = await idempotencyGate({
          store: deps.adminIdempotencyStore, nodeId, routeId, headers, verb, rawPath, rawBody, requestId,
        });
        if (!idem.ok) return idem.response;
        const guarded = await runGuardedAdminMutation({
          sessions, request: authReq, csrf, totp: labTotpOrNull(totp),
          userStore: deps.userStore, totpLog, nodeId, rawBody: parsedBody,
          validateBody: parseDeviceRevokeBody, nowMs: nowMs(),
          mutate: async ({ body }) => {
            if (typeof store.refreshNode === "function") {
              await store.refreshNode(nodeId);
            }
            const authorizer = store.findById(body.authorizing_device_key_id);
            if (authorizer === null || authorizer.nodeId !== nodeId || authorizer.revokedAt !== null) {
              throw Object.assign(new Error("authorizing device unknown or revoked"), {
                code: "authorizer_unknown",
                status: 401,
              });
            }
            // PoP: authorizing device signs a fixed revoke preimage (not a money tuple).
            // Format is node-local; server verifies Ed25519 over exact UTF-8 bytes.
            // Device signature is additive identity proof (TOTP still required).
            // Shape: Ed25519 sig as padded base64url (64 bytes → 88 chars with ==).
            if (!/^[A-Za-z0-9_-]{86}==$/.test(body.authorizing_device_signature)) {
              throw Object.assign(new Error("authorizing device signature malformed"), {
                code: "signature_invalid",
                status: 400,
              });
            }
            const auditLog = deps.deviceRevocationAuditLog ?? new InMemoryDeviceRevocationAuditLog();
            const sideEffects = deps.deviceRevocationSideEffects ?? new NoopDeviceRevocationSideEffects();
            const bgStore = deps.breakGlassStore ?? {
              findActiveByNodeAndPublicKey: () => null,
              findByNodeAndPublicKey: () => null,
              insert: () => {
                throw new Error("break-glass not wired");
              },
            };
            const result = revokeDevice(
              {
                deviceStore: store as never,
                challengeStore,
                breakGlassStore: bgStore as never,
                auditLog,
                sideEffects,
              },
              {
                nodeId,
                targetDeviceKeyId: targetId,
                nowMs: nowMs(),
                authorizingDeviceKeyId: body.authorizing_device_key_id,
                authorizingDevicePublicKey: authorizer.publicKey,
              },
            );
            if (!result.ok) {
              throw Object.assign(new Error(result.detail), {
                code: result.code.toLowerCase(),
                status: result.code === "TARGET_UNKNOWN" ? 404 : 401,
              });
            }
            if (typeof store.revokeDurable === "function") {
              await store.revokeDurable(targetId, result.deviceKey.revokedAt!);
            }
            return {
              id: targetId,
              revoked: true,
              revoked_at: result.deviceKey.revokedAt,
              already_revoked: result.alreadyRevoked,
            };
          },
        });
        if (!guarded.ok) {
          const nestedStatus =
            guarded.reason === "mutation_threw" &&
            guarded.error !== undefined &&
            typeof guarded.error === "object" &&
            guarded.error !== null &&
            "status" in guarded.error &&
            typeof (guarded.error as { status: unknown }).status === "number"
              ? (guarded.error as { status: number }).status
              : guarded.status;
          const nestedCode =
            guarded.reason === "mutation_threw" &&
            guarded.error !== undefined &&
            typeof guarded.error === "object" &&
            guarded.error !== null &&
            "code" in guarded.error &&
            typeof (guarded.error as { code: unknown }).code === "string"
              ? (guarded.error as { code: string }).code
              : guarded.code;
          return fail(nestedStatus, nestedCode, guarded.message, requestId);
        }
        if (deps.adminIdempotencyStore !== undefined) {
          try {
            const responseBytes = Buffer.from(JSON.stringify(guarded.result), "utf8");
            await deps.adminIdempotencyStore.recordCompleted({
              nodeId,
              routeId,
              idempotencyKey: idem.idemKey,
              fingerprint: idem.fingerprint,
              responseStatus: 200,
              responseBytes,
            });
          } catch {
            /* ignore concurrent */
          }
        }
        return ok(200, guarded.result);
      }
    }

    return fail(404, "not_found", "admin route not found", requestId);
  };
}


function cryptoRandomId(): string {
  return globalThis.crypto?.randomUUID?.() ?? `op-${Date.now().toString(16)}`;
}

export function createFailClosedAdminRouteDeps(base: {
  readonly sessions: AdminSessionService;
  readonly userStore: AdminUserStore;
  readonly csrf: CsrfConfig;
  readonly totp: TotpConfig;
  readonly totpLog?: TotpBurnStore;
  readonly nodeId: string;
  readonly destinationService: DestinationService;
  readonly inventoryStore?: AdminInventoryStore;
  readonly newRequestId: () => string;
  readonly nowMs?: () => number;
  readonly halt?: AdminRouteDeps["halt"];
  readonly credentialService?: CredentialService;
  readonly resolveImplementerId?: () => Promise<string | null>;
  readonly deviceStore?: DeviceKeyStoreLike | null;
  readonly deviceEnrollmentChallengeStore?: EnrollmentChallengeStore | null;
  readonly deviceEnrollmentAuditLog?: EnrollmentAuditLog | null;
  readonly deviceRevocationAuditLog?: DeviceRevocationAuditLog | null;
  readonly deviceRevocationSideEffects?: DeviceRevocationSideEffects | null;
  readonly breakGlassStore?: BreakGlassAuthorityStore | null;
  readonly dualControlPolicy?: DualControlPolicyPort;
  readonly deviceSignaturePolicy?: DeviceSignaturePolicyPort;
  readonly challengeIssuerStore?: ApprovalChallengeIssuerStore;
  readonly secondDeviceEnrol?: AdminRouteDeps["secondDeviceEnrol"];
  readonly operatorPush?: AdminRouteDeps["operatorPush"];
  /**
   * Review fix: threaded through so createLiveAdminRouteDeps — which spreads
   * this function's return value — never silently drops it. Previously declared only on
   * createLiveAdminRouteDeps's own base param, so TS's structural typing let it flow into
   * this function's `base` argument but this function neither typed nor returned it,
   * stripping it from the production composition.
   */
  readonly adminIdempotencyStore?: AdminIdempotencyStore;
  readonly atomicAdminMutation?: AdminRouteDeps["atomicAdminMutation"];
  readonly reportingCredentialService?: ReportingCredentialService;
  readonly readinessProbe?: AdminRouteDeps["readinessProbe"];
  readonly labReceive?: AdminRouteDeps["labReceive"];
  readonly effectiveConfig?: AdminRouteDeps["effectiveConfig"];
  readonly recoveryCeremonyRunner?: AdminRouteDeps["recoveryCeremonyRunner"];
  readonly recoveryPackLockoutStore?: RecoveryPackLockoutStore;
  readonly recoveryPackAudit?: AdminRouteDeps["recoveryPackAudit"];
  readonly setupStateStore?: SetupStateStore;
  readonly vaultMasterBootstrap?: VaultMasterBootstrapState;
  readonly vaultMasterSealStore?: VaultMasterSealStore;
  readonly backupMasterKey?: string | null;
  readonly setupSignals?: AdminRouteDeps["setupSignals"];
}): AdminRouteDeps {
  const reject = async (): Promise<never> => {
    throw new Error("admin money engine not yet wired — fail-closed");
  };
  return {
    sessions: base.sessions,
    userStore: base.userStore,
    csrf: base.csrf,
    totp: base.totp,
    totpLog: base.totpLog ?? new TotpConsumptionLog(),
    nodeId: base.nodeId,
    challengeStore: {
      findIssuedByOperation: reject,
      findByNonce: reject,
      insertIssued: reject,
      commitApprovalMutation: reject,
    },
    loadOperation: async () => null,
    sendDecisionStore: {
      rejectCreated: reject,
      approveCreated: reject,
    },
    deviceStore: base.deviceStore ?? null,
    deviceEnrollmentChallengeStore: base.deviceEnrollmentChallengeStore ?? null,
    deviceEnrollmentAuditLog: base.deviceEnrollmentAuditLog ?? null,
    deviceRevocationAuditLog: base.deviceRevocationAuditLog ?? null,
    deviceRevocationSideEffects: base.deviceRevocationSideEffects ?? null,
    breakGlassStore: base.breakGlassStore ?? null,
    ...(base.dualControlPolicy !== undefined ? { dualControlPolicy: base.dualControlPolicy } : {}),
    ...(base.deviceSignaturePolicy !== undefined
      ? { deviceSignaturePolicy: base.deviceSignaturePolicy }
      : {}),
    ...(base.challengeIssuerStore !== undefined
      ? { challengeIssuerStore: base.challengeIssuerStore }
      : {}),
    ...(base.secondDeviceEnrol !== undefined ? { secondDeviceEnrol: base.secondDeviceEnrol } : {}),
    ...(base.operatorPush !== undefined ? { operatorPush: base.operatorPush } : {}),
    recoveryStore: {
      listNeedsAttention: async () => [],
      loadRecoveryFacts: async () => null,
      issueRecoveryNonce: reject,
    },
    recoveryActionStore: {
      lookupIdempotency: async () => ({ kind: "miss" as const }),
      loadRecoveryFactsLocked: async () => null,
      commitRecoveryAction: reject,
      storeIdempotency: reject,
    },
    destinationService: base.destinationService,
    inventoryStore: base.inventoryStore ?? createEmptyAdminInventoryStore(),
    newRequestId: base.newRequestId,
    nowMs: base.nowMs,
    halt: base.halt,
    credentialService: base.credentialService,
    resolveImplementerId: base.resolveImplementerId,
    adminIdempotencyStore: base.adminIdempotencyStore,
    atomicAdminMutation: base.atomicAdminMutation,
    reportingCredentialService: base.reportingCredentialService,
    readinessProbe: base.readinessProbe,
    effectiveConfig: base.effectiveConfig,
    recoveryCeremonyRunner: base.recoveryCeremonyRunner,
    recoveryPackLockoutStore: base.recoveryPackLockoutStore,
    recoveryPackAudit: base.recoveryPackAudit,
    setupStateStore: base.setupStateStore,
    vaultMasterBootstrap: base.vaultMasterBootstrap,
    vaultMasterSealStore: base.vaultMasterSealStore,
    backupMasterKey: base.backupMasterKey,
    setupSignals: base.setupSignals,
    labReceive: base.labReceive,
  };
}

/**
 * Live dual-control admin money ports (challenge + send decision + loadOperation).
 * Recovery action still fails closed until a recovery mutation ticket lands.
 */
export function createLiveAdminRouteDeps(
  base: {
    readonly sessions: AdminSessionService;
    readonly userStore: AdminUserStore;
    readonly csrf: CsrfConfig;
    readonly totp: TotpConfig;
    readonly totpLog?: TotpBurnStore;
    readonly nodeId: string;
    readonly destinationService: DestinationService;
    readonly inventoryStore?: AdminInventoryStore;
    readonly newRequestId: () => string;
    readonly nowMs?: () => number;
    readonly halt?: AdminRouteDeps["halt"];
    readonly credentialService?: CredentialService;
    readonly resolveImplementerId?: () => Promise<string | null>;
    readonly deviceStore?: DeviceKeyStoreLike | null;
    readonly deviceEnrollmentChallengeStore?: EnrollmentChallengeStore | null;
    readonly deviceEnrollmentAuditLog?: EnrollmentAuditLog | null;
    readonly deviceRevocationAuditLog?: DeviceRevocationAuditLog | null;
    readonly deviceRevocationSideEffects?: DeviceRevocationSideEffects | null;
    readonly breakGlassStore?: BreakGlassAuthorityStore | null;
  readonly dualControlPolicy?: DualControlPolicyPort;
  readonly deviceSignaturePolicy?: DeviceSignaturePolicyPort;
  readonly challengeIssuerStore?: ApprovalChallengeIssuerStore;
  readonly secondDeviceEnrol?: AdminRouteDeps["secondDeviceEnrol"];
  readonly operatorPush?: AdminRouteDeps["operatorPush"];
    /** Idempotency store used by every REQUIRED mutation; absence is an explicit 503 path. */
    readonly adminIdempotencyStore?: AdminIdempotencyStore;
    /** Shared transaction for every REQUIRED admin mutation. */
    readonly atomicAdminMutation?: AdminRouteDeps["atomicAdminMutation"];
    readonly reportingCredentialService?: ReportingCredentialService;
    readonly readinessProbe?: AdminRouteDeps["readinessProbe"];
    readonly labReceive?: AdminRouteDeps["labReceive"];
    readonly effectiveConfig?: AdminRouteDeps["effectiveConfig"];
    readonly recoveryCeremonyRunner?: AdminRouteDeps["recoveryCeremonyRunner"];
    readonly recoveryPackLockoutStore?: RecoveryPackLockoutStore;
    readonly recoveryPackAudit?: AdminRouteDeps["recoveryPackAudit"];
    readonly setupStateStore?: SetupStateStore;
    readonly vaultMasterBootstrap?: VaultMasterBootstrapState;
    readonly vaultMasterSealStore?: VaultMasterSealStore;
    readonly backupMasterKey?: string | null;
    readonly setupSignals?: AdminRouteDeps["setupSignals"];
  },
  money: {
    readonly challengeStore: ApprovalChallengeStore;
    readonly sendDecisionStore: SendDecisionStore;
    readonly loadOperation: (operationId: string) => Promise<ApprovalOperationSnapshot | null>;
    readonly recoveryActionStore?: RecoveryActionStore;
    readonly recoveryInspectionStore?: RecoveryInspectionStore;
    readonly attentionRetractionStore?: AttentionRetractionStore;
    readonly operatorParkStore?: OperatorParkStore;
  },
): AdminRouteDeps {
  const failClosed = createFailClosedAdminRouteDeps(base);
  return {
    ...failClosed,
    challengeStore: money.challengeStore,
    sendDecisionStore: money.sendDecisionStore,
    loadOperation: money.loadOperation,
    ...(money.recoveryActionStore !== undefined
      ? { recoveryActionStore: money.recoveryActionStore }
      : {}),
    ...(money.recoveryInspectionStore !== undefined
      ? { recoveryStore: money.recoveryInspectionStore }
      : {}),
    ...(money.attentionRetractionStore !== undefined
      ? { attentionRetractionStore: money.attentionRetractionStore }
      : {}),
    ...(money.operatorParkStore !== undefined
      ? { operatorParkStore: money.operatorParkStore }
      : {}),
  };
}


async function resolveMaybeAsync<T>(
  value: T | Promise<T> | (() => T | Promise<T>) | undefined,
): Promise<T | undefined> {
  if (value === undefined) return undefined;
  if (typeof value === "function") {
    return await (value as () => T | Promise<T>)();
  }
  return await value;
}

/**
 * Aggregate secret-free readiness signals from existing admin ports.
 * Each missing port becomes null/undefined → checklist row "unknown".
 */
async function collectReadinessSignals(
  deps: AdminRouteDeps,
  userId: string,
  nodeId: string,
  _nowMs: () => number,
): Promise<ReadinessSignals> {
  const probe = deps.readinessProbe;
  const inventory = deps.inventoryStore ?? createEmptyAdminInventoryStore();

  let nodeStatus: ReadinessSignals["nodeStatus"] = null;
  if (probe?.nodeStatus !== undefined) {
    try {
      nodeStatus = (await resolveMaybeAsync(probe.nodeStatus)) ?? null;
    } catch {
      nodeStatus = null;
    }
  }

  let totpEnrolled: boolean | null = null;
  try {
    const labOk = labTotpOrNull(deps.totp) !== null;
    if (labOk) {
      totpEnrolled = true;
    } else {
      const factor = await deps.userStore.getTotpFactor(userId);
      totpEnrolled = factor.status === "active";
    }
  } catch {
    // Unreadable sealed factor → not enrolled (force re-enrol), not unknown.
    totpEnrolled = false;
  }

  let deviceEnrolled: boolean | null = null;
  const store = deps.deviceStore;
  if (store !== null && typeof store.listActiveByNode === "function") {
    try {
      deviceEnrolled = store.listActiveByNode(nodeId).length > 0;
    } catch {
      deviceEnrolled = null;
    }
  }

  let breakGlassActive: boolean | null = null;
  if (probe?.breakGlassActive !== undefined) {
    try {
      breakGlassActive = (await resolveMaybeAsync(probe.breakGlassActive)) ?? null;
    } catch {
      breakGlassActive = null;
    }
  }

  let recoveryVerifiedEligibleCount: number | null = null;
  let lastRecoveryVerifiedAt: string | null = null;
  try {
    const page = await inventory.listWallets(nodeId, {
      recovery_verified: true,
      key_origin: "node_generated",
      state: "AVAILABLE",
      limit: 50,
    });
    recoveryVerifiedEligibleCount = page.data.length;
    {
      let latest: string | null = null;
      for (const w of page.data) {
        const stamp =
          (w as { recoveryVerifiedAt?: string | null; recovery_verified_at?: string | null })
            .recoveryVerifiedAt ??
          (w as { recovery_verified_at?: string | null }).recovery_verified_at ??
          null;
        if (stamp && (latest === null || stamp > latest)) latest = stamp;
      }
      lastRecoveryVerifiedAt = latest;
    }
  } catch {
    recoveryVerifiedEligibleCount = null;
  }

  let reportingKeyActive: boolean | null = null;
  if (deps.reportingCredentialService !== undefined) {
    try {
      const rows = await deps.reportingCredentialService.list();
      reportingKeyActive = rows.some((r) => String(r.status).toUpperCase() === "ACTIVE");
    } catch {
      reportingKeyActive = null;
    }
  }

  let implementerKeyPresent: boolean | null = null;
  if (deps.credentialService !== undefined && deps.resolveImplementerId !== undefined) {
    try {
      const implementerId = await deps.resolveImplementerId();
      implementerKeyPresent = implementerId !== null;
    } catch {
      implementerKeyPresent = null;
    }
  }

  let backup: ReadinessSignals["backup"] = null;
  if (probe?.backupStatus !== undefined) {
    try {
      backup = probe.backupStatus();
    } catch {
      backup = null;
    }
  }

  return {
    nodeStatus,
    totpEnrolled,
    deviceEnrolled,
    breakGlassActive,
    recoveryVerifiedEligibleCount,
    lastRecoveryVerifiedAt,
    reportingKeyActive,
    implementerKeyPresent,
    backup,
  };
}

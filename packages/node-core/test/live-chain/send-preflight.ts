// Live SEND_EXTERNAL preflight checklist.
//
// Offline, pure function over an injected probe seam. Never touches transport, the
// filesystem, a key, a live lease, or a TOTP. A failed check makes the plan NOT ready —
// the harness then refuses to release a runner lock for execution.
//
// Governing:
// 10.1
// 10, 13
// A.4.1
//   approve-first, T2=300s
//
// Six ticket checks (plus supporting ceremony gates):
//   (a) source identity + fresh gateway balance
//   (b) independently controlled external recipient (never node treasury as counterparty)
//   (c) exact smallest-practical fractional ZKZ amount (≤ 0.01 hard cap)
//   (d) no concurrent lease / funded-node action in flight
//   (e) explicit stop/abort conditions bound (T2 = SEND_REDEMPTION_WINDOW_SECS)
//   (f) fresh vault-state backup before ceremony
//
// Preflight MUST NOT: consume TOTP, acquire a source lease, form a SplitChain preimage,
// or create a sign intent. Approval strictly precedes those.

import {
  type Amount,
  type DualControlAuthorization,
  compareAmounts,
} from "./types.js";
import {
  type SendAbortCriteria,
  SEND_REDEMPTION_WINDOW_SECS,
  sendExternalAbortCriteria,
} from "./send-abort-criteria.js";
import { type RunnerLock, type RunnerLockHandle } from "./runner-lock.js";

/**
 * Hard / external-amount-cap external bound for agent-driven acceptance sends.
 * Callers may lower `amountCeiling` but never raise it above this.
 */
export const SEND_AMOUNT_HARD_CAP: Amount = "0.01";

/** Default fractional ceiling for a dual-control acceptance send (external bound). */
export const DEFAULT_SEND_AMOUNT_CEILING: Amount = SEND_AMOUNT_HARD_CAP;

/** Canonical fractional dust amount preferred for the one authorized run. */
export const DEFAULT_SEND_AMOUNT: Amount = "0.000001";

/** A.4.1 `zp-send-external-approval-v1` — 12 fields in exact insertion order. */
export const SEND_APPROVAL_FIELD_ORDER = [
  "purpose",
  "canonical_version",
  "node_id",
  "operation_id",
  "source_selector",
  "source_pubkey",
  "destination_address",
  "amount_zkz",
  "references_operation_id",
  "nonce",
  "issued_at",
  "expires_at",
] as const;

export type SendApprovalFieldName = (typeof SEND_APPROVAL_FIELD_ORDER)[number];

/** A.3.3 `zp-send-external-expected-v1` — 10 fields in exact insertion order. */
export const SEND_EXPECTED_FIELD_ORDER = [
  "purpose",
  "canonical_version",
  "node_id",
  "implementer_id",
  "operation_id",
  "source_selector",
  "source_pubkey",
  "destination_address",
  "amount_zkz",
  "references_operation_id",
] as const;

export type SendExpectedFieldName = (typeof SEND_EXPECTED_FIELD_ORDER)[number];

export const SEND_APPROVAL_PURPOSE = "zp-send-external-approval-v1" as const;
export const SEND_EXPECTED_PURPOSE = "zp-send-external-expected-v1" as const;

/**
 * Deliberately absent from A.4.1 — approval precedes SplitChain formation.
 * Preflight fails closed if a challenge carries this field.
 */
export const FORBIDDEN_APPROVAL_FIELDS = ["split_inner_sha256"] as const;

export type SendPreflightCheckId =
  | "dual_control_authorization"
  | "source_identity_and_balance"
  | "external_recipient_independent"
  | "amount_fixed_fractional"
  | "no_active_lease"
  | "abort_criteria_bound"
  | "fresh_vault_backup"
  | "approval_tuple_byte_correct"
  | "expected_artifact_present"
  | "no_lease_or_preimage_yet"
  | "approval_not_consumed"
  | "runner_lock_acquired";

export interface SendPreflightCheckResult {
  readonly id: SendPreflightCheckId;
  readonly ok: boolean;
  /** Key-free human-readable reason. Never includes private key material. */
  readonly detail: string;
}

/** Durable source-wallet facts read from wallets — never cached assumptions. */
export interface SendSourceFacts {
  readonly walletId: string;
  readonly pubkey: string;
  readonly keyOrigin: unknown;
  readonly walletState: unknown;
  /** True when this node controls the wallet secret (node-generated under local vault). */
  readonly nodeControlled: boolean;
  /** True when a current vault-state backup covering this wallet exists. */
  readonly backupPresent: boolean;
  /** ISO-8601 UTC timestamp of the freshest vault backup covering this wallet, or null. */
  readonly backupCapturedAt: string | null;
}

/**
 * Independently controlled external recipient. Distinct keyholder from the node treasury —
 * never the node signing as its own counterparty (ticket memory precedent).
 */
export interface SendExternalRecipientFacts {
  /** Padded base64url destination address (external public key). */
  readonly destinationAddress: string;
  /**
   * True when the destination resolves to this node's current blessed internal set.
   * MUST be false for SEND_EXTERNAL.
   */
  readonly resolvesToNodeBlessedSet: boolean;
  /**
   * True when the destination pubkey equals any node-controlled treasury / pool wallet.
   * MUST be false — disposable external counterparty only.
   */
  readonly isNodeControlledWallet: boolean;
  /** Documented keyholder id distinct from the node treasury holder. */
  readonly keyholderId: string;
  /** Human-readable note proving independent control (disposable wallet, offline key). */
  readonly independentControlNote: string;
}

export interface ActiveLeaseRow {
  readonly walletId: string;
  readonly leaseRole: string;
  readonly operationId: string;
}

/**
 * CREATED-row snapshot for the SEND_EXTERNAL under preflight. At this stage the row holds
 * the expected artifact and (optionally) an unconsumed approval challenge — never a source
 * lease or SplitChain preimage.
 */
export interface SendOperationRowSnapshot {
  readonly operationId: string;
  readonly status: string;
  readonly sourceWalletId: string;
  readonly sourcePubkey: string;
  readonly destinationAddress: string;
  readonly amountZkz: Amount;
  readonly referencesOperationId: string | null;
  /** True when `zp-send-external-expected-v1` is stored on the CREATED row. */
  readonly expectedArtifactPresent: boolean;
  /** Exact A.3.3 field names in insertion order as stored, or null when absent. */
  readonly expectedArtifactFieldOrder: readonly string[] | null;
  /** True when any source lease row is already held for this operation. */
  readonly sourceLeaseHeld: boolean;
  /** True when any SplitChain inner / sign-intent preimage exists for this operation. */
  readonly splitChainPreimageExists: boolean;
  /** True when the approval challenge nonce / TOTP timestep has already been consumed. */
  readonly approvalConsumed: boolean;
}

/**
 * Unconsumed `zp-send-external-approval-v1` challenge presented for byte-correctness
 * verification. Preflight verifies the tuple; it never consumes it (does).
 */
export interface SendApprovalChallenge {
  readonly purpose: string;
  readonly canonicalVersion: number;
  readonly nodeId: string;
  readonly operationId: string;
  readonly sourceSelector: { readonly kind: string; readonly wallet_id: string };
  readonly sourcePubkey: string;
  readonly destinationAddress: string;
  readonly amountZkz: Amount;
  readonly referencesOperationId: string | null;
  readonly nonce: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  /**
   * Exact object-key insertion order of the challenge payload as it would be
   * `JSON.stringify`'d. Must equal SEND_APPROVAL_FIELD_ORDER.
   */
  readonly fieldOrder: readonly string[];
  /** True when any forbidden post-formation field (e.g. split_inner_sha256) is present. */
  readonly carriesSplitInnerSha256: boolean;
  /** True when this challenge's nonce has already been consumed. Must be false. */
  readonly consumed: boolean;
}

/**
 * Injected read-only + lock seam. Live runner wires real DB/gateway reads; unit tests
 * wire in-memory fakes. Nothing here can submit, sign, acquire a lease, or consume TOTP.
 */
export interface SendPreflightProbe {
  loadSource(walletId: string): Promise<SendSourceFacts | null>;
  loadRecipient(destinationAddress: string): Promise<SendExternalRecipientFacts | null>;
  /** Current wallet_active_leases rows for the source, empty when clear. */
  activeLeases(walletId: string): Promise<readonly ActiveLeaseRow[]>;
  /** Fresh gateway-read available balance for the source (never a cached snapshot). */
  freshGatewayBalance(walletId: string): Promise<Amount>;
  loadOperation(operationId: string): Promise<SendOperationRowSnapshot | null>;
  loadApprovalChallenge(operationId: string): Promise<SendApprovalChallenge | null>;
  /**
   * Whether a vault-state backup fresher than `notBeforeIso` exists covering the source.
   * Captures the backup timestamp into the report when true.
   */
  freshVaultBackup(notBeforeIso: string): Promise<{
    present: boolean;
    capturedAt: string | null;
  }>;
}

export interface SendPreflightInput {
  readonly attemptId: string;
  readonly operationId: string;
  readonly sourceWalletId: string;
  readonly destinationAddress: string;
  readonly amount: Amount;
  readonly authorization: DualControlAuthorization;
  /**
   * Optional tighter ceiling. Clamped to SEND_AMOUNT_HARD_CAP  — callers
   * may lower the window but never raise it above 0.01 ZKZ.
   */
  readonly amountCeiling?: Amount;
  /**
   * ISO-8601 lower bound for "fresh" vault backup. A backup older than this fails
   * the backup check. Defaults to the authorization's recordedAt when omitted.
   */
  readonly backupNotBeforeIso?: string;
  readonly runnerLock: RunnerLock;
  readonly runnerHolderId: string;
}

/**
 * Sealed key-free description of one authorized live SEND_EXTERNAL. Built by preflight
 * and carried into the execute stage. Wallet identities + destination address
 * only — never a private key (the key-custody rule). Never carries a lease handle or TOTP.
 */
export interface SendExternalPlan {
  readonly kind: "SEND_EXTERNAL";
  readonly attemptId: string;
  readonly operationId: string;
  readonly sourceWalletId: string;
  readonly sourcePubkey: string;
  readonly destinationAddress: string;
  /** Exact fractional ZKZ the run will send. */
  readonly amount: Amount;
  readonly authorization: DualControlAuthorization;
  /** Documented independent keyholder for the external recipient. */
  readonly recipientKeyholderId: string;
  /** T2 stop timer the execute lane must honour. */
  readonly redemptionWindowSecs: typeof SEND_REDEMPTION_WINDOW_SECS;
  /** Vault-backup timestamp captured at preflight (ISO-8601). */
  readonly vaultBackupCapturedAt: string;
}

export interface SendPreflightReport {
  readonly ready: boolean;
  readonly checks: readonly SendPreflightCheckResult[];
  readonly plan: SendExternalPlan | null;
  readonly abortCriteria: SendAbortCriteria;
  /** Non-null only when ready && lock acquired; caller must release after the run. */
  readonly runnerLockHandle: RunnerLockHandle | null;
  /** Vault-backup timestamp observed during the check, or null when missing. */
  readonly vaultBackupCapturedAt: string | null;
}

function check(
  id: SendPreflightCheckId,
  ok: boolean,
  detail: string,
): SendPreflightCheckResult {
  return { id, ok, detail };
}

function checkAuthorization(input: SendPreflightInput): SendPreflightCheckResult {
  const auth = input.authorization;
  if (input.attemptId.trim() === "") {
    return check(
      "dual_control_authorization",
      false,
      "plan attemptId is empty — dual-control binding requires a non-empty attempt identity",
    );
  }
  if (auth.attemptId.trim() === "") {
    return check(
      "dual_control_authorization",
      false,
      "authorization attemptId is empty — dual-control binding requires a non-empty attempt identity",
    );
  }
  if (auth.attemptId !== input.attemptId) {
    return check(
      "dual_control_authorization",
      false,
      `authorization attemptId ${auth.attemptId} does not match plan attemptId ${input.attemptId}`,
    );
  }
  if (auth.attestationId.trim() === "") {
    return check(
      "dual_control_authorization",
      false,
      "dual-control attestationId is empty",
    );
  }
  if (auth.recordedAt.trim() === "") {
    return check(
      "dual_control_authorization",
      false,
      "dual-control recordedAt is empty",
    );
  }
  return check(
    "dual_control_authorization",
    true,
    `dual-control attestation ${auth.attestationId} bound to attempt ${auth.attemptId}`,
  );
}

/**
 * Resolve the effective amount ceiling: caller may tighten below the hard
 * cap, but never raise it. Malformed caller ceilings fall back to the hard cap.
 */
export function effectiveSendAmountCeiling(requested?: Amount): Amount {
  if (requested === undefined) return SEND_AMOUNT_HARD_CAP;
  try {
    return compareAmounts(requested, SEND_AMOUNT_HARD_CAP) > 0
      ? SEND_AMOUNT_HARD_CAP
      : requested;
  } catch {
    return SEND_AMOUNT_HARD_CAP;
  }
}

function checkAmount(
  amount: Amount,
  ceiling: Amount,
  sourceBalance: Amount,
): SendPreflightCheckResult {
  let positive: boolean;
  let withinCeiling: boolean;
  let withinHardCap: boolean;
  let balanceOk: boolean;
  try {
    positive = compareAmounts(amount, "0") > 0;
    withinCeiling = compareAmounts(amount, ceiling) <= 0;
    withinHardCap = compareAmounts(amount, SEND_AMOUNT_HARD_CAP) <= 0;
    balanceOk = compareAmounts(sourceBalance, amount) >= 0;
  } catch (err) {
    return check(
      "amount_fixed_fractional",
      false,
      err instanceof Error ? err.message : "malformed amount",
    );
  }
  if (!positive) {
    return check(
      "amount_fixed_fractional",
      false,
      `amount must be strictly positive (got ${amount})`,
    );
  }
  if (!withinHardCap) {
    return check(
      "amount_fixed_fractional",
      false,
      `amount ${amount} exceeds the ${SEND_AMOUNT_HARD_CAP} ZKZ external-amount-cap hard cap`,
    );
  }
  if (!withinCeiling) {
    return check(
      "amount_fixed_fractional",
      false,
      `amount ${amount} exceeds the ${ceiling} ZKZ acceptance ceiling`,
    );
  }
  if (!balanceOk) {
    return check(
      "amount_fixed_fractional",
      false,
      `source balance ${sourceBalance} < fixed amount ${amount}`,
    );
  }
  return check(
    "amount_fixed_fractional",
    true,
    `amount ${amount} ZKZ fixed within (0, ${ceiling}] (hard cap ${SEND_AMOUNT_HARD_CAP}) and covered by fresh gateway balance ${sourceBalance}`,
  );
}

/**
 * Source predicate: node-generated and controlled; AVAILABLE|PINNED.
 * Recovery_verified is NOT required for the source role on SEND_EXTERNAL.
 */
export function evaluateSendSourceEligibility(facts: SendSourceFacts): {
  ok: boolean;
  detail: string;
} {
  if (!facts.nodeControlled) {
    return { ok: false, detail: `source ${facts.walletId} is not node-controlled` };
  }
  if (facts.keyOrigin !== "node_generated") {
    return {
      ok: false,
      detail: `source ${facts.walletId} key_origin=${String(facts.keyOrigin)} (require node_generated)`,
    };
  }
  const state = String(facts.walletState);
  if (state !== "AVAILABLE" && state !== "PINNED") {
    return {
      ok: false,
      detail: `source ${facts.walletId} wallet_state=${state} (require AVAILABLE|PINNED)`,
    };
  }
  if (facts.pubkey.trim() === "") {
    return { ok: false, detail: `source ${facts.walletId} pubkey is empty` };
  }
  return {
    ok: true,
    detail: `source ${facts.walletId} node_generated+controlled pubkey=${facts.pubkey.slice(0, 12)}… state=${state}`,
  };
}

/**
 * External recipient predicate (step 2 + ticket memory): destination must NOT
 * resolve to this node's blessed internal set, must NOT be a node-controlled wallet, and
 * must document an independent keyholder.
 */
export function evaluateExternalRecipient(facts: SendExternalRecipientFacts): {
  ok: boolean;
  detail: string;
} {
  if (facts.destinationAddress.trim() === "") {
    return { ok: false, detail: "destination_address is empty" };
  }
  if (facts.resolvesToNodeBlessedSet) {
    return {
      ok: false,
      detail: `destination ${facts.destinationAddress.slice(0, 12)}… resolves to this node's blessed internal set — refuse (stale/internal destination)`,
    };
  }
  if (facts.isNodeControlledWallet) {
    return {
      ok: false,
      detail: `destination ${facts.destinationAddress.slice(0, 12)}… is a node-controlled wallet — external counterparty must be independently held`,
    };
  }
  if (facts.keyholderId.trim() === "") {
    return {
      ok: false,
      detail: "external recipient keyholderId is empty — independent control must be documented",
    };
  }
  if (facts.independentControlNote.trim() === "") {
    return {
      ok: false,
      detail: "external recipient independentControlNote is empty",
    };
  }
  return {
    ok: true,
    detail: `destination independently held by keyholder=${facts.keyholderId} (not node blessed/controlled): ${facts.independentControlNote}`,
  };
}

function fieldOrdersEqual(
  actual: readonly string[],
  expected: readonly string[],
): boolean {
  if (actual.length !== expected.length) return false;
  return actual.every((name, i) => name === expected[i]);
}

function checkApprovalTuple(
  challenge: SendApprovalChallenge | null,
  input: SendPreflightInput,
  source: SendSourceFacts | null,
): SendPreflightCheckResult {
  if (challenge === null) {
    return check(
      "approval_tuple_byte_correct",
      false,
      `no zp-send-external-approval-v1 challenge loaded for operation ${input.operationId}`,
    );
  }
  if (challenge.purpose !== SEND_APPROVAL_PURPOSE) {
    return check(
      "approval_tuple_byte_correct",
      false,
      `approval purpose ${challenge.purpose} ≠ ${SEND_APPROVAL_PURPOSE}`,
    );
  }
  if (challenge.canonicalVersion !== 1) {
    return check(
      "approval_tuple_byte_correct",
      false,
      `approval canonical_version=${String(challenge.canonicalVersion)} (require 1)`,
    );
  }
  if (!fieldOrdersEqual(challenge.fieldOrder, SEND_APPROVAL_FIELD_ORDER)) {
    return check(
      "approval_tuple_byte_correct",
      false,
      `approval field order [${challenge.fieldOrder.join(",")}] ≠ A.4.1 [${SEND_APPROVAL_FIELD_ORDER.join(",")}]`,
    );
  }
  if (challenge.carriesSplitInnerSha256) {
    return check(
      "approval_tuple_byte_correct",
      false,
      "approval carries forbidden split_inner_sha256 — the approval schema deliberately omits it (approve-first)",
    );
  }
  if (challenge.operationId !== input.operationId) {
    return check(
      "approval_tuple_byte_correct",
      false,
      `approval operation_id ${challenge.operationId} ≠ plan operation ${input.operationId}`,
    );
  }
  if (challenge.sourceSelector.kind !== "WALLET_ID") {
    return check(
      "approval_tuple_byte_correct",
      false,
      `approval source_selector.kind=${challenge.sourceSelector.kind} (require WALLET_ID)`,
    );
  }
  if (challenge.sourceSelector.wallet_id !== input.sourceWalletId) {
    return check(
      "approval_tuple_byte_correct",
      false,
      `approval source wallet ${challenge.sourceSelector.wallet_id} ≠ plan source ${input.sourceWalletId}`,
    );
  }
  if (source !== null && challenge.sourcePubkey !== source.pubkey) {
    return check(
      "approval_tuple_byte_correct",
      false,
      "approval source_pubkey does not match loaded source wallet pubkey",
    );
  }
  if (challenge.destinationAddress !== input.destinationAddress) {
    return check(
      "approval_tuple_byte_correct",
      false,
      "approval destination_address does not match plan destination",
    );
  }
  try {
    if (compareAmounts(challenge.amountZkz, input.amount) !== 0) {
      return check(
        "approval_tuple_byte_correct",
        false,
        `approval amount_zkz ${challenge.amountZkz} ≠ plan amount ${input.amount}`,
      );
    }
  } catch (err) {
    return check(
      "approval_tuple_byte_correct",
      false,
      err instanceof Error ? err.message : "malformed approval amount",
    );
  }
  if (!(challenge.expiresAt > challenge.issuedAt)) {
    return check(
      "approval_tuple_byte_correct",
      false,
      "approval expires_at is not strictly later than issued_at",
    );
  }
  const windowMs =
    Date.parse(challenge.expiresAt) - Date.parse(challenge.issuedAt);
  if (!Number.isFinite(windowMs) || windowMs > SEND_REDEMPTION_WINDOW_SECS * 1000) {
    // T1 ceiling is ≤300s (A.4.1) — numerically equal to T2 but a distinct timer.
    return check(
      "approval_tuple_byte_correct",
      false,
      `approval T1 window ${windowMs}ms exceeds the approval-window ceiling of ${SEND_REDEMPTION_WINDOW_SECS}s`,
    );
  }
  return check(
    "approval_tuple_byte_correct",
    true,
    `A.4.1 zp-send-external-approval-v1 12-field order verified; no split_inner_sha256; T1 window ok; unconsumed nonce=${challenge.nonce}`,
  );
}

/**
 * Run the full SEND_EXTERNAL preflight checklist. Read-only except for acquiring the
 * serialized runner lock on the all-green path (released by the caller after the run).
 * Lock is acquired LAST so earlier failures never need to release it.
 *
 * This function does NOT consume TOTP, acquire a wallet lease, or form a SplitChain
 * preimage — those are execute-ceremony responsibilities after operator go-approval.
 */
export async function runSendExternalPreflight(
  probe: SendPreflightProbe,
  input: SendPreflightInput,
): Promise<SendPreflightReport> {
  const ceiling = effectiveSendAmountCeiling(input.amountCeiling);
  const abortCriteria = sendExternalAbortCriteria();
  const checks: SendPreflightCheckResult[] = [];
  let vaultBackupCapturedAt: string | null = null;

  checks.push(checkAuthorization(input));

  const source = await probe.loadSource(input.sourceWalletId);
  let sourceBalance: Amount = "0";
  let gatewayBalanceOk = false;
  if (source === null) {
    checks.push(
      check(
        "source_identity_and_balance",
        false,
        `source wallet ${input.sourceWalletId} not found`,
      ),
    );
  } else {
    const src = evaluateSendSourceEligibility(source);
    if (!src.ok) {
      checks.push(check("source_identity_and_balance", false, src.detail));
    } else {
      try {
        sourceBalance = await probe.freshGatewayBalance(input.sourceWalletId);
        gatewayBalanceOk = true;
        checks.push(
          check(
            "source_identity_and_balance",
            true,
            `${src.detail}; fresh gateway balance=${sourceBalance}`,
          ),
        );
      } catch (err) {
        checks.push(
          check(
            "source_identity_and_balance",
            false,
            `fresh gateway balance read failed: ${err instanceof Error ? err.message : String(err)}`,
          ),
        );
      }
    }
  }

  const recipient = await probe.loadRecipient(input.destinationAddress);
  if (recipient === null) {
    checks.push(
      check(
        "external_recipient_independent",
        false,
        `external recipient ${input.destinationAddress.slice(0, 12)}… not documented`,
      ),
    );
  } else {
    const dst = evaluateExternalRecipient(recipient);
    checks.push(check("external_recipient_independent", dst.ok, dst.detail));
  }

  checks.push(
    checkAmount(
      input.amount,
      ceiling,
      gatewayBalanceOk ? sourceBalance : "0",
    ),
  );

  const srcLeases = await probe.activeLeases(input.sourceWalletId);
  checks.push(
    check(
      "no_active_lease",
      srcLeases.length === 0,
      srcLeases.length === 0
        ? "wallet_active_leases clear for source (no concurrent funded-node action)"
        : `in-flight lease blocks preflight: ${srcLeases
            .map((l) => `${l.leaseRole}@${l.operationId}`)
            .join(",")}`,
    ),
  );

  checks.push(
    check(
      "abort_criteria_bound",
      abortCriteria.nodeSubmitForbidden &&
        abortCriteria.blindRetryForbidden &&
        abortCriteria.redemptionWindowSecs === SEND_REDEMPTION_WINDOW_SECS &&
        abortCriteria.rebuildRequiresPositiveNonLandingOracle,
      `abort policy ${abortCriteria.policyId}: node-submit forbidden; blind-retry forbidden; T2=${abortCriteria.redemptionWindowSecs}s; rebuild only via positive non-landing oracle`,
    ),
  );

  const backupNotBefore =
    input.backupNotBeforeIso ?? input.authorization.recordedAt;
  const backup = await probe.freshVaultBackup(backupNotBefore);
  vaultBackupCapturedAt = backup.capturedAt;
  const sourceBackupOk = source?.backupPresent === true;
  const freshBackupOk = backup.present && backup.capturedAt !== null;
  const backupsOk = sourceBackupOk && freshBackupOk;
  checks.push(
    check(
      "fresh_vault_backup",
      backupsOk,
      backupsOk
        ? `fresh vault-state backup present captured_at=${backup.capturedAt} (notBefore=${backupNotBefore})`
        : `missing/stale vault backup: source.backupPresent=${sourceBackupOk} probe.present=${backup.present} capturedAt=${backup.capturedAt ?? "null"} notBefore=${backupNotBefore}`,
    ),
  );

  const operation = await probe.loadOperation(input.operationId);
  const challenge = await probe.loadApprovalChallenge(input.operationId);

  checks.push(checkApprovalTuple(challenge, input, source));

  if (operation === null) {
    checks.push(
      check(
        "expected_artifact_present",
        false,
        `SEND_EXTERNAL operation ${input.operationId} not found`,
      ),
    );
    checks.push(
      check(
        "no_lease_or_preimage_yet",
        false,
        `operation ${input.operationId} missing — cannot prove CREATED-stage absence of lease/preimage`,
      ),
    );
    checks.push(
      check(
        "approval_not_consumed",
        false,
        `operation ${input.operationId} missing — cannot prove approval unconsumed`,
      ),
    );
  } else {
    if (operation.status !== "CREATED") {
      checks.push(
        check(
          "expected_artifact_present",
          false,
          `operation ${input.operationId} status=${operation.status} (preflight requires CREATED)`,
        ),
      );
    } else if (!operation.expectedArtifactPresent) {
      checks.push(
        check(
          "expected_artifact_present",
          false,
          `operation ${input.operationId} missing zp-send-external-expected-v1 intent artifact`,
        ),
      );
    } else if (
      operation.expectedArtifactFieldOrder === null ||
      !fieldOrdersEqual(operation.expectedArtifactFieldOrder, SEND_EXPECTED_FIELD_ORDER)
    ) {
      checks.push(
        check(
          "expected_artifact_present",
          false,
          `expected-artifact field order [${(operation.expectedArtifactFieldOrder ?? []).join(",")}] ≠ A.3.3 [${SEND_EXPECTED_FIELD_ORDER.join(",")}]`,
        ),
      );
    } else {
      const economicsMatch =
        operation.sourceWalletId === input.sourceWalletId &&
        operation.destinationAddress === input.destinationAddress &&
        (() => {
          try {
            return compareAmounts(operation.amountZkz, input.amount) === 0;
          } catch {
            return false;
          }
        })();
      checks.push(
        check(
          "expected_artifact_present",
          economicsMatch,
          economicsMatch
            ? `zp-send-external-expected-v1 present on CREATED row; A.3.3 10-field order ok; economics match plan`
            : `expected artifact economics diverge from plan (source/dest/amount)`,
        ),
      );
    }

    const cleanStage = !operation.sourceLeaseHeld && !operation.splitChainPreimageExists;
    checks.push(
      check(
        "no_lease_or_preimage_yet",
        cleanStage,
        cleanStage
          ? "CREATED stage clean: no source lease, no SplitChain preimage"
          : `CREATED-stage pollution: sourceLeaseHeld=${operation.sourceLeaseHeld} splitChainPreimageExists=${operation.splitChainPreimageExists}`,
      ),
    );

    const unconsumed =
      !operation.approvalConsumed && (challenge === null || !challenge.consumed);
    checks.push(
      check(
        "approval_not_consumed",
        unconsumed,
        unconsumed
          ? "approval challenge unconsumed — TOTP consumption is a separate step"
          : "approval already consumed — refuse to stage a second ceremony on a spent challenge",
      ),
    );
  }

  // Acquire the runner lock LAST so earlier failures never need to release it.
  let runnerLockHandle: RunnerLockHandle | null = null;
  const priorReady = checks.every((c) => c.ok);
  if (priorReady) {
    const handle = input.runnerLock.tryAcquire(input.runnerHolderId);
    if (handle === null) {
      checks.push(
        check(
          "runner_lock_acquired",
          false,
          `serialized runner lock held by ${input.runnerLock.holderId ?? "<unknown>"}`,
        ),
      );
    } else {
      runnerLockHandle = handle;
      checks.push(
        check(
          "runner_lock_acquired",
          true,
          `serialized runner lock acquired by ${handle.holderId} at ${handle.acquiredAt}`,
        ),
      );
    }
  } else {
    checks.push(
      check(
        "runner_lock_acquired",
        false,
        "runner lock not attempted because earlier checks failed",
      ),
    );
  }

  const ready = checks.every((c) => c.ok);
  const plan: SendExternalPlan | null =
    ready && source !== null && recipient !== null && vaultBackupCapturedAt !== null
      ? {
          kind: "SEND_EXTERNAL",
          attemptId: input.attemptId,
          operationId: input.operationId,
          sourceWalletId: input.sourceWalletId,
          sourcePubkey: source.pubkey,
          destinationAddress: input.destinationAddress,
          amount: input.amount,
          authorization: input.authorization,
          recipientKeyholderId: recipient.keyholderId,
          redemptionWindowSecs: SEND_REDEMPTION_WINDOW_SECS,
          vaultBackupCapturedAt,
        }
      : null;

  if (!ready && runnerLockHandle !== null) {
    runnerLockHandle.release();
    runnerLockHandle = null;
  }

  return {
    ready,
    checks,
    plan,
    abortCriteria,
    runnerLockHandle,
    vaultBackupCapturedAt,
  };
}

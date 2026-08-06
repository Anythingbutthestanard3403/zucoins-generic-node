// Live RECEIVE_EXTERNAL preflight checklist.
//
// Offline, pure function over an injected probe seam. Never touches transport, the
// filesystem, a key, a live lease, or the gateway submit path. A failed check makes the
// plan NOT ready — the harness then refuses to release a runner lock for execution.
//
// Governing:
// 13
//   B-08
//
// Ticket checks (plus supporting ceremony gates):
//   (a) dual-control attempt-bound attestation (no owner greenlight)
//   (b) receiver wallet/B-08 predicate (node_generated + recovery_verified + AVAILABLE)
//   (c) exact smallest-practical fractional ZKZ amount (≤ 0.01 hard cap)
//   (d) external payer is independently controlled disposable capital (not node treasury)
//   (e) no concurrent lease / funded-node action in flight on the receiver
//   (f) explicit stop/abort conditions bound (payer-code TTL)
//   (g) fresh vault-state backup before ceremony
//   (h) A.3.1 expected-artifact field order when a CREATED (pre-lease) row is under preflight
//   (i) serialized runner lock acquired last
//
// Stage discipline (mirrors SEND): clean-start (no op) + CREATED only.
// READY / leased / code-released rows are past preflight — execute/reconcile lane
// not. Preflight MUST NOT: assign a wallet, form a transfer code,
// acquire a RECEIVER lease, co-sign step_2, or submit.

import {
  type Amount,
  type DualControlAuthorization,
  compareAmounts,
} from "./types.js";
import {
  type ReceiveAbortCriteria,
  RECEIVE_CODE_TTL_DEFAULT_SECS,
  RECEIVE_CODE_TTL_MAX_SECS,
  RECEIVE_CODE_TTL_MIN_SECS,
  receiveExternalAbortCriteria,
} from "./receive-abort-criteria.js";
import { type RunnerLock, type RunnerLockHandle } from "./runner-lock.js";

/**
 * Hard / external-amount-cap external bound for agent-driven acceptance receives.
 * Callers may lower `amountCeiling` but never raise it above this.
 */
export const RECEIVE_AMOUNT_HARD_CAP: Amount = "0.01";

/** Default fractional ceiling for a dual-control acceptance receive (external bound). */
export const DEFAULT_RECEIVE_AMOUNT_CEILING: Amount = RECEIVE_AMOUNT_HARD_CAP;

/** Canonical fractional dust amount preferred for the one authorized run. */
export const DEFAULT_RECEIVE_AMOUNT: Amount = "0.000001";

/**
 * Assignment-time SQL predicate — frozen literal, three conjuncts.
 * Preflight evaluates the same three facts independently; it never widens them.
 */
export const RECEIVE_ELIGIBILITY_SQL = [
  "SELECT id",
  "  FROM wallets",
  " WHERE key_origin = 'node_generated'",
  "   AND recovery_verified_at IS NOT NULL",
  "   AND state = 'AVAILABLE'",
  "   FOR UPDATE SKIP LOCKED",
  " LIMIT 1;",
].join("\n") as const;

/** A.3.1 `zp-receive-expected-v1` — 14 fields in exact insertion order (purpose + version first). */
export const RECEIVE_EXPECTED_FIELD_ORDER = [
  "purpose",
  "canonical_version",
  "node_id",
  "implementer_id",
  "operation_id",
  "receiver_wallet_id",
  "receiver_pubkey",
  "amount_zkz",
  "discriminator",
  "anchor",
  "receiver_t0_fingerprint",
  "expiry_unix_time_secs",
  "after_landing",
  "transfer_code_sha256",
] as const;

export type ReceiveExpectedFieldName = (typeof RECEIVE_EXPECTED_FIELD_ORDER)[number];

export const RECEIVE_EXPECTED_PURPOSE = "zp-receive-expected-v1" as const;

export type ReceivePreflightCheckId =
  | "dual_control_authorization"
  | "receiver_eligibility_d917"
  | "external_payer_independent"
  | "amount_fixed_fractional"
  | "no_active_lease"
  | "abort_criteria_bound"
  | "fresh_vault_backup"
  | "expected_artifact_or_clean_start"
  | "no_submit_yet"
  | "build_version_recorded"
  | "runner_lock_acquired";

export interface ReceivePreflightCheckResult {
  readonly id: ReceivePreflightCheckId;
  readonly ok: boolean;
  /** Key-free human-readable reason. Never includes private key material. */
  readonly detail: string;
}

/**
 * Durable receiver-wallet facts read from wallets — never cached assumptions.
 * recoveryVerifiedAt must be a non-null ISO timestamp from the audited recovery-export
 * ceremony (B-08); a column DEFAULT is not acceptable evidence.
 */
export interface ReceiveReceiverFacts {
  readonly walletId: string;
  readonly pubkey: string;
  readonly keyOrigin: unknown;
  readonly walletState: unknown;
  /** ISO-8601 recovery-export ceremony stamp, or null when never verified. */
  readonly recoveryVerifiedAt: string | null;
  /** True when this node controls the wallet secret (node-generated under local vault). */
  readonly nodeControlled: boolean;
  /** True when a current vault-state backup covering this wallet exists. */
  readonly backupPresent: boolean;
  /** ISO-8601 UTC timestamp of the freshest vault backup covering this wallet, or null. */
  readonly backupCapturedAt: string | null;
}

/**
 * Independently controlled external payer. Distinct keyholder from the node treasury —
 * disposable test capital that signs step_1 outside the node (ticket funded-party rule).
 */
export interface ReceiveExternalPayerFacts {
  /** Padded base64url external payer public key (step_1 signer). */
  readonly payerAddress: string;
  /**
   * True when the payer resolves to this node's current blessed internal set.
   * MUST be false for RECEIVE_EXTERNAL live acceptance.
   */
  readonly resolvesToNodeBlessedSet: boolean;
  /**
   * True when the payer pubkey equals any node-controlled treasury / pool wallet.
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
 * Optional CREATED-row snapshot when preflighting against an already-admitted
 * receive. Null operation is allowed (clean start — assignment happens at execute).
 * At this stage the row must not show a RECEIVER lease, transfer-code release, or
 * step_2 submit (mirrors SEND CREATED-only discipline).
 */
export interface ReceiveOperationRowSnapshot {
  readonly operationId: string;
  readonly status: string;
  readonly receiverWalletId: string | null;
  readonly amountZkz: Amount;
  /** True when `zp-receive-expected-v1` is stored on the row. */
  readonly expectedArtifactPresent: boolean;
  /** Exact A.3.1 field names in insertion order as stored, or null when absent. */
  readonly expectedArtifactFieldOrder: readonly string[] | null;
  /**
   * True when any RECEIVER lease row is already held for this operation.
   * Must be false at preflight stage; gated against probe.activeLeases.
   */
  readonly receiverLeaseHeld: boolean;
  /** True when any step_2 sign intent / submit attempt exists for this operation. */
  readonly step2SubmitAttempted: boolean;
  /**
   * True when a transfer code has already been released to the payer.
   * Must be false at preflight stage (code formation is a later stage).
   */
  readonly transferCodeReleased: boolean;
}

/** Exact build/version/config the live attempt will run under. */
export interface ReceiveBuildVersionConfig {
  /** Full git commit SHA of the node binary / image contents. */
  readonly commitSha: string;
  /** Deployed image tag, or local-dev marker. */
  readonly imageTag: string;
  /** Gateway endpoint URL (no credentials). */
  readonly gatewayEndpoint: string;
  /** Node config fingerprint / boot-id (key-free). */
  readonly configFingerprint: string;
}

/**
 * Injected read-only + lock seam. Live runner wires real DB/gateway reads; unit tests
 * wire in-memory fakes. Nothing here can submit, sign, assign a wallet, or form a code.
 */
export interface ReceivePreflightProbe {
  loadReceiver(walletId: string): Promise<ReceiveReceiverFacts | null>;
  loadExternalPayer(payerAddress: string): Promise<ReceiveExternalPayerFacts | null>;
  /** Current wallet_active_leases rows for the receiver, empty when clear. */
  activeLeases(walletId: string): Promise<readonly ActiveLeaseRow[]>;
  loadOperation(operationId: string): Promise<ReceiveOperationRowSnapshot | null>;
  /**
   * Whether a vault-state backup fresher than `notBeforeIso` exists covering the receiver.
   * Captures the backup timestamp into the report when true.
   */
  freshVaultBackup(notBeforeIso: string): Promise<{
    present: boolean;
    capturedAt: string | null;
  }>;
  /** Exact build/version/config that will run the live attempt. */
  loadBuildVersion(): Promise<ReceiveBuildVersionConfig | null>;
}

export interface ReceivePreflightInput {
  readonly attemptId: string;
  /**
   * Optional operation id when preflighting an already-admitted CREATED row.
   * Null/omitted means clean-start (execute lane will admit + assign).
   * READY / post-lease rows are rejected — past stage.
   */
  readonly operationId?: string | null;
  readonly receiverWalletId: string;
  readonly externalPayerAddress: string;
  readonly amount: Amount;
  readonly authorization: DualControlAuthorization;
  /**
   * Optional tighter ceiling. Clamped to RECEIVE_AMOUNT_HARD_CAP  — callers
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
 * Sealed key-free description of one authorized live RECEIVE_EXTERNAL. Built by preflight
 * and carried into the execute stage. Wallet identities + payer address only —
 * never a private key (the key-custody rule). Never carries a lease handle or submit proof.
 */
export interface ReceiveExternalPlan {
  readonly kind: "RECEIVE_EXTERNAL";
  readonly attemptId: string;
  readonly operationId: string | null;
  readonly receiverWalletId: string;
  readonly receiverPubkey: string;
  readonly externalPayerAddress: string;
  /** Exact fractional ZKZ the run will receive. */
  readonly amount: Amount;
  readonly authorization: DualControlAuthorization;
  /** Documented independent keyholder for the external payer. */
  readonly payerKeyholderId: string;
  /**  default code TTL the execute lane must honour. */
  readonly codeTtlDefaultSecs: typeof RECEIVE_CODE_TTL_DEFAULT_SECS;
  /** Vault-backup timestamp captured at preflight (ISO-8601). */
  readonly vaultBackupCapturedAt: string;
  /** Build/version/config frozen at preflight. */
  readonly buildVersion: ReceiveBuildVersionConfig;
  /** recovery_verified_at stamp observed on the receiver. */
  readonly recoveryVerifiedAt: string;
}

export interface ReceivePreflightReport {
  readonly ready: boolean;
  readonly checks: readonly ReceivePreflightCheckResult[];
  readonly plan: ReceiveExternalPlan | null;
  readonly abortCriteria: ReceiveAbortCriteria;
  /** Non-null only when ready && lock acquired; caller must release after the run. */
  readonly runnerLockHandle: RunnerLockHandle | null;
  /** Vault-backup timestamp observed during the check, or null when missing. */
  readonly vaultBackupCapturedAt: string | null;
  /** Frozen SQL predicate string for evidence attachment. */
  readonly eligibilitySql: typeof RECEIVE_ELIGIBILITY_SQL;
}


function check(
  id: ReceivePreflightCheckId,
  ok: boolean,
  detail: string,
): ReceivePreflightCheckResult {
  return { id, ok, detail };
}

function checkAuthorization(input: ReceivePreflightInput): ReceivePreflightCheckResult {
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
export function effectiveReceiveAmountCeiling(requested?: Amount): Amount {
  if (requested === undefined) return RECEIVE_AMOUNT_HARD_CAP;
  try {
    return compareAmounts(requested, RECEIVE_AMOUNT_HARD_CAP) > 0
      ? RECEIVE_AMOUNT_HARD_CAP
      : requested;
  } catch {
    return RECEIVE_AMOUNT_HARD_CAP;
  }
}

function checkAmount(amount: Amount, ceiling: Amount): ReceivePreflightCheckResult {
  let positive: boolean;
  let withinCeiling: boolean;
  let withinHardCap: boolean;
  try {
    positive = compareAmounts(amount, "0") > 0;
    withinCeiling = compareAmounts(amount, ceiling) <= 0;
    withinHardCap = compareAmounts(amount, RECEIVE_AMOUNT_HARD_CAP) <= 0;
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
      `amount ${amount} exceeds the ${RECEIVE_AMOUNT_HARD_CAP} ZKZ external-amount-cap hard cap`,
    );
  }
  if (!withinCeiling) {
    return check(
      "amount_fixed_fractional",
      false,
      `amount ${amount} exceeds the ${ceiling} ZKZ acceptance ceiling`,
    );
  }
  return check(
    "amount_fixed_fractional",
    true,
    `amount ${amount} ZKZ fixed within (0, ${ceiling}] (hard cap ${RECEIVE_AMOUNT_HARD_CAP}); external payer funds this inbound`,
  );
}

/**
 * Receiver predicate (step 1/B-08):
 *   key_origin='node_generated' AND recovery_verified_at IS NOT NULL AND state='AVAILABLE'
 *
 * Assignment-time form requires AVAILABLE exactly (not PINNED) — the structural
 * RECEIVE_WINDOW trigger evaluates against AVAILABLE before the lease pins it.
 */
export function evaluateReceiveReceiverEligibility(facts: ReceiveReceiverFacts): {
  ok: boolean;
  detail: string;
} {
  if (!facts.nodeControlled) {
    return { ok: false, detail: `receiver ${facts.walletId} is not node-controlled` };
  }
  if (facts.keyOrigin !== "node_generated") {
    return {
      ok: false,
      detail: `receiver ${facts.walletId} key_origin=${String(facts.keyOrigin)} (require node_generated per the receiver-eligibility rule)`,
    };
  }
  if (facts.recoveryVerifiedAt === null || String(facts.recoveryVerifiedAt).trim() === "") {
    return {
      ok: false,
      detail: `receiver ${facts.walletId} recovery_verified_at IS NULL — receiver eligibility requires audited recovery-export ceremony stamp (not a column DEFAULT)`,
    };
  }
  const state = String(facts.walletState);
  if (state !== "AVAILABLE") {
    return {
      ok: false,
      detail: `receiver ${facts.walletId} wallet_state=${state} (require AVAILABLE exactly — assignment-time form; PINNED is post-lease)`,
    };
  }
  if (facts.pubkey.trim() === "") {
    return { ok: false, detail: `receiver ${facts.walletId} pubkey is empty` };
  }
  return {
    ok: true,
    detail: `receiver ${facts.walletId} receiver-eligible: node_generated + recovery_verified_at=${facts.recoveryVerifiedAt} + state=AVAILABLE pubkey=${facts.pubkey.slice(0, 12)}…`,
  };
}

/**
 * External payer predicate: destination of the funded-party ownership check.
 * Payer must NOT resolve to this node's blessed internal set, must NOT be a
 * node-controlled wallet, and must document an independent keyholder.
 */
export function evaluateExternalPayer(facts: ReceiveExternalPayerFacts): {
  ok: boolean;
  detail: string;
} {
  if (facts.payerAddress.trim() === "") {
    return { ok: false, detail: "external payer address is empty" };
  }
  if (facts.resolvesToNodeBlessedSet) {
    return {
      ok: false,
      detail: `payer ${facts.payerAddress.slice(0, 12)}… resolves to this node's blessed internal set — refuse (node must not sign as its own counterparty)`,
    };
  }
  if (facts.isNodeControlledWallet) {
    return {
      ok: false,
      detail: `payer ${facts.payerAddress.slice(0, 12)}… is a node-controlled wallet — external payer must be independently held disposable capital`,
    };
  }
  if (facts.keyholderId.trim() === "") {
    return {
      ok: false,
      detail: "external payer keyholderId is empty — independent control must be documented",
    };
  }
  if (facts.independentControlNote.trim() === "") {
    return {
      ok: false,
      detail: "external payer independentControlNote is empty",
    };
  }
  return {
    ok: true,
    detail: `payer independently held by keyholder=${facts.keyholderId} (not node blessed/controlled): ${facts.independentControlNote}`,
  };
}

function fieldOrdersEqual(
  actual: readonly string[],
  expected: readonly string[],
): boolean {
  if (actual.length !== expected.length) return false;
  return actual.every((name, i) => name === expected[i]);
}

function checkBuildVersion(
  build: ReceiveBuildVersionConfig | null,
): ReceivePreflightCheckResult {
  if (build === null) {
    return check(
      "build_version_recorded",
      false,
      "build/version/config not recorded — refuse to stage a live attempt without a frozen commit SHA + image tag + gateway endpoint",
    );
  }
  if (build.commitSha.trim() === "" || !/^[0-9a-f]{7,40}$/i.test(build.commitSha.trim())) {
    return check(
      "build_version_recorded",
      false,
      `commitSha ${JSON.stringify(build.commitSha)} is not a plausible git SHA`,
    );
  }
  if (build.imageTag.trim() === "") {
    return check("build_version_recorded", false, "imageTag is empty");
  }
  if (build.gatewayEndpoint.trim() === "") {
    return check("build_version_recorded", false, "gatewayEndpoint is empty");
  }
  if (build.configFingerprint.trim() === "") {
    return check("build_version_recorded", false, "configFingerprint is empty");
  }
  return check(
    "build_version_recorded",
    true,
    `build commit=${build.commitSha} image=${build.imageTag} gateway=${build.gatewayEndpoint} config=${build.configFingerprint}`,
  );
}


/**
 * Run the full RECEIVE_EXTERNAL preflight checklist. Read-only except for acquiring the
 * serialized runner lock on the all-green path (released by the caller after the run).
 * Lock is acquired LAST so earlier failures never need to release it.
 *
 * This function does NOT assign a wallet, form a transfer code, acquire a RECEIVER lease,
 * co-sign step_2, or submit — those are execute-stage responsibilities.
 */
export async function runReceiveExternalPreflight(
  probe: ReceivePreflightProbe,
  input: ReceivePreflightInput,
): Promise<ReceivePreflightReport> {
  const ceiling = effectiveReceiveAmountCeiling(input.amountCeiling);
  const abortCriteria = receiveExternalAbortCriteria();
  const checks: ReceivePreflightCheckResult[] = [];
  let vaultBackupCapturedAt: string | null = null;

  checks.push(checkAuthorization(input));

  const receiver = await probe.loadReceiver(input.receiverWalletId);
  if (receiver === null) {
    checks.push(
      check(
        "receiver_eligibility_d917",
        false,
        `receiver wallet ${input.receiverWalletId} not found`,
      ),
    );
  } else {
    const rcv = evaluateReceiveReceiverEligibility(receiver);
    checks.push(check("receiver_eligibility_d917", rcv.ok, rcv.detail));
  }

  const payer = await probe.loadExternalPayer(input.externalPayerAddress);
  if (payer === null) {
    checks.push(
      check(
        "external_payer_independent",
        false,
        `external payer ${input.externalPayerAddress.slice(0, 12)}… not documented`,
      ),
    );
  } else {
    const p = evaluateExternalPayer(payer);
    checks.push(check("external_payer_independent", p.ok, p.detail));
  }

  checks.push(checkAmount(input.amount, ceiling));

  const rcvLeases = await probe.activeLeases(input.receiverWalletId);
  checks.push(
    check(
      "no_active_lease",
      rcvLeases.length === 0,
      rcvLeases.length === 0
        ? "wallet_active_leases clear for receiver (no concurrent funded-node action)"
        : `in-flight lease blocks preflight: ${rcvLeases
            .map((l) => `${l.leaseRole}@${l.operationId}`)
            .join(",")}`,
    ),
  );

  checks.push(
    check(
      "abort_criteria_bound",
      abortCriteria.blindRetryForbidden &&
        abortCriteria.rebuildRequiresPositiveNonLandingOracle &&
        abortCriteria.singleSubmitOnly &&
        abortCriteria.codeTtlDefaultSecs === RECEIVE_CODE_TTL_DEFAULT_SECS &&
        abortCriteria.codeTtlMinSecs === RECEIVE_CODE_TTL_MIN_SECS &&
        abortCriteria.codeTtlMaxSecs === RECEIVE_CODE_TTL_MAX_SECS,
      `abort policy ${abortCriteria.policyId}: single-submit only; blind-retry forbidden; code TTL default=${abortCriteria.codeTtlDefaultSecs}s min=${abortCriteria.codeTtlMinSecs}s max=${abortCriteria.codeTtlMaxSecs}s; rebuild only via positive non-landing oracle; halt → HOLD_RECEIVER_LEASE_AND_RECONCILE / NEEDS_ATTENTION`,
    ),
  );

  const backupNotBefore =
    input.backupNotBeforeIso ?? input.authorization.recordedAt;
  const backup = await probe.freshVaultBackup(backupNotBefore);
  vaultBackupCapturedAt = backup.capturedAt;
  const receiverBackupOk = receiver?.backupPresent === true;
  const freshBackupOk = backup.present && backup.capturedAt !== null;
  const backupsOk = receiverBackupOk && freshBackupOk;
  checks.push(
    check(
      "fresh_vault_backup",
      backupsOk,
      backupsOk
        ? `fresh vault-state backup present captured_at=${backup.capturedAt} (notBefore=${backupNotBefore})`
        : `missing/stale vault backup: receiver.backupPresent=${receiverBackupOk} probe.present=${backup.present} capturedAt=${backup.capturedAt ?? "null"} notBefore=${backupNotBefore}`,
    ),
  );

  const operationId = input.operationId ?? null;
  if (operationId === null || operationId.trim() === "") {
    checks.push(
      check(
        "expected_artifact_or_clean_start",
        true,
        "clean start: no prior operation row — the execute path will admit and assign",
      ),
    );
    checks.push(
      check(
        "no_submit_yet",
        true,
        "clean start: no prior step_2 submit attempt possible without an operation row",
      ),
    );
  } else {
    const operation = await probe.loadOperation(operationId);
    if (operation === null) {
      checks.push(
        check(
          "expected_artifact_or_clean_start",
          false,
          `RECEIVE_EXTERNAL operation ${operationId} not found`,
        ),
      );
      checks.push(
        check(
          "no_submit_yet",
          false,
          `operation ${operationId} missing — cannot prove absence of prior submit`,
        ),
      );
    } else {
      // Stage discipline: CREATED only (mirrors SEND). READY implies receiver lease +
      // code path already past preflight — execute/reconcile lane, not.
      if (operation.status !== "CREATED") {
        checks.push(
          check(
            "expected_artifact_or_clean_start",
            false,
            `operation ${operationId} status=${operation.status} (preflight requires CREATED; READY/leased rows are past preflight — execute/reconcile lane)`,
          ),
        );
      } else if (!operation.expectedArtifactPresent) {
        const economicsMatch = (() => {
          try {
            return compareAmounts(operation.amountZkz, input.amount) === 0;
          } catch {
            return false;
          }
        })();
        checks.push(
          check(
            "expected_artifact_or_clean_start",
            economicsMatch,
            economicsMatch
              ? `CREATED unassigned row present; amount matches plan; artifact deferred until assignment`
              : `CREATED row amount ${operation.amountZkz} diverges from plan amount ${input.amount}`,
          ),
        );
      } else if (
        operation.expectedArtifactFieldOrder === null ||
        !fieldOrdersEqual(operation.expectedArtifactFieldOrder, RECEIVE_EXPECTED_FIELD_ORDER)
      ) {
        checks.push(
          check(
            "expected_artifact_or_clean_start",
            false,
            `expected-artifact field order [${(operation.expectedArtifactFieldOrder ?? []).join(",")}] ≠ A.3.1 [${RECEIVE_EXPECTED_FIELD_ORDER.join(",")}]`,
          ),
        );
      } else {
        const receiverMatch =
          operation.receiverWalletId === null ||
          operation.receiverWalletId === input.receiverWalletId;
        const economicsMatch = (() => {
          try {
            return compareAmounts(operation.amountZkz, input.amount) === 0;
          } catch {
            return false;
          }
        })();
        const ok = receiverMatch && economicsMatch;
        checks.push(
          check(
            "expected_artifact_or_clean_start",
            ok,
            ok
              ? `zp-receive-expected-v1 present on CREATED row; A.3.1 14-field order ok; economics match plan`
              : `expected artifact economics/receiver diverge from plan`,
          ),
        );
      }

      // CREATED-stage pollution gate: snapshot lease/code bits must be false and must
      // agree with the activeLeases probe (single-source; fail closed on disagreement).
      // Mirrors SEND `no_lease_or_preimage_yet` / sourceLeaseHeld gating.
      const probeLeaseHeld = rcvLeases.length > 0;
      const snapshotProbeAgree = operation.receiverLeaseHeld === probeLeaseHeld;
      const stageClean =
        !operation.receiverLeaseHeld &&
        !operation.transferCodeReleased &&
        !operation.step2SubmitAttempted &&
        !probeLeaseHeld &&
        snapshotProbeAgree;
      checks.push(
        check(
          "no_submit_yet",
          stageClean,
          stageClean
            ? "CREATED stage clean: no receiver lease, no transfer-code release, no step_2 submit"
            : operation.step2SubmitAttempted
              ? "step_2 submit already attempted — refuse to stage a second ceremony on a spent attempt (the never-blind-retry rule)"
              : !snapshotProbeAgree
                ? `CREATED-stage lease evidence disagree: snapshot.receiverLeaseHeld=${operation.receiverLeaseHeld} probe.activeLeases=${probeLeaseHeld}`
                : `CREATED-stage pollution: status=${operation.status} receiverLeaseHeld=${operation.receiverLeaseHeld} transferCodeReleased=${operation.transferCodeReleased} activeLeases=${rcvLeases.length} (past preflight — execute/reconcile lane)`,
        ),
      );
    }
  }

  const build = await probe.loadBuildVersion();
  checks.push(checkBuildVersion(build));

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
  const plan: ReceiveExternalPlan | null =
    ready &&
    receiver !== null &&
    payer !== null &&
    vaultBackupCapturedAt !== null &&
    build !== null &&
    receiver.recoveryVerifiedAt !== null
      ? {
          kind: "RECEIVE_EXTERNAL",
          attemptId: input.attemptId,
          operationId: operationId !== null && operationId.trim() !== "" ? operationId : null,
          receiverWalletId: input.receiverWalletId,
          receiverPubkey: receiver.pubkey,
          externalPayerAddress: input.externalPayerAddress,
          amount: input.amount,
          authorization: input.authorization,
          payerKeyholderId: payer.keyholderId,
          codeTtlDefaultSecs: RECEIVE_CODE_TTL_DEFAULT_SECS,
          vaultBackupCapturedAt,
          buildVersion: build,
          recoveryVerifiedAt: receiver.recoveryVerifiedAt,
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
    eligibilitySql: RECEIVE_ELIGIBILITY_SQL,
  };
}

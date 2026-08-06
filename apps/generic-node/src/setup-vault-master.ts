// First-boot vault master key generate + show-once.
//
// Mode B assist: virgin path generates a CSPRNG master key, returns it once
// over the admin session, requires offline-backup ack, then never re-serves
// the plaintext. vault master KEK ≠ backup KEK.
//
// Does NOT replace the recovery-verification ceremony. Does NOT POST the key
// into ceremony (that is the Mode A admin API). This module only assists first-boot
// generation so operators need not invent a 32+ char secret.

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export const VAULT_MASTER_MIN_CHARS = 32;
/** 32 random bytes → 43-char base64url (no pad) ≥ 32 chars entropy. */
export const VAULT_MASTER_ENTROPY_BYTES = 32;

export type VaultMasterPhase =
  | "virgin" // never generated; may call generate
  | "shown" // generated; plaintext held server-side once until ack
  | "sealed" // offline ack received; plaintext wiped; never retrievable
  | "configured"; // process already has VAULT_MASTER_KEY from env (non-wizard path)

export interface VaultMasterStatus {
  readonly object: "vault_master_status";
  readonly phase: VaultMasterPhase;
  /** True when generate is allowed (virgin only). */
  readonly can_generate: boolean;
  /** True when the show-once plaintext is still held for this session flow. */
  readonly plaintext_pending_ack: boolean;
  /** True after offline ack (or env-configured). */
  readonly offline_backup_acked: boolean;
  /**
   * Always true: vault master must differ from BACKUP_MASTER_KEY.
   * Enforced at generate/seal time when backup KEK is known.
   */
  readonly vault_master_distinct_from_backup_kek: true;
  /** Fingerprint only after sealed/configured — never the key. sha256 hex prefix. */
  readonly key_fingerprint_prefix: string | null;
}

export interface VaultMasterGenerateResult {
  readonly object: "vault_master_generate";
  /** Shown once. Caller must not log or put in localStorage. */
  readonly master_key: string;
  readonly phase: "shown";
  readonly guidance: string;
  readonly vault_master_distinct_from_backup_kek: true;
}

export interface VaultMasterAckResult {
  readonly object: "vault_master_ack";
  readonly phase: "sealed";
  readonly offline_backup_acked: true;
  readonly key_fingerprint_prefix: string;
}

export class VaultMasterError extends Error {
  readonly code:
    | "already_generated"
    | "not_pending"
    | "already_sealed"
    | "backup_kek_collision"
    | "configured_env"
    | "validation_error";
  constructor(code: VaultMasterError["code"], message: string) {
    super(message);
    this.name = "VaultMasterError";
    this.code = code;
  }
}

export interface VaultMasterBootstrapState {
  phase: VaultMasterPhase;
  /** Ephemeral plaintext — memory only; wiped on ack. Never persisted. */
  pendingPlaintext: string | null;
  offlineBackupAcked: boolean;
  /** sha256 hex of master (for fingerprint prefix only). */
  keyFingerprintHex: string | null;
  /** sha256 digest of master for backup-collision checks without retaining plaintext. */
  keyDigest: Buffer | null;
}

export function createVirginVaultMasterState(): VaultMasterBootstrapState {
  return {
    phase: "virgin",
    pendingPlaintext: null,
    offlineBackupAcked: false,
    keyFingerprintHex: null,
    keyDigest: null,
  };
}

/** Mark state as already configured from env (non-virgin boot). */
export function createConfiguredVaultMasterState(
  vaultMasterKey: string,
  offlineBackupAcked = false,
): VaultMasterBootstrapState {
  const digest = createHash("sha256").update(vaultMasterKey).digest();
  return {
    phase: "configured",
    pendingPlaintext: null,
    offlineBackupAcked,
    keyFingerprintHex: digest.toString("hex"),
    keyDigest: digest,
  };
}

export function fingerprintPrefix(hex: string | null): string | null {
  if (!hex || hex.length < 12) return null;
  return hex.slice(0, 12);
}

export function statusFromState(state: VaultMasterBootstrapState): VaultMasterStatus {
  return {
    object: "vault_master_status",
    phase: state.phase,
    can_generate: state.phase === "virgin",
    plaintext_pending_ack: state.phase === "shown" && state.pendingPlaintext !== null,
    offline_backup_acked: state.offlineBackupAcked || state.phase === "sealed",
    vault_master_distinct_from_backup_kek: true,
    key_fingerprint_prefix:
      state.phase === "sealed" || state.phase === "configured"
        ? fingerprintPrefix(state.keyFingerprintHex)
        : null,
  };
}

/**
 * Generate a CSPRNG master key (server-side). Documented choice: server
 * entropy via node:crypto randomBytes — browser WebCrypto would also be
 * valid; server generation keeps the show-once cache off localStorage.
 */
export function generateVaultMasterKey(): string {
  // base64url without padding — high entropy, operator-copyable, ≥32 chars.
  return randomBytes(VAULT_MASTER_ENTROPY_BYTES).toString("base64url");
}

export function assertDistinctFromBackupKek(
  vaultMasterKey: string,
  backupMasterKey: string | null | undefined,
): void {
  if (backupMasterKey === undefined || backupMasterKey === null || backupMasterKey.length === 0) {
    return;
  }
  const vaultDigest = createHash("sha256").update(vaultMasterKey).digest();
  const backupDigest = createHash("sha256").update(backupMasterKey).digest();
  if (timingSafeEqual(vaultDigest, backupDigest)) {
    throw new VaultMasterError(
      "backup_kek_collision",
      "vault master key must differ from BACKUP_MASTER_KEY (separate custody domains)",
    );
  }
}

/**
 * Transition virgin → shown. Returns plaintext once.
 * Does not persist the key; caller may optionally write to a sealed env file
 * outside this module (the deploy path).
 */
export function generateShowOnce(
  state: VaultMasterBootstrapState,
  opts: { readonly backupMasterKey?: string | null } = {},
): VaultMasterGenerateResult {
  if (state.phase === "configured") {
    throw new VaultMasterError(
      "configured_env",
      "vault already configured via VAULT_MASTER_KEY; generate is disabled",
    );
  }
  if (state.phase === "sealed") {
    throw new VaultMasterError("already_sealed", "vault master already sealed; key is not retrievable");
  }
  // "shown" refuses re-issue even after restart wiped pendingPlaintext (durable seal).
  if (state.phase === "shown") {
    throw new VaultMasterError(
      "already_generated",
      "master key already generated; complete offline ack — key is not re-issued",
    );
  }

  const master = generateVaultMasterKey();
  if (master.length < VAULT_MASTER_MIN_CHARS) {
    throw new VaultMasterError("validation_error", "generated key below minimum length");
  }
  assertDistinctFromBackupKek(master, opts.backupMasterKey);

  const digest = createHash("sha256").update(master).digest();
  state.phase = "shown";
  state.pendingPlaintext = master;
  state.keyFingerprintHex = digest.toString("hex");
  state.keyDigest = digest;
  state.offlineBackupAcked = false;

  return {
    object: "vault_master_generate",
    master_key: master,
    phase: "shown",
    guidance:
      "Store this vault master key offline now (paper or offline password manager). " +
      "It will never be shown again and cannot be emailed or re-fetched. " +
      "This is NOT the backup KEK (BACKUP_MASTER_KEY) — keep them distinct.",
    vault_master_distinct_from_backup_kek: true,
  };
}

/**
 * Second GET must not return the key. If still in shown phase, status only.
 * Explicit rejection when client asks for plaintext again.
 */
export function refuseSecondReveal(state: VaultMasterBootstrapState): void {
  if (state.phase === "shown" || state.phase === "sealed" || state.phase === "configured") {
    throw new VaultMasterError(
      "already_generated",
      "vault master key is show-once and is not retrievable after first generate",
    );
  }
}

/**
 * Operator acked "I stored this offline". Wipes pending plaintext from memory.
 */
export function acknowledgeOfflineBackup(
  state: VaultMasterBootstrapState,
  opts: { readonly backupMasterKey?: string | null; readonly ack: boolean } = { ack: true },
): VaultMasterAckResult {
  if (!opts.ack) {
    throw new VaultMasterError("validation_error", "offline backup ack must be true");
  }
  if (state.phase === "configured") {
    state.offlineBackupAcked = true;
    const fp = fingerprintPrefix(state.keyFingerprintHex) ?? "configured";
    return {
      object: "vault_master_ack",
      phase: "sealed",
      offline_backup_acked: true,
      key_fingerprint_prefix: fp,
    };
  }
  if (state.phase === "sealed") {
    throw new VaultMasterError("already_sealed", "offline backup already acknowledged");
  }
  if (state.phase !== "shown") {
    throw new VaultMasterError(
      "not_pending",
      "no pending master key to acknowledge — generate first",
    );
  }

  // Post-restart: phase may be durable "shown" with plaintext already wiped.
  // Operator already received the key once — allow offline ack without re-issue.
  if (state.pendingPlaintext !== null) {
    // Re-check distinctness at seal time while plaintext is still in memory.
    assertDistinctFromBackupKek(state.pendingPlaintext, opts.backupMasterKey);
    state.pendingPlaintext = null;
  } else if (!state.keyFingerprintHex) {
    throw new VaultMasterError(
      "not_pending",
      "no pending master key to acknowledge — generate first",
    );
  }

  state.phase = "sealed";
  state.offlineBackupAcked = true;

  const fp = fingerprintPrefix(state.keyFingerprintHex);
  if (!fp) {
    throw new VaultMasterError("validation_error", "missing fingerprint after seal");
  }

  return {
    object: "vault_master_ack",
    phase: "sealed",
    offline_backup_acked: true,
    key_fingerprint_prefix: fp,
  };
}

/** True when W5 vault path is satisfied for setup flags. */
export function vaultReadyForSetup(state: VaultMasterBootstrapState): boolean {
  if (state.phase === "sealed" && state.offlineBackupAcked) return true;
  if (state.phase === "configured" && state.offlineBackupAcked) return true;
  return false;
}

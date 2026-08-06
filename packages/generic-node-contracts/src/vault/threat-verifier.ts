import { type ThreatId } from "./threat-model.contract.ts";
import { AAD_BINDING, SUBSTITUTION_CONTROL } from "./aad.contract.ts";
import { ENVELOPE_STRUCTURE } from "./storage.contract.ts";
import { KEY_ISOLATION } from "./crypto.contract.ts";
import { ROTATION_INVARIANTS, SIGNING_CONCURRENCY } from "./lifecycle.contract.ts";
import { ZEROIZATION } from "./compatibility.contract.ts";
import { SEALING_API } from "./interfaces.contract.ts";
import { HKDF_INFO_ENCODING, CROSS_STORE_LABEL_SEPARATION } from "./hkdf-info.ts";

/**
 * Pure threat assessment. `controlEnabled` models whether the mitigating control is present:
 * when true, the assessor reads the ACTUAL frozen the vault model freeze/.2 contract values, so a weakened
 * control (e.g. `stored_aad_column` flipped true, or a dropped UNIQUE guard) makes the threat
 * no longer caught and fails the census. When false, the control is bypassed and the attack
 * succeeds (`NOT_CAUGHT`) — the mandatory per-threat negative.
 */

export type ThreatOutcome =
  | "AAD_MISMATCH"
  | "RECONSTRUCT_ONLY"
  | "WRITE_ABORT"
  | "LENGTH_OR_TAG_FAILURE"
  | "RESUME_BEFORE_DECOMMISSION"
  | "MIXED_VERSION_RESUME"
  | "SIGNING_QUIESCED"
  | "WIPED_NEVER_LOGGED"
  | "WIPED_POST_SIGN"
  | "DISTINCT_DERIVED_KEY"
  | "NOT_CAUGHT";

const substitutionCaught = (enabled: boolean): ThreatOutcome => {
  const aadBinds = enabled && AAD_BINDING.reconstructed_at_open && !AAD_BINDING.stored_as_column;
  const pubkeyCheck =
    enabled &&
    SUBSTITUTION_CONTROL.primary === "DECRYPT_DERIVE_PUBKEY_ASSERT_EQ_WALLETS_PUBLIC_KEY";
  if (aadBinds || pubkeyCheck) return "AAD_MISMATCH";
  return "NOT_CAUGHT";
};

export const assessThreat = (threatId: ThreatId, controlEnabled: boolean): ThreatOutcome => {
  switch (threatId) {
    case "SUBSTITUTION_CROSS_WALLET":
    case "SUBSTITUTION_CROSS_VERSION":
    case "SUBSTITUTION_CROSS_ORIGIN":
    case "KEY_SMUGGLE_ORIGIN_FLIP":
    case "AAD_STRIP_REORDER":
      return substitutionCaught(controlEnabled);
    case "STORED_AAD_DOWNGRADE":
      return controlEnabled &&
        ENVELOPE_STRUCTURE.stored_aad_column === false &&
        SEALING_API.open.reconstructs_aad_from === "AUTHORITATIVE_FIELDS_NEVER_STORED_COLUMN"
        ? "RECONSTRUCT_ONLY"
        : "NOT_CAUGHT";
    case "NONCE_REUSE":
      return controlEnabled &&
        KEY_ISOLATION.structural_nonce_reuse_guard === "UNIQUE(key_version, nonce)"
        ? "WRITE_ABORT"
        : "NOT_CAUGHT";
    case "TRUNCATED_CIPHERTEXT":
      return controlEnabled ? "LENGTH_OR_TAG_FAILURE" : "NOT_CAUGHT";
    case "ROTATION_CRASH_WINDOW":
      return controlEnabled &&
        ROTATION_INVARIANTS.old_key_retained_until_committed_marker &&
        ROTATION_INVARIANTS.unreadable_or_failed_pubkey_row_aborts_without_advancing_writer_version
        ? "RESUME_BEFORE_DECOMMISSION"
        : "NOT_CAUGHT";
    case "RESTORE_WITH_STALE_VAULT":
      return controlEnabled &&
        ROTATION_INVARIANTS.old_key_retained_until_committed_marker &&
        ROTATION_INVARIANTS.boot_reads_mixed_version_via_key_ring
        ? "MIXED_VERSION_RESUME"
        : "NOT_CAUGHT";
    case "SIGNING_DURING_ROTATION":
      return controlEnabled &&
        SIGNING_CONCURRENCY.vault_row_lock_held_across_signing === false &&
        SIGNING_CONCURRENCY.rotation_writer ===
          "QUIESCES_SIGNING_LOCKS_CANONICAL_WALLET_ID_SEQUENCE"
        ? "SIGNING_QUIESCED"
        : "NOT_CAUGHT";
    case "KEY_DISCLOSURE_LOGS_DUMPS":
      return controlEnabled &&
        ZEROIZATION.keys_logged === false &&
        ZEROIZATION.core_dumps === "DISABLED"
        ? "WIPED_NEVER_LOGGED"
        : "NOT_CAUGHT";
    case "STALE_PROCESS_HOLDS_KEY":
      return controlEnabled && ZEROIZATION.wipe === "SODIUM_MEMZERO_POST_SIGN"
        ? "WIPED_POST_SIGN"
        : "NOT_CAUGHT";
    case "CROSS_STORE_KEY_DERIVATION_COLLISION":
      return controlEnabled &&
        HKDF_INFO_ENCODING.domain_prefixed &&
        CROSS_STORE_LABEL_SEPARATION.requirement === "GLOBALLY_UNIQUE_HKDF_LABEL_PER_STORE"
        ? "DISTINCT_DERIVED_KEY"
        : "NOT_CAUGHT";
  }
};

export const isThreatMitigated = (threatId: ThreatId): boolean =>
  assessThreat(threatId, true) !== "NOT_CAUGHT";

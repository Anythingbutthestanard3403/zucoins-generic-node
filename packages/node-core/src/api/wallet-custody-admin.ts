// Wallet custody administration — the operator-facing view of a wallet's custody standing
// and the direct quarantine transition.
// It covers the operator custody endpoints, the derived destination eligibility this
// quarantine feeds, the trust-domain boundary, custody classification, the universal
// signing lease, and the `wallets` / `wallet_recovery_verifications` tables with their
// CHECKs and triggers.
//
// Keeping key material off every served surface is the whole point of this file. Plaintext
// private keys, the vault master key and the TOTP secret sit outside every surface the
// node database may serve, so the operator view below is an EXPLICIT projection: the response
// is built field by field from WALLET_CUSTODY_VIEW_FIELDS, never by spreading a store row.
// A store that hands back `ciphertext`/`nonce`/`auth_tag` — or any other column added later
// cannot leak it through here, because nothing copies unknown keys.
//
// Retirement is NOT re-implemented here. (`./destination.js`) owns
// `POST /admin/v1/destinations/:destination_id/retire`, and.2's "retirement never
// rewrites an existing signed operation" is upheld structurally: neither that service nor this
// one has any port reaching `operation_expected_artifacts`, `operation_transactions` or
// `external_send_partials`.
//
// Quarantine likewise touches `wallets` only. requires that a `NEEDS_ATTENTION` lease
// "remains held or the wallet is quarantined until human-gated resolution" — so quarantining a
// wallet must never release its `wallet_active_leases` row. There is no lease port on this
// service, so no code path here can.

import type {
  WalletKeyOrigin,
  WalletState,
} from "@zucoins/generic-node-contracts/custody";

import type { Uuid, WalletPublicKey } from "../protocol/scalars.js";

export type { WalletKeyOrigin, WalletState };

/**
 * The complete field allowlist for the operator custody view.
 * This array IS the schema: `buildWalletCustodyView` emits exactly these keys and the
 * field-level negative test asserts against this list rather than against sample responses.
 */
export const WALLET_CUSTODY_VIEW_FIELDS = [
  "wallet_id",
  "node_id",
  "public_key",
  "key_origin",
  "state",
  "created_at",
  "retired_at",
  "quarantine_reason",
  "recovery_verified",
  "recovery_verified_at",
  "recovery_verification",
] as const;

/**
 * Allowlist for the linked `wallet_recovery_verifications` evidence.
 * `audit_event_id` is a pointer into `audit_log` so an operator can trace the ceremony;
 * this view never re-serves the audit entry, and never the export bytes behind
 * `export_sha256`.
 */
export const WALLET_RECOVERY_EVIDENCE_FIELDS = [
  "method",
  "verified_at",
  "verifier_identity",
  "audit_event_id",
] as const;

export interface WalletRecoveryEvidenceView {
  readonly method: string;
  readonly verified_at: string;
  readonly verifier_identity: string;
  readonly audit_event_id: Uuid;
}

export interface WalletCustodyView {
  readonly wallet_id: Uuid;
  readonly node_id: Uuid;
  readonly public_key: WalletPublicKey;
  readonly key_origin: WalletKeyOrigin;
  readonly state: WalletState;
  readonly created_at: string;
  readonly retired_at: string | null;
  readonly quarantine_reason: string | null;
  /** presence fact: is this wallet recovery-verified at all. Never inferred. */
  readonly recovery_verified: boolean;
  readonly recovery_verified_at: string | null;
  /** The evidence row behind `recovery_verified_at`, or null when there is none. */
  readonly recovery_verification: WalletRecoveryEvidenceView | null;
}

/** Authoritative `wallets` columns. Deliberately carries no vault reference of any kind. */
export interface WalletCustodyRow {
  readonly walletId: Uuid;
  readonly nodeId: Uuid;
  readonly publicKey: WalletPublicKey;
  readonly keyOrigin: WalletKeyOrigin;
  readonly state: WalletState;
  readonly createdAt: string;
  readonly retiredAt: string | null;
  readonly quarantineReason: string | null;
  readonly recoveryVerifiedAt: string | null;
  readonly recoveryVerificationId: Uuid | null;
}

/** Authoritative `wallet_recovery_verifications` columns. */
export interface WalletRecoveryVerificationRow {
  readonly verificationId: Uuid;
  readonly walletId: Uuid;
  readonly method: string;
  readonly verifiedAt: string;
  readonly verifierIdentity: string;
  readonly auditEventId: Uuid;
}

// Persistence port. The store is the structural owner of the invariants this service cannot
// see: `wallets_quarantine_reason_iff` (state='QUARANTINED' iff quarantine_reason IS NOT NULL)
// and `wallets_retired_at_iff`, both CHECKs in custody-eligibility.sql. The guards below
// mirror those constraints so an operator gets a typed outcome instead of a 23514, but the
// database — not this file — is what a second concurrent process cannot race past.
export interface WalletCustodyStore {
  findWallet(walletId: Uuid): Promise<WalletCustodyRow | null>;
  findRecoveryVerification(verificationId: Uuid): Promise<WalletRecoveryVerificationRow | null>;
  /** Sets state='QUARANTINED' and quarantine_reason together. Never touches leases. */
  quarantine(walletId: Uuid, reason: string): Promise<WalletCustodyRow>;
}

export interface QuarantineWalletRequest {
  readonly nodeId: Uuid;
  readonly walletId: Uuid;
  readonly reason: string;
}

export type QuarantineWalletOutcome =
  | { readonly status: "quarantined"; readonly wallet: WalletCustodyView }
  | { readonly status: "already_quarantined"; readonly wallet: WalletCustodyView }
  | { readonly status: "not_found"; readonly walletId: Uuid }
  | { readonly status: "reason_required"; readonly walletId: Uuid }
  | { readonly status: "invalid_transition"; readonly walletId: Uuid; readonly from: WalletState };

export interface WalletCustodyAdminService {
  /** Operator custody view, tenant-scoped. Returns null for another tenant's wallet. */
  view(nodeId: Uuid, walletId: Uuid): Promise<WalletCustodyView | null>;
  quarantine(request: QuarantineWalletRequest): Promise<QuarantineWalletOutcome>;
}

/**
 * Project a wallet row (plus optional evidence) onto the allowlist. Every key is written
 * literally: this is the enforcement point for, not a convenience mapper.
 */
export function buildWalletCustodyView(
  row: WalletCustodyRow,
  evidence: WalletRecoveryVerificationRow | null,
): WalletCustodyView {
  return {
    wallet_id: row.walletId,
    node_id: row.nodeId,
    public_key: row.publicKey,
    key_origin: row.keyOrigin,
    state: row.state,
    created_at: row.createdAt,
    retired_at: row.retiredAt,
    quarantine_reason: row.quarantineReason,
    // Presence only, read straight off the column recovery_verified_at gate gates on. Never derived from the
    // existence of an evidence row — an evidence row that was never stamped onto the wallet
    // does not make the wallet verified.
    recovery_verified: row.recoveryVerifiedAt !== null,
    recovery_verified_at: row.recoveryVerifiedAt,
    recovery_verification:
      evidence === null
        ? null
        : {
            method: evidence.method,
            verified_at: evidence.verifiedAt,
            verifier_identity: evidence.verifierIdentity,
            audit_event_id: evidence.auditEventId,
          },
  };
}

/** Wallet states a quarantine may be entered from. RETIRED is terminal (retired_at iff). */
const QUARANTINABLE_STATES: readonly WalletState[] = ["AVAILABLE", "PINNED", "QUARANTINED"];

export function createWalletCustodyAdminService(deps: {
  readonly store: WalletCustodyStore;
}): WalletCustodyAdminService {
  const { store } = deps;

  // A wallet outside the authenticated tenant is indistinguishable from an absent one
  // (cross-tenant access collapses to not_found, never a 403 that
  // confirms existence).
  const loadForTenant = async (nodeId: Uuid, walletId: Uuid): Promise<WalletCustodyRow | null> => {
    const row = await store.findWallet(walletId);
    return row === null || row.nodeId !== nodeId ? null : row;
  };

  const viewOf = async (row: WalletCustodyRow): Promise<WalletCustodyView> => {
    const evidence =
      row.recoveryVerificationId === null
        ? null
        : await store.findRecoveryVerification(row.recoveryVerificationId);
    return buildWalletCustodyView(row, evidence);
  };

  return {
    async view(nodeId, walletId) {
      const row = await loadForTenant(nodeId, walletId);
      return row === null ? null : viewOf(row);
    },

    async quarantine(request) {
      const row = await loadForTenant(request.nodeId, request.walletId);
      if (row === null) {
        return { status: "not_found", walletId: request.walletId };
      }
      // Mirrors CHECK wallets_quarantine_reason_iff: the state is unreachable without a
      // reason, so a blank one is refused here rather than surfaced as a 23514.
      if (request.reason.trim() === "") {
        return { status: "reason_required", walletId: request.walletId };
      }
      if (!QUARANTINABLE_STATES.includes(row.state)) {
        return { status: "invalid_transition", walletId: request.walletId, from: row.state };
      }
      if (row.state === "QUARANTINED") {
        // Idempotent replay. The original reason is the operator record and is never
        // overwritten by a second call.
        return { status: "already_quarantined", wallet: await viewOf(row) };
      }
      const quarantined = await store.quarantine(request.walletId, request.reason);
      return { status: "quarantined", wallet: await viewOf(quarantined) };
    },
  };
}

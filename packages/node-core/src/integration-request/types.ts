// Integration-request domain types (Route 2 public handshake). ZTR-1239.

import type { ImplementerScope } from "../credential/types.js";
import type { IntegrationRequestStatus } from "../schema/integration-requests.contract.js";

export type { IntegrationRequestStatus };

/** Scopes platforms may request on Route 2 intake (subset of IMPLEMENTER_SCOPES). */
export const INTEGRATION_REQUEST_INTAKE_SCOPES = ["send:create", "send:read"] as const;

export type IntegrationRequestIntakeScope =
  (typeof INTEGRATION_REQUEST_INTAKE_SCOPES)[number];

export const CLAIM_TOKEN_PREFIX = "irq_" as const;

/** Default intake TTL — 7 days. */
export const INTEGRATION_REQUEST_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * After expires_at, DECLINED/EXPIRED (and past-TTL terminal rows) stay readable
 * for this grace window; then the poll path collapses to the uniform 404.
 */
export const INTEGRATION_REQUEST_READ_GRACE_MS = 30 * 24 * 60 * 60 * 1000;

/** Global cap on live PENDING rows (open-endpoint abuse bound). */
export const INTEGRATION_REQUEST_PENDING_CAP = 100;

export interface ProposedIntegrationRule {
  readonly rule_id?: string;
  readonly per_send_max_zkz: string;
  readonly per_send_min_zkz: string | null;
  readonly window_hours: number;
  readonly window_cap_zkz: string;
  readonly expires_at: string | null;
}

export interface IntegrationRequestRow {
  readonly id: string;
  readonly node_id: string;
  readonly display_name: string;
  readonly requested_scopes: readonly ImplementerScope[];
  readonly proposed_rule_json: string;
  readonly approved_rule_json: string | null;
  readonly status: IntegrationRequestStatus;
  readonly row_version: number;
  readonly claim_token_hash: string;
  readonly created_at: string;
  readonly expires_at: string;
  readonly decided_at: string | null;
  readonly decided_by: string | null;
  readonly implementer_id: string | null;
  readonly issued_credential_id: string | null;
  readonly claimed_at: string | null;
}

export interface IntegrationRequestIntakeInput {
  readonly nodeId: string;
  readonly displayName: string;
  readonly requestedScopes: readonly IntegrationRequestIntakeScope[];
  readonly proposedRuleJson: string;
  readonly claimTokenHash: string;
  readonly requestId?: string;
  readonly now?: Date;
  readonly ttlMs?: number;
}

export interface IntegrationRequestIntakeResult {
  readonly request_id: string;
  readonly claim_token: string;
  readonly expires_at: string;
}

export type ClaimOutcome =
  | { readonly kind: "status"; readonly status: IntegrationRequestStatus }
  | {
      readonly kind: "key";
      readonly status: "CLAIMED";
      readonly api_key: string;
      readonly public_prefix: string;
      readonly scopes: readonly ImplementerScope[];
      readonly approved_rule: unknown;
      readonly implementer_id: string;
      readonly credential_id: string;
    }
  | { readonly kind: "not_found" };

export interface IntegrationRequestStore {
  countPending(): Promise<number>;
  insertPending(input: IntegrationRequestIntakeInput): Promise<IntegrationRequestRow>;
  findById(id: string): Promise<IntegrationRequestRow | null>;
  /**
   * Lazy-expire PENDING/APPROVED past expires_at via CAS. Returns the row after
   * the attempt (EXPIRED on success, prior row on CAS miss / not eligible).
   */
  lazyExpire(id: string, now: Date): Promise<IntegrationRequestRow | null>;
  /**
   * Atomic APPROVED→CLAIMED + credential issue under implementer_id.
   * Winner returns the raw key once; CAS loser returns status-only CLAIMED.
   */
  claimApproved(input: {
    readonly id: string;
    readonly claimTokenHash: string;
    readonly nodeId: string;
    readonly now: Date;
  }): Promise<ClaimOutcome>;
}

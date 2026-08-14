// Implementer registry port — named integration identities.
// Schema: packages/node-core/src/schema/node-implementer-registry.sql
// (id uuid PK, name text NOT NULL, created_at, retired_at)
// + implementer-funding-wallet.sql (funding_wallet_id nullable FK → wallets).
//
// Retire sets retired_at. Issuance under a retired implementer is refused;
// existing credentials KEEP working until revoked/expired — retirement is an
// issuance gate, not a credential kill switch.
//
// Funding wallet (ZTR-1287): reserve/proof pin for SplitChain verification.
// NULL funding_wallet_id means resolve via node default
// (integration.default_funding_wallet_id). Never a forced send/source pin.

export interface ImplementerRecord {
  readonly id: string;
  readonly name: string;
  readonly created_at: string;
  readonly retired_at: string | null;
  /**
   * Explicit funding wallet id, or null when the integration uses the
   * node-wide default (or no default is configured yet).
   */
  readonly funding_wallet_id: string | null;
  /**
   * Public key of the resolved funding wallet when `funding_wallet_id` is set
   * (joined from wallets.public_key). Null when no explicit pin — callers that
   * need the effective key must also resolve the node default setting.
   */
  readonly funding_wallet_public_key: string | null;
}

export interface ImplementerCreateInput {
  readonly name: string;
  /** Operator session id for the audit row (actor_kind=OPERATOR_SESSION). */
  readonly actorId: string;
  readonly nodeId: string;
}

export interface ImplementerRetireInput {
  readonly id: string;
  readonly actorId: string;
  readonly nodeId: string;
}

/** How an operator pins funding wallet on an integration (ZTR-1287). */
export type FundingWalletSetMode = "DEFAULT" | "WALLET_ID" | "CREATE";

export interface ImplementerSetFundingWalletInput {
  readonly implementerId: string;
  readonly mode: FundingWalletSetMode;
  /**
   * Required when mode is WALLET_ID. Ignored for DEFAULT.
   * For CREATE, optional pre-minted id when the caller mints outside the registry
   * and only attaches; when omitted under CREATE the registry refuses unless a
   * mint hook was provided to the SQL implementation.
   */
  readonly walletId?: string;
  readonly actorId: string;
  readonly nodeId: string;
}

export type ImplementerSetFundingWalletOutcome =
  | { readonly ok: true; readonly implementer: ImplementerRecord }
  | {
      readonly ok: false;
      readonly reason:
        | "implementer_not_found"
        | "implementer_retired"
        | "wallet_not_found"
        | "wallet_retired"
        | "wallet_id_required"
        | "create_not_supported"
        | "invalid_mode";
    };

/**
 * Registry of named integration identities. Implementations must write the
 * audit row (`implementer.created` / `implementer.retired` /
 * `implementer.funding_wallet_changed`) in the same persistence unit as the
 * row mutation.
 */
export interface ImplementerRegistry {
  list(): Promise<readonly ImplementerRecord[]>;
  get(id: string): Promise<ImplementerRecord | null>;
  /** Non-retired row or null (absent / retired both collapse to null). */
  getActive(id: string): Promise<ImplementerRecord | null>;
  /**
   * Genesis default: earliest non-retired implementer by created_at, then id.
   * Null when the registry is empty or every row is retired.
   */
  resolveGenesisId(): Promise<string | null>;
  create(input: ImplementerCreateInput): Promise<ImplementerRecord>;
  retire(input: ImplementerRetireInput): Promise<ImplementerRecord>;
  /**
   * Pin funding wallet (DEFAULT clears to node default; WALLET_ID attaches an
   * existing non-retired wallet; CREATE attaches a freshly minted wallet id
   * supplied by the caller after mint — registry does not hold vault keys).
   */
  setFundingWallet(
    input: ImplementerSetFundingWalletInput,
  ): Promise<ImplementerSetFundingWalletOutcome>;
}

export type ImplementerRegistryErrorCode =
  | "IMPLEMENTER_NOT_FOUND"
  | "IMPLEMENTER_ALREADY_RETIRED"
  | "IMPLEMENTER_NAME_INVALID";

export class ImplementerRegistryError extends Error {
  constructor(
    message: string,
    readonly code: ImplementerRegistryErrorCode,
  ) {
    super(message);
    this.name = "ImplementerRegistryError";
  }
}

export const IMPLEMENTER_AUDIT_CREATED = "implementer.created" as const;
export const IMPLEMENTER_AUDIT_RETIRED = "implementer.retired" as const;
export const IMPLEMENTER_AUDIT_FUNDING_WALLET_CHANGED =
  "implementer.funding_wallet_changed" as const;

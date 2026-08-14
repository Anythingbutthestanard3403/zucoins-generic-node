// Effective funding-wallet resolution for discovery / implementer identity (ZTR-1288).
//
// Precedence:
//   1. implementers.funding_wallet_id when set (and pubkey joins)
//   2. else node_settings integration.default_funding_wallet_id
//   3. else unset → both fields null (explicit; never a worker/send key)
//
// Funding wallet is reserve/proof for SplitChain verification — never a forced
// send/source pin. Callers MUST surface nulls as-is; no silent substitution.

export interface FundingWalletPin {
  readonly funding_wallet_id: string | null;
  readonly funding_wallet_public_key: string | null;
}

export interface EffectiveFundingWallet extends FundingWalletPin {
  /**
   * Where the pin came from. `unset` means both id and pubkey are null —
   * unhealthy for integrations that require a SplitChain-verifiable funding key.
   */
  readonly source: "implementer" | "node_default" | "unset";
  /**
   * True only when both id and public_key are non-null. A dangling id with a
   * missing pubkey is NOT healthy (operator must re-pin).
   */
  readonly configured: boolean;
}

/**
 * Resolve the effective funding wallet pin for an integration.
 * Pure: no I/O. Pass already-loaded implementer pin + node default snapshot.
 */
export function resolveEffectiveFundingWallet(input: {
  readonly implementerPin: FundingWalletPin | null | undefined;
  readonly nodeDefault: FundingWalletPin | null | undefined;
}): EffectiveFundingWallet {
  const impl = input.implementerPin;
  if (
    impl !== null &&
    impl !== undefined &&
    impl.funding_wallet_id !== null &&
    impl.funding_wallet_id !== undefined &&
    impl.funding_wallet_id.length > 0
  ) {
    const id = impl.funding_wallet_id;
    const key =
      impl.funding_wallet_public_key !== null &&
      impl.funding_wallet_public_key !== undefined &&
      impl.funding_wallet_public_key.length > 0
        ? impl.funding_wallet_public_key
        : null;
    return {
      funding_wallet_id: id,
      funding_wallet_public_key: key,
      source: "implementer",
      configured: key !== null,
    };
  }

  const def = input.nodeDefault;
  if (
    def !== null &&
    def !== undefined &&
    def.funding_wallet_id !== null &&
    def.funding_wallet_id !== undefined &&
    def.funding_wallet_id.length > 0
  ) {
    const id = def.funding_wallet_id;
    const key =
      def.funding_wallet_public_key !== null &&
      def.funding_wallet_public_key !== undefined &&
      def.funding_wallet_public_key.length > 0
        ? def.funding_wallet_public_key
        : null;
    return {
      funding_wallet_id: id,
      funding_wallet_public_key: key,
      source: "node_default",
      configured: key !== null,
    };
  }

  return {
    funding_wallet_id: null,
    funding_wallet_public_key: null,
    source: "unset",
    configured: false,
  };
}

/** Wire projection: only the two public fields (null when unset / unhealthy). */
export function toFundingWalletWireFields(effective: EffectiveFundingWallet): FundingWalletPin {
  return {
    funding_wallet_id: effective.funding_wallet_id,
    funding_wallet_public_key: effective.funding_wallet_public_key,
  };
}

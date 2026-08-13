/**
 * Per-wallet money capability presets and flag triples (ZTR-1267).
 *
 * Pure model only — no I/O. Schema CHECKs mirror this matrix; admission gates
 * (ZTR-1268) consume the eligibility helpers.
 */

export const WALLET_MONEY_MODES = [
  "RECEIVE_ONLY",
  "SEND_ONLY",
  "INTERNAL_ONLY",
  "FULL",
] as const;

export type WalletMoneyMode = (typeof WALLET_MONEY_MODES)[number];

/** New mint + backfill default: unrestricted (today's behaviour). */
export const WALLET_MONEY_CAPABILITY_DEFAULT_MODE: WalletMoneyMode = "FULL";

export interface WalletMoneyCapabilityFlags {
  readonly allow_external_receive: boolean;
  readonly allow_external_send: boolean;
  readonly allow_internal_move: boolean;
}

export const WALLET_MONEY_MODE_FLAGS: Readonly<
  Record<WalletMoneyMode, WalletMoneyCapabilityFlags>
> = {
  RECEIVE_ONLY: {
    allow_external_receive: true,
    allow_external_send: false,
    allow_internal_move: true,
  },
  SEND_ONLY: {
    allow_external_receive: false,
    allow_external_send: true,
    allow_internal_move: true,
  },
  INTERNAL_ONLY: {
    allow_external_receive: false,
    allow_external_send: false,
    allow_internal_move: true,
  },
  FULL: {
    allow_external_receive: true,
    allow_external_send: true,
    allow_internal_move: true,
  },
} as const;

export function isWalletMoneyMode(value: unknown): value is WalletMoneyMode {
  return (
    typeof value === "string" &&
    (WALLET_MONEY_MODES as readonly string[]).includes(value)
  );
}

export function flagsFromMode(mode: WalletMoneyMode): WalletMoneyCapabilityFlags {
  return WALLET_MONEY_MODE_FLAGS[mode];
}

/**
 * Resolve mode from flags. Returns null when the triple is not one of the four
 * frozen presets (illegal / incomplete).
 */
export function modeFromFlags(
  flags: WalletMoneyCapabilityFlags,
): WalletMoneyMode | null {
  for (const mode of WALLET_MONEY_MODES) {
    const expected = WALLET_MONEY_MODE_FLAGS[mode];
    if (
      expected.allow_external_receive === flags.allow_external_receive &&
      expected.allow_external_send === flags.allow_external_send &&
      expected.allow_internal_move === flags.allow_internal_move
    ) {
      return mode;
    }
  }
  return null;
}

export function isLegalMoneyCapabilityTriple(
  flags: WalletMoneyCapabilityFlags,
): boolean {
  return modeFromFlags(flags) !== null;
}

/** Receive-pool assign / arm eligibility conjunct (capability half). */
export function isEligibleForReceiveAssign(
  flags: WalletMoneyCapabilityFlags,
): boolean {
  return flags.allow_external_receive === true;
}

/** SEND_EXTERNAL source eligibility conjunct (capability half). */
export function isEligibleForSendSource(
  flags: WalletMoneyCapabilityFlags,
): boolean {
  return flags.allow_external_send === true;
}

/** MOVE_INTERNAL source or destination eligibility conjunct (capability half). */
export function isEligibleForMoveParty(
  flags: WalletMoneyCapabilityFlags,
): boolean {
  return flags.allow_internal_move === true;
}

/** Auto top-up hub: internal-only preset (never external send/receive). */
export function isInternalOnlyHub(flags: WalletMoneyCapabilityFlags): boolean {
  return modeFromFlags(flags) === "INTERNAL_ONLY";
}

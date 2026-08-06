/**
 * What the generic core supplies, and what it deliberately does not.
 */
export const CORE_CAPABILITIES = [
  "NODE_IDENTITY",
  "DISCOVERY",
  "EXPECTED_ARTIFACT_VERIFICATION",
] as const;

export type CoreCapability = (typeof CORE_CAPABILITIES)[number];

/**
 * Launch deferral: greenfield launch exposes no wallet-key import endpoint, and leaves IMPORTED_DRAIN
 * absent. WALLET_IMPORT and IMPORTED_DRAIN form one indivisible future feature; neither may
 * ship alone.
 */
export const ABSENT_CAPABILITIES = {
  WALLET_IMPORT: "absent",
  IMPORTED_DRAIN: "absent",
} as const;

/** Deliberate launch exclusions, transcribed verbatim and in their canonical sequence. */
export const LAUNCH_EXCLUSIONS = [
  "imported wallets and imported-wallet drain", // contract-allow:launch-exclusion-citation
  "arbitrary workflows or more than one automatic child move",
  "batch external-send approval",
  "M-of-N operator approval",
  "multi-asset or asset-exchange behavior",
  "cross-node internal movement",
  "platform or browser custody",
  "retrospective proof reconstruction after the live verification window",
  "any automatic recovery action that would create a second possibly competing transaction",
] as const;

export const SOURCE = "core capabilities and launch exclusions" as const;

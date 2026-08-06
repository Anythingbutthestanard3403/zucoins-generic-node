/**
 * The chain-link rule and role-relative state ("For genesis, S=P=\"\" and B=\"0\"");
 * A.7 (GENESIS/HEAD fingerprint state kinds), A.9 negative vector 17 (funded sender with an
 * empty genesis predecessor); the `VERIFIED_GENESIS` parse result.
 *
 * the fixture-provenance purposes census — the frozen genesis vocabulary. DATA ONLY so `gen/genesis.json` stays a clean
 * review-diff snapshot. The `VERIFIED_GENESIS`/`VERIFIED_HEAD` observation parse results are
 * OWNED by `src/observation/enums.contract.ts` and only referenced here.
 */

/** Manifest version (v1 `*_CONTRACT_VERSION` discipline): bump on any reviewed change. */
export const GENESIS_CONTRACT_VERSION = 1 as const;

/** A wallet at genesis has no prior settled transaction: the state signature link is the empty
 *  signature string (protocol rules 1.5 and 5). */
export const GENESIS_STATE_SIGNATURE = "" as const;

/** A wallet at genesis has balance "0" (protocol rule 5). */
export const GENESIS_BALANCE = "0" as const;

/**
 * A wallet's chain link is its most recent settled transaction's `step_2_signature`, regardless
 * of whether it was step-1 sender or step-2 receiver in that transaction; genesis is signature
 * `""` and balance `"0"` (protocol rule 1.5).
 */
export const WALLET_CHAIN_LINK_RULE = {
  linkField: "step_2_signature",
  roleIndependent: true,
  genesisLink: GENESIS_STATE_SIGNATURE,
  genesisBalance: GENESIS_BALANCE,
} as const;

/** The `state_kind` closed set of `zp-wallet-head-fingerprint-v1` (A.7). */
export const WALLET_HEAD_STATE_KINDS = ["GENESIS", "HEAD"] as const;

/** The fingerprint field values AT genesis (A.7): empty signatures, null chain digests. */
export const GENESIS_FINGERPRINT_VALUES = {
  stateKind: "GENESIS",
  sSignature: "",
  pSignature: "",
  bAmount: GENESIS_BALANCE,
  innerSha256: null,
  step1Signature: null,
  step2Signature: null,
} as const;

/**
 * A.9 negative vector 17: a validly re-signed RECEIVE target whose funded sender presents an
 * EMPTY genesis predecessor fails specifically as `funded-sender/genesis-predecessor` during
 * sender preflight — before receiver co-sign or submit. A funded sender (a non-zero preflight
 * balance) cannot have a genesis link; the empty predecessor is only valid for an unfunded
 * (genesis) wallet.
 */
export const FUNDED_SENDER_GENESIS_PREDECESSOR_REJECTION = {
  rejectionCode: "funded-sender/genesis-predecessor",
  stage: "sender preflight, before receiver co-sign or submit",
  emptyPredecessorValidOnlyAtGenesis: true,
} as const;

/** The observation parse result for a verified genesis observation is OWNED by
 *  `src/observation/enums.contract.ts` (`VERIFIED_GENESIS`); genesis is a role in the
 *  `gateway_observations.wallet_role` CHECK domain there, and a terminal (never an entry) in
 *  the landing-proof ancestry walk. */
export const GENESIS_OBSERVATION_VOCABULARY_OWNER = "src/observation/enums.contract.ts" as const;

export const SOURCE = "protocol rules 1.5,5; A.7,A.9; data model 2" as const;

// the crypto-goldens freeze — Unified cryptographic golden-vector fixture set.
// Re-exports the frozen golden constants and negative-vector definitions.
export {
  COMPAT_LITERALS,
  EVENT_HASH_CHAIN,
  FIXTURE_IDS,
  PREDECESSOR_DIGESTS,
  PREDECESSOR_STEP_1_PREIMAGE,
  SEED_PUBLIC_KEYS,
  SEED_ROLES,
  SEND_PARTIAL_DIGESTS,
  SEND_PARTIAL_STEP_1_PREIMAGE,
  SUITE_GOLDEN_OUTPUTS,
  SUITE_GOLDEN_PREIMAGES,
  TARGET_DIGESTS,
  TARGET_STEP_1_PREIMAGE,
} from "./goldens.js";
export type { SuiteGoldenKey } from "./goldens.js";
export {
  ALL_NEGATIVE_VECTORS,
  GENERAL_NEGATIVE_COUNT,
  GENERAL_NEGATIVE_VECTORS,
  REGISTER_NEGATIVE_COUNT,
  REGISTER_NEGATIVE_VECTORS,
  TOTAL_NEGATIVE_COUNT,
} from "./negative-vectors.js";
export type { NegativeVector } from "./negative-vectors.js";
export { CRYPTO_GOLDENS_CONCERN_MANIFEST } from "./manifest.ts";

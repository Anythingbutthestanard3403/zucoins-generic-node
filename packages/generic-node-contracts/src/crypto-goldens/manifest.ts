// Crypto-goldens concern manifest: the unified cryptographic golden-vector fixture set.
// Aggregates ALL frozen golden bytes from A.8.1 (SplitChain) and A.8.2 (suite tuples) into one
// self-registered ConcernManifest for the concern-manifest registry assembly.

import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  EVENT_HASH_CHAIN,
  PREDECESSOR_DIGESTS,
  SEND_PARTIAL_DIGESTS,
  SUITE_GOLDEN_OUTPUTS,
  TARGET_DIGESTS,
} from "./goldens.js";
import { GENERAL_NEGATIVE_COUNT, REGISTER_NEGATIVE_COUNT, TOTAL_NEGATIVE_COUNT } from "./negative-vectors.js";

export const CRYPTO_GOLDENS_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "crypto-goldens",
  decisionRefs: ["artifacts-freeze", "compatibility-literals", "two-timer-separation", "reporting-key-enrolment"],
  frozenValues: {
    cryptoGoldens: {
      concern: "crypto-goldens",
      ticket: "crypto-goldens-fixtures",
      governing: {
        spec: "canonical serialization A.1.1, A.1.2; goldens A.8; negative vectors A.9",
        decisions: ["artifacts-freeze", "compatibility-literals", "two-timer-separation", "reporting-key-enrolment"],
      },
      splitChainGoldens: {
        sendPartial: {
          step_1_sha256: SEND_PARTIAL_DIGESTS.step_1_sha256,
          step_2_sha256: SEND_PARTIAL_DIGESTS.step_2_sha256,
          full_tx_sha256: SEND_PARTIAL_DIGESTS.full_tx_sha256,
          transfer_code_sha256: SEND_PARTIAL_DIGESTS.transfer_code_sha256,
        },
        predecessor: {
          step_1_sha256: PREDECESSOR_DIGESTS.step_1_sha256,
          step_2_sha256: PREDECESSOR_DIGESTS.step_2_sha256,
          settled_sha256: PREDECESSOR_DIGESTS.settled_sha256,
        },
        target: {
          step_1_sha256: TARGET_DIGESTS.step_1_sha256,
          step_2_sha256: TARGET_DIGESTS.step_2_sha256,
          settled_sha256: TARGET_DIGESTS.settled_sha256,
          transfer_code_sha256: TARGET_DIGESTS.transfer_code_sha256,
        },
      },
      suiteTupleGoldens: Object.fromEntries(
        Object.entries(SUITE_GOLDEN_OUTPUTS).map(([key, output]) => [key, { sha256: output.sha256 }]),
      ),
      eventHashChain: { ...EVENT_HASH_CHAIN },
      negativeVectors: {
        general: GENERAL_NEGATIVE_COUNT,
        reportingRegister: REGISTER_NEGATIVE_COUNT,
        total: TOTAL_NEGATIVE_COUNT,
      },
    },
  },
  goldenRefs: [
    {
      path: "src/crypto-goldens/gen/crypto-goldens.json",
      sha256: "434e243b475ad25da7a3f146ac8286f9a9041141c6f5890f3a9a6bde3ac1a288",
    },
  ],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "canonical serialization A.1.1",
    "native signing A.1.2",
    "byte goldens A.8",
    "negative vectors A.9",
    "artifacts-freeze",
    "compatibility-literals",
    "two-timer-separation",
    "reporting-key-enrolment",
  ],
});

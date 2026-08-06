import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  OBSERVER_DOMAINS,
  OBSERVATION_PARSE_RESULTS,
  VERIFIED_PARSE_RESULTS,
  OBSERVATION_RELATIONSHIPS,
  WALLET_OBSERVATION_ROLES,
  OBSERVATION_ANOMALY_KINDS,
} from "./enums.contract.ts";
import {
  SHA256_HEX_PATTERN,
  PADDED_BASE64URL_PUBKEY_PATTERN,
  PADDED_BASE64URL_PUBKEY_LENGTH,
  PADDED_BASE64URL_SIGNATURE_PATTERN,
  PADDED_BASE64URL_SIGNATURE_LENGTH,
  ZKZ_BALANCE_TEXT_PATTERN,
} from "./scalars.contract.ts";
import {
  RAW_OBSERVATION_CAPTURE_FIELDS,
  GATEWAY_OBSERVATION_RECORD_FIELDS,
  WALLET_OBSERVATION_CURSOR_FIELDS,
  OBSERVATION_ANOMALY_RECORD_FIELDS,
} from "./record-fields.contract.ts";
import { RECORD_INVARIANTS } from "./invariants.contract.ts";
import {
  CONSECUTIVE_DEDUP_KEY,
  DIGEST_ROLE,
  APPEND_OUTCOMES,
  SUPPRESSION_PRECONDITIONS,
  RETENTION_RULE,
} from "./dedup.contract.ts";
import {
  COMPARISON_LADDER,
  RELATIONSHIP_CLASSIFICATION_RULES,
  CLASSIFIER_OUTPUT_RELATIONSHIPS,
  NON_CLASSIFIER_RELATIONSHIPS,
  STATE_UNCHANGED_RELATIONSHIP,
} from "./relationship.contract.ts";
import { GOLDEN_SEQUENCES, SEQUENCE_PROPERTIES } from "./sequences.contract.ts";

/**
 * The aggregated frozen observation-record contract. gen/observation.json is a review-diff
 * snapshot of exactly this object (tier 2, never byte authority); the `.contract.ts` `as
 * const` sources are the authority. gen-sync.test.ts fails if the two diverge.
 */
export const OBSERVATION_CONTRACT = {
  enums: {
    OBSERVER_DOMAINS,
    OBSERVATION_PARSE_RESULTS,
    VERIFIED_PARSE_RESULTS,
    OBSERVATION_RELATIONSHIPS,
    WALLET_OBSERVATION_ROLES,
    OBSERVATION_ANOMALY_KINDS,
  },
  scalars: {
    SHA256_HEX_PATTERN,
    PADDED_BASE64URL_PUBKEY_PATTERN,
    PADDED_BASE64URL_PUBKEY_LENGTH,
    PADDED_BASE64URL_SIGNATURE_PATTERN,
    PADDED_BASE64URL_SIGNATURE_LENGTH,
    ZKZ_BALANCE_TEXT_PATTERN,
  },
  records: {
    RAW_OBSERVATION_CAPTURE_FIELDS,
    GATEWAY_OBSERVATION_RECORD_FIELDS,
    WALLET_OBSERVATION_CURSOR_FIELDS,
    OBSERVATION_ANOMALY_RECORD_FIELDS,
  },
  invariants: RECORD_INVARIANTS,
  dedup: {
    CONSECUTIVE_DEDUP_KEY,
    DIGEST_ROLE,
    APPEND_OUTCOMES,
    SUPPRESSION_PRECONDITIONS,
    RETENTION_RULE,
  },
  relationship: {
    COMPARISON_LADDER,
    RELATIONSHIP_CLASSIFICATION_RULES,
    CLASSIFIER_OUTPUT_RELATIONSHIPS,
    NON_CLASSIFIER_RELATIONSHIPS,
    STATE_UNCHANGED_RELATIONSHIP,
  },
  sequences: {
    GOLDEN_SEQUENCES,
    SEQUENCE_PROPERTIES,
  },
} as const;

/**
 * the observation concern's self-registered ConcernManifest (concern dir src/observation/). Seeded by
 * the observation dedup freeze (raw observation record contract); the observation concern.2 (dedup semantics) and the observation concern.3
 * (sequence proofs) extend this manifest. Registration export only — the concern-manifest registry assembles
 * src/registry.ts. The goldenRef sha256 pins gen/observation.json and is regenerated with it.
 */
export const OBSERVATION_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "observation",
  decisionRefs: ["observation-dedup", "complete-path-adjudication", "zkz-amount-grammar"],
  frozenValues: {
    OBSERVER_DOMAINS,
    OBSERVATION_PARSE_RESULTS,
    OBSERVATION_RELATIONSHIPS,
    WALLET_OBSERVATION_ROLES,
    OBSERVATION_ANOMALY_KINDS,
    RAW_OBSERVATION_CAPTURE_FIELDS,
    GATEWAY_OBSERVATION_RECORD_FIELDS,
    WALLET_OBSERVATION_CURSOR_FIELDS,
    OBSERVATION_ANOMALY_RECORD_FIELDS,
    RECORD_INVARIANTS,
    CONSECUTIVE_DEDUP_KEY,
    DIGEST_ROLE,
    RETENTION_RULE,
    COMPARISON_LADDER,
    RELATIONSHIP_CLASSIFICATION_RULES,
    CLASSIFIER_OUTPUT_RELATIONSHIPS,
    STATE_UNCHANGED_RELATIONSHIP,
    GOLDEN_SEQUENCES,
    SEQUENCE_PROPERTIES,
  },
  goldenRefs: [
    {
      path: "gen/observation.json",
      sha256: "5b3f801c14624da539e0c9fea99ed37a160726cfd8f7de2962d8c29ccd98ec78",
    },
  ],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "freeze-gate: permanent retention",
    "product-evaluation: observation feed",
    "data-model: enum vocabulary",
    "data-model: observation tables",
    "observation-verification: capture and classification",
    "observation-verification: retention and goldens",
    "integration: observation feed",
    "decision: observation-dedup",
    "decision: complete-path-adjudication",
    "decision: zkz-amount-grammar",
  ],
});

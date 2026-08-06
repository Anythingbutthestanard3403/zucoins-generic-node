import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  VAULT_STORAGE_GRAIN,
  VAULT_TABLE_NAME,
  VAULT_PRIMARY_KEY,
  VAULT_VERSION_COLUMN,
  STORAGE_RESOLUTION,
  ENVELOPE_STRUCTURE,
  REQUIRED_VAULT_MODEL,
  REJECTED_DRAFT_DESCRIPTOR,
} from "./storage.contract.ts";
import { KEY_DERIVATION, KEY_ISOLATION } from "./crypto.contract.ts";
import {
  AAD_DOMAIN,
  AAD_BINDING,
  SUBSTITUTION_CONTROL,
  SUPERSEDED_DRAFT_AAD,
} from "./aad.contract.ts";
import {
  ROTATION_STATES,
  ROTATION_TRANSITIONS,
  ROTATION_INVARIANTS,
  SIGNING_CONCURRENCY,
  RECOVERY,
} from "./lifecycle.contract.ts";
import {
  CARRIED_FORWARD_INVARIANTS,
  KEY_VERSION_SEMANTICS,
  SEALED_STORE_CENSUS,
  ZEROIZATION,
  DEFERRED_SUBCONTRACTS,
} from "./compatibility.contract.ts";
import {
  VAULT_COLUMNS,
  VAULT_CONSTRAINTS,
  VAULT_KEY_IDENTITY,
} from "./vault-schema.contract.ts";
import { AAD_SERIALIZATION, AAD_FULL_FIELD_SEQUENCE, AAD_GOLDEN } from "./aad-serialization.ts";
import {
  HKDF_DEK_LABEL,
  HKDF_INFO_ENCODING,
  HKDF_PARAMS,
  CROSS_STORE_LABEL_SEPARATION,
  HKDF_INFO_GOLDEN,
} from "./hkdf-info.ts";
import {
  CANONICAL_FIELD_PINS,
  AAD_SOURCE_INJECTIVITY,
  LABEL_FIELD_COUPLING,
  LABEL_VERSION_RULE,
} from "./canonicalization.contract.ts";
import {
  SEALING_API,
  SIGNER_BOUNDARY,
  LEADERSHIP_RULES,
  ZEROIZATION_INTERFACE,
} from "./interfaces.contract.ts";
import { VAULT_OPEN_FAILURE_CODES, NO_HYBRID_FALLBACK } from "./failure-behavior.ts";
import { THREAT_MATRIX, D9_11_GUARDS } from "./threat-model.contract.ts";

/**
 * The aggregated vault ARCHITECTURE contract (the vault model freeze). gen/vault.json is a review-diff
 * snapshot of exactly this object (tier 2, never byte authority); the `.contract.ts` `as const`
 * sources are authority. gen-sync.test.ts fails if the two diverge.
 */
export const VAULT_CONTRACT = {
  storage: {
    VAULT_STORAGE_GRAIN,
    VAULT_TABLE_NAME,
    VAULT_PRIMARY_KEY,
    VAULT_VERSION_COLUMN,
    STORAGE_RESOLUTION,
    ENVELOPE_STRUCTURE,
    REQUIRED_VAULT_MODEL,
    REJECTED_DRAFT_DESCRIPTOR,
  },
  crypto: { KEY_DERIVATION, KEY_ISOLATION },
  aad: { AAD_DOMAIN, AAD_BINDING, SUBSTITUTION_CONTROL, SUPERSEDED_DRAFT_AAD },
  lifecycle: {
    ROTATION_STATES,
    ROTATION_TRANSITIONS,
    ROTATION_INVARIANTS,
    SIGNING_CONCURRENCY,
    RECOVERY,
  },
  compatibility: {
    CARRIED_FORWARD_INVARIANTS,
    KEY_VERSION_SEMANTICS,
    SEALED_STORE_CENSUS,
    ZEROIZATION,
    DEFERRED_SUBCONTRACTS,
  },
  schema: { VAULT_COLUMNS, VAULT_CONSTRAINTS, VAULT_KEY_IDENTITY },
  serialization: {
    AAD_SERIALIZATION,
    AAD_FULL_FIELD_SEQUENCE,
    AAD_GOLDEN,
    HKDF_DEK_LABEL,
    HKDF_INFO_ENCODING,
    HKDF_PARAMS,
    CROSS_STORE_LABEL_SEPARATION,
    HKDF_INFO_GOLDEN,
  },
  canonicalization: {
    CANONICAL_FIELD_PINS,
    AAD_SOURCE_INJECTIVITY,
    LABEL_FIELD_COUPLING,
    LABEL_VERSION_RULE,
  },
  interfaces: { SEALING_API, SIGNER_BOUNDARY, LEADERSHIP_RULES, ZEROIZATION_INTERFACE },
  failure: { VAULT_OPEN_FAILURE_CODES, NO_HYBRID_FALLBACK },
  threats: { THREAT_MATRIX, D9_11_GUARDS },
} as const;

/**
 * the vault concern's self-registered ConcernManifest (concern dir src/vault/). Seeded by the vault model freeze (the
 * architecture ADR); the vault schema freeze (schema + interfaces) and the vault threat-model freeze (threat model) extend it.
 * Registration export only — the concern-manifest registry assembles src/registry.ts. Custody-sensitive: this ADR
 * fixes design only and authorizes no key access or ZKZ movement.
 */
export const VAULT_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "vault",
  decisionRefs: [
    "vault-storage-model",
    "single-blob-vault-precursor",
    "vault-column-names",
    "secure-buffer",
    "sealed-store",
  ],
  frozenValues: {
    VAULT_STORAGE_GRAIN,
    VAULT_TABLE_NAME,
    VAULT_VERSION_COLUMN,
    STORAGE_RESOLUTION,
    ENVELOPE_STRUCTURE,
    REQUIRED_VAULT_MODEL,
    KEY_DERIVATION,
    KEY_ISOLATION,
    AAD_BINDING,
    SUBSTITUTION_CONTROL,
    ROTATION_TRANSITIONS,
    ROTATION_INVARIANTS,
    SIGNING_CONCURRENCY,
    RECOVERY,
    CARRIED_FORWARD_INVARIANTS,
    KEY_VERSION_SEMANTICS,
    SEALED_STORE_CENSUS,
    ZEROIZATION,
    DEFERRED_SUBCONTRACTS,
    VAULT_COLUMNS,
    VAULT_CONSTRAINTS,
    AAD_SERIALIZATION,
    AAD_GOLDEN,
    HKDF_INFO_ENCODING,
    HKDF_INFO_GOLDEN,
    SEALING_API,
    SIGNER_BOUNDARY,
    LEADERSHIP_RULES,
    ZEROIZATION_INTERFACE,
    VAULT_OPEN_FAILURE_CODES,
    NO_HYBRID_FALLBACK,
    THREAT_MATRIX,
    D9_11_GUARDS,
    HKDF_PARAMS,
    CROSS_STORE_LABEL_SEPARATION,
    CANONICAL_FIELD_PINS,
    AAD_SOURCE_INJECTIVITY,
    LABEL_FIELD_COUPLING,
  },
  goldenRefs: [
    {
      path: "gen/vault.json",
      sha256: "da37c41bb2dd6d2361dd18676c2f611c824c8c30b6e947028bb05b34d42a97a0",
    },
  ],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "data-model: vault table",
    "signing-custody: vault",
    "decision: single-blob-vault-precursor",
    "decision: vault-column-names",
    "decision: vault-storage-model",
    "decision: secure-buffer",
    "decision: sealed-store",
    "SO conflicts",
  ],
});

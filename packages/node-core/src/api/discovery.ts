// Discovery and health.
// GET /.well-known/zupay-node is public, returns the node identity document.
// GET /health is public, returns basic liveness.
//
// Wire field names match packages/generic-node-contracts DISCOVERY_RESPONSE_FIELDS
// (canon prose under snake_case normalisation).

import { z } from "zod";
import { UuidSchema, WalletPublicKeySchema, Rfc3339MsSchema } from "./scalars.js";
import { OPERATION_KINDS, type OperationKind } from "@zucoins/generic-node-contracts/operations";
import { DISCOVERY_RESPONSE_FIELDS } from "@zucoins/generic-node-contracts/api-schema";

export const KeyValidityIntervalSchema = z
  .object({
    key_id: UuidSchema,
    valid_from: Rfc3339MsSchema,
    valid_until: Rfc3339MsSchema.nullable(),
  })
  .strict();

export const DiscoveryPublicKeySchema = z
  .object({
    key_id: UuidSchema,
    public_key: WalletPublicKeySchema,
  })
  .strict();

/** @deprecated Use DiscoveryPublicKeySchema — validity lives at top-level key_validity_intervals. */
export const DiscoveryKeyEntrySchema = DiscoveryPublicKeySchema;

export const NodeIdentityDocumentSchema = z
  .object({
    node_id: UuidSchema,
    api_version: z.string(),
    supported_operation_types: z.array(z.enum(OPERATION_KINDS)),
    event_signing_public_keys: z.array(DiscoveryPublicKeySchema),
    expected_artifact_public_keys: z.array(DiscoveryPublicKeySchema),
    canonical_suite_versions: z.array(z.string()),
    key_validity_intervals: z.array(KeyValidityIntervalSchema),
  })
  .strict();

export type KeyValidityInterval = z.infer<typeof KeyValidityIntervalSchema>;
export type DiscoveryPublicKey = z.infer<typeof DiscoveryPublicKeySchema>;
export type DiscoveryKeyEntry = DiscoveryPublicKey;
export type NodeIdentityDocument = z.infer<typeof NodeIdentityDocumentSchema>;

export interface DiscoveryKeyConfig {
  readonly keyId: string;
  readonly publicKey: string;
  readonly validFrom: string;
  readonly validUntil: string | null;
}

export interface DiscoveryConfig {
  readonly nodeId: string;
  readonly apiVersion: string;
  readonly supportedOperations: readonly OperationKind[];
  readonly canonicalSuites: readonly string[];
  readonly eventSigningKeys: readonly DiscoveryKeyConfig[];
  readonly artifactSigningKeys: readonly DiscoveryKeyConfig[];
}

export function buildNodeIdentityDocument(config: DiscoveryConfig): NodeIdentityDocument {
  const eventKeys = config.eventSigningKeys.map(toPublicKey);
  const artifactKeys = config.artifactSigningKeys.map(toPublicKey);
  const intervals = dedupeIntervalsByKeyId([
    ...config.eventSigningKeys.map(toInterval),
    ...config.artifactSigningKeys.map(toInterval),
  ]);

  const doc: NodeIdentityDocument = {
    node_id: config.nodeId,
    api_version: config.apiVersion,
    supported_operation_types: [...config.supportedOperations],
    event_signing_public_keys: eventKeys,
    expected_artifact_public_keys: artifactKeys,
    canonical_suite_versions: [...config.canonicalSuites],
    key_validity_intervals: intervals,
  };

  // Fail closed if builder drift reorders / renames canon fields.
  const keys = Object.keys(doc) as (typeof DISCOVERY_RESPONSE_FIELDS)[number][];
  if (keys.length !== DISCOVERY_RESPONSE_FIELDS.length) {
    throw new Error("discovery document field count drifted from DISCOVERY_RESPONSE_FIELDS");
  }
  for (let i = 0; i < DISCOVERY_RESPONSE_FIELDS.length; i++) {
    if (keys[i] !== DISCOVERY_RESPONSE_FIELDS[i]) {
      throw new Error(
        `discovery field order/name mismatch at ${i}: got ${keys[i]}, want ${DISCOVERY_RESPONSE_FIELDS[i]}`, // contract-allow:order:frozen structural vocabulary
      );
    }
  }

  return doc;
}

function toPublicKey(key: DiscoveryKeyConfig): DiscoveryPublicKey {
  return {
    key_id: key.keyId,
    public_key: key.publicKey,
  };
}

function toInterval(key: DiscoveryKeyConfig): KeyValidityInterval {
  return {
    key_id: key.keyId,
    valid_from: key.validFrom,
    valid_until: key.validUntil,
  };
}

function dedupeIntervalsByKeyId(
  intervals: readonly KeyValidityInterval[],
): KeyValidityInterval[] {
  const seen = new Set<string>();
  const out: KeyValidityInterval[] = [];
  for (const interval of intervals) {
    if (seen.has(interval.key_id)) continue;
    seen.add(interval.key_id);
    out.push(interval);
  }
  return out;
}

export interface HealthStatus {
  readonly status: "ok" | "degraded" | "unavailable";
  readonly version: string;
  readonly timestamp: string;
}

export function buildHealthResponse(
  version: string,
  databaseReady: boolean,
  now?: () => string,
): HealthStatus {
  const timestamp = (now ?? (() => new Date().toISOString()))();
  return {
    status: databaseReady ? "ok" : "unavailable",
    version,
    timestamp,
  };
}

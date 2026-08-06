/**
 * SOURCE: the API contract, discovery endpoint.
 *
 * The discovery endpoint response shape. `GET /.well-known/zupay-node` is public and returns
 * node identity, API version, supported operation types, event-signing public keys,
 * expected-artifact public keys, canonical-suite versions, and key validity intervals.
 * The `zupay` literal is intentionally retained.
 */

/** The discovery endpoint path. */
export const DISCOVERY_PATH = "/.well-known/zupay-node" as const;

/** The discovery response field names in their documented sequence. */
export const DISCOVERY_RESPONSE_FIELDS = [
  "node_id",
  "api_version",
  "supported_operation_types",
  "event_signing_public_keys",
  "expected_artifact_public_keys",
  "canonical_suite_versions",
  "key_validity_intervals",
] as const;

/** Properties the discovery endpoint must NOT expose. */
export const DISCOVERY_EXCLUSIONS = [
  "private_configuration",
  "gateway_credential",
  "implementer_list",
  "wallet_list",
  "health_detail",
] as const;

export const SOURCE = "api-contract: discovery endpoint" as const;

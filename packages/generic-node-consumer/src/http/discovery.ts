/**
 * Public discovery (`GET /.well-known/zupay-node`) and implementer who-am-I
 * (`GET /v1/implementer/identity`). Parses `verification_mode` with the
 * contracts vocabulary. Omitted / null fails closed — the node always emits it
 * (ZTR-1319); inventing INDEPENDENT would assert a default the node never stated.
 */

import { DISCOVERY_PATH } from "@zucoins/generic-node-contracts/instruction-origin";

import { assertOk } from "./errors.js";
import { resolveFetch, resolveUrl, type NodeClientConfig } from "./client-types.js";
import {
  parseVerificationMode,
  type VerificationMode,
} from "../verification-mode.js";

export { DISCOVERY_PATH };

export const IMPLEMENTER_IDENTITY_PATH = "/v1/implementer/identity" as const;

export interface DiscoveryKeyWireEntry {
  readonly key_id: string;
  readonly public_key: string;
}

export interface DiscoveryKeyValidityWire {
  readonly key_id: string;
  readonly valid_from: string;
  readonly valid_until: string | null;
}

/**
 * Identity document from `GET /.well-known/zupay-node`.
 * `verification_mode` is required on the wire (node always emits it).
 */
export interface NodeIdentityDocument {
  readonly node_id: string;
  readonly api_version: string;
  readonly supported_operation_types: readonly string[];
  readonly event_signing_public_keys: readonly DiscoveryKeyWireEntry[];
  readonly expected_artifact_public_keys: readonly DiscoveryKeyWireEntry[];
  readonly canonical_suite_versions: readonly string[];
  readonly key_validity_intervals: readonly DiscoveryKeyValidityWire[];
  readonly funding_wallet_id: string | null;
  readonly funding_wallet_public_key: string | null;
  readonly verification_mode: VerificationMode;
}

export type FundingSource = "implementer" | "node_default" | "unset";

/**
 * Who-am-I document from `GET /v1/implementer/identity`.
 * `verification_mode` is required on the wire (node always emits it).
 */
export interface ImplementerIdentityDocument {
  readonly implementer_id: string;
  readonly funding_wallet_id: string | null;
  readonly funding_wallet_public_key: string | null;
  readonly funding_configured: boolean;
  readonly funding_source: FundingSource;
  readonly verification_mode: VerificationMode;
}

export class IdentityDocumentError extends Error {
  readonly code = "IDENTITY_DOCUMENT_DRIFT" as const;
  readonly detail: string;

  constructor(detail: string) {
    super(detail);
    this.name = "IdentityDocumentError";
    this.detail = detail;
  }
}

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null) {
    throw new IdentityDocumentError(`${label} was not an object`);
  }
  return value as Record<string, unknown>;
}

function asString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new IdentityDocumentError(`${field} must be a non-empty string`);
  }
  return value;
}

function asNullableString(value: unknown, field: string): string | null {
  if (value === null) return null;
  if (typeof value !== "string") {
    throw new IdentityDocumentError(`${field} must be a string or null`);
  }
  return value;
}

function asKeyEntry(value: unknown, field: string): DiscoveryKeyWireEntry {
  const rec = asRecord(value, field);
  return {
    key_id: asString(rec.key_id, `${field}.key_id`),
    public_key: asString(rec.public_key, `${field}.public_key`),
  };
}

function asKeyEntries(value: unknown, field: string): readonly DiscoveryKeyWireEntry[] {
  if (!Array.isArray(value)) {
    throw new IdentityDocumentError(`${field} must be an array`);
  }
  return value.map((entry, i) => asKeyEntry(entry, `${field}[${i}]`));
}

function asInterval(value: unknown, field: string): DiscoveryKeyValidityWire {
  const rec = asRecord(value, field);
  return {
    key_id: asString(rec.key_id, `${field}.key_id`),
    valid_from: asString(rec.valid_from, `${field}.valid_from`),
    valid_until: asNullableString(rec.valid_until, `${field}.valid_until`),
  };
}

function asIntervals(value: unknown, field: string): readonly DiscoveryKeyValidityWire[] {
  if (!Array.isArray(value)) {
    throw new IdentityDocumentError(`${field} must be an array`);
  }
  return value.map((entry, i) => asInterval(entry, `${field}[${i}]`));
}

function asStringArray(value: unknown, field: string): readonly string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new IdentityDocumentError(`${field} must be an array of strings`);
  }
  return value as string[];
}

const FUNDING_SOURCES: ReadonlySet<string> = new Set(["implementer", "node_default", "unset"]);

function asFundingSource(value: unknown): FundingSource {
  if (typeof value !== "string" || !FUNDING_SOURCES.has(value)) {
    throw new IdentityDocumentError("funding_source is outside the closed vocabulary");
  }
  return value as FundingSource;
}

function requireVerificationMode(value: unknown): VerificationMode {
  if (value === undefined || value === null) {
    throw new IdentityDocumentError("verification_mode is required");
  }
  return parseVerificationMode(value);
}

/** Parse `GET /.well-known/zupay-node`. Missing / unknown `verification_mode` fails closed. */
export function parseNodeIdentityDocument(value: unknown): NodeIdentityDocument {
  const rec = asRecord(value, "discovery document");
  return {
    node_id: asString(rec.node_id, "node_id"),
    api_version: asString(rec.api_version, "api_version"),
    supported_operation_types: asStringArray(
      rec.supported_operation_types,
      "supported_operation_types",
    ),
    event_signing_public_keys: asKeyEntries(
      rec.event_signing_public_keys,
      "event_signing_public_keys",
    ),
    expected_artifact_public_keys: asKeyEntries(
      rec.expected_artifact_public_keys,
      "expected_artifact_public_keys",
    ),
    canonical_suite_versions: asStringArray(
      rec.canonical_suite_versions,
      "canonical_suite_versions",
    ),
    key_validity_intervals: asIntervals(rec.key_validity_intervals, "key_validity_intervals"),
    funding_wallet_id: asNullableString(rec.funding_wallet_id, "funding_wallet_id"),
    funding_wallet_public_key: asNullableString(
      rec.funding_wallet_public_key,
      "funding_wallet_public_key",
    ),
    verification_mode: requireVerificationMode(rec.verification_mode),
  };
}

/** Parse `GET /v1/implementer/identity`. Missing / unknown `verification_mode` fails closed. */
export function parseImplementerIdentityDocument(value: unknown): ImplementerIdentityDocument {
  const rec = asRecord(value, "implementer identity");
  if (typeof rec.funding_configured !== "boolean") {
    throw new IdentityDocumentError("funding_configured must be a boolean");
  }
  return {
    implementer_id: asString(rec.implementer_id, "implementer_id"),
    funding_wallet_id: asNullableString(rec.funding_wallet_id, "funding_wallet_id"),
    funding_wallet_public_key: asNullableString(
      rec.funding_wallet_public_key,
      "funding_wallet_public_key",
    ),
    funding_configured: rec.funding_configured,
    funding_source: asFundingSource(rec.funding_source),
    verification_mode: requireVerificationMode(rec.verification_mode),
  };
}

export interface GetDiscoveryInput {
  readonly config: NodeClientConfig;
}

/** `GET /.well-known/zupay-node` — public, no bearer. */
export async function getDiscovery(input: GetDiscoveryInput): Promise<NodeIdentityDocument> {
  const fetchImpl = resolveFetch(input.config);
  const response = await fetchImpl(resolveUrl(input.config, DISCOVERY_PATH), {
    method: "GET",
  });
  await assertOk(response);
  return parseNodeIdentityDocument(await response.json());
}

export interface GetImplementerIdentityInput {
  readonly config: NodeClientConfig;
  /** `Bearer ik_…` implementer key. */
  readonly bearerKey: string;
}

/** `GET /v1/implementer/identity` — implementer bearer who-am-I. */
export async function getImplementerIdentity(
  input: GetImplementerIdentityInput,
): Promise<ImplementerIdentityDocument> {
  const fetchImpl = resolveFetch(input.config);
  const response = await fetchImpl(resolveUrl(input.config, IMPLEMENTER_IDENTITY_PATH), {
    method: "GET",
    headers: { authorization: `Bearer ${input.bearerKey}` },
  });
  await assertOk(response);
  return parseImplementerIdentityDocument(await response.json());
}

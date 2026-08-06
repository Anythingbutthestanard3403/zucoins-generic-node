import { describe, expect, it } from "vitest";
import { DISCOVERY_RESPONSE_FIELDS } from "@zucoins/generic-node-contracts/api-schema";
import {
  buildNodeIdentityDocument,
  buildHealthResponse,
  NodeIdentityDocumentSchema,
  DiscoveryPublicKeySchema,
  DiscoveryKeyEntrySchema,
  KeyValidityIntervalSchema,
  findRouteSchema,
} from "../src/api/index.js";
import type { DiscoveryConfig } from "../src/api/index.js";

const VALID_UUID = "0192e3a4-b5c6-7d8e-9f0a-1b2c3d4e5f6a";
const VALID_PUBKEY = "wUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrM=";
const VALID_TIMESTAMP = "2026-01-15T00:00:00.000Z";

function validDiscoveryConfig(): DiscoveryConfig {
  return {
    nodeId: VALID_UUID,
    apiVersion: "v1",
    supportedOperations: ["RECEIVE_EXTERNAL", "MOVE_INTERNAL", "SEND_EXTERNAL"],
    canonicalSuites: [
      "zp-receive-expected-v1",
      "zp-move-internal-expected-v1",
      "zp-send-external-expected-v1",
      "zp-node-event-v1",
    ],
    eventSigningKeys: [
      { keyId: VALID_UUID, publicKey: VALID_PUBKEY, validFrom: VALID_TIMESTAMP, validUntil: null },
    ],
    artifactSigningKeys: [
      {
        keyId: VALID_UUID,
        publicKey: VALID_PUBKEY,
        validFrom: VALID_TIMESTAMP,
        validUntil: "2027-01-15T00:00:00.000Z",
      },
    ],
  };
}

describe("discovery document builder", () => {
  it("builds a valid identity document from config", () => {
    const doc = buildNodeIdentityDocument(validDiscoveryConfig());
    expect(doc.node_id).toBe(VALID_UUID);
    expect(doc.api_version).toBe("v1");
    expect(doc.supported_operation_types).toEqual([
      "RECEIVE_EXTERNAL",
      "MOVE_INTERNAL",
      "SEND_EXTERNAL",
    ]);
    expect(doc.canonical_suite_versions).toHaveLength(4);
    expect(doc.event_signing_public_keys).toHaveLength(1);
    expect(doc.expected_artifact_public_keys).toHaveLength(1);
    expect(doc.key_validity_intervals).toHaveLength(1);
  });

  it("emits exactly DISCOVERY_RESPONSE_FIELDS in canon sequence", () => {
    const doc = buildNodeIdentityDocument(validDiscoveryConfig());
    expect(Object.keys(doc)).toEqual([...DISCOVERY_RESPONSE_FIELDS]);
  });

  it("produces output that passes the Zod schema", () => {
    const doc = buildNodeIdentityDocument(validDiscoveryConfig());
    const result = NodeIdentityDocumentSchema.safeParse(doc);
    expect(result.success).toBe(true);
  });

  it("maps public keys and top-level validity intervals", () => {
    const doc = buildNodeIdentityDocument(validDiscoveryConfig());
    const eventKey = doc.event_signing_public_keys[0]!;
    expect(eventKey.key_id).toBe(VALID_UUID);
    expect(eventKey.public_key).toBe(VALID_PUBKEY);

    const artifactKey = doc.expected_artifact_public_keys[0]!;
    expect(artifactKey.key_id).toBe(VALID_UUID);

    // Same key_id in event + artifact → one deduped interval (first wins).
    const interval = doc.key_validity_intervals[0]!;
    expect(interval.key_id).toBe(VALID_UUID);
    expect(interval.valid_from).toBe(VALID_TIMESTAMP);
    expect(interval.valid_until).toBeNull();
  });

  it("keeps separate validity intervals for distinct key ids", () => {
    const artifactKeyId = "0192e3a4-b5c6-7d8e-9f0a-1b2c3d4e5f6b";
    const config = validDiscoveryConfig();
    const doc = buildNodeIdentityDocument({
      ...config,
      artifactSigningKeys: [
        {
          keyId: artifactKeyId,
          publicKey: VALID_PUBKEY,
          validFrom: VALID_TIMESTAMP,
          validUntil: "2027-01-15T00:00:00.000Z",
        },
      ],
    });
    expect(doc.key_validity_intervals).toHaveLength(2);
    const artifactInterval = doc.key_validity_intervals.find((i) => i.key_id === artifactKeyId)!;
    expect(artifactInterval.valid_until).toBe("2027-01-15T00:00:00.000Z");
  });

  it("returns a copy of arrays (no shared references)", () => {
    const config = validDiscoveryConfig();
    const doc = buildNodeIdentityDocument(config);
    expect(doc.supported_operation_types).not.toBe(config.supportedOperations);
    expect(doc.canonical_suite_versions).not.toBe(config.canonicalSuites);
  });

  it("handles empty key arrays", () => {
    const config = validDiscoveryConfig();
    const doc = buildNodeIdentityDocument({
      ...config,
      eventSigningKeys: [],
      artifactSigningKeys: [],
    });
    expect(doc.event_signing_public_keys).toEqual([]);
    expect(doc.expected_artifact_public_keys).toEqual([]);
    expect(doc.key_validity_intervals).toEqual([]);
    expect(NodeIdentityDocumentSchema.safeParse(doc).success).toBe(true);
  });

  it("does not emit software_version or pre-canon field names", () => {
    const doc = buildNodeIdentityDocument(validDiscoveryConfig());
    const json = JSON.stringify(doc);
    expect(json).not.toContain("software_version");
    expect(json).not.toContain("supported_operations");
    expect(json).not.toContain("event_signing_keys");
    expect(json).not.toContain("artifact_signing_keys");
    expect(json).not.toContain("canonical_suites");
  });
});

describe("discovery document schema validation", () => {
  it("rejects unknown fields", () => {
    const doc = buildNodeIdentityDocument(validDiscoveryConfig());
    const withExtra = { ...doc, secret_field: "should not be here" };
    const result = NodeIdentityDocumentSchema.safeParse(withExtra);
    expect(result.success).toBe(false);
  });

  it("rejects invalid operation kinds", () => {
    const doc = buildNodeIdentityDocument(validDiscoveryConfig());
    const bad = { ...doc, supported_operation_types: ["DRAIN_WALLET"] };
    const result = NodeIdentityDocumentSchema.safeParse(bad);
    expect(result.success).toBe(false);
  });

  it("validates public key schema independently", () => {
    const entry = { key_id: VALID_UUID, public_key: VALID_PUBKEY };
    expect(DiscoveryPublicKeySchema.safeParse(entry).success).toBe(true);
    expect(DiscoveryKeyEntrySchema.safeParse(entry).success).toBe(true);
  });

  it("validates key validity interval schema", () => {
    expect(
      KeyValidityIntervalSchema.safeParse({
        key_id: VALID_UUID,
        valid_from: VALID_TIMESTAMP,
        valid_until: null,
      }).success,
    ).toBe(true);
    expect(
      KeyValidityIntervalSchema.safeParse({
        key_id: VALID_UUID,
        valid_from: VALID_TIMESTAMP,
        valid_until: VALID_TIMESTAMP,
      }).success,
    ).toBe(true);
    expect(
      KeyValidityIntervalSchema.safeParse({ valid_from: VALID_TIMESTAMP, valid_until: null }).success,
    ).toBe(false);
  });
});

describe("health check builder", () => {
  const fixedNow = () => "2026-01-15T12:00:00.000Z";

  it("returns ok when database is ready", () => {
    const health = buildHealthResponse("0.0.0", true, fixedNow);
    expect(health.status).toBe("ok");
    expect(health.version).toBe("0.0.0");
    expect(health.timestamp).toBe("2026-01-15T12:00:00.000Z");
  });

  it("returns unavailable when database is not ready", () => {
    const health = buildHealthResponse("0.0.0", false, fixedNow);
    expect(health.status).toBe("unavailable");
  });
});

describe("route registration", () => {
  it("registers /.well-known/zupay-node as a public GET", () => {
    const route = findRouteSchema("GET", "/.well-known/zupay-node");
    expect(route).toBeDefined();
    expect(route!.requiresIdempotencyKey).toBe(false);
  });

  it("registers /health as a public GET", () => {
    const route = findRouteSchema("GET", "/health");
    expect(route).toBeDefined();
    expect(route!.requiresIdempotencyKey).toBe(false);
  });
});

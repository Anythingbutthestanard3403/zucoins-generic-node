import { describe, expect, it, vi } from "vitest";

import {
  DISCOVERY_PATH,
  IMPLEMENTER_IDENTITY_PATH,
  IdentityDocumentError,
  getDiscovery,
  getImplementerIdentity,
  parseImplementerIdentityDocument,
  parseNodeIdentityDocument,
} from "./discovery.js";
import { VerificationModeDriftError } from "../verification-mode.js";
import type { FetchLike } from "./client-types.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const KEY_ID = "33333333-3333-4333-8333-333333333333";
const IMPLEMENTER_ID = "22222222-2222-4222-8222-222222222222";

function discoveryBody(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    node_id: NODE_ID,
    api_version: "1",
    supported_operation_types: ["RECEIVE_EXTERNAL"],
    event_signing_public_keys: [{ key_id: KEY_ID, public_key: "pub" }],
    expected_artifact_public_keys: [{ key_id: KEY_ID, public_key: "pub" }],
    canonical_suite_versions: ["v1"],
    key_validity_intervals: [{ key_id: KEY_ID, valid_from: "2026-01-01T00:00:00.000Z", valid_until: null }],
    funding_wallet_id: null,
    funding_wallet_public_key: null,
    verification_mode: "INDEPENDENT",
    ...over,
  };
}

function identityBody(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    implementer_id: IMPLEMENTER_ID,
    funding_wallet_id: null,
    funding_wallet_public_key: null,
    funding_configured: false,
    funding_source: "unset",
    verification_mode: "INDEPENDENT",
    ...over,
  };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("parseNodeIdentityDocument", () => {
  it("reads emitted INDEPENDENT from /.well-known/zupay-node", () => {
    const doc = parseNodeIdentityDocument(discoveryBody());
    expect(doc.verification_mode).toBe("INDEPENDENT");
    expect(doc.node_id).toBe(NODE_ID);
  });

  it("preserves NODE_VERIFIED from /.well-known/zupay-node", () => {
    const doc = parseNodeIdentityDocument(discoveryBody({ verification_mode: "NODE_VERIFIED" }));
    expect(doc.verification_mode).toBe("NODE_VERIFIED");
  });

  it("rejects omitted verification_mode (fail closed; no silent INDEPENDENT)", () => {
    const { verification_mode: _omit, ...body } = discoveryBody();
    expect(() => parseNodeIdentityDocument(body)).toThrow(IdentityDocumentError);
    expect(() => parseNodeIdentityDocument(body)).toThrow(/verification_mode is required/);
  });

  it("rejects null verification_mode", () => {
    expect(() => parseNodeIdentityDocument(discoveryBody({ verification_mode: null }))).toThrow(
      IdentityDocumentError,
    );
  });

  it("rejects unknown verification_mode", () => {
    expect(() => parseNodeIdentityDocument(discoveryBody({ verification_mode: "HYBRID" }))).toThrow(
      VerificationModeDriftError,
    );
  });

  it("rejects a non-object body", () => {
    expect(() => parseNodeIdentityDocument(null)).toThrow(IdentityDocumentError);
  });
});

describe("parseImplementerIdentityDocument", () => {
  it("reads emitted INDEPENDENT on who-am-I", () => {
    expect(parseImplementerIdentityDocument(identityBody()).verification_mode).toBe("INDEPENDENT");
  });

  it("preserves NODE_VERIFIED on who-am-I", () => {
    const doc = parseImplementerIdentityDocument(identityBody({ verification_mode: "NODE_VERIFIED" }));
    expect(doc.verification_mode).toBe("NODE_VERIFIED");
    expect(doc.implementer_id).toBe(IMPLEMENTER_ID);
  });

  it("rejects omitted verification_mode (fail closed; no silent INDEPENDENT)", () => {
    const { verification_mode: _omit, ...body } = identityBody();
    expect(() => parseImplementerIdentityDocument(body)).toThrow(IdentityDocumentError);
    expect(() => parseImplementerIdentityDocument(body)).toThrow(/verification_mode is required/);
  });

  it("rejects unknown verification_mode", () => {
    expect(() =>
      parseImplementerIdentityDocument(identityBody({ verification_mode: "HYBRID" })),
    ).toThrow(VerificationModeDriftError);
  });
});

describe("getDiscovery / getImplementerIdentity", () => {
  it("GETs /.well-known/zupay-node and parses verification_mode", async () => {
    const fetchImpl = vi.fn<FetchLike>(async () =>
      jsonResponse(200, discoveryBody({ verification_mode: "NODE_VERIFIED" })),
    );
    const doc = await getDiscovery({ config: { baseUrl: "https://node.example.com", fetchImpl } });
    expect(fetchImpl.mock.calls[0]![0]).toBe(`https://node.example.com${DISCOVERY_PATH}`);
    expect(DISCOVERY_PATH).toBe("/.well-known/zupay-node");
    expect(doc.verification_mode).toBe("NODE_VERIFIED");
  });

  it("GETs /v1/implementer/identity with the bearer key", async () => {
    const fetchImpl = vi.fn<FetchLike>(async () => jsonResponse(200, identityBody()));
    const doc = await getImplementerIdentity({
      config: { baseUrl: "https://node.example.com", fetchImpl },
      bearerKey: "ik_test",
    });
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe(`https://node.example.com${IMPLEMENTER_IDENTITY_PATH}`);
    expect((init?.headers as Record<string, string>).authorization).toBe("Bearer ik_test");
    expect(doc.verification_mode).toBe("INDEPENDENT");
  });
});

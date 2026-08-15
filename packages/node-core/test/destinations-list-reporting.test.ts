// `GET /v1/destinations` on the signed reporting credential.
// credential binding this handler scopes on.
//
// The transport edge only — the reporting pipeline verifies the credential and burns the
// nonce before this handler runs (api-contract step 3).

import { describe, expect, it } from "vitest";

import {
  createDestinationsListRouteHandler,
  destinationToWire,
  handleCreateDestination,
  handleListDestinations,
  listDestinationsBody,
  parseListDestinationsQueryFromTarget,
} from "../src/api/destination-http.js";
import type {
  DestinationListItem,
  DestinationPage,
  DestinationService,
} from "../src/api/destination.js";
import type { VerifiedReportRequest } from "../src/reporting/request-verifier.js";
import type { Uuid, WalletPublicKey } from "../src/protocol/scalars.js";

const NODE_A = "11111111-1111-4111-8111-111111111111" as Uuid;
const NODE_B = "22222222-2222-4222-8222-222222222222" as Uuid;
const AFTER_ID = "33333333-3333-4333-8333-333333333333";

const item = (tag: string, nodeId: Uuid, state: DestinationListItem["state"]): DestinationListItem => ({
  destinationId: `00000000-0000-4000-8000-${tag.padStart(12, "0")}` as Uuid,
  nodeId,
  walletId: `00000000-0000-4000-8000-${`9${tag}`.padStart(12, "0")}` as Uuid,
  walletPublicKey: `${tag}-pubkey` as WalletPublicKey,
  state,
  label: "",
  blessedAt: state === "PENDING" ? null : "2026-07-30T00:00:00.000Z",
  blessedByDeviceKeyId: null,
  blessingArtifactId: null,
  retiredAt: state === "RETIRED" ? "2026-07-30T01:00:00.000Z" : null,
  createdAt: "2026-07-29T00:00:00.000Z",
  move_eligible: state === "BLESSED",
  ineligibility_reason: state === "BLESSED" ? null : "DESTINATION_NOT_BLESSED",
});

const NODE_A_ROWS = [item("1", NODE_A, "PENDING"), item("2", NODE_A, "BLESSED")];

interface RecordedCall {
  readonly nodeId: Uuid;
  readonly filter: Parameters<DestinationService["list"]>[1];
}

/** Node-scoped stub with the same tenant semantics as the SQL store's `d.node_id = $1`. */
function stubService(calls: RecordedCall[] = []): DestinationService & { readonly calls: RecordedCall[] } {
  const service = {
    calls,
    async list(nodeId: Uuid, filter: Parameters<DestinationService["list"]>[1]): Promise<DestinationPage> {
      calls.push({ nodeId, filter });
      const rows = nodeId === NODE_A ? NODE_A_ROWS : [];
      const filtered =
        filter.state === undefined ? rows : rows.filter((row) => row.state === filter.state);
      return { items: filtered, nextAfter: null };
    },
    register: async () => {
      throw new Error("not used");
    },
    bless: async () => {
      throw new Error("not used");
    },
    retire: async () => {
      throw new Error("not used");
    },
    get: async () => null,
  };
  return service as never;
}

function verified(nodeId: string, rawTarget: string): VerifiedReportRequest {
  return {
    ok: true,
    binding: {
      reportingKeyId: "44444444-4444-4444-8444-444444444444",
      nodeId,
      implementerId: "55555555-5555-4555-8555-555555555555",
      publicKeyEncoded: "AAAA",
    },
    route: {
      routeId: "destinations_list",
      requestClass: "READ",
      retentionClass: "READ_NO_PRUNE_UNTIL_SAFETY_FREEZE",
    },
    nonceEvidence: {} as never,
    idempotencyKey: null,
    fingerprint: { method: "GET", rawTarget, bodySha256: "00".repeat(32) },
    bodyBytes: new Uint8Array(),
    lastEventId: null,
  } as VerifiedReportRequest;
}

const decode = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

describe("query parse off the exact raw signed target", () => {
  it("accepts the parameter set and defaults an empty query", () => {
    expect(parseListDestinationsQueryFromTarget("/v1/destinations")).toEqual({
      ok: true,
      query: {},
    });
    const parsed = parseListDestinationsQueryFromTarget(
      `/v1/destinations?state=BLESSED&after=${AFTER_ID}&limit=100`,
    );
    expect(parsed).toEqual({
      ok: true,
      query: { state: "BLESSED", after: AFTER_ID, limit: 100 },
    });
  });

  it("rejects limit outside 1-100, a non-enum state, a non-uuid after, and unknown params", () => {
    for (const target of [
      "/v1/destinations?limit=0",
      "/v1/destinations?limit=101",
      "/v1/destinations?state=BLESSED_MAYBE",
      "/v1/destinations?after=not-a-uuid",
      "/v1/destinations?after_implementer_seq=1",
    ]) {
      expect(parseListDestinationsQueryFromTarget(target).ok, target).toBe(false);
    }
  });
});

describe("reporting-credential destinations list", () => {
  it("AC1: page is byte-identical to the implementer-bearer page for the same tenant/node", async () => {
    const service = stubService();
    const handler = createDestinationsListRouteHandler({
      service,
      newRequestId: () => "req-reporting",
    });

    const reporting = await handler(verified(NODE_A, "/v1/destinations?state=BLESSED"));
    expect(reporting.response.status).toBe(200);
    expect(reporting.persistChild).toBeNull();

    const bearer = await handleListDestinations(
      {
        requestId: "req-bearer",
        principal: { implementerId: "55555555-5555-4555-8555-555555555555" },
        request: { query: { state: "BLESSED" }, headers: {} },
      } as never,
      { service, nodeId: NODE_A },
    );

    expect(bearer.ok).toBe(true);
    const bearerBody = (bearer as { readonly body: string }).body;
    expect(decode(reporting.response.bodyBytes)).toBe(bearerBody);
    expect(JSON.parse(bearerBody)).toEqual({
      items: [destinationToWire(item("2", NODE_A, "BLESSED"))],
      next_after: null,
    });
  });

  it("AC2: a credential bound to another node collapses to an empty page, not a 404", async () => {
    const calls: RecordedCall[] = [];
    const service = stubService(calls);
    const handler = createDestinationsListRouteHandler({
      service,
      newRequestId: () => "req-1",
    });

    const response = await handler(verified(NODE_B, `/v1/destinations?after=${AFTER_ID}`));
    expect(response.response.status).toBe(200);
    expect(decode(response.response.bodyBytes)).toBe('{"items":[],"next_after":null}');
    // Tenant scope comes from the credential binding, never ambient config.
    expect(calls.map((call) => call.nodeId)).toEqual([NODE_B]);
    // A foreign `after` stays an opaque ordering bound — never a differentiated error.
    expect(calls[0]?.filter.after).toBe(AFTER_ID);
  });

  it("emits the api invalid_scalar envelope for a malformed query and writes no completion", async () => {
    const handler = createDestinationsListRouteHandler({
      service: stubService(),
      newRequestId: () => "req-bad",
    });
    const response = await handler(verified(NODE_A, "/v1/destinations?limit=0"));
    expect(response.response.status).toBe(400);
    expect(response.persistChild).toBeNull();
    const raw = decode(response.response.bodyBytes);
    const body = JSON.parse(raw) as {
      error: { code: string; message: string; request_id: string };
    };
    expect(body.error.code).toBe("invalid_scalar");
    expect(body.error.request_id).toBe("req-bad");
    // ZTR-1200: canonical message only — Zod issue dumps (expected/received/path) stay off the wire.
    expect(body.error.message).toBe(
      "A field value does not satisfy its canonical scalar constraint.",
    );
    expect(raw).not.toMatch(/"expected"\s*:/);
    expect(raw).not.toMatch(/"received"\s*:/);
    expect(raw).not.toContain("Too small");
    expect(raw).not.toContain("Too big");
  });

  it("parseListDestinationsQueryFromTarget failure carries no Zod message field", () => {
    const bad = parseListDestinationsQueryFromTarget("/v1/destinations?limit=0");
    expect(bad).toEqual({ ok: false });
    expect(bad).not.toHaveProperty("message");
  });

  it("a throwing service fails closed as internal_error and never leaks the reason", async () => {
    const failing = {
      ...stubService(),
      list: async () => {
        throw new Error("destination engine store is not yet wired — fail-closed");
      },
    } as unknown as DestinationService;
    const handler = createDestinationsListRouteHandler({
      service: failing,
      newRequestId: () => "req-boom",
    });
    const response = await handler(verified(NODE_A, "/v1/destinations"));
    expect(response.response.status).toBe(500);
    expect(response.persistChild).toBeNull();
    const text = decode(response.response.bodyBytes);
    expect(JSON.parse(text).error.code).toBe("internal_error");
    expect(text).not.toContain("not yet wired");
  });

  it("listDestinationsBody is the single renderer for both auth classes", () => {
    const page: DestinationPage = { items: NODE_A_ROWS, nextAfter: NODE_A_ROWS[1]!.destinationId };
    expect(listDestinationsBody(page)).toBe(
      JSON.stringify({
        items: NODE_A_ROWS.map(destinationToWire),
        next_after: NODE_A_ROWS[1]!.destinationId,
      }),
    );
  });
});

describe("handleCreateDestination Zod body failures (ZTR-1200)", () => {
  it("returns canonical invalid_scalar without Zod expected/received dumps", async () => {
    const result = await handleCreateDestination(
      {
        requestId: "req-create-bad",
        principal: { implementerId: "55555555-5555-4555-8555-555555555555" },
        request: { headers: { "idempotency-key": "idem-create-1" }, query: {} },
        parsedBody: { label: 12 },
        idempotencyTenantId: "55555555-5555-4555-8555-555555555555",
      } as never,
      {
        service: stubService(),
        nodeId: NODE_A,
      },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    const raw = result.error.body;
    const body = JSON.parse(raw) as { error: { code: string; message: string } };
    expect(result.error.status).toBe(400);
    expect(body.error.code).toBe("invalid_scalar");
    expect(body.error.message).toBe(
      "A field value does not satisfy its canonical scalar constraint.",
    );
    expect(raw).not.toMatch(/"expected"\s*:/);
    expect(raw).not.toMatch(/"received"\s*:/);
    expect(raw).not.toContain("invalid_type");
  });
});

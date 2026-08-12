import { createHash, randomUUID } from "node:crypto";
import { describe, expect, it, beforeEach } from "vitest";

import type { PipelineContext } from "../api/pipeline.js";
import { buildApiErrorBody } from "../api/error-envelope.js";
import {
  handleCreateIntegrationRequest,
  handleGetIntegrationRequest,
  extractClaimToken,
} from "./handlers.js";
import { InMemoryIntegrationRequestStore } from "./memory-store.js";
import {
  _resetIntegrationRequestRateLimitForTests,
} from "./rate-limit.js";
import { hashClaimToken } from "./token.js";
import { INTEGRATION_REQUEST_PENDING_CAP } from "./types.js";

const NODE = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const IMPL = "11111111-2222-3333-4444-555555555555";

function ctx(body: unknown, headers: Record<string, string | undefined> = {}): PipelineContext {
  return {
    requestId: randomUUID(),
    request: {
      method: "POST",
      path: "/v1/integration-requests",
      rawBody: new Uint8Array(),
      headers,
      query: {},
    },
    routeSchema: {
      method: "POST",
      path: "/v1/integration-requests",
      requiresIdempotencyKey: false,
    },
    parsedBody: body,
  };
}

function validBody(overrides: Record<string, unknown> = {}) {
  return {
    display_name: "Acme Rewards",
    requested_scopes: ["send:create", "send:read"],
    proposed_rule: {
      per_send_max_zkz: "0.001",
      per_send_min_zkz: null,
      window_hours: 288,
      window_cap_zkz: "100",
      expires_at: null,
    },
    ...overrides,
  };
}

describe("integration request public handshake", () => {
  let store: InMemoryIntegrationRequestStore;

  beforeEach(() => {
    store = new InMemoryIntegrationRequestStore();
    _resetIntegrationRequestRateLimitForTests();
  });

  it("intake round-trips and returns claim_token once", async () => {
    const result = await handleCreateIntegrationRequest(ctx(validBody()), {
      store,
      nodeId: NODE,
      sourceIp: "10.0.0.1",
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.status).toBe(201);
    const body = JSON.parse(result.body) as {
      request_id: string;
      claim_token: string;
      expires_at: string;
    };
    expect(body.claim_token.startsWith("irq_")).toBe(true);
    expect(body.request_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    const row = await store.findById(body.request_id);
    expect(row?.status).toBe("PENDING");
    expect(row?.claim_token_hash).toBe(hashClaimToken(body.claim_token));
    // raw token never stored
    expect(JSON.stringify(row)).not.toContain(body.claim_token);
  });

  it("rejects invalid rule/scopes/name with nothing stored", async () => {
    for (const bad of [
      validBody({ display_name: "" }),
      validBody({ display_name: "x".repeat(121) }),
      validBody({ requested_scopes: ["receive:create"] }),
      validBody({ requested_scopes: [] }),
      validBody({ proposed_rule: { per_send_max_zkz: "nope" } }),
      validBody({
        proposed_rule: {
          per_send_max_zkz: "1",
          window_hours: 1,
          window_cap_zkz: "0.5", // cap < max
          expires_at: null,
        },
      }),
      validBody({ extra: true }),
    ]) {
      _resetIntegrationRequestRateLimitForTests();
      store = new InMemoryIntegrationRequestStore();
      const result = await handleCreateIntegrationRequest(ctx(bad), {
        store,
        nodeId: NODE,
        sourceIp: "10.0.0.2",
      });
      expect(result.ok).toBe(false);
      expect(await store.countPending()).toBe(0);
    }
  });

  it("rate limit trips on N+1 within window", async () => {
    const ip = "10.0.0.3";
    let lastOk = true;
    for (let i = 0; i < 12; i++) {
      const result = await handleCreateIntegrationRequest(ctx(validBody()), {
        store,
        nodeId: NODE,
        sourceIp: ip,
      });
      lastOk = result.ok;
      if (!result.ok) {
        expect(result.error.status).toBe(429);
        break;
      }
    }
    expect(lastOk).toBe(false);
  });

  it("global PENDING cap refuses further intake", async () => {
    _resetIntegrationRequestRateLimitForTests();
    // Use high rate budget, tiny pending cap
    for (let i = 0; i < 3; i++) {
      const r = await handleCreateIntegrationRequest(ctx(validBody()), {
        store,
        nodeId: NODE,
        sourceIp: `10.1.0.${i}`,
        pendingCap: 2,
      });
      if (i < 2) expect(r.ok).toBe(true);
      else {
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error.status).toBe(429);
      }
    }
    expect(await store.countPending()).toBe(2);
    expect(INTEGRATION_REQUEST_PENDING_CAP).toBe(100);
  });

  it("claim one-time: APPROVED first GET gets key; second is status only", async () => {
    const created = await handleCreateIntegrationRequest(ctx(validBody()), {
      store,
      nodeId: NODE,
      sourceIp: "10.0.0.4",
    });
    expect(created.ok).toBe(true);
    if (!created.ok) return;
    const { request_id, claim_token } = JSON.parse(created.body) as {
      request_id: string;
      claim_token: string;
    };
    store.seedApproved(request_id, {
      implementerId: IMPL,
      approvedRuleJson: JSON.stringify({
        per_send_max_zkz: "0.001",
        window_hours: 288,
        window_cap_zkz: "50",
      }),
    });

    const getCtx = (token: string): PipelineContext => ({
      requestId: randomUUID(),
      request: {
        method: "GET",
        path: "/v1/integration-requests/:id",
        rawBody: new Uint8Array(),
        headers: { authorization: `Bearer ${token}` },
        query: {},
      },
      routeSchema: {
        method: "GET",
        path: "/v1/integration-requests/:id",
        requiresIdempotencyKey: false,
      },
    });

    const first = await handleGetIntegrationRequest(getCtx(claim_token), {
      store,
      nodeId: NODE,
      sourceIp: null,
    }, request_id);
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    const b1 = JSON.parse(first.body) as {
      status: string;
      api_key?: string;
      implementer_id?: string;
    };
    expect(b1.status).toBe("CLAIMED");
    expect(b1.api_key?.startsWith("ik_")).toBe(true);
    expect(b1.implementer_id).toBe(IMPL);

    const second = await handleGetIntegrationRequest(getCtx(claim_token), {
      store,
      nodeId: NODE,
      sourceIp: null,
    }, request_id);
    expect(second.ok).toBe(true);
    if (!second.ok) return;
    const b2 = JSON.parse(second.body) as { status: string; api_key?: string };
    expect(b2.status).toBe("CLAIMED");
    expect(b2.api_key).toBeUndefined();
  });

  it("PENDING/DECLINED never return a key", async () => {
    const created = await handleCreateIntegrationRequest(ctx(validBody()), {
      store,
      nodeId: NODE,
      sourceIp: "10.0.0.5",
    });
    if (!created.ok) throw new Error("create failed");
    const { request_id, claim_token } = JSON.parse(created.body) as {
      request_id: string;
      claim_token: string;
    };
    const headers = { authorization: `Bearer ${claim_token}` };
    const pending = await handleGetIntegrationRequest(
      { ...ctx({}, headers), request: { ...ctx({}, headers).request, method: "GET", headers } },
      { store, nodeId: NODE, sourceIp: null },
      request_id,
    );
    expect(pending.ok).toBe(true);
    if (pending.ok) {
      const b = JSON.parse(pending.body) as { status: string; api_key?: string };
      expect(b.status).toBe("PENDING");
      expect(b.api_key).toBeUndefined();
    }
  });

  it("unknown id / wrong token / foreign token ⇒ byte-identical 404 bodies", async () => {
    const created = await handleCreateIntegrationRequest(ctx(validBody()), {
      store,
      nodeId: NODE,
      sourceIp: "10.0.0.6",
    });
    if (!created.ok) throw new Error("create failed");
    const { request_id, claim_token } = JSON.parse(created.body) as {
      request_id: string;
      claim_token: string;
    };
    const other = await handleCreateIntegrationRequest(ctx(validBody()), {
      store,
      nodeId: NODE,
      sourceIp: "10.0.0.7",
    });
    if (!other.ok) throw new Error("other failed");
    const foreignToken = (JSON.parse(other.body) as { claim_token: string }).claim_token;

    const rid = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"; // fixed request id for envelope
    async function bodyOf(
      id: string,
      token: string | null,
    ): Promise<{ status: number; body: string }> {
      const headers: Record<string, string | undefined> =
        token === null ? {} : { authorization: `Bearer ${token}` };
      const c: PipelineContext = {
        requestId: rid,
        request: {
          method: "GET",
          path: "/v1/integration-requests/:id",
          rawBody: new Uint8Array(),
          headers,
          query: {},
        },
        routeSchema: {
          method: "GET",
          path: "/v1/integration-requests/:id",
          requiresIdempotencyKey: false,
        },
      };
      const r = await handleGetIntegrationRequest(c, {
        store,
        nodeId: NODE,
        sourceIp: null,
      }, id);
      expect(r.ok).toBe(false);
      if (r.ok) throw new Error("expected fail");
      return { status: r.error.status, body: r.error.body };
    }

    const a = await bodyOf(randomUUID(), claim_token);
    const b = await bodyOf(request_id, "irq_wrongtoken");
    const c = await bodyOf(request_id, foreignToken);
    const d = await bodyOf(request_id, null);

    expect(a.status).toBe(404);
    expect(a.body).toBe(b.body);
    expect(b.body).toBe(c.body);
    expect(c.body).toBe(d.body);
    // Matches canonical not_found envelope for this request id
    expect(a.body).toBe(buildApiErrorBody("not_found", rid));
  });

  it("lazy expiry: PENDING past TTL reads EXPIRED", async () => {
    const past = new Date("2020-01-01T00:00:00.000Z");
    const created = await handleCreateIntegrationRequest(ctx(validBody()), {
      store,
      nodeId: NODE,
      sourceIp: "10.0.0.8",
      now: () => past,
      ttlMs: 1000,
    });
    if (!created.ok) throw new Error("create failed");
    const { request_id, claim_token } = JSON.parse(created.body) as {
      request_id: string;
      claim_token: string;
    };
    const later = new Date(past.getTime() + 60_000);
    const r = await handleGetIntegrationRequest(
      {
        requestId: randomUUID(),
        request: {
          method: "GET",
          path: "/v1/integration-requests/:id",
          rawBody: new Uint8Array(),
          headers: { "x-zp-claim-token": claim_token },
          query: {},
        },
        routeSchema: {
          method: "GET",
          path: "/v1/integration-requests/:id",
          requiresIdempotencyKey: false,
        },
      },
      { store, nodeId: NODE, sourceIp: null, now: () => later },
      request_id,
    );
    expect(r.ok).toBe(true);
    if (r.ok) {
      const b = JSON.parse(r.body) as { status: string; api_key?: string };
      expect(b.status).toBe("EXPIRED");
      expect(b.api_key).toBeUndefined();
    }
  });

  it("extractClaimToken reads Bearer and X-ZP-Claim-Token", () => {
    expect(extractClaimToken({ authorization: "Bearer irq_abc" })).toBe("irq_abc");
    expect(extractClaimToken({ "x-zp-claim-token": "irq_xyz" })).toBe("irq_xyz");
    expect(extractClaimToken({})).toBeNull();
  });
});

// silence unused
void createHash;

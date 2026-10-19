import { describe, expect, it } from "vitest";

import { InMemoryConnectorConfigStore } from "../implementer/connector-configs.js";
import { InMemoryConnectorRuleRequestStore } from "../implementer/connector-rule-requests.js";
import { createConnectorRuleRequestRouter } from "./connector-rule-requests-router.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const OWNER = "22222222-2222-4222-8222-222222222222";
const OTHER = "33333333-3333-4333-8333-333333333333";
const REQUEST_ID_HEADER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

const HAPPY = {
  rule_id: "winter-promo-2026",
  label: "Winter Promo",
  per_send_max_zkz: "20",
  per_send_min_zkz: "1",
  window_hours: 24,
  window_cap_zkz: "100",
  total_cap_zkz: "200",
};

function routerFor(opts?: {
  readonly scopes?: readonly string[];
  readonly connectorScopes?: readonly string[];
  readonly omitConnectorStore?: boolean;
  readonly webhookUrl?: string | null;
}) {
  const requests = new InMemoryConnectorRuleRequestStore();
  const connectors = new InMemoryConnectorConfigStore();
  const keys = new Map<string, { implementer_id: string; scopes: readonly string[] }>([
    ["ik_owner", { implementer_id: OWNER, scopes: opts?.scopes ?? ["send:create", "send:read"] }],
    ["ik_other", { implementer_id: OTHER, scopes: ["send:create"] }],
    ["ik_nosend", { implementer_id: OWNER, scopes: ["receive:read"] }],
  ]);
  const seed = async (implementerId: string, scopes: readonly string[]) => {
    await connectors.upsert({
      implementerId,
      displayName: "promo",
      scopes: [...scopes],
      webhookUrl: opts?.webhookUrl ?? "https://hooks.example/promo",
      webhookEnabled: true,
    });
  };
  return {
    requests,
    connectors,
    seed,
    router: createConnectorRuleRequestRouter({
      store: requests,
      ...(opts?.omitConnectorStore === true ? {} : { connectorConfigStore: connectors }),
      nodeId: NODE_ID,
      validateCredential: async (rawKey) => keys.get(rawKey) ?? null,
      newRequestId: () => REQUEST_ID_HEADER,
    }),
  };
}

function auth(key: string): Record<string, string> {
  return { authorization: `Bearer ${key}` };
}

describe("connector rule request router (ZTR-1331)", () => {
  it("creates a pending request and records the hook flag without the target", async () => {
    const { router, requests, seed } = routerFor();
    await seed(OWNER, ["sends:write"]);
    const res = await router("POST", "/v1/connector-rules/requests", Buffer.from(JSON.stringify(HAPPY)), auth("ik_owner"));
    expect(res.status).toBe(201);
    const body = JSON.parse(res.body) as { request_id: string; status: string; rule_id: string };
    expect(body.status).toBe("PENDING");
    expect(body.rule_id).toBe("winter-promo-2026");
    const saved = await requests.get(body.request_id);
    expect(saved?.webhook_enabled).toBe(true);
    expect(requests.audits[0]?.detailsText).toContain("\"webhook_enabled\":true");
    expect(requests.audits[0]?.detailsText).not.toContain("hooks.example");
    expect(requests.audits[0]?.actorKind).toBe("IMPLEMENTER");
  });

  it("rejects a missing send:create scope and a missing sends:write label as 401", async () => {
    const missingScope = routerFor({ scopes: ["receive:read"] });
    await missingScope.seed(OWNER, ["sends:write"]);
    const scopeRes = await missingScope.router(
      "POST",
      "/v1/connector-rules/requests",
      Buffer.from(JSON.stringify(HAPPY)),
      auth("ik_nosend"),
    );
    expect(scopeRes.status).toBe(401);
    expect(JSON.parse(scopeRes.body).error.code).toBe("invalid_api_key");

    const missingLabel = routerFor();
    await missingLabel.seed(OWNER, ["wallets:read_linked"]);
    const labelRes = await missingLabel.router(
      "POST",
      "/v1/connector-rules/requests",
      Buffer.from(JSON.stringify(HAPPY)),
      auth("ik_owner"),
    );
    expect(labelRes.status).toBe(401);
    expect(JSON.parse(labelRes.body).error.code).toBe("invalid_api_key");
  });

  it("rejects an unknown field and a non-canonical amount", async () => {
    const { router, seed } = routerFor();
    await seed(OWNER, ["sends:write"]);
    const unknown = await router(
      "POST",
      "/v1/connector-rules/requests",
      Buffer.from(JSON.stringify({ ...HAPPY, extra: true })),
      auth("ik_owner"),
    );
    expect(unknown.status).toBe(400);
    expect(JSON.parse(unknown.body).error.code).toBe("unknown_field");

    const padded = await router(
      "POST",
      "/v1/connector-rules/requests",
      Buffer.from(JSON.stringify({ ...HAPPY, per_send_max_zkz: "200.00000000" })),
      auth("ik_owner"),
    );
    expect(padded.status).toBe(400);
    expect(JSON.parse(padded.body).error.code).toBe("invalid_scalar");
  });

  it("rate-limits the 11th pending request", async () => {
    const { router, seed } = routerFor();
    await seed(OWNER, ["sends:write"]);
    for (let i = 0; i < 10; i += 1) {
      const res = await router(
        "POST",
        "/v1/connector-rules/requests",
        Buffer.from(JSON.stringify({ ...HAPPY, rule_id: `rule-${i}` })),
        auth("ik_owner"),
      );
      expect(res.status).toBe(201);
    }
    const limited = await router(
      "POST",
      "/v1/connector-rules/requests",
      Buffer.from(JSON.stringify({ ...HAPPY, rule_id: "rule-10" })),
      auth("ik_owner"),
    );
    expect(limited.status).toBe(429);
    expect(JSON.parse(limited.body).error.code).toBe("rate_limited");
  });

  it("hides another implementer's request", async () => {
    const { router, seed } = routerFor();
    await seed(OWNER, ["sends:write"]);
    await seed(OTHER, ["sends:write"]);
    const created = await router(
      "POST",
      "/v1/connector-rules/requests",
      Buffer.from(JSON.stringify(HAPPY)),
      auth("ik_owner"),
    );
    const requestId = (JSON.parse(created.body) as { request_id: string }).request_id;
    const hidden = await router("GET", `/v1/connector-rules/requests/${requestId}`, new Uint8Array(), auth("ik_other"));
    expect(hidden.status).toBe(404);
    expect(JSON.parse(hidden.body).error.code).toBe("not_found");
    const own = await router("GET", `/v1/connector-rules/requests/${requestId}`, new Uint8Array(), auth("ik_owner"));
    expect(own.status).toBe(200);
    const bare = await router("GET", "/v1/connector-rules/requests", new Uint8Array(), auth("ik_owner"));
    expect(bare.status).toBe(404);
  });
});

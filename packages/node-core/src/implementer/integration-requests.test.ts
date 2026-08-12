// Unit tests for in-memory integration-request store (ZTR-1240).

import { describe, expect, it } from "vitest";

import {
  INTEGRATION_REQUEST_APPROVED_ACTION,
  INTEGRATION_REQUEST_DECLINED_ACTION,
  InMemoryIntegrationRequestStore,
  IntegrationRequestStoreError,
  type IntegrationRequestRecord,
} from "./integration-requests.js";

const NODE = "11111111-1111-4111-8111-111111111111";
const REQ = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OP = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const IMPL = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

function pending(over: Partial<IntegrationRequestRecord> = {}): IntegrationRequestRecord {
  return {
    id: REQ,
    node_id: NODE,
    display_name: "Platform Alpha",
    requested_scopes: ["send:create", "send:read"],
    proposed_rule_json: JSON.stringify({
      rule_id: "r1",
      per_send_max_zkz: "10",
      window_cap_zkz: "100",
    }),
    approved_rule_json: null,
    status: "PENDING",
    row_version: 1,
    created_at: "2026-08-01T00:00:00.000Z",
    expires_at: "2026-08-08T00:00:00.000Z",
    decided_at: null,
    decided_by: null,
    implementer_id: null,
    ...over,
  };
}

describe("InMemoryIntegrationRequestStore", () => {
  it("lists PENDING only when filtered", async () => {
    const store = new InMemoryIntegrationRequestStore();
    store.seed(pending());
    store.seed(
      pending({
        id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        status: "DECLINED",
        decided_at: "2026-08-02T00:00:00.000Z",
        decided_by: OP,
        row_version: 2,
      }),
    );
    const pendingOnly = await store.list({ nodeId: NODE, status: "PENDING" });
    expect(pendingOnly).toHaveLength(1);
    expect(pendingOnly[0]!.id).toBe(REQ);
  });

  it("approve CAS advances row and writes audit", async () => {
    const store = new InMemoryIntegrationRequestStore(
      () => new Date("2026-08-03T12:00:00.000Z"),
    );
    store.seed(pending());
    const rule = JSON.stringify({
      rule_id: "r1",
      implementer_id: IMPL,
      per_send_max_zkz: "5",
      per_send_min_zkz: null,
      window_hours: 24,
      window_cap_zkz: "50",
      expires_at: null,
      enabled: true,
    });
    const out = await store.approve({
      id: REQ,
      nodeId: NODE,
      expectedRowVersion: 1,
      approvedRuleJson: rule,
      implementerId: IMPL,
      decidedBy: OP,
      actorId: OP,
    });
    expect(out.status).toBe("APPROVED");
    expect(out.row_version).toBe(2);
    expect(out.implementer_id).toBe(IMPL);
    expect(out.approved_rule_json).toBe(rule);
    expect(out.decided_by).toBe(OP);
    expect(store.audit).toHaveLength(1);
    expect(store.audit[0]!.action).toBe(INTEGRATION_REQUEST_APPROVED_ACTION);
    expect(store.audit[0]!.detailsText).toContain(REQ);
    expect(store.audit[0]!.detailsText).toContain(IMPL);
  });

  it("approve CAS miss on wrong version", async () => {
    const store = new InMemoryIntegrationRequestStore();
    store.seed(pending());
    await expect(
      store.approve({
        id: REQ,
        nodeId: NODE,
        expectedRowVersion: 99,
        approvedRuleJson: "{}",
        implementerId: IMPL,
        decidedBy: OP,
        actorId: OP,
      }),
    ).rejects.toMatchObject({ code: "CAS_MISS" } satisfies Partial<IntegrationRequestStoreError>);
  });

  it("decline only flips status + audit", async () => {
    const store = new InMemoryIntegrationRequestStore();
    store.seed(pending());
    const out = await store.decline({
      id: REQ,
      nodeId: NODE,
      expectedRowVersion: 1,
      decidedBy: OP,
      actorId: OP,
    });
    expect(out.status).toBe("DECLINED");
    expect(out.implementer_id).toBeNull();
    expect(out.approved_rule_json).toBeNull();
    expect(store.audit[0]!.action).toBe(INTEGRATION_REQUEST_DECLINED_ACTION);
  });

  it("second concurrent-style approve loses CAS", async () => {
    const store = new InMemoryIntegrationRequestStore();
    store.seed(pending());
    await store.approve({
      id: REQ,
      nodeId: NODE,
      expectedRowVersion: 1,
      approvedRuleJson: "{}",
      implementerId: IMPL,
      decidedBy: OP,
      actorId: OP,
    });
    await expect(
      store.decline({
        id: REQ,
        nodeId: NODE,
        expectedRowVersion: 1,
        decidedBy: OP,
        actorId: OP,
      }),
    ).rejects.toMatchObject({ code: "CAS_MISS" });
  });
});

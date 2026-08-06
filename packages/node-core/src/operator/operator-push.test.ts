// Optional operator push: payload schema forbids secrets; fail-soft notify.

import { describe, expect, it } from "vitest";

import {
  assertOperatorPushPayloadSafe,
  buildOperatorPushPayload,
  InMemoryOperatorPushSubscriptionStore,
  notifyOperatorsPendingAttention,
  OPERATOR_PUSH_FORBIDDEN_PAYLOAD_KEYS,
  type OperatorPushPayload,
  type OperatorPushSender,
} from "./operator-push.js";

describe("operator push payload schema", () => {
  it("accepts attention type + deep link + summary only", () => {
    const payload = buildOperatorPushPayload({
      attentionType: "send_pending_approval",
      deepLinkPath: "/transfers/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      summary: "Outgoing 0.01 ZKZ needs approval",
      operationId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    });
    assertOperatorPushPayloadSafe(payload);
    expect(payload.attention_type).toBe("send_pending_approval");
    expect(payload.deep_link_path.startsWith("/")).toBe(true);
  });

  it("forbids secret fields", () => {
    for (const key of OPERATOR_PUSH_FORBIDDEN_PAYLOAD_KEYS) {
      const bad = {
        attention_type: "needs_attention",
        deep_link_path: "/operations",
        summary: "x",
        [key]: "leak",
      };
      expect(() => assertOperatorPushPayloadSafe(bad)).toThrow(/forbid|secret/i);
    }
  });

  it("rejects non-root-relative deep links", () => {
    expect(() =>
      buildOperatorPushPayload({
        attentionType: "needs_attention",
        deepLinkPath: "https://evil.example/x",
        summary: "x",
      }),
    ).toThrow(/path/i);
  });
});

describe("operator push store separation + fail-soft", () => {
  it("stores operator subscriptions separately from wallet push shape", () => {
    const store = new InMemoryOperatorPushSubscriptionStore();
    store.upsert({
      id: "sub-1",
      nodeId: "node-1",
      operatorId: "op-1",
      endpoint: "https://push.example/ep/1",
      p256dh: "pk",
      authSealed: "sealed:16",
      createdAt: "2026-08-03T00:00:00.000Z",
      userAgent: null,
    });
    expect(store.listByOperator("node-1", "op-1")).toHaveLength(1);
    expect(store.listByOperator("node-1", "op-2")).toHaveLength(0);
    // No wallet_id field on operator rows.
    expect("walletId" in store.listActiveByNode("node-1")[0]!).toBe(false);
  });

  it("notify fails soft when sender throws — never throws to caller", async () => {
    const store = new InMemoryOperatorPushSubscriptionStore();
    store.upsert({
      id: "sub-1",
      nodeId: "node-1",
      operatorId: "op-1",
      endpoint: "https://push.example/ep/1",
      p256dh: "pk",
      authSealed: "sealed:16",
      createdAt: "2026-08-03T00:00:00.000Z",
      userAgent: null,
    });
    const sender: OperatorPushSender = {
      async send() {
        throw new Error("push infra down");
      },
    };
    const payload: OperatorPushPayload = buildOperatorPushPayload({
      attentionType: "send_pending_approval",
      deepLinkPath: "/transfers/x",
      summary: "Pending",
    });
    const result = await notifyOperatorsPendingAttention(
      { store, sender, nodeId: "node-1" },
      payload,
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.delivered).toBe(0);
      expect(result.failed).toBe(1);
    }
  });

  it("unsubscribe leaves inbox path intact (opt-in only)", () => {
    const store = new InMemoryOperatorPushSubscriptionStore();
    store.upsert({
      id: "sub-1",
      nodeId: "node-1",
      operatorId: "op-1",
      endpoint: "https://push.example/ep/1",
      p256dh: "pk",
      authSealed: "sealed:16",
      createdAt: "2026-08-03T00:00:00.000Z",
      userAgent: null,
    });
    expect(store.deleteByEndpoint("node-1", "op-1", "https://push.example/ep/1")).toBe(true);
    expect(store.listActiveByNode("node-1")).toHaveLength(0);
  });
});

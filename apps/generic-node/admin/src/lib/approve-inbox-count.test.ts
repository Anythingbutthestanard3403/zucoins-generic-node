import { describe, expect, it } from "vitest";
import { countApproveInboxItems } from "./approve-inbox-count.js";
import type { NeedsAttentionListItem } from "./ops.js";
import type { DestinationItem, IntegrationRequestItem, OperationListItem } from "./money.js";

const send = (id: string): OperationListItem =>
  ({
    operation_id: id,
    operation_type: "SEND_EXTERNAL",
    status: "CREATED",
    amount_zkz: "1",
    row_version: 1,
    attention_required: false,
    attention_reason: null,
    created_at: "t",
    updated_at: "t",
    terminal_at: null,
    source_wallet_id: null,
    receiver_wallet_id: null,
    destination_id: null,
    destination_address: null,
    after_landing: null,
    after_landing_destination_id: null,
    formation_state: null,
    verification_verdict: null,
    implementer_id: null,
    client_reference: null,
  }) as OperationListItem;

const attn = (
  id: string,
  opts: Partial<NeedsAttentionListItem> = {},
): NeedsAttentionListItem => ({
  operation_id: id,
  operation_type: "RECEIVE_EXTERNAL",
  status: "READY",
  attention_required: true,
  attention_reason: "x",
  classification: "WAITING",
  classification_rationale: "r",
  severity: "P1",
  permitted_actions: [],
  row_version: 1,
  lease_epoch: null,
  attention_since: null,
  wallet_ids: [],
  ...opts,
});

describe("countApproveInboxItems (ZTR-1257)", () => {
  it("sums sends + bless + recovery + integration", () => {
    expect(
      countApproveInboxItems({
        sends: [send("s1")],
        attentionOps: [attn("a1")],
        pendingBless: [{ state: "PENDING" } as DestinationItem],
        pendingIntegration: [{} as IntegrationRequestItem],
      }),
    ).toBe(4);
  });

  it("does not double-count CREATED send that also appears in attention", () => {
    expect(
      countApproveInboxItems({
        sends: [send("s1")],
        attentionOps: [
          attn("s1", {
            operation_type: "SEND_EXTERNAL",
            status: "CREATED",
            attention_required: true,
          }),
        ],
        pendingBless: [],
        pendingIntegration: [],
      }),
    ).toBe(1);
  });

  it("attention-only backlog still counts as recovery cards (inbox work)", () => {
    // Badge equals inbox header — recovery cards ARE part of the inbox page.
    // They must not be the *only* thing the badge meant when it was wired to
    // needs-attention summary.total alone; here they are one of four terms.
    expect(
      countApproveInboxItems({
        sends: [],
        attentionOps: [attn("a1"), attn("a2")],
        pendingBless: [],
        pendingIntegration: [],
      }),
    ).toBe(2);
  });
});

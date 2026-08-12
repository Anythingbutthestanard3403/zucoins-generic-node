/**
 * Shared Approve-inbox actionable count (ZTR-1257).
 * Must stay identical to ApproveInboxPage header `totalPending` so the nav
 * badge never shows needs-attention totals under the Approve label.
 */

import { useQueries } from "@tanstack/react-query";
import { apiSoftRead } from "./api.js";
import {
  listDestinationsInventory,
  listIntegrationRequests,
  listSendOperationsInventory,
  type DestinationItem,
  type IntegrationRequestItem,
  type OperationListItem,
} from "./money.js";
import {
  EMPTY_NEEDS_ATTENTION,
  type NeedsAttentionListItem,
  type NeedsAttentionResponse,
} from "./ops.js";

export const APPROVE_INBOX_SENDS_KEY = ["approve-inbox-sends"] as const;
export const APPROVE_INBOX_ATTENTION_KEY = ["approve-inbox-attention"] as const;
export const APPROVE_INBOX_DESTINATIONS_KEY = ["approve-inbox-destinations"] as const;
export const APPROVE_INBOX_INTEGRATION_KEY = ["approve-inbox-integration-requests"] as const;

/** Query keys the inbox mutates — keep nav badge in sync via invalidation. */
export const APPROVE_INBOX_QUERY_KEYS = [
  APPROVE_INBOX_SENDS_KEY,
  APPROVE_INBOX_ATTENTION_KEY,
  APPROVE_INBOX_DESTINATIONS_KEY,
  APPROVE_INBOX_INTEGRATION_KEY,
] as const;

export function countApproveInboxItems(input: {
  readonly sends: readonly OperationListItem[];
  readonly attentionOps: readonly NeedsAttentionListItem[];
  readonly pendingBless: readonly DestinationItem[];
  readonly pendingIntegration: readonly IntegrationRequestItem[];
}): number {
  const sendIds = new Set(input.sends.map((s) => s.operation_id));
  const recoveryCards = input.attentionOps.filter((a) => {
    if (sendIds.has(a.operation_id) && a.status === "CREATED") return false;
    return a.attention_required || a.permitted_actions.length > 0;
  });
  return (
    input.sends.length +
    input.pendingBless.length +
    recoveryCards.length +
    input.pendingIntegration.length
  );
}

/**
 * Live badge count for the Approve nav item. Returns undefined while sources
 * are loading or all soft-reads are offline (do not show a stale/zero lie).
 */
export function useApproveInboxBadgeCount(enabled: boolean): number | undefined {
  const results = useQueries({
    queries: [
      {
        queryKey: [...APPROVE_INBOX_SENDS_KEY],
        queryFn: () => listSendOperationsInventory({ status: "CREATED" }),
        refetchInterval: 30_000,
        enabled,
      },
      {
        queryKey: [...APPROVE_INBOX_ATTENTION_KEY],
        queryFn: () =>
          apiSoftRead<NeedsAttentionResponse>(
            "/operations/needs-attention",
            EMPTY_NEEDS_ATTENTION,
          ),
        refetchInterval: 30_000,
        enabled,
      },
      {
        queryKey: [...APPROVE_INBOX_DESTINATIONS_KEY],
        queryFn: () => listDestinationsInventory(),
        refetchInterval: 30_000,
        enabled,
      },
      {
        queryKey: [...APPROVE_INBOX_INTEGRATION_KEY],
        queryFn: () => listIntegrationRequests({ status: "PENDING" }),
        refetchInterval: 30_000,
        enabled,
      },
    ],
  });

  const [sendsQ, attentionQ, destQ, irQ] = results;
  if (!enabled) return undefined;
  if (results.some((q) => q.isLoading)) return undefined;

  const sendsLive = sendsQ.data?.live === true;
  const sends: readonly OperationListItem[] = sendsLive ? (sendsQ.data?.data ?? []) : [];
  const attentionLive = attentionQ.data?.live === true;
  const attentionOps: readonly NeedsAttentionListItem[] = attentionLive
    ? (attentionQ.data?.data.operations ?? [])
    : [];
  const destLive = destQ.data?.live === true;
  const pendingBless: readonly DestinationItem[] = destLive
    ? (destQ.data?.data ?? []).filter((d) => d.state === "PENDING")
    : [];
  const irLive = irQ.data?.live === true;
  const pendingIntegration: readonly IntegrationRequestItem[] = irLive
    ? (irQ.data?.data ?? [])
    : [];

  // Need at least one primary live source before showing a number (matches page).
  if (!sendsLive && !attentionLive && !irLive && !destLive) return undefined;

  return countApproveInboxItems({
    sends,
    attentionOps,
    pendingBless,
    pendingIntegration,
  });
}

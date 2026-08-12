/**
 * Single shared needs-attention query (ZTR-1261).
 * All surfaces (Overview, Operations, Approve inbox, badge) use NEEDS_ATTENTION_KEY
 * so one invalidation refreshes every consumer.
 */

import { useQuery, type QueryClient, type UseQueryResult } from "@tanstack/react-query";
import { apiSoftRead, type ApiFailureDetail } from "./api.js";
import {
  EMPTY_NEEDS_ATTENTION,
  type NeedsAttentionResponse,
} from "./ops.js";

/** Sole React Query key for GET /admin/v1/operations/needs-attention. */
export const NEEDS_ATTENTION_KEY = ["needs-attention"] as const;

export type NeedsAttentionSoftRead = {
  readonly data: NeedsAttentionResponse;
  readonly live: boolean;
  readonly error?: ApiFailureDetail;
};

const DEFAULT_REFETCH_MS = 15_000;

export async function fetchNeedsAttentionSoft(): Promise<NeedsAttentionSoftRead> {
  return apiSoftRead<NeedsAttentionResponse>(
    "/operations/needs-attention",
    EMPTY_NEEDS_ATTENTION,
  );
}

/**
 * Shared soft-read of the needs-attention queue.
 * @param refetchIntervalMs poll interval (default 15s); pass false to disable.
 */
export function useNeedsAttention(options?: {
  readonly enabled?: boolean;
  readonly refetchIntervalMs?: number | false;
}): UseQueryResult<NeedsAttentionSoftRead> {
  const enabled = options?.enabled ?? true;
  const refetchInterval =
    options?.refetchIntervalMs === false
      ? false
      : (options?.refetchIntervalMs ?? DEFAULT_REFETCH_MS);
  return useQuery({
    queryKey: [...NEEDS_ATTENTION_KEY],
    queryFn: fetchNeedsAttentionSoft,
    refetchInterval,
    enabled,
  });
}

/** Invalidate the sole needs-attention cache entry (and legacy alias keys if any linger). */
export function invalidateNeedsAttention(qc: QueryClient): void {
  void qc.invalidateQueries({ queryKey: [...NEEDS_ATTENTION_KEY] });
  // Drop legacy keys so a stale mount cannot keep a second poll loop alive.
  void qc.removeQueries({ queryKey: ["needs-attention-overview"] });
  void qc.removeQueries({ queryKey: ["needs-attention-nav"] });
  void qc.removeQueries({ queryKey: ["approve-inbox-attention"] });
}

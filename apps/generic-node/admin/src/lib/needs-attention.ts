/**
 * Single shared needs-attention query (ZTR-1261).
 * All surfaces (Overview, Operations, Approve inbox, badge) use NEEDS_ATTENTION_KEY
 * so one invalidation refreshes every consumer.
 *
 * ZTR-1284: first page is cached under NEEDS_ATTENTION_KEY (badge uses summary.total).
 * Operations inbox may walk `after` / next_cursor for load-more without polluting the
 * shared first-page cache.
 */

import { useQuery, type QueryClient, type UseQueryResult } from "@tanstack/react-query";
import { api, apiSoftRead, type ApiFailureDetail } from "./api.js";
import {
  EMPTY_NEEDS_ATTENTION,
  type NeedsAttentionResponse,
} from "./ops.js";

/** Sole React Query key for GET /admin/v1/operations/needs-attention (first page). */
export const NEEDS_ATTENTION_KEY = ["needs-attention"] as const;

/** Default page size — matches server NEEDS_ATTENTION_DEFAULT_LIMIT. */
export const NEEDS_ATTENTION_PAGE_LIMIT = 50;

export type NeedsAttentionSoftRead = {
  readonly data: NeedsAttentionResponse;
  readonly live: boolean;
  readonly error?: ApiFailureDetail;
};

const DEFAULT_REFETCH_MS = 15_000;

function needsAttentionPath(params?: {
  readonly limit?: number;
  readonly after?: string;
}): string {
  const q = new URLSearchParams();
  if (params?.limit !== undefined) q.set("limit", String(params.limit));
  if (params?.after !== undefined) q.set("after", params.after);
  const encoded = q.toString();
  return encoded.length === 0
    ? "/operations/needs-attention"
    : `/operations/needs-attention?${encoded}`;
}

/** Soft-read first page (badge / overview / shared cache). */
export async function fetchNeedsAttentionSoft(): Promise<NeedsAttentionSoftRead> {
  return apiSoftRead<NeedsAttentionResponse>(
    needsAttentionPath({ limit: NEEDS_ATTENTION_PAGE_LIMIT }),
    EMPTY_NEEDS_ATTENTION,
  );
}

/** Hard-read a page (load-more). Throws on transport/auth failure. */
export async function fetchNeedsAttentionPage(params?: {
  readonly limit?: number;
  readonly after?: string;
}): Promise<NeedsAttentionResponse> {
  return api<NeedsAttentionResponse>(
    needsAttentionPath({
      limit: params?.limit ?? NEEDS_ATTENTION_PAGE_LIMIT,
      ...(params?.after !== undefined ? { after: params.after } : {}),
    }),
  );
}

/**
 * Shared soft-read of the needs-attention queue (first page).
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

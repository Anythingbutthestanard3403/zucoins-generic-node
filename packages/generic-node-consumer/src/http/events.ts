/**
 * GET /v1/events. Signed-reporting-credential authenticated.
 *
 * Each served item is exactly the `zp-implementer-event-v1` artifact envelope
 * (`{key_id, preimage_text, preimage_sha256, signature}` — packages/node-core
 * event-log/dual-chain-appender.ts `buildArtifactEnvelope`); the event's own fields
 * (event_id, implementer_seq, operation_id, event_type, …) live inside the signed
 * `preimage_text`, not as separate top-level JSON properties. Companion
 * `checkpoints[]` carry opaque `zp-implementer-checkpoint-v1` envelopes.
 *
 * Authenticate served envelopes with `authenticateImplementerEvent` (exported from
 * this package and from `@zucoins/node-core/verifier/consumer`). Turn an authenticated
 * event into a `NodeEventWake` and hand it to `ingestEventWake` in pipeline.ts.
 */

import type { ArtifactEnvelope } from "@zucoins/node-core/verifier/consumer";

import { assertOk } from "./errors.js";
import { resolveFetch, resolveUrl, type NodeClientConfig } from "./client-types.js";
import {
  buildSignedReportingHeaders,
  type ReportingCredential,
} from "./reporting-signer.js";

export interface GetEventsQuery {
  /** Decimal string, exclusive. Omit for the beginning of the stream. */
  readonly afterImplementerSeq?: string;
  /** 1–500, default 100. */
  readonly limit?: number;
  /** 0–30 seconds, default 0 (long-poll budget). */
  readonly waitSeconds?: number;
}

export interface GetEventsResponse {
  readonly events: readonly ArtifactEnvelope[];
  /** Durable zp-implementer-checkpoint-v1 proofs, carried through unparsed. Always present, may be empty. */
  readonly checkpoints: readonly ArtifactEnvelope[];
  readonly implementer_watermark_seq: string;
  readonly next_after_implementer_seq: string;
}

export interface GetEventsInput {
  readonly config: NodeClientConfig;
  readonly credential: ReportingCredential;
  readonly query?: GetEventsQuery;
}

/**
 * Build the exact raw target for `GET /v1/events`. Query keys are emitted in the frozen
 * ascending-ASCII order the node's signed-target validator requires
 * (`after_implementer_seq` < `limit` < `wait_seconds`) — never reordered by a generic
 * query-string builder.
 */
export function buildEventsRawTarget(query: GetEventsQuery = {}): string {
  const pairs: string[] = [];
  if (query.afterImplementerSeq !== undefined) {
    pairs.push(`after_implementer_seq=${query.afterImplementerSeq}`);
  }
  if (query.limit !== undefined) {
    pairs.push(`limit=${query.limit}`);
  }
  if (query.waitSeconds !== undefined) {
    pairs.push(`wait_seconds=${query.waitSeconds}`);
  }
  return pairs.length === 0 ? "/v1/events" : `/v1/events?${pairs.join("&")}`;
}

/** `GET /v1/events`. Cursor fields are decimal strings — never parsed to `number` here. */
export async function getEvents(input: GetEventsInput): Promise<GetEventsResponse> {
  const rawTarget = buildEventsRawTarget(input.query);
  const emptyBody = new Uint8Array(0);
  const headers = await buildSignedReportingHeaders({
    credential: input.credential,
    method: "GET",
    rawTarget,
    bodyBytes: emptyBody,
  });
  const fetchImpl = resolveFetch(input.config);
  const response = await fetchImpl(resolveUrl(input.config, rawTarget), {
    method: "GET",
    headers,
  });
  await assertOk(response);
  return (await response.json()) as GetEventsResponse;
}

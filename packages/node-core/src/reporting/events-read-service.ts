// the read-only events read-service backing GET /v1/events and
// GET /v1/events/stream. It is a pure pagination + SSE
// framing layer over a READ-ONLY store seam; it performs no persistence write, opens no
// socket, and makes zero node-initiated push. This is the sanctioned signed pull event stream / reporting-key enrolment ceremony pull
// channel that replaced the removed node-side delivery table: the node never pushes, the
// tenant pulls.
//
// Scope of the served stream: these routes serve the calling implementer's own
// zp-implementer-event-v1 proof stream, cursored by that implementer's decimal
// implementer_seq. / UP-07: GET /v1/events also carries the implementer's durable
// zp-implementer-checkpoint-v1 proofs as `checkpoints[]` (companions). The
// node-global signed event stream is operator/auditor-only and is NEVER exposed on
// any route reachable by a signed reporting credential, so this module never reads it
// the store port speaks only implementer-scoped events and checkpoints.
//
// Byte discipline: each event's and checkpoint's proof representation is a
// signed artifact. Its exact byte format is frozen elsewhere (the sibling byte-freeze child,
// binding condition C4), so this module treats every proof representation as OPAQUE exact
// bytes supplied by the store and only frames it — it never re-serializes or reorders a
// proof, in the JSON envelope or in an SSE data line.

// One implementer-scoped event as served on the wire: its decimal cursor position, its
// event_type (used as the SSE `event:` field), and the exact zp-implementer-event-v1 proof
// representation text (inserted verbatim; never reformatted).
export interface ServedImplementerEvent {
  readonly implementerSeq: bigint;
  readonly eventType: string;
  readonly proofRepresentation: string;
}

// One durable zp-implementer-checkpoint-v1 proof as served on GET /v1/events `checkpoints[]`.
export interface ServedImplementerCheckpoint {
  readonly checkpointEpoch: bigint;
  readonly implementerSeqHead: bigint;
  readonly proofRepresentation: string;
}

// limit bounds: 1.500, default 100.
export const EVENTS_LIMIT_MIN = 1 as const;
export const EVENTS_LIMIT_MAX = 500 as const;
export const EVENTS_LIMIT_DEFAULT = 100 as const;

export function clampEventsLimit(limit: number | undefined): number {
  if (limit === undefined) return EVENTS_LIMIT_DEFAULT;
  if (limit < EVENTS_LIMIT_MIN) return EVENTS_LIMIT_MIN;
  if (limit > EVENTS_LIMIT_MAX) return EVENTS_LIMIT_MAX;
  return Math.trunc(limit);
}

// Read-only store seam. Events after an exclusive cursor; checkpoints for the implementer.
// There is deliberately NO write/append/deliver/push method — the node never emits from here.
export interface ImplementerEventReadStore {
  readEvents(
    implementerId: string,
    afterImplementerSeq: bigint | null,
    limit: number,
  ): Promise<ImplementerEventPage>;
  /**
   * Durable zp-implementer-checkpoint-v1 proofs for this implementer (UP-07).
   * Optional on legacy fixtures: absence is treated as an empty list.
   */
  readCheckpoints?(implementerId: string): Promise<readonly ServedImplementerCheckpoint[]>;
}

export interface ImplementerEventPage {
  readonly events: readonly ServedImplementerEvent[];
  readonly watermarkSeq: bigint;
}

export interface EventsListQuery {
  readonly implementerId: string;
  readonly afterImplementerSeq: bigint | null;
  readonly limit?: number;
}

export interface EventsListResult {
  readonly events: readonly ServedImplementerEvent[];
  readonly checkpoints: readonly ServedImplementerCheckpoint[];
  readonly watermarkSeq: bigint;
  readonly nextAfterSeq: bigint;
}

// GET /v1/events (+ checkpoints[]): read a bounded event page, the durable
// checkpoint proofs, and compute the resume cursor. When the page is non-empty, the next
// cursor is the last returned event's seq; when the caller is caught up (empty page), it is
// the current watermark, so the client resumes at head.
export async function listEvents(
  store: ImplementerEventReadStore,
  query: EventsListQuery,
): Promise<EventsListResult> {
  const limit = clampEventsLimit(query.limit);
  const page = await store.readEvents(query.implementerId, query.afterImplementerSeq, limit);
  const checkpoints =
    store.readCheckpoints === undefined
      ? []
      : await store.readCheckpoints(query.implementerId);
  const last = page.events.at(-1);
  const nextAfterSeq = last === undefined ? page.watermarkSeq : last.implementerSeq;
  return {
    events: page.events,
    checkpoints,
    watermarkSeq: page.watermarkSeq,
    nextAfterSeq,
  };
}

// Renders the GET /v1/events response body. Event and checkpoint proof representations are
// inserted VERBATIM between structural tokens so their signed bytes survive unchanged; only
// the envelope and the decimal cursor strings are composed here. `checkpoints` is always
// present (may be `[]`) so the channel is audible even on a quiet tail (UP-07).
export function renderEventsListBody(result: EventsListResult): string {
  const events = result.events.map((event) => event.proofRepresentation).join(",");
  const checkpoints = result.checkpoints
    .map((checkpoint) => checkpoint.proofRepresentation)
    .join(",");
  return (
    `{"events":[${events}],` +
    `"checkpoints":[${checkpoints}],` +
    `"implementer_watermark_seq":"${result.watermarkSeq.toString()}",` +
    `"next_after_implementer_seq":"${result.nextAfterSeq.toString()}"}`
  );
}

export type StreamCursorResolution =
  | { readonly ok: true; readonly afterImplementerSeq: bigint | null }
  | { readonly ok: false; readonly code: "cursor_mismatch" };

// GET /v1/events/stream: the resume position is the query after_implementer_seq; a
// supplied Last-Event-ID must equal it exactly, else the node returns 400 cursor_mismatch.
export function resolveStreamCursor(
  afterImplementerSeq: bigint | null,
  lastEventId: string | null,
): StreamCursorResolution {
  if (lastEventId === null) {
    return { ok: true, afterImplementerSeq };
  }
  if (afterImplementerSeq !== null && lastEventId === afterImplementerSeq.toString()) {
    return { ok: true, afterImplementerSeq };
  }
  return { ok: false, code: "cursor_mismatch" };
}

// Frames a page as SSE: `id` is the decimal implementer_seq, `event` is the
// event_type, and `data` is the exact proof representation inserted verbatim. Each record ends
// with the blank line that terminates an SSE event.
export function frameImplementerEventStream(
  events: readonly ServedImplementerEvent[],
): string {
  return events
    .map(
      (event) =>
        `id: ${event.implementerSeq.toString()}\n` +
        `event: ${event.eventType}\n` +
        `data: ${event.proofRepresentation}\n\n`,
    )
    .join("");
}

// Single-process reference adapter (mirrors reporting/in-memory-store.ts). Seeded per
// implementer; reads are pure filters over the seeded events and checkpoints. READ-ONLY: the
// only surfaces are seed (test/deploy harness) and readEvents/readCheckpoints.
export class InMemoryImplementerEventReadStore implements ImplementerEventReadStore {
  private readonly byImplementer = new Map<string, ServedImplementerEvent[]>();
  private readonly checkpointsByImplementer = new Map<string, ServedImplementerCheckpoint[]>();

  seedEvent(implementerId: string, event: ServedImplementerEvent): void {
    const list = this.byImplementer.get(implementerId) ?? [];
    list.push(event);
    list.sort((left, right) => (left.implementerSeq < right.implementerSeq ? -1 : 1));
    this.byImplementer.set(implementerId, list);
  }

  seedCheckpoint(implementerId: string, checkpoint: ServedImplementerCheckpoint): void {
    const list = this.checkpointsByImplementer.get(implementerId) ?? [];
    list.push(checkpoint);
    list.sort((left, right) => (left.checkpointEpoch < right.checkpointEpoch ? -1 : 1));
    this.checkpointsByImplementer.set(implementerId, list);
  }

  readEvents(
    implementerId: string,
    afterImplementerSeq: bigint | null,
    limit: number,
  ): Promise<ImplementerEventPage> {
    const all = this.byImplementer.get(implementerId) ?? [];
    const watermarkSeq = all.reduce(
      (high, event) => (event.implementerSeq > high ? event.implementerSeq : high),
      0n,
    );
    const after = afterImplementerSeq ?? -1n;
    const events = all.filter((event) => event.implementerSeq > after).slice(0, limit);
    return Promise.resolve({ events, watermarkSeq });
  }

  readCheckpoints(implementerId: string): Promise<readonly ServedImplementerCheckpoint[]> {
    return Promise.resolve(this.checkpointsByImplementer.get(implementerId) ?? []);
  }
}

// the mint/writer that produces one durable event on BOTH continuity chains.
//
// Every durable event exists twice by construction: the node-global operator/auditor
// zp-node-event-v1 row, and the tenant-facing zp-implementer-event-v1 proof that carries the
// non-invertible node_event_hash back to it (NC2 — the tenant never sees the global seq).
// Both rows are written on the CALLER'S transaction, so an event is durable exactly when the
// state change that triggered it is: both are appended in the same transaction.
//
// Locks are always taken global-head first, implementer-head second (the fixed lock sequence
// IMPLEMENTER_SEQ_MODEL pins); both seqs are allocated pre-sign from a locked counter, never
// IDENTITY (gapless per-node event counter).
//
// This is a pull-side durability surface only. There is no outbox, no delivery table and no
// node→platform push here (reporting-key enrolment ceremony): the node appends and the tenant reads GET /v1/events.

import { createHash, randomUUID } from "node:crypto";

import { buildNodeEventPreimage } from "@zucoins/generic-node-contracts";
import { Rfc3339MsSchema } from "@zucoins/generic-node-contracts/api-schema";
import {
  buildImplementerEventPreimage,
  IMPLEMENTER_EVENT_CANONICAL_VERSION,
  IMPLEMENTER_EVENT_PURPOSE,
} from "@zucoins/generic-node-contracts/implementer-events";

import type { NodeEventType } from "../protocol/suite/index.js";
import { computeEventLogNodeEventHash } from "./event-list.js";
import {
  createPgEventListStore,
  lockNodeEventCounter,
  type SqlQueryFn,
} from "./pg-event-store.js";
import { EventLogError, type EventRecord } from "./store.js";

/** Ed25519 EVENT_SIGNING signer. `sign` returns the padded base64url wire signature. */
export interface NodeEventSigner {
  readonly signingKeyId: string;
  sign(preimageBytes: Uint8Array): string;
}

export interface DualChainAppendInput {
  readonly implementerId: string;
  readonly eventType: NodeEventType;
  readonly operationId: string | null;
  readonly walletId: string | null;
  /** Exact separately stored event-data JSON text. Digested, never reformatted (the byte-exact signing rule). */
  readonly dataText: string;
  readonly dataSha256: string;
  /**
   * Canonical RFC3339 millisecond timestamp shared by both tuples. Optional — omit it to have
   * the appender server-stamp the wall-clock time of the append; if supplied, it is
   * validated (never trusted verbatim into a signed preimage) rather than overridden, since some
   * callers need it to match a business timestamp captured earlier in the same transaction.
   */
  readonly createdAt?: string;
  /** Optional caller-chosen event id; both chains carry the same one. */
  readonly eventId?: string;
}

// createdAt is resolved (server-stamped or validated) before either append helper runs, so both
// take this narrowed shape rather than DualChainAppendInput itself — TypeScript does not narrow
// a parameter type from what a call site happens to pass.
type ResolvedDualChainAppendInput = Omit<DualChainAppendInput, "createdAt"> & {
  readonly createdAt: string;
};

export type DualChainAppendOutcome =
  | {
      readonly kind: "APPENDED";
      readonly eventId: string;
      readonly nodeSeq: bigint;
      readonly nodeEventHash: string;
      readonly implementerSeq: bigint;
      readonly proofRepresentation: string;
    }
  | { readonly kind: "QUOTA_EXCEEDED"; readonly windowCap: number; readonly windowMs: number };

/**
 * Per-(node, implementer) rolling-window cap on durable event appends.
 *
 * The event tables are append-only with no retention, so an uncapped append reachable
 * from a tenant-driven operation path is a disk-fill DoS. The bound rejects rather than grows:
 * over quota, NEITHER chain is written, so both stay gapless-as-minted (NC1 permits a node
 * that never assigns a seq; it does not permit a gap).
 */
export const DEFAULT_IMPLEMENTER_EVENT_QUOTA = Object.freeze({
  windowCap: 1_000,
  windowMs: 3_600_000,
});

export interface DualChainEventQuota {
  readonly windowCap: number;
  readonly windowMs: number;
}

export interface DualChainAppenderConfig {
  readonly nodeId: string;
  /** MUST be bound to the caller's open transaction — both rows commit with the state change. */
  readonly query: SqlQueryFn;
  readonly signer: NodeEventSigner;
  readonly quota?: DualChainEventQuota;
  /** Bounded STALE_TAIL retries on the node chain (each retry re-signs at the new seq). */
  readonly maxAppendRetries?: number;
  /** Clock used to server-stamp created_at when the caller omits it. Defaults to `new Date`. */
  readonly now?: () => Date;
}

const DEFAULT_MAX_APPEND_RETRIES = 8;

// event-log must not import from reporting/ (dependency-direction gate), so the digest helper
// is local. Same rule as reporting/ed25519.ts sha256HexUtf8: SHA-256 over the UTF-8 bytes.
function sha256HexUtf8(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

const ENSURE_IMPLEMENTER_COUNTER = `
INSERT INTO implementer_event_seq_counters (node_id, implementer_id, next_seq)
VALUES ($1::uuid, $2::uuid, 1)
ON CONFLICT (node_id, implementer_id) DO NOTHING
`;

const LOCK_IMPLEMENTER_COUNTER = `
SELECT next_seq FROM implementer_event_seq_counters
 WHERE node_id = $1::uuid AND implementer_id = $2::uuid
 FOR UPDATE
`;

const ADVANCE_IMPLEMENTER_COUNTER = `
UPDATE implementer_event_seq_counters
   SET next_seq = $3::bigint
 WHERE node_id = $1::uuid AND implementer_id = $2::uuid AND next_seq = $4::bigint
RETURNING next_seq
`;

const SELECT_IMPLEMENTER_PREVIOUS = `
SELECT proof_representation
  FROM implementer_events
 WHERE node_id = $1::uuid AND implementer_id = $2::uuid AND implementer_seq = $3::bigint
`;

const INSERT_IMPLEMENTER_EVENT = `
INSERT INTO implementer_events (
  node_id, implementer_id, implementer_seq, event_id, event_type,
  proof_representation, created_at
) VALUES (
  $1::uuid, $2::uuid, $3::bigint, $4::uuid, $5::text,
  $6::text, $7::timestamptz
)
`;

// Quota probe head. Read from the event rows rather than the counter so the probe takes no
// lock and creates no counter row before the global head is locked (lock-sequence safety).
const SELECT_IMPLEMENTER_HEAD = `
SELECT COALESCE(max(implementer_seq), 0) AS head
  FROM implementer_events
 WHERE node_id = $1::uuid AND implementer_id = $2::uuid
`;

// Quota probe: seqs are gapless, so "cap events already inside the window" is exactly
// "the row cap-1 positions behind the head is still inside the window" — one primary-key
// lookup, never a scan that grows with the tenant's history.
const IMPLEMENTER_QUOTA_PROBE = `
SELECT 1 AS over
  FROM implementer_events
 WHERE node_id = $1::uuid
   AND implementer_id = $2::uuid
   AND implementer_seq = $3::bigint
   AND created_at > now() - ($4::bigint * interval '1 millisecond')
`;

interface ArtifactEnvelopeFields {
  readonly keyId: string;
  readonly preimageText: string;
  readonly signature: string;
}

/**
 * Artifact envelope — the exact four fields in the exact frozen sequence. The
 * envelope is not itself signed; it carries the signed preimage bytes verbatim so a verifier
 * can recompute and check.
 */
export function buildArtifactEnvelope(fields: ArtifactEnvelopeFields): string {
  return JSON.stringify({
    key_id: fields.keyId,
    preimage_text: fields.preimageText,
    preimage_sha256: sha256HexUtf8(fields.preimageText),
    signature: fields.signature,
  });
}

/**
 * Recompute an implementer event's hash from its stored proof representation. Chaining needs
 * the previous hash and implementer_events stores only the envelope — parsing the envelope to
 * recompute SHA256(preimage_bytes ‖ signature_bytes) is the inverse of the builder, never a
 * re-serialization of signed bytes.
 */
export function implementerEventHashOf(proofRepresentation: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(proofRepresentation);
  } catch {
    throw new EventLogError("stored implementer proof representation is not valid JSON");
  }
  const envelope = parsed as { preimage_text?: unknown; signature?: unknown };
  if (typeof envelope.preimage_text !== "string" || typeof envelope.signature !== "string") {
    throw new EventLogError("stored implementer proof representation is not an artifact envelope");
  }
  return computeEventLogNodeEventHash(envelope.preimage_text, envelope.signature);
}

function asBigint(value: unknown): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return BigInt(value);
  if (typeof value === "string") return BigInt(value);
  throw new EventLogError(`expected bigint-compatible value, got ${typeof value}`);
}

export interface DualChainEventAppender {
  append(input: DualChainAppendInput): Promise<DualChainAppendOutcome>;
}

export interface ImplementerEventLegInput {
  readonly nodeId: string;
  readonly implementerId: string;
  /** Both chains carry the same event id — the caller minted it with the node leg. */
  readonly eventId: string;
  readonly eventType: NodeEventType;
  readonly operationId: string | null;
  readonly walletId: string | null;
  readonly dataSha256: string;
  /** The non-invertible link back to the node-global row (NC2 — the tenant never sees the global seq). */
  readonly nodeEventHash: string;
  readonly createdAt: string;
  readonly signer: NodeEventSigner;
}

export interface ImplementerEventLegResult {
  readonly seq: bigint;
  readonly proofRepresentation: string;
}

/**
 * Append the tenant zp-implementer-event-v1 leg alone, for a node-global row the CALLER
 * already minted and inserted.
 *
 * `append()` above owns both legs and is what almost every slice wants. The exception is
 * MOVE_INTERNAL: `core/move-internal-landing-store.ts` inserts the node_events row inside its
 * own compare-and-swap CTE (one statement, so the state change and its event cannot tear), so
 * the node leg cannot be delegated here without double-inserting. That caller mints and signs
 * the node tuple, hands it to the CAS, and then calls this with the resulting node event hash
 * — on the same transaction, so the tenant proof is durable exactly when the state change is.
 *
 * The rolling implementer quota is NOT probed here; `append()` owns that decision, because a
 * quota refusal must be able to abort the whole append and only the two-leg entry point can.
 */
export async function appendImplementerEventLeg(
  query: SqlQueryFn,
  input: ImplementerEventLegInput,
): Promise<ImplementerEventLegResult> {
  const { nodeId, implementerId, eventId, nodeEventHash, signer } = input;
  await query(ENSURE_IMPLEMENTER_COUNTER, [nodeId, implementerId]);
  const locked = await query(LOCK_IMPLEMENTER_COUNTER, [nodeId, implementerId]);
  const lockRow = locked[0];
  if (lockRow === undefined) {
    throw new EventLogError("implementer_event_seq_counters row missing after ensure");
  }
  const nextSeq = asBigint(lockRow.next_seq);
  const previousRows =
    nextSeq === 1n
      ? []
      : await query(SELECT_IMPLEMENTER_PREVIOUS, [
          nodeId,
          implementerId,
          (nextSeq - 1n).toString(),
        ]);
  const previousRow = previousRows[0];
  if (nextSeq > 1n && previousRow === undefined) {
    throw new EventLogError(
      `implementer chain gap: seq ${(nextSeq - 1n).toString()} missing for ${implementerId}`,
    );
  }
  const implementerPreviousEventHash =
    previousRow === undefined
      ? null
      : implementerEventHashOf(String(previousRow.proof_representation));

  const preimageText = buildImplementerEventPreimage({
    purpose: IMPLEMENTER_EVENT_PURPOSE,
    canonical_version: IMPLEMENTER_EVENT_CANONICAL_VERSION,
    node_id: nodeId,
    implementer_id: implementerId,
    event_id: eventId,
    implementer_seq: nextSeq.toString(),
    operation_id: input.operationId,
    wallet_id: input.walletId,
    event_type: input.eventType,
    data_sha256: input.dataSha256,
    node_event_hash: nodeEventHash,
    implementer_previous_event_hash: implementerPreviousEventHash,
    created_at: input.createdAt,
  });
  const proofRepresentation = buildArtifactEnvelope({
    keyId: signer.signingKeyId,
    preimageText,
    signature: signer.sign(Buffer.from(preimageText, "utf8")),
  });

  await query(INSERT_IMPLEMENTER_EVENT, [
    nodeId,
    implementerId,
    nextSeq.toString(),
    eventId,
    input.eventType,
    proofRepresentation,
    input.createdAt,
  ]);
  const advanced = await query(ADVANCE_IMPLEMENTER_COUNTER, [
    nodeId,
    implementerId,
    (nextSeq + 1n).toString(),
    nextSeq.toString(),
  ]);
  if (advanced[0] === undefined) {
    throw new EventLogError("implementer_seq counter advance lost the race under lock");
  }
  return { seq: nextSeq, proofRepresentation };
}

export function createDualChainEventAppender(
  config: DualChainAppenderConfig,
): DualChainEventAppender {
  const { nodeId, query, signer } = config;
  const quota = config.quota ?? DEFAULT_IMPLEMENTER_EVENT_QUOTA;
  const maxAppendRetries = config.maxAppendRetries ?? DEFAULT_MAX_APPEND_RETRIES;
  const now = config.now ?? (() => new Date());
  // Bind the frozen node_events adapter to the caller's transaction: its counter lock, insert
  // and advance all run inline, so the node row commits with the caller's state change.
  const nodeStore = createPgEventListStore({
    query,
    withTransaction: (body) => body(query),
  });

  const overQuota = async (implementerId: string): Promise<boolean> => {
    const headRows = await query(SELECT_IMPLEMENTER_HEAD, [nodeId, implementerId]);
    const head = asBigint(headRows[0]?.head ?? 0);
    const probeSeq = head - BigInt(quota.windowCap) + 1n;
    if (probeSeq < 1n) return false;
    const rows = await query(IMPLEMENTER_QUOTA_PROBE, [
      nodeId,
      implementerId,
      probeSeq.toString(),
      quota.windowMs.toString(),
    ]);
    return rows.length > 0;
  };

  const appendNodeEvent = async (
    input: ResolvedDualChainAppendInput,
    eventId: string,
  ): Promise<EventRecord> => {
    for (let attempt = 0; attempt <= maxAppendRetries; attempt += 1) {
      const tail = await nodeStore.readTail(nodeId);
      const seq = tail.highWater + 1n;
      const preimageText = buildNodeEventPreimage({
        purpose: "zp-node-event-v1",
        canonical_version: 1,
        node_id: nodeId,
        event_id: eventId,
        seq: seq.toString(),
        operation_id: input.operationId,
        wallet_id: input.walletId,
        event_type: input.eventType,
        data_sha256: input.dataSha256,
        previous_event_hash: tail.lastEventHash,
        created_at: input.createdAt,
      });
      const signature = signer.sign(Buffer.from(preimageText, "utf8"));
      const record: EventRecord = Object.freeze({
        seq,
        eventId,
        purpose: "zp-node-event-v1" as const,
        canonicalVersion: 1 as const,
        nodeId,
        operationId: input.operationId,
        walletId: input.walletId,
        eventType: input.eventType,
        dataText: input.dataText,
        dataSha256: input.dataSha256,
        preimageText,
        preimageSha256: sha256HexUtf8(preimageText),
        signingKeyId: signer.signingKeyId,
        signature,
        previousEventHash: tail.lastEventHash,
        eventHash: computeEventLogNodeEventHash(preimageText, signature),
        createdAt: input.createdAt,
      });
      const outcome = await nodeStore.appendBatch(nodeId, [record], tail.highWater);
      if (outcome.kind === "APPENDED") return record;
      // STALE_TAIL: another writer committed between readTail and the counter lock. The lock is
      // now held on this transaction, so the re-read is final; re-sign at the new seq.
    }
    throw new EventLogError(
      `node event append could not commit after ${maxAppendRetries} retries under contention`,
    );
  };

  const appendImplementerEvent = async (
    input: ResolvedDualChainAppendInput,
    eventId: string,
    nodeEventHash: string,
  ): Promise<ImplementerEventLegResult> =>
    appendImplementerEventLeg(query, {
      nodeId,
      implementerId: input.implementerId,
      eventId,
      eventType: input.eventType,
      operationId: input.operationId,
      walletId: input.walletId,
      dataSha256: input.dataSha256,
      nodeEventHash,
      createdAt: input.createdAt,
      signer,
    });

  return {
    async append(input: DualChainAppendInput): Promise<DualChainAppendOutcome> {
      // Server-stamp when omitted; validate either way before anything durable
      // happens — created_at is embedded verbatim in both signed preimages (the byte-exact signing rule), so
      // a malformed value must never reach either chain.
      const createdAt = input.createdAt ?? now().toISOString();
      if (!Rfc3339MsSchema.safeParse(createdAt).success) {
        throw new EventLogError(
          `created_at must be an RFC 3339 UTC timestamp with millisecond precision, got ${createdAt}`,
        );
      }
      const resolvedInput: ResolvedDualChainAppendInput = { ...input, createdAt };

      // take the node-global counter lock BEFORE the quota probe. overQuota below
      // reads implementer_events with no lock of its own, so without this every concurrent
      // append for this node would race the same TOCTOU window and could all pass the probe
      // before any of them commits. Locks are global-head first (IMPLEMENTER_SEQ_MODEL), so
      // taking it here — ahead of the implementer-head work below — is in the fixed sequence.
      // appendNodeEvent's appendBatch re-acquires this same row lock later in the same
      // transaction; Postgres allows a transaction to re-lock a row it already holds, so that
      // second acquisition is a no-op, not a second wait.
      await lockNodeEventCounter(query, nodeId);

      // Quota first: over the bound NEITHER chain is written, so both stay gapless-as-minted.
      if (await overQuota(input.implementerId)) {
        return { kind: "QUOTA_EXCEEDED", windowCap: quota.windowCap, windowMs: quota.windowMs };
      }

      const eventId = input.eventId ?? randomUUID();
      const nodeRecord = await appendNodeEvent(resolvedInput, eventId);
      const implementer = await appendImplementerEvent(resolvedInput, eventId, nodeRecord.eventHash);
      return {
        kind: "APPENDED",
        eventId,
        nodeSeq: nodeRecord.seq,
        nodeEventHash: nodeRecord.eventHash,
        implementerSeq: implementer.seq,
        proofRepresentation: implementer.proofRepresentation,
      };
    },
  };
}

/**
 * Raised when a terminal landed transition cannot be accompanied by its signed dual-chain
 * event. Always aborts the caller's landing transaction — see `appendTerminalLandedEvent`.
 */
export class TerminalEventNotAppendableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TerminalEventNotAppendableError";
  }
}

export interface TerminalLandedEventInput {
  readonly nodeId: string;
  readonly implementerId: string;
  readonly operationId: string;
  readonly walletId: string | null;
  /** Terminal event literal for the slice — `receive.landed` or `external_send.landed`. */
  readonly eventType: NodeEventType;
  /** The slice's already-built event data. Digested, never re-serialized (the byte-exact signing rule). */
  readonly dataText: string;
  /** The landed instant, so the signed tuples and the durable row cite one timestamp. */
  readonly createdAt: string;
  readonly signer: NodeEventSigner;
  readonly quota?: DualChainEventQuota;
}

/**
 * append a terminal `*.landed` event on BOTH continuity chains, on the caller's
 * open landing transaction.
 *
 * `query` MUST be bound to the transaction running the landed status CAS: that is what makes
 * the status change and its authoritative event one durable unit ("appended in
 * the same transaction"). Before this existed, RECEIVE and SEND landings wrote only their
 * slice-local `*_landing_events` row, so an operation could be durably LANDED while every
 * signed pull/SSE consumer of `node_events` / `implementer_events` saw nothing terminal.
 *
 * FAIL-CLOSED, and that is the point (Byte-exact): every non-append path here THROWS rather than
 * returning, so the caller's transaction rolls back and no landed status is ever committed
 * without its signed event. That includes an exhausted tenant event quota — a dropped
 * terminal event is a permanent hole in the authoritative chain, whereas an aborted landing
 * is a retryable stall that leaves the settled body and the operation exactly as they were.
 */
export async function appendTerminalLandedEvent(
  query: SqlQueryFn,
  input: TerminalLandedEventInput,
): Promise<DualChainAppendOutcome & { readonly kind: "APPENDED" }> {
  const appender = createDualChainEventAppender({
    nodeId: input.nodeId,
    query,
    signer: input.signer,
    ...(input.quota !== undefined ? { quota: input.quota } : {}),
  });
  const outcome = await appender.append({
    implementerId: input.implementerId,
    eventType: input.eventType,
    operationId: input.operationId,
    walletId: input.walletId,
    dataText: input.dataText,
    dataSha256: sha256HexUtf8(input.dataText),
    createdAt: input.createdAt,
  });
  if (outcome.kind === "QUOTA_EXCEEDED") {
    throw new TerminalEventNotAppendableError(
      `${input.eventType} for operation ${input.operationId} cannot be appended: implementer ` +
        `${input.implementerId} is over its event quota (${outcome.windowCap} per ` +
        `${outcome.windowMs}ms). The landing is aborted rather than committed unproven (Byte-exact).`,
    );
  }
  return outcome;
}

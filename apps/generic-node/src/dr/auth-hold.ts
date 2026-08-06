// Post-restore lifecycle auth_hold force.
//
// A production dump may encode lifecycle heads with auth_hold=false (post-release).
// The disaster-recovery policy requires every restored head auth_hold=true before readiness so that
// clearing restore_hold alone cannot open admission (fault injection case 9).
//
// Heads/events are linked by a composite FK that includes auth_hold, and
// reporting_guard_lifecycle_head_update rejects silent head/event drift. The
// legitimate path is therefore:
//   1. append an AUTH_HOLD_SET lifecycle event (schema CHECKs + deferred assert)
//   2. advance the head via reporting_advance_lifecycle_head
// Already-held heads are skipped (idempotent).
//
// The stock reporting DDL shipped a broken reporting_validate_lifecycle_deferred
// (CASE that cross-evaluates NEW fields). Dumps of pre-0001 DBs carry that body; restore
// heals it in-session before AUTH_HOLD_SET so force commits on the real stock DDL.

import { createHash, randomUUID } from "node:crypto";
import type { Client } from "pg";

import { withConnectedPgClient } from "./hold-db-orchestration.js";
import { forceRestoreHoldOnClient } from "./restore-hold.js";

export interface ForceAuthHoldResult {
  readonly applied: boolean;
  /** Number of heads that received a new AUTH_HOLD_SET (already-held skipped). */
  readonly headsForced: number;
  /** Distinct (node_id, implementer_id) pairs forced. */
  readonly headKeys: readonly { readonly nodeId: string; readonly implementerId: string }[];
}

export interface DualGateForceResult {
  readonly restoreHold: { readonly applied: boolean; readonly nodeIds: readonly string[] };
  readonly authHold: ForceAuthHoldResult;
}

const LIFECYCLE_HEADS_EXISTS_SQL = `
  SELECT 1
    FROM information_schema.tables
   WHERE table_schema = 'public'
     AND table_name = 'reporting_key_lifecycle_heads'
   LIMIT 1
`;

const ADVANCE_FN_EXISTS_SQL = `
  SELECT 1
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'public'
     AND p.proname = 'reporting_advance_lifecycle_head'
   LIMIT 1
`;

const DEFERRED_FN_EXISTS_SQL = `
  SELECT 1
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'public'
     AND p.proname = 'reporting_validate_lifecycle_deferred'
   LIMIT 1
`;

const OPEN_HEADS_SQL = `
  SELECT h.node_id::text AS node_id,
         h.implementer_id::text AS implementer_id,
         h.epoch::text AS epoch,
         h.current_key_id::text AS current_key_id,
         h.prior_key_id::text AS prior_key_id,
         h.overlap_expires_at,
         h.lifecycle_event_id::text AS lifecycle_event_id,
         e.event_hash::text AS previous_event_hash
    FROM reporting_key_lifecycle_heads h
    JOIN reporting_key_lifecycle_events e
      ON e.id = h.lifecycle_event_id
   WHERE h.auth_hold = false
     AND h.epoch > 0
     AND h.lifecycle_event_id IS NOT NULL
`;

/**
 * IF/ELSIF rewrite of the stock reporting-DDL reporting_validate_lifecycle_deferred.
 * Exported so unit tests pin the shape (no CASE NEW cross-field refs).
 */
export const HEAL_LIFECYCLE_DEFERRED_VALIDATOR_SQL = `
CREATE OR REPLACE FUNCTION reporting_validate_lifecycle_deferred()
RETURNS trigger LANGUAGE plpgsql
AS $$
DECLARE
  event_id uuid;
BEGIN
  IF TG_TABLE_NAME = 'reporting_key_lifecycle_events' THEN
    event_id := NEW.id;
  ELSIF TG_TABLE_NAME = 'reporting_key_state_transitions' THEN
    event_id := NEW.lifecycle_event_id;
  ELSIF TG_TABLE_NAME = 'reporting_key_lifecycle_states' THEN
    event_id := NEW.lifecycle_event_id;
  ELSIF TG_TABLE_NAME = 'reporting_key_lifecycle_heads' THEN
    event_id := NEW.lifecycle_event_id;
  ELSE
    event_id := NULL;
  END IF;
  IF event_id IS NOT NULL THEN
    PERFORM reporting_assert_lifecycle_event(event_id);
  END IF;
  RETURN NULL;
END
$$;
`.trim();

/** Fixed-length padded base64url signature placeholder (domain shape only; not verified). */
function dummySignature(): string {
  // 86 base64url chars + "==" → 88, matching padded_base64url_signature domain.
  return `${"A".repeat(86)}==`;
}

function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/**
 * SQL shape exported for unit tests: proves the force path inserts AUTH_HOLD_SET
 * with auth_hold=true and advances the head (never a bare head UPDATE alone).
 */
export function buildForceAuthHoldSetStatements(input: {
  readonly nodeId: string;
  readonly implementerId: string;
  readonly priorEpoch: bigint;
  readonly previousEventId: string;
  readonly previousEventHash: string;
  readonly currentKeyId: string | null;
  readonly priorKeyId: string | null;
  readonly overlapExpiresAt: string | null;
  readonly now: Date;
  readonly eventId?: string;
  readonly nonceRowId?: string;
  readonly nonceValue?: string;
  readonly eventHash?: string;
  readonly nonceBurnSequence?: bigint;
}): {
  readonly nonceSql: string;
  readonly eventSql: string;
  readonly advanceSql: string;
  readonly params: {
    readonly eventId: string;
    readonly nonceRowId: string;
    readonly nonceValue: string;
    readonly eventHash: string;
    readonly epoch: string;
    readonly evidenceText: string;
    readonly evidenceSha256: string;
    readonly bodySha256: string;
    readonly preimageSha256: string;
    readonly nowIso: string;
    readonly expiresIso: string;
    readonly nonceBurnSequence: string;
  };
} {
  const eventId = input.eventId ?? randomUUID();
  const nonceRowId = input.nonceRowId ?? randomUUID();
  const nonceValue = input.nonceValue ?? randomUUID();
  const epoch = (input.priorEpoch + 1n).toString();
  const nowIso = input.now.toISOString();
  const expiresIso = new Date(input.now.getTime() + 30_000).toISOString();
  const evidenceText = `zp-gn-restore-auth-hold-v1\n${input.nodeId}\n${input.implementerId}\n${epoch}\n${nowIso}`;
  const evidenceSha256 = sha256Hex(evidenceText);
  const eventHash =
    input.eventHash ??
    sha256Hex(`AUTH_HOLD_SET|${eventId}|${input.previousEventHash}|${evidenceSha256}`);
  const bodySha256 = sha256Hex(evidenceText);
  const preimageSha256 = bodySha256;
  const nonceBurnSequence = (input.nonceBurnSequence ?? 1n).toString();

  // nonce_purpose must be zp-report-request-v1 for AUTH_HOLD_SET (event CHECK).
  const nonceSql = `
    INSERT INTO reporting_request_nonces (
      id, node_id, implementer_id, nonce, purpose,
      route_id, request_class, reporting_key_id,
      lifecycle_epoch, nonce_burn_sequence,
      request_preimage_text, request_preimage_sha256, request_signature,
      method, raw_target, body_sha256,
      issued_at, expires_at, received_at, consumed_at,
      retention_class
    ) VALUES (
      $1::uuid, $2::uuid, $3::uuid, $4::uuid, 'zp-report-request-v1',
      'restore_auth_hold', 'READ', $5::uuid,
      $6::bigint, $7::bigint,
      $8, $9::text, $10,
      'POST', '/internal/restore-auth-hold', $11::text,
      $12::timestamptz, $13::timestamptz, $12::timestamptz, $12::timestamptz,
      'READ_NO_PRUNE_UNTIL_SAFETY_FREEZE'
    )
  `;

  const eventSql = `
    INSERT INTO reporting_key_lifecycle_events (
      id, node_id, implementer_id, epoch, event_type,
      current_key_id, prior_key_id, overlap_expires_at, auth_hold,
      successor_registered_at, nonce_evidence_id, nonce_purpose,
      enrolment_evidence_id, public_evidence_text, public_evidence_sha256,
      previous_event_id, previous_epoch, previous_event_hash,
      event_hash, committed_at
    ) VALUES (
      $1::uuid, $2::uuid, $3::uuid, $4::bigint, 'AUTH_HOLD_SET',
      $5::uuid, $6::uuid, $7::timestamptz, true,
      NULL, $8::uuid, 'zp-report-request-v1',
      NULL, $9, $10::text,
      $11::uuid, $12::bigint, $13::text,
      $14::text, $15::timestamptz
    )
  `;

  const advanceSql = `SELECT reporting_advance_lifecycle_head($1::uuid)`;

  return {
    nonceSql,
    eventSql,
    advanceSql,
    params: {
      eventId,
      nonceRowId,
      nonceValue,
      eventHash,
      epoch,
      evidenceText,
      evidenceSha256,
      bodySha256,
      preimageSha256,
      nowIso,
      expiresIso,
      nonceBurnSequence,
    },
  };
}

/**
 * Heal the stock deferred validator so AUTH_HOLD_SET can COMMIT. Idempotent
 * CREATE OR REPLACE; no-ops when the function is absent (min-schema / drill DBs).
 */
export async function healLifecycleDeferredValidator(
  client: Pick<Client, "query">,
): Promise<boolean> {
  const exists = await client.query(DEFERRED_FN_EXISTS_SQL);
  if (exists.rowCount === 0) {
    return false;
  }
  await client.query(HEAL_LIFECYCLE_DEFERRED_VALIDATOR_SQL);
  return true;
}

async function forceAuthHoldOnClient(
  client: Pick<Client, "query">,
  options: { readonly now?: Date } = {},
): Promise<ForceAuthHoldResult> {
  const headsExist = await client.query(LIFECYCLE_HEADS_EXISTS_SQL);
  if (headsExist.rowCount === 0) {
    return { applied: false, headsForced: 0, headKeys: [] };
  }

  const advanceExists = await client.query(ADVANCE_FN_EXISTS_SQL);
  if (advanceExists.rowCount === 0) {
    throw new Error(
      "reporting_key_lifecycle_heads exists but reporting_advance_lifecycle_head is missing; refuse restore auth_hold force",
    );
  }

  // Production dumps may carry the stock CASE-based deferred body. Heal before
  // any AUTH_HOLD_SET so COMMIT does not abort on NEW field type-check.
  await healLifecycleDeferredValidator(client);

  const now = options.now ?? new Date();
  const open = await client.query<{
    node_id: string;
    implementer_id: string;
    epoch: string;
    current_key_id: string | null;
    prior_key_id: string | null;
    overlap_expires_at: Date | string | null;
    lifecycle_event_id: string;
    previous_event_hash: string;
  }>(OPEN_HEADS_SQL);

  if (open.rowCount === 0) {
    // Table present; nothing to force (all held or empty) — still "applied".
    return { applied: true, headsForced: 0, headKeys: [] };
  }

  const headKeys: { nodeId: string; implementerId: string }[] = [];
  for (const row of open.rows) {
    // AUTH_HOLD_SET requires a non-null reporting_key_id on the nonce
    // (zp-report-request-v1 CHECK). Heads with auth_hold=false must carry a
    // current_key_id per heads CHECK; refuse if the dump is inconsistent.
    if (row.current_key_id === null) {
      throw new Error(
        `lifecycle head (${row.node_id},${row.implementer_id}) has auth_hold=false but null current_key_id`,
      );
    }

    // Allocate a fresh burn sequence above the node high-water.
    const seqRes = await client.query<{ next: string }>(
      `
      SELECT COALESCE(MAX(nonce_burn_sequence), 0) + 1 AS next
        FROM reporting_request_nonces
       WHERE node_id = $1::uuid
      `,
      [row.node_id],
    );
    const nextSeq = BigInt(seqRes.rows[0]?.next ?? "1");

    // Keep the burn counter consistent when the table is present.
    await client.query(
      `
      INSERT INTO reporting_nonce_burn_counters (node_id, next_burn_sequence)
      VALUES ($1::uuid, $2::bigint)
      ON CONFLICT (node_id) DO UPDATE
        SET next_burn_sequence = GREATEST(
          reporting_nonce_burn_counters.next_burn_sequence,
          EXCLUDED.next_burn_sequence
        )
      `,
      [row.node_id, (nextSeq + 1n).toString()],
    );

    const overlap =
      row.overlap_expires_at === null || row.overlap_expires_at === undefined
        ? null
        : row.overlap_expires_at instanceof Date
          ? row.overlap_expires_at.toISOString()
          : String(row.overlap_expires_at);

    const built = buildForceAuthHoldSetStatements({
      nodeId: row.node_id,
      implementerId: row.implementer_id,
      priorEpoch: BigInt(row.epoch),
      previousEventId: row.lifecycle_event_id,
      previousEventHash: row.previous_event_hash,
      currentKeyId: row.current_key_id,
      priorKeyId: row.prior_key_id,
      overlapExpiresAt: overlap,
      now,
      nonceBurnSequence: nextSeq,
    });
    const p = built.params;
    const sig = dummySignature();

    await client.query(built.nonceSql, [
      p.nonceRowId,
      row.node_id,
      row.implementer_id,
      p.nonceValue,
      row.current_key_id,
      p.epoch,
      p.nonceBurnSequence,
      p.evidenceText,
      p.preimageSha256,
      sig,
      p.bodySha256,
      p.nowIso,
      p.expiresIso,
    ]);

    await client.query(built.eventSql, [
      p.eventId,
      row.node_id,
      row.implementer_id,
      p.epoch,
      row.current_key_id,
      row.prior_key_id,
      overlap,
      p.nonceRowId,
      p.evidenceText,
      p.evidenceSha256,
      row.lifecycle_event_id,
      row.epoch,
      row.previous_event_hash,
      p.eventHash,
      p.nowIso,
    ]);

    await client.query(built.advanceSql, [p.eventId]);

    headKeys.push({ nodeId: row.node_id, implementerId: row.implementer_id });
  }

  return { applied: true, headsForced: headKeys.length, headKeys };
}

/**
 * After a successful psql apply, force auth_hold=true on every restored lifecycle
 * head that is currently false by appending AUTH_HOLD_SET + advancing the head.
 * No-ops when the lifecycle-heads table is absent — e.g. drill DBs without the reporting schema.
 * Fail-closed: any error while the table/path exists propagates to the caller.
 * Fail-closed if heads exist but reporting_advance_lifecycle_head is missing.
 */
export async function applyForceAuthHoldAfterRestore(
  databaseUrl: string,
  options: { readonly now?: Date } = {},
): Promise<ForceAuthHoldResult> {
  return withConnectedPgClient(databaseUrl, async (client) => {
    await client.query("BEGIN");
    try {
      const result = await forceAuthHoldOnClient(client, options);
      await client.query("COMMIT");
      return result;
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    }
  });
}

/**
 * The post-restore dual gate in one transaction: restore_hold force + auth_hold force.
 * Either both commit or neither does — avoids D1-held / D2-open partial state
 * when AUTH_HOLD_SET would otherwise fail after restore_hold already committed.
 */
export async function applyDualGateForceAfterRestore(
  databaseUrl: string,
  options: { readonly nodeId?: string; readonly now?: Date } = {},
): Promise<DualGateForceResult> {
  return withConnectedPgClient(databaseUrl, async (client) => {
    await client.query("BEGIN");
    try {
      const restoreHold = await forceRestoreHoldOnClient(client, options);
      const authHold = await forceAuthHoldOnClient(client, options);
      await client.query("COMMIT");
      return { restoreHold, authHold };
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    }
  });
}

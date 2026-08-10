// Externally trusted continuity markers for reporting restore-hold release.
// Markers live OUTSIDE the node database and are emitted only after a successful backup.

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import { withConnectedPgClient, type HoldDbClient } from "./hold-db-orchestration.js";

export const CONTINUITY_MARKER_FORMAT = "zp-gn-continuity-markers-v1" as const;

export interface ContinuityMarkers {
  readonly format: typeof CONTINUITY_MARKER_FORMAT;
  readonly trustedSourceId: string;
  readonly trustedSourceObservedAt: string;
  readonly lifecycleEpoch: string;
  readonly nonceBurnHighWater: string;
  readonly terminalEventHash: string;
  readonly provenance: "successful_scheduled_backup";
  readonly backupArtifactSha256: string;
  readonly backupOutputPath: string;
  readonly note?: string;
}

export interface LocalContinuitySnapshot {
  readonly lifecycleEpoch: bigint;
  readonly nonceBurnHighWater: bigint;
  readonly terminalEventHash: string;
}

export type MarkerLoadResult =
  | { readonly ok: true; readonly markers: ContinuityMarkers }
  | { readonly ok: false; readonly reason: string };

export type MarkerCompareResult =
  | { readonly equal: true }
  | { readonly equal: false; readonly reason: string };

const SHA256_HEX = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const RFC3339_MS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function parseContinuityMarkers(raw: unknown): MarkerLoadResult {
  if (!isObject(raw)) return { ok: false, reason: "markers_not_an_object" };
  if (raw.format !== CONTINUITY_MARKER_FORMAT) {
    return { ok: false, reason: "markers_unknown_format" };
  }
  if (typeof raw.trustedSourceId !== "string" || raw.trustedSourceId.trim() === "") {
    return { ok: false, reason: "markers_missing_trusted_source_id" };
  }
  if (
    typeof raw.trustedSourceObservedAt !== "string" ||
    !RFC3339_MS.test(raw.trustedSourceObservedAt)
  ) {
    return { ok: false, reason: "markers_bad_observed_at" };
  }
  if (typeof raw.lifecycleEpoch !== "string" || !DECIMAL.test(raw.lifecycleEpoch)) {
    return { ok: false, reason: "markers_bad_lifecycle_epoch" };
  }
  if (typeof raw.nonceBurnHighWater !== "string" || !DECIMAL.test(raw.nonceBurnHighWater)) {
    return { ok: false, reason: "markers_bad_nonce_burn_high_water" };
  }
  if (typeof raw.terminalEventHash !== "string" || !SHA256_HEX.test(raw.terminalEventHash)) {
    return { ok: false, reason: "markers_bad_terminal_event_hash" };
  }
  if (
    raw.provenance !== "successful_scheduled_backup" ||
    typeof raw.backupArtifactSha256 !== "string" ||
    !SHA256_HEX.test(raw.backupArtifactSha256) ||
    typeof raw.backupOutputPath !== "string" ||
    raw.backupOutputPath.trim() === ""
  ) {
    return { ok: false, reason: "markers_not_from_successful_backup" };
  }
  if (raw.note !== undefined && typeof raw.note !== "string") {
    return { ok: false, reason: "markers_bad_note" };
  }
  const markers: ContinuityMarkers = {
    format: CONTINUITY_MARKER_FORMAT,
    trustedSourceId: raw.trustedSourceId,
    trustedSourceObservedAt: raw.trustedSourceObservedAt,
    lifecycleEpoch: raw.lifecycleEpoch,
    nonceBurnHighWater: raw.nonceBurnHighWater,
    terminalEventHash: raw.terminalEventHash,
    provenance: raw.provenance,
    backupArtifactSha256: raw.backupArtifactSha256,
    backupOutputPath: raw.backupOutputPath,
    ...(typeof raw.note === "string" ? { note: raw.note } : {}),
  };
  return { ok: true, markers };
}

export async function loadContinuityMarkers(path: string): Promise<MarkerLoadResult> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch {
    return { ok: false, reason: "markers_source_unreadable" };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    return { ok: false, reason: "markers_json_invalid" };
  }
  return parseContinuityMarkers(parsed);
}

export async function writeContinuityMarkers(
  path: string,
  markers: ContinuityMarkers,
): Promise<void> {
  const checked = parseContinuityMarkers(markers);
  if (!checked.ok) {
    throw new Error(`refusing to write invalid continuity markers: ${checked.reason}`);
  }
  await mkdir(dirname(path), { recursive: true });
  const body = `${JSON.stringify(checked.markers, null, 2)}\n`;
  await writeFile(path, body, { encoding: "utf8", mode: 0o600 });
}

export function compareContinuityMarkers(
  local: LocalContinuitySnapshot,
  trusted: ContinuityMarkers,
): MarkerCompareResult {
  if (!SHA256_HEX.test(local.terminalEventHash)) {
    return { equal: false, reason: "local_event_hash_malformed" };
  }
  if (local.lifecycleEpoch.toString() !== trusted.lifecycleEpoch) {
    return { equal: false, reason: "lifecycle_epoch_mismatch" };
  }
  if (local.nonceBurnHighWater.toString() !== trusted.nonceBurnHighWater) {
    return { equal: false, reason: "nonce_burn_high_water_mismatch" };
  }
  if (local.terminalEventHash !== trusted.terminalEventHash) {
    return { equal: false, reason: "terminal_event_hash_mismatch" };
  }
  return { equal: true };
}

export function hashHoldReleaseEvidence(markers: ContinuityMarkers): string {
  const checked = parseContinuityMarkers(markers);
  if (!checked.ok) {
    throw new Error(`cannot hash invalid markers: ${checked.reason}`);
  }
  const payload = {
    format: checked.markers.format,
    trustedSourceId: checked.markers.trustedSourceId,
    trustedSourceObservedAt: checked.markers.trustedSourceObservedAt,
    lifecycleEpoch: checked.markers.lifecycleEpoch,
    nonceBurnHighWater: checked.markers.nonceBurnHighWater,
    terminalEventHash: checked.markers.terminalEventHash,
    provenance: checked.markers.provenance,
    backupArtifactSha256: checked.markers.backupArtifactSha256,
  };
  return createHash("sha256").update(JSON.stringify(payload), "utf8").digest("hex");
}

/** The sole production constructor: a successful scheduled backup result is mandatory. */
export function buildScheduledBackupMarkers(
  local: LocalContinuitySnapshot,
  input: {
    readonly backupArtifactSha256: string;
    readonly backupOutputPath: string;
    readonly observedAt?: Date;
    readonly note?: string;
  },
): ContinuityMarkers {
  const markers: ContinuityMarkers = {
    format: CONTINUITY_MARKER_FORMAT,
    trustedSourceId: `scheduled-backup:${input.backupArtifactSha256}`,
    trustedSourceObservedAt: (input.observedAt ?? new Date()).toISOString(),
    lifecycleEpoch: local.lifecycleEpoch.toString(),
    nonceBurnHighWater: local.nonceBurnHighWater.toString(),
    terminalEventHash: local.terminalEventHash,
    provenance: "successful_scheduled_backup",
    backupArtifactSha256: input.backupArtifactSha256,
    backupOutputPath: input.backupOutputPath,
    ...(input.note !== undefined ? { note: input.note } : {}),
  };
  const checked = parseContinuityMarkers(markers);
  if (!checked.ok) throw new Error(`cannot build continuity markers: ${checked.reason}`);
  return checked.markers;
}

/**
 * Derive the node-wide continuity point from live rows. After restore the
 * canonical AUTH_HOLD_SET is a local gate event, not part of the restored
 * backup's continuity. Project that head to its predecessor and exclude only
 * the corresponding force nonce. AUTH_HOLD_RELEASED remains part of continuity.
 */
export async function deriveContinuitySnapshotOnClient(
  client: Pick<HoldDbClient, "query">,
  nodeId: string,
): Promise<LocalContinuitySnapshot> {
  const result = await client.query<{
    lifecycle_epoch: string;
    nonce_burn_high_water: string;
    terminal_event_hash: string;
  }>(
    `
    WITH projected_heads AS (
      SELECT CASE WHEN e.event_type = 'AUTH_HOLD_SET' THEN e.previous_epoch ELSE e.epoch END AS epoch,
             CASE WHEN e.event_type = 'AUTH_HOLD_SET' THEN e.previous_event_hash ELSE e.event_hash END AS event_hash,
             CASE WHEN e.event_type = 'AUTH_HOLD_SET' THEN previous.committed_at ELSE e.committed_at END AS committed_at,
             h.implementer_id
        FROM reporting_key_lifecycle_heads h
        JOIN reporting_key_lifecycle_events e ON e.id = h.lifecycle_event_id
        LEFT JOIN reporting_key_lifecycle_events previous ON previous.id = e.previous_event_id
       WHERE h.node_id = $1::uuid
    ), terminal AS (
      SELECT epoch, event_hash
        FROM projected_heads
       WHERE epoch IS NOT NULL AND event_hash IS NOT NULL
       ORDER BY epoch DESC, committed_at DESC, implementer_id DESC
       LIMIT 1
    )
    SELECT terminal.epoch::text AS lifecycle_epoch,
           COALESCE((
             SELECT MAX(nonce_burn_sequence)
               FROM reporting_request_nonces
              WHERE node_id = $1::uuid
                AND route_id IS DISTINCT FROM 'restore_auth_hold'
           ), 0)::text AS nonce_burn_high_water,
           terminal.event_hash::text AS terminal_event_hash
      FROM terminal
    `,
    [nodeId],
  );
  const row = result.rows[0];
  if (row === undefined || !SHA256_HEX.test(row.terminal_event_hash)) {
    throw new Error("continuity_snapshot_unavailable");
  }
  return {
    lifecycleEpoch: BigInt(row.lifecycle_epoch),
    nonceBurnHighWater: BigInt(row.nonce_burn_high_water),
    terminalEventHash: row.terminal_event_hash,
  };
}

export async function deriveContinuitySnapshot(
  databaseUrl: string,
  nodeId: string,
): Promise<LocalContinuitySnapshot> {
  return withConnectedPgClient(databaseUrl, (client) =>
    deriveContinuitySnapshotOnClient(client, nodeId),
  );
}

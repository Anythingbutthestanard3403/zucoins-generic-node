// Externally trusted continuity markers for reporting restore-hold release.
// Markers live OUTSIDE the node database.

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

export const CONTINUITY_MARKER_FORMAT = "zp-gn-continuity-markers-v1" as const;

export interface ContinuityMarkers {
  readonly format: typeof CONTINUITY_MARKER_FORMAT;
  readonly trustedSourceId: string;
  readonly trustedSourceObservedAt: string;
  readonly lifecycleEpoch: string;
  readonly nonceBurnHighWater: string;
  readonly terminalEventHash: string;
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
  };
  return createHash("sha256").update(JSON.stringify(payload), "utf8").digest("hex");
}

export function buildMarkersFromLocal(
  local: LocalContinuitySnapshot,
  trustedSourceId: string,
  observedAt: Date = new Date(),
  note?: string,
): ContinuityMarkers {
  const trustedSourceObservedAt = observedAt.toISOString();
  return {
    format: CONTINUITY_MARKER_FORMAT,
    trustedSourceId,
    trustedSourceObservedAt,
    lifecycleEpoch: local.lifecycleEpoch.toString(),
    nonceBurnHighWater: local.nonceBurnHighWater.toString(),
    terminalEventHash: local.terminalEventHash,
    ...(note !== undefined ? { note } : {}),
  };
}

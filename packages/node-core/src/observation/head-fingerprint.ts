// Aggregate observation-head fingerprint: one deterministic SHA-256 over the node's whole
// observed head state — the latest accepted observation per wallet, that wallet's cursor
// position, and its anomaly count (read-stream/cursor model,
// wallet_observation_cursors + observation_anomalies). It is the
// node-wide sibling of the per-wallet A.7 `zp-wallet-head-fingerprint-v1` semantic fingerprint:
// like A.7 it is hashed, never signed, and it deliberately excludes wall-clock fields
// (last_seen_at, created_at), the gateway endpoint, and raw envelope bytes so two nodes that
// observe the same chain state derive an identical digest regardless of when or where they read.
//
// Determinism contract: entries are canonicalized by sorting on wallet_public_key and each
// entry is emitted in a fixed field sequence, so input sequence never affects the digest.
// Wall-clock timestamps are excluded by construction — the same head state always yields the
// same fingerprint, which is what makes cross-time / cross-observer drift comparison sound.

import { createHash } from "node:crypto";

import { parseSha256Hex } from "../protocol/scalars.js";

export const OBSERVATION_HEAD_FINGERPRINT_PURPOSE = "zp-observation-head-fingerprint-v1";

export const OBSERVATION_HEAD_FINGERPRINT_FIELDS = [
  "purpose",
  "canonical_version",
  "wallet_count",
  "wallets",
] as const;

// One wallet's contribution to the head fingerprint: its latest accepted observation's
// semantic fingerprint (the A.7 digest, or null when the latest accepted state is genesis
// or otherwise carries no semantic fingerprint), its cursor position (next_wallet_seq and
// consecutive_repeat_count from wallet_observation_cursors), and the count of anomaly rows
// recorded for this read stream.
export interface WalletHeadStateEntry {
  readonly walletPublicKey: string;
  readonly latestSemanticFingerprint: string | null;
  readonly nextWalletSeq: number;
  readonly consecutiveRepeatCount: number;
  readonly anomalyCount: number;
}

export interface ObservationHeadState {
  readonly entries: readonly WalletHeadStateEntry[];
}

export type ObservationHeadFingerprintReason =
  | "invalid_public_key"
  | "invalid_semantic_fingerprint"
  | "invalid_next_wallet_seq"
  | "invalid_repeat_count"
  | "invalid_anomaly_count"
  | "duplicate_wallet_key";

export class ObservationHeadFingerprintError extends Error {
  readonly code = "OBSERVATION_HEAD_FINGERPRINT";

  constructor(
    readonly reason: ObservationHeadFingerprintReason,
    readonly detail: string,
  ) {
    super(`observation head fingerprint rejected (${reason}${detail ? `: ${detail}` : ""})`);
    this.name = "ObservationHeadFingerprintError";
  }
}

// A non-negative safe integer; bigint and fractional/NaN values are rejected so the
// canonical JSON can never vary by platform or serialization of an out-of-range number.
function requireNonNegativeInt(value: unknown, reason: ObservationHeadFingerprintReason, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new ObservationHeadFingerprintError(reason, field);
  }
  return value;
}

function canonicalizeEntries(state: ObservationHeadState): readonly WalletHeadStateEntry[] {
  const seen = new Set<string>();
  for (const entry of state.entries) {
    if (typeof entry.walletPublicKey !== "string" || entry.walletPublicKey.length === 0) {
      throw new ObservationHeadFingerprintError("invalid_public_key", "empty");
    }
    if (seen.has(entry.walletPublicKey)) {
      throw new ObservationHeadFingerprintError("duplicate_wallet_key", entry.walletPublicKey);
    }
    seen.add(entry.walletPublicKey);

    if (entry.latestSemanticFingerprint !== null) {
      try {
        parseSha256Hex(entry.latestSemanticFingerprint);
      } catch {
        throw new ObservationHeadFingerprintError(
          "invalid_semantic_fingerprint",
          entry.walletPublicKey,
        );
      }
    }
    requireNonNegativeInt(entry.nextWalletSeq, "invalid_next_wallet_seq", entry.walletPublicKey);
    requireNonNegativeInt(
      entry.consecutiveRepeatCount,
      "invalid_repeat_count",
      entry.walletPublicKey,
    );
    requireNonNegativeInt(entry.anomalyCount, "invalid_anomaly_count", entry.walletPublicKey);
  }

  // Sort on the wallet public key so caller-supplied sequence never affects the digest.
  return [...state.entries].sort((a, b) =>
    a.walletPublicKey < b.walletPublicKey ? -1 : a.walletPublicKey > b.walletPublicKey ? 1 : 0,
  );
}

// Build the exact canonical preimage: the purpose line, a newline, then the payload JSON in
// the frozen field sequence with entries sorted by wallet public key.
export function buildObservationHeadFingerprintPreimage(state: ObservationHeadState): string {
  const wallets = canonicalizeEntries(state).map((entry) => ({
    wallet_public_key: entry.walletPublicKey,
    latest_semantic_fingerprint: entry.latestSemanticFingerprint,
    next_wallet_seq: entry.nextWalletSeq,
    consecutive_repeat_count: entry.consecutiveRepeatCount,
    anomaly_count: entry.anomalyCount,
  }));

  const payload = {
    purpose: OBSERVATION_HEAD_FINGERPRINT_PURPOSE,
    canonical_version: 1,
    wallet_count: wallets.length,
    wallets,
  };
  return `${OBSERVATION_HEAD_FINGERPRINT_PURPOSE}\n${JSON.stringify(payload)}`;
}

export function computeObservationHeadFingerprint(state: ObservationHeadState): string {
  return createHash("sha256")
    .update(buildObservationHeadFingerprintPreimage(state), "utf8")
    .digest("hex");
}

// Drift verdict between two head fingerprints. `equal` means the two snapshots assert the same
// observed head state; `drifted` means at least one wallet's latest observation, cursor, or
// anomaly count differs.
export const HEAD_FINGERPRINT_DRIFT_VERDICTS = ["EQUAL", "DRIFTED"] as const;
export type HeadFingerprintDriftVerdict = (typeof HEAD_FINGERPRINT_DRIFT_VERDICTS)[number];

export function compareObservationHeadFingerprints(
  prior: string,
  current: string,
): HeadFingerprintDriftVerdict {
  return prior === current ? "EQUAL" : "DRIFTED";
}

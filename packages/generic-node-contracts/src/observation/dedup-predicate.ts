import { createHash } from "node:crypto";

import { type AppendOutcome } from "./dedup.contract.ts";

// node:crypto is a pure hash (no keys, no network) and is not a forbidden module specifier
// under the package dependency-boundary gate.
export const rawResponseDigest = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

export const rawResponseOctets = (bytes: Uint8Array): number => bytes.length;

/** Length-guarded exact byte comparison; the authoritative equality check. */
export const rawBytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
};

export interface ConsecutiveCandidate {
  readonly verified: boolean;
  readonly rawResponseSha256: string;
  readonly rawResponseOctets: number;
  readonly rawResponseBytes: Uint8Array;
}

/**
 * The pairwise consecutive-dedup primitive. Given the immediately prior RECORDED observation
 * (or null when the stream has none) and the next capture, decide APPEND vs
 * SUPPRESS_AS_SIGHTING. Suppression requires BOTH sides verified and full digest -> length ->
 * exact-byte equality; a non-verified side or any byte difference always appends. The digest
 * and length are candidate gates only, never a substitute for the exact-byte check, so a
 * digest collision with differing bytes still appends.
 */
export const decideAppend = (
  prior: ConsecutiveCandidate | null,
  next: ConsecutiveCandidate,
): AppendOutcome => {
  if (prior === null) return "APPEND";
  if (!prior.verified || !next.verified) return "APPEND";
  if (prior.rawResponseSha256 !== next.rawResponseSha256) return "APPEND";
  if (prior.rawResponseOctets !== next.rawResponseOctets) return "APPEND";
  if (!rawBytesEqual(prior.rawResponseBytes, next.rawResponseBytes)) return "APPEND";
  return "SUPPRESS_AS_SIGHTING";
};

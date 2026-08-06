// Per-stream serialized capture. A read stream is
// one (observer_id, wallet_public_key) pair. This service assigns each captured
// response a strictly monotonic position (wallet_seq) within its stream, deduplicates
// consecutive byte-identical responses ("insert no row; increment
// consecutive_repeat_count"), and guarantees no gaps in the position sequence.
//
// The raw hash is an index, not equality proof; equality includes a byte comparison
// ("Exact raw-byte equality is only a consecutive dedup key"). A response identical
// to an older non-adjacent response is appended, not deduplicated.

import { sha256Hex } from "./capture.js";

export interface StreamKey {
  readonly observerId: string;
  readonly walletPublicKey: string;
}

export interface CapturedEntry {
  readonly streamKey: StreamKey;
  readonly walletSeq: number;
  readonly rawResponseBytes: Uint8Array;
  readonly rawResponseSha256: string;
  readonly consecutiveRepeatCount: number;
}

export interface CaptureResult {
  readonly appended: boolean;
  readonly entry: CapturedEntry;
}

interface StreamCursor {
  nextSeq: number;
  lastBytes: Uint8Array | null;
  lastSha256: string | null;
  lastEntry: CapturedEntry | null;
}

function streamKeyId(key: StreamKey): string {
  return `${key.observerId}\x00${key.walletPublicKey}`;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export interface StreamCaptureService {
  capture(streamKey: StreamKey, rawResponseBytes: Uint8Array): CaptureResult;
  getCursor(streamKey: StreamKey): { nextSeq: number; lastEntry: CapturedEntry | null } | null;
  getEntries(streamKey: StreamKey): readonly CapturedEntry[];
}

export function createStreamCaptureService(): StreamCaptureService {
  const cursors = new Map<string, StreamCursor>();
  const entries = new Map<string, CapturedEntry[]>();

  function capture(streamKey: StreamKey, rawResponseBytes: Uint8Array): CaptureResult {
    const id = streamKeyId(streamKey);
    const sha256 = sha256Hex(rawResponseBytes);

    let cursor = cursors.get(id);
    if (!cursor) {
      cursor = { nextSeq: 1, lastBytes: null, lastSha256: null, lastEntry: null };
      cursors.set(id, cursor);
      entries.set(id, []);
    }

    // Consecutive dedup — if the immediately prior stored result has
    // identical raw bytes (digest match + byte-length match + exact byte comparison),
    // increment repeat count without appending a new position.
    if (
      cursor.lastBytes !== null &&
      cursor.lastSha256 === sha256 &&
      bytesEqual(cursor.lastBytes, rawResponseBytes)
    ) {
      const repeatedEntry: CapturedEntry = {
        streamKey,
        walletSeq: cursor.lastEntry!.walletSeq,
        rawResponseBytes: cursor.lastBytes,
        rawResponseSha256: cursor.lastSha256,
        consecutiveRepeatCount: cursor.lastEntry!.consecutiveRepeatCount + 1,
      };
      cursor.lastEntry = repeatedEntry;
      const streamEntries = entries.get(id)!;
      streamEntries[streamEntries.length - 1] = repeatedEntry;
      return { appended: false, entry: repeatedEntry };
    }

    // Append with the next per-stream wallet_seq (gap-free, monotonic).
    const entry: CapturedEntry = {
      streamKey,
      walletSeq: cursor.nextSeq,
      rawResponseBytes,
      rawResponseSha256: sha256,
      consecutiveRepeatCount: 0,
    };

    cursor.nextSeq += 1;
    cursor.lastBytes = rawResponseBytes;
    cursor.lastSha256 = sha256;
    cursor.lastEntry = entry;
    entries.get(id)!.push(entry);

    return { appended: true, entry };
  }

  function getCursor(
    streamKey: StreamKey,
  ): { nextSeq: number; lastEntry: CapturedEntry | null } | null {
    const cursor = cursors.get(streamKeyId(streamKey));
    if (!cursor) return null;
    return { nextSeq: cursor.nextSeq, lastEntry: cursor.lastEntry };
  }

  function getEntries(streamKey: StreamKey): readonly CapturedEntry[] {
    return entries.get(streamKeyId(streamKey)) ?? [];
  }

  return { capture, getCursor, getEntries };
}

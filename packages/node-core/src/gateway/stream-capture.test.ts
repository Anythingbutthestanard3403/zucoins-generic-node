import { describe, expect, it } from "vitest";

import { sha256Hex } from "./capture.js";
import {
  createStreamCaptureService,
  type StreamKey,
} from "./stream-capture.js";

const STREAM_A: StreamKey = { observerId: "obs-1", walletPublicKey: "wallet-alpha" };
const STREAM_B: StreamKey = { observerId: "obs-1", walletPublicKey: "wallet-beta" };
const STREAM_C: StreamKey = { observerId: "obs-2", walletPublicKey: "wallet-alpha" };

const BYTES_A = Uint8Array.from([123, 34, 115, 116, 97, 116, 117, 115, 34, 125]);
const BYTES_B = Uint8Array.from([123, 34, 111, 116, 104, 101, 114, 34, 125]);
const BYTES_C = Uint8Array.from([91, 93]);

describe("per-stream serialized capture — monotonic position and gap-free sequence", () => {
  it("assigns wallet_seq starting at 1 and incrementing monotonically per stream", () => {
    const svc = createStreamCaptureService();
    const r1 = svc.capture(STREAM_A, BYTES_A);
    const r2 = svc.capture(STREAM_A, BYTES_B);
    const r3 = svc.capture(STREAM_A, BYTES_C);

    expect(r1.entry.walletSeq).toBe(1);
    expect(r2.entry.walletSeq).toBe(2);
    expect(r3.entry.walletSeq).toBe(3);
    expect(r1.appended).toBe(true);
    expect(r2.appended).toBe(true);
    expect(r3.appended).toBe(true);
  });

  it("maintains independent sequences per stream (different wallet_public_key)", () => {
    const svc = createStreamCaptureService();
    svc.capture(STREAM_A, BYTES_A);
    svc.capture(STREAM_A, BYTES_B);
    const rb = svc.capture(STREAM_B, BYTES_C);

    expect(rb.entry.walletSeq).toBe(1);
    expect(svc.getCursor(STREAM_A)!.nextSeq).toBe(3);
    expect(svc.getCursor(STREAM_B)!.nextSeq).toBe(2);
  });

  it("maintains independent sequences per stream (different observer_id)", () => {
    const svc = createStreamCaptureService();
    svc.capture(STREAM_A, BYTES_A);
    const rc = svc.capture(STREAM_C, BYTES_A);

    expect(rc.entry.walletSeq).toBe(1);
    expect(rc.appended).toBe(true);
  });

  it("guarantees no gaps: entries are contiguous 1..N", () => {
    const svc = createStreamCaptureService();
    for (let i = 0; i < 10; i++) {
      svc.capture(STREAM_A, Uint8Array.from([i]));
    }
    const entries = svc.getEntries(STREAM_A);
    expect(entries.length).toBe(10);
    for (let i = 0; i < entries.length; i++) {
      expect(entries[i]!.walletSeq).toBe(i + 1);
    }
  });
});

describe("consecutive dedup — byte-identical responses", () => {
  it("does not append a new row for consecutive byte-identical responses", () => {
    const svc = createStreamCaptureService();
    const r1 = svc.capture(STREAM_A, BYTES_A);
    const r2 = svc.capture(STREAM_A, BYTES_A);

    expect(r1.appended).toBe(true);
    expect(r2.appended).toBe(false);
    expect(r2.entry.walletSeq).toBe(1);
    expect(r2.entry.consecutiveRepeatCount).toBe(1);
    expect(svc.getEntries(STREAM_A).length).toBe(1);
  });

  it("increments consecutive_repeat_count on each repeat", () => {
    const svc = createStreamCaptureService();
    svc.capture(STREAM_A, BYTES_A);
    svc.capture(STREAM_A, BYTES_A);
    const r3 = svc.capture(STREAM_A, BYTES_A);

    expect(r3.entry.consecutiveRepeatCount).toBe(2);
    expect(svc.getEntries(STREAM_A).length).toBe(1);
  });

  it("appends after a different response breaks the consecutive run", () => {
    const svc = createStreamCaptureService();
    svc.capture(STREAM_A, BYTES_A);
    svc.capture(STREAM_A, BYTES_A);
    const r3 = svc.capture(STREAM_A, BYTES_B);

    expect(r3.appended).toBe(true);
    expect(r3.entry.walletSeq).toBe(2);
    expect(r3.entry.consecutiveRepeatCount).toBe(0);
  });

  it("a response identical to a non-adjacent older response IS appended (not consecutive)", () => {
    const svc = createStreamCaptureService();
    svc.capture(STREAM_A, BYTES_A);
    svc.capture(STREAM_A, BYTES_B);
    const r3 = svc.capture(STREAM_A, BYTES_A);

    expect(r3.appended).toBe(true);
    expect(r3.entry.walletSeq).toBe(3);
  });

  it("same sha256 but different byte length is not deduped (hash is index, not proof)", () => {
    const svc = createStreamCaptureService();
    const original = Uint8Array.from([1, 2, 3]);
    const sameHashDifferentLength = Uint8Array.from([1, 2, 3, 4]);
    svc.capture(STREAM_A, original);
    const r2 = svc.capture(STREAM_A, sameHashDifferentLength);

    expect(r2.appended).toBe(true);
    expect(r2.entry.walletSeq).toBe(2);
  });
});

describe("idempotency — same response yields same result", () => {
  it("capturing the same bytes on the same stream at the same position is deterministic", () => {
    const svc1 = createStreamCaptureService();
    const svc2 = createStreamCaptureService();

    const r1 = svc1.capture(STREAM_A, BYTES_A);
    const r2 = svc2.capture(STREAM_A, BYTES_A);

    expect(r1.entry.walletSeq).toBe(r2.entry.walletSeq);
    expect(r1.entry.rawResponseSha256).toBe(r2.entry.rawResponseSha256);
    expect(r1.appended).toBe(r2.appended);
  });

  it("replay of an identical sequence produces identical entries", () => {
    const sequence = [BYTES_A, BYTES_A, BYTES_B, BYTES_C, BYTES_C, BYTES_A];
    const svc1 = createStreamCaptureService();
    const svc2 = createStreamCaptureService();

    for (const bytes of sequence) {
      svc1.capture(STREAM_A, bytes);
      svc2.capture(STREAM_A, bytes);
    }

    const e1 = svc1.getEntries(STREAM_A);
    const e2 = svc2.getEntries(STREAM_A);
    expect(e1.length).toBe(e2.length);
    for (let i = 0; i < e1.length; i++) {
      expect(e1[i]!.walletSeq).toBe(e2[i]!.walletSeq);
      expect(e1[i]!.rawResponseSha256).toBe(e2[i]!.rawResponseSha256);
      expect(e1[i]!.consecutiveRepeatCount).toBe(e2[i]!.consecutiveRepeatCount);
    }
  });
});

describe("raw body hash storage", () => {
  it("stores the SHA-256 of the raw response bytes with each entry", () => {
    const svc = createStreamCaptureService();
    const result = svc.capture(STREAM_A, BYTES_A);

    expect(result.entry.rawResponseSha256).toBe(sha256Hex(BYTES_A));
    expect(result.entry.rawResponseSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("preserves the exact raw bytes in the entry", () => {
    const svc = createStreamCaptureService();
    const result = svc.capture(STREAM_A, BYTES_A);
    expect(result.entry.rawResponseBytes).toBe(BYTES_A);
  });
});

describe("cursor state", () => {
  it("returns null for an unknown stream", () => {
    const svc = createStreamCaptureService();
    expect(svc.getCursor(STREAM_A)).toBeNull();
  });

  it("tracks lastEntry through dedup", () => {
    const svc = createStreamCaptureService();
    svc.capture(STREAM_A, BYTES_A);
    svc.capture(STREAM_A, BYTES_A);
    const cursor = svc.getCursor(STREAM_A)!;

    expect(cursor.nextSeq).toBe(2);
    expect(cursor.lastEntry!.consecutiveRepeatCount).toBe(1);
    expect(cursor.lastEntry!.walletSeq).toBe(1);
  });

  it("only one capture per stream position — wallet_seq is unique per stream", () => {
    const svc = createStreamCaptureService();
    svc.capture(STREAM_A, BYTES_A);
    svc.capture(STREAM_A, BYTES_B);
    svc.capture(STREAM_A, BYTES_C);

    const entries = svc.getEntries(STREAM_A);
    const seqs = entries.map((e) => e.walletSeq);
    expect(new Set(seqs).size).toBe(seqs.length);
  });
});

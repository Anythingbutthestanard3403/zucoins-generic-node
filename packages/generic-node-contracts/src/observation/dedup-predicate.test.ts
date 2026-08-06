import { describe, expect, it } from "vitest";

import { assertFieldOrder } from "../testkit/freeze.ts";
import {
  APPEND_OUTCOMES,
  CONSECUTIVE_DEDUP_KEY,
  DIGEST_ROLE,
  RETENTION_RULE,
  SUPPRESSION_PRECONDITIONS,
} from "./dedup.contract.ts";
import {
  rawResponseDigest,
  rawResponseOctets,
  rawBytesEqual,
  decideAppend,
  type ConsecutiveCandidate,
} from "./dedup-predicate.ts";

const candidate = (bytes: Uint8Array, verified: boolean): ConsecutiveCandidate => ({
  verified,
  rawResponseSha256: rawResponseDigest(bytes),
  rawResponseOctets: rawResponseOctets(bytes),
  rawResponseBytes: bytes,
});

describe("dedup + retention facts are frozen (byte-dedup slice; observation-dedup decision)", () => {
  it("consecutive-dedup key, digest role, and decision vocabulary", () => {
    expect(CONSECUTIVE_DEDUP_KEY).toBe("EXACT_RAW_BYTE_EQUALITY");
    expect(DIGEST_ROLE).toBe("CANDIDATE_INDEX_NOT_EQUALITY_AUTHORITY");
    assertFieldOrder(APPEND_OUTCOMES, ["APPEND", "SUPPRESS_AS_SIGHTING"]);
  });

  it("suppression preconditions sequence", () => {
    assertFieldOrder(SUPPRESSION_PRECONDITIONS, [
      "prior recorded row exists",
      "prior recorded row was verified",
      "next capture is verified",
      "equal raw_response_sha256",
      "equal raw_response octet length",
      "exact raw-byte equality",
    ]);
  });

  it("retention rule facts", () => {
    expect(RETENTION_RULE).toEqual({
      append_only: true,
      anomalies_always_append: true,
      global_deduplication: false,
      recurrence_of_older_state_retained: true,
      raw_bytes_storage: "BYTEA_NEVER_JSONB",
      raw_bytes_never_reserialized: true,
    });
  });
});

describe("digest and byte helpers (the observation dedup freeze)", () => {
  it("rawResponseDigest matches known SHA-256 vectors", () => {
    expect(rawResponseDigest(new Uint8Array())).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    expect(rawResponseDigest(new Uint8Array([0x61, 0x62, 0x63]))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("rawBytesEqual is length-guarded and exact", () => {
    expect(rawBytesEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
    expect(rawBytesEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
    expect(rawBytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
  });
});

describe("decideAppend pairwise primitive (the observation dedup freeze)", () => {
  const A = new Uint8Array([10, 20, 30]);
  const B = new Uint8Array([10, 20, 31]);

  it("suppresses a byte-identical verified consecutive repeat", () => {
    expect(decideAppend(candidate(A, true), candidate(A, true))).toBe("SUPPRESS_AS_SIGHTING");
  });

  it("appends when there is no prior recorded row", () => {
    expect(decideAppend(null, candidate(A, true))).toBe("APPEND");
  });

  it("appends when either side is not verified", () => {
    expect(decideAppend(candidate(A, false), candidate(A, true))).toBe("APPEND");
    expect(decideAppend(candidate(A, true), candidate(A, false))).toBe("APPEND");
  });

  it("appends a byte-different verified response", () => {
    expect(decideAppend(candidate(A, true), candidate(B, true))).toBe("APPEND");
  });

  it("appends on a digest collision with differing bytes (exact bytes are authority)", () => {
    const prior: ConsecutiveCandidate = {
      verified: true,
      rawResponseSha256: "collision",
      rawResponseOctets: A.length,
      rawResponseBytes: A,
    };
    const next: ConsecutiveCandidate = {
      verified: true,
      rawResponseSha256: "collision",
      rawResponseOctets: B.length,
      rawResponseBytes: B,
    };
    expect(decideAppend(prior, next)).toBe("APPEND");
  });
});

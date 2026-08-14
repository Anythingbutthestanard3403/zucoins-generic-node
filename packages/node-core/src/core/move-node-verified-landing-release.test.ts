// ZTR-1304 — NODE_VERIFIED move landing release helper (unit, no sockets).

import { describe, expect, it } from "vitest";

import {
  computeNodeVerifiedMoveLandingReleaseDigest,
  releaseNodeVerifiedMoveLeasesOnLanding,
} from "./move-node-verified-landing-release.js";

const OP = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SRC = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const DST = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const GROUP = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const MEM_S = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const SRC_TERM = "22222222-2222-4222-8222-222222222222";
const DST_TERM = "33333333-3333-4333-8333-333333333333";

describe("computeNodeVerifiedMoveLandingReleaseDigest", () => {
  it("is byte-stable and hex-64", () => {
    const fields = {
      operationId: OP,
      walletId: SRC,
      membershipId: MEM_S,
      leaseGroupId: GROUP,
      leaseEpoch: 1n,
      sourceTerminalObservationId: SRC_TERM,
      destinationTerminalObservationId: DST_TERM,
    };
    const a = computeNodeVerifiedMoveLandingReleaseDigest(fields);
    const b = computeNodeVerifiedMoveLandingReleaseDigest(fields);
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("changes when a bound field changes", () => {
    const base = {
      operationId: OP,
      walletId: SRC,
      membershipId: MEM_S,
      leaseGroupId: GROUP,
      leaseEpoch: 1n,
      sourceTerminalObservationId: SRC_TERM,
      destinationTerminalObservationId: DST_TERM,
    };
    const a = computeNodeVerifiedMoveLandingReleaseDigest(base);
    const b = computeNodeVerifiedMoveLandingReleaseDigest({
      ...base,
      destinationTerminalObservationId: "44444444-4444-4444-8444-444444444444",
    });
    expect(a).not.toBe(b);
  });
});

describe("releaseNodeVerifiedMoveLeasesOnLanding", () => {
  it("skips INDEPENDENT without reading active leases", async () => {
    const calls: string[] = [];
    const tx = {
      query: async <R>(text: string, _params?: readonly unknown[]) => {
        calls.push(text);
        if (text.includes("verification_mode")) {
          return {
            rows: [
              {
                verification_mode: "INDEPENDENT",
                source_wallet_id: SRC,
                destination_wallet_id: DST,
              },
            ] as R[],
            rowCount: 1,
          };
        }
        throw new Error(`unexpected query after INDEPENDENT skip: ${text.slice(0, 60)}`);
      },
    };
    const result = await releaseNodeVerifiedMoveLeasesOnLanding(tx, {
      operationId: OP,
      sourceTerminalObservationId: SRC_TERM,
      destinationTerminalObservationId: DST_TERM,
    });
    expect(result).toEqual({ kind: "SKIPPED_INDEPENDENT" });
    expect(calls).toHaveLength(1);
  });

  it("skips when operation row is missing", async () => {
    const tx = {
      query: async <R>(_text: string) => ({ rows: [] as R[], rowCount: 0 }),
    };
    const result = await releaseNodeVerifiedMoveLeasesOnLanding(tx, {
      operationId: OP,
      sourceTerminalObservationId: SRC_TERM,
      destinationTerminalObservationId: DST_TERM,
    });
    expect(result).toEqual({ kind: "SKIPPED_INDEPENDENT" });
  });

  it("returns SKIPPED_NO_LEASES when NODE_VERIFIED but no MOVE_* active rows", async () => {
    const tx = {
      query: async <R>(text: string) => {
        if (text.includes("verification_mode")) {
          return {
            rows: [
              {
                verification_mode: "NODE_VERIFIED",
                source_wallet_id: SRC,
                destination_wallet_id: DST,
              },
            ] as R[],
            rowCount: 1,
          };
        }
        if (text.includes("wallet_active_leases")) {
          return { rows: [] as R[], rowCount: 0 };
        }
        throw new Error(`unexpected: ${text.slice(0, 60)}`);
      },
    };
    const result = await releaseNodeVerifiedMoveLeasesOnLanding(tx, {
      operationId: OP,
      sourceTerminalObservationId: SRC_TERM,
      destinationTerminalObservationId: DST_TERM,
    });
    expect(result).toEqual({ kind: "SKIPPED_NO_LEASES" });
  });
});

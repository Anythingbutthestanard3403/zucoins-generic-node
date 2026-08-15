// Pure release-predicate and frozen-contract parity tests.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { RECEIVE_QUEUE_MAX_WAIT_MS as CONTRACT_QUEUE_MAX_WAIT_MS } from "../../../generic-node-contracts/src/pool-policy/constants.js";
import {
  POST_EXPIRY_RECONCILING as CONTRACT_POST_EXPIRY_RECONCILING,
} from "../../../generic-node-contracts/src/receive-expiry/lifecycle.js";
import {
  SAFE_TERMINAL_RELEASE_STATUS as CONTRACT_SAFE_TERMINAL_RELEASE_STATUS,
} from "../../../generic-node-contracts/src/receive-expiry/consumer.js";

import {
  LOAD_EXPIRED_RECEIVE_CANDIDATES,
  POST_EXPIRY_RECONCILING,
  RECEIVE_EXPIRY_RELEASE_STATEMENTS,
  RECEIVE_QUEUE_MAX_WAIT_MS,
  RECEIVE_RELEASE_PREDICATE_CAUSES,
  SAFE_TERMINAL_RELEASE_STATUS,
  allReceiveReleasePredicatesHold,
  buildReceiveExpiryAttentionDetail,
  failedReceiveReleasePredicates,
  serializeFreshReadOutcome,
  type ReceiveReleasePredicateName,
  type ReceiveReleasePredicates,
} from "./expiry-release.js";

const PREDICATES = [
  ["expiryPlusSafetyMargin", "EXPIRY_PLUS_SAFETY_MARGIN"],
  ["noLandedProof", "NO_LANDED_PROOF"],
  ["freshVerifiedT0Exact", "FRESH_VERIFIED_T0_EXACT"],
  ["noAnomalyLineageOrSubmit", "NO_ANOMALY_LINEAGE_OR_SUBMIT"],
  ["childAbsentOrSafeTerminal", "CHILD_ABSENT_OR_SAFE_TERMINAL"],
  ["preCodeFormationProvenSafe", "PRE_CODE_FORMATION_PROVEN_SAFE"],
] as const satisfies readonly [
  keyof ReceiveReleasePredicates,
  ReceiveReleasePredicateName,
][];

function vector(mask: number): ReceiveReleasePredicates {
  return Object.fromEntries(
    PREDICATES.map(([key], bit) => [key, (mask & (1 << bit)) !== 0]),
  ) as unknown as ReceiveReleasePredicates;
}

describe("receive expiry/release frozen constants", () => {
  it("matches the package-private pool and attention hold contract sources", () => {
    expect(RECEIVE_QUEUE_MAX_WAIT_MS).toBe(CONTRACT_QUEUE_MAX_WAIT_MS);
    expect(POST_EXPIRY_RECONCILING).toBe(CONTRACT_POST_EXPIRY_RECONCILING);
    expect(SAFE_TERMINAL_RELEASE_STATUS).toBe(
      CONTRACT_SAFE_TERMINAL_RELEASE_STATUS,
    );
  });
});

describe("buildReceiveExpiryAttentionDetail (ZTR-1279)", () => {
  it("names each failed predicate with a human cause and the fresh-read outcome", () => {
    const detail = buildReceiveExpiryAttentionDetail(
      ["FRESH_VERIFIED_T0_EXACT", "NO_LANDED_PROOF"],
      { kind: "exact_repeat", observationId: "obs-1" },
      "obs-1",
    );
    const parsed = JSON.parse(detail) as {
      failed_predicates: string[];
      predicate_causes: { predicate: string; cause: string }[];
      fresh_read: { kind: string; summary: string };
    };
    expect(parsed.failed_predicates).toEqual([
      "FRESH_VERIFIED_T0_EXACT",
      "NO_LANDED_PROOF",
    ]);
    expect(parsed.predicate_causes).toHaveLength(2);
    const freshCause = parsed.predicate_causes.find(
      (c) => c.predicate === "FRESH_VERIFIED_T0_EXACT",
    );
    expect(freshCause?.cause).toMatch(/exact repeat/i);
    expect(freshCause?.cause).toContain("obs-1");
    expect(parsed.fresh_read.kind).toBe("exact-repeat");
    expect(parsed.fresh_read.summary).toBe("exact-repeat:obs-1");
  });

  it("covers every release predicate with a frozen cause string", () => {
    for (const [, name] of PREDICATES) {
      expect(RECEIVE_RELEASE_PREDICATE_CAUSES[name].length).toBeGreaterThan(10);
    }
  });

  it("serializeFreshReadOutcome is stable for worker log lines", () => {
    expect(serializeFreshReadOutcome({ kind: "skipped", reason: "wallet_row_undefined" })).toBe(
      "skipped:wallet_row_undefined",
    );
    expect(serializeFreshReadOutcome({ kind: "failed", reason: "gateway down" })).toBe(
      "failed:gateway down",
    );
    expect(
      serializeFreshReadOutcome({
        kind: "appended",
        observationId: "o1",
        relationship: "SUCCESSOR",
      }),
    ).toBe("appended:SUCCESSOR:o1");
  });
});

describe("release predicate mutation matrix", () => {
  it.each(Array.from({ length: 64 }, (_, mask) => mask))(
    "admits only the all-true vector (mask=%i)",
    (mask) => {
      const predicates = vector(mask);
      const expectedFailed = PREDICATES.filter(
        ([key]) => !predicates[key],
      ).map(([, name]) => name);

      expect(failedReceiveReleasePredicates(predicates)).toEqual(expectedFailed);
      expect(allReceiveReleasePredicatesHold(predicates)).toBe(mask === 63);
    },
  );

  it("keeps landing/candidate/submit checks inside the expiry CAS", () => {
    expect(RECEIVE_EXPIRY_RELEASE_STATEMENTS.CAS_TO_EXPIRED).toMatch(
      /NOT EXISTS .*operation_transactions/i,
    );
    expect(RECEIVE_EXPIRY_RELEASE_STATEMENTS.CAS_TO_EXPIRED).toMatch(
      /NOT EXISTS .*gateway_submit_attempts/i,
    );
    expect(RECEIVE_EXPIRY_RELEASE_STATEMENTS.CAS_TO_EXPIRED).toMatch(
      /NOT EXISTS .*receive_landing_proofs/i,
    );
    expect(RECEIVE_EXPIRY_RELEASE_STATEMENTS.CAS_TO_EXPIRED).toContain(
      "terminal_at = COALESCE(terminal_at, now())",
    );
  });

  it("does not infer walletless expiry from the nullable operation projection", () => {
    expect(RECEIVE_EXPIRY_RELEASE_STATEMENTS.CAS_UNASSIGNED_TO_EXPIRED).toMatch(
      /NOT EXISTS .*operation_wallets/i,
    );
    expect(RECEIVE_EXPIRY_RELEASE_STATEMENTS.CAS_UNASSIGNED_TO_EXPIRED).toMatch(
      /NOT EXISTS .*wallet_active_leases/i,
    );
    expect(RECEIVE_EXPIRY_RELEASE_STATEMENTS.CAS_UNASSIGNED_TO_EXPIRED).toMatch(
      /NOT EXISTS .*operation_transactions/i,
    );
    expect(RECEIVE_EXPIRY_RELEASE_STATEMENTS.CAS_UNASSIGNED_TO_EXPIRED).toMatch(
      /NOT EXISTS .*gateway_submit_attempts/i,
    );
    expect(RECEIVE_EXPIRY_RELEASE_STATEMENTS.CAS_UNASSIGNED_TO_EXPIRED).toMatch(
      /NOT EXISTS .*receive_landing_proofs/i,
    );
    expect(RECEIVE_EXPIRY_RELEASE_STATEMENTS.CAS_UNASSIGNED_TO_EXPIRED).toContain(
      "terminal_at = COALESCE(terminal_at, now())",
    );
  });

  it("excludes terminalized walletless EXPIRED from the expiry candidate scan (ZTR-1249)", () => {
    expect(LOAD_EXPIRED_RECEIVE_CANDIDATES).toContain("o.status = 'EXPIRED'");
    expect(LOAD_EXPIRED_RECEIVE_CANDIDATES).toContain("o.terminal_at IS NOT NULL");
    expect(LOAD_EXPIRED_RECEIVE_CANDIDATES).toContain("o.receiver_wallet_id IS NULL");
  });

  it("excludes attention-parked receives from the expiry candidate scan (ZTR-1277)", () => {
    expect(LOAD_EXPIRED_RECEIVE_CANDIDATES).toContain("o.attention_required = false");
  });

  it("LOAD_OBSERVATIONS names append-only fresh.observed_at, never cursor last_seen_at (ZTR-1274 r2)", () => {
    const sql = RECEIVE_EXPIRY_RELEASE_STATEMENTS.LOAD_OBSERVATIONS;
    expect(sql).toContain("fresh.observed_at::text AS fresh_observed_at");
    expect(sql).not.toMatch(/wallet_observation_cursors/i);
    expect(sql).not.toMatch(/last_seen_at/i);
    expect(sql).not.toMatch(/suppressedT0SightingIsFresh/i);
  });

  it("expire() stays DB-only: no persist and no FORCE_RELEASE (ZTR-1274 r2)", () => {
    const src = readFileSync(
      resolve(dirname(fileURLToPath(import.meta.url)), "expiry-release.ts"),
      "utf8",
    );
    expect(src).not.toMatch(/\bpersistSqlObservation\s*\(/);
    expect(src).not.toMatch(/\bFORCE_RELEASE\b/);
    expect(src).not.toMatch(/\bappendExactRepeat\b/);
  });
});

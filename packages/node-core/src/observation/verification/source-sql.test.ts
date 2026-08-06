// behavioral tests for the SQL VerificationMaterialTablePort.
//
// This suite asserts:
// - attempt classification never forges LANDED_VERIFIED from attempt_phase /
// settled body alone (landing-path oracle; DurableAttemptRow contract)
// - cross-tenant loadOperation filter
// - path body ordering + move evidence role mapping
// - INDETERMINATE lineage verdict passthrough

import { describe, expect, it } from "vitest";

import {
  classifyAttemptFromLandingFacts,
  createSqlVerificationMaterialTablePort,
  type SqlQueryFn,
} from "./source-sql.js";

const OP = "22222222-2222-4222-8222-222222222222";
const TENANT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OTHER = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const SIG_A = `${"A".repeat(86)}==`;
const SIG_B = `${"B".repeat(86)}==`;
const SHA_A = "a".repeat(64);
const SHA_B = "b".repeat(64);
const PUB_SRC = `${"S".repeat(43)}=`;
const PUB_DST = `${"D".repeat(43)}=`;
const PATH_ID = "66666666-6666-4666-8666-666666666666";
const OBS_T0 = "77777777-7777-4777-8777-777777777777";
const OBS_TERM = "88888888-8888-4888-8888-888888888888";
const OBS_DT0 = "99999999-9999-4999-8999-999999999999";
const OBS_DTERM = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
const WALLET_SRC = "55555555-5555-4555-8555-555555555555";
const TX_SETTLED = `{"inner":{"v":1},"step_1_signature":"${SIG_A}","step_2_signature":"${SIG_A}"}`;
const RAW_B64 = Buffer.from('{"node_observed":true}').toString("base64");

interface Recorded {
  readonly text: string;
  readonly values: readonly unknown[] | undefined;
}

/** Route by distinctive FROM/WHERE fragments; ignore whitespace noise. */
function makeRouter(
  handlers: ReadonlyArray<{
    readonly match: (sql: string, params: readonly unknown[] | undefined) => boolean;
    readonly rows: ReadonlyArray<Record<string, unknown>>;
  }>,
): { readonly calls: Recorded[]; readonly query: SqlQueryFn } {
  const calls: Recorded[] = [];
  const query: SqlQueryFn = async (text, params) => {
    calls.push({ text, values: params });
    const hit = handlers.find((h) => h.match(text, params));
    if (hit === undefined) {
      throw new Error(`unhandled SQL in test fixture:\n${text}\nparams=${JSON.stringify(params)}`);
    }
    return hit.rows;
  };
  return { calls, query };
}

const includesAll =
  (...needles: string[]) =>
  (sql: string): boolean =>
    needles.every((n) => sql.includes(n));

describe("classifyAttemptFromLandingFacts", () => {
  it("returns LANDED_VERIFIED only for LANDED_EXACT / LANDED_COMPLETE_PATH proofs", () => {
    expect(
      classifyAttemptFromLandingFacts({
        landing_proof_verdict: "LANDED_EXACT",
        step_1_signature: SIG_A,
      }),
    ).toBe("LANDED_VERIFIED");
    expect(
      classifyAttemptFromLandingFacts({
        landing_proof_verdict: "LANDED_COMPLETE_PATH",
        step_1_signature: SIG_A,
      }),
    ).toBe("LANDED_VERIFIED");
  });

  it("never forges LANDED_VERIFIED from settled body / missing landing proof", () => {
    // Settled body present is represented only by step_1 being set + no proof
    // the classifier has no attempt_phase input by design.
    expect(
      classifyAttemptFromLandingFacts({
        landing_proof_verdict: null,
        step_1_signature: SIG_A,
      }),
    ).toBe("INDETERMINATE");
    expect(
      classifyAttemptFromLandingFacts({
        landing_proof_verdict: "INDETERMINATE",
        step_1_signature: SIG_A,
      }),
    ).toBe("INDETERMINATE");
    expect(
      classifyAttemptFromLandingFacts({
        landing_proof_verdict: "INVARIANT_BREACH",
        step_1_signature: SIG_A,
      }),
    ).toBe("INDETERMINATE");
  });

  it("returns PROVEN_NOT_STARTED when the signer boundary was never crossed", () => {
    expect(
      classifyAttemptFromLandingFacts({
        landing_proof_verdict: null,
        step_1_signature: null,
      }),
    ).toBe("PROVEN_NOT_STARTED");
    expect(
      classifyAttemptFromLandingFacts({
        landing_proof_verdict: null,
        step_1_signature: "",
      }),
    ).toBe("PROVEN_NOT_STARTED");
  });
});

describe("createSqlVerificationMaterialTablePort", () => {
  it("does not wire LANDED_VERIFIED for SETTLED_BODY_PERSISTED without landing proof", async () => {
    const { calls, query } = makeRouter([
      {
        match: includesAll("FROM operation_transactions"),
        rows: [
          {
            attempt_no: 1,
            // Deliberately omit landing_proof_verdict / set null — settled body present.
            landing_proof_verdict: null,
            inner_preimage_text: '{"v":1}',
            inner_sha256: SHA_A,
            step_1_signature: SIG_A,
            step_2_preimage_text: '{"step2":1}',
            step_2_signature: SIG_A,
            completed_transaction_text: TX_SETTLED,
          },
        ],
      },
    ]);
    const port = createSqlVerificationMaterialTablePort(query);
    const attempts = await port.loadAttempts(OP);
    expect(attempts).toHaveLength(1);
    expect(attempts[0]!.classification).toBe("INDETERMINATE");
    expect(attempts[0]!.classification).not.toBe("LANDED_VERIFIED");
    expect(attempts[0]!.settled_transaction_text).toBe(TX_SETTLED);
    // SQL must join landing proofs / never CASE on attempt_phase for classification.
    const attemptsSql = calls[0]!.text;
    expect(attemptsSql).toContain("operation_landing_proofs");
    expect(attemptsSql).not.toMatch(/attempt_phase\s*=\s*'SETTLED_BODY_PERSISTED'/);
    expect(attemptsSql).not.toMatch(/THEN\s+'LANDED_VERIFIED'/);
  });

  it("wires LANDED_VERIFIED only when landing proof verdict is LANDED_*", async () => {
    const { query } = makeRouter([
      {
        match: includesAll("FROM operation_transactions"),
        rows: [
          {
            attempt_no: 1,
            landing_proof_verdict: "LANDED_COMPLETE_PATH",
            inner_preimage_text: '{"v":1}',
            inner_sha256: SHA_A,
            step_1_signature: SIG_A,
            step_2_preimage_text: '{"step2":1}',
            step_2_signature: SIG_A,
            completed_transaction_text: TX_SETTLED,
          },
        ],
      },
    ]);
    const port = createSqlVerificationMaterialTablePort(query);
    const attempts = await port.loadAttempts(OP);
    expect(attempts[0]!.classification).toBe("LANDED_VERIFIED");
  });

  it("filters loadOperation by implementer_id (cross-tenant → null)", async () => {
    const { calls, query } = makeRouter([
      {
        match: (sql, params) =>
          sql.includes("FROM operations") &&
          Array.isArray(params) &&
          params[0] === OP &&
          params[1] === OTHER,
        rows: [], // tenant mismatch → empty
      },
      {
        match: (sql, params) =>
          sql.includes("FROM operations") &&
          Array.isArray(params) &&
          params[0] === OP &&
          params[1] === TENANT,
        rows: [
          {
            id: OP,
            implementer_id: TENANT,
            kind: "MOVE_INTERNAL",
            status: "INTERNAL_MOVE_LANDED",
            verification_material_available_until_ms: 1_700_000_000_000,
            landed_attempt_no: 1,
          },
        ],
      },
    ]);
    const port = createSqlVerificationMaterialTablePort(query);
    expect(await port.loadOperation(OP, OTHER)).toBeNull();
    const ok = await port.loadOperation(OP, TENANT);
    expect(ok).not.toBeNull();
    expect(ok!.implementer_id).toBe(TENANT);
    expect(ok!.landed_attempt_no).toBe(1);
    // Both calls bind implementer_id as $2.
    expect(calls[0]!.values).toEqual([OP, OTHER]);
    expect(calls[1]!.values).toEqual([OP, TENANT]);
    expect(calls[0]!.text).toMatch(/implementer_id/);
  });

  it("loads path bodies in ascending path_index ordering", async () => {
    const { calls, query } = makeRouter([
      {
        match: includesAll("FROM lineage_path_proofs", "operation_landing_proofs"),
        rows: [
          {
            path_id: PATH_ID,
            path_role: "SOURCE",
            wallet_public_key: PUB_SRC,
            verdict: "LANDED_COMPLETE_PATH",
            fresh_head_completed_transaction_sha256: SHA_B,
            expected_step_2_signature: SIG_A,
            fresh_head_step_2_signature: SIG_B,
          },
        ],
      },
      {
        match: includesAll("FROM lineage_path_bodies"),
        rows: [
          {
            path_index: 0,
            step_2_signature: SIG_A,
            p_signature: "",
            completed_transaction_sha256: SHA_A,
            completed_transaction_text: TX_SETTLED,
          },
          {
            path_index: 1,
            step_2_signature: SIG_B,
            p_signature: SIG_A,
            completed_transaction_sha256: SHA_B,
            completed_transaction_text: TX_SETTLED.replace(SIG_A, SIG_B),
          },
        ],
      },
    ]);
    const port = createSqlVerificationMaterialTablePort(query);
    const paths = await port.loadAncestorPaths(OP);
    expect(paths).toHaveLength(1);
    expect(paths[0]!.bodies.map((b) => b.path_index)).toEqual([0, 1]);
    expect(paths[0]!.verdict).toBe("LANDED_COMPLETE_PATH");
    const bodiesSql = calls.find(
      (c) =>
        c.text.includes("FROM lineage_path_bodies") &&
        !c.text.includes("lineage_path_proofs"),
    )!.text;
    expect(bodiesSql).toMatch(/ORDER BY\s+path_index\s+ASC/i); // contract-allow:order:frozen-sql-text
  });

  it("passthrough INDETERMINATE lineage verdict without forging EXPECTED_*", async () => {
    const { query } = makeRouter([
      {
        match: includesAll("FROM lineage_path_proofs"),
        rows: [
          {
            path_id: PATH_ID,
            path_role: "RECEIVER",
            wallet_public_key: PUB_SRC,
            verdict: "INDETERMINATE",
            fresh_head_completed_transaction_sha256: SHA_A,
            expected_step_2_signature: SIG_A,
            fresh_head_step_2_signature: SIG_A,
          },
        ],
      },
      {
        match: includesAll("FROM lineage_path_bodies"),
        rows: [],
      },
    ]);
    const port = createSqlVerificationMaterialTablePort(query);
    const paths = await port.loadAncestorPaths(OP);
    expect(paths).toHaveLength(1);
    expect(paths[0]!.verdict).toBe("INDETERMINATE");
    expect(paths[0]!.bodies).toEqual([]);
  });

  it("maps move_observation_evidence into SOURCE + DESTINATION roles", async () => {
    const obs = (id: string, pub: string, wallet: string | null) => ({
      id,
      wallet_id: wallet,
      wallet_public_key: pub,
      s_signature: SIG_A,
      p_signature: "",
      b_amount: "1.0",
      raw_response_body_base64: RAW_B64,
    });
    const { query } = makeRouter([
      {
        match: includesAll("FROM move_observation_evidence"),
        rows: [
          {
            source_t0: OBS_T0,
            dest_t0: OBS_DT0,
            source_term: OBS_TERM,
            dest_term: OBS_DTERM,
          },
        ],
      },
      {
        match: (sql, params) =>
          sql.includes("FROM gateway_observations") && params?.[0] === OBS_T0,
        rows: [obs(OBS_T0, PUB_SRC, WALLET_SRC)],
      },
      {
        match: (sql, params) =>
          sql.includes("FROM gateway_observations") && params?.[0] === OBS_DT0,
        rows: [obs(OBS_DT0, PUB_DST, null)],
      },
      {
        match: (sql, params) =>
          sql.includes("FROM gateway_observations") && params?.[0] === OBS_TERM,
        rows: [obs(OBS_TERM, PUB_SRC, WALLET_SRC)],
      },
      {
        match: (sql, params) =>
          sql.includes("FROM gateway_observations") && params?.[0] === OBS_DTERM,
        rows: [obs(OBS_DTERM, PUB_DST, null)],
      },
    ]);
    const port = createSqlVerificationMaterialTablePort(query);
    const evidence = await port.loadObservationEvidence(OP, "MOVE_INTERNAL");
    expect(evidence.map((e) => e.evidence_role).sort()).toEqual(["DESTINATION", "SOURCE"]);
    const source = evidence.find((e) => e.evidence_role === "SOURCE")!;
    expect(source.t0.id).toBe(OBS_T0);
    expect(source.terminal!.id).toBe(OBS_TERM);
    expect(source.wallet_id).toBe(WALLET_SRC);
    const dest = evidence.find((e) => e.evidence_role === "DESTINATION")!;
    expect(dest.wallet_id).toBeNull();
    expect(dest.t0.raw_response_body_base64).toBe(RAW_B64);
  });

  it("maps operation_observation_bindings RECEIVER_T0/TERMINAL for non-move kinds", async () => {
    const { query } = makeRouter([
      {
        match: includesAll("FROM operation_observation_bindings"),
        rows: [
          {
            evidence_role: "RECEIVER_T0",
            observation_id: OBS_T0,
            wallet_public_key: PUB_SRC,
          },
          {
            evidence_role: "RECEIVER_TERMINAL",
            observation_id: OBS_TERM,
            wallet_public_key: PUB_SRC,
          },
        ],
      },
      {
        match: (sql, params) =>
          sql.includes("FROM gateway_observations") && params?.[0] === OBS_T0,
        rows: [
          {
            id: OBS_T0,
            wallet_id: WALLET_SRC,
            wallet_public_key: PUB_SRC,
            s_signature: "",
            p_signature: "",
            b_amount: "0",
            raw_response_body_base64: RAW_B64,
          },
        ],
      },
      {
        match: (sql, params) =>
          sql.includes("FROM gateway_observations") && params?.[0] === OBS_TERM,
        rows: [
          {
            id: OBS_TERM,
            wallet_id: WALLET_SRC,
            wallet_public_key: PUB_SRC,
            s_signature: SIG_A,
            p_signature: "",
            b_amount: "5.0",
            raw_response_body_base64: RAW_B64,
          },
        ],
      },
    ]);
    const port = createSqlVerificationMaterialTablePort(query);
    const evidence = await port.loadObservationEvidence(OP, "RECEIVE_EXTERNAL");
    expect(evidence).toHaveLength(1);
    expect(evidence[0]!.evidence_role).toBe("RECEIVER");
    expect(evidence[0]!.terminal!.id).toBe(OBS_TERM);
  });
});

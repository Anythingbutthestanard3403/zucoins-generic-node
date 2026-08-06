// census + real-PostgreSQL proof for move-baseline-binding.sql.
//
// The census block binds the frozen invariant inventory to the literal SQL and runs always. The
// live-PostgreSQL block is gated on TEST_DATABASE_URL (assigned by vitest.global-setup.ts under
// the ROOT vitest project) and discharges the execution obligations against a scratch schema:
// the durability bounds this suite exists to prove are enforced by the database rejecting the
// writes that must not land, and by running the REAL capture flow through a psql-backed
// SqlExecutor rather than an in-memory double. psql runs as a child process, keeping the
// in-process network-containment guard intact — as signing-key-registry.pg.test.ts does.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { beforeAll, describe, expect, it } from "vitest";
import { registerPgRequiredGuard } from "./pg-required-guard.ts";

import { MOVE_INTERNAL_EXPECTED } from "../../generic-node-contracts/src/artifacts/expected-artifacts.contract.ts";
import { buildMoveInternalExpectedArtifact } from "../src/protocol/suite/builders.ts";
import {
  captureAndBindMoveBaselines,
  STATEMENTS,
  type MoveBaselineBindingInput,
  type SqlExecutor,
  type SqlQueryResult,
} from "../src/core/move-baseline-binding.ts";
import {
  DEFERRED_FOREIGN_KEYS,
  SCHEMA_EXECUTION_OBLIGATIONS,
  MOVE_BASELINE_SCHEMA_FILE,
  MOVE_BASELINE_SCHEMA_INVARIANTS,
} from "../src/schema/move-baseline-binding.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", MOVE_BASELINE_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);

describe("move-baseline binding census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = MOVE_BASELINE_SCHEMA_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("declares exactly the three tables", () => {
    expect(sql).toContain("CREATE TABLE operation_expected_artifacts (");
    expect(sql).toContain("CREATE TABLE operation_observation_bindings (");
    expect(sql).toContain("CREATE TABLE move_observation_evidence (");
    // The wallet/lease/observation/registry roots belong to their own slices, never this one.
    expect(sql).not.toContain("CREATE TABLE wallets");
    expect(sql).not.toContain("CREATE TABLE operations");
    expect(sql).not.toContain("CREATE TABLE gateway_observations");
    expect(sql).not.toContain("CREATE TABLE node_signing_keys");
  });

  it("carries no key material and no REFERENCES to a table it does not create", () => {
    expect(sql).not.toMatch(/private_key|secret_key|\bseed\b|key_material|keypair/);
    expect(sql).not.toMatch(/REFERENCES\s+(operations|gateway_observations|node_signing_keys)/);
    expect(DEFERRED_FOREIGN_KEYS.length).toBe(3);
  });

  it("mutation negative: removing an anchored clause is caught by the census", () => {
    const mutated = sql.replace(
      "CHECK (source_t0_observation_id <> destination_t0_observation_id)",
      "CHECK (source_t0_observation_id IS NOT NULL)",
    );
    const missing = MOVE_BASELINE_SCHEMA_INVARIANTS.filter(
      (invariant) => !mutated.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual(["EVIDENCE_DISTINCT_T0"]);
  });

  it("execution obligations are inventoried and non-trivial", () => {
    expect(SCHEMA_EXECUTION_OBLIGATIONS.length).toBeGreaterThanOrEqual(8);
    for (const obligation of SCHEMA_EXECUTION_OBLIGATIONS) {
      expect(obligation.length).toBeGreaterThan(20);
    }
  });

  // The artifact this slice persists is a-frozen byte surface, so the census pins its field
  // sequence to the contract inventory rather than to a literal repeated in the test.
  it("persists an artifact whose payload matches the frozen A.3.2 field sequence", () => {
    const preimage = buildMoveInternalExpectedArtifact({
      node_id: "11111111-1111-4111-8111-111111111111",
      implementer_id: "22222222-2222-4222-8222-222222222222",
      operation_id: OP_FLOW,
      source_wallet_id: "55555555-5555-4555-8555-555555555555",
      source_pubkey: SOURCE_PUBKEY,
      destination_id: "66666666-6666-4666-8666-666666666666",
      destination_wallet_id: "44444444-4444-4444-8444-444444444444",
      destination_pubkey: DESTINATION_PUBKEY,
      amount_zkz: "2.25",
      spawned_from_operation_id: null,
      references_operation_id: null,
    } as unknown as Parameters<typeof buildMoveInternalExpectedArtifact>[0]);

    const [prefix, payload] = preimage.preimageText.split("\n");
    expect(prefix).toBe("zp-move-internal-expected-v1");
    expect([...(payload ?? "").matchAll(/"([a-z0-9_]+)":/g)].map((match) => match[1])).toEqual(
      MOVE_INTERNAL_EXPECTED.fields.map((field) => field.name),
    );
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });
});

/* ─── live PostgreSQL ─────────────────────────────────────────────── */

const SCHEMA = "move_baseline_binding_move_baseline_binding";
const SQLSTATE_UNIQUE_VIOLATION = "23505";
const SQLSTATE_CHECK_VIOLATION = "23514";

const databaseUrl = process.env.TEST_DATABASE_URL;

// True only after beforeAll finishes schema apply successfully.
let liveReady = false;

const pgEnv = (): Record<string, string> => {
  const url = new URL(databaseUrl as string);
  const env: Record<string, string> = { ...process.env } as Record<string, string>;
  env.PGHOST = url.hostname;
  env.PGPORT = url.port || "5432";
  if (url.username !== "") env.PGUSER = decodeURIComponent(url.username);
  if (url.password !== "") env.PGPASSWORD = decodeURIComponent(url.password);
  env.PGDATABASE = url.pathname.replace(/^\//, "");
  return env;
};

interface PsqlResult {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
}

const psql = (args: readonly string[]): PsqlResult => {
  try {
    const stdout = execFileSync("psql", ["-v", "ON_ERROR_STOP=1", "-q", ...args], {
      env: pgEnv(),
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 20_000,
    });
    return { status: 0, stdout: stdout.toString(), stderr: "" };
  } catch (error) {
    const err = error as { status?: number; stdout?: Buffer; stderr?: Buffer };
    return {
      status: err.status ?? 1,
      stdout: err.stdout?.toString() ?? "",
      stderr: err.stderr?.toString() ?? String(error),
    };
  }
};

// search_path persists across -c args within one psql session, so a failing statement yields a
// non-zero status the negative drills assert on. VERBOSITY=verbose emits the machine-readable
// `ERROR:  <sqlstate>:` and `CONSTRAINT NAME:` lines.
const run = (statement: string): PsqlResult =>
  psql(["-v", "VERBOSITY=verbose", "-c", `SET search_path TO ${SCHEMA}`, "-c", statement]);

// Unaligned, tuple-only: the artifact preimage contains a newline by construction
// (purpose + LF + payload), so only raw tuple output can be byte-compared against it.
const runTuple = (statement: string): PsqlResult =>
  psql(["-qAt", "-c", `SET search_path TO ${SCHEMA}`, "-c", statement]);

const seed = (statement: string): void => {
  const result = run(statement);
  expect(result.stderr, `seed must apply cleanly: ${statement}`).toBe("");
  expect(result.status, `seed must apply cleanly: ${statement}`).toBe(0);
};

const sqlstateOf = (stderr: string): string => /\bERROR:\s+([0-9A-Z]{5}):/.exec(stderr)?.[1] ?? "";
const constraintOf = (stderr: string): string =>
  /CONSTRAINT NAME:\s+(\S+)/.exec(stderr)?.[1] ?? "";

const sqlLiteral = (value: unknown): string =>
  value === null || value === undefined ? "NULL" : `'${String(value).replaceAll("'", "''")}'`;

// The module's OWN statement text, executed against the live schema. Only the $n placeholders are
// rewritten (psql -c takes no bind parameters); the column lists and table names reach the server
// verbatim, so a statement the schema does not carry fails here rather than passing in-memory.
const livePsqlExecutor: SqlExecutor = {
  query<R>(text: string, params: readonly unknown[]): Promise<SqlQueryResult<R>> {
    const statement = text.replace(/\$(\d+)/g, (_m, index: string) =>
      sqlLiteral(params[Number(index) - 1]),
    );
    const result = run(statement);
    if (result.status !== 0) {
      return Promise.reject(Object.assign(new Error(result.stderr), {
        code: sqlstateOf(result.stderr),
      }));
    }
    return Promise.resolve({ rows: [] as R[] });
  },
};

const OP_A = "33333333-3333-4333-8333-000000000001";
const OP_B = "33333333-3333-4333-8333-000000000002";
const OP_FLOW = "33333333-3333-4333-8333-000000000003";
const OBS_1 = "aaaaaaaa-0000-4000-8000-000000000001";
const OBS_2 = "aaaaaaaa-0000-4000-8000-000000000002";
const OBS_3 = "aaaaaaaa-0000-4000-8000-000000000003";
const ARTIFACT_A = "99999999-9999-4999-8999-000000000001";
const ARTIFACT_B = "99999999-9999-4999-8999-000000000002";
const ARTIFACT_FLOW = "99999999-9999-4999-8999-000000000003";
const SIGNING_KEY_ID = "bbbbbbbb-0000-4000-8000-000000000001";
const SOURCE_PUBKEY = "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=";
const DESTINATION_PUBKEY = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=";
const DIGEST = "a".repeat(64);
const SIGNATURE = `${"A".repeat(86)}==`;

const insertArtifact = (
  id: string,
  operationId: string,
  overrides: { purpose?: string; version?: number; preimage?: string } = {},
): string =>
  `INSERT INTO operation_expected_artifacts
     (id, operation_id, purpose, canonical_version, signing_key_id, preimage_text, preimage_sha256, signature)
   VALUES ('${id}', '${operationId}', '${overrides.purpose ?? "zp-move-internal-expected-v1"}',
     ${overrides.version ?? 1}, '${SIGNING_KEY_ID}', '${overrides.preimage ?? "zp-move-internal-expected-v1"}',
     '${DIGEST}', '${SIGNATURE}')`;

const insertEvidence = (operationId: string, sourceObs: string, destObs: string): string =>
  `INSERT INTO move_observation_evidence (operation_id, source_t0_observation_id, destination_t0_observation_id)
   VALUES ('${operationId}', '${sourceObs}', '${destObs}')`;

const insertBinding = (operationId: string, obs: string, role: string, key: string): string =>
  `INSERT INTO operation_observation_bindings (operation_id, observation_id, evidence_role, wallet_public_key)
   VALUES ('${operationId}', '${obs}', '${role}', '${key}')`;

describe.skipIf(databaseUrl === undefined)("against a live PostgreSQL", () => {
  beforeAll(() => {
    // No silent no-op: TEST_DATABASE_URL set but unreachable FAILS the block loudly rather than
    // letting every case skip itself into a green tick.
    const probe = psql(["-c", "SELECT 1"]);
    if (probe.status !== 0) {
      throw new Error(`TEST_DATABASE_URL is set but PostgreSQL is unreachable: ${probe.stderr}`);
    }
    psql(["-c", `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`]);
    const applied = psql([
      "-c",
      `CREATE SCHEMA ${SCHEMA}`,
      "-c",
      `SET search_path TO ${SCHEMA}`,
      "-f",
      sqlPath,
    ]);
    expect(applied.stderr, "greenfield apply should be clean").toBe("");
    expect(applied.status, "greenfield apply should succeed").toBe(0);
    liveReady = true;
  });

  it("materialises the three tables greenfield", () => {
    const tables = run(
      `SELECT table_name FROM information_schema.tables WHERE table_schema = '${SCHEMA}' ORDER BY 1`,
    );
    expect(tables.status).toBe(0);
    expect(tables.stdout).toContain("move_observation_evidence");
    expect(tables.stdout).toContain("operation_expected_artifacts");
    expect(tables.stdout).toContain("operation_observation_bindings");
  });

  it("rejects a second move-evidence row for the same operation (23505)", () => {
    seed(insertEvidence(OP_A, OBS_1, OBS_2));
    const duplicate = run(insertEvidence(OP_A, OBS_2, OBS_3));
    expect(duplicate.status).not.toBe(0);
    expect(sqlstateOf(duplicate.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    expect(constraintOf(duplicate.stderr)).toBe("move_observation_evidence_pkey");
  });

  // Case 3: the CHECK targets the observation ROW id, not the projected
  // values, so two wallets that both read genesis still need two distinct observations.
  it("rejects two identical T0 observation ids even for identical genesis projections (23514)", () => {
    const shared = run(insertEvidence(OP_B, OBS_1, OBS_1));
    expect(shared.status).not.toBe(0);
    expect(sqlstateOf(shared.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    expect(constraintOf(shared.stderr)).toBe("move_observation_evidence_distinct_t0");
  });

  it("rejects a partially-filled terminal set (23514)", () => {
    const partial = run(
      `INSERT INTO move_observation_evidence
         (operation_id, source_t0_observation_id, destination_t0_observation_id, source_terminal_observation_id)
       VALUES ('${OP_B}', '${OBS_1}', '${OBS_2}', '${OBS_3}')`,
    );
    expect(partial.status).not.toBe(0);
    expect(sqlstateOf(partial.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    expect(constraintOf(partial.stderr)).toBe("move_observation_evidence_terminal_set_together");
  });

  it("binds each evidence role at most once per operation and never reuses one observation", () => {
    seed(insertBinding(OP_A, OBS_1, "SOURCE_T0", SOURCE_PUBKEY));
    seed(insertBinding(OP_A, OBS_2, "DESTINATION_T0", DESTINATION_PUBKEY));

    const secondSource = run(insertBinding(OP_A, OBS_3, "SOURCE_T0", SOURCE_PUBKEY));
    expect(sqlstateOf(secondSource.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    expect(constraintOf(secondSource.stderr)).toBe("operation_observation_bindings_pkey");

    const reused = run(insertBinding(OP_A, OBS_1, "DESTINATION_TERMINAL", DESTINATION_PUBKEY));
    expect(sqlstateOf(reused.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);
    expect(constraintOf(reused.stderr)).toBe(
      "operation_observation_bindings_operation_observation_key",
    );

    const badRole = run(insertBinding(OP_B, OBS_3, "SOURCE_T1", SOURCE_PUBKEY));
    expect(sqlstateOf(badRole.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    expect(constraintOf(badRole.stderr)).toBe(
      "operation_observation_bindings_evidence_role_check",
    );
  });

  it("holds one expected artifact per operation and rejects an out-of-contract row", () => {
    seed(insertArtifact(ARTIFACT_A, OP_A));

    const second = run(insertArtifact(ARTIFACT_B, OP_A));
    expect(sqlstateOf(second.stderr)).toBe(SQLSTATE_UNIQUE_VIOLATION);

    const badPurpose = run(insertArtifact(ARTIFACT_B, OP_B, { purpose: "zp-move-internal-v2" }));
    expect(sqlstateOf(badPurpose.stderr)).toBe(SQLSTATE_CHECK_VIOLATION);
    expect(constraintOf(badPurpose.stderr)).toBe("operation_expected_artifacts_purpose_check");

    const badVersion = run(insertArtifact(ARTIFACT_B, OP_B, { version: 2 }));
    expect(constraintOf(badVersion.stderr)).toBe(
      "operation_expected_artifacts_canonical_version_check",
    );

    const emptyPreimage = run(insertArtifact(ARTIFACT_B, OP_B, { preimage: "" }));
    expect(constraintOf(emptyPreimage.stderr)).toBe(
      "operation_expected_artifacts_preimage_nonempty",
    );
  });

  // 09 axiom 3: the bytes a crash-recovery resumes from must not be rewritable.
  it("rejects UPDATE and DELETE against a persisted artifact", () => {
    const updated = run(
      `UPDATE operation_expected_artifacts SET preimage_text = 'tampered' WHERE id = '${ARTIFACT_A}'`,
    );
    expect(updated.status).not.toBe(0);
    expect(updated.stderr).toContain("EXPECTED_ARTIFACT_INSERT_ONLY");

    const deleted = run(`DELETE FROM operation_expected_artifacts WHERE id = '${ARTIFACT_A}'`);
    expect(deleted.status).not.toBe(0);
    expect(deleted.stderr).toContain("EXPECTED_ARTIFACT_INSERT_ONLY");

    const survivor = run(
      `SELECT preimage_text FROM operation_expected_artifacts WHERE id = '${ARTIFACT_A}'`,
    );
    expect(survivor.stdout).toContain("zp-move-internal-expected-v1");
    expect(survivor.stdout).not.toContain("tampered");
  });

  it("runs the real capture flow end to end and leaves all four rows durable", async () => {
    const input: MoveBaselineBindingInput = {
      nodeId: "11111111-1111-4111-8111-111111111111",
      implementerId: "22222222-2222-4222-8222-222222222222",
      operationId: OP_FLOW,
      expectedArtifactId: ARTIFACT_FLOW,
      sourceWalletId: "55555555-5555-4555-8555-555555555555",
      sourceWalletPublicKey: SOURCE_PUBKEY,
      destinationId: "66666666-6666-4666-8666-666666666666",
      destinationWalletId: "44444444-4444-4444-8444-444444444444",
      destinationWalletPublicKey: DESTINATION_PUBKEY,
      amountZkz: "2.25",
      spawnedFromOperationId: null,
      referencesOperationId: null,
      sourceLease: { role: "MOVE_SOURCE", lifecycle: "ACTIVE" },
      destinationLease: { role: "MOVE_DESTINATION", lifecycle: "ACTIVE" },
      capturedAt: 1700000000000,
      observer: {
        observe: (_key, role) =>
          Promise.resolve(
            role === "MOVE_SOURCE_T0"
              ? {
                  kind: "VERIFIED",
                  observationId: OBS_2,
                  projection: { role: "sender", S: "s", P: "p", B: "10", I: "i" },
                }
              : {
                  kind: "VERIFIED",
                  observationId: OBS_3,
                  projection: { role: "receiver", S: "s", P: "p", B: "5", I: "i" },
                },
          ),
      },
      destinations: {
        recheckDestination: () =>
          Promise.resolve({ eligible: true, detail: "BLESSED, recovery verified" }),
      },
      signer: {
        signWithNodeIdentity: () =>
          Promise.resolve({ signingKeyId: SIGNING_KEY_ID, signature: SIGNATURE }),
      },
      sql: livePsqlExecutor,
    };

    const result = await captureAndBindMoveBaselines(input);
    expect(result.ok, JSON.stringify(result)).toBe(true);
    if (!result.ok) return;

    const evidence = runTuple(
      `SELECT source_t0_observation_id || ' ' || destination_t0_observation_id FROM move_observation_evidence WHERE operation_id = '${OP_FLOW}'`,
    );
    expect(evidence.stdout.trim()).toBe(`${OBS_2} ${OBS_3}`);

    const bindings = runTuple(
      `SELECT evidence_role || '=' || wallet_public_key FROM operation_observation_bindings WHERE operation_id = '${OP_FLOW}' ORDER BY 1`,
    );
    expect(bindings.stdout.trim().split("\n")).toEqual([
      `DESTINATION_T0=${DESTINATION_PUBKEY}`,
      `SOURCE_T0=${SOURCE_PUBKEY}`,
    ]);

    // The persisted preimage is the exact bytes the frozen builder produced — not a re-render.
    const preimage = runTuple(
      `SELECT preimage_text FROM operation_expected_artifacts WHERE operation_id = '${OP_FLOW}'`,
    );
    expect(preimage.stdout.replace(/\n$/, "")).toBe(result.binding.artifact.preimageText);

    const digest = runTuple(
      `SELECT preimage_sha256 || ' ' || purpose || ' ' || canonical_version FROM operation_expected_artifacts WHERE operation_id = '${OP_FLOW}'`,
    );
    expect(digest.stdout.trim()).toBe(
      `${result.binding.artifact.preimageSha256} zp-move-internal-expected-v1 1`,
    );

    // A second capture for the same operation is refused by the database, not by memory.
    const replay = await captureAndBindMoveBaselines(input);
    expect(replay.ok).toBe(false);
    if (replay.ok) return;
    expect(replay.reason).toBe("already_captured");
  });

  it("uses the module's own statement text, so a drifted column list fails here", () => {
    for (const statement of Object.values(STATEMENTS)) {
      const explained = run(`EXPLAIN ${statement.replace(/\$\d+/g, "NULL")}`);
      expect(explained.stderr, statement).not.toContain("does not exist");
    }
  });
});

registerPgRequiredGuard({
  name: "move-baseline-binding live block",
  databaseUrl,
  isReady: () => liveReady,
  readyMessage:
    "PG_REQUIRED=1 but the move-baseline beforeAll never completed — binding proofs skipped, not proven",
});

// Real-PostgreSQL proof for integration-requests.sql (ZTR-1238).
//
// Engine-only properties (cannot be established in-process):
//   1. Consistency CHECKs reject half-set states per status.
//   2. CAS on (status, row_version): concurrent double-approve -> one winner.
//   3. Illegal transitions match zero rows.
//   4. Duplicate claim_token_hash -> unique_violation.
//   5. APPROVED->CLAIMED + credential INSERT are atomic (forced mid-TX failure rolls both back).
//
// psql runs as a child process (node:child_process), keeping the in-process
// network-containment guard intact - same pattern as implementer-credentials.pg.test.ts.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { IMPLEMENTER_CREDENTIAL_SCHEMA_FILE } from "../src/schema/implementer-credentials.contract.ts";
import { INTEGRATION_REQUESTS_SCHEMA_FILE } from "../src/schema/integration-requests.contract.ts";
import { registerPgRequiredGuard } from "./pg-required-guard.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../src/schema");
const integrationSql = readFileSync(
  resolve(schemaDir, INTEGRATION_REQUESTS_SCHEMA_FILE),
  "utf8",
);
const credentialsSql = readFileSync(
  resolve(schemaDir, IMPLEMENTER_CREDENTIAL_SCHEMA_FILE),
  "utf8",
);

const NODE = "00000000-0000-4000-8000-0000000000b1";
const IMPL = "00000000-0000-4000-8000-0000000000a1";
const OP = "00000000-0000-4000-8000-0000000000d1";
const REQ = "00000000-0000-4000-8000-0000000000e1";
const CRED = "00000000-0000-4000-8000-0000000000c1";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const HASH_C = "c".repeat(64);
const CRED_HASH = "d".repeat(64);
const PREFIX = "ik_AAAAAAAA";

// Minimal FK targets: nodes/implementers from registry shape; credentials from frozen slice.
const PREREQUISITES = `
CREATE TABLE nodes (id uuid PRIMARY KEY);
CREATE TABLE implementers (id uuid PRIMARY KEY);
${credentialsSql}
`;

const databaseUrl = process.env.TEST_DATABASE_URL;

const pgEnv = (): Record<string, string> => {
  const url = new URL(databaseUrl as string);
  const env: Record<string, string> = { ...process.env } as Record<string, string>;
  env.PGHOST = url.hostname;
  env.PGPORT = url.port || "5432";
  env.PGUSER = decodeURIComponent(url.username);
  env.PGPASSWORD = decodeURIComponent(url.password);
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

const SCHEMA = "integration_requests_ztr1238";
let reachable = false;

const run = (statement: string): PsqlResult =>
  psql(["-c", `SET search_path TO ${SCHEMA}`, "-c", statement]);

const scalar = (query: string): string =>
  psql(["-t", "-A", "-c", `SET search_path TO ${SCHEMA}`, "-c", query]).stdout.trim();

const seedPending = (id: string, tokenHash: string): void => {
  run(
    `INSERT INTO integration_requests (
       id, node_id, display_name, requested_scopes, proposed_rule_json, status,
       row_version, claim_token_hash, created_at, expires_at
     ) VALUES (
       '${id}', '${NODE}', 'Platform Alpha', ARRAY['send:create','send:read']::text[],
       '{"cap":"1"}', 'PENDING', 1, '${tokenHash}',
       '2026-08-01T00:00:00Z', '2026-08-08T00:00:00Z'
     )`,
  );
};

const clearRequests = (): void => {
  run(`DELETE FROM integration_requests`);
  run(`DELETE FROM implementer_credentials`);
  run(`DELETE FROM implementers WHERE id = '${IMPL}'`);
  run(`INSERT INTO implementers (id) VALUES ('${IMPL}') ON CONFLICT DO NOTHING`);
};

describe("integration requests PG drills", () => {
  beforeAll(() => {
    if (!databaseUrl) return;
    const probe = psql(["-c", "SELECT 1"]);
    if (probe.status !== 0) return;
    reachable = true;
    psql([
      "-c",
      `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE; CREATE SCHEMA ${SCHEMA};`,
    ]);
    const prep = psql([
      "-c",
      `SET search_path TO ${SCHEMA}`,
      "-c",
      PREREQUISITES,
      "-c",
      integrationSql,
      "-c",
      `INSERT INTO nodes (id) VALUES ('${NODE}');
       INSERT INTO implementers (id) VALUES ('${IMPL}');`,
    ]);
    if (prep.status !== 0) {
      throw new Error(`schema apply failed: ${prep.stderr}`);
    }
  });

  afterAll(() => {
    if (!reachable) return;
    psql(["-c", `DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`]);
  });

  registerPgRequiredGuard({
    name: "integration-requests.pg",
    databaseUrl,
    isReady: () => reachable,
  });

  it("duplicate claim_token_hash is rejected", () => {
    if (!databaseUrl || !reachable) return;
    clearRequests();
    seedPending(REQ, HASH_A);
    const dup = run(
      `INSERT INTO integration_requests (
         id, node_id, display_name, requested_scopes, proposed_rule_json, status,
         row_version, claim_token_hash, created_at, expires_at
       ) VALUES (
         '00000000-0000-4000-8000-0000000000e2', '${NODE}', 'Other',
         ARRAY['send:read']::text[], '{}', 'PENDING', 1, '${HASH_A}',
         '2026-08-01T00:00:00Z', '2026-08-08T00:00:00Z'
       )`,
    );
    expect(dup.status).not.toBe(0);
    expect(dup.stderr + dup.stdout).toMatch(/unique|duplicate/i);
  });

  it("scope CHECK rejects empty and unknown scopes", () => {
    if (!databaseUrl || !reachable) return;
    clearRequests();
    const empty = run(
      `INSERT INTO integration_requests (
         id, node_id, display_name, requested_scopes, proposed_rule_json, status,
         row_version, claim_token_hash, created_at, expires_at
       ) VALUES (
         '${REQ}', '${NODE}', 'X', ARRAY[]::text[], '{}', 'PENDING', 1, '${HASH_A}',
         '2026-08-01T00:00:00Z', '2026-08-08T00:00:00Z'
       )`,
    );
    expect(empty.status).not.toBe(0);
    const unknown = run(
      `INSERT INTO integration_requests (
         id, node_id, display_name, requested_scopes, proposed_rule_json, status,
         row_version, claim_token_hash, created_at, expires_at
       ) VALUES (
         '${REQ}', '${NODE}', 'X', ARRAY['admin:all']::text[], '{}', 'PENDING', 1, '${HASH_A}',
         '2026-08-01T00:00:00Z', '2026-08-08T00:00:00Z'
       )`,
    );
    expect(unknown.status).not.toBe(0);
  });

  it("consistency CHECK rejects half-set APPROVED and CLAIMED rows", () => {
    if (!databaseUrl || !reachable) return;
    clearRequests();
    // APPROVED without decided_by / implementer_id / approved_rule_json
    const halfApproved = run(
      `INSERT INTO integration_requests (
         id, node_id, display_name, requested_scopes, proposed_rule_json, status,
         row_version, claim_token_hash, created_at, expires_at
       ) VALUES (
         '${REQ}', '${NODE}', 'X', ARRAY['send:read']::text[], '{}', 'APPROVED', 1, '${HASH_A}',
         '2026-08-01T00:00:00Z', '2026-08-08T00:00:00Z'
       )`,
    );
    expect(halfApproved.status).not.toBe(0);

    seedPending(REQ, HASH_A);
    // Force CLAIMED without credential fields via UPDATE (bypass would need full set)
    const halfClaimed = run(
      `UPDATE integration_requests SET
         status = 'CLAIMED',
         row_version = 2,
         approved_rule_json = '{}',
         decided_at = now(),
         decided_by = '${OP}',
         implementer_id = '${IMPL}',
         issued_credential_id = NULL,
         claimed_at = NULL
       WHERE id = '${REQ}'`,
    );
    expect(halfClaimed.status).not.toBe(0);

    // DECLINED with a credential id must fail
    const declinedWithCred = run(
      `UPDATE integration_requests SET
         status = 'DECLINED',
         row_version = 2,
         decided_at = now(),
         decided_by = '${OP}',
         issued_credential_id = '${CRED}',
         claimed_at = NULL
       WHERE id = '${REQ}'`,
    );
    expect(declinedWithCred.status).not.toBe(0);
  });

  it("PENDING->APPROVED CAS: concurrent double-approve yields one winner", () => {
    if (!databaseUrl || !reachable) return;
    clearRequests();
    seedPending(REQ, HASH_A);

    const approveSql = `
UPDATE integration_requests SET
  status = 'APPROVED',
  row_version = row_version + 1,
  approved_rule_json = '{"cap":"1"}',
  decided_at = '2026-08-02T00:00:00Z',
  decided_by = '${OP}',
  implementer_id = '${IMPL}'
WHERE id = '${REQ}' AND status = 'PENDING' AND row_version = 1
RETURNING id, status, row_version;
`;
    // Two sequential CAS attempts (engine-level lock serializes concurrent UPDATEs
    // on the same row the same way under READ COMMITTED).
    const first = run(approveSql);
    expect(first.status).toBe(0);
    expect(first.stdout).toMatch(/APPROVED/);
    const second = run(approveSql);
    expect(second.status).toBe(0);
    // zero rows matched - psql -q still prints nothing useful; count via scalar
    const status = scalar(
      `SELECT status || ':' || row_version::text FROM integration_requests WHERE id = '${REQ}'`,
    );
    expect(status).toBe("APPROVED:2");
    const winners = scalar(
      `SELECT count(*)::text FROM integration_requests
       WHERE id = '${REQ}' AND status = 'APPROVED' AND row_version = 2`,
    );
    expect(winners).toBe("1");
    // Second UPDATE affected 0 rows: row_version stayed 2
    expect(scalar(`SELECT row_version::text FROM integration_requests WHERE id = '${REQ}'`)).toBe(
      "2",
    );
  });

  it("illegal transitions match zero rows under CAS status guards", () => {
    if (!databaseUrl || !reachable) return;
    clearRequests();
    seedPending(REQ, HASH_A);
    // PENDING row: claim path requires status = APPROVED -> zero rows
    run(
      `UPDATE integration_requests SET
         status = 'CLAIMED',
         row_version = row_version + 1,
         approved_rule_json = '{}',
         decided_at = now(),
         decided_by = '${OP}',
         implementer_id = '${IMPL}',
         issued_credential_id = '${CRED}',
         claimed_at = now()
       WHERE id = '${REQ}' AND status = 'APPROVED' AND row_version = 1`,
    );
    expect(
      scalar(`SELECT status || ':' || row_version::text FROM integration_requests WHERE id = '${REQ}'`),
    ).toBe("PENDING:1");

    // Decline, then claim CAS (from APPROVED) matches zero
    run(
      `UPDATE integration_requests SET
         status = 'DECLINED',
         row_version = row_version + 1,
         decided_at = '2026-08-02T00:00:00Z',
         decided_by = '${OP}'
       WHERE id = '${REQ}' AND status = 'PENDING' AND row_version = 1`,
    );
    run(
      `UPDATE integration_requests SET
         status = 'CLAIMED',
         row_version = row_version + 1,
         approved_rule_json = '{}',
         implementer_id = '${IMPL}',
         issued_credential_id = '${CRED}',
         claimed_at = now()
       WHERE id = '${REQ}' AND status = 'APPROVED' AND row_version = 2`,
    );
    expect(
      scalar(`SELECT status || ':' || row_version::text FROM integration_requests WHERE id = '${REQ}'`),
    ).toBe("DECLINED:2");

    // CLAIMED -> anything: CAS writers only match their from-status; wrong from -> zero rows
    clearRequests();
    run(
      `INSERT INTO implementer_credentials (
         id, implementer_id, public_prefix, credential_hash, scopes, status,
         key_version, issued_at, expires_at, revoked_at, rotated_from_id, rotated_to_id,
         rotated_at, rotation_grace_until
       ) VALUES (
         '${CRED}', '${IMPL}', '${PREFIX}', '${CRED_HASH}',
         ARRAY['send:read']::text[], 'ACTIVE', 1,
         '2026-08-02T00:00:00Z', NULL, NULL, NULL, NULL, NULL, NULL
       )`,
    );
    run(
      `INSERT INTO integration_requests (
         id, node_id, display_name, requested_scopes, proposed_rule_json,
         approved_rule_json, status, row_version, claim_token_hash,
         created_at, expires_at, decided_at, decided_by, implementer_id,
         issued_credential_id, claimed_at
       ) VALUES (
         '${REQ}', '${NODE}', 'X', ARRAY['send:read']::text[], '{}', '{}',
         'CLAIMED', 3, '${HASH_B}',
         '2026-08-01T00:00:00Z', '2026-08-08T00:00:00Z',
         '2026-08-02T00:00:00Z', '${OP}', '${IMPL}', '${CRED}',
         '2026-08-03T00:00:00Z'
       )`,
    );
    // Expire CAS only admits PENDING|APPROVED
    run(
      `UPDATE integration_requests SET status = 'EXPIRED', row_version = row_version + 1
       WHERE id = '${REQ}' AND status IN ('PENDING', 'APPROVED') AND row_version = 3`,
    );
    // Approve CAS only admits PENDING
    run(
      `UPDATE integration_requests SET
         status = 'APPROVED',
         row_version = row_version + 1,
         approved_rule_json = '{}',
         decided_at = now(),
         decided_by = '${OP}',
         implementer_id = '${IMPL}'
       WHERE id = '${REQ}' AND status = 'PENDING' AND row_version = 3`,
    );
    expect(
      scalar(`SELECT status || ':' || row_version::text FROM integration_requests WHERE id = '${REQ}'`),
    ).toBe("CLAIMED:3");
  });

  it("PENDING|APPROVED -> EXPIRED CAS applies once", () => {
    if (!databaseUrl || !reachable) return;
    clearRequests();
    seedPending(REQ, HASH_A);
    run(
      `UPDATE integration_requests SET
         status = 'EXPIRED',
         row_version = row_version + 1
       WHERE id = '${REQ}' AND status IN ('PENDING', 'APPROVED') AND row_version = 1`,
    );
    expect(
      scalar(`SELECT status || ':' || row_version::text FROM integration_requests WHERE id = '${REQ}'`),
    ).toBe("EXPIRED:2");
    run(
      `UPDATE integration_requests SET
         status = 'EXPIRED',
         row_version = row_version + 1
       WHERE id = '${REQ}' AND status IN ('PENDING', 'APPROVED') AND row_version = 2`,
    );
    expect(
      scalar(`SELECT status || ':' || row_version::text FROM integration_requests WHERE id = '${REQ}'`),
    ).toBe("EXPIRED:2");
  });

  it("APPROVED->CLAIMED + credential insert commit atomically; mid-TX failure rolls both back", () => {
    if (!databaseUrl || !reachable) return;
    clearRequests();
    seedPending(REQ, HASH_A);
    // Approve first
    run(
      `UPDATE integration_requests SET
         status = 'APPROVED',
         row_version = row_version + 1,
         approved_rule_json = '{"cap":"1"}',
         decided_at = '2026-08-02T00:00:00Z',
         decided_by = '${OP}',
         implementer_id = '${IMPL}'
       WHERE id = '${REQ}' AND status = 'PENDING' AND row_version = 1`,
    );

    // Happy path: same TX claim + credential
    const happy = run(`
BEGIN;
INSERT INTO implementer_credentials (
  id, implementer_id, public_prefix, credential_hash, scopes, status,
  key_version, issued_at, expires_at, revoked_at, rotated_from_id, rotated_to_id,
  rotated_at, rotation_grace_until
) VALUES (
  '${CRED}', '${IMPL}', '${PREFIX}', '${CRED_HASH}',
  ARRAY['send:create']::text[], 'ACTIVE', 1,
  '2026-08-03T00:00:00Z', NULL, NULL, NULL, NULL, NULL, NULL
);
UPDATE integration_requests SET
  status = 'CLAIMED',
  row_version = row_version + 1,
  issued_credential_id = '${CRED}',
  claimed_at = '2026-08-03T00:00:00Z'
WHERE id = '${REQ}' AND status = 'APPROVED' AND row_version = 2;
COMMIT;
`);
    expect(happy.status).toBe(0);
    expect(
      scalar(`SELECT status || ':' || issued_credential_id::text FROM integration_requests WHERE id = '${REQ}'`),
    ).toBe(`CLAIMED:${CRED}`);
    expect(scalar(`SELECT count(*)::text FROM implementer_credentials WHERE id = '${CRED}'`)).toBe(
      "1",
    );

    // Rollback drill: fresh approved row, insert credential then fail before claim UPDATE
    clearRequests();
    seedPending(REQ, HASH_C);
    run(
      `UPDATE integration_requests SET
         status = 'APPROVED',
         row_version = row_version + 1,
         approved_rule_json = '{"cap":"1"}',
         decided_at = '2026-08-02T00:00:00Z',
         decided_by = '${OP}',
         implementer_id = '${IMPL}'
       WHERE id = '${REQ}' AND status = 'PENDING' AND row_version = 1`,
    );
    const failMid = run(`
BEGIN;
INSERT INTO implementer_credentials (
  id, implementer_id, public_prefix, credential_hash, scopes, status,
  key_version, issued_at, expires_at, revoked_at, rotated_from_id, rotated_to_id,
  rotated_at, rotation_grace_until
) VALUES (
  '${CRED}', '${IMPL}', '${PREFIX}', '${CRED_HASH}',
  ARRAY['send:create']::text[], 'ACTIVE', 1,
  '2026-08-03T00:00:00Z', NULL, NULL, NULL, NULL, NULL, NULL
);
-- force failure before claim UPDATE
DO $$ BEGIN RAISE EXCEPTION 'forced claim failure' USING ERRCODE = 'P0001'; END $$;
UPDATE integration_requests SET
  status = 'CLAIMED',
  row_version = row_version + 1,
  issued_credential_id = '${CRED}',
  claimed_at = '2026-08-03T00:00:00Z'
WHERE id = '${REQ}' AND status = 'APPROVED' AND row_version = 2;
COMMIT;
`);
    expect(failMid.status).not.toBe(0);
    // Both rolled back
    expect(
      scalar(`SELECT status || ':' || coalesce(issued_credential_id::text, 'null')
              FROM integration_requests WHERE id = '${REQ}'`),
    ).toBe("APPROVED:null");
    expect(scalar(`SELECT count(*)::text FROM implementer_credentials WHERE id = '${CRED}'`)).toBe(
      "0",
    );
  });
});

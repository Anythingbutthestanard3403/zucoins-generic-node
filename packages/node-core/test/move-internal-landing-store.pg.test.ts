// Real-PostgreSQL proof that the MOVE_INTERNAL landing/attention persist is ATOMIC and
// compare-and-swap arbitrated by the database. Governing:
// steps 5-6 (the DB-TX);
// the data model (operations CHECKs), (move_observation_evidence all-or-nothing),
// 3 (node_events); node-core rules (CAS on operation_id + expected state + row_version
// inside ONE transaction); the state/event reference (closed attention_reason),
// (the three MOVE_INTERNAL rows), (event data).
//
// The blocking defect this suite exists to catch is a TORN WRITE: a state change recorded
// without its event, an event appended for a state change that then rolls back, or half of the
// terminal-observation pair attached. An in-memory store cannot prove the cure, because the
// arbiter under test IS the database transaction boundary, so an earlier in-memory scaffold
// was replaced. DDL applied here is the frozen contract text of
// move-baseline-binding.sql (CREATE TABLE move_observation_evidence — sole owner),
// move-observation-evidence.sql (ALTER FKs only), and event-ledger.sql,
// verbatim; the real persistMoveOutcome runs against it.
//
// operations / gateway_observations / wallets are the FK targets no slice in this package
// creates (the documented reconciliation gap, test/migration-integrity.test.ts).
// They are stubbed to the columns this seam touches, and the operations stub carries the four
// data-model CHECKs verbatim — the tables under test are applied from their frozen files, never
// retyped. Enum labels and the wallet_active_leases DDL are read out of the frozen files too,
// so a literal used here that the frozen vocabulary does not contain fails at runtime.
//
// psql runs as a child process (node:child_process), which keeps the in-process
// network-containment guard intact — as submit-decision-claim-store.pg.test.ts already does.

import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  persistMoveOutcome,
  type SignedNodeEvent,
} from "../src/core/move-internal-landing-store.ts";
import type { SqlQueryFn } from "../src/core/sql-query-fn.ts";
import { sha256Hex } from "../src/gateway/capture.ts";
import { mintLandingPathProofFromOracle } from "../src/protocol/reconcile/landing-oracle-mint.fixture.js";
import type { MoveReconcileOutcome } from "../src/protocol/reconcile/move.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaFile = (name: string): string =>
  readFileSync(resolve(here, "../src/schema", name), "utf8");

const baseEnumsSql = schemaFile("base-enums-domains.sql");
const registrySql = schemaFile("node-implementer-registry.sql");
const signingKeysSql = schemaFile("signing-key-registry.sql");
const custodySql = schemaFile("custody-eligibility.sql");
const eventLedgerSql = schemaFile("event-ledger.sql");
const moveBaselineSql = schemaFile("move-baseline-binding.sql");
const moveEvidenceAlterSql = schemaFile("move-observation-evidence.sql");

// Lift a single frozen declaration out of a slice rather than retyping it: the enum labels and
// the lease table this suite depends on then come from the frozen vocabulary itself.
function frozenDeclaration(sql: string, opening: string): string {
  const start = sql.indexOf(opening);
  if (start === -1) throw new Error(`frozen declaration not found: ${opening}`);
  const end = sql.indexOf(";", start);
  if (end === -1) throw new Error(`unterminated frozen declaration: ${opening}`);
  return `${sql.slice(start, end + 1)}\n`;
}

// CREATE TABLE move_observation_evidence is owned by move-baseline-binding.sql.
// Lift only that CREATE — not the whole baseline slice — so this suite does not also
// materialise expected-artifact / observation-binding tables it never touches.
const moveEvidenceCreateSql = frozenDeclaration(
  moveBaselineSql,
  "CREATE TABLE move_observation_evidence (",
);

const operationKindEnum = frozenDeclaration(baseEnumsSql, "CREATE TYPE operation_kind AS ENUM");
const operationStatusEnum = frozenDeclaration(
  baseEnumsSql,
  "CREATE TYPE operation_status AS ENUM",
);
const walletActiveLeasesDdl = frozenDeclaration(custodySql, "CREATE TABLE wallet_active_leases (");
// signing-key-registry.sql re-declares the domain node-implementer-registry.sql already
// declares (each frozen slice is self-contained). Layering them needs the duplicate dropped —
// same treatment as signing-key-registry.pg.test.ts.
const layeredSigningKeysSql = signingKeysSql.replace(
  /CREATE DOMAIN padded_base64url_pubkey AS text[^;]*;/,
  "",
);

// data-model, columns this seam reads or writes, with the four CHECKs that constrain it verbatim.
// Omitted columns (amount, destination, formation/verification state, idempotency) are
// untouched by the landing DB-TX; including them would need six more FK-target stubs and would
// not add a single assertion.
const OPERATIONS_STUB = `CREATE TABLE operations (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  kind operation_kind NOT NULL,
  status operation_status NOT NULL,
  row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0),
  attention_required boolean NOT NULL DEFAULT false,
  attention_reason text,
  attention_detail text,
  source_wallet_id uuid REFERENCES wallets(id),
  verification_material_available_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  terminal_at timestamptz,
  CHECK (
    (kind = 'RECEIVE_EXTERNAL' AND status IN
      ('CREATED','READY','RECEIVE_LANDED','EXPIRED'))
    OR
    (kind = 'MOVE_INTERNAL' AND status IN
      ('CREATED','INTERNAL_MOVE_LANDED','NEEDS_ATTENTION'))
    OR
    (kind = 'SEND_EXTERNAL' AND status IN
      ('CREATED','APPROVED','AWAITING_REDEMPTION','EXTERNAL_SEND_LANDED',
       'REJECTED','NEEDS_ATTENTION'))
  ),
  CHECK (attention_required = (attention_reason IS NOT NULL)),
  CHECK (terminal_at IS NULL OR terminal_at >= created_at)
);`;

const SCHEMA = "move_internal_landing_move_landing";
const UNIQUE_VIOLATION = "23505";
const CHECK_VIOLATION = "23514";

const CREATED_AT = "2026-07-25T00:00:00.000Z";
const OCCURRED_AT = "2026-07-25T01:00:00.000Z";
const PROOF_EXPIRY = "2026-08-24T01:00:00.000Z";

const databaseUrl = process.env.TEST_DATABASE_URL;

const pgEnv = (): NodeJS.ProcessEnv => {
  const url = new URL(databaseUrl as string);
  return {
    ...process.env,
    PGHOST: url.hostname,
    PGPORT: url.port || "5432",
    PGUSER: decodeURIComponent(url.username),
    PGPASSWORD: decodeURIComponent(url.password),
    PGDATABASE: url.pathname.replace(/^\//, ""),
  };
};

interface PsqlResult {
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;
}

// Test-only stand-in for a driver's parameter binding: psql has no wire-protocol parameters, so
// each $n is spliced as a psql variable reference, which psql quotes and escapes. Every
// parameter in the statement under test carries an explicit ::cast, which is what makes that
// substitution faithful. SQL is fed on stdin rather than -c because psql expands variables only
// in lexed input. VERBOSITY=verbose makes it print the SQLSTATE the negative tests assert on.
function psql(
  sql: string,
  values: readonly unknown[] = [],
  tuplesOnly = true,
): Promise<PsqlResult> {
  const args = ["-X", "-q", "-A", "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose"];
  if (tuplesOnly) args.push("-t");
  values.forEach((value, index) => {
    if (value !== null && value !== undefined) {
      args.push("-v", `p${index + 1}=${String(value)}`);
    }
  });
  args.push("-f", "-");
  const bound = sql.replace(/\$(\d+)/g, (_match, position: string) =>
    values[Number(position) - 1] === null || values[Number(position) - 1] === undefined
      ? "NULL"
      : `:'p${position}'`,
  );
  return new Promise((settle, fail) => {
    const child = spawn("psql", args, { env: pgEnv(), stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.on("error", fail);
    child.on("close", (code) => settle({ code: code ?? 1, stdout, stderr }));
    child.stdin.end(`${sql.trimEnd().endsWith(";") ? bound : `${bound};`}\n`);
  });
}

async function psqlOk(sql: string, values: readonly unknown[] = []): Promise<string> {
  const result = await psql(sql, values);
  if (result.code !== 0) throw new Error(result.stderr.trim());
  return result.stdout;
}

const inSchema = (sql: string): string => `SET search_path TO ${SCHEMA};\n${sql}`;

const scalar = async (sql: string): Promise<string> => (await psqlOk(inSchema(sql))).trim();

const errorOf = async (sql: string): Promise<string> => (await psql(inSchema(sql))).stderr;

// The statement under test is a top-level data-modifying CTE, and PostgreSQL rejects those
// anywhere but the top level — so it cannot be wrapped in an aggregating outer query the way
// submit-decision-claim-store.pg.test.ts wraps its statements. Column names come from psql's
// own header line instead (-A without -t), which keeps the statement byte-identical to the one
// the store issues.
const query: SqlQueryFn = async (text, values) => {
  const result = await psql(inSchema(text), values, false);
  if (result.code !== 0) throw new Error(result.stderr.trim());
  const lines = result.stdout.split("\n").filter((line) => line !== "");
  const body = lines.filter((line) => !/^\(\d+ rows?\)$/.test(line));
  const header = body[0]?.split("|") ?? [];
  return body.slice(1).map((line) => {
    const cells = line.split("|");
    return Object.fromEntries(header.map((name, index) => [name, cells[index]]));
  });
};

const PUBKEY = `${"A".repeat(43)}=`;
const SIGNATURE = `${"A".repeat(86)}==`;
const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

const nodeId = randomUUID();
const implementerId = randomUUID();
const signingKeyId = randomUUID();

let nextSeq = 1;

// One already-signed event tuple. seq, the preimage and the signature are formed and signed
// BEFORE this seam — the store stores them verbatim and never re-serializes.
function signedEvent(
  eventType: SignedNodeEvent["eventType"],
  data: Record<string, unknown>,
  overrides: Partial<SignedNodeEvent> = {},
): SignedNodeEvent {
  const seq = nextSeq++;
  const dataText = JSON.stringify(data);
  const preimageText = JSON.stringify({ seq: String(seq), event_type: eventType, data });
  return {
    seq: String(seq),
    eventId: randomUUID(),
    nodeId,
    walletId: null,
    eventType,
    dataText,
    dataSha256: sha256Hex(utf8(dataText)),
    preimageText,
    preimageSha256: sha256Hex(utf8(preimageText)),
    signingKeyId,
    signature: SIGNATURE,
    previousEventHash: null,
    eventHash: sha256Hex(utf8(`${seq}:${eventType}`)),
    ...overrides,
  };
}

interface SeededMove {
  readonly operationId: string;
  readonly sourceWalletId: string;
  readonly destinationWalletId: string;
  readonly sourceT0: string;
  readonly destinationT0: string;
  readonly sourceTerminal: string;
  readonly destinationTerminal: string;
}

// Each test owns a fresh operation, its own wallets, its own observations and its own evidence
// row, so nothing here shares a key with a sibling test or a concurrent lane.
async function seedMove(
  status: "CREATED" | "NEEDS_ATTENTION" = "CREATED",
  options: { readonly withEvidence?: boolean } = {},
): Promise<SeededMove> {
  const move: SeededMove = {
    operationId: randomUUID(),
    sourceWalletId: randomUUID(),
    destinationWalletId: randomUUID(),
    sourceT0: randomUUID(),
    destinationT0: randomUUID(),
    sourceTerminal: randomUUID(),
    destinationTerminal: randomUUID(),
  };
  const attention =
    status === "NEEDS_ATTENTION" ? "true, 'VERIFICATION_INDETERMINATE'" : "false, NULL";
  // Frozen wallet_active_leases carries full fencing columns (NOT NULL).
  const srcMem = randomUUID();
  const dstMem = randomUUID();
  const srcGroup = randomUUID();
  const dstGroup = randomUUID();
  const owner = randomUUID();
  await psqlOk(
    inSchema(
      `INSERT INTO wallets (id, wallet_id) VALUES
         ('${move.sourceWalletId}', '${move.sourceWalletId}'),
         ('${move.destinationWalletId}', '${move.destinationWalletId}');
       INSERT INTO wallet_active_leases (
         wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
         lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id
       ) VALUES
         ('${move.sourceWalletId}', '${srcMem}', '${srcGroup}', '${move.operationId}',
          '${move.operationId}', 'MOVE_SOURCE', 1, '${CREATED_AT}', '${CREATED_AT}', '${owner}'),
         ('${move.destinationWalletId}', '${dstMem}', '${dstGroup}', '${move.operationId}',
          '${move.operationId}', 'MOVE_DESTINATION', 1, '${CREATED_AT}', '${CREATED_AT}', '${owner}');
       INSERT INTO gateway_observations (id) VALUES
         ('${move.sourceT0}'), ('${move.destinationT0}'),
         ('${move.sourceTerminal}'), ('${move.destinationTerminal}');
       INSERT INTO operations
         (id, node_id, implementer_id, kind, status, source_wallet_id,
          attention_required, attention_reason, created_at, updated_at)
       VALUES ('${move.operationId}', '${nodeId}', '${implementerId}', 'MOVE_INTERNAL',
          '${status}', '${move.sourceWalletId}', ${attention},
          '${CREATED_AT}', '${CREATED_AT}');`,
    ),
  );
  if (options.withEvidence !== false) {
    await psqlOk(
      inSchema(
        `INSERT INTO move_observation_evidence
           (operation_id, source_t0_observation_id, destination_t0_observation_id)
         VALUES ('${move.operationId}', '${move.sourceT0}', '${move.destinationT0}');`,
      ),
    );
  }
  return move;
}

// A landing path is a capability, not a shape: persistMoveOutcome identity-checks both proofs
// against the mint's issued set, so they are minted fresh per call — the seal is single-use.
// `kind` is the minter's to derive from depth; declaring it here could only drift.
function landedVerdict(move: SeededMove): MoveReconcileOutcome {
  const expectedBodySha256 = sha256Hex(utf8("move-body"));
  return {
    kind: "LANDED_VERIFIED",
    moveAttemptId: move.operationId,
    sourcePath: mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: PUBKEY,
      expectedBodySha256,
      freshHeadBodySha256: expectedBodySha256,
      freshHeadObservationId: move.sourceTerminal,
      depth: 0,
    }),
    // The asymmetric-burial shape exercises: the destination side is proven at depth,
    // by walking step_2 forward-linkage to the chain head, not by a position-only lookup.
    // Burial is what makes the head body differ from the expected one, which is exactly what
    // the seal validator demands at depth >= 1.
    destinationPath: mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: PUBKEY,
      expectedBodySha256,
      freshHeadBodySha256: sha256Hex(utf8("move-body-buried-head")),
      freshHeadObservationId: move.destinationTerminal,
      depth: 3,
    }),
  };
}

const INDETERMINATE_VERDICT: MoveReconcileOutcome = {
  kind: "INDETERMINATE",
  moveAttemptId: randomUUID(),
  reason: { source: "SUBMIT_OUTCOME_UNKNOWN" },
};

const landedEventFor = (move: SeededMove): SignedNodeEvent =>
  signedEvent("internal_move.landed", {
    source_terminal_observation_id: move.sourceTerminal,
    destination_terminal_observation_id: move.destinationTerminal,
    landed_at: OCCURRED_AT,
  });

const attentionEventFor = (state: string): SignedNodeEvent =>
  signedEvent("operation.needs_attention", {
    current_state: state,
    attention_reason: "SUBMIT_OUTCOME_AMBIGUOUS",
    attention_episode: 1,
    operator_action_required: true,
  });

const operationRow = (operationId: string): Promise<string> =>
  scalar(`SELECT row_to_json(o)::text FROM operations o WHERE id = '${operationId}'`);

const evidenceRow = (operationId: string): Promise<string> =>
  scalar(
    `SELECT row_to_json(e)::text FROM move_observation_evidence e
     WHERE operation_id = '${operationId}'`,
  );

const leaseRows = (move: SeededMove): Promise<string> =>
  scalar(
    `SELECT coalesce(string_agg(row_to_json(l)::text, ' ' ORDER BY wallet_id::text), 'none')
     FROM wallet_active_leases l
     WHERE wallet_id IN ('${move.sourceWalletId}', '${move.destinationWalletId}')`,
  );

const eventRows = (operationId: string): Promise<string> =>
  scalar(
    `SELECT coalesce(string_agg(event_type || ' ' || data_text, ' | ' ORDER BY seq), 'none')
     FROM node_events WHERE operation_id = '${operationId}'`,
  );

let reachable = false;

describe.skipIf(databaseUrl === undefined)(
  "MOVE_INTERNAL landing persist against a live PostgreSQL",
  // Every statement is a psql child process, and the Postgres instance is shared with
  // concurrent lanes; a test that runs in ~4s idle has been seen take 30s under contention.
  // The generous budget is so a loaded machine reports a slow pass, never a fake skip.
  { timeout: 120_000 },
  () => {
    beforeAll(async () => {
      await psqlOk(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE; CREATE SCHEMA ${SCHEMA};`);
      await psqlOk(
        inSchema(
          [
            operationKindEnum,
            operationStatusEnum,
            registrySql,
            layeredSigningKeysSql,
            "CREATE TABLE wallets (id uuid PRIMARY KEY, wallet_id uuid NOT NULL UNIQUE);",
            "CREATE TABLE gateway_observations (id uuid PRIMARY KEY);",
            OPERATIONS_STUB,
            walletActiveLeasesDdl,
            eventLedgerSql,
            // Single CREATE owner (baseline) then ALTER-only FKs.
            moveEvidenceCreateSql,
            moveEvidenceAlterSql,
          ].join("\n"),
        ),
      );
      await psqlOk(
        inSchema(
          `INSERT INTO nodes (id, display_name, identity_public_key)
             VALUES ('${nodeId}', 'move-internal-landing', '${PUBKEY}');
           INSERT INTO implementers (id, name) VALUES ('${implementerId}', 'move-internal-landing');
           INSERT INTO node_signing_keys
             (id, node_id, purpose, public_key, vault_secret_ref, activated_at)
           VALUES ('${signingKeyId}', '${nodeId}', 'EVENT_SIGNING', '${PUBKEY}',
             '${randomUUID()}', '${CREATED_AT}');`,
        ),
      );
      reachable = true;
    }, 60_000);

    afterAll(async () => {
      // Scoped to this suite's own schema: the Postgres instance is shared between lanes.
      if (reachable) await psqlOk(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE;`);
    });

    it("applies baseline CREATE then the frozen ALTER-only contract unmodified", async () => {
      const columns = await scalar(
        `SELECT string_agg(column_name, ',' ORDER BY ordinal_position)
         FROM information_schema.columns
         WHERE table_schema = '${SCHEMA}' AND table_name = 'move_observation_evidence'`,
      );
      expect(columns).toBe(
        "operation_id,source_t0_observation_id,destination_t0_observation_id," +
          "source_terminal_observation_id,destination_terminal_observation_id,verified_at",
      );
      // Four observation FKs are live (operation_id → operations remains deferred on
      // the baseline CREATE, same as DEFERRED_FOREIGN_KEYS in move-baseline-binding.contract).
      const foreignKeys = await scalar(
        `SELECT count(*) FROM information_schema.table_constraints
         WHERE table_schema = '${SCHEMA}' AND table_name = 'move_observation_evidence'
           AND constraint_type = 'FOREIGN KEY'`,
      );
      expect(foreignKeys).toBe("4");
      // Dual-CREATE guard: the ALTER-only file must not re-declare the relation.
      const alterActive = moveEvidenceAlterSql.replace(/--[^\n]*/g, "");
      expect(alterActive).not.toMatch(/CREATE\s+TABLE\s+move_observation_evidence\b/i);
      expect(moveEvidenceCreateSql).toMatch(/CREATE\s+TABLE\s+move_observation_evidence\b/i);
    });

    // state/event row 1: CREATED → INTERNAL_MOVE_LANDED on internal_move.landed.
    it("a LANDED_VERIFIED verdict lands the operation, attaches both terminals and appends the event", async () => {
      const move = await seedMove();
      const event = landedEventFor(move);
      const leasesBefore = await leaseRows(move);

      const result = await persistMoveOutcome(query, {
        operationId: move.operationId,
        expectedState: "CREATED",
        expectedRowVersion: 1,
        outcome: landedVerdict(move),
        event,
        occurredAt: OCCURRED_AT,
        verificationMaterialAvailableUntil: PROOF_EXPIRY,
      });

      expect(result).toEqual({ kind: "PERSISTED", state: "INTERNAL_MOVE_LANDED", rowVersion: 2 });
      expect(
        await scalar(
          `SELECT status || ' ' || row_version || ' ' || attention_required || ' ' ||
                  coalesce(attention_reason, '-') || ' ' ||
                  (terminal_at IS NOT NULL) || ' ' ||
                  to_char(verification_material_available_until AT TIME ZONE 'UTC', 'YYYY-MM-DD')
           FROM operations WHERE id = '${move.operationId}'`,
        ),
      ).toBe("INTERNAL_MOVE_LANDED 2 false - true 2026-08-24");
      expect(
        await scalar(
          `SELECT source_terminal_observation_id || ' ' || destination_terminal_observation_id
                  || ' ' || (verified_at IS NOT NULL)
           FROM move_observation_evidence WHERE operation_id = '${move.operationId}'`,
        ),
      ).toBe(`${move.sourceTerminal} ${move.destinationTerminal} true`);
      // The signed payload crosses the seam byte-for-byte, never re-serialized.
      expect(await eventRows(move.operationId)).toBe(
        `internal_move.landed ${event.dataText}`,
      );
      expect(
        await scalar(
          `SELECT signature = '${event.signature}' AND event_hash = '${event.eventHash}'
                  AND preimage_text = '${event.preimageText}'
           FROM node_events WHERE event_id = '${event.eventId}'`,
        ),
      ).toBe("t");
      // operation-flow step 6: leases are released elsewhere, never by this step.
      expect(await leaseRows(move)).toBe(leasesBefore);
    });

    // D2: data-model writes the column at the landed terminal as terminal_at + window.
    // The caller passing the value explicitly (above) proves the column accepts a write; this
    // proves a landing that passes nothing still commits a populated window, which is what the
    // api-contract gate needs to answer 200 instead of 409 forever.
    it("a landing that supplies no expiry still writes terminal_at + the 30-day window", async () => {
      const move = await seedMove();

      const result = await persistMoveOutcome(query, {
        operationId: move.operationId,
        expectedState: "CREATED",
        expectedRowVersion: 1,
        outcome: landedVerdict(move),
        event: landedEventFor(move),
        occurredAt: OCCURRED_AT,
      });

      expect(result).toEqual({ kind: "PERSISTED", state: "INTERNAL_MOVE_LANDED", rowVersion: 2 });
      // The derived value equals the same instant the explicit-expiry case above passes in,
      // and it opens at the terminal this statement wrote — never at a read-time clock.
      expect(
        await scalar(
          `SELECT (verification_material_available_until = timestamptz '${PROOF_EXPIRY}')
                  AND (verification_material_available_until
                       = terminal_at + interval '30 days')
           FROM operations WHERE id = '${move.operationId}'`,
        ),
      ).toBe("t");
    });

    // state/event row 2: CREATED → NEEDS_ATTENTION on operation.needs_attention.
    it("an INDETERMINATE verdict parks the operation with a closed-vocabulary reason and no terminal attachment", async () => {
      const move = await seedMove();
      const evidenceBefore = await evidenceRow(move.operationId);
      const leasesBefore = await leaseRows(move);

      const result = await persistMoveOutcome(query, {
        operationId: move.operationId,
        expectedState: "CREATED",
        expectedRowVersion: 1,
        outcome: INDETERMINATE_VERDICT,
        event: attentionEventFor("CREATED"),
        occurredAt: OCCURRED_AT,
        attentionDetail: "gateway response unreadable",
      });

      expect(result).toEqual({ kind: "PERSISTED", state: "NEEDS_ATTENTION", rowVersion: 2 });
      expect(
        await scalar(
          `SELECT status || ' ' || attention_required || ' ' || attention_reason || ' ' ||
                  attention_detail || ' ' || (terminal_at IS NULL)
           FROM operations WHERE id = '${move.operationId}'`,
        ),
      ).toBe("NEEDS_ATTENTION true SUBMIT_OUTCOME_AMBIGUOUS gateway response unreadable true");
      // No landing was proven, so no terminal observation is attached — the evidence row is
      // untouched, which is what keeps a parked move from reading as settled.
      expect(await evidenceRow(move.operationId)).toBe(evidenceBefore);
      expect(await eventRows(move.operationId)).toContain("operation.needs_attention");
      expect(await leaseRows(move)).toBe(leasesBefore);
    });

    // state/event row 3: a parked move reaches INTERNAL_MOVE_LANDED through this same service on a
    // later reconciliation pass — the recovery path.
    it("NEEDS_ATTENTION → INTERNAL_MOVE_LANDED recovers through the same code path and clears attention", async () => {
      const move = await seedMove("NEEDS_ATTENTION");

      const result = await persistMoveOutcome(query, {
        operationId: move.operationId,
        expectedState: "NEEDS_ATTENTION",
        expectedRowVersion: 1,
        outcome: landedVerdict(move),
        event: landedEventFor(move),
        occurredAt: OCCURRED_AT,
      });

      expect(result).toEqual({ kind: "PERSISTED", state: "INTERNAL_MOVE_LANDED", rowVersion: 2 });
      expect(
        await scalar(
          `SELECT attention_required || ' ' || coalesce(attention_reason, '-')
           FROM operations WHERE id = '${move.operationId}'`,
        ),
      ).toBe("false -");
      expect(await evidenceRow(move.operationId)).toContain(move.destinationTerminal);
    });

    // THE atomicity proof. The event-append leg is forced to fail inside the statement (a
    // duplicate event_hash), and every earlier leg must roll back with it. A two-statement
    // sequence would leave the operation landed with no event — the torn state this suite
    // exists to prevent.
    it("a failure in the event-append leg rolls back the state change and the terminal attachment", async () => {
      const move = await seedMove();
      const event = landedEventFor(move);
      const collidingOperation = await seedMove();
      await psqlOk(
        inSchema(
          `INSERT INTO node_events
             (seq, event_id, canonical_version, node_id, operation_id, event_type,
              data_text, data_sha256, preimage_text, preimage_sha256, signing_key_id,
              signature, event_hash, created_at)
           VALUES (${nextSeq++}, '${randomUUID()}', 1, '${nodeId}',
             '${collidingOperation.operationId}', 'internal_move.landed', '{}',
             '${sha256Hex(utf8("{}"))}', '{}', '${sha256Hex(utf8("{}"))}',
             '${signingKeyId}', '${SIGNATURE}', '${event.eventHash}', '${CREATED_AT}');`,
        ),
      );

      const operationBefore = await operationRow(move.operationId);
      const evidenceBefore = await evidenceRow(move.operationId);

      await expect(
        persistMoveOutcome(query, {
          operationId: move.operationId,
          expectedState: "CREATED",
          expectedRowVersion: 1,
          outcome: landedVerdict(move),
          event,
          occurredAt: OCCURRED_AT,
          verificationMaterialAvailableUntil: PROOF_EXPIRY,
        }),
      ).rejects.toThrow(new RegExp(UNIQUE_VIOLATION));

      expect(await operationRow(move.operationId)).toBe(operationBefore);
      expect(await evidenceRow(move.operationId)).toBe(evidenceBefore);
      expect(await eventRows(move.operationId)).toBe("none");
    });

    // The database, not a prior read, arbitrates the transition.
    it("two concurrent callers on the same row_version produce exactly one winner and one event", async () => {
      const move = await seedMove();
      const [first, second] = await Promise.all([
        persistMoveOutcome(query, {
          operationId: move.operationId,
          expectedState: "CREATED",
          expectedRowVersion: 1,
          outcome: landedVerdict(move),
          event: landedEventFor(move),
          occurredAt: OCCURRED_AT,
        }),
        persistMoveOutcome(query, {
          operationId: move.operationId,
          expectedState: "CREATED",
          expectedRowVersion: 1,
          outcome: INDETERMINATE_VERDICT,
          event: attentionEventFor("CREATED"),
          occurredAt: OCCURRED_AT,
        }),
      ]);

      const outcomes = [first.kind, second.kind].sort();
      expect(outcomes).toEqual(["PERSISTED", "PRECONDITION_UNMET"]);
      // The loser wrote nothing at all: one version bump, one event, and its read-back reports
      // the winner's state so the caller can re-decide rather than blind-retry.
      expect(
        await scalar(`SELECT row_version FROM operations WHERE id = '${move.operationId}'`),
      ).toBe("2");
      expect(
        await scalar(
          `SELECT count(*) FROM node_events WHERE operation_id = '${move.operationId}'`,
        ),
      ).toBe("1");
      const loser = first.kind === "PRECONDITION_UNMET" ? first : second;
      expect(loser).toMatchObject({ rowVersion: 2 });
    });

    it("a stale row_version writes nothing and reports the current row back", async () => {
      const move = await seedMove();
      await psqlOk(
        inSchema(
          `UPDATE operations SET row_version = 7 WHERE id = '${move.operationId}';`,
        ),
      );

      const result = await persistMoveOutcome(query, {
        operationId: move.operationId,
        expectedState: "CREATED",
        expectedRowVersion: 1,
        outcome: landedVerdict(move),
        event: landedEventFor(move),
        occurredAt: OCCURRED_AT,
      });

      expect(result).toEqual({ kind: "PRECONDITION_UNMET", state: "CREATED", rowVersion: 7 });
      expect(await eventRows(move.operationId)).toBe("none");
      expect(await evidenceRow(move.operationId)).toContain('"verified_at":null');
    });

    // data-model's barrier: INTERNAL_MOVE_LANDED is unreachable without an evidence row to carry
    // both terminal observations, so the landing branch refuses rather than landing blind.
    it("the landing branch refuses when the operation has no evidence row", async () => {
      const move = await seedMove("CREATED", { withEvidence: false });

      const result = await persistMoveOutcome(query, {
        operationId: move.operationId,
        expectedState: "CREATED",
        expectedRowVersion: 1,
        outcome: landedVerdict(move),
        event: landedEventFor(move),
        occurredAt: OCCURRED_AT,
      });

      expect(result).toEqual({ kind: "PRECONDITION_UNMET", state: "CREATED", rowVersion: 1 });
      expect(await eventRows(move.operationId)).toBe("none");
    });

    // The attention branch has no such barrier — parking a move must never depend on evidence.
    it("the attention branch parks an operation that has no evidence row", async () => {
      const move = await seedMove("CREATED", { withEvidence: false });

      const result = await persistMoveOutcome(query, {
        operationId: move.operationId,
        expectedState: "CREATED",
        expectedRowVersion: 1,
        outcome: INDETERMINATE_VERDICT,
        event: attentionEventFor("CREATED"),
        occurredAt: OCCURRED_AT,
      });

      expect(result).toEqual({ kind: "PERSISTED", state: "NEEDS_ATTENTION", rowVersion: 2 });
    });

    it("a half-attached terminal pair is rejected by the data-model CHECK", async () => {
      const move = await seedMove();
      const stderr = await errorOf(
        `UPDATE move_observation_evidence
           SET source_terminal_observation_id = '${move.sourceTerminal}'
         WHERE operation_id = '${move.operationId}';`,
      );
      expect(stderr).toContain(CHECK_VIOLATION);
    });

    it("one observation cannot stand as both terminals", async () => {
      const move = await seedMove();
      const stderr = await errorOf(
        `UPDATE move_observation_evidence SET
           source_terminal_observation_id = '${move.sourceTerminal}',
           destination_terminal_observation_id = '${move.sourceTerminal}',
           verified_at = '${OCCURRED_AT}'
         WHERE operation_id = '${move.operationId}';`,
      );
      expect(stderr).toContain(CHECK_VIOLATION);
    });

    it("a second evidence row for one operation is rejected", async () => {
      const move = await seedMove();
      const stderr = await errorOf(
        `INSERT INTO move_observation_evidence
           (operation_id, source_t0_observation_id, destination_t0_observation_id)
         VALUES ('${move.operationId}', '${move.sourceTerminal}', '${move.destinationTerminal}');`,
      );
      expect(stderr).toContain(UNIQUE_VIOLATION);
    });
  },
);

// Pure guards — no database, so they hold in every environment.
const refuseQuery: SqlQueryFn = () => {
  throw new Error("the database must not be touched");
};

it("PROVEN_NOT_STARTED is refused: it is a rebuild decision, not a landing write", async () => {
  await expect(
    persistMoveOutcome(refuseQuery, {
      operationId: randomUUID(),
      expectedState: "CREATED",
      expectedRowVersion: 1,
      outcome: {
        kind: "PROVEN_NOT_STARTED",
        moveAttemptId: randomUUID(),
        neverCrossedBoundary: "SUBMITTER",
        resumeAction: "SUBMIT_ONCE",
      },
      event: signedEvent("internal_move.landed", {}),
      occurredAt: OCCURRED_AT,
    }),
  ).rejects.toThrow(/rebuild decision/);
});

it("a transition absent from the frozen state/event table is refused before any write", async () => {
  const bodySha = sha256Hex(utf8("body"));
  await expect(
    persistMoveOutcome(refuseQuery, {
      operationId: randomUUID(),
      // INTERNAL_MOVE_LANDED is terminal: re-landing it is not a frozen transition.
      expectedState: "INTERNAL_MOVE_LANDED",
      expectedRowVersion: 1,
      outcome: {
        kind: "LANDED_VERIFIED",
        moveAttemptId: randomUUID(),
        sourcePath: mintLandingPathProofFromOracle({
          walletPubkeyBase64Urlsafe: PUBKEY,
          expectedBodySha256: bodySha,
          freshHeadBodySha256: bodySha,
          freshHeadObservationId: randomUUID(),
          depth: 0,
        }),
        destinationPath: mintLandingPathProofFromOracle({
          walletPubkeyBase64Urlsafe: PUBKEY,
          expectedBodySha256: bodySha,
          freshHeadBodySha256: bodySha,
          freshHeadObservationId: randomUUID(),
          depth: 0,
        }),
      },
      event: signedEvent("internal_move.landed", {}),
      occurredAt: OCCURRED_AT,
    }),
  ).rejects.toThrow(/not a frozen MOVE_INTERNAL transition/);
});

// fail-closed guard: a TEST_DATABASE_URL-gated suite that skips silently reports green
// having proven nothing, which is precisely the failure mode this suite exists to avoid.
it("live-PostgreSQL characterization must execute under PG_REQUIRED=1 (no silent skip)", () => {
  if (process.env.PG_REQUIRED !== "1") return;
  expect(
    databaseUrl,
    "PG_REQUIRED=1 but TEST_DATABASE_URL is unassigned — the atomicity proof did not run",
  ).toBeDefined();
  expect(
    reachable,
    "PG_REQUIRED=1 but the live block never reached the server — the atomicity proof did not run",
  ).toBe(true);
});

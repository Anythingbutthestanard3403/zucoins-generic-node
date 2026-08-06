// unit proof of the fail-closed privilege readiness gate (no live Postgres).
// Exercises every branch of assertPrivilegeReadiness against a scripted PrivilegeSqlExecutor
// so a broken role/revoke check fails the ordinary unit suite, not only PG_REQUIRED runs.
import { describe, expect, it } from "vitest";

import {
  assertPrivilegeReadiness,
  NODE_CORE_APP_ROLE,
  NODE_CORE_SEND_ROLE,
  PrivilegeReadinessError,
  SUBMIT_LEDGER_TABLES,
  type PrivilegeSqlExecutor,
  type PrivilegeSqlQueryResult,
} from "./privilege-readiness.js";

type ScriptedResponse =
  | { kind: "role"; exists: boolean }
  | {
      kind: "privs";
      rows: ReadonlyArray<{
        tablename: string;
        can_delete: boolean;
        can_truncate: boolean;
      }>;
    }
  | {
      kind: "ledger";
      rows: ReadonlyArray<{
        tablename: string;
        can_insert: boolean;
        can_update: boolean;
      }>;
    };

function scriptedExecutor(responses: ScriptedResponse[]): PrivilegeSqlExecutor {
  let i = 0;
  return {
    async query<R>(text: string): Promise<PrivilegeSqlQueryResult<R>> {
      const step = responses[i];
      i += 1;
      if (step === undefined) {
        throw new Error(`unexpected query past scripted responses: ${text}`);
      }
      if (step.kind === "role") {
        if (!/pg_roles/.test(text)) {
          throw new Error(`expected role-existence query, got: ${text}`);
        }
        return { rows: [{ role_exists: step.exists }] as R[] };
      }
      if (!/has_table_privilege/.test(text)) {
        throw new Error(`expected privilege scan query, got: ${text}`);
      }
      // The two scans differ by the privileges they probe: DELETE/TRUNCATE for the app role,
      // INSERT/UPDATE on the submit ledgers for the SEND role.
      const isLedgerScan = /can_insert/.test(text);
      if (isLedgerScan !== (step.kind === "ledger")) {
        throw new Error(`scripted ${step.kind} step does not match query: ${text}`);
      }
      return { rows: step.rows as R[] };
    },
  };
}

// appended three steps to the gate: the SEND role must exist, must hold no
// DELETE/TRUNCATE on any covered table, and must hold no write on either submit ledger.
// Scripts that expect a resolve carry this clean tail.
const CLEAN_SEND_TAIL: ScriptedResponse[] = [
  { kind: "role", exists: true },
  { kind: "privs", rows: [] },
  { kind: "ledger", rows: [] },
];

// The app-role half of a script that gets as far as the SEND role: role present, no covered
// table holding DELETE/TRUNCATE.
const CLEAN_APP_HEAD: ScriptedResponse[] = [
  { kind: "role", exists: true },
  { kind: "privs", rows: [] },
];

describe("assertPrivilegeReadiness", () => {
  it("exports the canonical app role name", () => {
    expect(NODE_CORE_APP_ROLE).toBe("node_core_app");
  });

  it("allows boot when the role exists and no table holds DELETE/TRUNCATE", async () => {
    const db = scriptedExecutor([
      { kind: "role", exists: true },
      {
        kind: "privs",
        rows: [
          { tablename: "nodes", can_delete: false, can_truncate: false },
          { tablename: "implementers", can_delete: false, can_truncate: false },
        ],
      },
      ...CLEAN_SEND_TAIL,
    ]);
    await expect(assertPrivilegeReadiness(db)).resolves.toBeUndefined();
  });

  it("allows boot when the role exists and the schema has zero tables", async () => {
    const db = scriptedExecutor([
      { kind: "role", exists: true },
      { kind: "privs", rows: [] },
      ...CLEAN_SEND_TAIL,
    ]);
    await expect(assertPrivilegeReadiness(db)).resolves.toBeUndefined();
  });

  it("refuses boot when the runtime role does not exist", async () => {
    const db = scriptedExecutor([{ kind: "role", exists: false }]);
    await expect(assertPrivilegeReadiness(db)).rejects.toBeInstanceOf(PrivilegeReadinessError);
    await expect(
      assertPrivilegeReadiness(scriptedExecutor([{ kind: "role", exists: false }]), {
        roleName: "node_core_app_absent_probe",
      }),
    ).rejects.toThrow(/role "node_core_app_absent_probe" does not exist/);
  });

  it("refuses boot when DELETE is held on a covered table", async () => {
    const script: ScriptedResponse[] = [
      { kind: "role", exists: true },
      {
        kind: "privs",
        rows: [{ tablename: "nodes", can_delete: true, can_truncate: false }],
      },
    ];
    await expect(assertPrivilegeReadiness(scriptedExecutor(script))).rejects.toThrow(
      /nodes \(DELETE\)/,
    );
    await expect(assertPrivilegeReadiness(scriptedExecutor(script))).rejects.toBeInstanceOf(
      PrivilegeReadinessError,
    );
  });

  it("refuses boot when TRUNCATE is held on a covered table", async () => {
    const db = scriptedExecutor([
      { kind: "role", exists: true },
      {
        kind: "privs",
        rows: [{ tablename: "implementers", can_delete: false, can_truncate: true }],
      },
    ]);
    await expect(assertPrivilegeReadiness(db)).rejects.toThrow(/implementers \(TRUNCATE\)/);
  });

  it("lists every violating table in the error (DELETE and TRUNCATE together)", async () => {
    const db = scriptedExecutor([
      { kind: "role", exists: true },
      {
        kind: "privs",
        rows: [
          { tablename: "nodes", can_delete: true, can_truncate: true },
          { tablename: "wallets", can_delete: true, can_truncate: false },
        ],
      },
    ]);
    await expect(assertPrivilegeReadiness(db)).rejects.toThrow(
      /nodes \(DELETE, TRUNCATE\); wallets \(DELETE\)/,
    );
  });

  it("exports the canonical SEND role name and the two submit ledgers", () => {
    expect(NODE_CORE_SEND_ROLE).toBe("node_core_send");
    expect([...SUBMIT_LEDGER_TABLES]).toEqual(["submit_decisions", "gateway_submit_attempts"]);
  });

  it("refuses boot when the SEND-path role does not exist", async () => {
    const db = scriptedExecutor([...CLEAN_APP_HEAD, { kind: "role", exists: false }]);
    await expect(assertPrivilegeReadiness(db)).rejects.toThrow(
      /role "node_core_send" does not exist/,
    );
  });

  // A SEND role that cannot INSERT a submit decision but CAN delete or truncate the ledger
  // destroys the same record by another verb. privileges.sql revokes both from node_core_send;
  // these two are the boot half of that subtraction (review finding 2).
  it("refuses boot when DELETE is held by the SEND role on a covered table", async () => {
    const db = scriptedExecutor([
      ...CLEAN_APP_HEAD,
      { kind: "role", exists: true },
      {
        kind: "privs",
        rows: [{ tablename: "wallets", can_delete: true, can_truncate: false }],
      },
    ]);
    await expect(assertPrivilegeReadiness(db)).rejects.toThrow(
      /role "node_core_send" holds revoked privileges on public tables: wallets \(DELETE\)/,
    );
  });

  it("refuses boot when TRUNCATE is held by the SEND role on a covered table", async () => {
    const db = scriptedExecutor([
      ...CLEAN_APP_HEAD,
      { kind: "role", exists: true },
      {
        kind: "privs",
        rows: [{ tablename: "submit_decisions", can_delete: false, can_truncate: true }],
      },
    ]);
    await expect(assertPrivilegeReadiness(db)).rejects.toThrow(
      /role "node_core_send" holds revoked privileges on public tables: submit_decisions \(TRUNCATE\)/,
    );
    await expect(
      assertPrivilegeReadiness(
        scriptedExecutor([
          ...CLEAN_APP_HEAD,
          { kind: "role", exists: true },
          {
            kind: "privs",
            rows: [{ tablename: "submit_decisions", can_delete: false, can_truncate: true }],
          },
        ]),
      ),
    ).rejects.toBeInstanceOf(PrivilegeReadinessError);
  });

  it("refuses boot when INSERT is re-granted to the SEND role on submit_decisions", async () => {
    const db = scriptedExecutor([
      ...CLEAN_APP_HEAD,
      { kind: "role", exists: true },
      { kind: "privs", rows: [] },
      {
        kind: "ledger",
        rows: [{ tablename: "submit_decisions", can_insert: true, can_update: false }],
      },
    ]);
    await expect(assertPrivilegeReadiness(db)).rejects.toThrow(/submit_decisions \(INSERT\)/);
  });

  it("lists every writable submit ledger in the error (INSERT and UPDATE together)", async () => {
    const db = scriptedExecutor([
      ...CLEAN_APP_HEAD,
      { kind: "role", exists: true },
      { kind: "privs", rows: [] },
      {
        kind: "ledger",
        rows: [
          { tablename: "submit_decisions", can_insert: true, can_update: true },
          { tablename: "gateway_submit_attempts", can_insert: false, can_update: true },
        ],
      },
    ]);
    await expect(assertPrivilegeReadiness(db)).rejects.toThrow(
      /submit_decisions \(INSERT, UPDATE\); gateway_submit_attempts \(UPDATE\)/,
    );
    await expect(
      assertPrivilegeReadiness(
        scriptedExecutor([
          ...CLEAN_APP_HEAD,
          { kind: "role", exists: true },
          { kind: "privs", rows: [] },
          {
            kind: "ledger",
            rows: [{ tablename: "gateway_submit_attempts", can_insert: true, can_update: false }],
          },
        ]),
      ),
    ).rejects.toBeInstanceOf(PrivilegeReadinessError);
  });

  it("error messages never echo credential-shaped material from options", async () => {
    const db = scriptedExecutor([{ kind: "role", exists: false }]);
    try {
      await assertPrivilegeReadiness(db, { roleName: "node_core_app" });
      expect.unreachable("should have thrown");
    } catch (err) {
      const message = (err as Error).message;
      expect(message).not.toMatch(/password|secret|postgres:\/\//i);
      expect(message).toContain('role "node_core_app" does not exist');
    }
  });
});

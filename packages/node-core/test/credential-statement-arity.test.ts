// Regression: every CREDENTIAL_STATEMENTS text must bind exactly as many parameters as
// SqlCredentialStore actually supplies for it.
//
// P1#2 added the OPERATOR_SESSION actor-kind computation to auditParams (an 8th
// audit value) but left `actor_kind` as the literal 'IMPLEMENTER' in all three audit
// clauses, which have only 7 placeholders. Every issue/rotate/revoke therefore died at
// bind time with "bind message supplies 22 parameters, but prepared statement requires 21",
// and the operator-principal feature was inert — the literal always wrote IMPLEMENTER.
//
// implementer-credentials.pg.test.ts cannot catch this: it PREPAREs the frozen text against
// its own hand-written parameter list rather than binding through the store, so drift
// between the SQL and the runtime param builders is invisible to it, and it skips entirely
// without DATABASE_URL. This check needs no driver and no database.

import { describe, expect, it } from "vitest";

import { SqlCredentialStore, CREDENTIAL_STATEMENTS } from "../src/credential/sql-store.ts";
import type { CredentialAuditEntry, StoredCredential } from "../src/credential/types.ts";

const NODE_ID = "11111111-1111-4111-8111-111111111111";

const credential: StoredCredential = {
  id: "22222222-2222-4222-8222-222222222222",
  implementer_id: "33333333-3333-4333-8333-333333333333",
  public_prefix: "zpk_test",
  credential_hash: "a".repeat(64),
  scopes: ["receive:create"],
  status: "ACTIVE",
  key_version: 1,
  issued_at: "2026-07-31T00:00:00.000Z",
  expires_at: null,
  revoked_at: null,
  rotated_from_id: null,
  rotated_to_id: null,
  rotated_at: null,
  rotation_grace_until: null,
};

const audit: CredentialAuditEntry = {
  id: "44444444-4444-4444-8444-444444444444",
  implementer_id: credential.implementer_id,
  action: "ISSUE",
  credential_id: credential.id,
  replacement_credential_id: null,
  created_at: "2026-07-31T00:00:00.000Z",
};

/** Highest $n appearing in the statement — what PostgreSQL will require at bind time. */
function requiredParameterCount(text: string): number {
  const found = text.match(/\$(\d+)/gu) ?? [];
  return found.reduce((max, token) => Math.max(max, Number(token.slice(1))), 0);
}

function capturingStore(): {
  readonly store: SqlCredentialStore;
  readonly calls: { text: string; params: readonly unknown[] }[];
} {
  const calls: { text: string; params: readonly unknown[] }[] = [];
  const sql = {
    query: async (text: string, params?: readonly unknown[]) => {
      calls.push({ text, params: params ?? [] });
      return { rows: [{ id: credential.id }], rowCount: 1 };
    },
  };
  return { store: new SqlCredentialStore(sql as never, NODE_ID), calls };
}

describe("CREDENTIAL_STATEMENTS parameter arity", () => {
  it("issue binds exactly the parameters ISSUE requires", async () => {
    const { store, calls } = capturingStore();
    await store.issue(credential, audit);
    const call = calls[0]!;
    expect(call.params).toHaveLength(requiredParameterCount(call.text));
  });

  it("rotate binds exactly the parameters ROTATE requires", async () => {
    const { store, calls } = capturingStore();
    await store.rotate(
      credential.id,
      credential.implementer_id,
      credential,
      "2026-07-31T01:00:00.000Z",
      "2026-08-01T01:00:00.000Z",
      { ...audit, action: "ROTATE" },
    );
    const call = calls[0]!;
    expect(call.params).toHaveLength(requiredParameterCount(call.text));
  });

  it("revoke binds exactly the parameters REVOKE requires", async () => {
    const { store, calls } = capturingStore();
    await store.revoke(credential.id, credential.implementer_id, "2026-07-31T01:00:00.000Z", {
      ...audit,
      action: "REVOKE",
    });
    const call = calls[0]!;
    expect(call.params).toHaveLength(requiredParameterCount(call.text));
  });

  // The literal that caused the defect: actor_kind must be a bound parameter, otherwise the
  // OPERATOR_SESSION principal computed in auditParams can never reach the row.
  it("no audit clause hardcodes actor_kind", () => {
    for (const [name, text] of Object.entries(CREDENTIAL_STATEMENTS)) {
      expect(text, `${name} must bind actor_kind, not hardcode it`).not.toContain(
        "'IMPLEMENTER'",
      );
    }
  });
});

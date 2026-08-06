// Census: binds the frozen signer-support invariant inventory to the literal SQL
// contract text, so the two truth carriers (contract inventory, SQL text) cannot drift
// apart silently. Live-database execution is a schema-apply obligation, inventoried in the
// contract, not silently omitted.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  A42_DESTINATION_BLESS_DEVICE_SIGNATURE,
  SCHEMA_SIGNER_SUPPORT_OBLIGATIONS,
  SIGNER_SUPPORT_AUDIT_OUTCOMES,
  SIGNER_SUPPORT_AUDIT_PURPOSES,
  SIGNER_SUPPORT_INVARIANTS,
  SIGNER_SUPPORT_MUTABILITY_REGIMES,
  SIGNER_SUPPORT_PADDED_BASE64URL_SIGNATURE_CHECK,
  SIGNER_SUPPORT_RATE_DIMENSIONS,
  SIGNER_SUPPORT_SCHEMA_FILE,
  SIGNER_SUPPORT_TOTP_PURPOSES,
} from "../src/schema/signer-support.contract.ts";

const here = dirname(fileURLToPath(import.meta.url));
const sqlPath = resolve(here, "../src/schema", SIGNER_SUPPORT_SCHEMA_FILE);
const sql = readFileSync(sqlPath, "utf8");
const sqlBytes = readFileSync(sqlPath);
const ddl = sql
  .split("\n")
  .filter((line) => !/^\s*--/.test(line))
  .join("\n");

const parseCheckLiterals = (column: string, text: string): string[] => {
  const pattern = new RegExp(
    `${column} IN\\s*\\(\\s*'([^']+)'(?:\\s*,\\s*'([^']+)')*\\s*\\)`,
  );
  const check = pattern.exec(text);
  if (check === null) {
    return [];
  }
  return [...check[0].matchAll(/'([^']+)'/g)].map((match) => match[1] ?? "");
};

describe("signer-support schema census", () => {
  it("every frozen invariant anchors to the literal SQL text", () => {
    const missing = SIGNER_SUPPORT_INVARIANTS.filter(
      (invariant) => !sql.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toEqual([]);
  });

  it("signer_audit outcome and purpose literals equal the frozen taxonomies", () => {
    expect(parseCheckLiterals("outcome", sql)).toEqual([...SIGNER_SUPPORT_AUDIT_OUTCOMES]);
    expect(parseCheckLiterals("purpose", sql).slice(0, 5)).toEqual([
      ...SIGNER_SUPPORT_AUDIT_PURPOSES,
    ]);
  });

  it("signer_audit records lease, preimage digest, called_at, and outcome", () => {
    expect(sql).toContain("lease_group_id uuid,");
    expect(sql).toContain("lease_epoch bigint CHECK (lease_epoch IS NULL OR lease_epoch > 0),");
    expect(sql).toContain("preimage_sha256 sha256_hex NOT NULL,");
    expect(sql).toContain("called_at timestamptz NOT NULL,");
    expect(sql).toContain("CREATE TABLE signer_audit");
  });

  it("padded_base64url_signature domain is {86}== and accepts A.4.2 golden device signature", () => {
    expect(sql).toContain(
      `CREATE DOMAIN padded_base64url_signature AS text\n  CHECK (${SIGNER_SUPPORT_PADDED_BASE64URL_SIGNATURE_CHECK});`,
    );
    // Wrong shape that previously shipped ({87}=$) rejects every valid Ed25519 padded sig.
    expect(sql).not.toContain("VALUE ~ '^[A-Za-z0-9_-]{87}=$'");
    const domainRe = new RegExp("^[A-Za-z0-9_-]{86}==$");
    expect(A42_DESTINATION_BLESS_DEVICE_SIGNATURE).toHaveLength(88);
    expect(domainRe.test(A42_DESTINATION_BLESS_DEVICE_SIGNATURE)).toBe(true);
    expect(new RegExp("^[A-Za-z0-9_-]{87}=$").test(A42_DESTINATION_BLESS_DEVICE_SIGNATURE)).toBe(
      false,
    );
  });

  it("destination_blessing_artifacts persist the A.4.2 tuple with UNIQUE nonce", () => {
    expect(sql).toContain("CREATE TABLE destination_blessing_artifacts");
    expect(sql).toContain("purpose text NOT NULL CHECK (purpose = 'zp-destination-bless-v1')");
    expect(sql).toContain("wallet_pubkey padded_base64url_pubkey NOT NULL,");
    expect(sql).toContain("device_signature padded_base64url_signature NOT NULL,");
    expect(sql).toContain("CHECK (EXTRACT(EPOCH FROM (expires_at - issued_at)) <= 300)");
    expect((sql.match(/nonce uuid NOT NULL UNIQUE/g) ?? []).length).toBeGreaterThanOrEqual(2);
  });

  it("destinations.blessing_artifact_id has a real foreign-key target", () => {
    expect(sql).toContain("REFERENCES destination_blessing_artifacts (id)");
    expect(sql).toContain("destinations_blessing_artifact_fk");
  });

  it("recovery_nonces enforce single-use and one ISSUED per operation", () => {
    expect(sql).toContain("CREATE TABLE recovery_nonces");
    expect(sql).toContain("CREATE UNIQUE INDEX recovery_nonces_one_issued_per_operation");
    expect(sql).toContain("WHERE status = 'ISSUED'");
    expect(sql).toContain("('ISSUED','CONSUMED','SUPERSEDED')");
  });

  it("totp_timestep_burns is globally unique on (node_id, totp_timestep) across purposes", () => {
    expect(sql).toContain("CREATE TABLE totp_timestep_burns");
    expect(sql).toContain("UNIQUE (node_id, totp_timestep)");
    const totpBlock = sql.slice(sql.indexOf("CREATE TABLE totp_timestep_burns"));
    expect(parseCheckLiterals("purpose", totpBlock)).toEqual([...SIGNER_SUPPORT_TOTP_PURPOSES]);
  });

  it("api_rate_buckets cover the four dimensions with non-negative counts", () => {
    expect(sql).toContain("CREATE TABLE api_rate_buckets");
    expect(parseCheckLiterals("dimension", sql)).toEqual([...SIGNER_SUPPORT_RATE_DIMENSIONS]);
    expect(sql).toContain("UNIQUE (node_id, dimension, dimension_key, window_start)");
    expect(sql).toContain("request_count integer NOT NULL DEFAULT 0 CHECK (request_count >= 0)");
  });

  it("auth_failure_state tracks failed_login_count and locked_until per account", () => {
    expect(sql).toContain("CREATE TABLE auth_failure_state");
    expect(sql).toContain("failed_login_count integer NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0)");
    expect(sql).toContain("locked_until timestamptz,");
    expect(sql).toContain("UNIQUE (node_id, account_key)");
  });

  it("exact-content tables are insert-only; counters use guarded projection", () => {
    const byTable = Object.fromEntries(
      SIGNER_SUPPORT_MUTABILITY_REGIMES.map((regime) => [regime.table, regime]),
    );
    expect(byTable.signer_audit?.regime).toBe("insert_only");
    expect(byTable.destination_blessing_artifacts?.regime).toBe("insert_only");
    expect(byTable.totp_timestep_burns?.regime).toBe("insert_only");
    expect(byTable.recovery_nonces?.regime).toBe("guarded_projection");
    expect(byTable.api_rate_buckets?.regime).toBe("guarded_projection");
    expect(byTable.auth_failure_state?.regime).toBe("guarded_projection");
    expect(byTable.signer_audit?.updatableColumns).toEqual([]);
    expect(byTable.destination_blessing_artifacts?.updatableColumns).toEqual([]);
  });

  it("secret-free schema: no private key / secret / authorization column token in the DDL", () => {
    for (const token of ["private_key", "secret", "authorization", "vault"] as const) {
      expect(ddl.toLowerCase()).not.toContain(token);
    }
    expect(ddl.toLowerCase()).not.toContain("totp_code");
    expect(ddl.toLowerCase()).not.toContain("totp_secret");
  });

  it("mutation negative: wrong signature domain {87}=$ is caught", () => {
    const broken = sql.replace(
      "VALUE ~ '^[A-Za-z0-9_-]{86}==$'",
      "VALUE ~ '^[A-Za-z0-9_-]{87}=$'",
    );
    const missing = SIGNER_SUPPORT_INVARIANTS.filter(
      (invariant) => !broken.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("DOMAIN_PADDED_BASE64URL_SIGNATURE");
  });

  it("mutation negative: dropping the global TOTP UNIQUE is caught", () => {
    const removed = sql.replace("UNIQUE (node_id, totp_timestep)", "");
    const missing = SIGNER_SUPPORT_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("TOTP_BURN_GLOBAL_UNIQUE");
  });

  it("mutation negative: dropping the blessing artifact FK is caught", () => {
    const removed = sql.replace(
      `ALTER TABLE destinations
  ADD CONSTRAINT destinations_blessing_artifact_fk
  FOREIGN KEY (blessing_artifact_id)
  REFERENCES destination_blessing_artifacts (id);`,
      "",
    );
    const missing = SIGNER_SUPPORT_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("BLESS_ARTIFACT_FK_TARGET");
  });

  it("mutation negative: dropping recovery one-ISSUED index is caught", () => {
    const removed = sql.replace(
      `CREATE UNIQUE INDEX recovery_nonces_one_issued_per_operation
  ON recovery_nonces (operation_id)
  WHERE status = 'ISSUED';`,
      "",
    );
    const missing = SIGNER_SUPPORT_INVARIANTS.filter(
      (invariant) => !removed.includes(invariant.sqlAnchor),
    ).map((invariant) => invariant.id);
    expect(missing).toContain("RECOVERY_NONCE_ONE_ISSUED");
  });

  it("schema-apply obligations invent recovery classification and global TOTP negatives", () => {
    expect(SCHEMA_SIGNER_SUPPORT_OBLIGATIONS.length).toBeGreaterThanOrEqual(8);
    expect(
      SCHEMA_SIGNER_SUPPORT_OBLIGATIONS.some((obligation) =>
        obligation.includes("INVARIANT_BREACH"),
      ),
    ).toBe(true);
    expect(
      SCHEMA_SIGNER_SUPPORT_OBLIGATIONS.some((obligation) =>
        obligation.includes("PROVEN_NOT_STARTED"),
      ),
    ).toBe(true);
    expect(
      SCHEMA_SIGNER_SUPPORT_OBLIGATIONS.some(
        (obligation) =>
          obligation.includes("globally") || obligation.includes("global"),
      ),
    ).toBe(true);
  });

  it("file hygiene: pure ASCII, no BOM, no CRLF, final non-whitespace char is ';'", () => {
    expect(sqlBytes.every((byte) => byte <= 0x7f)).toBe(true);
    expect(sqlBytes[0] === 0xef && sqlBytes[1] === 0xbb && sqlBytes[2] === 0xbf).toBe(false);
    expect(sql.includes("\r")).toBe(false);
    expect(sql.trimEnd().endsWith(";")).toBe(true);
  });
});

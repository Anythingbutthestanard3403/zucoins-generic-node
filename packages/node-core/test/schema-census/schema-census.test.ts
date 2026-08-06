// schema-to-spec traceability census.
// Live gate: reverse noun→table, orphan FK, unsafe cascade, unindexed worker query.
// Four injected negative-path assertions (one per failure class) prove the gate is
// not vacuous. Machine-readable report pinned at schema-census.report.json.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  EVIDENCE_TABLE_EXCLUSIONS,
  EVIDENCE_TABLES,
  GOVERNING_DOCS,
  NORMATIVE_NOUNS,
  RETENTION_MATRIX_EVIDENCE,
  SPEC_TABLE_DISPOSITIONS,
  WORKER_ACCESS_PATTERNS,
  deriveEvidenceTables,
} from "./normative-manifest.ts";
import {
  CENSUS_REPORT_PATH,
  DECLARED_PRODUCERS,
  DEFAULT_PRODUCER_EXEMPT,
  buildCensus,
  buildCensusFromSql,
  checkSpecTableDispositions,
  extractCreateTableNames,
  formatReportText,
  indexCovers,
  loadSchemaDir,
  scanProducerTables,
} from "./schema-census.ts";
import { parseSchemaFromMap } from "./schema-ddl.ts";

const here = dirname(fileURLToPath(import.meta.url));
const schemaDir = resolve(here, "../../src/schema");
const repoRoot = resolve(here, "../../../..");

const live = buildCensus();
const { report, model, ok } = live;

describe("schema-object census — live gate", () => {
  it("opens the frozen governing schema surface", () => {
    expect(report.docsRead).toHaveLength(GOVERNING_DOCS.length);
    for (const doc of GOVERNING_DOCS) {
      expect(report.docsRead.some((p) => p.endsWith(doc.relativePath))).toBe(true);
    }
  });

  it("enumerates every .sql contract under src/schema", () => {
    const onDisk = [...loadSchemaDir(schemaDir).keys()];
    expect(report.schemaFiles).toEqual(onDisk);
    expect(report.schemaFiles.length).toBeGreaterThan(10);
  });

  // high-signal inventory gate: schema.sql add/remove must flip the
  // committed report's schemaFiles list. Full-body pin below still else-where covers
  // FK/noun drift; this assertion names the inventory delta explicitly.
  it("committed report schemaFiles equals on-disk .sql set (add/remove gate)", () => {
    const onDisk = [...loadSchemaDir(schemaDir).keys()];
    let committedRaw: string;
    try {
      committedRaw = readFileSync(CENSUS_REPORT_PATH, "utf8");
    } catch (err) {
      const code =
        err && typeof err === "object" && "code" in err
          ? (err as NodeJS.ErrnoException).code
          : undefined;
      if (code === "ENOENT") {
        throw new Error(
          "schema-census.report.json missing — run: node scripts/check-schema-census.mjs --write-report",
        );
      }
      throw err;
    }
    const committed = JSON.parse(committedRaw) as { schemaFiles?: string[] };
    const committedFiles = [...(committed.schemaFiles ?? [])].sort();
    const added = onDisk.filter((f) => !committedFiles.includes(f));
    const removed = committedFiles.filter((f) => !onDisk.includes(f));
    expect(
      { added, removed },
      "schemaFiles drift — intentional add/remove requires: node scripts/check-schema-census.mjs --write-report and commit",
    ).toEqual({ added: [], removed: [] });
    expect(committedFiles).toEqual(onDisk);
  });

  it("checks every normative noun and emits noun→satisfier|NONE", () => {
    expect(report.nouns.length).toBe(NORMATIVE_NOUNS.length);
    for (const noun of report.nouns) {
      expect(noun.satisfiedBy.length).toBeGreaterThan(0);
      expect(noun.id.length).toBeGreaterThan(0);
    }
  });

  it("parent scope line nouns are all present in the report", () => {
    const ids = new Set(report.nouns.map((n) => n.id));
    for (const required of [
      "node-scope.pool-membership",
      "node-scope.reporting-nonces",
      "node-scope.subscription-handles",
      "node-scope.callback-registrations",
      "node-scope.signer-audit",
      "node-scope.worker-leader-state",
      "node-scope.credentials",
      "node-scope.admin-sessions",
      "node-scope.totp-burns",
      "node-scope.blessing-artifacts",
      "node-scope.candidate-manifests",
      "node-scope.gateway-read-intents",
      "gap.destinations-blessing-artifact-fk-target",
    ]) {
      expect(ids.has(required), `missing parent-scope noun ${required}`).toBe(true);
    }
  });

  it("blessing-artifact target and sibling stores satisfy their nouns", () => {
    const byId = Object.fromEntries(report.nouns.map((n) => [n.id, n]));
    expect(byId["gap.destinations-blessing-artifact-fk-target"]?.satisfiedBy).toBe(
      "table:destination_blessing_artifacts",
    );
    expect(byId["node-scope.signer-audit"]?.satisfiedBy).toBe("table:signer_audit");
    expect(byId["node-scope.totp-burns"]?.satisfiedBy).toBe("table:totp_timestep_burns");
    expect(byId["node-scope.worker-leader-state"]?.ok).toBe(true);
    expect(byId["node-core.node-settings"]?.satisfiedBy).toBe("table:node_settings");
    expect(byId["node-core.operator-halts"]?.satisfiedBy).toBe("table:operator_halts");
  });

  it("callback registrations are excluded-by-canon, not a missing store", () => {
    const cb = report.nouns.find((n) => n.id === "node-scope.callback-registrations");
    expect(cb?.disposition).toBe("excluded");
    expect(cb?.ok).toBe(true);
    expect(cb?.satisfiedBy).toContain("excluded-by-canon");
  });

  it("subscription handles + admin sessions are required and satisfied (B1 — no deferred greenwash)", () => {
    const byId = Object.fromEntries(report.nouns.map((n) => [n.id, n]));
    expect(byId["node-scope.subscription-handles"]?.disposition).toBe("required");
    expect(byId["node-scope.subscription-handles"]?.satisfiedBy).toBe("table:subscription_handles");
    expect(byId["node-scope.subscription-handles"]?.ok).toBe(true);
    expect(byId["node-scope.admin-sessions"]?.disposition).toBe("required");
    expect(byId["node-scope.admin-sessions"]?.satisfiedBy).toBe("table:admin_sessions");
    expect(byId["node-scope.admin-sessions"]?.ok).toBe(true);
    // Live schema must actually contain the tables (not just a satisfier string).
    expect(model.tables.has("subscription_handles")).toBe(true);
    expect(model.tables.has("admin_sessions")).toBe(true);
  });

  it("producer arm is non-hollow: money-path FK targets are not blanket-exempt (B3)", () => {
    const moneyPath = [
      "wallets",
      "destinations",
      "audit_log",
      "operation_transactions",
      "external_send_partials",
      "external_send_sign_intents",
      "operator_device_keys",
    ];
    for (const t of moneyPath) {
      expect(
        DEFAULT_PRODUCER_EXEMPT.has(t),
        `${t} must not be producer-exempt (B3)`,
      ).toBe(false);
    }
    const producers = scanProducerTables(resolve(here, "../../src"));
    for (const t of moneyPath) {
      expect(
        producers.has(t),
        `${t} must have a detectable or declared producer`,
      ).toBe(true);
    }
    // Declarations exist for the store-port tables the SQL scanner alone cannot see.
    for (const t of ["wallets", "destinations", "audit_log", "operator_device_keys"]) {
      expect(DECLARED_PRODUCERS[t]?.length ?? 0).toBeGreaterThan(20);
    }
    // Live FK edges targeting money-path tables must report ok (producer arm).
    const moneyFk = report.foreignKeys.filter((fk) =>
      moneyPath.some((t) => fk.target.startsWith(`${t}(`)),
    );
    expect(moneyFk.length).toBeGreaterThan(5);
    for (const fk of moneyFk) {
      expect(fk.ok, fk.detail ?? fk.target).toBe(true);
    }
  });

  it("live schema has zero census failures", () => {
    if (!ok) {
      throw new Error(
        `census FAIL (${report.summary.failureCount}):\n` + formatReportText(report),
      );
    }
    expect(report.summary.failureCount).toBe(0);
    expect(report.summary.byClass.missing_store).toBe(0);
    expect(report.summary.byClass.orphan_fk).toBe(0);
    expect(report.summary.byClass.unsafe_cascade).toBe(0);
    expect(report.summary.byClass.unindexed_query).toBe(0);
  });

  it("parses foreign keys including ALTER TABLE ADD CONSTRAINT form", () => {
    expect(model.foreignKeys.length).toBeGreaterThan(20);
    const blessingFk = model.foreignKeys.find(
      (fk) =>
        fk.sourceTable === "destinations" &&
        fk.targetTable === "destination_blessing_artifacts",
    );
    expect(blessingFk, "destinations→destination_blessing_artifacts FK must parse").toBeTruthy();
  });

  it("every worker access pattern has a supporting index on the live schema", () => {
    for (const row of report.accessPatterns) {
      expect(row.ok, `${row.id} unindexed`).toBe(true);
      expect(row.satisfiedBy.startsWith("index:")).toBe(true);
    }
    expect(report.accessPatterns.length).toBe(WORKER_ACCESS_PATTERNS.length);
  });

  it("evidence tables derive from matrix + permanent retentionClass (A2/B2)", () => {
    const derived = deriveEvidenceTables(model.tables, NORMATIVE_NOUNS);
    // Live default must match the derivation (no hand floor / self-spot-check).
    expect([...EVIDENCE_TABLES].sort()).toEqual([...derived].sort());

    // Every permanent/exact-content matrix row contributes ≥1 table name.
    for (const row of RETENTION_MATRIX_EVIDENCE) {
      expect(
        row.tables.length,
        `retention-matrix row "${row.matrixRow}" must map to schema table names`,
      ).toBeGreaterThan(0);
    }

    // Every matrix table that exists in schema is cascade-protected.
    const matrixNames = new Set(
      RETENTION_MATRIX_EVIDENCE.flatMap((r) => [...r.tables]),
    );
    for (const ex of EVIDENCE_TABLE_EXCLUSIONS) matrixNames.delete(ex.table);
    const presentProtected = [...matrixNames].filter((t) => model.tables.has(t));
    expect(presentProtected.length).toBeGreaterThan(10);
    for (const t of presentProtected) {
      expect(derived, `schema table ${t} from must be in evidence set`).toContain(t);
    }

    // Manifest retentionClass permanent/evidence nouns must also be covered.
    for (const n of NORMATIVE_NOUNS) {
      if (!n.retentionClass) continue;
      if (!/permanent|verbatim|exact-content|evidence|blessing|lease group history/i.test(n.retentionClass)) {
        continue;
      }
      for (const s of n.satisfiers) {
        if (!s.startsWith("table:")) continue;
        const t = s.slice("table:".length);
        if (EVIDENCE_TABLE_EXCLUSIONS.some((e) => e.table === t)) continue;
        expect(derived, `${n.id} retentionClass → ${t}`).toContain(t);
      }
    }

    // Tables previously omitted from the hand list (A2 sample) must be present when in schema.
    for (const t of ["destinations", "operations", "lease_groups", "wallets", "vault"]) {
      if (model.tables.has(t)) expect(derived).toContain(t);
    }
  });

  it("SPEC_TABLE_DISPOSITIONS covers every governing CREATE TABLE (A1/B1 drift guard)", () => {
    const docTables = new Set<string>();
    for (const doc of GOVERNING_DOCS) {
      const text = readFileSync(resolve(repoRoot, doc.relativePath), "utf8");
      for (const name of extractCreateTableNames(text)) docTables.add(name);
    }
    const dispositioned = new Set(SPEC_TABLE_DISPOSITIONS.map((d) => d.table.toLowerCase()));
    // Set equality — peer of migration-integrity SCHEMA_FILES guard.
    expect([...dispositioned].sort()).toEqual([...docTables].sort());

    const deferred = SPEC_TABLE_DISPOSITIONS.filter((d) => d.disposition === "deferred");
    // Remaining open stores after main landed approval + verification + lineage DDL.
    // lineage_path_proofs/bodies promoted to required; deferred floor is the
    // remaining observation_relationship_adjudications (+ any later deferred rows).
    expect(deferred.length).toBeGreaterThanOrEqual(1);
    for (const d of deferred) {
      expect(d.authority && d.authority.length >= 8, `${d.table} deferred needs authority`).toBe(
        true,
      );
      expect(model.tables.has(d.table), `${d.table} deferred but present — promote to required`).toBe(
        false,
      );
    }

    // Previously invisible tables must be dispositioned (required or deferred).
    for (const t of [
      "receive_codes",
      "receive_arms",
      "receive_release_proofs",
      "approval_challenges",
      "operation_approvals",
      "operation_landing_proofs",
      "lineage_path_proofs",
      "lineage_path_bodies",
      "observation_relationship_adjudications",
      "operation_verifications",
      "verification_acknowledgements",
      "verification_ack_wallet_evidence",
    ]) {
      expect(dispositioned.has(t), t).toBe(true);
    }
    // Landed on main via approval-stores / verification-proofs — must be required.
    for (const t of [
      "approval_challenges",
      "operation_approvals",
      "operation_landing_proofs",
      "lineage_path_proofs",
      "lineage_path_bodies",
      "operation_verifications",
      "verification_acknowledgements",
      "verification_ack_wallet_evidence",
    ]) {
      const row = SPEC_TABLE_DISPOSITIONS.find((d) => d.table === t);
      expect(row?.disposition, t).toBe("required");
      expect(model.tables.has(t), t).toBe(true);
    }
  });

  it("committed report artifact matches the live census (regenerate on drift)", () => {
    // Fail closed on missing artifact — only `check-schema-census.mjs --write-report` may write.
    const rendered = `${JSON.stringify(report, null, 2)}\n`;
    let committed: string;
    try {
      committed = readFileSync(CENSUS_REPORT_PATH, "utf8");
    } catch (err) {
      const code =
        err && typeof err === "object" && "code" in err
          ? (err as NodeJS.ErrnoException).code
          : undefined;
      if (code === "ENOENT") {
        throw new Error(
          "schema-census.report.json missing — run: node scripts/check-schema-census.mjs --write-report",
        );
      }
      throw err;
    }
    expect(
      committed,
      "schema-census.report.json is stale — run: node scripts/check-schema-census.mjs --write-report and commit",
    ).toBe(rendered);
  });
});

describe("negative-path assertions (one per failure class)", () => {
  const baseSql = loadSchemaDir(schemaDir);

  const allProducers = (): Set<string> => {
    const producers = new Set<string>();
    for (const t of model.tables.keys()) producers.add(t.toLowerCase());
    return producers;
  };

  it("missing_store: dropping destination_blessing_artifacts fails the blessing noun", () => {
    const mutated = new Map(baseSql);
    const signer = mutated.get("signer-support.sql") ?? "";
    const stripped = signer
      .replace(
        /CREATE TABLE destination_blessing_artifacts \([\s\S]*?\);/,
        "-- removed for negative-path",
      )
      .replace(
        /ALTER TABLE destinations[\s\S]*?REFERENCES destination_blessing_artifacts \(id\);/,
        "-- removed fk",
      );
    mutated.set("signer-support.sql", stripped);

    const result = buildCensusFromSql(mutated);
    const misses = result.report.failures.filter((f) => f.class === "missing_store");
    expect(misses.length).toBeGreaterThan(0);
    expect(
      misses.some(
        (f) =>
          f.id === "gap.destinations-blessing-artifact-fk-target" ||
          f.id === "node-scope.blessing-artifacts",
      ),
      JSON.stringify(misses),
    ).toBe(true);
    expect(result.ok).toBe(false);
  });

  it("missing_store: dropping subscription_handles fails the required noun (B1)", () => {
    const mutated = new Map(baseSql);
    mutated.delete("session-subscription-stores.sql");
    // Also strip if inlined elsewhere
    for (const [name, sql] of [...mutated.entries()]) {
      if (sql.includes("CREATE TABLE subscription_handles")) {
        mutated.set(
          name,
          sql.replace(/CREATE TABLE subscription_handles \([\s\S]*?;\s*(?:CREATE INDEX[\s\S]*?;\s*)*/m, "-- removed sub handles\n"),
        );
      }
    }
    const result = buildCensusFromSql(mutated);
    const miss = result.report.failures.find(
      (f) => f.class === "missing_store" && f.id === "node-scope.subscription-handles",
    );
    expect(miss, "subscription-handles must fail as missing_store when table absent").toBeTruthy();
    expect(result.ok).toBe(false);
  });

  it("orphan_fk producer arm: FK target without producer and without exemption fails (B3)", () => {
    const mutated = new Map(baseSql);
    mutated.set(
      "_negative_no_producer.sql",
      `
      CREATE TABLE producer_orphan_target (
        id uuid PRIMARY KEY
      );
      CREATE TABLE producer_orphan_source (
        id uuid PRIMARY KEY,
        target_id uuid NOT NULL REFERENCES producer_orphan_target (id)
      );
      `,
    );
    const producers = allProducers();
    producers.add("producer_orphan_source");
    // deliberately do NOT add producer_orphan_target
    producers.delete("producer_orphan_target");
    const result = buildCensusFromSql(mutated, {
      producerTables: producers,
      producerExemptTables: new Set(), // no exemptions
    });
    const orphans = result.report.failures.filter((f) => f.class === "orphan_fk");
    expect(
      orphans.some(
        (f) =>
          f.detail.includes("producer_orphan_target") &&
          f.detail.includes("no INSERT producer"),
      ),
      JSON.stringify(orphans),
    ).toBe(true);
    expect(result.ok).toBe(false);
  });

  it("orphan_fk: REFERENCES to a non-existent table is caught", () => {
    const mutated = new Map(baseSql);
    mutated.set(
      "_negative_orphan.sql",
      `
      CREATE TABLE orphan_source (
        id uuid PRIMARY KEY,
        target_id uuid NOT NULL REFERENCES totally_missing_table (id)
      );
      `,
    );
    const producers = allProducers();
    producers.add("orphan_source");
    const result = buildCensusFromSql(mutated, { producerTables: producers });
    const orphans = result.report.failures.filter((f) => f.class === "orphan_fk");
    expect(
      orphans.some((f) => f.detail.includes("totally_missing_table")),
      JSON.stringify(orphans),
    ).toBe(true);
    expect(result.ok).toBe(false);
  });

  it("orphan_fk: FK target column that does not exist is caught", () => {
    const mutated = new Map(baseSql);
    mutated.set(
      "_negative_orphan_col.sql",
      `
      CREATE TABLE orphan_col_source (
        id uuid PRIMARY KEY,
        wallet_ref uuid NOT NULL REFERENCES wallets (no_such_column)
      );
      `,
    );
    const producers = allProducers();
    producers.add("orphan_col_source");
    producers.add("wallets");
    const result = buildCensusFromSql(mutated, { producerTables: producers });
    const orphans = result.report.failures.filter((f) => f.class === "orphan_fk");
    expect(
      orphans.some((f) => f.detail.includes("no_such_column")),
      JSON.stringify(orphans),
    ).toBe(true);
  });

  it("unsafe_cascade: ON DELETE CASCADE into an evidence table fails", () => {
    const mutated = new Map(baseSql);
    mutated.set(
      "_negative_cascade.sql",
      `
      CREATE TABLE cascade_parent (
        id uuid PRIMARY KEY
      );
      CREATE TABLE cascade_child_evidence (
        id uuid PRIMARY KEY,
        parent_id uuid NOT NULL REFERENCES cascade_parent (id) ON DELETE CASCADE
      );
      `,
    );
    const evidence = [...EVIDENCE_TABLES, "cascade_child_evidence"];
    const producers = allProducers();
    producers.add("cascade_parent");
    producers.add("cascade_child_evidence");
    const result = buildCensusFromSql(mutated, {
      evidenceTables: evidence,
      producerTables: producers,
    });
    const cascades = result.report.failures.filter((f) => f.class === "unsafe_cascade");
    expect(
      cascades.some(
        (f) =>
          f.detail.includes("ON DELETE CASCADE") &&
          f.detail.includes("cascade_child_evidence"),
      ),
      JSON.stringify(cascades),
    ).toBe(true);
    expect(result.ok).toBe(false);
  });

  it("unsafe_cascade: definition-sensitive — CASCADE on a real evidence FK is caught", () => {
    const mutated = new Map(baseSql);
    const signer = mutated.get("signer-support.sql") ?? "";
    expect(signer).toContain("destination_blessing_artifacts");
    const withCascade = signer.replace(
      /FOREIGN KEY \(blessing_artifact_id\)\s*REFERENCES destination_blessing_artifacts \(id\);/,
      "FOREIGN KEY (blessing_artifact_id) REFERENCES destination_blessing_artifacts (id) ON DELETE CASCADE;",
    );
    expect(withCascade).not.toBe(signer);
    mutated.set("signer-support.sql", withCascade);
    const result = buildCensusFromSql(mutated);
    const cascades = result.report.failures.filter((f) => f.class === "unsafe_cascade");
    expect(
      cascades.some((f) => f.detail.includes("destination_blessing_artifacts")),
      JSON.stringify(cascades),
    ).toBe(true);
  });

  it("unindexed_query: access pattern without a covering index fails", () => {
    const result = buildCensus({
      accessPatterns: [
        ...WORKER_ACCESS_PATTERNS,
        {
          id: "neg.unindexed-hot-col",
          table: "operations",
          columns: ["attention_reason"],
          source: "synthetic negative-path pattern",
        },
      ],
    });
    const unindexed = result.report.failures.filter((f) => f.class === "unindexed_query");
    expect(
      unindexed.some((f) => f.id === "neg.unindexed-hot-col"),
      JSON.stringify(unindexed),
    ).toBe(true);
    expect(result.ok).toBe(false);
  });

  it("indexCovers requires leading-column agreement (unit)", () => {
    const idx = {
      sourceFile: "t.sql",
      name: "t_idx",
      table: "t",
      columns: ["a", "b"],
      unique: false,
      definition: "CREATE INDEX t_idx ON t (a, b)",
    };
    expect(indexCovers(idx, ["a"])).toBe(true);
    expect(indexCovers(idx, ["a", "b"])).toBe(true);
    expect(indexCovers(idx, ["b"])).toBe(false);
    expect(indexCovers(idx, ["a", "c"])).toBe(false);
  });

  it("ddl parser captures ON DELETE CASCADE action text", () => {
    const model2 = parseSchemaFromMap(
      new Map([
        [
          "t.sql",
          `CREATE TABLE parent (id uuid PRIMARY KEY);
           CREATE TABLE child (
             id uuid PRIMARY KEY,
             parent_id uuid REFERENCES parent (id) ON DELETE CASCADE ON UPDATE RESTRICT
           );`,
        ],
      ]),
    );
    expect(model2.foreignKeys).toHaveLength(1);
    expect(model2.foreignKeys[0]?.onDelete).toBe("CASCADE");
    expect(model2.foreignKeys[0]?.onUpdate).toBe("RESTRICT");
  });

  it("undispositioned_spec_table: CREATE TABLE in governing docs with no catalog row fails (Probe 2 / A1)", () => {
    // Simulate Probe 2: a new CREATE TABLE appears in 04 without a disposition row.
    const docTexts = new Map<string, string>([
      [
        "packages/node-core/test/data-model.fixture.md",
        "x".repeat(120) +
          "\nCREATE TABLE probe_spec_only (\n  id uuid PRIMARY KEY\n);\n",
      ],
    ]);
    const result = checkSpecTableDispositions(model, docTexts, SPEC_TABLE_DISPOSITIONS);
    expect(
      result.failures.some(
        (f) =>
          f.class === "undispositioned_spec_table" &&
          f.detail.includes("probe_spec_only"),
      ),
      JSON.stringify(result.failures),
    ).toBe(true);
  });

  it("missing_store: required disposition with absent schema table fails", () => {
    const dispositions = [
      ...SPEC_TABLE_DISPOSITIONS,
      {
        table: "required_but_absent_probe",
        disposition: "required" as const,
        section: "probe",
      },
    ];
    const docTexts = new Map<string, string>([
      [
        "packages/node-core/test/data-model.fixture.md",
        "x".repeat(120) +
          "\n" +
          // Include every dispositioned table name so stale_spec_disposition does not fire,
          // plus the probe table.
          SPEC_TABLE_DISPOSITIONS.map((d) => `CREATE TABLE ${d.table} (id int);`).join("\n") +
          "\nCREATE TABLE required_but_absent_probe (id int);\n",
      ],
    ]);
    const result = checkSpecTableDispositions(model, docTexts, dispositions);
    expect(
      result.failures.some(
        (f) =>
          f.class === "missing_store" && f.detail.includes("required_but_absent_probe"),
      ),
      JSON.stringify(result.failures),
    ).toBe(true);
  });

  it("unsafe_cascade: CASCADE on destinations (A2-protected table) fails", () => {
    const mutated = new Map(baseSql);
    mutated.set(
      "_negative_dest_cascade.sql",
      `
      CREATE TABLE destinations_cascade_child (
        id uuid PRIMARY KEY,
        destination_id uuid NOT NULL REFERENCES destinations (id) ON DELETE CASCADE
      );
      `,
    );
    const producers = allProducers();
    producers.add("destinations_cascade_child");
    producers.add("destinations");
    const result = buildCensusFromSql(mutated, { producerTables: producers });
    const cascades = result.report.failures.filter((f) => f.class === "unsafe_cascade");
    expect(
      cascades.some((f) => f.detail.includes("destinations")),
      JSON.stringify(cascades),
    ).toBe(true);
    expect(result.ok).toBe(false);
  });
});

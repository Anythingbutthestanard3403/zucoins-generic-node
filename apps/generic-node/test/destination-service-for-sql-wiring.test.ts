// Regression guard: full-http-mount.ts consumes
// `config.destinationServiceForSql?.(client) ?? createFailClosedDestinationService()`
// inside the atomic admin mutation executor's portsFor, but no caller supplied
// destinationServiceForSql — production bless/retire silently fell back to the
// fail-closed service and threw inside the tx, turning into a permanent 503.
// This guards main.ts's wiring so that regression can't land silently again.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const mainSrc = readFileSync(join(here, "../src/main.ts"), "utf8");

describe("destinationServiceForSql production wiring", () => {
  it("createProductionRouteSurface receives a destinationServiceForSql factory", () => {
    expect(mainSrc).toContain("destinationServiceForSql:");
  });

  it("the factory rebinds the SQL store to the tx client, not the outer pool", () => {
    const region = mainSrc.slice(
      mainSrc.indexOf("destinationServiceForSql:"),
      mainSrc.indexOf("destinationServiceForSql:") + 400,
    );
    // Must construct a DestinationService per invocation using the callback's own
    // `client` argument — never fall through to the pool-bound store or a stub.
    expect(region).toMatch(/\(client\)\s*=>/);
    expect(region).toContain("createSqlDestinationStore(client)");
    expect(region).not.toContain("createSqlDestinationStore(pool)");
  });

  it("binds the device-blessing authorizer PER-CLIENT so bless is one transaction", () => {
    // The prior assertion here demanded a single SHARED authorizer instance — that
    // inverts the fix. authorize's artifact-insert + audit-append run on the
    // authorizer's bound sql executor; if that stays pool-bound while store.bless() runs
    // on the tx client, bless commits across two connections, a post-action rollback
    // orphans the single-use nonce artifact, and a same-nonce retry is stuck on
    // nonce_reused. main.ts must rebind the authorizer to each sql executor via a helper.
    expect(mainSrc).toMatch(/const blessingAuthorizerForSql\s*=\s*\(sql[^)]*\)\s*=>/);
    const helper = mainSrc.slice(
      mainSrc.indexOf("blessingAuthorizerForSql ="),
      mainSrc.indexOf("blessingAuthorizerForSql =") + 400,
    );
    // The helper rebinds ALL THREE device ports to its own `sql` argument — the tx
    // client reaches persistArtifact and appendAudit, not just the store.
    expect(helper).toContain("createSqlActiveDeviceLookup(sql)");
    expect(helper).toContain("createSqlBlessingArtifactPersister(sql)");
    expect(helper).toContain("createSqlBlessingAuditAppender(sql)");
    // The tx-client factory passes its own `client` into the authorizer helper — never a
    // pre-built pool-bound authorizer.
    const region = mainSrc.slice(
      mainSrc.indexOf("destinationServiceForSql:"),
      mainSrc.indexOf("destinationServiceForSql:") + 500,
    );
    expect(region).toContain("blessingAuthorizerForSql(client)");
    // The wallet key generator stays a single shared construction: bless/retire never
    // call it, and register's node-key generation is pool-scoped by design.
    const keyGenConstructions = mainSrc.match(/(?<!function )createNodeGeneratedWalletKeyGenerator\(/g) ?? [];
    expect(keyGenConstructions).toHaveLength(1);
  });

  it("never resolves destinationServiceForSql to only the fail-closed stub", () => {
    const region = mainSrc.slice(
      mainSrc.indexOf("destinationServiceForSql:"),
      mainSrc.indexOf("destinationServiceForSql:") + 400,
    );
    expect(region).not.toContain("createFailClosedDestinationService");
  });
});

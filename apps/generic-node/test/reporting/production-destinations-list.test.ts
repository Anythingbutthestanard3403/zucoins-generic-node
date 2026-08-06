// Live destinations_list on the signed reporting credential.
//
// Dual auth: `destination:read` OR signed reporting credential; tenant-scoped
// `items` + `next_after`; derived `move_eligible` / `ineligibility_reason`.
//
// Part A (no PG): the F5 census marks the engine LIVE only when the mounted handler is not
// the fail-closed port. Part B (real PG): the reporting page is byte-identical to the
// implementer-bearer page over the same rows, and a credential bound to another node
// collapses to an empty page.

import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client, Pool } from "pg";

import {
  createDestinationService,
  createSqlDestinationStore,
  handleListDestinations,
  REPORTING_ROUTE_IDS,
  type DestinationService,
  type ProofBodyStore,
  type VerificationAccessWindowStore,
} from "@zucoins/node-core";

import {
  createProductionRouteSurface,
  LIVE_DESTINATIONS_LIST_ENGINE,
} from "../../src/full-http-mount.js";
import { createLiveReportingReads } from "../../src/reporting/live-reporting-reads.js";
import type { ReportingHandlerResult } from "@zucoins/node-core";

const NODE_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const NODE_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const IMPLEMENTER_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

const stubPool = () =>
  ({
    query: async () => ({ rows: [] }),
    connect: async () => ({
      query: async () => ({ rows: [] }),
      release: () => {},
    }),
  }) as never;

// createLiveReportingReads now requires durable proofBodyStore/verificationAccessStore
// ports. None of the destinations_list scenarios below exercise verification_material, so these
// mirror the lightweight fakes in reporting/durable-security-ports.pg.test.ts rather than wiring
// real SQL-backed instances.
const fakeProofBodyStore = { findByPathProof: async () => [] } as unknown as ProofBodyStore;
const fakeVerificationAccessStore = {} as VerificationAccessWindowStore;

/** Only `list` is exercised; the write ports throw so an accidental mutation is loud. */
function serviceOverPool(pool: Pool): DestinationService {
  return createDestinationService({
    store: createSqlDestinationStore({
      query: async <R extends Record<string, unknown>>(
        text: string,
        params?: readonly unknown[],
      ) => {
        const result = await pool.query(text, (params ?? []) as unknown[]);
        return { rows: result.rows as R[] };
      },
    }),
    keyGenerator: {
      generate: async () => {
        throw new Error("destinations-list read test never mints wallets");
      },
    },
    blessingAuthorizer: {
      authorize: async () => {
        throw new Error("destinations-list read test never blesses");
      },
    },
    clock: { now: () => new Date().toISOString() },
    ids: { destinationId: () => randomUUID() as never },
  });
}

function verifiedRequest(nodeId: string, rawTarget: string): never {
  return {
    ok: true,
    binding: {
      reportingKeyId: randomUUID(),
      nodeId,
      implementerId: IMPLEMENTER_ID,
      publicKeyEncoded: "AAAA",
    },
    route: {
      routeId: REPORTING_ROUTE_IDS.destinationsList,
      requestClass: "READ",
      retentionClass: "READ_NO_PRUNE_UNTIL_SAFETY_FREEZE",
    },
    nonceEvidence: {},
    idempotencyKey: null,
    fingerprint: { method: "GET", rawTarget, bodySha256: "00".repeat(32) },
    bodyBytes: new Uint8Array(),
    lastEventId: null,
  } as never;
}

const decode = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

describe("destinations_list composition census (no PG)", () => {
  it("AC3: engine is absent from the census while the route maps to fail-closed", () => {
    const surface = createProductionRouteSurface({
      nodeId: NODE_A,
      pool: stubPool(),
      env: {},
      proofBodyStore: fakeProofBodyStore,
      verificationAccessStore: fakeVerificationAccessStore,
    });
    // No DestinationService injected → createFailClosedDestinationService() placeholder,
    // whose list() throws, so the route must stay on the fail-closed port.
    expect(surface.liveReportingEngines.map((engine) => engine.routeId)).not.toContain(
      LIVE_DESTINATIONS_LIST_ENGINE.routeId,
    );
  });

  it("AC3: engine appears once a real DestinationService is composed", () => {
    const surface = createProductionRouteSurface({
      nodeId: NODE_A,
      pool: stubPool(),
      env: {},
      proofBodyStore: fakeProofBodyStore,
      verificationAccessStore: fakeVerificationAccessStore,
      destinationService: {
        list: async () => ({ items: [], nextAfter: null }),
        get: async () => null,
        register: async () => {
          throw new Error("unused");
        },
        bless: async () => {
          throw new Error("unused");
        },
        retire: async () => {
          throw new Error("unused");
        },
      } as never,
    });
    expect(surface.liveReportingEngines.map((engine) => engine.routeId)).toContain(
      LIVE_DESTINATIONS_LIST_ENGINE.routeId,
    );
    expect(LIVE_DESTINATIONS_LIST_ENGINE.routeId).toBe(REPORTING_ROUTE_IDS.destinationsList);
  });

  it("AC3: production source no longer pins destinations_list to config.failClosed", () => {
    const liveSrc = readFileSync(
      fileURLToPath(new URL("../../src/reporting/live-reporting-reads.ts", import.meta.url)),
      "utf8",
    );
    expect(liveSrc).not.toMatch(
      /\[REPORTING_ROUTE_IDS\.destinationsList\]:[ \t]*config\.failClosed/,
    );
    expect(liveSrc).toMatch(/createDestinationsListRouteHandler/);
    const mountSrc = readFileSync(
      fileURLToPath(new URL("../../src/full-http-mount.ts", import.meta.url)),
      "utf8",
    );
    expect(mountSrc).toMatch(
      /\[REPORTING_ROUTE_IDS\.destinationsList,\s*LIVE_DESTINATIONS_LIST_ENGINE\]/,
    );
  });

  it("the credential gate still holds: unsigned GET /v1/destinations is 401", async () => {
    const surface = createProductionRouteSurface({
      nodeId: NODE_A,
      pool: stubPool(),
      env: {},
      proofBodyStore: fakeProofBodyStore,
      verificationAccessStore: fakeVerificationAccessStore,
    });
    const response = await surface.reportingHandle({
      method: "GET",
      rawTarget: "/v1/destinations",
      rawHeaders: [],
      bodyBytes: new Uint8Array(),
      receivedAtMs: Date.now(),
    });
    expect(response.status).toBe(401);
    expect(JSON.parse(decode(response.bodyBytes)).error.code).toBe("missing_reporting_headers");
  });

  it("adversarial fix: throwing service returns internal_error", async () => {
    const liveReads = createLiveReportingReads({
      pool: stubPool(),
      nodeId: NODE_A,
      newRequestId: () => "req-adv",
      nowMs: () => Date.now(),
      failClosed: async () => { throw new Error("fail-closed must not be reached"); },
      liveArm: async () => { throw new Error("arm not used"); },
      proofBodyStore: fakeProofBodyStore,
      verificationAccessStore: fakeVerificationAccessStore,
      destinationService: {
        list: async () => { throw new Error("simulated DB connection drop"); },
        get: async () => null,
        register: async () => { throw new Error("unused"); },
        bless: async () => { throw new Error("unused"); },
        retire: async () => { throw new Error("unused"); },
      } as never,
    });
    const handler = liveReads.handlers[REPORTING_ROUTE_IDS.destinationsList] as never;
    const response = await handler(verifiedRequest(NODE_A, "/v1/destinations") as never);
    expect(response.response.status).toBe(500);
    expect(JSON.parse(decode(response.response.bodyBytes)).error.code).toBe("internal_error");
  });

  it("adversarial fix: invalid query params are rejected", async () => {
    const liveReads = createLiveReportingReads({
      pool: stubPool(),
      nodeId: NODE_A,
      newRequestId: () => "req-adv2",
      nowMs: () => Date.now(),
      failClosed: async () => { throw new Error("fail-closed must not be reached"); },
      liveArm: async () => { throw new Error("arm not used"); },
      proofBodyStore: fakeProofBodyStore,
      verificationAccessStore: fakeVerificationAccessStore,
      destinationService: {
        list: async () => ({ items: [], nextAfter: null }),
        get: async () => null,
        register: async () => { throw new Error("unused"); },
        bless: async () => { throw new Error("unused"); },
        retire: async () => { throw new Error("unused"); },
      } as never,
    });
    const handler = liveReads.handlers[REPORTING_ROUTE_IDS.destinationsList] as never;
    // limit=0 is invalid (must be 1-100)
    const resp1 = await handler(verifiedRequest(NODE_A, "/v1/destinations?limit=0") as never);
    expect(resp1.response.status).toBeGreaterThanOrEqual(400);
    // limit=999 is invalid (must be 1-100)
    const resp2 = await handler(verifiedRequest(NODE_A, "/v1/destinations?limit=999") as never);
    expect(resp2.response.status).toBeGreaterThanOrEqual(400);
    // state=INVALID is not a valid destination_state enum
    const resp3 = await handler(verifiedRequest(NODE_A, "/v1/destinations?state=INVALID") as never);
    expect(resp3.response.status).toBeGreaterThanOrEqual(400);
  });
});

// ---------------------------------------------------------------------------
// Real PG: the live page over real destinations/wallets rows
// ---------------------------------------------------------------------------

const PG_HOST = process.env.PGHOST ?? "127.0.0.1";
const PG_PORT = Number(process.env.PGPORT ?? "5432");
const PG_USER = process.env.PGUSER ?? process.env.USER ?? "postgres";

function hasClientTool(name: string): boolean {
  try {
    execFileSync(name, ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const adminClientConfig = (database: string) => ({
  host: PG_HOST,
  port: PG_PORT,
  user: PG_USER,
  database,
  password: process.env.PGPASSWORD,
});

const PG_AVAILABLE = (() => {
  // Review fix: use the repo's standard PG harness pattern (try pg_isready
  // AND a direct TCP connection) instead of ambient pg_isready alone.
  try {
    if (hasClientTool("pg_isready")) {
      execFileSync("pg_isready", ["-q", "-h", PG_HOST, "-p", String(PG_PORT), "-U", PG_USER], {
        stdio: "ignore",
      });
      return true;
    }
  } catch {
    /* fall through to TCP probe */
  }
  try {
    execFileSync(
      "node",
      [
        "-e",
        `const {Client}=require("pg");const c=new Client({host:${JSON.stringify(PG_HOST)},port:${PG_PORT},user:${JSON.stringify(PG_USER)},database:"postgres",password:process.env.PGPASSWORD,connectionTimeoutMillis:1500});c.connect().then(()=>c.end()).then(()=>process.exit(0)).catch(()=>process.exit(1))`,
      ],
      { stdio: "ignore", env: process.env },
    );
    return true;
  } catch {
    return false;
  }
})();

function pgDatabaseUrl(dbName: string): string {
  const auth = process.env.PGPASSWORD
    ? `${encodeURIComponent(PG_USER)}:${encodeURIComponent(process.env.PGPASSWORD)}`
    : encodeURIComponent(PG_USER);
  const host = PG_HOST === "/tmp" ? "localhost" : PG_HOST;
  return `postgres://${auth}@${host}:${PG_PORT}/${dbName}`;
}

const uniquePubkey = (): string => `${randomUUID().replace(/-/g, "")}AAAAAAAAAAA=`;

describe("live destinations_list page (real PG)", () => {
  const dbName = `prod_destinations_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
  let pool: Pool;
  let service: DestinationService;
  let handler: (request: never) => Promise<ReportingHandlerResult>;
  let priorDatabaseUrl: string | undefined;
  const seeded: { id: string; state: string; eligible: boolean }[] = [];

  // Review fix: fail closed when PG is not available — the acceptance criteria
  // require real-PostgreSQL evidence; silently skipping them is a false green.
  beforeAll(() => {
    if (!PG_AVAILABLE) {
      throw new Error(
        "AC1/AC2 require a real PostgreSQL — set PGHOST/PGPORT/PGUSER/PGPASSWORD or install pg_isready. " +
          "Tests fail closed rather than silently skipping.",
      );
    }
  }, 10_000);

  beforeAll(async () => {
    const admin = new Client(adminClientConfig("postgres"));
    await admin.connect();
    try {
      await admin.query(`CREATE DATABASE ${dbName}`);
    } finally {
      await admin.end();
    }
    pool = new Pool({
      host: PG_HOST,
      port: PG_PORT,
      user: PG_USER,
      database: dbName,
      password: process.env.PGPASSWORD,
    });
    // options.databaseUrl below is what runMigrationsOnPool actually uses; DATABASE_URL is set
    // here only so other code paths in this suite that read it directly stay consistent.
    const url = pgDatabaseUrl(dbName);
    priorDatabaseUrl = process.env.DATABASE_URL;
    process.env.DATABASE_URL = url;
    const { runMigrationsOnPool } = await import("../../src/db/migrate.js");
    await runMigrationsOnPool(pool, { databaseUrl: url });

    // Real DDL, real trigger guards: destinations_custody_insert_guard only admits a
    // node_generated wallet, so nothing here is force-fed past predicate 2.
    for (const nodeId of [NODE_A, NODE_B]) {
      await pool.query(
        `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ($1, $2, $3)`,
        [nodeId, `prod-destinations-${nodeId.slice(0, 4)}`, uniquePubkey()],
      );
    }

    // Node A: PENDING, BLESSED (recovery-verified → move_eligible), RETIRED.
    // Node B: one BLESSED row that must never appear on a node-A page.
    const rows = [
      { nodeId: NODE_A, state: "PENDING", recovery: false },
      { nodeId: NODE_A, state: "BLESSED", recovery: true },
      { nodeId: NODE_A, state: "RETIRED", recovery: false },
      { nodeId: NODE_B, state: "BLESSED", recovery: true },
    ] as const;

    for (const row of rows) {
      const walletId = randomUUID();
      const destinationId = randomUUID();
      await pool.query(
        `INSERT INTO wallets (id, node_id, public_key, key_origin, state)
         VALUES ($1, $2, $3, 'node_generated', 'AVAILABLE')`,
        [walletId, row.nodeId, uniquePubkey()],
      );
      if (row.recovery) {
        const verificationId = randomUUID();
        await pool.query(
          `INSERT INTO wallet_recovery_verifications
             (id, wallet_id, method, public_key, export_sha256, audit_event_id,
              verified_at, verifier_identity)
           VALUES ($1, $2, 'AUDITED_EXPORT',
                   (SELECT public_key FROM wallets WHERE id = $2),
                   $3, $4, now(), 'prod-destinations-operator')`,
          [verificationId, walletId, "ab".repeat(32), randomUUID()],
        );
        await pool.query(
          `UPDATE wallets
              SET recovery_verified_at = now(), recovery_verification_id = $2
            WHERE id = $1`,
          [walletId, verificationId],
        );
      }
      const blessed = row.state === "BLESSED" || row.state === "RETIRED";
      let artifactId: string | null = null;
      if (blessed) {
        // destinations_blessing_artifact_fk is real: a blessed row needs the A.4.2
        // ceremony artifact, so seed one rather than loosening the constraint.
        artifactId = randomUUID();
        await pool.query(
          `INSERT INTO destination_blessing_artifacts
             (id, purpose, canonical_version, node_id, destination_id, wallet_id,
              wallet_pubkey, nonce, issued_at, expires_at, device_signature,
              preimage_text, preimage_sha256, created_at)
           VALUES ($1, 'zp-destination-bless-v1', 1, $2, $3, $4,
                   (SELECT public_key FROM wallets WHERE id = $4), $5,
                   now(), now() + interval '60 seconds', $6,
                   'prod-destinations-bless-preimage', $7, now())`,
          [
            artifactId,
            row.nodeId,
            destinationId,
            walletId,
            randomUUID(),
            `${"A".repeat(86)}==`,
            "cd".repeat(32),
          ],
        );
      }
      await pool.query(
        `INSERT INTO destinations
           (id, node_id, wallet_id, state, blessed_at,
            blessed_by_device_key_id, blessing_artifact_id, retired_at)
         VALUES ($1, $2, $3, $4::destination_state,
                 CASE WHEN $5 THEN now() ELSE NULL END,
                 CASE WHEN $5 THEN $6::uuid ELSE NULL END,
                 CASE WHEN $5 THEN $7::uuid ELSE NULL END,
                 CASE WHEN $4 = 'RETIRED' THEN now() ELSE NULL END)`,
        [destinationId, row.nodeId, walletId, row.state, blessed, randomUUID(), artifactId],
      );
      if (row.nodeId === NODE_A) {
        seeded.push({
          id: destinationId,
          state: row.state,
          eligible: row.state === "BLESSED" && row.recovery,
        });
      }
    }

    service = serviceOverPool(pool);
    // Production composition path — the same factory createProductionRouteSurface calls.
    const liveReads = createLiveReportingReads({
      pool,
      nodeId: NODE_A,
      newRequestId: () => "req-957",
      nowMs: () => Date.now(),
      failClosed: async () => {
        throw new Error("fail-closed port must not be reached with a live service");
      },
      liveArm: async () => {
        throw new Error("arm not used");
      },
      proofBodyStore: fakeProofBodyStore,
      verificationAccessStore: fakeVerificationAccessStore,
      destinationService: service,
    });
    expect(liveReads.liveEngines.map((engine) => engine.routeId)).toContain(
      REPORTING_ROUTE_IDS.destinationsList,
    );
    handler = liveReads.handlers[REPORTING_ROUTE_IDS.destinationsList] as never;
  }, 300_000);

  afterAll(async () => {
    if (priorDatabaseUrl === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = priorDatabaseUrl;
    await pool?.end();
    const admin = new Client(adminClientConfig("postgres"));
    await admin.connect();
    try {
      await admin.query(
        `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
        [dbName],
      );
      await admin.query(`DROP DATABASE IF EXISTS ${dbName}`);
    } finally {
      await admin.end();
    }
  }, 60_000);

  async function bearerBody(query: Record<string, string>): Promise<string> {
    const result = await handleListDestinations(
      {
        requestId: "req-bearer",
        principal: { implementerId: IMPLEMENTER_ID },
        request: { query, headers: {} },
      } as never,
      { service, nodeId: NODE_A as never },
    );
    expect(result.ok).toBe(true);
    return (result as { readonly body: string }).body;
  }

  it("AC1: reporting page byte-equals the implementer page for the same tenant/node", async () => {
    const response = await handler(verifiedRequest(NODE_A, "/v1/destinations") as never);
    expect(response.response.status).toBe(200);
    expect(response.persistChild).toBeNull();
    const text = decode(response.response.bodyBytes);
    expect(text).toBe(await bearerBody({}));

    const page = JSON.parse(text) as {
      items: { destinationId: string; state: string; move_eligible: boolean; walletPublicKey: string }[];
      next_after: string | null;
    };
    // Node A's three rows, and never node B's.
    expect(page.items).toHaveLength(3);
    expect(page.items.map((row) => row.destinationId).sort()).toEqual(
      seeded.map((row) => row.id).sort(),
    );
    // Derived eligibility survives the reporting page (move_eligible).
    const blessed = seeded.find((row) => row.state === "BLESSED")!;
    expect(page.items.find((row) => row.destinationId === blessed.id)?.move_eligible).toBe(true);
    expect(
      page.items.filter((row) => row.state !== "BLESSED").every((row) => !row.move_eligible),
    ).toBe(true);
    // Public material only — no private key / transfer code / reporting secret leaks.
    for (const needle of ["private_key", "transfer_code", "secret"]) {
      expect(text).not.toContain(needle);
    }
  });

  it("AC1: state filter and limit/next_after pagination match the implementer page", async () => {
    const filtered = await handler(
      verifiedRequest(NODE_A, "/v1/destinations?state=BLESSED") as never,
    );
    expect(decode(filtered.response.bodyBytes)).toBe(await bearerBody({ state: "BLESSED" }));

    const firstPage = await handler(verifiedRequest(NODE_A, "/v1/destinations?limit=1") as never);
    const firstText = decode(firstPage.response.bodyBytes);
    expect(firstText).toBe(await bearerBody({ limit: "1" }));
    const first = JSON.parse(firstText) as { items: unknown[]; next_after: string | null };
    expect(first.items).toHaveLength(1);
    expect(first.next_after).not.toBeNull();

    const secondPage = await handler(
      verifiedRequest(NODE_A, `/v1/destinations?limit=1&after=${first.next_after!}`) as never,
    );
    expect(decode(secondPage.response.bodyBytes)).toBe(
      await bearerBody({ limit: "1", after: first.next_after! }),
    );
  });

  it("AC2: a credential bound to node B never sees node A's rows", async () => {
    const response = await handler(verifiedRequest(NODE_B, "/v1/destinations") as never);
    expect(response.response.status).toBe(200);
    const page = JSON.parse(decode(response.response.bodyBytes)) as {
      items: { nodeId: string }[];
    };
    // Node B has exactly its own single row and none of node A's three.
    expect(page.items).toHaveLength(1);
    expect(page.items.every((row) => row.nodeId === NODE_B)).toBe(true);
  });

  it("AC2: a foreign `after` id collapses to an empty page, never a differentiated 404", async () => {
    const foreign = await pool.query<{ id: string }>(
      `SELECT id FROM destinations WHERE node_id = $1 LIMIT 1`,
      [NODE_B],
    );
    const foreignId = foreign.rows[0]!.id;
    // Node A's page keyed on node B's id: an opaque ordering bound, still 200, and only
    // node A rows sorting after it — never node B's row, never a 404 existence oracle.
    const response = await handler(
      verifiedRequest(NODE_A, `/v1/destinations?after=${foreignId}`) as never,
    );
    expect(response.response.status).toBe(200);
    const text = decode(response.response.bodyBytes);
    expect(text).toBe(await bearerBody({ after: foreignId }));
    const page = JSON.parse(text) as { items: { nodeId: string }[] };
    expect(page.items.every((row) => row.nodeId === NODE_A)).toBe(true);

    // An id belonging to no tenant at all is likewise a plain cursor, not an error.
    const unknown = await handler(
      verifiedRequest(NODE_A, `/v1/destinations?after=${randomUUID()}`) as never,
    );
    expect(unknown.response.status).toBe(200);
  });
});

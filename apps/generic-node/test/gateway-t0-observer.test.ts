// Real T0 OBSERVE offline fixtures (synthetic gateway, never live/submit).
//
// Proves:
//   AC1: resolveMoneyPathT0Observer with gatewayUrls does NOT use genesis stub
//   AC2: gateway-derived VERIFIED observation carries observationId + S/P/B (READY GET font)
//   AC3: offline synthetic get_transaction__v1 read path green; never submit_
//   D1/D4: durable write via stream writer — FIRST/SUCCESSOR/cursor/previous lineage
//   D2: empty gatewayUrls fail closed unless allowGenesisT0Stub
//   D3: VERIFIED_HEAD pathway with node-core settle golden + cursor advance
//   ARM 409: mismatch against durable T0 is documented as t0_mismatch (census on arm-route)
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";

import {
  GENESIS_PROJECTION,
  RECEIVE_T0_OBSERVATION_ROLE,
  STREAM_WRITER_SQL,
  fingerprintEndpoint,
  createMetricsHooks,
  createNodeMetrics,
  sha256Hex,
  toBase64UrlPadded,
  type GatewayExchangeCapture,
  type GatewayExchangeTransport,
  type GatewayRequest,
  type ReceiveT0Observation,
} from "@zucoins/node-core";

import { createGatewayT0Observer } from "../src/money-workers/gateway-t0-observer.js";
import { createSqlFreshHeadReader } from "../src/money-workers/sql-fresh-head-reader.js";
import { persistSqlObservation } from "../src/money-workers/sql-observation-persistence.js";
import {
  resolveMoneyPathT0Observer,
  startMoneyWorkers,
} from "../src/money-workers/start-money-workers.js";

const here = dirname(fileURLToPath(import.meta.url));
const GATEWAY_A = "https://gateway-a.test.invalid/";
const NODE_ID = "11111111-1111-4111-8111-111111111111";

const GEN_DIR = new URL(
  "../../../packages/generic-node-contracts/src/receive-golden/gen/",
  import.meta.url,
);

function fixtureText(name: string): string {
  return readFileSync(fileURLToPath(new URL(name, GEN_DIR)), "utf8");
}

const MANIFEST = JSON.parse(fixtureText("manifest.json")) as {
  public_keys: { seed_02: string; seed_03: string };
  target: {
    role_relative_projection: {
      seed_02_sender: { S: string; P: string; B: string };
      seed_03_receiver: { S: string; P: string; B: string };
    };
  };
  predecessor: {
    role_relative_projection: {
      seed_02_receiver: { S: string; P: string; B: string };
    };
  };
};

const SEED_02 = MANIFEST.public_keys.seed_02;
const SEED_03 = MANIFEST.public_keys.seed_03;

function mintTestWalletPublicKey(): string {
  const { publicKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ format: "der", type: "spki" }).subarray(12);
  return toBase64UrlPadded(Buffer.from(raw));
}

function genesisEnvelopeBytes(): Uint8Array {
  return new TextEncoder().encode(
    `{"status":false,"code":"account_not_found","message":"no account","data":null}`,
  );
}

/** Live virgin-wallet shape — status:true + empty history. */
function emptyHistoryGenesisEnvelopeBytes(): Uint8Array {
  return new TextEncoder().encode(
    `{"status":true,"code":"pq8xgr5opv","message":"OK","data":[]}`,
  );
}

function headEnvelopeBytes(settledFile: string): Uint8Array {
  return new TextEncoder().encode(
    `{"status":true,"code":"success","message":"","data":[${fixtureText(settledFile)}]}`,
  );
}

function syntheticExchange(opts: {
  readonly responseForKey: (walletPublicKey: string) => Uint8Array;
  readonly onExchange?: (endpoint: string, request: GatewayRequest) => void;
}): GatewayExchangeTransport {
  return {
    async exchange(endpoint: string, request: GatewayRequest): Promise<GatewayExchangeCapture> {
      opts.onExchange?.(endpoint, request);
      const body = Buffer.from(request.bodyBytes).toString("utf8");
      expect(body).not.toMatch(/submit_transaction__v1/);
      expect(request.rpc).toBe("get_transaction__v1");
      // Extract queried key if present in form body for fixed fixtures.
      const match = body.match(/key_public__base64urlsafe=([^&]+)/);
      const key = match ? decodeURIComponent(match[1]!) : "";
      const responseBytes = opts.responseForKey(key);
      return {
        endpoint,
        endpointFingerprint: fingerprintEndpoint(endpoint),
        requestBytes: request.bodyBytes,
        requestSha256: sha256Hex(request.bodyBytes),
        statusCode: 200,
        responseBytes,
        responseSha256: sha256Hex(responseBytes),
      };
    },
  };
}

function syntheticGenesisExchange(opts?: {
  readonly onExchange?: (endpoint: string, request: GatewayRequest) => void;
}): GatewayExchangeTransport {
  return syntheticExchange({
    responseForKey: () => genesisEnvelopeBytes(),
    onExchange: opts?.onExchange,
  });
}

type ObsRow = {
  id: string;
  observer_id: string;
  endpoint_fingerprint: string;
  wallet_id: string | null;
  wallet_public_key: string;
  wallet_seq: number;
  raw_response_bytes: Buffer;
  raw_response_sha256: string;
  parse_result: string;
  relationship: string;
  semantic_fingerprint: string | null;
  state_changed: boolean | null;
  wallet_role: string | null;
  s_signature: string | null;
  p_signature: string | null;
  b_amount: string | null;
  previous_recorded_observation_id: string | null;
  inner_preimage_text: string | null;
  step_1_signature: string | null;
  step_2_signature: string | null;
  completed_transaction_text: string | null;
  completed_transaction_sha256: string | null;
};

type CursorRow = {
  observer_id: string;
  wallet_id: string | null;
  wallet_public_key: string;
  last_recorded_observation_id: string;
  last_raw_response_sha256: string;
  last_semantic_fingerprint: string | null;
  consecutive_repeat_count: number;
  next_wallet_seq: number;
};

/**
 * In-memory Postgres stand-in that enforces stream-writer cursor + unique seq semantics
 * (D1/D3) without a live DATABASE_URL. Models the subset of STREAM_WRITER_SQL used here.
 */
function fakePoolForStreamWriterT0(walletPublicKey?: string) {
  const observers = new Map<string, string>(); // nodeId -> observerId
  const observations: ObsRow[] = [];
  const anomalies: Array<{ observation_id: string; kind: string }> = [];
  const cursors = new Map<string, CursorRow>(); // `${observer}\0${wallet}`
  const wallet = walletPublicKey === undefined
    ? null
    : {
        id: "33333333-3333-4333-8333-333333333333",
        publicKey: walletPublicKey,
        state: "PINNED",
        quarantineReason: null as string | null,
        activeLeaseId: "44444444-4444-4444-8444-444444444444",
      };
  const audits: string[] = [];

  const streamKey = (observerId: string, wallet: string) => `${observerId}\0${wallet}`;

  const run = async (sql: string, params?: readonly unknown[]) => {
    const text = sql.replace(/\s+/g, " ").trim();
    if (text === "BEGIN" || text === "COMMIT" || text === "ROLLBACK") {
      return { rows: [], rowCount: 0 };
    }
    if (text.includes("FROM observers") && text.includes("SELECT id")) {
      const nodeId = String(params?.[0] ?? "");
      const id = observers.get(nodeId);
      return { rows: id !== undefined ? [{ id }] : [], rowCount: id !== undefined ? 1 : 0 };
    }
    if (text.includes("INSERT INTO observers")) {
      const id = String(params?.[0]);
      const nodeId = String(params?.[1]);
      if (!observers.has(nodeId)) observers.set(nodeId, id);
      return { rows: [], rowCount: 1 };
    }
    if (text.includes("FROM wallets WHERE public_key")) {
      const found = wallet?.publicKey === String(params?.[0]);
      return { rows: found ? [{ id: wallet.id }] : [], rowCount: found ? 1 : 0 };
    }
    if (text.includes("FROM wallets w LEFT JOIN wallet_active_leases")) {
      const found = wallet?.id === String(params?.[0]);
      return {
        rows: found
          ? [{
              id: wallet.id,
              state: wallet.state,
              quarantine_reason: wallet.quarantineReason,
              active_lease_id: wallet.activeLeaseId,
            }]
          : [],
        rowCount: found ? 1 : 0,
      };
    }
    if (text.includes("UPDATE wallets SET state = 'QUARANTINED'")) {
      if (wallet?.id === String(params?.[0])) {
        wallet.state = "QUARANTINED";
        wallet.quarantineReason = String(params?.[1]);
      }
      return { rows: [], rowCount: wallet === null ? 0 : 1 };
    }
    if (text.includes("FROM wallet_active_leases") && text.includes("operation_id")) {
      return { rows: [], rowCount: 0 };
    }
    if (text.includes("INSERT INTO audit_log")) {
      audits.push(String(params?.[2]));
      return { rows: [], rowCount: 1 };
    }
    // Advisory lock — no-op in fake.
    if (text.includes("pg_advisory_xact_lock")) {
      return { rows: [{}], rowCount: 1 };
    }
    // LOAD_CURSOR_ROW
    if (
      text.includes("FROM wallet_observation_cursors c") &&
      text.includes("last_recorded_observation_id") &&
      !text.includes("JOIN gateway_observations")
    ) {
      const observerId = String(params?.[0]);
      const wallet = String(params?.[1]);
      const c = cursors.get(streamKey(observerId, wallet));
      if (c === undefined) return { rows: [], rowCount: 0 };
      return {
        rows: [{ last_recorded_observation_id: c.last_recorded_observation_id }],
        rowCount: 1,
      };
    }
    // LOAD_CURSORjoin
    if (text.includes("JOIN gateway_observations o") && text.includes("wallet_observation_cursors")) {
      const observerId = String(params?.[0]);
      const wallet = String(params?.[1]);
      const c = cursors.get(streamKey(observerId, wallet));
      if (c === undefined) return { rows: [], rowCount: 0 };
      const o = observations.find((row) => row.id === c.last_recorded_observation_id);
      if (o === undefined || o.observer_id !== observerId) return { rows: [], rowCount: 0 };
      return {
        rows: [
          {
            next_wallet_seq: String(c.next_wallet_seq),
            consecutive_repeat_count: String(c.consecutive_repeat_count),
            last_recorded_observation_id: c.last_recorded_observation_id,
            last_raw_response_sha256: c.last_raw_response_sha256,
            last_semantic_fingerprint: c.last_semantic_fingerprint,
            wallet_seq: String(o.wallet_seq),
            raw_response_bytes: o.raw_response_bytes,
            raw_response_sha256: o.raw_response_sha256,
            parse_result: o.parse_result,
            wallet_role: o.wallet_role,
            s_signature: o.s_signature,
            p_signature: o.p_signature,
            semantic_fingerprint: o.semantic_fingerprint,
          },
        ],
        rowCount: 1,
      };
    }
    // LOAD_HISTORY
    if (
      text.includes("FROM gateway_observations") &&
      text.includes("ORDER BY wallet_seq") &&
      text.includes("relationship")
    ) {
      const observerId = String(params?.[0]);
      const wallet = String(params?.[1]);
      const rows = observations
        .filter((o) => o.observer_id === observerId && o.wallet_public_key === wallet)
        .sort((a, b) => a.wallet_seq - b.wallet_seq)
        .map((o) => ({
          wallet_seq: String(o.wallet_seq),
          parse_result: o.parse_result,
          wallet_role: o.wallet_role,
          s_signature: o.s_signature,
          p_signature: o.p_signature,
          semantic_fingerprint: o.semantic_fingerprint,
          relationship: o.relationship,
        }));
      return { rows, rowCount: rows.length };
    }
    // INSERT observation — unique (observer, wallet, seq) + lineage
    if (text.includes("INSERT INTO gateway_observations")) {
      const id = String(params?.[0]);
      const observerId = String(params?.[1]);
      const endpointFp = String(params?.[2]);
      const walletId = (params?.[3] as string | null) ?? null;
      const walletPk = String(params?.[4]);
      const walletSeq = Number(params?.[5]);
      // params 6 observed_at, 7 http, 8 bytes, 9 sha, 10 parse, 11 rel, 12 semantic, 13 state_changed
      // 14 role, 15 s, 16 p, 17 b, 18 inner, 19 step1, 20 step2, 21 completed, 22 completedSha, 23 previous
      const collision = observations.some(
        (o) =>
          o.observer_id === observerId &&
          o.wallet_public_key === walletPk &&
          o.wallet_seq === walletSeq,
      );
      if (collision) {
        throw new Error(
          `unique violation gateway_observations (observer_id, wallet_public_key, wallet_seq)=(${observerId},${walletPk},${walletSeq})`,
        );
      }
      const row: ObsRow = {
        id,
        observer_id: observerId,
        endpoint_fingerprint: endpointFp,
        wallet_id: walletId,
        wallet_public_key: walletPk,
        wallet_seq: walletSeq,
        raw_response_bytes: Buffer.from(params?.[8] as Buffer | Uint8Array),
        raw_response_sha256: String(params?.[9]),
        parse_result: String(params?.[10]),
        relationship: String(params?.[11]),
        semantic_fingerprint: (params?.[12] as string | null) ?? null,
        state_changed: (params?.[13] as boolean | null) ?? null,
        wallet_role: (params?.[14] as string | null) ?? null,
        s_signature: (params?.[15] as string | null) ?? null,
        p_signature: (params?.[16] as string | null) ?? null,
        b_amount: (params?.[17] as string | null) ?? null,
        inner_preimage_text: (params?.[18] as string | null) ?? null,
        step_1_signature: (params?.[19] as string | null) ?? null,
        step_2_signature: (params?.[20] as string | null) ?? null,
        completed_transaction_text: (params?.[21] as string | null) ?? null,
        completed_transaction_sha256: (params?.[22] as string | null) ?? null,
        previous_recorded_observation_id: (params?.[23] as string | null) ?? null,
      };
      observations.push(row);
      return { rows: [], rowCount: 1 };
    }
    if (text.includes("INSERT INTO observation_anomalies")) {
      anomalies.push({ observation_id: String(params?.[1]), kind: String(params?.[5]) });
      return { rows: [], rowCount: 1 };
    }
    // UPSERT_CURSOR
    if (text.includes("INSERT INTO wallet_observation_cursors")) {
      const observerId = String(params?.[0]);
      const walletId = (params?.[1] as string | null) ?? null;
      const walletPk = String(params?.[2]);
      const lastId = String(params?.[3]);
      const lastSha = String(params?.[4]);
      const lastSem = (params?.[5] as string | null) ?? null;
      const repeat = Number(params?.[7]);
      const nextSeq = Number(params?.[8]);
      cursors.set(streamKey(observerId, walletPk), {
        observer_id: observerId,
        wallet_id: walletId,
        wallet_public_key: walletPk,
        last_recorded_observation_id: lastId,
        last_raw_response_sha256: lastSha,
        last_semantic_fingerprint: lastSem,
        consecutive_repeat_count: repeat,
        next_wallet_seq: nextSeq,
      });
      return { rows: [], rowCount: 1 };
    }
    // UPDATE_SIGHTING
    if (text.includes("UPDATE wallet_observation_cursors")) {
      const observerId = String(params?.[0]);
      const walletPk = String(params?.[1]);
      const repeat = Number(params?.[2]);
      const c = cursors.get(streamKey(observerId, walletPk));
      if (c !== undefined) {
        c.consecutive_repeat_count = repeat;
      }
      return { rows: [], rowCount: c !== undefined ? 1 : 0 };
    }
    // Tip read after SUPPRESS
    if (
      text.includes("SELECT last_recorded_observation_id") &&
      text.includes("FROM wallet_observation_cursors")
    ) {
      const observerId = String(params?.[0]);
      const wallet = String(params?.[1]);
      const c = cursors.get(streamKey(observerId, wallet));
      if (c === undefined) return { rows: [], rowCount: 0 };
      return { rows: [{ id: c.last_recorded_observation_id }], rowCount: 1 };
    }
    // DIY path marker — must not appear after stream-writer net rework.
    if (text.includes("max(wallet_seq)")) {
      throw new Error("DIY max(wallet_seq) path forbidden — use stream writer");
    }
    return { rows: [], rowCount: 0 };
  };

  return {
    query: vi.fn(run),
    connect: vi.fn(async () => ({
      query: run,
      release: () => {},
    })),
    _observations: observations,
    _anomalies: anomalies,
    _cursors: cursors,
    _observers: observers,
    _wallet: wallet,
    _audits: audits,
  };
}

describe("real T0 OBSERVE (offline)", () => {
  it("increments gateway-duration, T0-failure, and anomaly metrics at the real observer seam", async () => {
    const metrics = createNodeMetrics();
    const observer = createGatewayT0Observer({
      pool: {} as never,
      nodeId: NODE_ID,
      gatewayUrls: [GATEWAY_A],
      exchange: { exchange: async () => { throw new Error("offline"); } },
      metricsHooks: createMetricsHooks(metrics),
    });
    await expect(
      observer.observe(mintTestWalletPublicKey(), RECEIVE_T0_OBSERVATION_ROLE),
    ).resolves.toMatchObject({ kind: "INDETERMINATE" });
    expect(metrics.t0ReadFailures.get({})).toBe(1);
    expect(metrics.observationAnomalies.get({ kind: "TRANSPORT_ERROR" })).toBe(1);
    expect(metrics.gatewayRequestDuration.series().some(([name, labels]) =>
      name.endsWith("_count") && labels.rpc === "get_transaction__v1" && labels.outcome === "error"
    )).toBe(true);
  });

  it("AC1: gatewayUrls set → resolveMoneyPathT0Observer kind=gateway (not genesis_stub)", () => {
    const pool = fakePoolForStreamWriterT0();
    const resolved = resolveMoneyPathT0Observer({
      pool: pool as never,
      nodeId: NODE_ID,
      gatewayUrls: [GATEWAY_A],
      gatewayExchange: syntheticGenesisExchange(),
    });
    expect(resolved.kind).toBe("gateway");
  });

  it("D2: empty gatewayUrls without allowGenesisT0Stub fail closed", () => {
    const pool = fakePoolForStreamWriterT0();
    expect(() =>
      resolveMoneyPathT0Observer({
        pool: pool as never,
        nodeId: NODE_ID,
        gatewayUrls: [],
      }),
    ).toThrow(/non-empty gatewayUrls/);
    expect(() =>
      resolveMoneyPathT0Observer({
        pool: pool as never,
        nodeId: NODE_ID,
        gatewayUrls: undefined,
      }),
    ).toThrow(/non-empty gatewayUrls/);
  });

  it("D2: allowGenesisT0Stub=true is the only loud genesis stub path", () => {
    const pool = fakePoolForStreamWriterT0();
    const resolved = resolveMoneyPathT0Observer({
      pool: pool as never,
      nodeId: NODE_ID,
      gatewayUrls: [],
      allowGenesisT0Stub: true,
    });
    expect(resolved.kind).toBe("genesis_stub");
  });

  it("AC1 census: main.ts wires SPLITCHAIN_GATEWAY_URLS; start refuses silent stub", () => {
    const main = readFileSync(join(here, "../src/main.ts"), "utf8");
    expect(main).toMatch(/gatewayUrls:\s*config\.SPLITCHAIN_GATEWAY_URLS/);
    const start = readFileSync(join(here, "../src/money-workers/start-money-workers.ts"), "utf8");
    expect(start).toMatch(/createGatewayT0Observer/);
    expect(start).toMatch(/resolveMoneyPathT0Observer/);
    expect(start).toMatch(/allowGenesisT0Stub/);
    expect(start).toMatch(/kind === "gateway"/);
    // D1: production T0 path must invokefrozen stream writer, not DIY INSERT alone.
    const observer = readFileSync(join(here, "../src/money-workers/gateway-t0-observer.ts"), "utf8");
    expect(observer).toMatch(/persistSqlObservation/);
    const persistence = readFileSync(
      join(here, "../src/money-workers/sql-observation-persistence.ts"),
      "utf8",
    );
    expect(persistence).toMatch(/createSerializedStreamWriter/);
    expect(persistence).toMatch(/createSqlStreamWriterEffects/);
    expect(persistence).toMatch(/createSqlAnomalyRecorder/);
    expect(persistence).toMatch(/applyAnomalyAction/);
    expect(observer).not.toMatch(/'FIRST'::observation_relationship/);
    // Census: STREAM_WRITER_SQL still the production plan source of truth.
    expect(STREAM_WRITER_SQL.INSERT_OBSERVATION).toMatch(/previous_recorded_observation_id/);
  });

  it("AC2+AC3+D1+D4: synthetic genesis → VERIFIED + FIRST + cursor next_seq=2", async () => {
    const pool = fakePoolForStreamWriterT0();
    const walletPk = mintTestWalletPublicKey();
    const calls: GatewayRequest[] = [];
    const observer = createGatewayT0Observer({
      pool: pool as never,
      nodeId: NODE_ID,
      gatewayUrls: [GATEWAY_A],
      exchange: syntheticGenesisExchange({
        onExchange: (_ep, req) => calls.push(req),
      }),
    });

    const outcome: ReceiveT0Observation = await observer.observe(walletPk);
    expect(outcome.kind).toBe("VERIFIED");
    if (outcome.kind !== "VERIFIED") return;

    expect(outcome.observationId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    );
    expect(outcome.projection.S).toBe(GENESIS_PROJECTION.S);
    expect(outcome.projection.P).toBe(GENESIS_PROJECTION.P);
    expect(outcome.projection.B).toBe(GENESIS_PROJECTION.B);

    expect(pool._observations.length).toBe(1);
    const row = pool._observations[0]!;
    expect(row.id).toBe(outcome.observationId);
    expect(row.parse_result).toBe("VERIFIED_GENESIS");
    expect(row.relationship).toBe("FIRST");
    expect(row.previous_recorded_observation_id).toBeNull();
    expect(row.s_signature).toBe("");
    expect(row.p_signature).toBe("");
    expect(row.b_amount).toBe("0");
    expect(row.wallet_seq).toBe(1);
    expect(typeof row.semantic_fingerprint).toBe("string");
    expect(String(row.semantic_fingerprint).length).toBe(64);

    // Cursor advanced so a later stream-writer capture plans seq=2 (no unique collision).
    expect(pool._cursors.size).toBe(1);
    const cursor = [...pool._cursors.values()][0]!;
    expect(cursor.last_recorded_observation_id).toBe(outcome.observationId);
    expect(cursor.next_wallet_seq).toBe(2);
    expect(cursor.consecutive_repeat_count).toBe(0);

    expect(calls.length).toBeGreaterThanOrEqual(1);
    expect(calls.every((c) => c.rpc === "get_transaction__v1")).toBe(true);
    const form = Buffer.from(calls[0]!.bodyBytes).toString("utf8");
    expect(form).toMatch(/key_public__base64urlsafe/);
    expect(form).not.toMatch(/submit_transaction__v1/);
  });

  it("live virgin empty-history [] → VERIFIED genesis (not NOT_VERIFIED)", async () => {
    const pool = fakePoolForStreamWriterT0();
    const walletPk = mintTestWalletPublicKey();
    const calls: GatewayRequest[] = [];
    const observer = createGatewayT0Observer({
      pool: pool as never,
      nodeId: NODE_ID,
      gatewayUrls: [GATEWAY_A],
      exchange: syntheticExchange({
        responseForKey: () => emptyHistoryGenesisEnvelopeBytes(),
        onExchange: (_ep, req) => calls.push(req),
      }),
    });

    const outcome = await observer.observe(walletPk);
    expect(outcome.kind).toBe("VERIFIED");
    if (outcome.kind !== "VERIFIED") return;
    expect(outcome.projection.role).toBe("genesis");
    expect(outcome.projection.S).toBe("");
    expect(outcome.projection.P).toBe("");
    expect(outcome.projection.B).toBe("0");
    expect(pool._observations[0]!.parse_result).toBe("VERIFIED_GENESIS");
    expect(calls.every((c) => c.rpc === "get_transaction__v1")).toBe(true);
    expect(Buffer.from(calls[0]!.bodyBytes).toString("utf8")).not.toMatch(/submit_transaction/);
  });

  it("D3: VERIFIED_HEAD golden → projection S/P/B + stream FIRST + cursor", async () => {
    const pool = fakePoolForStreamWriterT0();
    const projected = MANIFEST.target.role_relative_projection.seed_03_receiver;
    const observer = createGatewayT0Observer({
      pool: pool as never,
      nodeId: NODE_ID,
      gatewayUrls: [GATEWAY_A],
      exchange: syntheticExchange({
        responseForKey: () => headEnvelopeBytes("target.settled.json"),
      }),
    });

    const outcome = await observer.observe(SEED_03);
    expect(outcome.kind).toBe("VERIFIED");
    if (outcome.kind !== "VERIFIED") return;

    expect(outcome.projection.S).toBe(projected.S);
    expect(outcome.projection.P).toBe(projected.P);
    expect(outcome.projection.B).toBe(projected.B);
    expect(outcome.projection.role).toBe("receiver");

    expect(pool._observations.length).toBe(1);
    const row = pool._observations[0]!;
    expect(row.id).toBe(outcome.observationId);
    expect(row.parse_result).toBe("VERIFIED_HEAD");
    expect(row.relationship).toBe("FIRST");
    expect(row.previous_recorded_observation_id).toBeNull();
    expect(row.s_signature).toBe(projected.S);
    expect(row.p_signature).toBe(projected.P);
    expect(row.b_amount).toBe(projected.B);
    expect(row.wallet_seq).toBe(1);
    expect(row.inner_preimage_text).toBeTruthy();
    expect(row.step_1_signature).toBeTruthy();
    expect(row.step_2_signature).toBeTruthy();
    expect(row.completed_transaction_text).toBeTruthy();
    expect(row.completed_transaction_sha256).toMatch(/^[0-9a-f]{64}$/);

    const cursor = [...pool._cursors.values()][0]!;
    expect(cursor.next_wallet_seq).toBe(2);
    expect(cursor.last_recorded_observation_id).toBe(outcome.observationId);
  });

  it("D1+D3+D4: predecessor→target on seed_02 is FIRST then SUCCESSOR with lineage", async () => {
    const pool = fakePoolForStreamWriterT0();
    let call = 0;
    const observer = createGatewayT0Observer({
      pool: pool as never,
      nodeId: NODE_ID,
      gatewayUrls: [GATEWAY_A],
      exchange: syntheticExchange({
        responseForKey: () => {
          call += 1;
          return call === 1
            ? headEnvelopeBytes("predecessor.settled.json")
            : headEnvelopeBytes("target.settled.json");
        },
      }),
    });

    const first = await observer.observe(SEED_02);
    expect(first.kind).toBe("VERIFIED");
    if (first.kind !== "VERIFIED") return;
    const pred = MANIFEST.predecessor.role_relative_projection.seed_02_receiver;
    expect(first.projection.S).toBe(pred.S);
    expect(first.projection.B).toBe(pred.B);

    const second = await observer.observe(SEED_02);
    expect(second.kind).toBe("VERIFIED");
    if (second.kind !== "VERIFIED") return;
    const tgt = MANIFEST.target.role_relative_projection.seed_02_sender;
    expect(second.projection.S).toBe(tgt.S);
    expect(second.projection.P).toBe(tgt.P);
    expect(second.projection.B).toBe(tgt.B);

    expect(pool._observations.length).toBe(2);
    const [r1, r2] = pool._observations;
    expect(r1!.relationship).toBe("FIRST");
    expect(r1!.previous_recorded_observation_id).toBeNull();
    expect(r1!.wallet_seq).toBe(1);
    expect(r1!.id).toBe(first.observationId);

    expect(r2!.relationship).toBe("SUCCESSOR");
    expect(r2!.previous_recorded_observation_id).toBe(r1!.id);
    expect(r2!.wallet_seq).toBe(2);
    expect(r2!.id).toBe(second.observationId);
    expect(r2!.id).not.toBe(r1!.id);

    const cursor = [...pool._cursors.values()][0]!;
    expect(cursor.next_wallet_seq).toBe(3);
    expect(cursor.last_recorded_observation_id).toBe(second.observationId);

    // A subsequent stream-writer plan would allocate seq=3 — cursor has no hole at seq=1/2.
    expect(pool._observations.map((o) => o.wallet_seq).sort()).toEqual([1, 2]);
  });

  it("REGRESSION atomically records evidence, quarantines the wallet, preserves lease, fails closed", async () => {
    const pool = fakePoolForStreamWriterT0(SEED_02);
    let call = 0;
    const observer = createGatewayT0Observer({
      pool: pool as never,
      nodeId: NODE_ID,
      gatewayUrls: [GATEWAY_A],
      exchange: syntheticExchange({
        responseForKey: () => {
          call += 1;
          return call === 1
            ? headEnvelopeBytes("predecessor.settled.json")
            : call === 2
              ? headEnvelopeBytes("target.settled.json")
              : headEnvelopeBytes("predecessor.settled.json");
        },
      }),
    });

    expect((await observer.observe(SEED_02)).kind).toBe("VERIFIED");
    expect((await observer.observe(SEED_02)).kind).toBe("VERIFIED");
    // Anomalous relationship must never surface as VERIFIED (D1).
    const third = await observer.observe(SEED_02);
    expect(third.kind).toBe("INDETERMINATE");
    if (third.kind === "INDETERMINATE") {
      expect(third.detail).toMatch(/REGRESSION/);
    }

    expect(pool._observations.map((row) => row.relationship)).toEqual([
      "FIRST",
      "SUCCESSOR",
      "REGRESSION",
    ]);
    expect(pool._anomalies).toHaveLength(1);
    expect(pool._anomalies[0]!.kind).toBe("REGRESSION");
    expect(pool._wallet?.state).toBe("QUARANTINED");
    expect(pool._wallet?.quarantineReason).toBe("REGRESSION");
    expect(pool._wallet?.activeLeaseId).toBe("44444444-4444-4444-8444-444444444444");
    // canAcquireNewLease-equivalent: QUARANTINED or active lease blocks new claims.
    expect(
      pool._wallet?.state === "QUARANTINED" || pool._wallet?.activeLeaseId !== null,
    ).toBe(true);
    expect(pool._audits).toEqual(["anomaly.quarantine_wallet_halt_signing"]);
    expect(pool._cursors.values().next().value?.next_wallet_seq).toBe(4);
  });

  it("UNEXPLAINED_JUMP with no active lease still commits observation+anomaly (no rollback)", async () => {
    // No wallet/lease seeded → operationId null. Prior defect threw in applyAnomalyAction
    // and ROLLBACKed the observation+anomaly pair (Q5 / empty-ledger failure mode).
    const pool = fakePoolForStreamWriterT0();
    const walletPk = mintTestWalletPublicKey();
    const fp = (label: string) => sha256Hex(new TextEncoder().encode(label));
    const sig = (ch: string) => `${ch.repeat(86)}==`;

    const first = await persistSqlObservation({
      pool: pool as never,
      nodeId: NODE_ID,
      walletPublicKey: walletPk,
      endpointFingerprint: fingerprintEndpoint(GATEWAY_A),
      httpStatus: 200,
      capture: {
        parseResult: "VERIFIED_HEAD",
        rawResponseBytes: new TextEncoder().encode("head-A"),
        isGenesis: false,
        sSignature: sig("A"),
        pSignature: "",
        semanticFingerprint: fp("A"),
      },
      projection: {
        walletRole: "sender",
        bAmount: "1",
        innerPreimageText: null,
        step1Signature: null,
        step2Signature: null,
        completedTransactionText: null,
        completedTransactionSha256: null,
      },
    });
    expect(first.relationship).toBe("FIRST");

    // Different S, P does not equal prior S → UNEXPLAINED_JUMP. No lease → operationId null.
    const jump = await persistSqlObservation({
      pool: pool as never,
      nodeId: NODE_ID,
      walletPublicKey: walletPk,
      endpointFingerprint: fingerprintEndpoint(GATEWAY_A),
      httpStatus: 200,
      capture: {
        parseResult: "VERIFIED_HEAD",
        rawResponseBytes: new TextEncoder().encode("head-JUMP"),
        isGenesis: false,
        sSignature: sig("Z"),
        pSignature: sig("Y"),
        semanticFingerprint: fp("Z"),
      },
      projection: {
        walletRole: "sender",
        bAmount: "9",
        innerPreimageText: null,
        step1Signature: null,
        step2Signature: null,
        completedTransactionText: null,
        completedTransactionSha256: null,
      },
    });
    expect(jump.relationship).toBe("UNEXPLAINED_JUMP");
    expect(pool._observations.map((row) => row.relationship)).toEqual([
      "FIRST",
      "UNEXPLAINED_JUMP",
    ]);
    expect(pool._anomalies).toHaveLength(1);
    expect(pool._anomalies[0]!.kind).toBe("UNEXPLAINED_JUMP");
    expect(pool._anomalies[0]!.observation_id).toBe(jump.observationId);
    // Audit landed even without an operation to stamp attention on.
    expect(pool._audits).toContain("anomaly.needs_attention");
    expect(pool._cursors.values().next().value?.next_wallet_seq).toBe(3);
  });

  it("T0 surface: REGRESSION relationship never returns VERIFIED to the money path", async () => {
    // Companion to the evidence test — pin the outcome kind at the observer boundary.
    const pool = fakePoolForStreamWriterT0(SEED_02);
    let call = 0;
    const observer = createGatewayT0Observer({
      pool: pool as never,
      nodeId: NODE_ID,
      gatewayUrls: [GATEWAY_A],
      exchange: syntheticExchange({
        responseForKey: () => {
          call += 1;
          return call === 1
            ? headEnvelopeBytes("predecessor.settled.json")
            : call === 2
              ? headEnvelopeBytes("target.settled.json")
              : headEnvelopeBytes("predecessor.settled.json");
        },
      }),
    });
    await observer.observe(SEED_02);
    await observer.observe(SEED_02);
    const outcome = await observer.observe(SEED_02);
    expect(outcome.kind).toBe("INDETERMINATE");
    expect(pool._anomalies[0]!.kind).toBe("REGRESSION");
  });

  it("fresh-head REGRESSION fails closed after durable quarantine evidence", async () => {
    const pool = fakePoolForStreamWriterT0(SEED_02);
    let call = 0;
    const reader = createSqlFreshHeadReader({
      pool: pool as never,
      nodeId: NODE_ID,
      gatewayUrls: [GATEWAY_A],
      exchange: syntheticExchange({
        responseForKey: () => {
          call += 1;
          return call === 1
            ? headEnvelopeBytes("predecessor.settled.json")
            : call === 2
              ? headEnvelopeBytes("target.settled.json")
              : headEnvelopeBytes("predecessor.settled.json");
        },
      }),
    });
    await reader(SEED_02);
    await reader(SEED_02);
    await expect(reader(SEED_02)).rejects.toThrow(/REGRESSION/);
    expect(pool._observations.map((r) => r.relationship)).toEqual([
      "FIRST",
      "SUCCESSOR",
      "REGRESSION",
    ]);
    expect(pool._anomalies[0]!.kind).toBe("REGRESSION");
    expect(pool._wallet?.state).toBe("QUARANTINED");
    expect(pool._wallet?.activeLeaseId).toBe("44444444-4444-4444-8444-444444444444");
  });

  it("D1: second stream-writer path after T0 does not collide on wallet_seq=1", async () => {
    const pool = fakePoolForStreamWriterT0();
    const walletPk = mintTestWalletPublicKey();
    const observer = createGatewayT0Observer({
      pool: pool as never,
      nodeId: NODE_ID,
      gatewayUrls: [GATEWAY_A],
      exchange: syntheticGenesisExchange(),
    });
    const first = await observer.observe(walletPk);
    expect(first.kind).toBe("VERIFIED");

    // Re-simulate production later OBSERVE (e.g. landing): same stream writer, different bytes.
    // Cursor next_wallet_seq=2 so seq=1 UNIQUE collision is impossible.
    const follow = await observer.observe(walletPk);
    // Genesis re-observation is byte-identical → SUPPRESS sighting (no new row), same tip id.
    expect(follow.kind).toBe("VERIFIED");
    if (first.kind === "VERIFIED" && follow.kind === "VERIFIED") {
      expect(follow.observationId).toBe(first.observationId);
    }
    expect(pool._observations.length).toBe(1);
    const cursor = [...pool._cursors.values()][0]!;
    expect(cursor.next_wallet_seq).toBe(2);
    expect(cursor.consecutive_repeat_count).toBe(1);
  });

  it("identical malformed bodies append byte-identical observation+anomaly pairs twice", async () => {
    const pool = fakePoolForStreamWriterT0();
    const bad: GatewayExchangeTransport = {
      async exchange(endpoint, request): Promise<GatewayExchangeCapture> {
        const responseBytes = new TextEncoder().encode("not-json{");
        return {
          endpoint,
          endpointFingerprint: fingerprintEndpoint(endpoint),
          requestBytes: request.bodyBytes,
          requestSha256: sha256Hex(request.bodyBytes),
          statusCode: 200,
          responseBytes,
          responseSha256: sha256Hex(responseBytes),
        };
      },
    };
    const observer = createGatewayT0Observer({
      pool: pool as never,
      nodeId: NODE_ID,
      gatewayUrls: [GATEWAY_A],
      exchange: bad,
    });
    const wallet = mintTestWalletPublicKey();
    const first = await observer.observe(wallet);
    const second = await observer.observe(wallet);
    expect(first.kind).toBe("UNVERIFIED");
    expect(second.kind).toBe("UNVERIFIED");
    expect(pool._observations).toHaveLength(2);
    expect(pool._anomalies).toHaveLength(2);
    expect(pool._observations.map((row) => row.parse_result)).toEqual([
      "MALFORMED_ENVELOPE",
      "MALFORMED_ENVELOPE",
    ]);
    expect(pool._anomalies.map((row) => row.kind)).toEqual([
      "MALFORMED_ENVELOPE",
      "MALFORMED_ENVELOPE",
    ]);
    expect(pool._observations[0]!.raw_response_bytes.equals(Buffer.from("not-json{"))).toBe(true);
    expect(pool._observations[1]!.raw_response_bytes.equals(Buffer.from("not-json{"))).toBe(true);
    expect(pool._cursors.values().next().value?.next_wallet_seq).toBe(3);
  });

  it("fresh-head malformed response is durable before the read fails closed", async () => {
    const pool = fakePoolForStreamWriterT0();
    const responseBytes = new TextEncoder().encode("not-json{");
    const reader = createSqlFreshHeadReader({
      pool: pool as never,
      nodeId: NODE_ID,
      gatewayUrls: [GATEWAY_A],
      exchange: {
        async exchange(endpoint, request): Promise<GatewayExchangeCapture> {
          return {
            endpoint,
            endpointFingerprint: fingerprintEndpoint(endpoint),
            requestBytes: request.bodyBytes,
            requestSha256: sha256Hex(request.bodyBytes),
            statusCode: 200,
            responseBytes,
            responseSha256: sha256Hex(responseBytes),
          };
        },
      },
    });

    await expect(reader(mintTestWalletPublicKey())).rejects.toThrow(/head envelope malformed/);
    expect(pool._observations).toHaveLength(1);
    expect(pool._observations[0]!.parse_result).toBe("MALFORMED_ENVELOPE");
    expect(pool._observations[0]!.raw_response_bytes.equals(Buffer.from("not-json{"))).toBe(true);
    expect(pool._anomalies).toHaveLength(1);
    expect(pool._anomalies[0]!.kind).toBe("MALFORMED_ENVELOPE");
  });

  it("createGatewayT0Observer refuses empty URL list (no silent stub)", () => {
    expect(() =>
      createGatewayT0Observer({
        pool: fakePoolForStreamWriterT0() as never,
        nodeId: NODE_ID,
        gatewayUrls: [],
      }),
    ).toThrow(/at least one gateway URL/);
  });

  it("startMoneyWorkers with gatewayUrls logs T0 observer kind=gateway", () => {
    const pool = fakePoolForStreamWriterT0();
    const logs: string[] = [];
    const handle = startMoneyWorkers({
      pool: pool as never,
      vault: { seal: vi.fn(async () => {}) } as never,
      config: {
        nodeId: NODE_ID,
        ownerInstanceId: NODE_ID,
        poolCapTotal: 50,
        receiveQueueCap: 50,
        receiveQueueMaxWaitSecs: 30,
        receiveTtlDefaultSecs: 300,
        receiveTtlMinSecs: 60,
        receiveTtlMaxSecs: 3600,
        tickIntervalMs: 60_000,
        gatewayUrls: [GATEWAY_A],
        // Observer-selection assertion only — no event append.
        allowMissingEventSigner: true,
      },
      logger: {
        info: (m) => logs.push(m),
        error: (m) => logs.push(`err:${m}`),
      },
      moneyPathGates: {
        assertMoneyAdmitted: () => {
          throw new Error("closed");
        },
        assertCanOperate: () => {},
        assertWalletMaySign: () => {},
        assertHaltAdmitsKind: () => {},
      },
      nodeIdentitySigner: () => null,
      gatewayExchange: syntheticGenesisExchange(),
    });
    expect(logs.some((l) => l.includes("T0 observer kind=gateway"))).toBe(true);
    handle.stop();
  });

  it("D2: startMoneyWorkers without gatewayUrls throws (no silent stub)", () => {
    const pool = fakePoolForStreamWriterT0();
    expect(() =>
      startMoneyWorkers({
        pool: pool as never,
        vault: { seal: vi.fn(async () => {}) } as never,
        config: {
          nodeId: NODE_ID,
          ownerInstanceId: NODE_ID,
          poolCapTotal: 50,
          receiveQueueCap: 50,
          receiveQueueMaxWaitSecs: 30,
          receiveTtlDefaultSecs: 300,
          receiveTtlMinSecs: 60,
          receiveTtlMaxSecs: 3600,
          tickIntervalMs: 60_000,
          // Isolate the gateway gate: without this the signer gate would
          // refuse first and this assertion would stop testing what it names.
          allowMissingEventSigner: true,
        },
        logger: { info: () => {}, error: () => {} },
        moneyPathGates: {
          assertMoneyAdmitted: () => {},
          assertCanOperate: () => {},
          assertWalletMaySign: () => {},
          assertHaltAdmitsKind: () => {},
        },
        nodeIdentitySigner: () => null,
      }),
    ).toThrow(/non-empty gatewayUrls/);
  });


  it("gate: onAnomalyRequired is required on SqlStreamWriterEffectsOptions (money-workers)", () => {
    const streamWriter = readFileSync(
      join(here, "../../../packages/node-core/src/observation/stream-writer-sql.ts"),
      "utf8",
    );
    // Non-optional property (no `?:`)
    expect(streamWriter).toMatch(/readonly onAnomalyRequired:\s*SqlAnomalyRequiredHandler/);
    expect(streamWriter).not.toMatch(/readonly onAnomalyRequired\?:/);
    // Runtime throw when anomalyRequired and handler missing
    expect(streamWriter).toMatch(/onAnomalyRequired is required when plan\.anomalyRequired/);
    const persistence = readFileSync(
      join(here, "../src/money-workers/sql-observation-persistence.ts"),
      "utf8",
    );
    expect(persistence).toMatch(/onAnomalyRequired:\s*async/);
    expect(persistence).toMatch(/planAnomalyAction|planActionForRelationship/);
    expect(persistence).toMatch(/applyAnomalyAction/);
  });

  it("gate: money-workers gateway readers do not pass inert ObservationRecorder no-ops", () => {
    const sites = [
      "gateway-t0-observer.ts",
      "sql-fresh-head-reader.ts",
      "receive-settle-step.ts",
      "sql-candidate-intake-ports.ts",
    ] as const;
    for (const file of sites) {
      const src = readFileSync(join(here, `../src/money-workers/${file}`), "utf8");
      expect(src, file).not.toMatch(/recordObservation:\s*async\s*\(\s*\)\s*=>\s*\{\s*\}/);
      expect(src, file).not.toMatch(/recordObservation:\s*async\s*\(\)\s*=>\s*\{\}/);
      expect(src, file).toMatch(/persistSqlObservation/);
    }
    // Boot readiness smoke in main.ts is allowed a documented no-op (no wallet to attribute).
    const main = readFileSync(join(here, "../src/main.ts"), "utf8");
    expect(main).toMatch(/readiness smoke: intentionally non-durable/);
  });

  it("parse-result MALFORMED_ENVELOPE applies retain/alert audit action", async () => {
    const pool = fakePoolForStreamWriterT0(SEED_02);
    const bad: GatewayExchangeTransport = {
      async exchange(endpoint, request): Promise<GatewayExchangeCapture> {
        const responseBytes = new TextEncoder().encode("not-json{");
        return {
          endpoint,
          endpointFingerprint: fingerprintEndpoint(endpoint),
          requestBytes: request.bodyBytes,
          requestSha256: sha256Hex(request.bodyBytes),
          statusCode: 200,
          responseBytes,
          responseSha256: sha256Hex(responseBytes),
        };
      },
    };
    const observer = createGatewayT0Observer({
      pool: pool as never,
      nodeId: NODE_ID,
      gatewayUrls: [GATEWAY_A],
      exchange: bad,
    });
    await observer.observe(SEED_02);
    expect(pool._anomalies[0]!.kind).toBe("MALFORMED_ENVELOPE");
    expect(pool._audits).toContain("anomaly.retain_raw_alert_no_sign");
  });

  it("ARM 409 t0_mismatch path remains load-bearing (census)", () => {
    const armRoute = readFileSync(join(here, "../src/operations/arm-route.ts"), "utf8");
    expect(armRoute).toMatch(/t0_mismatch/);
    const ready = readFileSync(
      join(here, "../../../packages/node-core/src/receive/code-ready-commit.ts"),
      "utf8",
    );
    expect(ready).toMatch(/observation_id:\s*formed\.t0\.observationId/);
    expect(ready).toMatch(/b_zkz:\s*formed\.t0\.b0/);
  });
});


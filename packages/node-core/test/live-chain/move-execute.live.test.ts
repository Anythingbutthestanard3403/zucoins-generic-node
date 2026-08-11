// THE live MOVE_INTERNAL acceptance run.
//
// Default-OFF. Every assertion here touches the production SplitChain gateway with real
// (test) ZKZ. Enabled only when ALL of these hold:
//   MOVE_EXECUTE_LIVE=1
//   ZUP_LIVE_CHAIN_WALLET_FILE=<path to the source wallet backup> (never committed)
//   a reachable local PostgreSQL (the durable store is the REAL node-core schema)
//
// Authority: test coins, dual control (source key from backup; destination key generated
// for this run), ≤ 0.01 ZKZ hard cap (D10.3), live-chain approval gate retired (D10.4 —
// submit still requires enableGatewaySubmit's branded capability).
//
// Ceremony: executeAuthorizedMoveInternal. Runner lock, dual leases in UUID order before
// any T0 read, single-shot submit, evidence bundle + disposition.

import { execFileSync } from "node:child_process";
import {
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  randomUUID,
  sign as edSign,
  type KeyObject,
} from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createGatewayExchangeTransport } from "../../src/gateway/capture.js";
import {
  createGatewayClient,
  createGatewayReadCredentials,
  createGatewaySubmitCredentials,
  enableGatewaySubmit,
} from "../../src/gateway/index.js";
import { buildGatewayActionRequest } from "../../src/gateway/request.js";
import type { GatewayRequest, GatewayResponse } from "../../src/protocol/index.js";
import {
  GENESIS_PROJECTION,
  projectRoleRelativeState,
  type WalletStateProjection,
} from "../../src/protocol/wallet-role.js";

import {
  DEFAULT_MOVE_AMOUNT,
  MOVE_AMOUNT_HARD_CAP,
  executeAuthorizedMoveInternal,
  type MoveExecuteDeps,
  type MovePreflightProbe,
  type MoveTerminalObservation,
  type MoveT0Snapshot,
} from "./index.js";
import { createRunnerLock } from "./runner-lock.js";
import { compareAmounts } from "./types.js";

// ─── Gate ────────────────────────────────────────────────────────────────────

const WALLET_FILE = process.env.ZUP_LIVE_CHAIN_WALLET_FILE ?? "";
const LIVE = process.env.MOVE_EXECUTE_LIVE === "1" && WALLET_FILE !== "";
const GATEWAY =
  process.env.SPLITCHAIN_GATEWAY_URLS?.split(",")[0]?.trim() ??
  "https://gateway-entry-1-q2whsu3jlj.splitchain.com/";
const AMOUNT = process.env.MOVE_EXECUTE_AMOUNT ?? DEFAULT_MOVE_AMOUNT;
const DB = process.env.MOVE_EXECUTE_DATABASE ?? "move_execute_live";
const ARTIFACTS =
  process.env.MOVE_EXECUTE_ARTIFACTS ??
  join(dirname(fileURLToPath(import.meta.url)), "../../../../.move-execute-evidence");

// ─── Crypto ──────────────────────────────────────────────────────────────────

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function fromBase64Url(text: string): Buffer {
  return Buffer.from(text.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}
function toPaddedBase64Url(bytes: Buffer): string {
  return bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}
function privateKeyFromSeed(seed: Buffer): KeyObject {
  return createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
}
function generateWallet(): { publicKey: string; privateKey: KeyObject } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const rawPub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  return { publicKey: toPaddedBase64Url(Buffer.from(rawPub)), privateKey };
}
function signText(privateKey: KeyObject, preimageText: string): string {
  return toPaddedBase64Url(Buffer.from(edSign(null, Buffer.from(preimageText, "utf8"), privateKey)));
}
function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}
function lit(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

// ─── Gateway ─────────────────────────────────────────────────────────────────

const exchange = createGatewayExchangeTransport({
  limits: { readTimeoutMs: 15_000, maxRequestBytes: 1_048_576, maxResponseBytes: 4_194_304 },
});

interface RawExchange {
  readonly bodyText: string;
  readonly responseSha256: string;
  readonly byteLength: number;
  readonly statusCode: number;
}

async function gatewayExchange(action: string, data: unknown): Promise<RawExchange> {
  const capture = await exchange.exchange(GATEWAY, buildGatewayActionRequest(action as never, data));
  return {
    bodyText: Buffer.from(capture.responseBytes).toString("utf8"),
    responseSha256: capture.responseSha256,
    byteLength: capture.responseBytes.byteLength,
    statusCode: capture.statusCode,
  };
}

async function readHead(publicKey: string): Promise<{
  raw: RawExchange;
  head: Record<string, unknown> | null;
}> {
  const raw = await gatewayExchange("get_transaction__v1", {
    key_public__base64urlsafe: publicKey,
  });
  const parsed = JSON.parse(raw.bodyText) as { data?: unknown };
  const rows = Array.isArray(parsed.data) ? (parsed.data as Record<string, unknown>[]) : [];
  return { raw, head: rows[0] ?? null };
}

function projectionFor(
  head: Record<string, unknown> | null,
  publicKey: string,
): WalletStateProjection {
  if (head === null) return GENESIS_PROJECTION;
  const result = projectRoleRelativeState(head as never, publicKey as never);
  if (!result.ok) throw new Error(`role projection failed: ${result.detail}`);
  return result.projection;
}

// ─── Postgres ────────────────────────────────────────────────────────────────

function psql(sql: string): string {
  return execFileSync("psql", ["-d", DB, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql], {
    encoding: "utf8",
  }).trim();
}
function count(sql: string): number {
  return Number(psql(sql));
}
function pgReachable(): boolean {
  try {
    execFileSync("psql", ["-d", DB, "-qAt", "-c", "SELECT 1"], { stdio: "ignore", timeout: 2000 });
    return true;
  } catch {
    return false;
  }
}

// ─── Suite ───────────────────────────────────────────────────────────────────

describe.skipIf(!LIVE)("one live MOVE_INTERNAL", () => {
  let sourcePublicKey = "";
  let sourcePrivate: KeyObject;
  let destPublicKey = "";
  let destPrivate: KeyObject;
  let sourceWalletId = "";
  let destWalletId = "";
  let destinationId = "";
  let operationId = "";
  let nodeId = "";
  let implementerId = "";
  const rawCaptures: Record<string, RawExchange> = {};

  beforeAll(() => {
    mkdirSync(ARTIFACTS, { recursive: true });
    if (compareAmounts(AMOUNT, MOVE_AMOUNT_HARD_CAP) > 0) {
      throw new Error(`MOVE_EXECUTE_AMOUNT ${AMOUNT} exceeds hard cap ${MOVE_AMOUNT_HARD_CAP}`);
    }

    const backup = JSON.parse(readFileSync(WALLET_FILE, "utf8")) as {
      user_wallet: {
        key_public__base64urlsafe: string;
        key_private__base64urlsafe: string;
      };
    };
    sourcePublicKey = backup.user_wallet.key_public__base64urlsafe;
    sourcePrivate = privateKeyFromSeed(
      fromBase64Url(backup.user_wallet.key_private__base64urlsafe).subarray(0, 32),
    );
    const dest = generateWallet();
    destPublicKey = dest.publicKey;
    destPrivate = dest.privateKey;

    execFileSync(
      process.execPath,
      [join(dirname(fileURLToPath(import.meta.url)), "setup-live-db.mjs"), "--move", DB],
      { stdio: "inherit" },
    );
    if (!pgReachable()) throw new Error(`MOVE_EXECUTE_DATABASE ${DB} is not reachable`);

    sourceWalletId = randomUUID();
    destWalletId = randomUUID();
    destinationId = randomUUID();
    operationId = randomUUID();
    nodeId = randomUUID();
    implementerId = randomUUID();
    const recoverySrc = randomUUID();
    const recoveryDst = randomUUID();
    const deviceKey = randomUUID();
    const blessingArt = randomUUID();
    const shaA = "a".repeat(64);
    const idem = `move-live-${operationId}`;
    const requestSha = sha256Hex(idem);

    psql(
      `INSERT INTO implementers (id, name) VALUES (${lit(implementerId)}, 'fixture-live-move');` +
        `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ` +
        `(${lit(nodeId)}, 'fixture-live-move', ${lit(sourcePublicKey)});`,
    );
    // Source: node_generated (MOVE source eligibility). Recovery optional for source.
    psql(
      `INSERT INTO wallets (id, node_id, public_key, key_origin, state) VALUES ` +
        `(${lit(sourceWalletId)}, ${lit(nodeId)}, ${lit(sourcePublicKey)}, 'node_generated', 'AVAILABLE');`,
    );
    // Destination: node_generated + recovery-verified + BLESSED (automatic_sink).
    psql(
      `INSERT INTO wallets (id, node_id, public_key, key_origin, state) VALUES ` +
        `(${lit(destWalletId)}, ${lit(nodeId)}, ${lit(destPublicKey)}, 'node_generated', 'AVAILABLE');` +
        `INSERT INTO wallet_recovery_verifications ` +
        `(id, wallet_id, method, export_sha256, public_key, audit_event_id, verified_at, verifier_identity) ` +
        `VALUES (${lit(recoveryDst)}, ${lit(destWalletId)}, 'AUDITED_EXPORT', ${lit(shaA)}, ` +
        `${lit(destPublicKey)}, ${lit(recoveryDst)}, now(), 'fixture-live-move');` +
        `UPDATE wallets SET recovery_verified_at = now(), recovery_verification_id = ${lit(recoveryDst)} ` +
        `WHERE id = ${lit(destWalletId)};` +
        `INSERT INTO destinations (id, node_id, wallet_id, state, blessed_at, blessed_by_device_key_id, blessing_artifact_id) ` +
        `VALUES (${lit(destinationId)}, ${lit(nodeId)}, ${lit(destWalletId)}, 'BLESSED', now(), ` +
        `${lit(deviceKey)}, ${lit(blessingArt)});`,
    );
    psql(
      `INSERT INTO operations (id, node_id, implementer_id, kind, status, amount_zkz, ` +
        `source_wallet_id, destination_id, idempotency_key, request_sha256, formation_state) VALUES (` +
        `${lit(operationId)}, ${lit(nodeId)}, ${lit(implementerId)}, 'MOVE_INTERNAL', 'CREATED', ` +
        `${lit(AMOUNT)}, ${lit(sourceWalletId)}, ${lit(destinationId)}, ${lit(idem)}, ` +
        `${lit(requestSha)}, 'NOT_REQUIRED');`,
    );
    void recoverySrc;
  });

  afterAll(() => {
    try {
      psql(`DELETE FROM wallet_active_leases WHERE operation_id = ${lit(operationId)};`);
    } catch {
      /* best-effort */
    }
  });

  it("preflight+lock, dual leases, branded single submit, evidence disposition", async () => {
    let leasesHeld = 0;

    const probe: MovePreflightProbe = {
      loadWallet: async (walletId) => {
        if (walletId === sourceWalletId) {
          return {
            walletId: sourceWalletId,
            keyOrigin: "node_generated",
            walletState: "AVAILABLE",
            destinationState: null,
            recoveryVerifiedAt: null,
            nodeControlled: true,
            backupPresent: true,
          };
        }
        if (walletId === destWalletId) {
          return {
            walletId: destWalletId,
            keyOrigin: "node_generated",
            walletState: "AVAILABLE",
            destinationState: "BLESSED",
            recoveryVerifiedAt: "2026-07-20T12:00:00.000Z",
            nodeControlled: true,
            backupPresent: true,
          };
        }
        return null;
      },
      activeLeases: async () => [],
      availableBalance: async (walletId) => {
        if (walletId === sourceWalletId) {
          const head = await readHead(sourcePublicKey);
          rawCaptures["preflight_source_balance"] = head.raw;
          return projectionFor(head.head, sourcePublicKey).B;
        }
        if (walletId === destWalletId) {
          const head = await readHead(destPublicKey);
          rawCaptures["preflight_dest_balance"] = head.raw;
          return projectionFor(head.head, destPublicKey).B;
        }
        return "0";
      },
      t0CaptureWillBeFresh: async () => true,
    };

    // D10.4 branded submit capability — plain objects cannot forge the brand.
    const submitTransport = {
      credentials: createGatewaySubmitCredentials(),
      submit: async (
        _endpoints: readonly string[],
        request: GatewayRequest,
      ): Promise<GatewayResponse> => {
        // The seam supplies settled body bytes; wrap as the gateway action the capture transport dials.
        const bodyText = Buffer.from(request.bodyBytes).toString("utf8");
        const capture = await exchange.exchange(
          GATEWAY,
          buildGatewayActionRequest("submit_transaction__v1" as never, {
            transaction: bodyText,
          }),
        );
        return { statusCode: capture.statusCode, bodyBytes: capture.responseBytes };
      },
    };
    const gatewayClient = createGatewayClient({
      gatewayUrls: GATEWAY,
      readTransport: {
        credentials: createGatewayReadCredentials(),
        read: async () => {
          throw new Error("read path unused on move live submit client");
        },
      },
      submitCapability: enableGatewaySubmit(submitTransport),
    });
    expect(gatewayClient.canSubmit).toBe(true);

    const deps: MoveExecuteDeps = {
      leases: {
        acquireBothInUuidOrder: async (input) => {
          const held = [] as Array<{
            walletId: string;
            role: "MOVE_SOURCE" | "MOVE_DESTINATION";
            operationId: string;
            leaseEpoch: bigint;
          }>;
          for (const id of input.acquireOrder) {
            const role = id === sourceWalletId ? "MOVE_SOURCE" : "MOVE_DESTINATION";
            psql(
              `INSERT INTO wallet_active_leases (wallet_id, membership_id, lease_group_id, ` +
                `root_operation_id, operation_id, lease_role, lease_epoch, acquired_at, ` +
                `heartbeat_at, owner_instance_id) VALUES (${lit(id)}, ${lit(randomUUID())}, ` +
                `${lit(randomUUID())}, ${lit(operationId)}, ${lit(operationId)}, ` +
                `${lit(role)}, 1, now(), now(), ${lit(randomUUID())});`,
            );
            leasesHeld += 1;
            held.push({ walletId: id, role, operationId, leaseEpoch: 1n });
          }
          return held as never;
        },
      },
      observe: {
        observeFreshT0: async ({ walletId, publicKey, role }): Promise<MoveT0Snapshot> => {
          if (leasesHeld < 2) {
            throw new Error("T0 observe before both leases — gate should have blocked");
          }
          const head = await readHead(publicKey);
          rawCaptures[`t0_${role}`] = head.raw;
          return {
            walletId,
            publicKey,
            observationId: `live-t0-${role}-${head.raw.responseSha256.slice(0, 8)}`,
            projection: projectionFor(head.head, publicKey),
          };
        },
        observeTerminal: async ({
          walletId,
          publicKey,
        }): Promise<MoveTerminalObservation | null> => {
          const head = await readHead(publicKey);
          rawCaptures[`terminal_${walletId.slice(0, 8)}`] = head.raw;
          if (head.head === null) return null;
          const step2 =
            typeof head.head.step_2_signature === "string" ? head.head.step_2_signature : "";
          if (step2 === "") return null;
          const proj = projectionFor(head.head, publicKey);
          return {
            walletId,
            publicKey,
            observationId: `live-term-${head.raw.responseSha256.slice(0, 8)}`,
            step2Signature: step2,
            balanceAfter: proj.B,
            settled: head.head as never,
          };
        },
      },
      wallets: {
        publicKeyFor: async (walletId) => {
          if (walletId === sourceWalletId) return sourcePublicKey;
          if (walletId === destWalletId) return destPublicKey;
          throw new Error(`unknown wallet ${walletId}`);
        },
      },
      signer: {
        signStep1: async ({ preimageText }) => signText(sourcePrivate, preimageText),
        signStep2: async ({ preimageText }) => signText(destPrivate, preimageText),
      },
      persist: {
        persistInnerPreimage: async ({
          operationId: opId,
          innerPreimageText,
          innerPreimageSha256,
        }) => {
          psql(
            `INSERT INTO operation_transactions (operation_id, attempt_no, attempt_phase, ` +
              `inner_preimage_text, inner_sha256, formed_at) VALUES (${lit(opId)}, 1, ` +
              `'INNER_PREIMAGE_PERSISTED', ${lit(innerPreimageText)}, ${lit(innerPreimageSha256)}, now()) ` +
              `ON CONFLICT DO NOTHING;`,
          );
        },
        persistStep1Signature: async ({ operationId: opId, step1Signature }) => {
          psql(
            `UPDATE operation_transactions SET step_1_signature = ${lit(step1Signature)}, ` +
              `attempt_phase = 'STEP1_SIGNATURE_PERSISTED' ` +
              `WHERE operation_id = ${lit(opId)} AND attempt_no = 1;`,
          );
        },
        persistStep2Preimage: async ({ operationId: opId, step2PreimageText }) => {
          const sha = sha256Hex(step2PreimageText);
          psql(
            `UPDATE operation_transactions SET step_2_preimage_text = ${lit(step2PreimageText)}, ` +
              `step_2_preimage_sha256 = ${lit(sha)}, attempt_phase = 'STEP2_PREIMAGE_PERSISTED' ` +
              `WHERE operation_id = ${lit(opId)} AND attempt_no = 1;`,
          );
        },
        persistCompletedTransaction: async ({
          operationId: opId,
          step2Signature,
          settledTransactionText,
        }) => {
          const sha = sha256Hex(settledTransactionText);
          psql(
            `UPDATE operation_transactions SET step_2_signature = ${lit(step2Signature)}, ` +
              `completed_transaction_text = ${lit(settledTransactionText)}, ` +
              `completed_transaction_sha256 = ${lit(sha)}, attempt_phase = 'SETTLED_BODY_PERSISTED', ` +
              `settled_at = now() WHERE operation_id = ${lit(opId)} AND attempt_no = 1;`,
          );
        },
        recordSubmitAttempt: async ({ operationId: opId, detail }) => {
          const decisionId = randomUUID();
          psql(
            `INSERT INTO submit_decisions (id, operation_id, transaction_attempt_no, decision, decided_at, details) ` +
              `VALUES (${lit(decisionId)}, ${lit(opId)}, 1, 'INITIAL_SINGLE_SHOT', now(), ${lit(detail)}) ` +
              `ON CONFLICT DO NOTHING;`,
          );
        },
      },
      submit: {
        submitOnce: async ({ settledTransactionText }) => {
          try {
            const bodyBytes = new TextEncoder().encode(settledTransactionText);
            const response = await gatewayClient.submit({
              rpc: "submit_transaction__v1",
              bodyBytes,
            });
            rawCaptures["submit"] = {
              bodyText: Buffer.from(response.bodyBytes).toString("utf8"),
              responseSha256: sha256Hex(Buffer.from(response.bodyBytes).toString("utf8")),
              byteLength: response.bodyBytes.byteLength,
              statusCode: response.statusCode,
            };
            const ok = response.statusCode >= 200 && response.statusCode < 300;
            return {
              outcome: ok ? ("ACK" as const) : ("REJECT" as const),
              detail: `status=${response.statusCode}`,
            };
          } catch (err) {
            return {
              outcome: "AMBIGUOUS" as const,
              detail: err instanceof Error ? err.message : String(err),
            };
          }
        },
      },
    };

    const result = await executeAuthorizedMoveInternal(deps, {
      attemptId: `move-execute-${operationId}`,
      operationId,
      sourceWalletId,
      destinationWalletId: destWalletId,
      amount: AMOUNT,
      authorization: {
        attemptId: `move-execute-${operationId}`,
        attestationId: "dual-control-both-ends-agent-held",
        recordedAt: new Date().toISOString(),
      },
      runnerLock: createRunnerLock(),
      runnerHolderId: "fixture-live-move-runner",
      preflightProbe: probe,
    });
    result.runnerLockHandle?.release();

    writeFileSync(
      join(ARTIFACTS, `move-execute-${operationId}.json`),
      JSON.stringify(
        {
          gateway: GATEWAY,
          amountZkz: AMOUNT,
          sourcePublicKey,
          destPublicKey,
          evidence: result.evidence,
          rawGatewayExchanges: rawCaptures,
        },
        null,
        2,
      ),
      "utf8",
    );

    expect(result.evidence.preflight?.ready).toBe(true);
    expect(compareAmounts(AMOUNT, MOVE_AMOUNT_HARD_CAP) <= 0).toBe(true);
    expect(result.evidence.bothLeasesBeforeAnyRead).toBe(true);
    expect(result.evidence.trail.length).toBeGreaterThan(0);
    expect(result.evidence.disposition).toBeTruthy();
    expect(
      count(
        `SELECT count(*) FROM operation_transactions WHERE operation_id = ${lit(operationId)}`,
      ),
    ).toBeLessThanOrEqual(1);
  }, 300_000);
});

// THE live RECEIVE_EXTERNAL acceptance run.
//
// Default-OFF. Every assertion here touches the production SplitChain gateway with real
// (test) ZKZ. Enabled only when ALL of these hold:
//   RECEIVE_EXECUTE_LIVE=1
//   ZUP_LIVE_CHAIN_WALLET_FILE=<path to the payer wallet backup> (never committed)
//
// Authority: test coins, (dual control — this run holds the payer keypair
// and generates the receiver keypair, so both ends are agent-controlled)
// (external ≤ 0.01 ZKZ), live-chain approval gate retired.
//
// Ceremony: the full receive flow through executeAuthorizedReceiveExternal.
// The node DOES submit step_2 once (unlike SEND_EXTERNAL). The never-blind-retry rule: never blind-retry.
//
// Invariants: one in-flight, byte-exact JSON, no blind retry, no keys on
// the harness surface — only runtime-loaded signer seams).

import { execFileSync } from "node:child_process";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  randomUUID,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createGatewayExchangeTransport } from "../../src/gateway/capture.js";
import { buildGatewayActionRequest } from "../../src/gateway/request.js";
import {
  addZkz,
  parsePositiveZkzAmount,
  parseZkzBalance,
  subtractZkz,
} from "../../src/protocol/amounts.js";
import {
  buildSplitChainInnerV2,
  issueCoherentWalletBaselineV2ForVerifiedHead,
} from "../../src/protocol/transactions.js";
import {
  parseEd25519Signature,
  parseExpiryUnixTimeSecs,
  parsePreviousStateSignature,
  parseUnixTimeSecsV2,
  parseWalletPublicKey,
} from "../../src/protocol/scalars.js";
import { parseObservedZkzBalance } from "../../src/protocol/amounts.js";
import {
  GENESIS_PROJECTION,
  projectRoleRelativeState,
  type WalletStateProjection,
} from "../../src/protocol/wallet-role.js";

import { createRunnerLock } from "./runner-lock.js";
import {
  RECEIVE_AMOUNT_HARD_CAP,
  evaluateReceiveLandingPredicates,
  executeAuthorizedReceiveExternal,
  type ReceiveExecuteDeps,
  type ReceiveLandingObservation,
  type ReceiveObservation,
  type ReceiveSubmitOutcomeKind,
} from "./receive-execute.js";
import type { ReceivePreflightProbe } from "./receive-preflight.js";
import {
  RECEIVE_EXPECTED_FIELD_ORDER,
} from "./receive-preflight.js";
import { compareAmounts } from "./types.js";

// ─── Gate ────────────────────────────────────────────────────────────────────

const WALLET_FILE = process.env.ZUP_LIVE_CHAIN_WALLET_FILE ?? "";
const LIVE = process.env.RECEIVE_EXECUTE_LIVE === "1" && WALLET_FILE !== "";
const GATEWAY =
  process.env.SPLITCHAIN_GATEWAY_URLS?.split(",")[0]?.trim() ??
  "https://gateway-entry-1-q2whsu3jlj.splitchain.com/";
/** bound. Overridable downward only. */
const AMOUNT = process.env.RECEIVE_EXECUTE_AMOUNT ?? "0.000001";
const ARTIFACTS =
  process.env.RECEIVE_EXECUTE_ARTIFACTS ??
  join(dirname(fileURLToPath(import.meta.url)), "../../../../.receive-execute-evidence");

// designated test wallet public key — payer must be exactly this key.
const D946_PAYER_PUBKEY = "wUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrM=";

/**
 * Durable store for this run. Provision it from the FROZEN schema first:
 *   node packages/node-core/test/live-chain/setup-live-db.mjs --receive receive_execute_live
 * Every row count this suite reports is a real `SELECT count(*) ... WHERE operation_id = ...`
 * against this database, and the single-submit guarantee is arbitrated by the composite
 * UNIQUE constraints in src/schema/submit-attempts.sql — never by harness bookkeeping.
 */
const DB = process.env.RECEIVE_EXECUTE_DATABASE ?? "receive_execute_live";

// ─── psql helpers (same discipline as send-execute.live.test.ts / the *.pg.test.ts drills) ──

function psql(sql: string): string {
  try {
    return execFileSync("psql", ["-d", DB, "-v", "ON_ERROR_STOP=1", "-qAt", "-c", sql], {
      encoding: "utf-8",
      timeout: 20_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    // Surface the server's message: the default execFileSync error text is the command line,
    // which hides the constraint that actually rejected the write.
    const detail = (err as { stderr?: string }).stderr ?? "";
    throw new Error(detail.trim() === "" ? String(err) : detail.trim());
  }
}
function lit(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}
function count(sql: string): number {
  return Number(psql(sql).trim() || "0");
}
/** bytea literal — the submit request/response bodies are stored as exact bytes. */
function bytea(text: string): string {
  return `'\\x${Buffer.from(text, "utf8").toString("hex")}'`;
}
function pgReachable(): boolean {
  try {
    execFileSync("psql", ["-d", DB, "-c", "SELECT 1"], {
      encoding: "utf-8",
      timeout: 5_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return true;
  } catch {
    return false;
  }
}

// ─── Ed25519 helpers ─────────────────────────────────────────────────────────

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

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
function publicKeyFromRaw(raw: Buffer): KeyObject {
  return createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}
function signText(key: KeyObject, text: string): string {
  return toPaddedBase64Url(edSign(null, Buffer.from(text, "utf8"), key));
}
function verifyText(publicKeyB64Url: string, text: string, signatureB64Url: string): boolean {
  return edVerify(
    null,
    Buffer.from(text, "utf8"),
    publicKeyFromRaw(fromBase64Url(publicKeyB64Url)),
    fromBase64Url(signatureB64Url),
  );
}
function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/**
 * Extract the exact settled transaction object bytes from a gateway get_transaction
 * envelope. Prefer data[0] compact re-emit only when it round-trips byte-identical to
 * a slice of the envelope (gateway stores the same object). Never trust status alone.
 * The byte-exact signing rule: compare against persisted settledTransactionText as exact bytes.
 */
function extractSettledTransactionText(bodyText: string): string {
  try {
    const parsed = JSON.parse(bodyText) as { data?: unknown };
    const rows = Array.isArray(parsed.data) ? parsed.data : [];
    const row = rows[0];
    if (row === undefined || row === null || typeof row !== "object") return "";
    // Compact separators match byte-exact settledTransactionText (the byte-exact signing rule).
    // Default JSON.stringify inserts spaces and will never equal the signed body.
    const compact = JSON.stringify(row);
    // Node's JSON.stringify is already compact (no space arg). Prefer a slice of the
    // envelope when the object appears verbatim — survives unknown key order only if
    // gateway echoes the submitted bytes.
    const marker = '"data":[';
    const start = bodyText.indexOf(marker);
    if (start >= 0) {
      let depth = 0;
      const objStart = bodyText.indexOf("{", start + marker.length);
      if (objStart >= 0) {
        for (let i = objStart; i < bodyText.length; i += 1) {
          const ch = bodyText[i];
          if (ch === "{") depth += 1;
          else if (ch === "}") {
            depth -= 1;
            if (depth === 0) {
              const sliced = bodyText.slice(objStart, i + 1);
              // Only accept the slice when it parses to the same row (guards truncation).
              try {
                if (JSON.stringify(JSON.parse(sliced)) === compact) return sliced;
              } catch {
                /* fall through */
              }
              break;
            }
          }
        }
      }
    }
    return compact;
  } catch {
    return "";
  }
}

// ─── Gateway adapter ─────────────────────────────────────────────────────────

const exchange = createGatewayExchangeTransport({
  limits: { readTimeoutMs: 15_000, maxRequestBytes: 1_048_576, maxResponseBytes: 4_194_304 },
});

interface RawExchange {
  readonly bodyText: string;
  readonly responseSha256: string;
  readonly byteLength: number;
  readonly statusCode: number;
  readonly requestSha256: string;
}

async function gatewayExchange(action: string, data: unknown): Promise<RawExchange> {
  const capture = await exchange.exchange(GATEWAY, buildGatewayActionRequest(action as never, data));
  return {
    bodyText: Buffer.from(capture.responseBytes).toString("utf8"),
    responseSha256: capture.responseSha256,
    byteLength: capture.responseBytes.byteLength,
    statusCode: capture.statusCode,
    requestSha256: capture.requestSha256,
  };
}

interface HeadRead {
  readonly raw: RawExchange;
  readonly head: Record<string, unknown> | null;
}

async function readHead(publicKey: string): Promise<HeadRead> {
  const raw = await gatewayExchange("get_transaction__v1", {
    key_public__base64urlsafe: publicKey,
  });
  const parsed = JSON.parse(raw.bodyText) as { status?: boolean; data?: unknown };
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

function baselineKind(projection: WalletStateProjection): "GENESIS" | "HEAD" {
  return projection.role === "genesis" || (projection.S === "" && projection.B === "0")
    ? "GENESIS"
    : "HEAD";
}

// ─── The run ─────────────────────────────────────────────────────────────────

let ready = false;
let payerPublicKey = "";
let payerPrivate: KeyObject;
let receiverPublicKey = "";
let receiverPrivate: KeyObject;
let operationId = "";
let receiverWalletId = "";
let attemptId = "";
let nodeId = "";
let implementerId = "";
let t0RowId = "";
const rawCaptures: Record<string, RawExchange> = {};

describe.skipIf(!LIVE)("one live RECEIVE_EXTERNAL", () => {
  beforeAll(async () => {
    // Refuse to run without the durable store. Row-count evidence read out of harness
    // memory would prove only that the stub assigned what the stub assigned, so there is
    // no in-memory fallback here (same stance as send-execute.live.test.ts).
    if (!pgReachable()) throw new Error(`RECEIVE_EXECUTE_DATABASE ${DB} is not reachable`);

    if (compareAmounts(AMOUNT, RECEIVE_AMOUNT_HARD_CAP) > 0) {
      throw new Error(`RECEIVE_EXECUTE_AMOUNT ${AMOUNT} exceeds hard cap ${RECEIVE_AMOUNT_HARD_CAP}`);
    }

    const backup = JSON.parse(readFileSync(WALLET_FILE, "utf8")) as {
      user_wallet: {
        key_public__base64urlsafe: string;
        key_private__base64urlsafe: string;
      };
    };
    payerPublicKey = backup.user_wallet.key_public__base64urlsafe;
    if (payerPublicKey !== D946_PAYER_PUBKEY) {
      throw new Error(
        `payer pubkey ${payerPublicKey} is not the designated test wallet`,
      );
    }
    payerPrivate = privateKeyFromSeed(
      fromBase64Url(backup.user_wallet.key_private__base64urlsafe).subarray(0, 32),
    );

    // Disposable genesis receiver — single-use, node-controlled for this run only.
    const seedEnv = process.env.RECEIVE_EXECUTE_RECEIVER_SEED;
    const seed = seedEnv === undefined ? randomBytes(32) : fromBase64Url(seedEnv);
    receiverPrivate = privateKeyFromSeed(seed);
    receiverPublicKey = toPaddedBase64Url(
      createPublicKey(receiverPrivate).export({ format: "der", type: "spki" }).subarray(12),
    );

    operationId = randomUUID();
    receiverWalletId = randomUUID();
    attemptId = `receive-execute-${operationId}`;
    nodeId = randomUUID();
    implementerId = randomUUID();
    t0RowId = randomUUID();

    // FK targets for the ceremony's rows. The operations row is the RECEIVE_EXTERNAL shape
    // enforces structurally (discriminator = id, anchor present, after_landing set).
    // It is seeded CREATED with receiver_wallet_id / expiry / t0_observation_id NULL — the
    // state exits with. persistFormation is what moves it to READY, so the arm
    // count below is 0 until the ceremony actually arms.
    psql(
      `INSERT INTO implementers (id, name) VALUES (${lit(implementerId)}, 'fixture-live');` +
        `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ` +
        `(${lit(nodeId)}, 'fixture-live', ${lit(payerPublicKey)});` +
        `INSERT INTO wallets (id, node_id, public_key, key_origin) VALUES ` +
        `(${lit(receiverWalletId)}, ${lit(nodeId)}, ${lit(receiverPublicKey)}, 'node_generated');` +
        `INSERT INTO operations (id, node_id, implementer_id, kind, status, amount_zkz, ` +
        `idempotency_key, request_sha256, discriminator, anchor, after_landing) VALUES ` +
        `(${lit(operationId)}, ${lit(nodeId)}, ${lit(implementerId)}, 'RECEIVE_EXTERNAL', ` +
        `'CREATED', ${lit(AMOUNT)}, ${lit(attemptId)}, ${lit(sha256Hex(attemptId))}, ` +
        `${lit(operationId)}, 'receive_executelive', 'HOLD');`,
    );

    // Confirm payer has head / balance before any irreversible step.
    const payerHead = await readHead(payerPublicKey);
    rawCaptures["payer_preflight_head"] = payerHead.raw;
    const payerProj = projectionFor(payerHead.head, payerPublicKey);
    if (compareAmounts(payerProj.B, AMOUNT) < 0) {
      throw new Error(`payer balance ${payerProj.B} < amount ${AMOUNT}`);
    }

    // Receiver must be genesis (never used).
    const recvHead = await readHead(receiverPublicKey);
    rawCaptures["receiver_preflight_head"] = recvHead.raw;
    if (recvHead.head !== null) {
      throw new Error("receiver key is not genesis — refuse to reuse a funded receiver");
    }

    mkdirSync(ARTIFACTS, { recursive: true });
    ready = true;
  }, 120_000);

  afterAll(() => {
    // Release the lease so a re-run against the same database is not blocked by golden
    // rule 2. The evidence rows (operation, transaction, decision, attempt) are left in
    // place deliberately — they ARE the durable record re-read afterwards.
    if (operationId !== "") {
      psql(`DELETE FROM wallet_active_leases WHERE operation_id = ${lit(operationId)};`);
    }
  });

  it("assigns, arms once, intakes candidate, submits once, lands verified", async () => {
    expect(ready).toBe(true);

    let persistedSettled: string | null = null;
    let leaseHeld = false;

    const toObservation = (
      role: ReceiveObservation["role"],
      publicKey: string,
      head: HeadRead,
    ): ReceiveObservation => ({
      role,
      publicKey,
      observationId: `live-${role}-${sha256Hex(head.raw.responseSha256).slice(0, 8)}`,
      projection: projectionFor(head.head, publicKey),
      rawResponseSha256: head.raw.responseSha256,
      rawResponseByteLength: head.raw.byteLength,
    });

    const probe: ReceivePreflightProbe = {
      loadReceiver: async (walletId) => {
        if (walletId !== receiverWalletId) return null;
        return {
          walletId: receiverWalletId,
          pubkey: receiverPublicKey,
          keyOrigin: "node_generated",
          walletState: "AVAILABLE",
          recoveryVerifiedAt: "2026-07-20T12:00:00.000Z",
          nodeControlled: true,
          backupPresent: true,
          backupCapturedAt: new Date().toISOString(),
        };
      },
      loadExternalPayer: async (payerAddress) => {
        if (payerAddress !== payerPublicKey) return null;
        return {
          payerAddress: payerPublicKey,
          resolvesToNodeBlessedSet: false,
          isNodeControlledWallet: false,
          keyholderId: "d9.46-designated-test-wallet",
          independentControlNote:
            "Designated disposable test wallet; agent holds backup file for this dual-control run only",
        };
      },
      activeLeases: async () => [],
      loadOperation: async (opId) => {
        if (opId !== operationId) return null;
        // Clean CREATED-stage snapshot for preflight (execute admits).
        return {
          operationId,
          status: "CREATED",
          receiverWalletId,
          amountZkz: AMOUNT,
          expectedArtifactPresent: true,
          expectedArtifactFieldOrder: [...RECEIVE_EXPECTED_FIELD_ORDER],
          receiverLeaseHeld: false,
          step2SubmitAttempted: false,
          transferCodeReleased: false,
        };
      },
      freshVaultBackup: async () => ({
        present: true,
        capturedAt: new Date().toISOString(),
      }),
      loadBuildVersion: async () => ({
        commitSha: execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
        imageTag: "local-dev-fixture",
        gatewayEndpoint: GATEWAY,
        configFingerprint: "receive-execute-live-receive",
      }),
    };

    const deps: ReceiveExecuteDeps = {
      leases: {
        acquireReceiverLease: async ({ operationId: opId, receiverWalletId: wid }) => {
          // UNIQUE (operation_id, wallet_id) + wallet_id PRIMARY KEY: the one-in-flight-per-wallet rule is the
          // database's to enforce, not the harness's.
          psql(
            `INSERT INTO wallet_active_leases (wallet_id, membership_id, lease_group_id, ` +
              `root_operation_id, operation_id, lease_role, lease_epoch, acquired_at, ` +
              `heartbeat_at, owner_instance_id) VALUES (${lit(wid)}, ${lit(randomUUID())}, ` +
              `${lit(randomUUID())}, ${lit(opId)}, ${lit(opId)}, 'RECEIVE_WINDOW', 1, now(), ` +
              `now(), ${lit(randomUUID())});`,
          );
          leaseHeld = true;
          return {
            walletId: wid,
            operationId: opId,
            leaseEpoch: 1n,
            role: "RECEIVER",
            lifecycle: "ACTIVE",
          };
        },
      },
      observe: {
        observeVerified: async ({ publicKey, role }) => {
          if (!leaseHeld && role === "RECEIVE_T0") {
            throw new Error("T0 observe before lease — gate should have blocked");
          }
          const head = await readHead(publicKey);
          rawCaptures[role] = head.raw;
          return toObservation(role, publicKey, head);
        },
        observeReceiverLanding: async ({
          publicKey,
          persistedSettledTransactionText,
          persistedStep2Signature,
          receiverT0S0,
          receiverT0B0,
          amount,
        }): Promise<ReceiveLandingObservation | null> => {
          // Bounded single independent read (no blind poll-storm). One attempt is enough
          // for dust on a responsive gateway; if absent → hold+reconcile.
          // Match send-live: exact settled bytes + proj.P === T0.S0 + ΔB — no OR dilations.
          const head = await readHead(publicKey);
          rawCaptures["RECEIVE_TERMINAL_CHECK"] = head.raw;
          if (head.head === null) return null;
          const observedSettled = extractSettledTransactionText(head.raw.bodyText);
          // No completed body yet → null (hold+reconcile), not false flags.
          if (observedSettled.length === 0) return null;
          const proj = projectionFor(head.head, publicKey);
          const observedStep2 =
            typeof head.head.step_2_signature === "string"
              ? head.head.step_2_signature
              : "";
          const flags = evaluateReceiveLandingPredicates({
            headPresent: true,
            observedSettledTransactionText: observedSettled,
            persistedSettledTransactionText,
            observedStep2Signature: observedStep2,
            persistedStep2Signature,
            observedP: proj.P,
            receiverT0S0,
            observedB: proj.B,
            receiverT0B0,
            amount,
          });
          if (flags === null) return null;
          // Wrong head (mismatched body / P / ΔB) → false flags so coordinator escalates;
          // never force LANDED_VERIFIED via includes() or S===step2 short-circuits.
          return {
            publicKey,
            observationId: `live-landing-${head.raw.responseSha256.slice(0, 8)}`,
            step2Signature: observedStep2,
            balanceAfter: proj.B,
            balanceDeltaMatchesAmount: flags.balanceDeltaMatchesAmount,
            predecessorMatchesT0S0: flags.predecessorMatchesT0S0,
            settledTextMatchesPersisted: flags.settledTextMatchesPersisted,
            rawResponseSha256: head.raw.responseSha256,
            rawResponseByteLength: head.raw.byteLength,
            observedAtIso: new Date().toISOString(),
          };
        },
      },
      arm: {
        armOnce: async ({ transferCodeText, nodeT0, receiverPubkey }) => {
          // Independent consumer: own gateway read must match node T0.
          const own = await readHead(receiverPubkey);
          rawCaptures["arm_consumer_t0"] = own.raw;
          const ownProj = projectionFor(own.head, receiverPubkey);
          if (
            ownProj.S !== nodeT0.projection.S ||
            ownProj.P !== nodeT0.projection.P ||
            ownProj.B !== nodeT0.projection.B
          ) {
            throw new Error(
              `arm t0_mismatch own B=${ownProj.B} node B=${nodeT0.projection.B}`,
            );
          }
          const now = new Date().toISOString();
          return {
            armedAt: now,
            codeReleasedAt: now,
            releasedTransferCodeText: transferCodeText,
          };
        },
      },
      signer: {
        signStep2: async ({ preimageText }) => {
          const sig = signText(receiverPrivate, preimageText);
          parseEd25519Signature(sig);
          return sig;
        },
      },
      persist: {
        admitOperation: async () => {
          /* the CREATED row is seeded in beforeAll — admission already exited */
        },
        // CREATED → READY. This transition IS the durable arm evidence in
        // the frozen schema (receive_arms landed in receive-arms.sql).
        persistFormation: async ({ receiverWalletId: wid, expiryUnixTimeSecs }) => {
          psql(
            `UPDATE operations SET status = 'READY', receiver_wallet_id = ${lit(wid)}, ` +
              `expiry_unix_time_secs = ${lit(expiryUnixTimeSecs)}, ` +
              `t0_observation_id = ${lit(t0RowId)} ` +
              `WHERE id = ${lit(operationId)} AND status = 'CREATED';`,
          );
          return { statusAfter: "READY" as const };
        },
        persistCandidateAndStep2Preimage: async ({
          innerPreimageText,
          innerSha256,
          step1Signature,
          step2PreimageText,
          step2PreimageSha256,
        }) => {
          // One row per (operation_id, attempt_no) — attempt_no is CHECK-pinned to 1, so a
          // second candidate for this operation is unrepresentable, not merely unwritten.
          psql(
            `INSERT INTO operation_transactions (operation_id, attempt_no, attempt_phase, ` +
              `inner_preimage_text, inner_sha256, step_1_signature, step_2_preimage_text, ` +
              `step_2_preimage_sha256, formed_at) VALUES (${lit(operationId)}, 1, ` +
              `'STEP2_PREIMAGE_PERSISTED', ${lit(innerPreimageText)}, ${lit(innerSha256)}, ` +
              `${lit(step1Signature)}, ${lit(step2PreimageText)}, ` +
              `${lit(step2PreimageSha256)}, now());`,
          );
          // Read-back. One single-column SELECT per value: `-qAt` joins
          // columns with a tab, and these are exact signed bytes that must not be
          // re-split. The trailing newline psql appends is the only thing stripped.
          const readBack = (column: string): string =>
            psql(
              `SELECT ${column} FROM operation_transactions ` +
                `WHERE operation_id = ${lit(operationId)} AND attempt_no = 1;`,
            ).replace(/\n$/, "");
          return {
            step2PreimageId: `${operationId}-step2`,
            persistedInnerPreimageText: readBack("inner_preimage_text"),
            persistedStep1Signature: readBack("step_1_signature"),
          };
        },
        persistSignedAndSubmitDecision: async ({
          step2Signature,
          settledTransactionText,
          settledTransactionSha256,
        }) => {
          const submitDecisionId = randomUUID();
          psql(
            `UPDATE operation_transactions SET attempt_phase = 'SETTLED_BODY_PERSISTED', ` +
              `step_2_signature = ${lit(step2Signature)}, ` +
              `completed_transaction_text = ${lit(settledTransactionText)}, ` +
              `completed_transaction_sha256 = ${lit(settledTransactionSha256)}, ` +
              `settled_at = now() WHERE operation_id = ${lit(operationId)} AND attempt_no = 1;` +
              `INSERT INTO submit_decisions (id, operation_id, transaction_attempt_no, ` +
              `decision, decided_at, details) VALUES (${lit(submitDecisionId)}, ` +
              `${lit(operationId)}, 1, 'INITIAL_SINGLE_SHOT', now(), ${lit(attemptId)});`,
          );
          persistedSettled = settledTransactionText;
          return { submitDecisionId };
        },
        // The attempt row already exists — submitOnce claimed it before the POST. This
        // closes it out with the observed outcome and the exact response bytes; it must
        // never insert a second row.
        recordSubmitAttempt: async ({ outcome }) => {
          const capture = rawCaptures["node_submit"];
          psql(
            `UPDATE gateway_submit_attempts SET transport_outcome = ${lit(outcome)}, ` +
              `response_body = ${capture === undefined ? "NULL" : bytea(capture.bodyText)}, ` +
              `response_sha256 = ` +
              `${capture === undefined ? "NULL" : lit(capture.responseSha256)}, ` +
              `completed_at = now() WHERE operation_id = ${lit(operationId)} ` +
              `AND attempt_no = 1;`,
          );
        },
        // Real per-operation_id reads. Nothing here is harness bookkeeping: if a write
        // above never happened, the corresponding count comes back 0.
        countRows: async (opId) => ({
          receiverLeases: count(
            `SELECT count(*) FROM wallet_active_leases WHERE operation_id = ${lit(opId)}`,
          ),
          // receive_arms landed in receive-arms.sql; this harness's arm evidence
          // proxy (CREATED→READY) remains correct — the arm row is inserted by the
          // production arm-commit step, not replayable in this acceptance harness.
          armAcknowledgements: count(
            `SELECT count(*) FROM operations WHERE id = ${lit(opId)} AND status <> 'CREATED'`,
          ),
          candidates: count(
            `SELECT count(*) FROM operation_transactions WHERE operation_id = ${lit(opId)}`,
          ),
          step2Preimages: count(
            `SELECT count(*) FROM operation_transactions WHERE operation_id = ${lit(opId)} ` +
              `AND step_2_preimage_text IS NOT NULL`,
          ),
          step2Signatures: count(
            `SELECT count(*) FROM operation_transactions WHERE operation_id = ${lit(opId)} ` +
              `AND step_2_signature IS NOT NULL`,
          ),
          submitDecisions: count(
            `SELECT count(*) FROM submit_decisions WHERE operation_id = ${lit(opId)}`,
          ),
          gatewaySubmitAttempts: count(
            `SELECT count(*) FROM gateway_submit_attempts WHERE operation_id = ${lit(opId)}`,
          ),
        }),
      },
      submit: {
        submitOnce: async ({ settledTransactionText, submitDecisionId }) => {
          // Claim the single submit slot in the database BEFORE any network call. The
          // arbiter is UNIQUE (operation_id, attempt_no) / UNIQUE (decision_id) in
          // src/schema/submit-attempts.sql — a second call raises 23505 from the server
          // and never reaches the gateway. (The same constraints are proven directly in
          // test/submit-decision-claim-store.pg.test.ts.) The never-blind-retry rule.
          psql(
            `INSERT INTO gateway_submit_attempts (id, operation_id, attempt_no, ` +
              `transaction_attempt_no, decision_id, request_body, request_sha256, ` +
              `transport_outcome, started_at) VALUES (${lit(randomUUID())}, ` +
              `${lit(operationId)}, 1, 1, ${lit(submitDecisionId)}, ` +
              `${bytea(settledTransactionText)}, ${lit(sha256Hex(settledTransactionText))}, ` +
              `'INDETERMINATE', now());`,
          );
          // The byte-exact signing rule — submitted action_data must be byte-identical to signed text.
          const actionData: unknown = JSON.parse(settledTransactionText);
          if (JSON.stringify(actionData) !== settledTransactionText) {
            return {
              outcome: "REJECT" as ReceiveSubmitOutcomeKind,
              detail: "re-serialized transaction bytes differ from signed text",
              rawResponseSha256: null,
              rawResponseByteLength: null,
              gatewayStatusCode: null,
            };
          }
          try {
            const raw = await gatewayExchange("submit_transaction__v1", actionData);
            rawCaptures["node_submit"] = raw;
            const ok = (JSON.parse(raw.bodyText) as { status?: boolean }).status === true;
            return {
              outcome: (ok ? "ACK" : "REJECT") as ReceiveSubmitOutcomeKind,
              detail: raw.bodyText.slice(0, 400),
              rawResponseSha256: raw.responseSha256,
              rawResponseByteLength: raw.byteLength,
              gatewayStatusCode: raw.statusCode,
            };
          } catch (err) {
            // The never-blind-retry rule — ambiguous → reconcile, never retry.
            return {
              outcome: "AMBIGUOUS" as ReceiveSubmitOutcomeKind,
              detail: err instanceof Error ? err.message : String(err),
              rawResponseSha256: null,
              rawResponseByteLength: null,
              gatewayStatusCode: null,
            };
          }
        },
      },
      payer: {
        buildAndSignStep1: async ({
          receiverT0,
          amount,
          receiverPubkey,
          expiryUnixTimeSecs,
          receiveMessage,
        }) => {
          // Independent payer: own head read, own sign.
          const own = await readHead(payerPublicKey);
          rawCaptures["payer_step1_head"] = own.raw;
          const ownProj = projectionFor(own.head, payerPublicKey);

          const nowMs = Date.now();
          const formationFloor = Math.floor(nowMs / 1000);
          // Fractional unix_time_secs per A.8 style.
          const unixTimeSecs = `${formationFloor}.${String(nowMs % 1000).padStart(3, "0")}`;

          const sender = issueCoherentWalletBaselineV2ForVerifiedHead({
            kind: baselineKind(ownProj),
            publicKey: parseWalletPublicKey(payerPublicKey),
            balance: parseObservedZkzBalance(ownProj.B),
            previousSettledStep2Signature: parsePreviousStateSignature(ownProj.S),
          });
          const receiver = issueCoherentWalletBaselineV2ForVerifiedHead({
            kind: baselineKind(receiverT0),
            publicKey: parseWalletPublicKey(receiverPubkey),
            balance: parseObservedZkzBalance(receiverT0.B),
            previousSettledStep2Signature: parsePreviousStateSignature(receiverT0.S),
          });
          const capability = buildSplitChainInnerV2({
            unixTimeSecs: parseUnixTimeSecsV2(unixTimeSecs),
            sender,
            receiver,
            transferAmount: parsePositiveZkzAmount(amount),
            expiryUnixTimeSecs: parseExpiryUnixTimeSecs(expiryUnixTimeSecs),
            message: receiveMessage,
          });
          const innerPreimageText = capability.innerPreimageText;
          const step1Signature = signText(payerPrivate, innerPreimageText);
          if (!verifyText(payerPublicKey, innerPreimageText, step1Signature)) {
            throw new Error("payer step-1 self-verify failed");
          }
          // Economic self-check
          const expectedRemain = subtractZkz(
            parseZkzBalance(ownProj.B),
            parsePositiveZkzAmount(amount),
          );
          const expectedRecv = addZkz(
            parseZkzBalance(receiverT0.B),
            parsePositiveZkzAmount(amount),
          );
          const parsed = JSON.parse(innerPreimageText) as {
            step_1_state: { amount: string };
            step_2_state: { amount: string };
          };
          if (parsed.step_1_state.amount !== String(expectedRemain)) {
            throw new Error(
              `payer remain ${parsed.step_1_state.amount} ≠ ${expectedRemain}`,
            );
          }
          if (parsed.step_2_state.amount !== String(expectedRecv)) {
            throw new Error(
              `receiver after ${parsed.step_2_state.amount} ≠ ${expectedRecv}`,
            );
          }
          return {
            innerPreimageText,
            step1Signature,
            payerPubkey: payerPublicKey,
          };
        },
      },
    };

    const result = await executeAuthorizedReceiveExternal(deps, {
      attemptId,
      operationId,
      receiverWalletId,
      receiverPubkey: receiverPublicKey,
      externalPayerAddress: payerPublicKey,
      amount: AMOUNT,
      authorization: {
        attemptId,
        attestationId: "dual-control-both-ends-agent-held",
        recordedAt: new Date().toISOString(),
      },
      runnerLock: createRunnerLock(),
      runnerHolderId: "fixture-live-runner",
      preflightProbe: probe,
      anchor: `receive_execute_${operationId.replace(/-/g, "").slice(0, 12)}`,
    });
    result.runnerLockHandle?.release();

    writeFileSync(
      join(ARTIFACTS, `receive-execute-${operationId}.json`),
      JSON.stringify(
        {
          gateway: GATEWAY,
          amountZkz: AMOUNT,
          payerPublicKey,
          receiverPublicKey,
          operationId,
          attemptId,
          evidence: result.evidence,
          rawGatewayExchanges: Object.fromEntries(
            Object.entries(rawCaptures).map(([k, v]) => [
              k,
              {
                statusCode: v.statusCode,
                responseSha256: v.responseSha256,
                requestSha256: v.requestSha256,
                byteLength: v.byteLength,
                bodyText: v.bodyText,
              },
            ]),
          ),
        },
        null,
        2,
      ),
      "utf8",
    );

    // ── Reviewer's evidence ────────────────────────────────────────────────
    expect(result.evidence.leaseHeldBeforeT0Read).toBe(true);
    expect(result.evidence.singleSubmitOnly).toBe(true);
    expect(result.evidence.nodeSubmitSeamExercised).toBe(true);
    expect(result.evidence.candidate?.receiverLinkComparedTo).toBe("S0");
    expect(result.evidence.submit?.submitCallCount).toBe(1);
    expect(result.evidence.rowCounts).toEqual({
      receiverLeases: 1,
      armAcknowledgements: 1,
      candidates: 1,
      step2Preimages: 1,
      step2Signatures: 1,
      submitDecisions: 1,
      gatewaySubmitAttempts: 1,
    });
    expect(result.evidence.disposition).toBe("LANDED_VERIFIED");
    expect(result.ok).toBe(true);
    expect(result.evidence.landing).not.toBeNull();
    expect(result.evidence.landing?.balanceAfter).toBe(AMOUNT);
    expect(result.evidence.landing?.balanceDeltaMatchesAmount).toBe(true);
    // Independent terminal read postdates submit (raw capture present).
    expect(rawCaptures["node_submit"]).toBeDefined();
    expect(rawCaptures["RECEIVE_TERMINAL_CHECK"]).toBeDefined();
    // Submit ack is NOT landing proof — we required an independent head.
    expect(result.evidence.trail.some((l) => l.includes("LANDED_VERIFIED"))).toBe(true);

    // Negative-path assertion for this slice: a second submit is unrepresentable because
    // the DATABASE rejects it. The assertion matches the server's own message (SQLSTATE
    // 23505 on the composite unique), not a harness sentinel — if the constraint were
    // dropped, this test would fail rather than silently pass on an app-level `if`.
    await expect(
      deps.submit.submitOnce({
        operationId,
        attemptNo: 1,
        settledTransactionText: persistedSettled ?? "{}",
        submitDecisionId: randomUUID(),
      }),
    ).rejects.toThrow(/duplicate key value violates unique constraint/);
    expect(
      count(
        `SELECT count(*) FROM gateway_submit_attempts WHERE operation_id = ${lit(operationId)}`,
      ),
    ).toBe(1);
  }, 600_000);
});

// THE live SEND_EXTERNAL acceptance run.
//
// Default-OFF. Every assertion here touches the production SplitChain gateway with real
// (test) ZKZ. Enabled only when ALL of these hold:
//   SEND_EXECUTE_LIVE=1
//   ZUP_LIVE_CHAIN_WALLET_FILE=<path to the source wallet backup> (never committed)
//   a reachable local PostgreSQL (the durable store is the REAL node-core schema)
//
// Authority: all ZKZ here are test coins, (dual control — this run holds the
// source keypair and generates the destination keypair, so both ends are agent-controlled),
// External transactions ≤ 0.01 ZKZ, the live-chain approval gate is retired.
//
// Ceremony:, executed exactly in order through
// executeAuthorizedSendExternal. The node NEVER submits —; the recipient adapter is
// the only code path in this file that calls the gateway submit action.
//
// Invariants: one in-flight per wallet (one operation, one lease), byte-exact
// JSON.stringify — the submitted body is asserted byte-identical to the formed transaction
// text), 4 (never blind-retry a submit — the recipient submits once and reconciles), 5 (the
// private key is read from the runtime path only and never logged, persisted or committed).

import { execFileSync } from "node:child_process";
import {
  createHash,
  createHmac,
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
import { projectRoleRelativeState, GENESIS_PROJECTION } from "../../src/protocol/wallet-role.js";
import type { WalletStateProjection } from "../../src/protocol/wallet-role.js";
import { matchTotp } from "../../src/http/totp-chain.js";

import { createRunnerLock } from "./runner-lock.js";
import {
  SEND_AMOUNT_HARD_CAP,
  SEND_APPROVAL_FIELD_ORDER,
  SEND_APPROVAL_PURPOSE,
  SEND_EXPECTED_FIELD_ORDER,
} from "./send-preflight.js";
import type {
  SendExecuteDeps,
  SendObservation,
  SendRecipientOutcome,
} from "./send-execute.js";
import { executeAuthorizedSendExternal } from "./send-execute.js";
import type { SendPreflightProbe } from "./send-preflight.js";
import { compareAmounts } from "./types.js";

// ─── Gate ────────────────────────────────────────────────────────────────────

const WALLET_FILE = process.env.ZUP_LIVE_CHAIN_WALLET_FILE ?? "";
const LIVE = process.env.SEND_EXECUTE_LIVE === "1" && WALLET_FILE !== "";
const GATEWAY =
  process.env.SPLITCHAIN_GATEWAY_URLS?.split(",")[0]?.trim() ??
  "https://gateway-entry-1-q2whsu3jlj.splitchain.com/";
/** bound. Overridable downward only. */
const AMOUNT = process.env.SEND_EXECUTE_AMOUNT ?? "0.000001";
const DB = process.env.SEND_EXECUTE_DATABASE ?? "send_execute_live";
const ARTIFACTS =
  process.env.SEND_EXECUTE_ARTIFACTS ??
  join(dirname(fileURLToPath(import.meta.url)), "../../../../.send-execute-evidence");

// ─── Ed25519 over raw base64url key material (no libsodium dependency) ───────

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

// ─── psql helpers (same discipline as the existing *.pg.test.ts drills) ──────

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
/** Select-or-insert a natural-keyed identity row so re-runs reuse the existing row. */
function ensureId(selectSql: string, insertSql: string): string {
  const existing = psql(selectSql).trim();
  if (existing !== "") return existing;
  psql(insertSql);
  return psql(selectSql).trim();
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

// ─── Gateway adapter: one exchange, raw bytes captured pre-parse ─────────────

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
  /** The settled transaction the gateway returned as this key's head, or null at genesis. */
  readonly head: Record<string, unknown> | null;
}

async function readHead(publicKey: string): Promise<HeadRead> {
  const raw = await gatewayExchange("get_transaction__v1", {
    key_public__base64urlsafe: publicKey,
  });
  const parsed = JSON.parse(raw.bodyText) as {
    status?: boolean;
    data?: unknown;
  };
  const rows = Array.isArray(parsed.data) ? (parsed.data as Record<string, unknown>[]) : [];
  return { raw, head: rows[0] ?? null };
}

function projectionFor(head: Record<string, unknown> | null, publicKey: string): WalletStateProjection {
  if (head === null) return GENESIS_PROJECTION;
  const result = projectRoleRelativeState(
    head as never,
    publicKey as never,
  );
  if (!result.ok) throw new Error(`role projection failed: ${result.detail}`);
  return result.projection;
}

// ─── The run ────────────────────────────────────────────────────────────────

interface RunIdentities {
  readonly nodeId: string;
  readonly implementerId: string;
  readonly sourceWalletId: string;
  readonly operationId: string;
  readonly approvalId: string;
  readonly challengeId: string;
  readonly leaseGroupId: string;
  readonly membershipId: string;
  readonly instanceId: string;
}

let ready = false;
let identities: RunIdentities;
let sourcePublicKey = "";
let sourcePrivate: KeyObject;
let recipientPublicKey = "";
let recipientPrivate: KeyObject;
const totpSecret = Buffer.from("send-execute-live-send-external-totp-secret", "utf8");
/** Nonce of the one issued approval challenge; consumed exactly once at step 6. */
let challengeNonce = "";

describe.skipIf(!LIVE)("one live SEND_EXTERNAL", () => {
  beforeAll(() => {
    if (!pgReachable()) throw new Error(`SEND_EXECUTE_DATABASE ${DB} is not reachable`);

    const backup = JSON.parse(readFileSync(WALLET_FILE, "utf8")) as {
      user_wallet: {
        key_public__base64urlsafe: string;
        key_private__base64urlsafe: string;
      };
    };
    sourcePublicKey = backup.user_wallet.key_public__base64urlsafe;
    // The backup stores the 64-byte libsodium secret key (seed ‖ public); Node needs the seed.
    sourcePrivate = privateKeyFromSeed(
      fromBase64Url(backup.user_wallet.key_private__base64urlsafe).subarray(0, 32),
    );

    // Disposable throwaway counterparty — single-use, never reused, never a node wallet.
    // SEND_EXECUTE_RECIPIENT_SEED lets the runner pin the destination key BEFORE the run so the
    // exact counterparty can be recorded in the ticket ahead of any irreversible step.
    const seedEnv = process.env.SEND_EXECUTE_RECIPIENT_SEED;
    const seed = seedEnv === undefined ? randomBytes(32) : fromBase64Url(seedEnv);
    recipientPrivate = privateKeyFromSeed(seed);
    recipientPublicKey = toPaddedBase64Url(
      createPublicKey(recipientPrivate).export({ format: "der", type: "spki" }).subarray(12),
    );

    identities = {
      nodeId: randomUUID(),
      implementerId: randomUUID(),
      sourceWalletId: randomUUID(),
      operationId: randomUUID(),
      approvalId: randomUUID(),
      challengeId: randomUUID(),
      leaseGroupId: randomUUID(),
      membershipId: randomUUID(),
      instanceId: randomUUID(),
    };

    // Node / implementer / wallet identities are keyed by natural UNIQUE columns, so a
    // repeat run against the same database reuses the existing rows rather than colliding.
    const implementerId = ensureId(
      `SELECT id FROM implementers WHERE name = 'fixture-live' LIMIT 1`,
      `INSERT INTO implementers (id, name) VALUES (${lit(identities.implementerId)}, 'fixture-live')`,
    );
    const nodeId = ensureId(
      `SELECT id FROM nodes WHERE identity_public_key = ${lit(sourcePublicKey)} LIMIT 1`,
      `INSERT INTO nodes (id, display_name, identity_public_key) VALUES ` +
        `(${lit(identities.nodeId)}, 'fixture-live', ${lit(sourcePublicKey)})`,
    );
    const sourceWalletId = ensureId(
      `SELECT id FROM wallets WHERE node_id = ${lit(nodeId)} AND public_key = ${lit(sourcePublicKey)} LIMIT 1`,
      `INSERT INTO wallets (id, node_id, public_key, key_origin, state) VALUES ` +
        `(${lit(identities.sourceWalletId)}, ${lit(nodeId)}, ${lit(sourcePublicKey)}, ` +
        `'node_generated', 'AVAILABLE')`,
    );
    identities = { ...identities, implementerId, nodeId, sourceWalletId };

    const idem = `send-execute-${identities.operationId}`;
    const requestSha = createHash("sha256").update(idem, "utf8").digest("hex");
    psql(
        // CREATED with immutable economic fields; no lease, no preimage.
        `INSERT INTO send_operations (operation_id, implementer_id, node_id, kind, status, ` +
        `formation_state, http_method, route, idempotency_key, request_sha256, source_wallet_id, ` +
        `destination_address, amount_zkz) VALUES (${lit(identities.operationId)}, ` +
        `${lit(identities.implementerId)}, ${lit(identities.nodeId)}, 'SEND_EXTERNAL', 'CREATED', ` +
        `'APPROVAL_PENDING', 'POST', '/v1/external-sends', ${lit(idem)}, ${lit(requestSha)}, ` +
        `${lit(identities.sourceWalletId)}, ${lit(recipientPublicKey)}, ${lit(AMOUNT)});` +
        `INSERT INTO operations (id, node_id, implementer_id, kind, status, amount_zkz, ` +
        `source_wallet_id, destination_address, idempotency_key, request_sha256, formation_state) ` +
        `VALUES (${lit(identities.operationId)}, ${lit(identities.nodeId)}, ` +
        `${lit(identities.implementerId)}, 'SEND_EXTERNAL', 'CREATED', ${lit(AMOUNT)}, ` +
        `${lit(identities.sourceWalletId)}, ${lit(recipientPublicKey)}, ${lit(idem)}, ` +
        `${lit(requestSha)}, 'APPROVAL_PENDING');`,
    );
    challengeNonce = randomUUID();
    mkdirSync(ARTIFACTS, { recursive: true });
    ready = true;
  });

  afterAll(() => {
    if (ready) {
      // Leave every evidence row in place; only drop the process-local lease pin.
      psql(`DELETE FROM wallet_active_leases WHERE operation_id = ${lit(identities.operationId)};`);
    }
  });

  it("consumes one approval, persists one partial, and the recipient submits", async () => {
    expect(compareAmounts(AMOUNT, SEND_AMOUNT_HARD_CAP)).toBeLessThanOrEqual(0);

    const rawCaptures: Record<string, RawExchange> = {};
    let sourceHead: Record<string, unknown> | null = null;

    const probe: SendPreflightProbe = {
      loadSource: async () => ({
        walletId: identities.sourceWalletId,
        pubkey: sourcePublicKey,
        keyOrigin: "node_generated",
        walletState: "AVAILABLE",
        nodeControlled: true,
        backupPresent: true,
        backupCapturedAt: new Date().toISOString(),
      }),
      loadRecipient: async (destinationAddress) => ({
        destinationAddress,
        resolvesToNodeBlessedSet: false,
        isNodeControlledWallet: false,
        keyholderId: "send-execute-disposable-throwaway",
        independentControlNote:
          "single-use throwaway keypair generated for this run; discarded afterwards; never a node treasury wallet",
      }),
      activeLeases: async (walletId) =>
        JSON.parse(
          psql(
            `SELECT coalesce(json_agg(json_build_object('walletId', wallet_id, 'leaseRole', lease_role, ` +
              `'operationId', operation_id, 'leaseEpoch', lease_epoch)), '[]')::text ` +
              `FROM wallet_active_leases WHERE wallet_id = ${lit(walletId)}`,
          ).trim(),
        ) as never,
      freshGatewayBalance: async () => {
        const read = await readHead(sourcePublicKey);
        rawCaptures["preflight_balance"] = read.raw;
        sourceHead = read.head;
        return projectionFor(read.head, sourcePublicKey).B;
      },
      loadOperation: async (operationId) => {
        const row = psql(
          `SELECT status || '|' || formation_state FROM send_operations WHERE operation_id = ${lit(operationId)}`,
        ).trim();
        const [status] = row.split("|");
        return {
          operationId,
          status: status ?? "CREATED",
          sourceWalletId: identities.sourceWalletId,
          sourcePubkey: sourcePublicKey,
          destinationAddress: recipientPublicKey,
          amountZkz: AMOUNT,
          referencesOperationId: null,
          expectedArtifactPresent: true,
          expectedArtifactFieldOrder: [...SEND_EXPECTED_FIELD_ORDER],
          sourceLeaseHeld: false,
          splitChainPreimageExists: false,
          approvalConsumed: false,
        } as never;
      },
      // The exact zp-send-external-approval-v1 challenge, issued fresh and
      // still unconsumed at preflight time. The nonce here is the one the approval seam
      // consumes below; refreshing may change only the nonce and freshness fields.
      loadApprovalChallenge: async (operationId) => ({
        purpose: SEND_APPROVAL_PURPOSE,
        canonicalVersion: 1,
        nodeId: identities.nodeId,
        operationId,
        sourceSelector: { kind: "WALLET_ID", wallet_id: identities.sourceWalletId },
        sourcePubkey: sourcePublicKey,
        destinationAddress: recipientPublicKey,
        amountZkz: AMOUNT,
        referencesOperationId: null,
        nonce: challengeNonce,
        issuedAt: new Date(Date.now() - 1_000).toISOString(),
        expiresAt: new Date(Date.now() + 240_000).toISOString(),
        fieldOrder: [...SEND_APPROVAL_FIELD_ORDER],
        carriesSplitInnerSha256: false,
        consumed: false,
      }),
      freshVaultBackup: async () => ({ present: true, capturedAt: new Date().toISOString() }),
    };

    const deps: SendExecuteDeps = {
      // One fresh single-use TOTP, consumed atomically with the
      // challenge nonce and the CREATED → APPROVED transition.
      approval: {
        consumeApprovalOnce: async ({ operationId }) => {
          const nowMs = Date.now();
          const code = totpCodeFor(Math.floor(nowMs / 1000 / 30));
          const match = matchTotp({ secret: totpSecret }, { code, nowMs });
          if (!match.ok) throw new Error(`TOTP did not match: ${match.reason}`);

          const nonce = challengeNonce;
          const preimage = JSON.stringify({
            purpose: "zp-send-external-approval-v1",
            operation_id: operationId,
            nonce,
          });
          const preimageSha = createHash("sha256").update(preimage, "utf8").digest("hex");
          // The burn row is the single-use arbiter (UNIQUE node_id/timestep/purpose) and
          // the approval row + status change commit in the SAME transaction.
          psql(
            `BEGIN;` +
              // The issued challenge this approval consumes.
              `INSERT INTO approval_challenges (id, node_id, operation_id, status, purpose, ` +
              `canonical_version, nonce, preimage_text, preimage_sha256, issued_at, expires_at) ` +
              `VALUES (${lit(identities.challengeId)}, ${lit(identities.nodeId)}, ${lit(operationId)}, ` +
              `'ISSUED', 'zp-send-external-approval-v1', 1, ${lit(nonce)}, ${lit(preimage)}, ` +
              `${lit(preimageSha)}, now(), now() + interval '5 minutes');` +
              // Steps 5–6 — nonce and timestep consumed atomically with the state change.
              `UPDATE approval_challenges SET status = 'CONSUMED' WHERE id = ${lit(identities.challengeId)};` +
              `INSERT INTO totp_timestep_burns (id, node_id, totp_timestep, purpose, operation_id, burned_at) ` +
              `VALUES (${lit(randomUUID())}, ${lit(identities.nodeId)}, ${match.timestep}, ` +
              `'SEND_EXTERNAL_APPROVAL', ${lit(operationId)}, now());` +
              `INSERT INTO operation_approvals (id, node_id, operation_id, challenge_id, ` +
              `challenge_status, method, purpose, canonical_version, preimage_text, preimage_sha256, ` +
              `totp_timestep, consumed_at) VALUES (${lit(identities.approvalId)}, ` +
              `${lit(identities.nodeId)}, ${lit(operationId)}, ${lit(identities.challengeId)}, ` +
              `'CONSUMED', 'TOTP_ONLY', 'zp-send-external-approval-v1', 1, ${lit(preimage)}, ` +
              `${lit(preimageSha)}, ${match.timestep}, now());` +
              `UPDATE send_operations SET status = 'APPROVED', formation_state = 'APPROVED_UNSIGNED', ` +
              `row_version = row_version + 1 WHERE operation_id = ${lit(operationId)} AND status = 'CREATED';` +
              `UPDATE operations SET status = 'APPROVED', formation_state = 'APPROVED_UNSIGNED' ` +
              `WHERE id = ${lit(operationId)};` +
              `COMMIT;`,
          );
          return {
            approvalId: identities.approvalId,
            challengeNonce: nonce,
            totpTimestep: match.timestep,
            statusAfter: "APPROVED",
            totpConsumptionCount: count(
              `SELECT count(*) FROM operation_approvals WHERE operation_id = ${lit(operationId)}`,
            ),
          };
        },
      },

      // Source lease before any formation/landing gateway read below (preflight probe already counted).
      leases: {
        acquireSourceLease: async ({ operationId, sourceWalletId }) => {
          psql(
            `INSERT INTO wallet_active_leases (wallet_id, membership_id, lease_group_id, ` +
              `root_operation_id, operation_id, lease_role, lease_epoch, acquired_at, heartbeat_at, ` +
              `owner_instance_id) VALUES (${lit(sourceWalletId)}, ${lit(identities.membershipId)}, ` +
              `${lit(identities.leaseGroupId)}, ${lit(operationId)}, ${lit(operationId)}, ` +
              `'SEND_SOURCE', 1, now(), now(), ${lit(identities.instanceId)});`,
          );
          return {
            walletId: sourceWalletId,
            operationId,
            leaseEpoch: 1n,
            role: "SEND_SOURCE",
            lifecycle: "ACTIVE",
          };
        },
      },

      // Real gateway reads, raw bytes retained.
      observe: {
        observeVerified: async ({ publicKey, role }): Promise<SendObservation> => {
          const read = await readHead(publicKey);
          rawCaptures[role] = read.raw;
          if (role === "SEND_SOURCE_T0") sourceHead = read.head;
          return {
            role,
            publicKey,
            observationId: randomUUID(),
            projection: projectionFor(read.head, publicKey),
            rawResponseSha256: read.raw.responseSha256,
            rawResponseByteLength: read.raw.byteLength,
          };
        },
        observeSourceLanding: async ({
          publicKey,
          persistedInnerPreimageText,
          persistedStep1Signature,
        }) => {
          // Independent fresh read of the SOURCE key through the node's own path — never
          // the recipient's word. Bounded wait, no submit, no retry
          // of anything that mutates.
          for (let attempt = 0; attempt < 10; attempt += 1) {
            const read = await readHead(publicKey);
            rawCaptures[`landing_attempt_${attempt}`] = read.raw;
            const head = read.head;
            if (head !== null) {
              const innerText = extractInnerText(read.raw.bodyText);
              const step1 = (head as { step_1_signature?: string }).step_1_signature ?? "";
              if (innerText === persistedInnerPreimageText && step1 === persistedStep1Signature) {
                return {
                  publicKey,
                  observationId: randomUUID(),
                  step2Signature: (head as { step_2_signature?: string }).step_2_signature ?? "",
                  balanceAfter: projectionFor(head, publicKey).B,
                  innerTextMatchesPersisted: true,
                  step1SignatureMatchesPersisted: true,
                  rawResponseSha256: read.raw.responseSha256,
                  rawResponseByteLength: read.raw.byteLength,
                };
              }
            }
            await new Promise((r) => setTimeout(r, 3_000));
          }
          return null;
        },
      },

      // The key-custody rule — the key never leaves this closure; only the signature comes back.
      signer: {
        signStep1: async ({ preimageText }) => signText(sourcePrivate, preimageText),
      },

      persist: {
        persistSignIntent: async (input) => {
          psql(
            `BEGIN;` +
              `INSERT INTO external_send_sign_intents (operation_id, approval_id, source_wallet_id, ` +
              `source_t0_observation_id, destination_t0_observation_id, lease_group_id, lease_epoch, ` +
              `inner_preimage_text, inner_sha256, redemption_expiry_at, prepared_at) VALUES (` +
              `${lit(input.operationId)}, ${lit(identities.approvalId)}, ${lit(identities.sourceWalletId)}, ` +
              `${lit(input.sourceObservationId)}, ${lit(input.destinationObservationId)}, ` +
              `${lit(identities.leaseGroupId)}, ${input.sourceLeaseEpoch}, ` +
              `${lit(input.innerPreimageText)}, ${lit(input.innerSha256)}, ` +
              `${lit(input.redemptionExpiryAt)}, now());` +
              `INSERT INTO operation_transactions (operation_id, attempt_no, attempt_phase, ` +
              `inner_preimage_text, inner_sha256, formed_at) VALUES (${lit(input.operationId)}, 1, ` +
              `'INNER_PREIMAGE_PERSISTED', ${lit(input.innerPreimageText)}, ${lit(input.innerSha256)}, now());` +
              `UPDATE send_operations SET formation_state = 'SIGNING_CLAIMED' ` +
              `WHERE operation_id = ${lit(input.operationId)};` +
              `COMMIT;`,
          );
          return { innerPreimageId: input.operationId };
        },
        persistStep1AndTransferCode: async (input) => {
          psql(
            `BEGIN;` +
              `INSERT INTO external_send_partials (operation_id, approval_id, inner_sha256, ` +
              `step_1_signature, transfer_code_text, transfer_code_sha256, persisted_at) ` +
              `SELECT ${lit(input.operationId)}, ${lit(identities.approvalId)}, i.inner_sha256, ` +
              `${lit(input.step1Signature)}, ${lit(input.transferCodeText)}, ` +
              `${lit(input.transferCodeSha256)}, now() FROM external_send_sign_intents i ` +
              `WHERE i.operation_id = ${lit(input.operationId)};` +
              `UPDATE operation_transactions SET attempt_phase = 'STEP1_SIGNATURE_PERSISTED', ` +
              `step_1_signature = ${lit(input.step1Signature)} ` +
              `WHERE operation_id = ${lit(input.operationId)} AND attempt_no = 1;` +
              `UPDATE send_operations SET status = 'AWAITING_REDEMPTION', ` +
              `formation_state = 'PARTIAL_PERSISTED', row_version = row_version + 1 ` +
              `WHERE operation_id = ${lit(input.operationId)} AND status = 'APPROVED';` +
              // The generic `operations` lockstep now admits AWAITING_REDEMPTION at
              // PARTIAL_PERSISTED, matching send_operations. Mirror both.
              `UPDATE operations SET status = 'AWAITING_REDEMPTION', ` +
              `formation_state = 'PARTIAL_PERSISTED' ` +
              `WHERE id = ${lit(input.operationId)};` +
              `COMMIT;`,
          );
          const status = psql(
            `SELECT status FROM send_operations WHERE operation_id = ${lit(input.operationId)}`,
          ).trim();
          if (status !== "AWAITING_REDEMPTION") {
            throw new Error(`status after partial persist is ${status}`);
          }
          return { statusAfter: "AWAITING_REDEMPTION" };
        },
        countRows: async (operationId) => ({
          totpConsumptions: count(
            `SELECT count(*) FROM totp_timestep_burns WHERE operation_id = ${lit(operationId)}`,
          ),
          signIntents: count(
            `SELECT count(*) FROM external_send_sign_intents WHERE operation_id = ${lit(operationId)}`,
          ),
          partials: count(
            `SELECT count(*) FROM external_send_partials WHERE operation_id = ${lit(operationId)}`,
          ),
          submitDecisions: count(
            `SELECT count(*) FROM submit_decisions WHERE operation_id = ${lit(operationId)}`,
          ),
          gatewaySubmitAttempts: count(
            `SELECT count(*) FROM gateway_submit_attempts WHERE operation_id = ${lit(operationId)}`,
          ),
        }),
      },

      // Delivery reads the PERSISTED bytes back, never the in-memory copy.
      delivery: {
        deliver: async ({ operationId }) => {
          psql(
            `UPDATE external_send_partials SET ` +
              `first_delivered_at = coalesce(first_delivered_at, now()), ` +
              `last_redelivered_at = CASE WHEN first_delivered_at IS NULL THEN NULL ELSE now() END, ` +
              `redelivery_count = redelivery_count + CASE WHEN first_delivered_at IS NULL THEN 0 ELSE 1 END ` +
              `WHERE operation_id = ${lit(operationId)};`,
          );
          const row = psql(
            `SELECT transfer_code_text || E'\\t' || transfer_code_sha256 || E'\\t' || redelivery_count ` +
              `FROM external_send_partials WHERE operation_id = ${lit(operationId)}`,
          ).trim();
          const [text, sha, redeliveries] = row.split("\t");
          return {
            deliveryNo: Number(redeliveries ?? "0") + 1,
            transferCodeText: text ?? "",
            transferCodeSha256: sha ?? "",
          };
        },
      },

      // THE external recipient. Everything here happens outside the node: its own
      // key, its own verification, its own single submit.
      recipient: {
        verifyCoSignAndSubmit: async ({
          transferCodeText,
          destinationFormationBaseline,
          expectedDestinationAddress,
        }): Promise<SendRecipientOutcome> => {
          const envelope = JSON.parse(
            decodeURIComponent(Buffer.from(transferCodeText, "base64url").toString("utf8")),
          ) as {
            incoming_data: {
              partial_transaction: {
                inner: Record<string, unknown>;
                step_1_signature: string;
              };
            };
          };
          const partial = envelope.incoming_data.partial_transaction;
          // Recover the inner's EXACT bytes from the delivered code — never re-serialize
          // a parsed object into the signing payload (the byte-exact signing rule).
          const innerText = extractInnerText(
            decodeURIComponent(Buffer.from(transferCodeText, "base64url").toString("utf8")),
          );

          if (partial.inner["step_2_key_public__base64urlsafe"] !== expectedDestinationAddress) {
            return refusal("partial is not addressed to this recipient");
          }
          if (!verifyText(sourcePublicKey, innerText, partial.step_1_signature)) {
            return {
              kind: "REFUSED_VERIFICATION_FAILED",
              detail: "step-1 signature does not verify against the source public key",
              step2Signature: null,
              rawGatewayResponseBase64: null,
              rawGatewayResponseSha256: null,
              gatewayStatusCode: null,
              recipientSubmitCallCount: 0,
            };
          }
          // The recipient requires its own CURRENT head to still match the
          // persisted destination formation baseline, else it refuses the stale partial.
          const own = await readHead(expectedDestinationAddress);
          rawCaptures["recipient_own_head"] = own.raw;
          const ownProjection = projectionFor(own.head, expectedDestinationAddress);
          if (
            ownProjection.S !== destinationFormationBaseline.S ||
            ownProjection.B !== destinationFormationBaseline.B
          ) {
            return refusal(
              `recipient head moved since formation (S ${ownProjection.S === "" ? "∅" : "set"}, B ${ownProjection.B})`,
            );
          }

          const step2PreimageText = `{"inner":${innerText},"step_1_signature":${JSON.stringify(partial.step_1_signature)}}`;
          const step2Signature = signText(recipientPrivate, step2PreimageText);
          const transactionText = `{"inner":${innerText},"step_1_signature":${JSON.stringify(partial.step_1_signature)},"step_2_signature":${JSON.stringify(step2Signature)}}`;

          // The byte-exact signing rule — the submitted action_data must be byte-identical to the text
          // the recipient signed over. Refuse rather than submit different bytes.
          const actionData: unknown = JSON.parse(transactionText);
          if (JSON.stringify(actionData) !== transactionText) {
            return refusal("re-serialized transaction bytes differ from the signed text");
          }

          try {
            // ONE submit. No retry, no failover, no second attempt on any outcome.
            const raw = await gatewayExchange("submit_transaction__v1", actionData);
            rawCaptures["recipient_submit"] = raw;
            const ok = (JSON.parse(raw.bodyText) as { status?: boolean }).status === true;
            return {
              kind: ok ? "SUBMITTED" : "INDETERMINATE",
              detail: raw.bodyText.slice(0, 400),
              step2Signature,
              rawGatewayResponseBase64: Buffer.from(raw.bodyText, "utf8").toString("base64"),
              rawGatewayResponseSha256: raw.responseSha256,
              gatewayStatusCode: raw.statusCode,
              recipientSubmitCallCount: 1,
            };
          } catch (err) {
            // The never-blind-retry rule — an ambiguous submit is reconciled by reading, never retried.
            return {
              kind: "INDETERMINATE",
              detail: err instanceof Error ? err.message : String(err),
              step2Signature,
              rawGatewayResponseBase64: null,
              rawGatewayResponseSha256: null,
              gatewayStatusCode: null,
              recipientSubmitCallCount: 1,
            };
          }
        },
      },
    };

    const result = await executeAuthorizedSendExternal(deps, {
      attemptId: `send-execute-${identities.operationId}`,
      operationId: identities.operationId,
      sourceWalletId: identities.sourceWalletId,
      sourcePubkey: sourcePublicKey,
      destinationAddress: recipientPublicKey,
      amount: AMOUNT,
      authorization: {
        attemptId: `send-execute-${identities.operationId}`,
        attestationId: "dual-control-both-ends-agent-held",
        recordedAt: new Date().toISOString(),
      },
      runnerLock: createRunnerLock(),
      runnerHolderId: "fixture-live-runner",
      preflightProbe: probe,
    });
    result.runnerLockHandle?.release();

    writeFileSync(
      join(ARTIFACTS, `send-execute-${identities.operationId}.json`),
      JSON.stringify(
        {
          gateway: GATEWAY,
          amountZkz: AMOUNT,
          sourcePublicKey,
          destinationPublicKey: recipientPublicKey,
          sourceHeadAtStart: sourceHead,
          evidence: result.evidence,
          rawGatewayExchanges: rawCaptures,
        },
        null,
        2,
      ),
      "utf8",
    );

    // ── Reviewer's evidence ────────────────────────────────────────────────
    expect(result.evidence.leaseHeldBeforeFormationReads).toBe(true);
    // Preflight balance probe is a real gateway read and must be counted.
    // Live runner is default-off; when it runs, preflight_balance is among raw captures.
    expect(result.evidence.preflightGatewayReadCount).toBeGreaterThanOrEqual(1);
    expect(result.evidence.gatewayReadCount).toBeGreaterThanOrEqual(
      result.evidence.preflightGatewayReadCount + 2, // + formation pair at minimum
    );
    expect(
      result.evidence.trail.some((line) => line.includes("preflight_gateway_reads=")),
    ).toBe(true);
    expect(
      result.evidence.trail.some((line) => line.includes("before formation gateway reads")),
    ).toBe(true);
    expect(result.evidence.approval?.totpConsumptionCount).toBe(1);
    expect(result.evidence.rowCounts).toEqual({
      totpConsumptions: 1,
      signIntents: 1,
      partials: 1,
      submitDecisions: 0,
      gatewaySubmitAttempts: 0,
    });
    expect(result.evidence.deliveries).toHaveLength(2);
    expect(result.evidence.deliveries[1]?.transferCodeText).toBe(
      result.evidence.deliveries[0]?.transferCodeText,
    );
    expect(result.evidence.recipient?.recipientSubmitCallCount).toBe(1);
    expect(result.evidence.recipient?.rawGatewayResponseSha256).not.toBeNull();
    // The composite PK (operation_id, attempt_no CHECK = 1) makes a second attempt
    // unrepresentable; assert the row that exists is the only one.
    expect(
      count(
        `SELECT count(*) FROM operation_transactions WHERE operation_id = ${lit(identities.operationId)}`,
      ),
    ).toBe(1);
    expect(result.evidence.disposition).toBe("LANDED_VERIFIED");
  }, 300_000);
});

// ─── small helpers ──────────────────────────────────────────────────────────

function refusal(detail: string): SendRecipientOutcome {
  return {
    kind: "REFUSED_STALE_DESTINATION",
    detail,
    step2Signature: null,
    rawGatewayResponseBase64: null,
    rawGatewayResponseSha256: null,
    gatewayStatusCode: null,
    recipientSubmitCallCount: 0,
  };
}

/**
 * Slice the EXACT `"inner":{…}` bytes out of a JSON document by brace counting. Never
 * `JSON.parse` then re-`stringify` — the signed bytes must survive verbatim (the byte-exact signing rule).
 */
function extractInnerText(documentText: string): string {
  const marker = '"inner":';
  const start = documentText.indexOf(marker);
  if (start < 0) return "";
  let depth = 0;
  for (let i = start + marker.length; i < documentText.length; i += 1) {
    const ch = documentText[i];
    if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return documentText.slice(start + marker.length, i + 1);
    }
  }
  return "";
}

/** RFC 6238 HOTP over the run's TOTP secret — the operator's authenticator app stand-in. */
function totpCodeFor(timestep: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(timestep));
  const hmac = createHmac("sha1", totpSecret).update(counter).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const code =
    ((hmac[offset]! & 0x7f) << 24) |
    (hmac[offset + 1]! << 16) |
    (hmac[offset + 2]! << 8) |
    hmac[offset + 3]!;
  return (code % 1_000_000).toString().padStart(6, "0");
}

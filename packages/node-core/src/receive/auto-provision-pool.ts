// GN-102 automatic Main Reserve plus the worker-pool floors.
//
// One call mints, under the scale-up advisory lock: the Main Reserve
// (INTERNAL_ONLY, display label, BLESSED destination), then SEND_ONLY workers
// up to SEND_POOL_FLOOR, then RECEIVE_ONLY workers up to POOL_FLOOR, stopping
// when the wallet cap is hit. The cap counts every wallet row.
//
// Receive workers stay PENDING so the allocator can still select them.
// Blessing a receive worker would hide it from that selection. Send workers
// stay WORKER. Only reserve wallets are blessed, and the artifact records a
// system auto-bless under the vault master (no enrolled-device ceremony).
//
// Recovery stamp and the setting-write audit run only after seal commits.
// A verification row or a wallet-referencing audit row blocks wallet delete,
// so a seal miss can still compensate by deleting the destination then the
// wallet. The lock is not held across seal.
//
// This module does not import the vault. The caller seals.

import { createHash, generateKeyPairSync, randomUUID } from "node:crypto";

import {
  deleteNodeGeneratedWalletMint,
  insertNodeGeneratedWalletWithPendingDestination,
  type NodeGeneratedMintRole,
  type NodeGeneratedWalletSqlExecutor,
} from "../api/insert-node-generated-wallet.js";
import {
  POOL_FLOOR,
  POOL_SCALE_UP_LOCK_KEY,
  POOL_SCALER_STATEMENTS,
  PoolScalerError,
  SEND_POOL_FLOOR,
} from "./pool-scaler.js";

export const MAIN_RESERVE_DISPLAY_LABEL = "Main Reserve";
export const DEFAULT_FUNDING_WALLET_SETTING_KEY = "integration.default_funding_wallet_id";
/** No foreign key on destinations.blessed_by_device_key_id. Marker only. */
export const SYSTEM_BLESS_DEVICE_KEY_ID = "00000000-0000-4000-8000-000000000102";
const SYSTEM_BLESS_SIGNATURE = `${"A".repeat(86)}==`;

export class ReservePoolCapError extends Error {
  readonly code = "conflict" as const;

  constructor() {
    super("wallet cap reached");
    this.name = "ReservePoolCapError";
  }
}

export interface EnsureNodeReserveDeps {
  readonly nodeId: string;
  readonly poolCapTotal: number;
  readonly withTx: <T>(fn: (sql: NodeGeneratedWalletSqlExecutor) => Promise<T>) => Promise<T>;
  readonly query: NodeGeneratedWalletSqlExecutor["query"];
  readonly seal: (input: {
    readonly walletId: string;
    readonly publicKey: string;
    readonly secret: Uint8Array;
  }) => Promise<void>;
  readonly onWalletsMinted?: (walletIds: readonly string[]) => void | Promise<void>;
}

const LOCK_SQL = POOL_SCALER_STATEMENTS.LOCK_SCALE_UP;

const READ_SETTING_SQL = `
SELECT setting_value
  FROM node_settings
 WHERE setting_key = $1`;

const READ_RESERVE_SQL = `
SELECT id::text AS id
  FROM wallets
 WHERE display_label = $1
   AND node_id = $2::uuid
   AND money_mode = 'INTERNAL_ONLY'
   AND key_origin = 'node_generated'
 LIMIT 1`;

const READ_DESTINATION_SQL = `
SELECT id::text AS id
  FROM destinations
 WHERE wallet_id = $1::uuid
 LIMIT 1`;

/** Insert the verification only when the wallet is still unstamped, so a miss leaves no row. */
export const STAMP_RECOVERY_UNDER_VAULT_SQL = `
WITH target AS (
  SELECT id, public_key
    FROM wallets
   WHERE id = $1::uuid
     AND recovery_verified_at IS NULL
     AND public_key = $2
), verif AS (
  INSERT INTO wallet_recovery_verifications (
    id, wallet_id, method, public_key, export_sha256, audit_event_id,
    verified_at, verifier_identity
  )
  SELECT gen_random_uuid(), target.id, 'AUDITED_EXPORT', target.public_key,
         $3, $4::uuid, now(), 'SYSTEM'
    FROM target
  RETURNING id, verified_at, wallet_id
), stamped AS (
  UPDATE wallets AS w
     SET recovery_verified_at = verif.verified_at,
         recovery_verification_id = verif.id
    FROM verif
   WHERE w.id = verif.wallet_id
     AND w.recovery_verified_at IS NULL
  RETURNING w.id
) SELECT stamped.id AS id FROM stamped`;

export const BLESS_RESERVE_DESTINATION_SQL = `
WITH artifact AS (
  INSERT INTO destination_blessing_artifacts (
    id, purpose, canonical_version, node_id, destination_id, wallet_id,
    wallet_pubkey, nonce, issued_at, expires_at, device_signature,
    preimage_text, preimage_sha256, created_at
  ) VALUES (
    gen_random_uuid(), 'zp-destination-bless-v1', 1, $1::uuid, $2::uuid, $3::uuid,
    $4, gen_random_uuid(), now(), now() + interval '60 seconds', $5,
    $6, $7, now()
  )
  RETURNING id
), blessed AS (
  UPDATE destinations AS d
     SET state = 'BLESSED',
         blessed_at = now(),
         blessed_by_device_key_id = $8::uuid,
         blessing_artifact_id = artifact.id
    FROM artifact
   WHERE d.id = $2::uuid
     AND d.state = 'PENDING'
  RETURNING d.id
) SELECT blessed.id AS id FROM blessed`;

export const WRITE_MAIN_RESERVE_SETTING_SQL = `
WITH upserted AS (
  INSERT INTO node_settings (setting_key, setting_value, row_version, updated_at)
  VALUES ($1, $2, 1, now())
  ON CONFLICT (setting_key) DO NOTHING
  RETURNING setting_key
), audited AS (
  INSERT INTO audit_log (
    id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
    details_text, details_sha256, created_at
  )
  SELECT gen_random_uuid(), $3::uuid, 'SYSTEM', 'SYSTEM',
         'wallet.main_reserve_provisioned', NULL, $4::uuid,
         $5, $6, now()
    FROM upserted
  RETURNING id
) SELECT audited.id AS id FROM audited`;

const CLEAR_SETTING_SQL = `
DELETE FROM node_settings
 WHERE setting_key = $1
   AND setting_value = $2`;

type Snapshot = {
  readonly settingValue: string | null;
  readonly reserveWalletId: string | null;
  readonly capCount: number;
  readonly sendWalletCount: number;
  readonly receiveWalletCount: number;
};

type NextMint = {
  readonly kind: "mint";
  readonly role: NodeGeneratedMintRole;
} | {
  readonly kind: "repair";
} | {
  readonly kind: "done";
};

function assertPoolCap(poolCapTotal: number): void {
  if (!Number.isInteger(poolCapTotal) || poolCapTotal < POOL_FLOOR) {
    throw new PoolScalerError(
      "POOL_CAP_INVALID",
      `POOL_CAP_TOTAL must be an integer >= ${POOL_FLOOR}, got ${String(poolCapTotal)}`,
    );
  }
}

function asInt(value: unknown): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n)) return 0;
  return n;
}

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function toBase64UrlPadded(bytes: Uint8Array): string {
  const body = Buffer.from(bytes).toString("base64url");
  return body + "=".repeat((4 - (body.length % 4)) % 4);
}

function generateCustodyKey(): { readonly publicKey: string; readonly secret: Buffer } {
  const { privateKey, publicKey: pubObj } = generateKeyPairSync("ed25519");
  const spki = pubObj.export({ format: "der", type: "spki" });
  const rawPub = Buffer.from(spki).subarray(-32);
  const publicKey = toBase64UrlPadded(rawPub);
  const jwk = privateKey.export({ format: "jwk" });
  const d = typeof jwk.d === "string" ? jwk.d : "";
  const seed = Buffer.from(d, "base64url");
  if (seed.length !== 32 || publicKey.length !== 44) {
    seed.fill(0);
    throw new Error("custody key generation failed");
  }
  const secret = Buffer.concat([seed, rawPub]);
  seed.fill(0);
  return { publicKey, secret };
}

async function lock(sql: NodeGeneratedWalletSqlExecutor): Promise<void> {
  await sql.query(LOCK_SQL, [POOL_SCALE_UP_LOCK_KEY]);
}

async function readSnapshot(
  sql: NodeGeneratedWalletSqlExecutor,
  nodeId: string,
): Promise<Snapshot> {
  const setting = await sql.query<{ setting_value: string }>(READ_SETTING_SQL, [
    DEFAULT_FUNDING_WALLET_SETTING_KEY,
  ]);
  const reserve = await sql.query<{ id: string }>(READ_RESERVE_SQL, [
    MAIN_RESERVE_DISPLAY_LABEL,
    nodeId,
  ]);
  const cap = await sql.query<{ cap_count: number }>(POOL_SCALER_STATEMENTS.COUNT_CAP_UNDER_LOCK);
  const send = await sql.query<{ n: number }>(POOL_SCALER_STATEMENTS.COUNT_SEND_WALLETS);
  const receive = await sql.query<{ n: number }>(POOL_SCALER_STATEMENTS.COUNT_RECEIVE_WALLETS);
  const settingValue = setting.rows[0]?.setting_value;
  return {
    settingValue: settingValue === undefined ? null : settingValue,
    reserveWalletId: reserve.rows[0]?.id ?? null,
    capCount: asInt(cap.rows[0]?.cap_count),
    sendWalletCount: asInt(send.rows[0]?.n),
    receiveWalletCount: asInt(receive.rows[0]?.n),
  };
}

function classify(snap: Snapshot, poolCapTotal: number): NextMint {
  if (snap.settingValue === null && snap.reserveWalletId === null) {
    if (snap.capCount >= poolCapTotal) return { kind: "done" };
    return { kind: "mint", role: "INTERNAL_ONLY" };
  }
  if (snap.settingValue === null && snap.reserveWalletId !== null) {
    return { kind: "repair" };
  }
  if (snap.sendWalletCount < SEND_POOL_FLOOR && snap.capCount < poolCapTotal) {
    return { kind: "mint", role: "SEND_ONLY" };
  }
  if (snap.receiveWalletCount < POOL_FLOOR && snap.capCount < poolCapTotal) {
    return { kind: "mint", role: "RECEIVE_ONLY" };
  }
  return { kind: "done" };
}

async function selectDestinationId(
  sql: NodeGeneratedWalletSqlExecutor,
  walletId: string,
): Promise<string> {
  const found = await sql.query<{ id: string }>(READ_DESTINATION_SQL, [walletId]);
  const id = found.rows[0]?.id;
  if (id === undefined || id.length === 0) {
    throw new Error("reserve destination missing after insert");
  }
  return id;
}

async function blessReserveDestination(
  sql: NodeGeneratedWalletSqlExecutor,
  input: {
    readonly nodeId: string;
    readonly destinationId: string;
    readonly walletId: string;
    readonly publicKey: string;
  },
): Promise<void> {
  const preimageText =
    `system auto-bless under vault master node=${input.nodeId} wallet=${input.walletId} destination=${input.destinationId}`;
  const blessed = await sql.query<{ id: string }>(BLESS_RESERVE_DESTINATION_SQL, [
    input.nodeId,
    input.destinationId,
    input.walletId,
    input.publicKey,
    SYSTEM_BLESS_SIGNATURE,
    preimageText,
    sha256Hex(preimageText),
    SYSTEM_BLESS_DEVICE_KEY_ID,
  ]);
  if (blessed.rows.length === 0) {
    throw new Error("reserve destination bless missed");
  }
}

async function writeMainReserveSetting(
  sql: NodeGeneratedWalletSqlExecutor,
  nodeId: string,
  walletId: string,
): Promise<void> {
  const detailsText = JSON.stringify({
    display_label: MAIN_RESERVE_DISPLAY_LABEL,
    wallet_id: walletId,
  });
  await sql.query(WRITE_MAIN_RESERVE_SETTING_SQL, [
    DEFAULT_FUNDING_WALLET_SETTING_KEY,
    walletId,
    nodeId,
    walletId,
    detailsText,
    sha256Hex(detailsText),
  ]);
}

export async function stampRecoveryUnderVault(
  sql: NodeGeneratedWalletSqlExecutor,
  input: { readonly nodeId: string; readonly walletId: string; readonly publicKey: string },
): Promise<boolean> {
  const exportSha = sha256Hex(
    `vault-master:${input.nodeId}:${input.walletId}:${input.publicKey}`,
  );
  const stamped = await sql.query<{ id: string }>(STAMP_RECOVERY_UNDER_VAULT_SQL, [
    input.walletId,
    input.publicKey,
    exportSha,
    randomUUID(),
  ]);
  return stamped.rows.length > 0;
}

async function compensateMint(deps: EnsureNodeReserveDeps, walletId: string): Promise<void> {
  const sql = { query: deps.query };
  try {
    await sql.query(CLEAR_SETTING_SQL, [DEFAULT_FUNDING_WALLET_SETTING_KEY, walletId]);
  } catch {
    /* setting row may already be gone */
  }
  try {
    await deleteNodeGeneratedWalletMint(sql, walletId);
  } catch {
    /* best-effort; the caller still surfaces the original failure */
  }
}

async function notifyMinted(
  deps: EnsureNodeReserveDeps,
  walletId: string,
): Promise<void> {
  if (deps.onWalletsMinted === undefined) return;
  try {
    await deps.onWalletsMinted([walletId]);
  } catch {
    /* push provision is best-effort; the wallet stays */
  }
}

type Step =
  | { readonly kind: "done" }
  | { readonly kind: "repaired" }
  | { readonly kind: "raced" }
  | { readonly kind: "minted"; readonly walletId: string };

async function provisionOne(deps: EnsureNodeReserveDeps): Promise<Step> {
  const preview = await deps.withTx(async (sql) => {
    await lock(sql);
    return classify(await readSnapshot(sql, deps.nodeId), deps.poolCapTotal);
  });
  if (preview.kind === "done") return { kind: "done" };
  if (preview.kind === "repair") {
    await deps.withTx(async (sql) => {
      await lock(sql);
      const snap = await readSnapshot(sql, deps.nodeId);
      if (classify(snap, deps.poolCapTotal).kind === "repair" && snap.reserveWalletId !== null) {
        await writeMainReserveSetting(sql, deps.nodeId, snap.reserveWalletId);
      }
    });
    return { kind: "repaired" };
  }

  const key = generateCustodyKey();
  const walletId = randomUUID();
  try {
    const role = await deps.withTx(async (sql) => {
      await lock(sql);
      const action = classify(await readSnapshot(sql, deps.nodeId), deps.poolCapTotal);
      if (action.kind !== "mint") return null;
      const reserve = action.role === "INTERNAL_ONLY";
      await insertNodeGeneratedWalletWithPendingDestination(sql, {
        walletId,
        nodeId: deps.nodeId,
        publicKey: key.publicKey,
        label: reserve ? MAIN_RESERVE_DISPLAY_LABEL : "",
        role: action.role,
        ...(reserve ? { displayLabel: MAIN_RESERVE_DISPLAY_LABEL } : {}),
      });
      if (reserve) {
        const destinationId = await selectDestinationId(sql, walletId);
        await blessReserveDestination(sql, {
          nodeId: deps.nodeId,
          destinationId,
          walletId,
          publicKey: key.publicKey,
        });
      }
      return action.role;
    });
    if (role === null) return { kind: "raced" };

    let sealed = false;
    try {
      await deps.seal({ walletId, publicKey: key.publicKey, secret: key.secret });
      sealed = true;
      await deps.withTx(async (sql) => {
        const stamped = await stampRecoveryUnderVault(sql, {
          nodeId: deps.nodeId,
          walletId,
          publicKey: key.publicKey,
        });
        if (!stamped) throw new Error("recovery stamp missed");
        if (role === "INTERNAL_ONLY") {
          await writeMainReserveSetting(sql, deps.nodeId, walletId);
        }
      });
    } catch (err) {
      if (sealed || role !== null) await compensateMint(deps, walletId);
      throw err;
    }
    await notifyMinted(deps, walletId);
    return { kind: "minted", walletId };
  } finally {
    key.secret.fill(0);
  }
}

export async function ensureNodeReserveAndWorkerPool(
  deps: EnsureNodeReserveDeps,
): Promise<{ readonly mintedWalletIds: readonly string[] }> {
  assertPoolCap(deps.poolCapTotal);
  const mintedWalletIds: string[] = [];
  const limit = deps.poolCapTotal + 4;
  for (let step = 0; step < limit; step += 1) {
    const outcome = await provisionOne(deps);
    if (outcome.kind === "done") return { mintedWalletIds };
    if (outcome.kind === "minted") mintedWalletIds.push(outcome.walletId);
  }
  throw new Error("reserve pool provisioning did not finish");
}

export async function mintNamedReserveWallet(
  deps: EnsureNodeReserveDeps & { readonly displayLabel: string },
): Promise<{
  readonly walletId: string;
  readonly moneyMode: "INTERNAL_ONLY";
  readonly displayLabel: string;
  readonly destinationState: "BLESSED";
}> {
  assertPoolCap(deps.poolCapTotal);
  const key = generateCustodyKey();
  const walletId = randomUUID();
  let committed = false;
  try {
    await deps.withTx(async (sql) => {
      await lock(sql);
      const snap = await readSnapshot(sql, deps.nodeId);
      if (snap.capCount >= deps.poolCapTotal) throw new ReservePoolCapError();
      await insertNodeGeneratedWalletWithPendingDestination(sql, {
        walletId,
        nodeId: deps.nodeId,
        publicKey: key.publicKey,
        label: deps.displayLabel,
        role: "INTERNAL_ONLY",
        displayLabel: deps.displayLabel,
      });
      const destinationId = await selectDestinationId(sql, walletId);
      await blessReserveDestination(sql, {
        nodeId: deps.nodeId,
        destinationId,
        walletId,
        publicKey: key.publicKey,
      });
    });
    committed = true;
    await deps.seal({ walletId, publicKey: key.publicKey, secret: key.secret });
    await deps.withTx(async (sql) => {
      const stamped = await stampRecoveryUnderVault(sql, {
        nodeId: deps.nodeId,
        walletId,
        publicKey: key.publicKey,
      });
      if (!stamped) throw new Error("recovery stamp missed");
    });
    await notifyMinted(deps, walletId);
    return {
      walletId,
      moneyMode: "INTERNAL_ONLY",
      displayLabel: deps.displayLabel,
      destinationState: "BLESSED",
    };
  } catch (err) {
    if (committed) await compensateMint(deps, walletId);
    throw err;
  } finally {
    key.secret.fill(0);
  }
}

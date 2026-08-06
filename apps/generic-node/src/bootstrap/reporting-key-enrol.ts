// Live reporting-key bootstrap enrolment.
//
// Out-of-band operator ceremony (Option B): genesis enlists the first ACTIVE
// implementer reporting key so POST /v1/operations/:id/armed succeeds with the five
// X-ZP-Reporting-* headers. No public HTTP route — node-local only.
//
// Private half is written once to REPORTING_KEY_OUT (mode 0600). Never logged.
// Public half + lifecycle evidence land in PG. Idempotent when a lifecycle head
// already holds an ACTIVE current key for (node_id, implementer_id).

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  sign,
} from "node:crypto";
import { access, chmod, writeFile } from "node:fs/promises";
import type { Pool, PoolClient } from "pg";

import {
  buildReportingRegister,
  toBase64UrlPadded,
} from "@zucoins/node-core";

import type { GenesisLogger } from "./genesis.js";

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

const sha256Hex = (text: string): string =>
  createHash("sha256").update(text, "utf8").digest("hex");

const paddedSig = (preimage: string, privateKey: ReturnType<typeof createPrivateKey>): string =>
  toBase64UrlPadded(sign(null, Buffer.from(preimage, "utf8"), privateKey));

const pubOf = (privateKey: ReturnType<typeof createPrivateKey>): string =>
  toBase64UrlPadded(
    Buffer.from(
      createPublicKey(privateKey).export({ format: "der", type: "spki" }),
    ).subarray(-32),
  );

function privateKeyFromSeed(seed: Uint8Array): ReturnType<typeof createPrivateKey> {
  if (seed.length < 32) throw new Error("reporting key seed must be ≥32 bytes");
  const seed32 = Buffer.from(seed.subarray(0, 32));
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, seed32]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}

function mintKeypair(seed?: Uint8Array): {
  readonly privateKey: ReturnType<typeof createPrivateKey>;
  readonly publicKey: string;
  readonly seedHex: string;
} {
  if (seed !== undefined) {
    const privateKey = privateKeyFromSeed(seed);
    return {
      privateKey,
      publicKey: pubOf(privateKey),
      seedHex: Buffer.from(seed.subarray(0, 32)).toString("hex"),
    };
  }
  const { privateKey, publicKey: pubObj } = generateKeyPairSync("ed25519");
  const spki = pubObj.export({ format: "der", type: "spki" });
  const publicKey = toBase64UrlPadded(Buffer.from(spki).subarray(-32));
  // Extract seed from PKCS8 for durable operator custody file (32 raw bytes).
  const pkcs8 = privateKey.export({ format: "der", type: "pkcs8" }) as Buffer;
  const seedHex = pkcs8.subarray(-32).toString("hex");
  return { privateKey, publicKey, seedHex };
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

export async function writeReportingKeyPrivateOut(
  outPath: string,
  envelope: {
    readonly node_id: string;
    readonly implementer_id: string;
    readonly reporting_key_id: string;
    readonly public_key: string;
    readonly seed_hex: string;
  },
): Promise<void> {
  const body = {
    format: "zp-reporting-key-v1",
    node_id: envelope.node_id,
    implementer_id: envelope.implementer_id,
    reporting_key_id: envelope.reporting_key_id,
    public_key: envelope.public_key,
    seed_hex: envelope.seed_hex,
  };
  await writeFile(outPath, `${JSON.stringify(body, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  await chmod(outPath, 0o600);
}

export interface ReportingKeyEnrolConfig {
  readonly nodeId: string;
  readonly implementerId: string;
  /** Write private seed once (mode 0600). Required to enroll on first boot. */
  readonly reportingKeyOut?: string;
  /** Optional 32-byte seed (tests only). Never logged. */
  readonly seed?: Uint8Array;
  readonly nowMs?: () => number;
  /** Operator actor label stored as onboarding_actor_id (public). */
  readonly onboardingActorId?: string;
  /**
   * Test-only fail-injection for REPORTING_KEY_OUT write (runs before COMMIT).
   * Production never sets this.
   */
  readonly writePrivateOut?: typeof writeReportingKeyPrivateOut;
}

export type ReportingKeyEnrolOutcome =
  | {
      readonly enrolled: true;
      readonly keyId: string;
      readonly publicKey: string;
      readonly wrotePrivateOut: boolean;
    }
  | {
      readonly enrolled: false;
      readonly reason:
        | "already_active"
        | "already_active_private_out_missing"
        | "out_path_required"
        | "no_implementer";
      readonly keyId?: string;
      readonly publicKey?: string;
    };

/**
 * Bootstrap first reporting key to ACTIVE + open restore_hold for ARM admission
 * on greenfield only (no pre-existing restore row).
 * Genesis itself is node-origin operator approval; implementer_id is
 * taken from the authenticated genesis/bootstrap identity (never a free request body).
 *
 * Custody: REPORTING_KEY_OUT is written **before** COMMIT. OUT failure rolls back so
 * ACTIVE never lands without a recoverable private half.
 */
export async function enrolBootstrapReportingKey(
  pool: Pool,
  config: ReportingKeyEnrolConfig,
  logger: GenesisLogger,
): Promise<ReportingKeyEnrolOutcome> {
  const outPath = config.reportingKeyOut?.trim();
  const writeOut = config.writePrivateOut ?? writeReportingKeyPrivateOut;

  const existing = await pool.query<{
    current_key_id: string | null;
    public_key: string | null;
  }>(
    `SELECT h.current_key_id::text AS current_key_id, k.public_key
       FROM reporting_key_lifecycle_heads h
       LEFT JOIN implementer_reporting_keys k
         ON k.id = h.current_key_id
        AND k.node_id = h.node_id
        AND k.implementer_id = h.implementer_id
      WHERE h.node_id = $1::uuid AND h.implementer_id = $2::uuid`,
    [config.nodeId, config.implementerId],
  );
  if (existing.rows[0]?.current_key_id) {
    const keyId = existing.rows[0].current_key_id;
    const publicKey = existing.rows[0].public_key ?? undefined;
    if (outPath !== undefined && outPath.length > 0 && !(await pathExists(outPath))) {
      logger.error(
        `boot: reporting key ACTIVE key_id=${keyId} but REPORTING_KEY_OUT missing — refusing silent already_active (private half not recoverable; rotate via lifecycle ceremony)`,
      );
      return {
        enrolled: false,
        reason: "already_active_private_out_missing",
        keyId,
        publicKey,
      };
    }
    logger.info(
      `boot: reporting key already ACTIVE key_id=${keyId}` +
        (publicKey !== undefined ? ` public_key=${publicKey}` : ""),
    );
    return { enrolled: false, reason: "already_active", keyId, publicKey };
  }

  if ((outPath === undefined || outPath.length === 0) && config.seed === undefined) {
    logger.info(
      "boot: reporting key not enrolled — set REPORTING_KEY_OUT to enrol first ACTIVE key on next boot",
    );
    return { enrolled: false, reason: "out_path_required" };
  }

  const { rows, seedHex } = prepareFirstKeyMaterial({
    nodeId: config.nodeId,
    implementerId: config.implementerId,
    onboardingActorId: config.onboardingActorId,
    seed: config.seed,
    nowMs: config.nowMs,
  });
  const { keyId, publicKey } = rows;

  const client = await pool.connect();
  let wrotePrivateOut = false;
  try {
    await client.query("BEGIN");
    await insertFirstKeyLifecycle(client, rows);
    // OUT before COMMIT: never durable-ACTIVE without recoverable private half.
    if (outPath !== undefined && outPath.length > 0) {
      await writeOut(outPath, {
        node_id: config.nodeId,
        implementer_id: config.implementerId,
        reporting_key_id: keyId,
        public_key: publicKey,
        seed_hex: seedHex,
      });
      wrotePrivateOut = true;
    }
    await client.query("COMMIT");
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch {
      /* best effort */
    }
    throw err;
  } finally {
    client.release();
  }

  if (wrotePrivateOut) {
    logger.info(
      `boot: reporting key enrolled key_id=${keyId} public_key=${publicKey} written once to REPORTING_KEY_OUT (mode 0600; private seed never logged)`,
    );
  } else {
    logger.info(
      `boot: reporting key enrolled key_id=${keyId} public_key=${publicKey} (private seed held by caller; never logged)`,
    );
  }

  return { enrolled: true, keyId, publicKey, wrotePrivateOut };
}

/** The raw private seed is surfaced exactly once to the admin SPA on issue. */
export interface ReportingCredentialIssue {
  readonly id: string;
  readonly public_key: string;
  /** 32-byte lowercase-hex Ed25519 seed. Returned once, never persisted, never logged. */
  readonly raw_private_key: string;
  readonly registered_at: string;
}

/** Thrown when a (node_id, implementer_id) head already holds a current reporting key. */
export class ReportingCredentialAlreadyActiveError extends Error {
  readonly code = "reporting_key_already_active" as const;
  constructor(readonly keyId: string) {
    super("a reporting credential is already active for this implementer");
    this.name = "ReportingCredentialAlreadyActiveError";
  }
}

/**
 * Mint + enrol the first ACTIVE reporting credential and RETURN the raw
 * private seed once (the admin SPA shows it once; the node persists public material only).
 * This is the same first-key bootstrap ceremony genesis runs — the only
 * difference is the private half is returned to the caller instead of written to
 * REPORTING_KEY_OUT. Throws {@link ReportingCredentialAlreadyActiveError} when a current
 * key already exists (superseding an active key requires the lifecycle rotation ceremony,
 * not surfaced here).
 */
export async function issueReportingCredential(
  pool: Pool,
  config: {
    readonly nodeId: string;
    readonly implementerId: string;
    /** Public operator label stored as onboarding_actor_id. */
    readonly onboardingActorId?: string;
    /** Optional 32-byte seed (tests only). Never logged. */
    readonly seed?: Uint8Array;
    readonly nowMs?: () => number;
  },
): Promise<ReportingCredentialIssue> {
  const existing = await pool.query<{ current_key_id: string | null }>(
    `SELECT current_key_id::text AS current_key_id
       FROM reporting_key_lifecycle_heads
      WHERE node_id = $1::uuid AND implementer_id = $2::uuid`,
    [config.nodeId, config.implementerId],
  );
  const currentKeyId = existing.rows[0]?.current_key_id;
  if (currentKeyId) {
    throw new ReportingCredentialAlreadyActiveError(currentKeyId);
  }

  const { rows, seedHex } = prepareFirstKeyMaterial({
    nodeId: config.nodeId,
    implementerId: config.implementerId,
    onboardingActorId: config.onboardingActorId,
    seed: config.seed,
    nowMs: config.nowMs,
  });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await insertFirstKeyLifecycle(client, rows);
    await client.query("COMMIT");
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch {
      /* best effort */
    }
    throw err;
  } finally {
    client.release();
  }

  return {
    id: rows.keyId,
    public_key: rows.publicKey,
    raw_private_key: seedHex,
    registered_at: rows.issuedAt,
  };
}

/**
 * Mint a keypair and assemble the ordered first-key lifecycle rows (public material
 * plus the register nonce / PoP evidence). Returns the seed hex separately so the
 * caller decides custody (genesis writes REPORTING_KEY_OUT; the SPA returns it once).
 */
function prepareFirstKeyMaterial(config: {
  readonly nodeId: string;
  readonly implementerId: string;
  readonly onboardingActorId?: string;
  readonly seed?: Uint8Array;
  readonly nowMs?: () => number;
}): { readonly rows: FirstKeyRows; readonly seedHex: string } {
  const nowMs = config.nowMs?.() ?? Date.now();
  const issuedAt = new Date(nowMs).toISOString();
  const expiresAt = new Date(nowMs + 300_000).toISOString();

  const keyId = randomUUID();
  const { privateKey, publicKey, seedHex } = mintKeypair(config.seed);
  const nonce = randomUUID();
  const built = buildReportingRegister({
    node_id: config.nodeId as never,
    implementer_id: config.implementerId as never,
    new_reporting_key_id: keyId as never,
    new_reporting_public_key: publicKey as never,
    supersedes_key_id: null,
    nonce: nonce as never,
    issued_at: issuedAt,
    expires_at: expiresAt,
  });
  const preimage = built.preimageText;
  const preSha = built.sha256;
  const popSig = paddedSig(preimage, privateKey);

  const publicEvidence = "genesis-first-key-activated";
  const rows: FirstKeyRows = {
    nodeId: config.nodeId,
    implementerId: config.implementerId,
    keyId,
    publicKey,
    issuedAt,
    expiresAt,
    nonce,
    nonceRegId: randomUUID(),
    bootstrapId: randomUUID(),
    enrolId: randomUUID(),
    pendingStateId: randomUUID(),
    activeStateId: randomUUID(),
    eventId: randomUUID(),
    approvalAuditId: randomUUID(),
    onboardingActor: config.onboardingActorId?.trim() || "genesis-bootstrap",
    preimage,
    preSha,
    popSig,
    publicEvidence,
    publicEvidenceSha: sha256Hex(publicEvidence),
    // Event hash chains on PoP preimage‖sig digest (public material only).
    eventHash: sha256Hex(`${preSha}|${popSig}`),
  };
  return { rows, seedHex };
}

interface FirstKeyRows {
  readonly nodeId: string;
  readonly implementerId: string;
  readonly keyId: string;
  readonly publicKey: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly nonce: string;
  readonly nonceRegId: string;
  readonly bootstrapId: string;
  readonly enrolId: string;
  readonly pendingStateId: string;
  readonly activeStateId: string;
  readonly eventId: string;
  readonly approvalAuditId: string;
  readonly onboardingActor: string;
  readonly preimage: string;
  readonly preSha: string;
  readonly popSig: string;
  readonly publicEvidence: string;
  readonly publicEvidenceSha: string;
  readonly eventHash: string;
}

/**
 * Ordered INSERT under deferred lifecycle triggers:
 * evidence → PENDING → epoch-0 head → FIRST_KEY event → ACTIVE+edge → advance head → open restore.
 */
async function insertFirstKeyLifecycle(
  client: PoolClient,
  r: FirstKeyRows,
): Promise<{ nonceBurnSequence: bigint }> {
  await client.query(
    `INSERT INTO implementer_reporting_keys (id, node_id, implementer_id, public_key, registered_at)
     VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::timestamptz)`,
    [r.keyId, r.nodeId, r.implementerId, r.publicKey, r.issuedAt],
  );
  await client.query(
    `INSERT INTO reporting_key_bootstrap_evidence (
       id, node_id, implementer_id, new_reporting_key_id,
       onboarding_actor_id, operator_approval_audit_id, approved_at, created_at
     ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, $6::uuid, $7::timestamptz, $7::timestamptz)`,
    [
      r.bootstrapId,
      r.nodeId,
      r.implementerId,
      r.keyId,
      r.onboardingActor,
      r.approvalAuditId,
      r.issuedAt,
    ],
  );
  // seed-then-atomic-claim: ON CONFLICT DO NOTHING keeps the seed idempotent,
  // then UPDATE...RETURNING atomically claims the next sequence value. Under concurrent
  // enrolment for different implementers on the same node, each caller gets a distinct
  // nonce_burn_sequence — no read-modify-write race.
  await client.query(
    `INSERT INTO reporting_nonce_burn_counters (node_id)
     VALUES ($1::uuid)
     ON CONFLICT (node_id) DO NOTHING`,
    [r.nodeId],
  );
  const claimed = await client.query<{ claimed_sequence: string }>(
    `UPDATE reporting_nonce_burn_counters
        SET next_burn_sequence = next_burn_sequence + 1
      WHERE node_id = $1
      RETURNING next_burn_sequence - 1 AS claimed_sequence`,
    [r.nodeId],
  );
  if (claimed.rows.length === 0) {
    throw new Error("reporting nonce burn counter vanished after seed");
  }
  const nonceBurnSequence = BigInt(claimed.rows[0].claimed_sequence);

  await client.query(
    `INSERT INTO reporting_request_nonces (
       id, node_id, implementer_id, nonce, purpose,
       route_id, request_class, reporting_key_id, new_reporting_key_id, bootstrap_evidence_id,
       lifecycle_epoch, nonce_burn_sequence,
       request_preimage_text, request_preimage_sha256, request_signature,
       method, raw_target, body_sha256,
       issued_at, expires_at, received_at, consumed_at, retention_class
     ) VALUES (
       $1::uuid, $2::uuid, $3::uuid, $4::uuid, 'zp-reporting-register-v1',
       NULL, NULL, NULL, $5::uuid, $6::uuid,
       1, $12,
       $7, $8, $9,
       NULL, NULL, NULL,
       $10::timestamptz, $11::timestamptz, $10::timestamptz, $10::timestamptz,
       'LIFECYCLE_PERMANENT'
     )`,
    [
      r.nonceRegId,
      r.nodeId,
      r.implementerId,
      r.nonce,
      r.keyId,
      r.bootstrapId,
      r.preimage,
      r.preSha,
      r.popSig,
      r.issuedAt,
      r.expiresAt,
      nonceBurnSequence.toString(),
    ],
  );
  await client.query(
    `INSERT INTO reporting_key_enrolment_evidence (
       id, node_id, implementer_id, new_reporting_key_id,
       supersedes_key_id, authorizing_key_id, bootstrap_evidence_id, nonce_evidence_id,
       proof_of_possession_preimage_text, proof_of_possession_preimage_sha256,
       proof_of_possession_signature,
       authorizing_preimage_text, authorizing_preimage_sha256, authorizing_signature,
       issued_at, expires_at, created_at
     ) VALUES (
       $1::uuid, $2::uuid, $3::uuid, $4::uuid, NULL, NULL, $5::uuid, $6::uuid,
       $7, $8, $9, NULL, NULL, NULL,
       $10::timestamptz, $11::timestamptz, $10::timestamptz
     )`,
    [
      r.enrolId,
      r.nodeId,
      r.implementerId,
      r.keyId,
      r.bootstrapId,
      r.nonceRegId,
      r.preimage,
      r.preSha,
      r.popSig,
      r.issuedAt,
      r.expiresAt,
    ],
  );
  await client.query(
    `INSERT INTO reporting_key_lifecycle_states (
       id, reporting_key_id, node_id, implementer_id, lifecycle_epoch,
       state, lifecycle_event_id, state_changed_at
     ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 0, 'PENDING', NULL, $5::timestamptz)`,
    [r.pendingStateId, r.keyId, r.nodeId, r.implementerId, r.issuedAt],
  );
  // Epoch-0 empty head (auth_hold=true) so reporting_advance_lifecycle_head can step 0→1.
  await client.query(
    `INSERT INTO reporting_key_lifecycle_heads (
       node_id, implementer_id, epoch, current_key_id, prior_key_id,
       overlap_expires_at, auth_hold, lifecycle_event_id, updated_at
     ) VALUES ($1::uuid, $2::uuid, 0, NULL, NULL, NULL, true, NULL, $3::timestamptz)
     ON CONFLICT (node_id, implementer_id) DO NOTHING`,
    [r.nodeId, r.implementerId, r.issuedAt],
  );
  await client.query(
    `INSERT INTO reporting_key_lifecycle_events (
       id, node_id, implementer_id, epoch, event_type,
       current_key_id, prior_key_id, overlap_expires_at, auth_hold,
       successor_registered_at, nonce_evidence_id, nonce_purpose,
       enrolment_evidence_id, public_evidence_text, public_evidence_sha256,
       previous_event_id, previous_epoch, previous_event_hash,
       event_hash, committed_at
     ) VALUES (
       $1::uuid, $2::uuid, $3::uuid, 1, 'FIRST_KEY_ACTIVATED',
       $4::uuid, NULL, NULL, false,
       $5::timestamptz, $6::uuid, 'zp-reporting-register-v1',
       $7::uuid, $8, $9,
       NULL, NULL, NULL,
       $10, $5::timestamptz
     )`,
    [
      r.eventId,
      r.nodeId,
      r.implementerId,
      r.keyId,
      r.issuedAt,
      r.nonceRegId,
      r.enrolId,
      r.publicEvidence,
      r.publicEvidenceSha,
      r.eventHash,
    ],
  );
  await client.query(
    `INSERT INTO reporting_key_lifecycle_states (
       id, reporting_key_id, node_id, implementer_id, lifecycle_epoch,
       state, lifecycle_event_id, state_changed_at
     ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 1, 'ACTIVE', $5::uuid, $6::timestamptz)`,
    [r.activeStateId, r.keyId, r.nodeId, r.implementerId, r.eventId, r.issuedAt],
  );
  await client.query(
    `INSERT INTO reporting_key_state_transitions (
       lifecycle_event_id, node_id, implementer_id, lifecycle_epoch, event_type,
       reporting_key_id, from_state_row_id, to_state_row_id,
       from_lifecycle_epoch, to_lifecycle_epoch, from_state, to_state, transitioned_at
     ) VALUES (
       $1::uuid, $2::uuid, $3::uuid, 1, 'FIRST_KEY_ACTIVATED',
       $4::uuid, $5::uuid, $6::uuid, 0, 1, 'PENDING', 'ACTIVE', $7::timestamptz
     )`,
    [
      r.eventId,
      r.nodeId,
      r.implementerId,
      r.keyId,
      r.pendingStateId,
      r.activeStateId,
      r.issuedAt,
    ],
  );
  await client.query(`SELECT reporting_advance_lifecycle_head($1::uuid)`, [r.eventId]);

  // Greenfield only: open restore_hold when no row exists. Never clear a held row
  // (post-DR force-upsert / the post-restore dual gate) — ON CONFLICT DO NOTHING keeps hold.
  await client.query(
    `INSERT INTO reporting_restore_state (
       node_id, restore_hold,
       local_lifecycle_epoch, local_nonce_burn_high_water, local_event_hash,
       trusted_lifecycle_epoch, trusted_nonce_burn_high_water, trusted_event_hash,
       trusted_source_id, trusted_source_observed_at,
       hold_release_evidence_sha256, hold_released_at, created_at, updated_at
     ) VALUES (
       $1::uuid, false,
       1, $2, $3,
       1, $2, $3,
       'genesis:reporting-key-enrol', $4::timestamptz,
       $5, $4::timestamptz, $4::timestamptz, $4::timestamptz
     )
     ON CONFLICT (node_id) DO NOTHING`,
    [
      r.nodeId,
      nonceBurnSequence.toString(),
      r.eventHash,
      r.issuedAt,
      sha256Hex(`release:${r.eventId}`),
    ],
  );

  return { nonceBurnSequence };
}

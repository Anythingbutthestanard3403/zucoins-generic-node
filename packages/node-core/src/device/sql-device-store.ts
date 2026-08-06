// SQL adapters for operator_device_keys + destination_blessing_artifacts.
// DRIVER-AGNOSTIC: composition injects SqlExecutor. Public keys only (Key-custody).

import { createHash, randomUUID } from "node:crypto";

import type { Uuid } from "../protocol/scalars.js";
import type {
  AppendBlessingAudit,
  DestinationBlessingArtifactRow,
  LookUpActiveDevice,
  PersistBlessingArtifact,
} from "./blessing-authorizer.js";
import type { DeviceKeyStore } from "./store.js";
import type { EnrolledDeviceKey } from "./types.js";
import type { EnrollmentChallenge, EnrollmentChallengeStatus } from "./types.js";
import type { EnrollmentChallengeStore } from "./challenge.js";

export interface DeviceSqlQueryResult<R> {
  readonly rows: R[];
}

export interface DeviceSqlExecutor {
  query<R extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    params?: readonly unknown[],
  ): Promise<DeviceSqlQueryResult<R>>;
}

function mapDeviceRow(row: Record<string, unknown>): EnrolledDeviceKey {
  return {
    id: String(row.id),
    nodeId: String(row.node_id),
    publicKey: String(row.public_key),
    label: String(row.label),
    enrolledAt:
      row.enrolled_at instanceof Date
        ? row.enrolled_at.toISOString()
        : String(row.enrolled_at),
    revokedAt:
      row.revoked_at === null || row.revoked_at === undefined
        ? null
        : row.revoked_at instanceof Date
          ? row.revoked_at.toISOString()
          : String(row.revoked_at),
  };
}

function isUniqueViolation(err: unknown): boolean {
  if (typeof err === "object" && err !== null && "code" in err) {
    if (String((err as { code?: unknown }).code) === "23505") return true;
  }
  const message = err instanceof Error ? err.message : String(err);
  return /\b23505\b/.test(message);
}

function sha256HexUtf8(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** Async lookup used by the blessing authorizer (PG I/O is async). */
export function createSqlActiveDeviceLookup(sql: DeviceSqlExecutor): LookUpActiveDevice {
  return async (nodeId, deviceKeyId) => {
    const result = await sql.query(
      `SELECT id, node_id, public_key::text AS public_key, label,
              enrolled_at, revoked_at
         FROM operator_device_keys
        WHERE id = $1::uuid AND node_id = $2::uuid AND revoked_at IS NULL`,
      [deviceKeyId, nodeId],
    );
    const row = result.rows[0];
    return row === undefined ? null : mapDeviceRow(row);
  };
}

export function createSqlBlessingArtifactPersister(
  sql: DeviceSqlExecutor,
): PersistBlessingArtifact {
  return async (row: DestinationBlessingArtifactRow) => {
    try {
      await sql.query(
        `INSERT INTO destination_blessing_artifacts (
           id, purpose, canonical_version, node_id, destination_id, wallet_id,
           wallet_pubkey, nonce, issued_at, expires_at, device_signature,
           preimage_text, preimage_sha256, created_at
         ) VALUES (
           $1::uuid, 'zp-destination-bless-v1', 1, $2::uuid, $3::uuid, $4::uuid,
           $5, $6::uuid, $7::timestamptz, $8::timestamptz, $9,
           $10, $11, $12::timestamptz
         )`,
        [
          row.id,
          row.nodeId,
          row.destinationId,
          row.walletId,
          row.walletPubkey,
          row.nonce,
          row.issuedAt,
          row.expiresAt,
          row.deviceSignature,
          row.preimageText,
          row.preimageSha256,
          row.createdAt,
        ],
      );
      return "inserted";
    } catch (err) {
      if (isUniqueViolation(err)) return "nonce_conflict";
      return "failed";
    }
  };
}

export function createSqlBlessingAuditAppender(
  sql: DeviceSqlExecutor,
  newId: () => Uuid = () => randomUUID() as Uuid,
): AppendBlessingAudit {
  return async (entry) => {
    // Never include device_signature or private key material (Key-custody / AC4).
    // Hand-built text — never JSON.stringify in device/ (construction-site census).
    const details =
      "code=" +
      entry.code +
      ";detail=" +
      entry.detail +
      ";device_key_id=" +
      String(entry.deviceKeyId) +
      ";artifact_id=" +
      String(entry.artifactId) +
      ";destination_id=" +
      entry.destinationId;
    const detailsSha = sha256HexUtf8(details);
    try {
      await sql.query(
        `INSERT INTO audit_log (
           id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
           details_text, details_sha256, created_at
         ) VALUES (
           $1::uuid, $2::uuid, 'DEVICE_KEY', $3, $4, NULL, $5::uuid,
           $6, $7, $8::timestamptz
         )`,
        [
          newId(),
          entry.nodeId,
          entry.deviceKeyId,
          entry.action,
          entry.walletId,
          details,
          detailsSha,
          entry.at,
        ],
      );
    } catch {
      // Audit failure must not reverse a committed bless.
    }
  };
}

export type SqlDeviceKeyStore = DeviceKeyStore & {
  refreshNode(nodeId: string): Promise<void>;
  insertDurable(deviceKey: EnrolledDeviceKey): Promise<void>;
  revokeDurable(id: string, revokedAt: string): Promise<void>;
};

/**
 * DeviceKeyStore with durable PG writes for operator_device_keys.
 * In-memory index mirrors rows after insertDurable / refreshNode.
 */
export function createSqlDeviceKeyStore(sql: DeviceSqlExecutor): SqlDeviceKeyStore {
  const byComposite = new Map<string, EnrolledDeviceKey>();
  const byId = new Map<string, string>();

  const composite = (nodeId: string, publicKey: string) => `${nodeId}:${publicKey}`;

  const remember = (key: EnrolledDeviceKey): void => {
    const ck = composite(key.nodeId, key.publicKey);
    byComposite.set(ck, key);
    byId.set(key.id, ck);
  };

  return {
    findByNodeAndPublicKey(nodeId, publicKey) {
      return byComposite.get(composite(nodeId, publicKey)) ?? null;
    },
    findActiveByNodeAndPublicKey(nodeId, publicKey) {
      const key = byComposite.get(composite(nodeId, publicKey));
      if (key === undefined || key.revokedAt !== null) return null;
      return key;
    },
    findById(id) {
      const ck = byId.get(id);
      if (ck === undefined) return null;
      return byComposite.get(ck) ?? null;
    },
    listActiveByNode(nodeId) {
      return [...byComposite.values()]
        .filter((key) => key.nodeId === nodeId && key.revokedAt === null)
        .sort((left, right) =>
          left.enrolledAt.localeCompare(right.enrolledAt) || left.id.localeCompare(right.id),
        );
    },
    insert(deviceKey) {
      const ck = composite(deviceKey.nodeId, deviceKey.publicKey);
      if (byComposite.has(ck)) {
        throw new Error(`duplicate device key: (${deviceKey.nodeId}, ${deviceKey.publicKey})`);
      }
      if (byId.has(deviceKey.id)) {
        throw new Error(`duplicate device key id: ${deviceKey.id}`);
      }
      remember(deviceKey);
    },
    revoke(id, revokedAt) {
      const ck = byId.get(id);
      if (ck === undefined) return;
      const key = byComposite.get(ck);
      if (key === undefined || key.revokedAt !== null) return;
      remember({ ...key, revokedAt });
    },
    async refreshNode(nodeId) {
      const result = await sql.query(
        `SELECT id, node_id, public_key::text AS public_key, label,
                enrolled_at, revoked_at
           FROM operator_device_keys
          WHERE node_id = $1::uuid`,
        [nodeId],
      );
      for (const row of result.rows) {
        remember(mapDeviceRow(row));
      }
    },
    async insertDurable(deviceKey) {
      await sql.query(
        `INSERT INTO operator_device_keys (id, node_id, public_key, label, enrolled_at, revoked_at)
         VALUES ($1::uuid, $2::uuid, $3, $4, $5::timestamptz, $6::timestamptz)
         ON CONFLICT (node_id, public_key) DO NOTHING`,
        [
          deviceKey.id,
          deviceKey.nodeId,
          deviceKey.publicKey,
          deviceKey.label,
          deviceKey.enrolledAt,
          deviceKey.revokedAt,
        ],
      );
      remember(deviceKey);
    },
    async revokeDurable(id, revokedAt) {
      await sql.query(
        `UPDATE operator_device_keys
            SET revoked_at = $2::timestamptz
          WHERE id = $1::uuid AND revoked_at IS NULL`,
        [id, revokedAt],
      );
      const ck = byId.get(id);
      if (ck === undefined) return;
      const key = byComposite.get(ck);
      if (key === undefined || key.revokedAt !== null) return;
      remember({ ...key, revokedAt });
    },
  };
}

function mapChallenge(row: Record<string, unknown>): EnrollmentChallenge {
  return {
    id: String(row.id),
    nodeId: String(row.node_id),
    status: row.status as EnrollmentChallengeStatus,
    purpose: "zp-device-enrol-v1",
    canonicalVersion: 1,
    nonce: String(row.nonce),
    issuedAt:
      row.issued_at instanceof Date ? row.issued_at.toISOString() : String(row.issued_at),
    expiresAt:
      row.expires_at instanceof Date ? row.expires_at.toISOString() : String(row.expires_at),
    supersededBy:
      row.superseded_by === null || row.superseded_by === undefined
        ? null
        : String(row.superseded_by),
  };
}

export type SqlEnrollmentChallengeStore = EnrollmentChallengeStore & {
  refreshNode(nodeId: string): Promise<void>;
  insertDurable(challenge: EnrollmentChallenge): Promise<void>;
  updateDurable(challenge: EnrollmentChallenge): Promise<void>;
};

/**
 * PG-backed device_enrollment_challenges with an in-memory working set.
 * Call refreshNode before ceremony; durable helpers write through to SQL.
 */
export function createSqlEnrollmentChallengeStore(
  sql: DeviceSqlExecutor,
): SqlEnrollmentChallengeStore {
  const byId = new Map<string, EnrollmentChallenge>();
  const byNonce = new Map<string, string>();

  const remember = (challenge: EnrollmentChallenge): void => {
    byId.set(challenge.id, challenge);
    byNonce.set(challenge.nonce, challenge.id);
  };

  return {
    findByNonce(nonce) {
      const id = byNonce.get(nonce);
      if (id === undefined) return null;
      return byId.get(id) ?? null;
    },
    findIssuedByNode(nodeId) {
      for (const c of byId.values()) {
        if (c.nodeId === nodeId && c.status === "ISSUED") return c;
      }
      return null;
    },
    listIssuedByNode(nodeId) {
      const out: EnrollmentChallenge[] = [];
      for (const c of byId.values()) {
        if (c.nodeId === nodeId && c.status === "ISSUED") out.push(c);
      }
      return out;
    },
    insert(challenge) {
      if (byNonce.has(challenge.nonce)) {
        throw new Error(`duplicate enrollment challenge nonce: ${challenge.nonce}`);
      }
      if (byId.has(challenge.id)) {
        throw new Error(`duplicate enrollment challenge id: ${challenge.id}`);
      }
      remember(challenge);
    },
    update(challenge) {
      if (!byId.has(challenge.id)) {
        throw new Error(`unknown enrollment challenge: ${challenge.id}`);
      }
      remember(challenge);
    },
    async refreshNode(nodeId) {
      const result = await sql.query(
        `SELECT id, node_id, status::text AS status, nonce, issued_at, expires_at, superseded_by
           FROM device_enrollment_challenges
          WHERE node_id = $1::uuid`,
        [nodeId],
      );
      for (const row of result.rows) {
        remember(mapChallenge(row));
      }
    },
    async insertDurable(challenge) {
      await sql.query(
        `INSERT INTO device_enrollment_challenges (
           id, node_id, status, purpose, canonical_version, nonce,
           issued_at, expires_at, superseded_by
         ) VALUES (
           $1::uuid, $2::uuid, $3::approval_challenge_status, 'zp-device-enrol-v1', 1,
           $4::uuid, $5::timestamptz, $6::timestamptz, $7::uuid
         )`,
        [
          challenge.id,
          challenge.nodeId,
          challenge.status,
          challenge.nonce,
          challenge.issuedAt,
          challenge.expiresAt,
          challenge.supersededBy,
        ],
      );
      remember(challenge);
    },
    async updateDurable(challenge) {
      await sql.query(
        `UPDATE device_enrollment_challenges
            SET status = $2::approval_challenge_status,
                superseded_by = $3::uuid
          WHERE id = $1::uuid`,
        [challenge.id, challenge.status, challenge.supersededBy],
      );
      remember(challenge);
    },
  };
}

// Durable enrollment / revocation audit — append-only audit_log rows (ZTR-1171 / doc 07 §5.4.3).
// Public keys and identifiers only; never private key material (key-custody rule).

import { createHash, randomUUID } from "node:crypto";

import type { EnrollmentAuditEntry } from "./types.js";
import type { EnrollmentAuditLog } from "./audit.js";
import type { DeviceRevocationAuditEntry } from "./types.js";
import type { DeviceRevocationAuditLog } from "./revocation.js";
import type { DeviceSqlExecutor } from "./sql-device-store.js";

function sha256HexUtf8(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function detailsLine(parts: ReadonlyArray<readonly [string, string | number | null | undefined]>): string {
  return parts
    .filter(([, v]) => v !== undefined && v !== null && String(v).length > 0)
    .map(([k, v]) => `${k}=${String(v)}`)
    .join(";");
}

/**
 * Fire-and-forget durable append. The EnrollmentAuditLog port is synchronous so
 * enrolment call sites stay unchanged; the INSERT is scheduled and failures are
 * logged to stderr without reversing a committed enrol (same posture as blessing audit).
 */
export function createSqlEnrollmentAuditLog(
  sql: DeviceSqlExecutor,
  opts: { readonly newId?: () => string } = {},
): EnrollmentAuditLog {
  const newId = opts.newId ?? (() => randomUUID());
  return {
    append(entry: EnrollmentAuditEntry): void {
      const details = detailsLine([
        ["outcome", entry.outcome],
        ["code", entry.code],
        ["detail", entry.detail],
        ["challenge_id", entry.challengeId],
        ["challenge_nonce", entry.challengeNonce],
        ["authorizing_key_id", entry.authorizingKeyId],
        ["authorizing_public_key", entry.authorizingPublicKey],
        ["new_device_key_id", entry.newDeviceKeyId],
        ["new_device_public_key", entry.newDevicePublicKey],
      ]);
      const detailsSha = sha256HexUtf8(details);
      const nodeId = entry.nodeId;
      if (nodeId === null || nodeId === "") {
        // Cannot satisfy audit_log.node_id NOT NULL — drop with diagnostic.
        console.error("sql-enrollment-audit: skip append — missing nodeId");
        return;
      }
      const action =
        entry.outcome === "ENROLLED" ? "device.enrol.ok" : "device.enrol.rejected";
      void sql
        .query(
          `INSERT INTO audit_log (
             id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
             details_text, details_sha256, created_at
           ) VALUES (
             $1::uuid, $2::uuid, 'DEVICE_KEY', $3, $4, NULL, NULL,
             $5, $6, $7::timestamptz
           )`,
          [
            newId(),
            nodeId,
            entry.authorizingKeyId ?? entry.newDeviceKeyId,
            action,
            details,
            detailsSha,
            entry.at,
          ],
        )
        .catch((err: unknown) => {
          console.error(
            `sql-enrollment-audit: append failed: ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
        });
    },
  };
}

export function createSqlDeviceRevocationAuditLog(
  sql: DeviceSqlExecutor,
  opts: { readonly newId?: () => string } = {},
): DeviceRevocationAuditLog {
  const newId = opts.newId ?? (() => randomUUID());
  return {
    append(entry: DeviceRevocationAuditEntry): void {
      const details = detailsLine([
        ["outcome", entry.outcome],
        ["code", entry.code],
        ["detail", entry.detail],
        ["target_device_key_id", entry.targetDeviceKeyId],
        ["authorizing_key_id", entry.authorizingKeyId],
        ["invalidated_enrollment_challenges", entry.invalidatedEnrollmentChallenges],
      ]);
      const detailsSha = sha256HexUtf8(details);
      const action =
        entry.outcome === "REVOKED" ? "device.revoke.ok" : "device.revoke.rejected";
      void sql
        .query(
          `INSERT INTO audit_log (
             id, node_id, actor_kind, actor_id, action, operation_id, wallet_id,
             details_text, details_sha256, created_at
           ) VALUES (
             $1::uuid, $2::uuid, 'DEVICE_KEY', $3, $4, NULL, NULL,
             $5, $6, $7::timestamptz
           )`,
          [
            newId(),
            entry.nodeId,
            entry.authorizingKeyId ?? entry.targetDeviceKeyId,
            action,
            details,
            detailsSha,
            entry.at,
          ],
        )
        .catch((err: unknown) => {
          console.error(
            `sql-device-revocation-audit: append failed: ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
        });
    },
  };
}

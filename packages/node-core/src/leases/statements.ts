// Exact parameterized statement catalogue for the lease repository. Tests and the
// in-process fake executor match on these strings so a silent statement drift fails loudly.

export const STATEMENTS = {
  LOCK_WALLET: `SELECT id AS wallet_id, state FROM wallets WHERE id = $1 FOR UPDATE`,

  SELECT_ACTIVE_FOR_UPDATE: `
SELECT wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
       lease_role, lease_epoch::text AS lease_epoch, acquired_at::text AS acquired_at,
       heartbeat_at::text AS heartbeat_at, owner_instance_id,
       release_not_before::text AS release_not_before
  FROM wallet_active_leases
 WHERE wallet_id = $1
 FOR UPDATE`.replace(/\s+/g, " ").trim(),

  SELECT_ACTIVE: `
SELECT wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
       lease_role, lease_epoch::text AS lease_epoch, acquired_at::text AS acquired_at,
       heartbeat_at::text AS heartbeat_at, owner_instance_id,
       release_not_before::text AS release_not_before
  FROM wallet_active_leases
 WHERE wallet_id = $1`.replace(/\s+/g, " ").trim(),

  INSERT_MEMBERSHIP: `
INSERT INTO wallet_lease_memberships (
  id, lease_group_id, wallet_id, operation_id, lease_role, lease_epoch, acquired_at
) VALUES ($1, $2, $3, $4, $5, $6, $7)`.replace(/\s+/g, " ").trim(),

  INSERT_ACTIVE: `
INSERT INTO wallet_active_leases (
  wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
  lease_role, lease_epoch, acquired_at, heartbeat_at, owner_instance_id
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`.replace(/\s+/g, " ").trim(),

  UPSERT_HIGHWATER: `
INSERT INTO wallet_lease_epoch_highwater (wallet_id, highwater)
VALUES ($1, $2)
ON CONFLICT (wallet_id) DO UPDATE
  SET highwater = EXCLUDED.highwater
WHERE wallet_lease_epoch_highwater.highwater < EXCLUDED.highwater`.replace(/\s+/g, " ").trim(),

  SELECT_HIGHWATER_FOR_UPDATE: `
SELECT highwater::text AS highwater
  FROM wallet_lease_epoch_highwater
 WHERE wallet_id = $1
 FOR UPDATE`.replace(/\s+/g, " ").trim(),

  SELECT_MAX_MEMBERSHIP_EPOCH: `
SELECT MAX(lease_epoch)::text AS max_epoch
  FROM wallet_lease_memberships
 WHERE wallet_id = $1`.replace(/\s+/g, " ").trim(),

  PIN_WALLET: `UPDATE wallets SET state = 'PINNED' WHERE id = $1 AND state = 'AVAILABLE'`,

  UNPIN_WALLET: `UPDATE wallets SET state = 'AVAILABLE' WHERE id = $1 AND state = 'PINNED'`,

  CLOSE_MEMBERSHIP: `
UPDATE wallet_lease_memberships
   SET released_at = $2, release_reason = $3, release_proof_id = $4
 WHERE id = $1
   AND released_at IS NULL`.replace(/\s+/g, " ").trim(),

  DELETE_ACTIVE_EXACT: `
DELETE FROM wallet_active_leases
 WHERE wallet_id = $1
   AND membership_id = $2
   AND lease_group_id = $3
   AND operation_id = $4
   AND lease_epoch = $5
   AND owner_instance_id = $6`.replace(/\s+/g, " ").trim(),

  LOCK_PROOF: `
SELECT proof_id, wallet_id, operation_id, membership_id, lease_group_id,
       lease_epoch::text AS lease_epoch, proof_kind, proof_digest, issuer,
       consumed_at::text AS consumed_at
  FROM lease_release_proofs
 WHERE proof_id = $1
 FOR UPDATE`.replace(/\s+/g, " ").trim(),

  CONSUME_PROOF: `
UPDATE lease_release_proofs
   SET consumed_at = $2
 WHERE proof_id = $1
   AND consumed_at IS NULL`.replace(/\s+/g, " ").trim(),

  INSERT_PROOF: `
INSERT INTO lease_release_proofs (
  proof_id, wallet_id, operation_id, membership_id, lease_group_id,
  lease_epoch, proof_kind, proof_digest, issuer, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'TRUSTED_VERIFIER', $9)`.replace(/\s+/g, " ").trim(),

  INSERT_LEASE_GROUP: `
INSERT INTO lease_groups (id, root_operation_id, created_at, child_disposition)
VALUES ($1, $2, $3, $4)`.replace(/\s+/g, " ").trim(),

  INSERT_GROUP_OPERATION: `
INSERT INTO lease_group_operations (lease_group_id, operation_id, joined_at)
VALUES ($1, $2, $3)`.replace(/\s+/g, " ").trim(),

  LOCK_LEASE_GROUP: `
SELECT id, root_operation_id, created_at::text AS created_at,
       child_disposition,
       released_at::text AS released_at, release_proof_id
  FROM lease_groups
 WHERE id = $1
 FOR UPDATE`.replace(/\s+/g, " ").trim(),

  LOCK_GROUP_OPERATIONS: `
SELECT lease_group_id, operation_id, joined_at::text AS joined_at,
       completed_at::text AS completed_at
  FROM lease_group_operations
 WHERE lease_group_id = $1
 ORDER BY operation_id /* contract-allow:order:frozen-sql-text */
 FOR UPDATE`.replace(/\s+/g, " ").trim(),

  LOCK_GROUP_ACTIVE_LEASES: `
SELECT wallet_id, membership_id, lease_group_id, root_operation_id, operation_id,
       lease_role, lease_epoch::text AS lease_epoch, acquired_at::text AS acquired_at,
       heartbeat_at::text AS heartbeat_at, owner_instance_id,
       release_not_before::text AS release_not_before
  FROM wallet_active_leases
 WHERE lease_group_id = $1
 ORDER BY wallet_id /* contract-allow:order:frozen-sql-text */
 FOR UPDATE`.replace(/\s+/g, " ").trim(),

  LOCK_GROUP_OPEN_MEMBERSHIPS: `
SELECT id, lease_group_id, wallet_id, operation_id, lease_role,
       lease_epoch::text AS lease_epoch, acquired_at::text AS acquired_at,
       released_at::text AS released_at
  FROM wallet_lease_memberships
 WHERE lease_group_id = $1
   AND released_at IS NULL
 ORDER BY wallet_id, id /* contract-allow:order:frozen-sql-text */
 FOR UPDATE`.replace(/\s+/g, " ").trim(),

  COMPLETE_GROUP_OPERATION: `
UPDATE lease_group_operations
   SET completed_at = $3
 WHERE lease_group_id = $1
   AND operation_id = $2
   AND completed_at IS NULL`.replace(/\s+/g, " ").trim(),

  MARK_CHILD_JOINED: `
UPDATE lease_groups
   SET child_disposition = 'JOINED'
 WHERE id = $1
   AND child_disposition = 'PENDING'
   AND released_at IS NULL`.replace(/\s+/g, " ").trim(),

  RELEASE_LEASE_GROUP: `
UPDATE lease_groups
   SET released_at = $2, release_proof_id = $3
 WHERE id = $1
   AND released_at IS NULL`.replace(/\s+/g, " ").trim(),

  INSERT_AUDIT: `
INSERT INTO lease_audit_events (
  id, action, wallet_id, operation_id, membership_id, lease_group_id,
  lease_epoch, owner_instance_id, details_text, details_sha256, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`.replace(/\s+/g, " ").trim(),

  HEARTBEAT: `
UPDATE wallet_active_leases
   SET heartbeat_at = $3
 WHERE wallet_id = $1
   AND owner_instance_id = $2`.replace(/\s+/g, " ").trim(),

  /**
   * Uninterrupted active-row re-point (lease hand-off). Never DELETE.
   * CAS on the full parent capability tuple so a lost race mutates nothing.
   */
  TRANSFER_ACTIVE: `
UPDATE wallet_active_leases
   SET membership_id = $2,
       operation_id = $3,
       lease_role = $4,
       lease_epoch = $5,
       heartbeat_at = $6
 WHERE wallet_id = $1
   AND membership_id = $7
   AND lease_group_id = $8
   AND operation_id = $9
   AND lease_epoch = $10
   AND owner_instance_id = $11`.replace(/\s+/g, " ").trim(),

  SELECT_FENCE: `SELECT schema_version FROM lease_schema_fence WHERE singleton = true`,

  UPSERT_FENCE: `
INSERT INTO lease_schema_fence (singleton, schema_version, applied_at)
VALUES (true, $1, $2)
ON CONFLICT (singleton) DO UPDATE
  SET schema_version = EXCLUDED.schema_version,
      applied_at = EXCLUDED.applied_at`.replace(/\s+/g, " ").trim(),

  COUNT_ACTIVE: `SELECT count(*)::text AS n FROM wallet_active_leases`,

  LIST_ACTIVE_COLUMNS: `
SELECT attname AS column_name, attnum AS ordinal_position
  FROM pg_attribute
 WHERE attrelid = to_regclass('wallet_active_leases')
   AND attnum > 0
   AND NOT attisdropped`.replace(/\s+/g, " ").trim(),
} as const;

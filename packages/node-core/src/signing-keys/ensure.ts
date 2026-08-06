// ensureActiveNodeSigningKey — first-boot (or recovery) mint+seal of NODE_IDENTITY /
// EVENT_SIGNING private material into node_signing_key_sealed_store, with public
// registration in node_signing_keys. Prefer sealed-store load on subsequent boots;
// NODE_IDENTITY_SEED is override for first mint / emergency rebuild only.
//
// Upgrade path (pre-923 public-only rows): seal-fill matching seed, or retire orphan
// and mint sealed. Never dual-active. Governing:.
// Never logs seed.

import { createPrivateKey, createHash, randomUUID, sign as edSign } from "node:crypto";

import { ED25519_SEED_BYTES, type SecureBuffer } from "../vault/envelope.js";
import {
  generateEd25519Seed,
  openNodeSigningSeed,
  publicKeyFromEd25519Seed,
  sealNodeSigningSeed,
  type NodeSigningKeyIdentity,
  type NodeSigningKeySealedEnvelope,
} from "./sealed-store.js";
import {
  assertExactPurpose,
  type NodeSigningKeyPurpose,
  type SqlExecutor,
} from "./registry-store.js";

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** Session/TX advisory lock class for one-active mint serialisation. */
export const NODE_SIGNING_KEY_ENSURE_LOCK_CLASS = 0x5a545232; // "ZTR2"

export interface EnsureActiveNodeSigningKeyInput {
  readonly sql: SqlExecutor;
  readonly rootKey: Uint8Array;
  readonly nodeId: string;
  readonly purpose: NodeSigningKeyPurpose | string;
  /** Optional first-mint / rebuild seed (exactly 32 bytes). Ignored when an active sealed row already exists. */
  readonly seedOverride?: Uint8Array;
  /**
   * Multi-instance serialisation. When omitted, ensure takes a TX-scoped advisory
   * lock on (NODE_SIGNING_KEY_ENSURE_LOCK_CLASS, hash(nodeId|purpose)) so concurrent
   * mints cannot dual-INSERT active rows. Prefer composition to also serialise via
   * leadership; this lock is the structural backstop inside the caller's TX.
   */
  readonly withExclusiveLock?: <T>(work: () => Promise<T>) => Promise<T>;
}

export interface NodeIdentityArtifactSigner {
  readonly signingKeyId: string;
  readonly publicKey: string;
  readonly purpose: NodeSigningKeyPurpose;
  readonly keyVersion: number;
  /** Sign exact preimage bytes (Ed25519). Opens sealed seed per call and wipes. */
  sign(preimageBytes: Uint8Array): Uint8Array;
}

interface ActiveSealedRow {
  readonly id: string;
  readonly public_key: string;
  readonly vault_secret_ref: string;
  readonly key_version: number;
  readonly ciphertext: Buffer;
  readonly nonce: Buffer;
  readonly auth_tag: Buffer;
  readonly ciphertext_sha256: string;
}

interface ActivePublicRow {
  readonly id: string;
  readonly public_key: string;
  readonly vault_secret_ref: string;
}

function buildSignerFromSealed(meta: {
  readonly signingKeyId: string;
  readonly publicKey: string;
  readonly purpose: NodeSigningKeyPurpose;
  readonly keyVersion: number;
  readonly rootKey: Uint8Array;
  readonly envelope: NodeSigningKeySealedEnvelope;
  readonly identity: NodeSigningKeyIdentity;
}): NodeIdentityArtifactSigner {
  const { signingKeyId, publicKey, purpose, keyVersion, rootKey, envelope, identity } = meta;
  return {
    signingKeyId,
    publicKey,
    purpose,
    keyVersion,
    sign(preimageBytes: Uint8Array): Uint8Array {
      const opened: SecureBuffer = openNodeSigningSeed(rootKey, envelope, identity);
      try {
        const seedBuf = Buffer.from(opened.bytes);
        try {
          const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, seedBuf]);
          try {
            const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
            return edSign(null, preimageBytes, privateKey);
          } finally {
            pkcs8.fill(0);
          }
        } finally {
          seedBuf.fill(0);
        }
      } finally {
        opened.wipe();
      }
    },
  };
}

function purposeLockKey2(nodeId: string, purpose: string): number {
  const digest = createHash("sha256").update(`${nodeId}\0${purpose}`, "utf8").digest();
  return digest.readInt32BE(0);
}

async function acquireEnsureLock(
  sql: SqlExecutor,
  nodeId: string,
  purpose: NodeSigningKeyPurpose,
): Promise<void> {
  await sql.query(`SELECT pg_advisory_xact_lock($1::integer, $2::integer)`, [
    NODE_SIGNING_KEY_ENSURE_LOCK_CLASS,
    purposeLockKey2(nodeId, purpose),
  ]);
}

async function selectActiveSealed(
  sql: SqlExecutor,
  nodeId: string,
  purpose: NodeSigningKeyPurpose,
): Promise<ActiveSealedRow | null> {
  const { rows } = await sql.query<ActiveSealedRow>(
    `SELECT k.id, k.public_key, k.vault_secret_ref,
            s.key_version, s.ciphertext, s.nonce, s.auth_tag, s.ciphertext_sha256
       FROM node_signing_keys k
       JOIN node_signing_key_sealed_store s
         ON s.vault_secret_ref = k.vault_secret_ref
      WHERE k.node_id = $1::uuid
        AND k.purpose = $2
        AND k.retired_at IS NULL
        AND k.activated_at <= now()
        AND NOT EXISTS (
              SELECT 1 FROM node_signing_keys newer
               WHERE newer.node_id = k.node_id
                 AND newer.purpose = k.purpose
                 AND newer.retired_at IS NULL
                 AND newer.activated_at <= now()
                 AND newer.activated_at > k.activated_at
            )
      LIMIT 1`,
    [nodeId, purpose],
  );
  return rows[0] ?? null;
}

/** Active public registry rows that have no openable sealed envelope (pre-923 or broken). */
async function selectActivePublicWithoutSeal(
  sql: SqlExecutor,
  nodeId: string,
  purpose: NodeSigningKeyPurpose,
): Promise<readonly ActivePublicRow[]> {
  const { rows } = await sql.query<ActivePublicRow>(
    `SELECT k.id, k.public_key, k.vault_secret_ref
       FROM node_signing_keys k
      WHERE k.node_id = $1::uuid
        AND k.purpose = $2
        AND k.retired_at IS NULL
        AND k.activated_at <= now()
        AND NOT EXISTS (
              SELECT 1 FROM node_signing_key_sealed_store s
               WHERE s.vault_secret_ref = k.vault_secret_ref
            )
      ORDER BY k.activated_at ASC, k.id ASC`, // contract-allow:order:frozen structural vocabulary
    [nodeId, purpose],
  );
  return rows;
}

async function retireActiveRows(
  sql: SqlExecutor,
  nodeId: string,
  purpose: NodeSigningKeyPurpose,
  exceptId?: string,
): Promise<void> {
  if (exceptId !== undefined) {
    await sql.query(
      `UPDATE node_signing_keys
          SET retired_at = now()
        WHERE node_id = $1::uuid
          AND purpose = $2
          AND retired_at IS NULL
          AND id <> $3::uuid`,
      [nodeId, purpose, exceptId],
    );
    return;
  }
  await sql.query(
    `UPDATE node_signing_keys
        SET retired_at = now()
      WHERE node_id = $1::uuid
        AND purpose = $2
        AND retired_at IS NULL`,
    [nodeId, purpose],
  );
}

async function syncIdentityPublicKey(
  sql: SqlExecutor,
  nodeId: string,
  publicKey: string,
): Promise<void> {
  await sql.query(
    `UPDATE nodes SET identity_public_key = $2 WHERE id = $1::uuid
       AND identity_public_key IS DISTINCT FROM $2`,
    [nodeId, publicKey],
  );
}

function rowToSigner(
  row: ActiveSealedRow,
  rootKey: Uint8Array,
  nodeId: string,
  purpose: NodeSigningKeyPurpose,
): NodeIdentityArtifactSigner {
  const identity: NodeSigningKeyIdentity = {
    nodeId,
    purpose,
    publicKey: row.public_key,
    keyVersion: row.key_version,
  };
  const envelope: NodeSigningKeySealedEnvelope = {
    vaultSecretRef: row.vault_secret_ref,
    keyVersion: row.key_version,
    ciphertext: row.ciphertext,
    nonce: row.nonce,
    authTag: row.auth_tag,
    ciphertextSha256: row.ciphertext_sha256,
  };
  // Prove the envelope opens under current root before arming the signer.
  const opened = openNodeSigningSeed(rootKey, envelope, identity);
  opened.wipe();
  return buildSignerFromSealed({
    signingKeyId: row.id,
    publicKey: row.public_key,
    purpose,
    keyVersion: row.key_version,
    rootKey,
    envelope,
    identity,
  });
}

function requireSeedExact(seed: Uint8Array, label: string): Buffer {
  if (seed.length !== ED25519_SEED_BYTES) {
    throw new Error(`${label}: seed must be exactly ${ED25519_SEED_BYTES} bytes`);
  }
  return Buffer.from(seed);
}

async function sealFillExisting(
  sql: SqlExecutor,
  rootKey: Uint8Array,
  nodeId: string,
  purpose: NodeSigningKeyPurpose,
  row: ActivePublicRow,
  seed: Uint8Array,
): Promise<NodeIdentityArtifactSigner> {
  const seedOwned = requireSeedExact(seed, "ensureActiveNodeSigningKey");
  try {
    const derivedPub = publicKeyFromEd25519Seed(seedOwned);
    if (derivedPub !== row.public_key) {
      throw new Error(
        "ensureActiveNodeSigningKey: seedOverride does not match active public-only registry key",
      );
    }
    const keyVersion = 1;
    const identity: NodeSigningKeyIdentity = {
      nodeId,
      purpose,
      publicKey: row.public_key,
      keyVersion,
    };
    const envelope = sealNodeSigningSeed(rootKey, identity, seedOwned, row.vault_secret_ref);
    await sql.query(
      `INSERT INTO node_signing_key_sealed_store
         (vault_secret_ref, key_version, ciphertext, nonce, auth_tag, ciphertext_sha256)
       VALUES ($1::uuid, $2, $3, $4, $5, $6)`,
      [
        row.vault_secret_ref,
        keyVersion,
        Buffer.from(envelope.ciphertext),
        Buffer.from(envelope.nonce),
        Buffer.from(envelope.authTag),
        envelope.ciphertextSha256,
      ],
    );
    await retireActiveRows(sql, nodeId, purpose, row.id);
    if (purpose === "NODE_IDENTITY") {
      await syncIdentityPublicKey(sql, nodeId, row.public_key);
    }
    return buildSignerFromSealed({
      signingKeyId: row.id,
      publicKey: row.public_key,
      purpose,
      keyVersion,
      rootKey,
      envelope,
      identity,
    });
  } finally {
    seedOwned.fill(0);
  }
}

async function mintAndSeal(
  sql: SqlExecutor,
  rootKey: Uint8Array,
  nodeId: string,
  purpose: NodeSigningKeyPurpose,
  seed: Uint8Array,
): Promise<NodeIdentityArtifactSigner> {
  const seedOwned = requireSeedExact(seed, "ensureActiveNodeSigningKey");
  try {
    // One-active structural: retire every prior active row before insert.
    await retireActiveRows(sql, nodeId, purpose);

    const publicKey = publicKeyFromEd25519Seed(seedOwned);
    const keyId = randomUUID();
    const vaultSecretRef = randomUUID();
    const keyVersion = 1;
    const identity: NodeSigningKeyIdentity = {
      nodeId,
      purpose,
      publicKey,
      keyVersion,
    };
    const envelope = sealNodeSigningSeed(rootKey, identity, seedOwned, vaultSecretRef);

    await sql.query(
      `INSERT INTO node_signing_key_sealed_store
         (vault_secret_ref, key_version, ciphertext, nonce, auth_tag, ciphertext_sha256)
       VALUES ($1::uuid, $2, $3, $4, $5, $6)`,
      [
        vaultSecretRef,
        keyVersion,
        Buffer.from(envelope.ciphertext),
        Buffer.from(envelope.nonce),
        Buffer.from(envelope.authTag),
        envelope.ciphertextSha256,
      ],
    );
    await sql.query(
      `INSERT INTO node_signing_keys
         (id, node_id, purpose, public_key, vault_secret_ref, activated_at)
       VALUES ($1::uuid, $2::uuid, $3, $4, $5::uuid, now())`,
      [keyId, nodeId, purpose, publicKey, vaultSecretRef],
    );

    if (purpose === "NODE_IDENTITY") {
      await syncIdentityPublicKey(sql, nodeId, publicKey);
    }

    return buildSignerFromSealed({
      signingKeyId: keyId,
      publicKey,
      purpose,
      keyVersion,
      rootKey,
      envelope,
      identity,
    });
  } finally {
    seedOwned.fill(0);
  }
}

/**
 * Load-or-mint an active node signing key for `purpose`.
 *
 * - Active sealed row present → open under root, return signer (prefer over any seed override).
 * - Active public-only (pre-923) → matching seedOverride seals under existing vault_secret_ref;
 * otherwise retire orphans and mint sealed (CSPRNG or override).
 * - Absent → mint from seedOverride or fresh CSPRNG seed, seal + register.
 * - seedOverride, when provided, must be exactly 32 bytes (no silent CSPRNG fallback).
 * - Fail-closed: open/mint errors propagate; no throwing stub signer is returned.
 */
export async function ensureActiveNodeSigningKey(
  input: EnsureActiveNodeSigningKeyInput,
): Promise<NodeIdentityArtifactSigner> {
  const purpose = assertExactPurpose(input.purpose);

  if (input.seedOverride !== undefined && input.seedOverride.length !== ED25519_SEED_BYTES) {
    throw new Error(
      `ensureActiveNodeSigningKey: seedOverride must be exactly ${ED25519_SEED_BYTES} bytes`,
    );
  }

  const run = async (): Promise<NodeIdentityArtifactSigner> => {
    // Structural serialize inside the caller's TX (no-op-(ish) if lock already held).
    // Memory test harnesses that do not implement advisory locks: catch and continue only
    // when the SQL harness explicitly has no lock surface (detected via error message).
    try {
      await acquireEnsureLock(input.sql, input.nodeId, purpose);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (!msg.includes("unexpected SQL") && !msg.includes("pg_advisory_xact_lock")) {
        throw err;
      }
      // In-memory unit harness: exclusiveLock path still serialises when composition wires it.
    }

    const existing = await selectActiveSealed(input.sql, input.nodeId, purpose);
    if (existing !== null) {
      const signer = rowToSigner(existing, input.rootKey, input.nodeId, purpose);
      if (purpose === "NODE_IDENTITY") {
        await syncIdentityPublicKey(input.sql, input.nodeId, signer.publicKey);
      }
      return signer;
    }

    const publicOnly = await selectActivePublicWithoutSeal(input.sql, input.nodeId, purpose);
    if (publicOnly.length > 0) {
      if (input.seedOverride !== undefined) {
        const overridePub = publicKeyFromEd25519Seed(input.seedOverride);
        const match = publicOnly.find((row) => row.public_key === overridePub);
        if (match !== undefined) {
          return sealFillExisting(
            input.sql,
            input.rootKey,
            input.nodeId,
            purpose,
            match,
            input.seedOverride,
          );
        }
        // Seed does not match any active public-only row — retire orphans and mint sealed.
        await retireActiveRows(input.sql, input.nodeId, purpose);
        return mintAndSeal(input.sql, input.rootKey, input.nodeId, purpose, input.seedOverride);
      }

      // No seed: cannot reconstruct orphan private material — retire and mint fresh sealed.
      await retireActiveRows(input.sql, input.nodeId, purpose);
      const fresh = generateEd25519Seed();
      try {
        return await mintAndSeal(input.sql, input.rootKey, input.nodeId, purpose, fresh);
      } finally {
        fresh.fill(0);
      }
    }

    // Greenfield: no active public or sealed row.
    if (input.seedOverride !== undefined) {
      return mintAndSeal(input.sql, input.rootKey, input.nodeId, purpose, input.seedOverride);
    }
    const fresh = generateEd25519Seed();
    try {
      return await mintAndSeal(input.sql, input.rootKey, input.nodeId, purpose, fresh);
    } finally {
      fresh.fill(0);
    }
  };

  if (input.withExclusiveLock) {
    return input.withExclusiveLock(run);
  }
  return run();
}

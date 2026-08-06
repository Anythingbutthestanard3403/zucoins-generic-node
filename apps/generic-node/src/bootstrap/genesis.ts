// first-boot operator genesis after migrations.
//
// Seeds the nodes row for NODE_ID (identity public key only), optional initial
// admin (in-memory admin store when Initial password is set), and optional
// implementer + credential when the registry is empty.

import { generateKeyPairSync, randomUUID, createPrivateKey, createPublicKey } from "node:crypto";
import { writeFile, chmod } from "node:fs/promises";
import type { Pool } from "pg";

import {
  bootstrapInitialAdmin,
  CredentialService,
  IMPLEMENTER_SCOPES,
  toBase64UrlPadded,
  type AdminUserStore,
  type CredentialStore,
} from "@zucoins/node-core";

import { enrolBootstrapReportingKey } from "./reporting-key-enrol.js";

export interface GenesisLogger {
  info(message: string): void;
  error(message: string, err?: unknown): void;
}

export interface GenesisConfig {
  readonly nodeId: string;
  readonly displayName?: string;
  /** Canonical padded base64url identity public key (44 chars). */
  readonly identityPublicKey: string;
  /** Production must never expose an operator surface with no account behind it. */
  readonly isProduction: boolean;
  readonly initialAdminPassword?: string;
  readonly bootstrapImplementerName?: string;
  /** When set, write the one-shot raw implementer key here (mode 0600). Never log full key. */
  readonly implementerCredentialOut?: string;
  /**
   * When set, genesis enrols the first ACTIVE reporting verification key and writes
   * the private seed once here (mode 0600). Required for live ARM (five headers).
   * Never log private material.
   */
  readonly reportingKeyOut?: string;
  /**
   * The reporting key id the operator declares unrecoverable (the genesis seed was
   * lost). Retires that key's implementer so the seeding path below runs the genesis first-key
   * ceremony again under a fresh one. Inert unless the id is the CURRENT head key.
   */
  readonly recoverLostReportingKeyId?: string;
}

export interface GenesisDeps {
  readonly pool: Pool;
  readonly adminUserStore: AdminUserStore;
  readonly credentialStore: CredentialStore;
  readonly logger: GenesisLogger;
}

/**
 * Seed the first operator, failing closed only for an empty production store.
 * Existing production nodes may remove INITIAL_ADMIN_PASSWORD after the first
 * successful seed; development retains the optional-password posture.
 */
export async function bootstrapGenesisAdmin(
  userStore: AdminUserStore,
  config: Pick<GenesisConfig, "initialAdminPassword" | "isProduction">,
  logger: GenesisLogger,
): Promise<void> {
  const passwordConfigured =
    config.initialAdminPassword !== undefined && config.initialAdminPassword.length > 0;
  if (!config.isProduction && !passwordConfigured) {
    return;
  }

  const outcome = await bootstrapInitialAdmin(
    userStore,
    { INITIAL_ADMIN_PASSWORD: config.initialAdminPassword },
    {
      info: (obj, msg) => {
        logger.info(typeof msg === "string" ? msg : JSON.stringify(obj));
      },
    },
  );
  if (outcome.seeded) {
    logger.info(
      `boot: initial admin seeded username=${outcome.username} (must change password + enrol TOTP)`,
    );
  }
}

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** Generate a valid padded base64url Ed25519 public key (nodes.identity_public_key). */
export function generateEphemeralIdentityPublicKey(): string {
  const { publicKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  return toBase64UrlPadded(Buffer.from(spki).subarray(-32));
}

/** Derive padded public key from a 32-byte Ed25519 seed (operator-held NODE_IDENTITY_SEED). */
export function publicKeyFromEd25519Seed(seed: Uint8Array): string {
  if (seed.length < 32) {
    throw new Error("ed25519 seed must be at least 32 bytes");
  }
  const seed32 = Buffer.from(seed.subarray(0, 32));
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, seed32]);
  const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return toBase64UrlPadded(Buffer.from(spki).subarray(-32));
}

/**
 * Parse NODE_IDENTITY_SEED: hex (≥64 hex chars) or base64/base64url (≥32 decoded bytes).
 * Returns the first 32 bytes as the Ed25519 seed.
 */
export function parseNodeIdentitySeed(raw: string): Uint8Array | null {
  const trimmed = raw.trim();
  if (trimmed.length === 0) return null;
  if (/^(?:[0-9a-fA-F]{2})+$/.test(trimmed) && trimmed.length >= 64) {
    return Buffer.from(trimmed.slice(0, 64), "hex");
  }
  try {
    const b64 = Buffer.from(trimmed, "base64");
    if (b64.length >= 32) return b64.subarray(0, 32);
  } catch {
    // fall through
  }
  try {
    const b64url = Buffer.from(trimmed, "base64url");
    if (b64url.length >= 32) return b64url.subarray(0, 32);
  } catch {
    // fall through
  }
  return null;
}

/** Idempotent nodes row for custody boot (FK target for ops / wallets / credentials audit). */
export async function ensureNodeRow(
  pool: Pool,
  args: {
    readonly nodeId: string;
    readonly displayName: string;
    readonly identityPublicKey: string;
  },
): Promise<{ readonly inserted: boolean }> {
  const result = await pool.query(
    `INSERT INTO nodes (id, display_name, identity_public_key)
     VALUES ($1::uuid, $2, $3)
     ON CONFLICT (id) DO NOTHING
     RETURNING id`,
    [args.nodeId, args.displayName, args.identityPublicKey],
  );
  return { inserted: (result.rowCount ?? 0) > 0 };
}

/**
 * @deprecated public-only register without seal is no longer the production path.
 * Prefer `ensureActiveNodeSigningKey` from `@zucoins/node-core` (seal + register).
 * Kept for test fixtures that only need a public registry row.
 */
export async function ensureNodeIdentitySigningKey(
  pool: Pool,
  args: {
    readonly keyId: string;
    readonly nodeId: string;
    readonly publicKey: string;
  },
): Promise<void> {
  await pool.query(
    `INSERT INTO node_signing_keys
       (id, node_id, purpose, public_key, vault_secret_ref, activated_at)
     VALUES ($1::uuid, $2::uuid, 'NODE_IDENTITY', $3, $4::uuid, now())
     ON CONFLICT (node_id, purpose, public_key) DO NOTHING`,
    [args.keyId, args.nodeId, args.publicKey, randomUUID()],
  );
}


/**
 * Operator-declared reporting-key seed loss (the reporting journal has no
 * in-implementer recovery without the private half). Retires only the implementer whose CURRENT head is `lostKeyId`, so a stale
 * recovery flag is inert. Tombstone only — evidence preserved, never deleted. Exported for the
 * admin SPA "I lost this key" path (same ceremony as REPORTING_KEY_RECOVER boot).
 */
export async function retireImplementerWithLostReportingKey(
  pool: Pool,
  nodeId: string,
  lostKeyId: string,
  logger?: GenesisLogger,
): Promise<string | null> {
  const log = logger ?? { info: () => undefined, error: () => undefined };
  return retireImplementerWithLostReportingKeyInner({ pool, logger: log }, nodeId, lostKeyId);
}

async function retireImplementerWithLostReportingKeyInner(
  deps: Pick<GenesisDeps, "pool" | "logger">,
  nodeId: string,
  lostKeyId: string,
): Promise<string | null> {
  const { rows } = await deps.pool.query<{ id: string }>(
    `UPDATE implementers i
        SET retired_at = now()
      WHERE i.retired_at IS NULL
        AND EXISTS (
          SELECT 1 FROM reporting_key_lifecycle_heads h
           WHERE h.node_id = $1::uuid
             AND h.implementer_id = i.id
             AND h.current_key_id = $2::uuid
        )
      RETURNING i.id::text AS id`,
    [nodeId, lostKeyId],
  );
  const retired = rows[0]?.id ?? null;
  if (retired === null) {
    deps.logger.info(
      `boot: reporting-key recovery requested for key_id=${lostKeyId} but it is not the current head key of any live implementer — no-op (already recovered, or wrong key id)`,
    );
    return null;
  }
  deps.logger.info(
    `boot: reporting-key recovery — implementer id=${retired} retired; its key_id=${lostKeyId} is declared unrecoverable and stays tombstoned (evidence preserved, never revoked, never deleted)`,
  );
  return retired;
}

async function bootstrapImplementerIfEmpty(
  deps: GenesisDeps,
  config: GenesisConfig,
): Promise<string | null> {
  const existing = await deps.pool.query<{ id: string }>(
    `SELECT id FROM implementers WHERE retired_at IS NULL ORDER BY id LIMIT 1`, // contract-allow:order:frozen structural vocabulary
  );
  if (existing.rows.length > 0) {
    return existing.rows[0]!.id;
  }

  const name = config.bootstrapImplementerName?.trim() || "dryrun";
  const implementerId = randomUUID();
  await deps.pool.query(`INSERT INTO implementers (id, name) VALUES ($1::uuid, $2)`, [
    implementerId,
    name,
  ]);

  const service = new CredentialService(deps.credentialStore);
  const created = await service.create(implementerId, [...IMPLEMENTER_SCOPES], null);
  const prefix = created.public_prefix;
  deps.logger.info(
    `boot: genesis implementer seeded name=${name} id=${implementerId} credential_prefix=${prefix}`,
  );

  const outPath = config.implementerCredentialOut?.trim();
  if (outPath !== undefined && outPath.length > 0) {
    await writeFile(outPath, `${created.raw_key}\n`, { encoding: "utf8", mode: 0o600 });
    await chmod(outPath, 0o600);
    deps.logger.info(
      `boot: implementer credential written once to IMPLEMENTER_CREDENTIAL_OUT (mode 0600); prefix=${prefix}`,
    );
  } else {
    deps.logger.info(
      `boot: implementer credential prefix=${prefix} — set IMPLEMENTER_CREDENTIAL_OUT to capture the raw key on first boot (never logged in full)`,
    );
  }
  return implementerId;
}

/**
 * Run after migrations (and privilege readiness). Idempotent where structural.
 */
export async function runGenesisBootstrap(
  deps: GenesisDeps,
  config: GenesisConfig,
): Promise<void> {
  const displayName = config.displayName?.trim() || config.nodeId;
  const node = await ensureNodeRow(deps.pool, {
    nodeId: config.nodeId,
    displayName,
    identityPublicKey: config.identityPublicKey,
  });
  if (node.inserted) {
    deps.logger.info(
      `boot: genesis nodes row inserted id=${config.nodeId} (ephemeral or seed-derived identity pubkey)`,
    );
  } else {
    deps.logger.info(`boot: genesis nodes row already present id=${config.nodeId}`);
  }

  await bootstrapGenesisAdmin(deps.adminUserStore, config, deps.logger);

  // Retire first, so the seeding below sees the bricked implementer as spent.
  const lostKeyId = config.recoverLostReportingKeyId?.trim();
  const recoveredFrom =
    lostKeyId !== undefined && lostKeyId.length > 0
      ? await retireImplementerWithLostReportingKeyInner(deps, config.nodeId, lostKeyId)
      : null;

  const implementerId = await bootstrapImplementerIfEmpty(deps, config);
  if (implementerId !== null) {
    await enrolBootstrapReportingKey(
      deps.pool,
      {
        nodeId: config.nodeId,
        implementerId,
        reportingKeyOut: config.reportingKeyOut,
        // AC2 successor link: names the superseded key on the new key's bootstrap evidence.
        onboardingActorId:
          recoveredFrom === null
            ? undefined
            : `reporting-key-recovery:superseded=${lostKeyId}`,
      },
      deps.logger,
    );
  }
}

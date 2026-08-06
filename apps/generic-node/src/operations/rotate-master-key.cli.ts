// Operator CLI for v2 generic-node master-key rotation.
//
// Node-local only (the key-custody rule). Keys are env-only — never argv — so they never
// land in shell history or the process table (logging discipline):
//
//   VAULT_MASTER_KEY       old master key (≥32 bytes)
//   VAULT_MASTER_KEY_NEW   new master key (≥32 bytes, ≠ old)
//   VAULT_ROOT_SALT_B64    base64 (std or url) of the PBKDF2 salt
//
//   node dist/operations/rotate-master-key.cli.js            # rotate + commit
//   node dist/operations/rotate-master-key.cli.js --dry-run  # prove, roll back
//
// This entrypoint wires the node-core rotation flow against the signing-key registry.
// Concrete vault + NODE_SIGNING_KEYS census + durable journal + SQL unit-of-work
// are injected by the composition root. unitOfWork is required (advisory xact lock
// on begin). Until adapters land, main() refuses with a diagnosable message
// (fail-closed).

import { fileURLToPath } from "node:url";

import {
  MASTER_KEY_ROTATION_ADVISORY_LOCK_ID,
  MasterKeyRotationError,
  SEALED_STORES,
  buildKeyRing,
  deriveRootKey,
  rewrapNodeSigningKeyStore,
  rewrapPushSecretStore,
  rotateMasterKey,
  type MasterKeyRotationInput,
  type MasterKeyRotationInterlock,
  type RotationLogger,
  type RotationUnitOfWork,
} from "@zucoins/node-core";

const MIN_MASTER_KEY_BYTES = 32;

export interface RotateMasterKeyCliDeps {
  readonly loadCensus:
    | MasterKeyRotationInput["walletVault"]
    | (() => Promise<MasterKeyRotationInput["walletVault"]>);
  readonly journal: MasterKeyRotationInput["journal"];
  readonly interlock: MasterKeyRotationInterlock;
  readonly commitWalletVault: MasterKeyRotationInput["commitWalletVault"];
  /**
   * Required live `vault` row count, issued on the ceremony connection inside the fence.
   * `loadCensus` runs before the rotation takes its locks, so this is what proves the
   * census still covers the store; a mismatch aborts with zero mutation (D-A2).
   */
  readonly countWalletVaultRows: MasterKeyRotationInput["countWalletVaultRows"];
  /**
   * NODE_SIGNING_KEYS census. Defaults to empty `{ rows: [] }` when omitted.
   * Composition with live rows MUST pass a real census; pair with countNodeSigningKeyRows.
   */
  readonly loadNodeSigningKeysCensus?:
    | MasterKeyRotationInput["nodeSigningKeys"]
    | (() => Promise<NonNullable<MasterKeyRotationInput["nodeSigningKeys"]>>);
  /**
   * Required live node_signing_key_sealed_store row count inside the fence.
   * Never defaulted to census length here — composition must prove the store count
   * (empty greenfield → 0).
   */
  readonly countNodeSigningKeyRows: NonNullable<
    MasterKeyRotationInput["countNodeSigningKeyRows"]
  >;
  readonly commitNodeSigningKeys?: MasterKeyRotationInput["commitNodeSigningKeys"];
  /** Full PUSH_RECEIVER_SECRETS snapshot loaded from the production store. */
  readonly loadPushSecretsCensus:
    | NonNullable<MasterKeyRotationInput["pushReceiverSecrets"]>
    | (() => Promise<NonNullable<MasterKeyRotationInput["pushReceiverSecrets"]>>);
  /** Authoritative live push-secret count on the ceremony connection inside the fence. */
  readonly countPushSecretRows: NonNullable<MasterKeyRotationInput["countPushSecretRows"]>;
  /** Same-UoW persistence port for the complete rewrapped push census. */
  readonly commitPushSecrets?: MasterKeyRotationInput["commitPushSecrets"];
  /** Required exclusive TX (advisory lock on begin). */
  readonly unitOfWork: RotationUnitOfWork;
  readonly fromEpoch: number;
  readonly logger?: RotationLogger;
  /** Override env reader (tests). */
  readonly env?: NodeJS.ProcessEnv;
  readonly argv?: readonly string[];
}

export interface RotateMasterKeyCliResult {
  readonly committed: boolean;
  readonly dryRun: boolean;
  readonly walletCount: number;
  readonly durationMs: number;
}

/** The hardened post-commit operator sequence. Ordered; OLD key retired LAST. */
export const OPERATOR_SEQUENCE = [
  "The rotation is COMMITTED — every IMPLEMENTED sealed store now decrypts under the new key (key-ring writer epoch advanced).",
  "Set VAULT_MASTER_KEY to the new key value in the node environment (and unset VAULT_MASTER_KEY_NEW).",
  "Boot the node: vault unlock under the new master is the independent verifier that env now matches the journal writer epoch.",
  "Re-take backups NOW — existing backups decrypt only under the OLD key and are stale the moment the node boots.",
  "Retire/destroy the OLD key LAST, only after a clean boot and fresh backups confirm the new key is good.",
] as const;

function requireEnv(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (value === undefined || value === "") {
    throw new MasterKeyRotationError(
      "ROTATION_REFUSED",
      `${name} is not set — rotation needs VAULT_MASTER_KEY, VAULT_MASTER_KEY_NEW, and VAULT_ROOT_SALT_B64`,
    );
  }
  return value;
}

function parseMasterKey(raw: string, label: string): Buffer {
  const buf = Buffer.from(raw, "utf8");
  if (buf.length < MIN_MASTER_KEY_BYTES) {
    throw new MasterKeyRotationError(
      "ROTATION_REFUSED",
      `${label} must be at least ${MIN_MASTER_KEY_BYTES} bytes`,
    );
  }
  return buf;
}

function parseSalt(raw: string): Buffer {
  const normalized = raw.replace(/-/g, "+").replace(/_/g, "/");
  const buf = Buffer.from(normalized, "base64");
  if (buf.length < 8) {
    throw new MasterKeyRotationError(
      "ROTATION_REFUSED",
      "VAULT_ROOT_SALT_B64 decodes to fewer than 8 bytes",
    );
  }
  return buf;
}

const defaultLogger: RotationLogger = {
  info: (obj, msg) => {
    console.log(JSON.stringify({ level: "info", msg, ...obj }));
  },
  error: (obj, msg) => {
    console.error(JSON.stringify({ level: "error", msg, ...obj }));
  },
};

/**
 * Programmatic entry used by tests and by a composition root. Validates env, derives
 * roots, and runs {@link rotateMasterKey} against the injected ports.
 */
export async function runRotateMasterKeyCli(
  deps: RotateMasterKeyCliDeps,
): Promise<RotateMasterKeyCliResult> {
  const env = deps.env ?? process.env;
  const argv = deps.argv ?? process.argv;
  const dryRun = argv.includes("--dry-run");
  const logger = deps.logger ?? defaultLogger;

  const oldRaw = requireEnv(env, "VAULT_MASTER_KEY");
  const newRaw = requireEnv(env, "VAULT_MASTER_KEY_NEW");
  const saltRaw = requireEnv(env, "VAULT_ROOT_SALT_B64");

  if (oldRaw === newRaw) {
    throw new MasterKeyRotationError(
      "ROTATION_REFUSED",
      "VAULT_MASTER_KEY_NEW equals VAULT_MASTER_KEY — nothing to rotate",
    );
  }

  // Fail closed when a live count is non-zero but that store's commit port is unwired.
  // `rotateMasterKey` also refuses (inside the fence, before any write), but a CLI-level
  // refusal names the CLI wiring gap. Deliberately ahead of `parseMasterKey`/`deriveRootKey`
  // (C3): nothing has been adopted yet, so the refusal path has no key material to
  // leave behind.
  const signingCountProbe = await deps.countNodeSigningKeyRows();
  if (signingCountProbe > 0 && deps.commitNodeSigningKeys === undefined) {
    throw new MasterKeyRotationError(
      "ROTATION_REFUSED",
      "NODE_SIGNING_KEYS rows present but commitNodeSigningKeys port is not wired",
    );
  }
  const pushCountProbe = await deps.countPushSecretRows();
  if (pushCountProbe > 0 && deps.commitPushSecrets === undefined) {
    throw new MasterKeyRotationError(
      "ROTATION_REFUSED",
      "PUSH_RECEIVER_SECRETS rows present but commitPushSecrets port is not wired",
    );
  }

  const oldMaster = parseMasterKey(oldRaw, "VAULT_MASTER_KEY");
  let newMaster: Buffer | undefined;
  let salt: Buffer | undefined;
  let oldRoot: Buffer | undefined;
  let newRoot: Buffer | undefined;
  let result;
  try {
    newMaster = parseMasterKey(newRaw, "VAULT_MASTER_KEY_NEW");
    salt = parseSalt(saltRaw);
    oldRoot = deriveRootKey(oldMaster, salt);
    newRoot = deriveRootKey(newMaster, salt);

    const fromEpoch = deps.fromEpoch;
    const toEpoch = fromEpoch + 1;
    const census =
      typeof deps.loadCensus === "function" ? await deps.loadCensus() : deps.loadCensus;
    const nodeSigningKeys =
      deps.loadNodeSigningKeysCensus === undefined
        ? { rows: [] as const }
        : typeof deps.loadNodeSigningKeysCensus === "function"
          ? await deps.loadNodeSigningKeysCensus()
          : deps.loadNodeSigningKeysCensus;
    const pushReceiverSecrets =
      typeof deps.loadPushSecretsCensus === "function"
        ? await deps.loadPushSecretsCensus()
        : deps.loadPushSecretsCensus;
    const keyRing = buildKeyRing({
      writerEpoch: toEpoch,
      writerRoot: newRoot,
      retained: [{ epoch: fromEpoch, root: oldRoot }],
    });

    result = await rotateMasterKey({
      sealedStores: SEALED_STORES,
      walletVault: census,
      nodeSigningKeys,
      pushReceiverSecrets,
      keyRing,
      fromEpoch,
      toEpoch,
      oldRootKey: oldRoot,
      newRootKey: newRoot,
      journal: deps.journal,
      interlock: deps.interlock,
      commitWalletVault: deps.commitWalletVault,
      countWalletVaultRows: deps.countWalletVaultRows,
      countNodeSigningKeyRows: deps.countNodeSigningKeyRows,
      commitNodeSigningKeys: deps.commitNodeSigningKeys,
      countPushSecretRows: deps.countPushSecretRows,
      commitPushSecrets: deps.commitPushSecrets,
      rewrapNodeSigningKeyStore: (input) => {
        // Rotation census types purpose as string; rewrap asserts exact purpose at seal/open.
        return rewrapNodeSigningKeyStore({
          oldRootKey: input.oldRootKey,
          newRootKey: input.newRootKey,
          rows: input.rows as Parameters<typeof rewrapNodeSigningKeyStore>[0]["rows"],
        });
      },
      rewrapPushSecretStore: (input) =>
        rewrapPushSecretStore({
          keyRing: input.keyRing,
          newRootKey: input.newRootKey,
          fromEpoch: input.fromEpoch,
          toEpoch: input.toEpoch,
          rows: input.rows as Parameters<typeof rewrapPushSecretStore>[0]["rows"],
        }),
      unitOfWork: deps.unitOfWork,
      dryRun,
      logger,
    });
  } finally {
    // Enclose derivation, every census loader, key-ring construction and the complete
    // rotation. This also covers synchronous throws before an awaited loader settles.
    oldMaster.fill(0);
    newMaster?.fill(0);
    oldRoot?.fill(0);
    newRoot?.fill(0);
    salt?.fill(0);
  }

  if (result.dryRun) {
    logger.info(
      {
        event: "rotate.dry_run_ok",
        walletCount: result.walletCount,
        durationMs: result.durationMs,
        advisoryLockId: MASTER_KEY_ROTATION_ADVISORY_LOCK_ID,
      },
      "rotate-master-key DRY-RUN OK — rotation would succeed; database left UNCHANGED",
    );
  } else {
    logger.info(
      {
        event: "rotate.operator_sequence",
        steps: OPERATOR_SEQUENCE,
        walletCount: result.walletCount,
        durationMs: result.durationMs,
      },
      "rotate-master-key COMMITTED — run the operator sequence in `steps` as listed now",
    );
  }

  return {
    committed: result.committed,
    dryRun: result.dryRun,
    walletCount: result.walletCount,
    durationMs: result.durationMs,
  };
}

/**
 * Process main. Fail-closed until the composition root supplies durable adapters —
 * printing a single actionable refusal rather than half-running against empty state.
 */
export async function main(_argv: readonly string[] = process.argv): Promise<void> {
  const logger = defaultLogger;
  logger.error(
    { event: "rotate.refused", reason: "adapters_not_wired" },
    "rotate-master-key REFUSED — durable vault census/journal/unit-of-work adapters are not wired in this binary. " +
      "Call runRotateMasterKeyCli(deps) from the node composition root that injects real ports " +
      `(advisory lock id=${MASTER_KEY_ROTATION_ADVISORY_LOCK_ID}), including NODE_SIGNING_KEYS and PUSH_RECEIVER_SECRETS census + authoritative count + same-UoW commit ports.`,
  );
  process.exitCode = 1;
}

const isMain = process.argv[1] === fileURLToPath(import.meta.url);
if (isMain) {
  main().catch((err: unknown) => {
    const refused = err instanceof MasterKeyRotationError && err.code === "ROTATION_REFUSED";
    defaultLogger.error(
      {
        event: refused ? "rotate.refused" : "rotate.failed",
        err: err instanceof Error ? err.message : String(err),
      },
      refused
        ? "rotate-master-key REFUSED — nothing changed"
        : "rotate-master-key FAILED — nothing changed",
    );
    process.exitCode = 1;
  });
}

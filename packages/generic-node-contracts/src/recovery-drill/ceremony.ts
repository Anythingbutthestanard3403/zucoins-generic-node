/**
 * SOURCE: the signing-custody-security spec the ceremony (ceremony),
 * the ceremony procedure (procedure), the ceremony negative paths (negative paths), the drill matrix (drill matrix); the data model receive-eligibility predicate;
 * the recovery-purposes freeze, the backup-archive freeze.
 *
 * A MODEL-LEVEL reproduction of the ceremony for the recovery-drill lane drills: it runs the real crypto
 * (vault open, public-key census, archived-proof verify, fresh probe sign/verify) against in-memory
 * "live" and "restored" databases, and it enforces the stamp discipline exactly — the designated
 * stamping path is the SOLE writer of `recovery_verified_at`, as one transaction with three writes
 * (audit_log + wallet_recovery_verifications + wallets stamp). Every write is recorded in a ledger
 * (the query witness) so each failure-class drill can assert ZERO stamp/evidence writes.
 *
 * SCOPE — this is CONTRACT_FREEZE drill machinery. It is a MODEL of the ceremony; the node
 * runs `packages/node-core/src/core/recovery/*` instead, and nothing here executes on that path.
 * Of what this file models, only the two SIGNED ARTIFACTS have committed goldens, and the
 * production modules that emit them are bound to those goldens by
 * `packages/node-core/test/recovery-golden-binding.test.ts` (ask 2). The ceremony
 * PROCEDURE modelled here — phase sequence, stamp discipline, failure-class outcomes — has no
 * committed golden, so it is not bound to production by anything; production's own procedure is
 * covered separately by `packages/node-core/test/recovery-restore-ceremony.test.ts` against its
 * own fixtures. A green run here proves the model, never production behaviour.
 */
import { sha256Hex, utf8Bytes, verifyPreimageSignature } from "../testkit/independentCrypto.ts";
import { deriveWalletDek } from "./hkdf.ts";
import { openWalletSecret } from "./envelope.ts";
import { derivePublicKey, publicKeyMatches, signWithSecret64, ready } from "./keys.ts";
import { verifyArchive } from "./verify.ts";
import {
  buildRecoveryVerificationPayload,
  recoveryVerificationPreimage,
} from "./recovery-payload.ts";
import { BACKUP_WALLET_EXPORT_PURPOSE } from "./purposes.contract.ts";
import {
  KEY_VERSION,
  NODE_ID,
  type DrillWorld,
  type LiveDb,
} from "./fixtures.ts";

/** The query witness: every live-database write the ceremony performs, in sequence. */
export interface WriteLedgerEntry {
  readonly table: "audit_log" | "wallet_recovery_verifications" | "wallets";
  readonly op: "insert" | "update_stamp";
  readonly walletId: string | null;
  readonly transaction: number;
}

export type WalletOutcome = "stamped" | "failed_closed" | "skipped";

export interface CeremonyResult {
  readonly phase0Accepted: boolean;
  readonly abortReasons: readonly string[];
  readonly bornBlocked: readonly string[];
  readonly outcomes: Readonly<Record<string, WalletOutcome>>;
  readonly ledger: readonly WriteLedgerEntry[];
  readonly restoredActiveLeases: number;
  readonly summaryWritten: boolean;
}

export interface CeremonyInput {
  readonly world: DrillWorld;
  readonly archiveText: string;
  readonly archiveEpochRoot: Uint8Array;
  readonly currentEpochRoot: Uint8Array;
  readonly liveDb: LiveDb;
  readonly ceremonyId: string;
  readonly ceremonyNonceB64Url: string;
  readonly issuedAt: string;
  readonly verifierIdentity: string;
}

const stampWrites = (ledger: WriteLedgerEntry[], walletId: string, transaction: number): void => {
  ledger.push({ table: "audit_log", op: "insert", walletId, transaction });
  ledger.push({ table: "wallet_recovery_verifications", op: "insert", walletId, transaction });
  ledger.push({ table: "wallets", op: "update_stamp", walletId, transaction });
};

/** Count stamp/evidence writes in the ledger — the assertion target for failure-class drills. */
export const countStampWrites = (ledger: readonly WriteLedgerEntry[]): number =>
  ledger.filter((entry) => entry.op === "update_stamp").length;

export const countEvidenceWrites = (ledger: readonly WriteLedgerEntry[]): number =>
  ledger.filter((entry) => entry.table === "wallet_recovery_verifications").length;

const recomputeExportSha256 = (section: Record<string, unknown>): string => {
  const fields = [
    "purpose",
    "canonical_version",
    "node_id",
    "export_id",
    "wallet_id",
    "public_key",
    "key_origin",
    "key_version",
    "vault",
  ];
  const payload = Object.fromEntries(fields.map((field) => [field, section[field]]));
  return sha256Hex(utf8Bytes(`${BACKUP_WALLET_EXPORT_PURPOSE}\n${JSON.stringify(payload)}`));
};

/** Run the ceremony against the model databases. Caller must have awaited `ready()`. */
export const runCeremony = (input: CeremonyInput): CeremonyResult => {
  const { world, archiveText, liveDb } = input;
  const ledger: WriteLedgerEntry[] = [];
  const outcomes: Record<string, WalletOutcome> = {};

  // Phase 0 — archive acceptance (all-or-nothing) + cross-node acceptance + census.
  const acceptance = verifyArchive(archiveText);
  const abortReasons = [...acceptance.reasons];
  const archive = JSON.parse(archiveText) as Record<string, unknown>;
  const manifest = archive.manifest as Record<string, unknown>;
  const sections = (archive.wallet_sections ?? []) as readonly Record<string, unknown>[];

  if (manifest.node_id !== liveDb.nodeId) {
    abortReasons.push(`cross-node: manifest node_id ${String(manifest.node_id)} != live ${liveDb.nodeId}`);
  }
  for (const section of sections) {
    const liveWallet = liveDb.wallets.get(String(section.wallet_id));
    if (liveWallet === undefined || liveWallet.publicKey !== section.public_key) {
      abortReasons.push(`cross-node: no live wallets row matching section ${String(section.wallet_id)}`);
    }
  }
  const sectionIds = new Set(sections.map((section) => String(section.wallet_id)));
  const bornBlocked = [...liveDb.wallets.keys()].filter((id) => !sectionIds.has(id)).sort();

  if (abortReasons.length > 0) {
    return {
      phase0Accepted: false,
      abortReasons,
      bornBlocked,
      outcomes,
      ledger,
      restoredActiveLeases: 0,
      summaryWritten: false,
    };
  }

  // Phase 1 — fresh-database restore. wallet_active_leases is NEVER restored (the coverage table exclusion).
  const restoredActiveLeases = 0;

  // Phase 2 preamble — current-key possession (read-only). Failure stamps nothing.
  const currentVault = [...liveDb.currentEpochVault.values()][0];
  let currentKeyHeld = false;
  if (currentVault !== undefined) {
    const dek = deriveWalletDek(input.currentEpochRoot, {
      nodeId: liveDb.nodeId,
      walletId: currentVault.walletId,
      keyVersion: String(currentVault.keyVersion),
    });
    const liveWallet = liveDb.wallets.get(currentVault.walletId);
    try {
      const opened = openWalletSecret(
        dek,
        {
          nodeId: liveDb.nodeId,
          walletId: currentVault.walletId,
          keyVersion: String(currentVault.keyVersion),
          publicKey: liveWallet?.publicKey ?? "",
          keyOrigin: "node_generated",
        },
        { ciphertext: currentVault.ciphertext, nonce: currentVault.nonce, authTag: currentVault.authTag },
      );
      currentKeyHeld = publicKeyMatches(derivePublicKey(opened), liveWallet?.publicKey ?? "");
    } catch {
      currentKeyHeld = false;
    }
  }
  if (!currentKeyHeld) {
    return {
      phase0Accepted: true,
      abortReasons: ["current-key possession check failed: gate MUST NOT stamp when the current key is lost"],
      bornBlocked,
      outcomes,
      ledger,
      restoredActiveLeases,
      summaryWritten: false,
    };
  }

  // Phase 2 — per-wallet proof, ascending wallet_id, one at a time.
  const manifestWallets = manifest.wallets as readonly Record<string, unknown>[];
  let transactionSeq = 0;
  for (const section of sections) {
    const walletId = String(section.wallet_id);
    const worldWallet = world.wallets.find((wallet) => wallet.def.id === walletId);
    const liveWallet = liveDb.wallets.get(walletId);
    const manifestEntry = manifestWallets.find((entry) => entry.wallet_id === walletId);
    if (worldWallet === undefined || liveWallet === undefined || manifestEntry === undefined) {
      outcomes[walletId] = "failed_closed";
      continue;
    }

    // Idempotent skip: an existing (wallet_id, export_sha256) evidence row is a skip, not an error.
    const exportSha256 = recomputeExportSha256(section);
    if (liveWallet.recoveryVerifiedAt !== null && manifestEntry.export_sha256 === exportSha256) {
      outcomes[walletId] = "skipped";
      continue;
    }

    // (a) Open the restored vault row under the archive-epoch root.
    let opened: Uint8Array;
    try {
      const dek = deriveWalletDek(input.archiveEpochRoot, {
        nodeId: NODE_ID,
        walletId,
        keyVersion: String(KEY_VERSION),
      });
      opened = openWalletSecret(
        dek,
        {
          nodeId: NODE_ID,
          walletId,
          keyVersion: String(KEY_VERSION),
          publicKey: worldWallet.publicKeyB64Url,
          keyOrigin: "node_generated",
        },
        worldWallet.envelope,
      );
    } catch {
      outcomes[walletId] = "failed_closed";
      continue;
    }

    // (b) Public-key census: derived key must match BOTH the restored and the live authoritative row.
    let derivedPublic: Uint8Array;
    try {
      derivedPublic = derivePublicKey(opened);
    } catch {
      outcomes[walletId] = "failed_closed";
      continue;
    }
    if (
      !publicKeyMatches(derivedPublic, worldWallet.publicKeyB64Url) ||
      !publicKeyMatches(derivedPublic, liveWallet.publicKey)
    ) {
      outcomes[walletId] = "failed_closed";
      continue;
    }

    // (c) Archived-proof verification against the recomputed digest (never node-reported).
    const proofPreimage = `${BACKUP_WALLET_EXPORT_PURPOSE}\n${JSON.stringify(
      Object.fromEntries(
        [
          "purpose",
          "canonical_version",
          "node_id",
          "export_id",
          "wallet_id",
          "public_key",
          "key_origin",
          "key_version",
          "vault",
        ].map((field) => [field, section[field]]),
      ),
    )}`;
    if (
      String(manifestEntry.export_sha256) !== exportSha256 ||
      !verifyPreimageSignature(proofPreimage, String(section.export_proof_signature), derivedPublic)
    ) {
      outcomes[walletId] = "failed_closed";
      continue;
    }

    // (d) Fresh sign-capability probe over the recovery-verification payload.
    const probePayload = buildRecoveryVerificationPayload({
      nodeId: NODE_ID,
      walletId,
      publicKeyB64Url: worldWallet.publicKeyB64Url,
      keyVersion: KEY_VERSION,
      exportId: String(manifest.export_id),
      exportSha256,
      ceremonyId: input.ceremonyId,
      ceremonyNonceB64Url: input.ceremonyNonceB64Url,
      issuedAt: input.issuedAt,
    });
    const probePreimage = recoveryVerificationPreimage(probePayload);
    const probeSignature = signWithSecret64(probePreimage, opened);
    if (!verifyPreimageSignature(probePreimage, probeSignature, derivedPublic)) {
      outcomes[walletId] = "failed_closed";
      continue;
    }

    // (e) Atomic evidence write on the LIVE database: ONE transaction, THREE writes.
    transactionSeq += 1;
    stampWrites(ledger, walletId, transactionSeq);
    liveDb.recoveryVerificationCount += 1;
    liveDb.auditLogCount += 1;
    liveWallet.recoveryVerifiedAt = input.issuedAt;
    liveWallet.recoveryVerificationId = `rvv-${walletId}`;
    outcomes[walletId] = "stamped";
  }

  // Phase 3 — ceremony-summary audit row, then destruction of the restored instance (modeled).
  liveDb.auditLogCount += 1;
  return {
    phase0Accepted: true,
    abortReasons: [],
    bornBlocked,
    outcomes,
    ledger,
    restoredActiveLeases,
    summaryWritten: true,
  };
};

export { ready };

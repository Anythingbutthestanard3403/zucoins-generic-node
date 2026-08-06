import { beforeAll, describe, expect, it } from "vitest";

import { ready, encodeBase64Url } from "../testkit/independentCrypto.ts";
import {
  buildDrillWorld,
  buildLiveDb,
  ROOT_EPOCH_1,
  ROOT_EPOCH_2,
  ROOT_WRONG,
  WALLET_DEFS,
  CEREMONY_ID,
  EXPORTED_AT,
  KEY_VERSION,
  NODE_ID,
  type DrillWorld,
  type LiveDb,
} from "./fixtures.ts";
import { buildArchive } from "./archive.ts";
import { verifyArchive } from "./verify.ts";
import {
  runCeremony,
  countStampWrites,
  countEvidenceWrites,
  type CeremonyInput,
  type CeremonyResult,
} from "./ceremony.ts";
import { sealWalletSecret } from "./envelope.ts";
import { deriveWalletDek } from "./hkdf.ts";
import { openWalletSecret } from "./envelope.ts";
import { walletKeyFromSeedByte } from "./keys.ts";

/**
 * the recovery-drill lane drill matrix (the signing-custody-security spec the drill matrix). Twelve drills — the eight required
 * destroy-restore / corrupt-recovery vectors PLUS four adversarial vectors — each executed against
 * the real crypto (AES-256-GCM vault open, Ed25519 census/proof/probe) over synthetic keys. Every
 * FAILURE-CLASS drill asserts the stamp discipline directly through the write-ledger query witness:
 * ZERO `recovery_verified_at` stamp writes and ZERO evidence writes. Only drill 1 (the designated
 * full destroy-and-restore stamping drill) writes the stamp, in the exact one-transaction
 * three-write shape.
 *
 * SCOPE OF A GREEN RUN — read this before treating a pass as "destroy-restore is proven".
 * These twelve drills exercise the MODEL in `src/recovery-drill/`, which is not the code the node
 * runs: production lives in `packages/node-core/src/core/backup/*` (the archive section export/verify) and
 * `packages/node-core/src/core/recovery/*` (the ceremony). Nothing in this file executes either.
 * What it proves is that the model and its committed goldens still agree.
 *
 * Production is held to the SAME committed goldens by
 * `packages/node-core/test/recovery-golden-binding.test.ts` (ask 2): the production
 * exporter must reproduce `goldens/recovery/archive.json.txt` and the `zp-backup-wallet-export-v1`
 * preimage/digest/signature byte-for-byte, and the production probe must reproduce the
 * `zp-recovery-verification-v1` preimage. That binding covers the two signed ARTIFACTS and the
 * archive — it does NOT cover the ceremony PROCEDURE these drills model (phase sequence, stamp
 * discipline, failure-class outcomes), because no golden of a ceremony run exists to bind it to.
 */

const ceremonyNonce = (): string => encodeBase64Url(new Uint8Array(32).fill(0x77));

const runDrill = (input: {
  world: DrillWorld;
  archiveText: string;
  liveDb: LiveDb;
  archiveEpochRoot?: Uint8Array;
  currentEpochRoot?: Uint8Array;
}): CeremonyResult =>
  runCeremony({
    world: input.world,
    archiveText: input.archiveText,
    archiveEpochRoot: input.archiveEpochRoot ?? ROOT_EPOCH_1,
    currentEpochRoot: input.currentEpochRoot ?? ROOT_EPOCH_1,
    liveDb: input.liveDb,
    ceremonyId: CEREMONY_ID,
    ceremonyNonceB64Url: ceremonyNonce(),
    issuedAt: EXPORTED_AT,
    verifierIdentity: "fixture-drill-verifier",
  } satisfies CeremonyInput);

/** The stamp-discipline query witness: a failure-class drill MUST leave the live database
 *  un-stamped — no stamp writes, no evidence writes, every wallet still born-blocked. */
const expectZeroStampWrites = (result: CeremonyResult, liveDb: LiveDb): void => {
  expect(countStampWrites(result.ledger)).toBe(0);
  expect(countEvidenceWrites(result.ledger)).toBe(0);
  expect(result.ledger).toHaveLength(0);
  for (const wallet of [...liveDb.wallets.values()]) {
    expect(wallet.recoveryVerifiedAt).toBeNull();
    expect(wallet.recoveryVerificationId).toBeNull();
  }
};

describe("the recovery-drill lane drill matrix (the drill matrix)", () => {
  beforeAll(async () => {
    await ready();
  });

  it("drill 1 — full destroy-and-restore: the designated stamping drill stamps all 3 wallets, one 3-write transaction each", () => {
    const world = buildDrillWorld();
    const built = buildArchive(world);
    const liveDb = buildLiveDb(world);
    const result = runDrill({ world, archiveText: built.archiveText, liveDb });

    expect(result.phase0Accepted).toBe(true);
    for (const wallet of world.wallets) expect(result.outcomes[wallet.def.id]).toBe("stamped");
    // Exact one-transaction three-write shape: 3 wallets × (audit_log + recovery_verifications + stamp).
    expect(countStampWrites(result.ledger)).toBe(3);
    expect(countEvidenceWrites(result.ledger)).toBe(3);
    expect(result.ledger).toHaveLength(9);
    expect(new Set(result.ledger.map((entry) => entry.transaction)).size).toBe(3);
    for (const wallet of world.wallets) {
      const writes = result.ledger.filter((entry) => entry.walletId === wallet.def.id);
      expect(writes.map((entry) => `${entry.table}:${entry.op}`)).toEqual([
        "audit_log:insert",
        "wallet_recovery_verifications:insert",
        "wallets:update_stamp",
      ]);
      expect(new Set(writes.map((entry) => entry.transaction)).size).toBe(1);
    }
    // the coverage table exclusion: wallet_active_leases is NEVER restored.
    expect(result.restoredActiveLeases).toBe(0);
    expect(liveDb.walletActiveLeases).toBe(0);
  });

  it("drill 2 — wrong-key (wrong backup root): archive-epoch open fails GCM, nothing stamps", () => {
    const world = buildDrillWorld();
    const built = buildArchive(world);
    const liveDb = buildLiveDb(world);
    const result = runDrill({
      world,
      archiveText: built.archiveText,
      liveDb,
      archiveEpochRoot: ROOT_WRONG,
      currentEpochRoot: ROOT_EPOCH_1,
    });
    expect(result.phase0Accepted).toBe(true);
    for (const wallet of world.wallets) expect(result.outcomes[wallet.def.id]).toBe("failed_closed");
    expectZeroStampWrites(result, liveDb);
  });

  it("drill 3 — missing-row (live wallets row absent): cross-node completeness aborts phase 0, nothing stamps", () => {
    const world = buildDrillWorld();
    const built = buildArchive(world);
    const liveDb = buildLiveDb(world);
    liveDb.wallets.delete(world.wallets[2].def.id); // a covered section now has no live wallets row
    const result = runDrill({ world, archiveText: built.archiveText, liveDb });
    expect(result.phase0Accepted).toBe(false);
    expect(result.abortReasons.some((reason) => reason.startsWith("cross-node"))).toBe(true);
    expectZeroStampWrites(result, liveDb);
  });

  it("drill 4 — corrupt-ciphertext / bad-tag / mismatched-AAD: real GCM authentication failures throw", () => {
    const key = walletKeyFromSeedByte(0x21);
    const dek = deriveWalletDek(ROOT_EPOCH_1, { nodeId: NODE_ID, walletId: WALLET_DEFS[0].id, keyVersion: String(KEY_VERSION) });
    const aad = {
      nodeId: NODE_ID,
      walletId: WALLET_DEFS[0].id,
      keyVersion: String(KEY_VERSION),
      publicKey: key.publicKeyB64Url,
      keyOrigin: "node_generated" as const,
    };
    const envelope = sealWalletSecret(dek, aad, key.secret64, new Uint8Array(12).fill(0x09));
    expect(openWalletSecret(dek, aad, envelope)).toEqual(key.secret64); // sanity: clean open

    // (a) flipped ciphertext byte
    const flippedCt = envelope.ciphertext.slice();
    flippedCt[0] ^= 0xff;
    expect(() => openWalletSecret(dek, aad, { ...envelope, ciphertext: flippedCt })).toThrow(/GCM authentication failed/);

    // (b) corrupt auth tag
    const badTag = envelope.authTag.slice();
    badTag[badTag.length - 1] ^= 0x01;
    expect(() => openWalletSecret(dek, aad, { ...envelope, authTag: badTag })).toThrow(/GCM authentication failed/);

    // (c) mismatched AAD (different wallet_id reconstructed at open)
    const wrongAad = { ...aad, walletId: WALLET_DEFS[1].id };
    expect(() => openWalletSecret(dek, wrongAad, envelope)).toThrow(/GCM authentication failed/);
  });

  it("drill 5 — partial-archive (subset of wallets): the absent wallet is born-blocked, present wallets stamp", () => {
    const subsetDefs = WALLET_DEFS.slice(0, 2); // archive covers wallets 1 and 2 only
    const world = buildDrillWorld(ROOT_EPOCH_1, subsetDefs);
    const built = buildArchive(world);
    // Live database still knows all three wallets (the node has a third wallet not in this archive).
    const fullWorld = buildDrillWorld();
    const liveDb = buildLiveDb(fullWorld);
    const result = runDrill({ world, archiveText: built.archiveText, liveDb });

    expect(result.phase0Accepted).toBe(true);
    const absentId = WALLET_DEFS[2].id;
    expect(result.bornBlocked).toEqual([absentId]);
    for (const def of subsetDefs) expect(result.outcomes[def.id]).toBe("stamped");
    expect(result.outcomes[absentId]).toBeUndefined(); // never processed, never stamped
    expect(countStampWrites(result.ledger)).toBe(2);
    expect(liveDb.wallets.get(absentId)?.recoveryVerifiedAt).toBeNull();
  });

  it("drill 6 — duplicate-identity (live row carries a conflicting public_key): cross-node abort, nothing stamps", () => {
    const world = buildDrillWorld();
    const built = buildArchive(world);
    const liveDb = buildLiveDb(world);
    // Reintroduce wallet 2's public_key under wallet 3's live row → identity conflict on cross-node check.
    const conflicting = liveDb.wallets.get(world.wallets[2].def.id);
    if (conflicting !== undefined) {
      liveDb.wallets.set(conflicting.id, { ...conflicting, publicKey: world.wallets[1].publicKeyB64Url });
    }
    const result = runDrill({ world, archiveText: built.archiveText, liveDb });
    expect(result.phase0Accepted).toBe(false);
    expect(result.abortReasons.some((reason) => reason.startsWith("cross-node"))).toBe(true);
    expectZeroStampWrites(result, liveDb);
  });

  it("drill 7 — stale-version (key_version AAD mismatch mid-rotation): open fails closed", () => {
    const key = walletKeyFromSeedByte(0x22);
    const sealAad = {
      nodeId: NODE_ID,
      walletId: WALLET_DEFS[0].id,
      keyVersion: "1",
      publicKey: key.publicKeyB64Url,
      keyOrigin: "node_generated" as const,
    };
    const dekV1 = deriveWalletDek(ROOT_EPOCH_1, { nodeId: NODE_ID, walletId: WALLET_DEFS[0].id, keyVersion: "1" });
    const envelope = sealWalletSecret(dekV1, sealAad, key.secret64, new Uint8Array(12).fill(0x0a));
    // Attempting to open at the rotated key_version 2 (stale archive presented post-rotation) changes
    // BOTH the DEK and the AAD → GCM authentication fails closed.
    const dekV2 = deriveWalletDek(ROOT_EPOCH_1, { nodeId: NODE_ID, walletId: WALLET_DEFS[0].id, keyVersion: "2" });
    const staleAad = { ...sealAad, keyVersion: "2" };
    expect(() => openWalletSecret(dekV2, staleAad, envelope)).toThrow(/GCM authentication failed/);
    expect(() => openWalletSecret(dekV1, staleAad, envelope)).toThrow(/GCM authentication failed/);
  });

  it("drill 8 — rotation-boundary (crash mid-rewrap): the partially-rewrapped wallet fails closed, others stamp, per-wallet isolation", () => {
    const world = buildDrillWorld();
    // Simulate a crash mid-rewrap: wallet 2's vault got rewrapped to the epoch-2 root before the
    // crash, but the archive manifest still declares key_version 1 / epoch-1. Rebuild its envelope
    // and vault row under ROOT_EPOCH_2 so the archive is internally signed yet epoch-divergent.
    const target = world.wallets[1];
    const dek2 = deriveWalletDek(ROOT_EPOCH_2, { nodeId: NODE_ID, walletId: target.def.id, keyVersion: String(KEY_VERSION) });
    const resealed = sealWalletSecret(
      dek2,
      {
        nodeId: NODE_ID,
        walletId: target.def.id,
        keyVersion: String(KEY_VERSION),
        publicKey: target.publicKeyB64Url,
        keyOrigin: "node_generated",
      },
      target.secret64,
      new Uint8Array(12).fill(0x0b),
    );
    (target as { envelope: typeof resealed }).envelope = resealed;
    target.vaultRow.ciphertext = encodeBase64Url(resealed.ciphertext);
    target.vaultRow.nonce = encodeBase64Url(resealed.nonce);
    target.vaultRow.auth_tag = encodeBase64Url(resealed.authTag);
    target.vaultRow.ciphertext_sha256 = resealed.ciphertextSha256;

    const built = buildArchive(world);
    expect(verifyArchive(built.archiveText).ok).toBe(true); // archive still verifies (signatures intact)
    const liveDb = buildLiveDb(world);
    // Current-key possession reads the first live vault row (wallet 1, still epoch-1) and opens it
    // under the epoch-1 root — that gate passes. The divergence is isolated to wallet 2's ARCHIVE
    // envelope (rewrapped to epoch-2 mid-rotation), which fails closed when the per-wallet proof
    // opens it under the epoch-1 archive root.
    const result = runDrill({ world, archiveText: built.archiveText, liveDb });

    expect(result.outcomes[target.def.id]).toBe("failed_closed"); // archive-epoch open fails GCM
    expect(result.outcomes[world.wallets[0].def.id]).toBe("stamped");
    expect(result.outcomes[world.wallets[2].def.id]).toBe("stamped");
    expect(countStampWrites(result.ledger)).toBe(2);
    // Per-wallet isolation: the failed wallet has NO ledger writes at all.
    expect(result.ledger.filter((entry) => entry.walletId === target.def.id)).toHaveLength(0);
    expect(liveDb.wallets.get(target.def.id)?.recoveryVerifiedAt).toBeNull();
  });

  it("adversarial 9 — current-key-lost on a valid prior-epoch archive: gate MUST NOT stamp", () => {
    const world = buildDrillWorld(); // a perfectly valid epoch-1 archive
    const built = buildArchive(world);
    expect(verifyArchive(built.archiveText).ok).toBe(true);
    const liveDb = buildLiveDb(world);
    const result = runDrill({
      world,
      archiveText: built.archiveText,
      liveDb,
      archiveEpochRoot: ROOT_EPOCH_1,
      currentEpochRoot: ROOT_WRONG, // the current epoch key is lost
    });
    expect(result.phase0Accepted).toBe(true); // archive itself is fine
    expect(result.abortReasons.some((reason) => reason.includes("current-key possession"))).toBe(true);
    expectZeroStampWrites(result, liveDb);
  });

  it("adversarial 10 — wrong-node archive: cross-node rejection aborts phase 0, nothing stamps", () => {
    const world = buildDrillWorld();
    const built = buildArchive(world); // manifest.node_id === NODE_ID
    const liveDb = buildLiveDb(world);
    (liveDb as { nodeId: string }).nodeId = "99999999-9999-4999-8999-999999999999"; // a different node
    const result = runDrill({ world, archiveText: built.archiveText, liveDb });
    expect(result.phase0Accepted).toBe(false);
    expect(result.abortReasons.some((reason) => reason.startsWith("cross-node"))).toBe(true);
    expectZeroStampWrites(result, liveDb);
  });

  it("adversarial 11 — replayed ceremony: an already-stamped wallet is an idempotent skip, never a double stamp", () => {
    const world = buildDrillWorld();
    const built = buildArchive(world);
    const liveDb = buildLiveDb(world);
    const first = runDrill({ world, archiveText: built.archiveText, liveDb });
    expect(countStampWrites(first.ledger)).toBe(3);

    const replay = runDrill({ world, archiveText: built.archiveText, liveDb });
    for (const wallet of world.wallets) expect(replay.outcomes[wallet.def.id]).toBe("skipped");
    expect(countStampWrites(replay.ledger)).toBe(0); // ZERO new stamps on replay
    expect(countEvidenceWrites(replay.ledger)).toBe(0);
    // The original stamp survives the replay unchanged.
    for (const wallet of world.wallets) {
      expect(liveDb.wallets.get(wallet.def.id)?.recoveryVerifiedAt).toBe(EXPORTED_AT);
    }
  });

  it("adversarial 12 — post-stamp corruption never clears an existing stamp", () => {
    const world = buildDrillWorld();
    const built = buildArchive(world);
    const liveDb = buildLiveDb(world);
    const first = runDrill({ world, archiveText: built.archiveText, liveDb });
    expect(countStampWrites(first.ledger)).toBe(3);
    const stampedAt = liveDb.wallets.get(world.wallets[0].def.id)?.recoveryVerifiedAt;
    expect(stampedAt).toBe(EXPORTED_AT);

    // Corrupt the archived proof signature AFTER the stamp: swap wallet 1's signature with wallet 2's
    // (valid base64url, but verifies against the wrong wallet/preimage). The archive must now fail
    // verification, and re-running the ceremony must NOT clear or overwrite the existing stamp.
    const archive = JSON.parse(built.archiveText) as Record<string, unknown>;
    const sections = archive.wallet_sections as Record<string, unknown>[];
    const firstSig = sections[0].export_proof_signature;
    sections[0].export_proof_signature = sections[1].export_proof_signature;
    sections[1].export_proof_signature = firstSig;
    const corruptText = JSON.stringify(archive);
    expect(verifyArchive(corruptText).ok).toBe(false);

    const rerun = runDrill({ world, archiveText: corruptText, liveDb });
    expect(rerun.phase0Accepted).toBe(false);
    expect(countStampWrites(rerun.ledger)).toBe(0);
    // The stamp is never cleared by a later corrupt archive.
    expect(liveDb.wallets.get(world.wallets[0].def.id)?.recoveryVerifiedAt).toBe(stampedAt);
  });
});

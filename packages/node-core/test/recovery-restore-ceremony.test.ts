import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createHash, generateKeyPairSync, sign as nodeSign, type KeyObject } from "node:crypto";
import { Buffer } from "node:buffer";
import { describe, expect, it, vi } from "vitest";

import {
  buildBackupArchive,
  type BackupArchive,
  type BackupEvidenceRow,
  type BackupSnapshot,
} from "../src/core/backup/index.js";
import {
  RECOVERY_VERIFICATION_PURPOSE,
  buildRecoveryProbePayload,
  buildRecoveryProbePreimageText,
  runRestoreRecoveryCeremony,
  type RecoveryLiveDatabase,
  type RecoveryStampInput,
  type RecoveryWalletRow,
  type RestoreCeremonyResult,
  type RestoredInstance,
  type RestoredVaultAccess,
} from "../src/core/recovery/index.js";
import type { ActiveLeaseRecord } from "../src/core/signer-boundary.js";

const NODE_ID = "00000000-0000-4000-8000-000000000001";
const EXPORT_ID = "00000000-0000-4000-8000-000000000002";
const WALLET_A = "00000000-0000-4000-8000-00000000000a";
const WALLET_B = "00000000-0000-4000-8000-00000000000b";
const CEREMONY_ID = "00000000-0000-4000-8000-0000000000c1";
const CEREMONY_NONCE = "d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3c=";
const ISSUED_AT = "2026-07-20T01:00:00.000Z";
const VERIFIER = "operator:node-local-admin";

function b64url(bytes: Uint8Array): string {
  const unpadded = Buffer.from(bytes).toString("base64url");
  return unpadded + "=".repeat((4 - (unpadded.length % 4)) % 4);
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

interface KeyPair {
  readonly publicKey: string;
  readonly privateKey: KeyObject;
}

function makeKeyPair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  return { publicKey: b64url(new Uint8Array(spki.subarray(spki.length - 32))), privateKey };
}

function makeVaultRow(walletId: string) {
  const ciphertext = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  return {
    wallet_id: walletId,
    key_version: 1,
    ciphertext: b64url(ciphertext),
    nonce: b64url(new Uint8Array([9, 10, 11, 12])),
    auth_tag: b64url(new Uint8Array([13, 14, 15, 16])),
    ciphertext_sha256: sha256Hex(ciphertext),
    created_at: "2026-01-01T00:00:00.000Z",
    rotated_at: null,
  };
}

function makeArchive(keys: ReadonlyMap<string, KeyPair>): {
  archiveJson: string;
  archive: BackupArchive;
} {
  const identity = makeKeyPair();
  const walletRows: BackupEvidenceRow[] = [...keys.entries()].map(([walletId, key]) => ({
    id: walletId,
    wallet_id: walletId,
    public_key: key.publicKey,
    key_origin: "node_generated",
    key_version: 1,
  }));

  const snapshot: BackupSnapshot = {
    nodeId: NODE_ID,
    exportId: EXPORT_ID,
    exportedAt: "2026-07-19T00:00:00.000Z",
    wallets: [...keys.entries()].map(([walletId, key]) => ({
      walletId,
      publicKey: key.publicKey,
      keyOrigin: "node_generated",
      keyVersion: 1,
      vault: makeVaultRow(walletId),
      signer: {
        sign: (preimageBytes: Uint8Array) =>
          new Uint8Array(nodeSign(null, Buffer.from(preimageBytes), key.privateKey)),
      },
    })),
    nodeSigningKeys: [
      {
        signingKeyId: "00000000-0000-4000-8000-0000000000aa",
        purpose: "node_identity",
        publicKey: identity.publicKey,
        vaultSecretRef: "sealed-store/node-identity",
        sealedCiphertextSha256: sha256Hex(new Uint8Array([42])),
      },
    ],
    evidenceTables: [
      { table: "wallets", primaryKey: [{ column: "id", kind: "uuid" }], rows: walletRows },
    ],
    settingsValues: { network: "splitchain" },
    identitySigner: {
      sign: (preimageBytes: Uint8Array) =>
        new Uint8Array(nodeSign(null, Buffer.from(preimageBytes), identity.privateKey)),
    },
  };
  return buildBackupArchive(snapshot);
}

interface WorldOverrides {
  /** Drop one restored `wallets` row to simulate a partial restore. */
  readonly dropRestoredWallet?: string;
  /** Under-report one covered table's restored row count. */
  readonly shortTable?: string;
  /** Leave an active lease behind on the restored instance. */
  readonly restoredActiveLeases?: number;
  /** Force a per-wallet open failure. */
  readonly unopenableWallet?: string;
  /** Corrupt the restored `wallets.public_key` for one wallet as the restore lands. */
  readonly tamperedRestoredWallet?: string;
  /** Corrupt one restored row only AFTER the completeness audit read it (item 2). */
  readonly tamperedAfterAuditWallet?: string;
  readonly currentKeyHeld?: boolean;
  readonly alreadyVerified?: ReadonlySet<string>;
  /**
   * Live wallets that already carry recovery_verified_at (any prior export).
   * Distinct from alreadyVerified (same export_sha256 evidence row): a fresh ceremony
   * export must skip these without hard-failing the stamp UPDATE.
   */
  readonly alreadyStampedLive?: ReadonlySet<string>;
  /** Extra live wallets absent from the manifest (born-blocked census). */
  readonly extraLiveWallets?: readonly string[];
  readonly liveNodeId?: string;
  /** Release the restored lease so the signer boundary rejects the probe. */
  readonly releasedLeaseWallet?: string;
}

function makeWorld(overrides: WorldOverrides = {}) {
  const keys = new Map<string, KeyPair>([
    [WALLET_A, makeKeyPair()],
    [WALLET_B, makeKeyPair()],
  ]);
  const { archiveJson, archive } = makeArchive(keys);

  const preStamped = overrides.alreadyStampedLive ?? new Set<string>();
  const liveWallets = new Map<string, RecoveryWalletRow>(
    [...keys.entries()].map(([walletId, key]) => [
      walletId,
      {
        walletId,
        publicKey: key.publicKey,
        recoveryVerifiedAt: preStamped.has(walletId) ? ISSUED_AT : null,
      },
    ]),
  );
  for (const extra of overrides.extraLiveWallets ?? []) {
    liveWallets.set(extra, {
      walletId: extra,
      publicKey: b64url(new Uint8Array(32)),
      recoveryVerifiedAt: preStamped.has(extra) ? ISSUED_AT : null,
    });
  }

  const restoredWallets = new Map<string, RecoveryWalletRow>();
  const walletReads = new Map<string, number>();
  const leases = new Map<string, ActiveLeaseRecord>();
  const stamps: RecoveryStampInput[] = [];
  const summaries: unknown[] = [];
  let concurrentLeases = 0;
  let maxConcurrentLeases = 0;

  const restoredInstance: RestoredInstance = {
    restore: vi.fn(async (restoredArchive: BackupArchive) => {
      for (const section of restoredArchive.wallet_sections) {
        if (section.wallet_id === overrides.dropRestoredWallet) continue;
        restoredWallets.set(section.wallet_id, {
          walletId: section.wallet_id,
          publicKey:
            section.wallet_id === overrides.tamperedRestoredWallet
              ? b64url(new Uint8Array(32))
              : section.public_key,
          recoveryVerifiedAt: null,
        });
      }
    }),
    readRestoredRowCounts: vi.fn(async () => {
      const counts = new Map<string, number>(
        archive.evidence_sections.map((section) => [section.table, section.rows.length]),
      );
      if (overrides.shortTable !== undefined) {
        counts.set(overrides.shortTable, (counts.get(overrides.shortTable) ?? 1) - 1);
      }
      return counts;
    }),
    countActiveLeases: vi.fn(async () => overrides.restoredActiveLeases ?? 0),
    readWallet: vi.fn(async (walletId: string) => {
      const reads = (walletReads.get(walletId) ?? 0) + 1;
      walletReads.set(walletId, reads);
      const row = restoredWallets.get(walletId) ?? null;
      // The completeness audit reads each wallet once; corrupt the row only afterwards.
      if (row !== null && walletId === overrides.tamperedAfterAuditWallet && reads > 1) {
        return { ...row, publicKey: b64url(new Uint8Array(32)) };
      }
      return row;
    }),
    acquireReconciliationLease: vi.fn(async (walletId: string) => {
      concurrentLeases += 1;
      maxConcurrentLeases = Math.max(maxConcurrentLeases, concurrentLeases);
      const lease: ActiveLeaseRecord = {
        walletId,
        operationId: `recovery-${walletId}`,
        epoch: 1n,
        role: "RECONCILIATION",
        lifecycle: walletId === overrides.releasedLeaseWallet ? "RELEASED" : "ACTIVE",
      };
      leases.set(walletId, lease);
      return lease;
    }),
    releaseReconciliationLease: vi.fn(async (walletId: string) => {
      concurrentLeases -= 1;
      leases.delete(walletId);
    }),
    readActiveLease: vi.fn(async (walletId: string) => leases.get(walletId) ?? null),
    destroy: vi.fn(async () => {}),
  };

  const restoredVault: RestoredVaultAccess = {
    openAndDerivePublicKey: vi.fn(async (walletId: string) =>
      walletId === overrides.unopenableWallet ? null : (keys.get(walletId)?.publicKey ?? null),
    ),
    sign: vi.fn(async (walletId: string, preimageBytes: Uint8Array) => {
      const key = keys.get(walletId);
      if (key === undefined) throw new Error("no restored key");
      return b64url(new Uint8Array(nodeSign(null, Buffer.from(preimageBytes), key.privateKey)));
    }),
  };

  const liveDatabase: RecoveryLiveDatabase = {
    readWallets: vi.fn(async () => liveWallets),
    proveCurrentKeyPossession: vi.fn(async () => overrides.currentKeyHeld ?? true),
    hasRecoveryVerification: vi.fn(async (walletId: string) =>
      (overrides.alreadyVerified ?? new Set<string>()).has(walletId),
    ),
    stampRecoveryVerification: vi.fn(async (input: RecoveryStampInput) => {
      stamps.push(input);
      const live = liveWallets.get(input.walletId);
      if (live !== undefined) {
        liveWallets.set(input.walletId, { ...live, recoveryVerifiedAt: ISSUED_AT });
      }
    }),
    appendCeremonySummary: vi.fn(async (summary) => {
      summaries.push(summary);
    }),
  };

  const run = (): Promise<RestoreCeremonyResult> =>
    runRestoreRecoveryCeremony({
      ceremonyId: CEREMONY_ID,
      ceremonyNonce: CEREMONY_NONCE,
      issuedAt: ISSUED_AT,
      verifierIdentity: VERIFIER,
      liveNodeId: overrides.liveNodeId ?? NODE_ID,
      archiveText: archiveJson,
      restoredInstance,
      restoredVault,
      liveDatabase,
    });

  return {
    keys,
    archive,
    archiveJson,
    liveWallets,
    restoredInstance,
    restoredVault,
    liveDatabase,
    stamps,
    summaries,
    run,
    maxConcurrentLeases: () => maxConcurrentLeases,
  };
}

describe("fresh probe payload", () => {
  it("emits the committed golden preimage byte-for-byte", () => {
    const goldenPath = fileURLToPath(
      new URL(
        "../../generic-node-contracts/goldens/recovery/zp-recovery-verification-v1.preimage.txt",
        import.meta.url,
      ),
    );
    const golden = readFileSync(goldenPath, "utf8");
    const meta = JSON.parse(
      readFileSync(
        fileURLToPath(
          new URL(
            "../../generic-node-contracts/goldens/recovery/zp-recovery-verification-v1.meta.json",
            import.meta.url,
          ),
        ),
        "utf8",
      ),
    ) as { wallet_id: string; wallet_public_key_b64: string; chained_export_digest: string };

    const preimage = buildRecoveryProbePreimageText(
      buildRecoveryProbePayload({
        nodeId: "11111111-1111-4111-8111-111111111111",
        walletId: meta.wallet_id,
        publicKey: meta.wallet_public_key_b64,
        keyVersion: 1,
        exportId: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        exportSha256: meta.chained_export_digest,
        ceremonyId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        ceremonyNonce: CEREMONY_NONCE,
        issuedAt: ISSUED_AT,
      }),
    );

    expect(preimage).toBe(golden);
    expect(preimage.split("\n", 1)[0]).toBe(RECOVERY_VERIFICATION_PURPOSE);
  });
});

describe("restore and recovery-verification ceremony", () => {
  it("stamps every proven wallet and writes one ceremony summary", async () => {
    const world = makeWorld();
    const result = await world.run();

    expect(result.accepted).toBe(true);
    expect(result.abortReasons).toEqual([]);
    expect([...result.outcomes.values()]).toEqual(["stamped", "stamped"]);
    expect(world.stamps.map((stamp) => stamp.walletId)).toEqual([WALLET_A, WALLET_B]);
    expect(world.stamps.every((stamp) => stamp.method === "AUDITED_EXPORT")).toBe(true);
    expect(world.summaries).toHaveLength(1);
    expect(result.summaryWritten).toBe(true);
    expect(result.instanceDestroyed).toBe(true);
    expect(world.restoredInstance.destroy).toHaveBeenCalledTimes(1);
    // Phase 2: one wallet at a time, never two leases concurrently.
    expect(world.maxConcurrentLeases()).toBe(1);
    // restore creates no active lease rows.
    expect(result.restoredActiveLeaseCount).toBe(0);
  });

  it("stamps only public material — no key-derived value reaches the evidence row", async () => {
    const world = makeWorld();
    await world.run();

    const stamp = world.stamps[0]!;
    expect(stamp.publicKey).toBe(world.keys.get(WALLET_A)!.publicKey);
    expect(stamp.exportSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(stamp.verifierIdentity).toBe(VERIFIER);
    expect(Object.values(stamp).every((value) => typeof value !== "object")).toBe(true);
  });

  it("routes the probe through the production signer boundary's lease re-read", async () => {
    const world = makeWorld();
    await world.run();

    // The boundary re-reads the current lease before the seam decrypts, once per probe.
    expect(world.restoredInstance.readActiveLease).toHaveBeenCalledTimes(4);
    expect(world.restoredVault.sign).toHaveBeenCalledTimes(2);
  });

  it("fails a wallet closed when its restored lease is not ACTIVE", async () => {
    const world = makeWorld({ releasedLeaseWallet: WALLET_A });
    const result = await world.run();

    expect(result.outcomes.get(WALLET_A)).toBe("failed_closed");
    expect(result.outcomes.get(WALLET_B)).toBe("stamped");
    expect(world.stamps.map((stamp) => stamp.walletId)).toEqual([WALLET_B]);
  });

  it("aborts with zero stamps when the archive fails acceptance", async () => {
    const world = makeWorld();
    const tampered = world.archiveJson.replace('"format":"zp-node-backup-v1"', '"format":"zp-node-backup-v2"');
    const result = await runRestoreRecoveryCeremony({
      ceremonyId: CEREMONY_ID,
      ceremonyNonce: CEREMONY_NONCE,
      issuedAt: ISSUED_AT,
      verifierIdentity: VERIFIER,
      liveNodeId: NODE_ID,
      archiveText: tampered,
      restoredInstance: world.restoredInstance,
      restoredVault: world.restoredVault,
      liveDatabase: world.liveDatabase,
    });

    expect(result.accepted).toBe(false);
    expect(result.abortReasons).toEqual(["archive_rejected"]);
    expect(result.archiveRejectionReasons.length).toBeGreaterThan(0);
    expect(world.stamps).toEqual([]);
    expect(world.summaries).toEqual([]);
    expect(world.restoredInstance.restore).not.toHaveBeenCalled();
    // The instance is secret-class: it is destroyed on every exit path, aborts included.
    expect(world.restoredInstance.destroy).toHaveBeenCalledTimes(1);
    expect(result.instanceDestroyed).toBe(true);
  });

  it("aborts with zero stamps when the archive belongs to another node", async () => {
    const world = makeWorld({ liveNodeId: "00000000-0000-4000-8000-0000000000ff" });
    const result = await world.run();

    expect(result.abortReasons).toEqual(["cross_node_mismatch"]);
    expect(world.stamps).toEqual([]);
    expect(world.restoredInstance.restore).not.toHaveBeenCalled();
  });

  it("aborts with zero stamps when the restore is incomplete — a short table", async () => {
    const world = makeWorld({ shortTable: "wallets" });
    const result = await world.run();

    expect(result.abortReasons).toEqual(["restore_incomplete"]);
    expect(result.restoreComplete).toBe(false);
    expect(world.stamps).toEqual([]);
    expect(world.summaries).toEqual([]);
  });

  it("aborts with zero stamps when a covered wallet row never lands", async () => {
    const world = makeWorld({ dropRestoredWallet: WALLET_B });
    const result = await world.run();

    expect(result.abortReasons).toEqual(["restore_incomplete"]);
    expect(world.stamps).toEqual([]);
  });

  it("aborts when the restore leaves an active lease behind", async () => {
    const world = makeWorld({ restoredActiveLeases: 1 });
    const result = await world.run();

    expect(result.abortReasons).toEqual(["restored_active_lease_present"]);
    expect(world.stamps).toEqual([]);
  });

  it("aborts with zero stamps when current-key possession cannot be proven", async () => {
    const world = makeWorld({ currentKeyHeld: false });
    const result = await world.run();

    expect(result.abortReasons).toEqual(["current_key_possession_failed"]);
    expect(result.restoreComplete).toBe(true);
    expect(world.stamps).toEqual([]);
  });

  it("fails one wallet closed and leaves its siblings unaffected", async () => {
    const world = makeWorld({ unopenableWallet: WALLET_A });
    const result = await world.run();

    expect(result.accepted).toBe(true);
    expect(result.outcomes.get(WALLET_A)).toBe("failed_closed");
    expect(result.outcomes.get(WALLET_B)).toBe("stamped");
    expect(world.stamps.map((stamp) => stamp.walletId)).toEqual([WALLET_B]);
  });

  it("aborts when the restore reproduces a wallet row with the wrong public key", async () => {
    // Corruption present when the restore lands is a completeness failure, not a per-wallet
    // one: the instance does not reproduce the archive, so nothing is stamped from it.
    const world = makeWorld({ tamperedRestoredWallet: WALLET_B });
    const result = await world.run();

    expect(result.abortReasons).toEqual(["restore_incomplete"]);
    expect(world.stamps).toEqual([]);
  });

  it("fails a wallet closed when its restored row is corrupted after the audit", async () => {
    // item 2 — corruption introduced POST-restore fails that wallet's census closed and
    // leaves siblings unaffected.
    const world = makeWorld({ tamperedAfterAuditWallet: WALLET_B });
    const result = await world.run();

    expect(result.accepted).toBe(true);
    expect(result.outcomes.get(WALLET_B)).toBe("failed_closed");
    expect(world.stamps.map((stamp) => stamp.walletId)).toEqual([WALLET_A]);
  });

  it("skips a wallet already verified against the same export digest", async () => {
    const world = makeWorld({ alreadyVerified: new Set([WALLET_A]) });
    const result = await world.run();

    expect(result.outcomes.get(WALLET_A)).toBe("skipped");
    expect(result.outcomes.get(WALLET_B)).toBe("stamped");
    expect(world.stamps.map((stamp) => stamp.walletId)).toEqual([WALLET_B]);
  });

  it("skips a live-stamped wallet on a fresh export so unstamped siblings can still stamp", async () => {
    // Partial first ceremony: A stamped under export E1; B failed_closed / unstamped.
    // Second ceremony builds export E2 (new export_sha256). hasRecoveryVerification(A, E2)
    // is false, but A.recovery_verified_at is set — must skip A, not throw on stamp UPDATE.
    const world = makeWorld({ alreadyStampedLive: new Set([WALLET_A]) });
    const result = await world.run();

    expect(result.accepted).toBe(true);
    expect(result.outcomes.get(WALLET_A)).toBe("skipped");
    expect(result.outcomes.get(WALLET_B)).toBe("stamped");
    expect(world.stamps.map((stamp) => stamp.walletId)).toEqual([WALLET_B]);
    expect(world.liveDatabase.stampRecoveryVerification).not.toHaveBeenCalledWith(
      expect.objectContaining({ walletId: WALLET_A }),
    );
  });

  it("reports live wallets absent from the manifest as born-blocked, never stamped", async () => {
    const orphan = "00000000-0000-4000-8000-00000000000f";
    const world = makeWorld({ extraLiveWallets: [orphan] });
    const result = await world.run();

    expect(result.bornBlocked).toEqual([orphan]);
    expect(world.stamps.some((stamp) => stamp.walletId === orphan)).toBe(false);
  });
});

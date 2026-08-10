// Fault-inject rotation and rollback.
//
// Acceptance criteria:
//   1. WALLET_VAULT mid-row crash injection → whole rotation rolls back; OLD-key only.
//      DEFERRED stores (no seal-write runtime): named once — no per-store row
//      injection until rows exist; dry-run (AC5) reports their deferred status.
//   2. Wrong-key refusals (old===new, under-length new, wrong OLD) → zero DB mutation.
//   3. Omitted-store detection → census check fails red when a registry entry is removed.
//   4. Race signer/backup → refuse while interlock held, proceed once released;
//      same exclusion for concurrent backup/export stub.
//   5. Dry run → correct per-store counts, committed:false, ciphertext byte-identical.
//   6. Restore pre/post rotation → identical public key + secret digest under NEW.
//      recovery_verified_at monotonicity is DEFERRED (no durable stamp on rotation path).
//   7. No mixed readable state after any induced abort — including post-vaultDurable
//      (commit+uow ok, journal.complete throws → NEW-only durable rows).
//
// Depends on rotateMasterKey + journal + interlock + UoW.
//
// Synthetic keys only.

import { afterEach, describe, expect, it, vi } from "vitest";

import { SEALED_STORES } from "../src/schema/sealed-store-registry.contract.js";
import * as vaultBarrel from "../src/vault/index.js";
import type { WalletVaultRewrapRow } from "../src/vault/index.js";

import {
  FROM_EPOCH,
  NEW_ROOT,
  OLD_ROOT,
  REGISTERED_STORE_IDS,
  TO_EPOCH,
  WRONG_ROOT,
  asRotationApi,
  assertNoMixedReadableState,
  auditedRecoveryExport,
  buildExportDigest,
  censusPorts,
  envelopeFingerprint,
  exportUnderInterlock,
  makeKeyRing,
  makeRow,
  registrySnapshot,
  type MasterKeyRotationJournalLike,
  type RotationPublicApi,
  type WalletFixture,
} from "./master-key-rotation.fault-inject.harness.js";

const api: RotationPublicApi | null = asRotationApi(vaultBarrel as unknown as Record<string, unknown>);
const describeIfApi = api !== null ? describe : describe.skip;

if (api === null) {
  describe("fault-inject (blocked on)", () => {
    it("self-skips until rotateMasterKey lands on the vault barrel", () => {
      expect(api).toBeNull();
      // Document the import path that will resolve once 217 merges:
      //   import { rotateMasterKey, ... } from "../src/vault/index.js"
      expect(typeof (vaultBarrel as { rotateMasterKey?: unknown }).rotateMasterKey).toBe(
        "undefined",
      );
    });
  });
}

describeIfApi("fault-inject rotation and rollback", () => {
  // Non-null assertion safe: describeIfApi only runs when api is loaded.
  const rot = api!;

  afterEach(() => {
    rot.InMemoryRotationUnitOfWork.resetGlobalHolder();
  });

  function baseInput(fixtures: readonly WalletFixture[], overrides: Record<string, unknown> = {}) {
    const rows = fixtures.map((f) => f.row);
    const journal = new rot.InMemoryMasterKeyRotationJournal(FROM_EPOCH);
    const interlock = new rot.ProcessLocalMasterKeyRotationInterlock();
    const uow = new rot.InMemoryRotationUnitOfWork();
    const committed: { rows: readonly WalletVaultRewrapRow[] | null } = { rows: null };
    return {
      journal,
      interlock,
      uow,
      committed,
      input: {
        sealedStores: registrySnapshot(),
        ...censusPorts(rows),
        keyRing: makeKeyRing(rot),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: OLD_ROOT,
        newRootKey: NEW_ROOT,
        journal,
        interlock,
        commitWalletVault: async (rewrapped: readonly WalletVaultRewrapRow[]) => {
          committed.rows = rewrapped;
        },
        unitOfWork: uow,
        ...overrides,
      },
    };
  }

  // ── AC1: WALLET mid-row crash + honest DEFERRED note ───────────────────────

  describe("AC1 — mid-row crash rolls the whole rotation back (WALLET_VAULT)", () => {
    /**
     * Only WALLET_VAULT is IMPLEMENTED. Mid-population corrupt auth-tag /
     * ciphertext forces the rewrap loop to throw after earlier rows are handled
     * in-memory; the whole unit must roll back with zero commit and OLD-only siblings.
     *
     * DEFERRED stores have no seal-write runtime and no fixture rows — per-store
     * mid-row injection is DEFERRED until those exist. Their deferred status is
     * observed via dry-run reports (AC5), not a vacuous per-id crash loop.
     */
    it("WALLET_VAULT mid-population corrupt authTag: abort, zero commit, OLD-only siblings", async () => {
      // N=5 so "mid-population" is neither first nor last under canonical wallet-id order.
      const fixtures = [1, 2, 3, 4, 5].map((n) => makeRow(0xa0 + n, n));
      const midIndex = 2; // wallet ordinal 3 — middle of sorted set
      const rows: WalletVaultRewrapRow[] = fixtures.map((f, i) => {
        if (i !== midIndex) return f.row;
        return {
          ...f.row,
          envelope: {
            ...f.row.envelope,
            authTag: Buffer.alloc(f.row.envelope.authTag.length, 0x7f),
          },
        };
      });

      const journal = new rot.InMemoryMasterKeyRotationJournal(FROM_EPOCH);
      const interlock = new rot.ProcessLocalMasterKeyRotationInterlock();
      const uow = new rot.InMemoryRotationUnitOfWork();
      const commit = vi.fn(async () => {
        throw new Error("commit must not run after abort");
      });

      await expect(
        rot.rotateMasterKey({
          sealedStores: registrySnapshot(),
          ...censusPorts(rows),
          keyRing: makeKeyRing(rot),
          fromEpoch: FROM_EPOCH,
          toEpoch: TO_EPOCH,
          oldRootKey: OLD_ROOT,
          newRootKey: NEW_ROOT,
          journal,
          interlock,
          commitWalletVault: commit,
          unitOfWork: uow,
        }),
      ).rejects.toMatchObject({
        code: expect.stringMatching(/ROTATION_ABORTED|ROTATION_REFUSED/),
      });

      expect(commit).not.toHaveBeenCalled();
      expect(uow.commits).toBe(0);
      expect((await journal.read()).writerEpoch).toBe(FROM_EPOCH);
      expect((await journal.read()).phase).toBe("STABLE");
      assertNoMixedReadableState(
        fixtures.filter((_, i) => i !== midIndex).map((f) => f.row),
        "old",
      );
    });

    it("WALLET_VAULT mid-population corrupt ciphertext: earlier in-memory rewraps do not leak to commit", async () => {
      const fixtures = [1, 2, 3, 4, 5].map((n) => makeRow(0xb0 + n, n));
      // Canonical sort is by wallet id; ordinals 1..5 sort as written. Corrupt ordinal 3.
      const rows = fixtures.map((f, i) =>
        i === 2
          ? {
              ...f.row,
              envelope: {
                ...f.row.envelope,
                ciphertext: Buffer.alloc(f.row.envelope.ciphertext.length, 0),
              },
            }
          : f.row,
      );
      const { journal, uow, committed, input } = baseInput(fixtures, {
        ...censusPorts(rows),
        commitWalletVault: async (rewrapped: readonly WalletVaultRewrapRow[]) => {
          committed.rows = rewrapped;
        },
      });

      await expect(rot.rotateMasterKey(input)).rejects.toMatchObject({ code: "ROTATION_ABORTED" });
      expect(committed.rows).toBeNull();
      expect(uow.commits).toBe(0);
      expect((await journal.read()).writerEpoch).toBe(FROM_EPOCH);
      assertNoMixedReadableState(
        fixtures.filter((_, i) => i !== 2).map((f) => f.row),
        "old",
      );
    });

    it("DEFERRED stores : no seal-write rows to inject — post-WALLET abort still OLD-only once", async () => {
      // Single named case (not a per-id loop). DEFERRED ids have zero sealed fixture rows;
      // cross-store OLD-only for those stores is untestable until seal-write runtime exists.
      // Abort after successful WALLET rewrap via commitWalletVault throw; journal stays
      // FROM_EPOCH; WALLET fixtures remain OLD-only. DEFERRED status coverage is AC5.
      const fixtures = [1, 2, 3].map((n) => makeRow(0xa8 + n, n));
      const { journal, uow, committed, input } = baseInput(fixtures, {
        commitWalletVault: async () => {
          throw new Error("injected abort after WALLET rewrap (DEFERRED stores have no row loop)");
        },
      });

      await expect(rot.rotateMasterKey(input)).rejects.toMatchObject({ code: "ROTATION_ABORTED" });
      expect(committed.rows).toBeNull();
      expect(uow.commits).toBe(0);
      expect((await journal.read()).writerEpoch).toBe(FROM_EPOCH);
      expect((await journal.read()).phase).toBe("STABLE");
      assertNoMixedReadableState(
        fixtures.map((f) => f.row),
        "old",
      );
    });
  });

  // ── AC2: wrong-key refusals ────────────────────────────────────────────────

  describe("AC2 — wrong-key refusals before any row is touched", () => {
    it("refuses oldRoot === newRoot with zero mutation", async () => {
      const fixtures = [makeRow(0xc1, 1), makeRow(0xc2, 2)];
      const preFingerprints = fixtures.map((f) => envelopeFingerprint(f.row.envelope));
      const { journal, uow, committed, input } = baseInput(fixtures, {
        newRootKey: OLD_ROOT,
        keyRing: makeKeyRing(rot, { equalRoots: true }),
      });

      await expect(rot.rotateMasterKey(input)).rejects.toMatchObject({ code: "ROTATION_REFUSED" });
      expect(committed.rows).toBeNull();
      expect(uow.begins).toBe(0);
      expect((await journal.read()).writerEpoch).toBe(FROM_EPOCH);
      expect(fixtures.map((f) => envelopeFingerprint(f.row.envelope))).toEqual(preFingerprints);
      assertNoMixedReadableState(
        fixtures.map((f) => f.row),
        "old",
      );
    });

    it("refuses under-length (empty) new root with zero mutation", async () => {
      const fixtures = [makeRow(0xc3, 1)];
      const preFingerprints = fixtures.map((f) => envelopeFingerprint(f.row.envelope));
      const emptyNew = new Uint8Array(0);
      const { journal, uow, committed, input } = baseInput(fixtures, {
        newRootKey: emptyNew,
        // Key-ring must still be constructible for the call to reach validateEpochs;
        // build with a placeholder then override newRootKey to empty.
        keyRing: rot.buildKeyRing({
          writerEpoch: TO_EPOCH,
          writerRoot: NEW_ROOT,
          retained: [{ epoch: FROM_EPOCH, root: OLD_ROOT }],
        }),
      });

      await expect(rot.rotateMasterKey(input)).rejects.toMatchObject({ code: "ROTATION_REFUSED" });
      expect(committed.rows).toBeNull();
      expect(uow.begins).toBe(0);
      expect((await journal.read()).writerEpoch).toBe(FROM_EPOCH);
      expect(fixtures.map((f) => envelopeFingerprint(f.row.envelope))).toEqual(preFingerprints);
      assertNoMixedReadableState(
        fixtures.map((f) => f.row),
        "old",
      );
    });

    it("refuses wrong OLD root (pre-rotation recovery check fails) with zero mutation", async () => {
      const fixtures = [makeRow(0xc4, 1), makeRow(0xc5, 2), makeRow(0xc6, 3)];
      const preFingerprints = fixtures.map((f) => envelopeFingerprint(f.row.envelope));
      // Key-ring retains the WRONG old root → open under key-ring fails for every row.
      const { journal, uow, committed, input } = baseInput(fixtures, {
        oldRootKey: WRONG_ROOT,
        keyRing: makeKeyRing(rot, { wrongOld: true }),
      });

      await expect(rot.rotateMasterKey(input)).rejects.toMatchObject({
        code: expect.stringMatching(/ROTATION_ABORTED|ROTATION_REFUSED/),
      });
      expect(committed.rows).toBeNull();
      expect(uow.commits).toBe(0);
      expect((await journal.read()).writerEpoch).toBe(FROM_EPOCH);
      expect(fixtures.map((f) => envelopeFingerprint(f.row.envelope))).toEqual(preFingerprints);
      assertNoMixedReadableState(
        fixtures.map((f) => f.row),
        "old",
      );
    });
  });

  // ── AC3: omitted-store detection ───────────────────────────────────────────

  describe("AC3 — omitted-store detection (census is load-bearing)", () => {
    it("removing WALLET_VAULT from the registry fails red (REGISTRY_INCOMPLETE)", async () => {
      const fixtures = [makeRow(0xd1, 1)];
      const omitted = registrySnapshot().filter((s) => s.id !== "WALLET_VAULT");
      expect(omitted.map((s) => s.id)).not.toContain("WALLET_VAULT");

      const { journal, uow, committed, input } = baseInput(fixtures, {
        sealedStores: omitted,
      });

      await expect(rot.rotateMasterKey(input)).rejects.toMatchObject({
        code: "REGISTRY_INCOMPLETE",
      });
      expect(committed.rows).toBeNull();
      expect(uow.begins).toBe(0);
      expect((await journal.read()).writerEpoch).toBe(FROM_EPOCH);
      assertNoMixedReadableState(
        fixtures.map((f) => f.row),
        "old",
      );
    });

    it("full registry (re-added) proceeds — census green path", async () => {
      const fixtures = [makeRow(0xd2, 1), makeRow(0xd3, 2)];
      const { journal, committed, input } = baseInput(fixtures);
      // Explicit full set — every SEALED_STORES id present.
      expect(input.sealedStores.map((s: { id: string }) => s.id).sort()).toEqual(
        [...REGISTERED_STORE_IDS].sort(),
      );

      const result = await rot.rotateMasterKey(input);
      expect(result.committed).toBe(true);
      expect(committed.rows).not.toBeNull();
      expect((await journal.read()).writerEpoch).toBe(TO_EPOCH);
      assertNoMixedReadableState(committed.rows!, "new");
    });

    it("structural census: SEALED_STORE_IDS is the closed set the orchestrator must cover", () => {
      // Independent of rotateMasterKey — pins the registry the omitted-store test mutates.
      expect([...REGISTERED_STORE_IDS].sort()).toEqual(
        [
          "NODE_SIGNING_KEYS",
          "PUSH_RECEIVER_SECRETS",
          "SESSION_SECRETS",
          "TOTP_SECRET",
          "WALLET_VAULT",
        ].sort(),
      );
      const byId = Object.fromEntries(SEALED_STORES.map((s) => [s.id, s.rewrapStatus]));
      expect(byId.WALLET_VAULT).toBe("IMPLEMENTED");
      expect(byId.NODE_SIGNING_KEYS).toBe("IMPLEMENTED");
      expect(byId.PUSH_RECEIVER_SECRETS).toBe("IMPLEMENTED");
      expect(byId.TOTP_SECRET).toBe("IMPLEMENTED");
      expect(byId.SESSION_SECRETS).toBe("DEFERRED_NO_SEAL_RUNTIME");
    });

    it("omitting a DEFERRED store from the input registry is visible in the report set", async () => {
      // Drop SESSION_SECRETS — rotation may still commit (orchestrator iterates input list),
      // but the report must NOT claim it was covered. Callers that pass a truncated
      // registry are the hazard; the structural census (above) is what catches a missing
      // production seal site. This test documents the orchestrator's input-driven scope.
      const fixtures = [makeRow(0xd4, 1)];
      const truncated = registrySnapshot().filter((s) => s.id !== "SESSION_SECRETS");
      const { input } = baseInput(fixtures, { sealedStores: truncated });

      const result = await rot.rotateMasterKey(input);
      expect(result.committed).toBe(true);
      expect(result.stores.map((s) => s.storeId)).not.toContain("SESSION_SECRETS");
      // Re-add: full registry reports the deferred entry.
      const { input: fullInput } = baseInput([makeRow(0xd5, 2)]);
      const full = await rot.rotateMasterKey(fullInput);
      expect(full.stores.map((s) => s.storeId)).toContain("SESSION_SECRETS");
    });
  });

  // ── AC4: race signer / backup ──────────────────────────────────────────────

  describe("AC4 — race signer leadership lock + concurrent backup/export stub", () => {
    it("refuses rotation while a second holder holds the interlock; proceeds once released", async () => {
      const fixtures = [makeRow(0xe1, 1), makeRow(0xe2, 2)];
      const sharedInterlock = new rot.ProcessLocalMasterKeyRotationInterlock();

      // Second "instance" holds the process-wide interlock (signer leadership stand-in).
      await sharedInterlock.acquire();
      expect(sharedInterlock.held).toBe(true);

      const { journal, uow, committed, input } = baseInput(fixtures, {
        interlock: sharedInterlock,
      });

      await expect(rot.rotateMasterKey(input)).rejects.toMatchObject({ code: "ROTATION_REFUSED" });
      expect(committed.rows).toBeNull();
      expect(uow.begins).toBe(0);
      expect((await journal.read()).writerEpoch).toBe(FROM_EPOCH);
      assertNoMixedReadableState(
        fixtures.map((f) => f.row),
        "old",
      );

      // Release the foreign holder — rotation proceeds.
      await sharedInterlock.release();
      const {
        journal: j2,
        committed: c2,
        input: input2,
      } = baseInput(fixtures, { interlock: sharedInterlock });
      const result = await rot.rotateMasterKey(input2);
      expect(result.committed).toBe(true);
      expect(c2.rows).not.toBeNull();
      expect((await j2.read()).writerEpoch).toBe(TO_EPOCH);
      assertNoMixedReadableState(c2.rows!, "new");
    });

    it("signing admission is quiesced while rotation holds the interlock", async () => {
      const fixtures = [makeRow(0xe3, 1)];
      const interlock = new rot.ProcessLocalMasterKeyRotationInterlock();
      const uow = new rot.InMemoryRotationUnitOfWork();
      const journal = new rot.InMemoryMasterKeyRotationJournal(FROM_EPOCH);
      let sawQuiesced = false;

      await rot.rotateMasterKey({
        sealedStores: registrySnapshot(),
        ...censusPorts(fixtures.map((f) => f.row)),
        keyRing: makeKeyRing(rot),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: OLD_ROOT,
        newRootKey: NEW_ROOT,
        journal,
        interlock,
        unitOfWork: uow,
        commitWalletVault: async () => {
          // Mid-ceremony: signing must be refused.
          expect(interlock.held).toBe(true);
          expect(() => interlock.assertSigningAdmitted?.("signUnderLease")).toThrow(
            expect.objectContaining({ code: "SIGNING_QUIESCED" }),
          );
          sawQuiesced = true;
        },
      });

      expect(sawQuiesced).toBe(true);
      expect(interlock.held).toBe(false);
      // After release, admission is open again.
      expect(() => interlock.assertSigningAdmitted?.("signUnderLease")).not.toThrow();
    });

    it("concurrent backup/export stub refuses while rotation holds the interlock, proceeds after", async () => {
      // Exclusion point (implementer judgment, not built): ProcessLocalMasterKeyRotationInterlock.acquire.
      const fixtures = [makeRow(0xe4, 1), makeRow(0xe5, 2)];
      const interlock = new rot.ProcessLocalMasterKeyRotationInterlock();
      const uow = new rot.InMemoryRotationUnitOfWork();
      const journal = new rot.InMemoryMasterKeyRotationJournal(FROM_EPOCH);
      const exportAttempts: string[] = [];

      await rot.rotateMasterKey({
        sealedStores: registrySnapshot(),
        ...censusPorts(fixtures.map((f) => f.row)),
        keyRing: makeKeyRing(rot),
        fromEpoch: FROM_EPOCH,
        toEpoch: TO_EPOCH,
        oldRootKey: OLD_ROOT,
        newRootKey: NEW_ROOT,
        journal,
        interlock,
        unitOfWork: uow,
        commitWalletVault: async (rows: readonly WalletVaultRewrapRow[]) => {
          // Concurrent export while rotation holds the lock must refuse.
          await expect(
            exportUnderInterlock(interlock, () => buildExportDigest(fixtures)),
          ).rejects.toMatchObject({ code: "ROTATION_REFUSED" });
          exportAttempts.push("refused-during-hold");
          // Persist (in-memory) so ceremony completes.
          void rows;
        },
      });

      expect(exportAttempts).toEqual(["refused-during-hold"]);
      expect(interlock.held).toBe(false);

      // After release, export proceeds.
      const digest = await exportUnderInterlock(interlock, () =>
        buildExportDigest(
          // Post-rotation fixtures still carry OLD envelopes in the local array;
          // digest is over whatever ciphertext is present — just prove the gate opens.
          fixtures,
        ),
      );
      expect(digest).toMatch(/^[0-9a-f]{64}$/);
      exportAttempts.push("proceeded-after-release");
      expect(exportAttempts).toEqual(["refused-during-hold", "proceeded-after-release"]);
    });
  });

  // ── AC5: dry run ───────────────────────────────────────────────────────────

  describe("AC5 — dry run reports counts, committed:false, ciphertext byte-identical", () => {
    it("dry-run: per-store counts, committed:false, every ciphertext byte-identical", async () => {
      const fixtures = [1, 2, 3].map((n) => makeRow(0xf0 + n, n));
      const preFingerprints = fixtures.map((f) => envelopeFingerprint(f.row.envelope));
      const commit = vi.fn(async () => {
        throw new Error("commit must not run on dry-run");
      });
      const { journal, uow, input } = baseInput(fixtures, {
        dryRun: true,
        commitWalletVault: commit,
      });

      const result = await rot.rotateMasterKey(input);

      expect(result.committed).toBe(false);
      expect(result.dryRun).toBe(true);
      expect(result.walletCount).toBe(3);

      const vaultReport = result.stores.find((s) => s.storeId === "WALLET_VAULT");
      expect(vaultReport?.status).toBe("REWRAPPED");
      expect(vaultReport?.result).toEqual({ rowsBefore: 3, rowsAfter: 3, rewrapped: 3 });

      // DEFERRED stores report null; signing/push/totp stores are IMPLEMENTED (empty censuses).
      for (const id of REGISTERED_STORE_IDS) {
        if (
          id === "WALLET_VAULT" ||
          id === "NODE_SIGNING_KEYS" ||
          id === "PUSH_RECEIVER_SECRETS" ||
          id === "TOTP_SECRET"
        ) continue;
        const rep = result.stores.find((s) => s.storeId === id);
        expect(rep?.status).toBe("DEFERRED_NO_SEAL_RUNTIME");
        expect(rep?.result).toBeNull();
      }
      const signingRep = result.stores.find((s) => s.storeId === "NODE_SIGNING_KEYS");
      expect(signingRep?.status).toBe("REWRAPPED");
      expect(signingRep?.result).toEqual({ rowsBefore: 0, rowsAfter: 0, rewrapped: 0 });
      const pushRep = result.stores.find((s) => s.storeId === "PUSH_RECEIVER_SECRETS");
      expect(pushRep?.status).toBe("REWRAPPED");
      expect(pushRep?.result).toEqual({ rowsBefore: 0, rowsAfter: 0, rewrapped: 0 });
      const totpRep = result.stores.find((s) => s.storeId === "TOTP_SECRET");
      expect(totpRep?.status).toBe("REWRAPPED");
      expect(totpRep?.result).toEqual({ rowsBefore: 0, rowsAfter: 0, rewrapped: 0 });

      expect(commit).not.toHaveBeenCalled();
      expect(uow.commits).toBe(0);
      expect(uow.rollbacks).toBe(1);
      expect((await journal.read()).phase).toBe("STABLE");
      expect((await journal.read()).writerEpoch).toBe(FROM_EPOCH);

      // Byte-identical ciphertext for every row.
      expect(fixtures.map((f) => envelopeFingerprint(f.row.envelope))).toEqual(preFingerprints);
      assertNoMixedReadableState(
        fixtures.map((f) => f.row),
        "old",
      );
    });
  });

  // ── AC6: restore pre/post rotation ─────────────────────────────────────────

  describe("AC6 — recovery export identical pre/post committed rotation (pubkey + digest)", () => {
    it("audited recovery export matches public key + secret digest before and after under NEW", async () => {
      // recovery_verified_at monotonicity is DEFERRED (review B D3): rotation never
      // receives or returns a durable stamp column/port. A fixture re-carry equality would be
      // a green tautology. Keep load-bearing pubkey + secretDigest asserts only.
      const fixtures = [1, 2].map((n) => makeRow(0x10 + n, n));

      const exportBefore = auditedRecoveryExport(fixtures, OLD_ROOT);
      expect(exportBefore).toHaveLength(2);
      for (let i = 0; i < fixtures.length; i++) {
        expect(exportBefore[i]!.publicKey).toBe(fixtures[i]!.row.identity.publicKey);
        expect(exportBefore[i]!.secretDigest).toMatch(/^[0-9a-f]{64}$/);
      }

      const { journal, committed, input } = baseInput(fixtures);
      const result = await rot.rotateMasterKey(input);
      expect(result.committed).toBe(true);
      expect(committed.rows).not.toBeNull();
      expect((await journal.read()).writerEpoch).toBe(TO_EPOCH);

      // Apply committed envelopes onto fixtures (simulates durable vault write).
      const byId = new Map(committed.rows!.map((r) => [r.identity.walletId, r]));
      const postFixtures: WalletFixture[] = fixtures.map((f) => {
        const next = byId.get(f.row.identity.walletId)!;
        return {
          row: next,
          secretKey: f.secretKey,
          // Stamp field is harness-local only — not asserted as rotation behaviour.
          recoveryVerifiedAt: f.recoveryVerifiedAt,
        };
      });

      // Export under NEW root reproduces the same public keys + secret digests.
      const exportAfter = auditedRecoveryExport(postFixtures, NEW_ROOT);
      expect(exportAfter.map((e) => e.publicKey)).toEqual(exportBefore.map((e) => e.publicKey));
      expect(exportAfter.map((e) => e.secretDigest)).toEqual(exportBefore.map((e) => e.secretDigest));

      assertNoMixedReadableState(committed.rows!, "new");
    });
  });

  // ── AC7: no mixed readable state (cross-cutting, every abort path) ─────────

  describe("AC7 — no mixed readable state after induced abort (incl. post-vaultDurable)", () => {
    it("commitWalletVault throw: every pre-image row still OLD-only", async () => {
      const fixtures = [1, 2, 3].map((n) => makeRow(0x20 + n, n));
      const { journal, uow, input } = baseInput(fixtures, {
        commitWalletVault: async () => {
          throw new Error("persist transport failure");
        },
      });

      await expect(rot.rotateMasterKey(input)).rejects.toMatchObject({ code: "ROTATION_ABORTED" });
      expect(uow.commits).toBe(0);
      expect((await journal.read()).writerEpoch).toBe(FROM_EPOCH);
      assertNoMixedReadableState(
        fixtures.map((f) => f.row),
        "old",
      );
    });

    it("unitOfWork.commit throw: every pre-image row still OLD-only", async () => {
      const fixtures = [1, 2].map((n) => makeRow(0x30 + n, n));
      const journal = new rot.InMemoryMasterKeyRotationJournal(FROM_EPOCH);
      const interlock = new rot.ProcessLocalMasterKeyRotationInterlock();
      const uow = new rot.InMemoryRotationUnitOfWork();
      const originalCommit = uow.commit.bind(uow);
      uow.commit = async () => {
        await originalCommit();
        // After a successful in-memory commit the orchestrator marks vaultDurable.
        // Force a throw BEFORE commit returns by replacing with a rejecting commit.
      };
      // Cleaner: reject commit entirely so vault never becomes durable.
      uow.commit = async () => {
        throw new Error("unit commit failed");
      };

      await expect(
        rot.rotateMasterKey({
          sealedStores: registrySnapshot(),
          ...censusPorts(fixtures.map((f) => f.row)),
          keyRing: makeKeyRing(rot),
          fromEpoch: FROM_EPOCH,
          toEpoch: TO_EPOCH,
          oldRootKey: OLD_ROOT,
          newRootKey: NEW_ROOT,
          journal,
          interlock,
          unitOfWork: uow,
          commitWalletVault: async () => {
            /* in-memory ok */
          },
        }),
      ).rejects.toMatchObject({ code: "ROTATION_ABORTED" });

      expect((await journal.read()).writerEpoch).toBe(FROM_EPOCH);
      assertNoMixedReadableState(
        fixtures.map((f) => f.row),
        "old",
      );
    });

    it("happy-path commit: every durable row NEW-only (positive control for the sweep)", async () => {
      const fixtures = [1, 2, 3, 4].map((n) => makeRow(0x40 + n, n));
      const { committed, input } = baseInput(fixtures);
      const result = await rot.rotateMasterKey(input);
      expect(result.committed).toBe(true);
      assertNoMixedReadableState(committed.rows!, "new");
      // Pre-image rows (caller's snapshot) remain OLD — commit wrote a new array.
      assertNoMixedReadableState(
        fixtures.map((f) => f.row),
        "old",
      );
    });

    it("post-vaultDurable journal.complete throw: durable rows NEW-only (resume window)", async () => {
      // 217 sets vaultDurable only after commitWalletVault + unitOfWork.commit succeed.
      // A later journal.complete failure leaves durable rows under NEW and journal for resume.
      // Must NOT claim journal stayed at FROM_EPOCH STABLE; must NOT leave mixed OLD/NEW rows.
      const fixtures = [1, 2, 3].map((n) => makeRow(0x50 + n, n));
      const journalBase = new rot.InMemoryMasterKeyRotationJournal(FROM_EPOCH);
      const journal: MasterKeyRotationJournalLike = {
        read: () => journalBase.read(),
        begin: (input) => journalBase.begin(input),
        markRewrapped: (id) => journalBase.markRewrapped(id),
        async complete() {
          throw new Error("complete transport failure after vault durable");
        },
        settleStable: () => journalBase.settleStable(),
      };
      const { uow, committed, input } = baseInput(fixtures, {
        journal,
        commitWalletVault: async (rewrapped: readonly WalletVaultRewrapRow[]) => {
          committed.rows = rewrapped;
        },
      });

      await expect(rot.rotateMasterKey(input)).rejects.toMatchObject({ code: "ROTATION_ABORTED" });

      expect(committed.rows).not.toBeNull();
      expect(uow.commits).toBe(1);
      // Journal was not restored to STABLE@FROM — resume-shaped (ROTATING; writerEpoch held).
      const snap = await journal.read();
      expect(snap.writerEpoch).toBe(FROM_EPOCH);
      expect(snap.phase).not.toBe("STABLE");
      // Durable vault rows are NEW-only — the correct post-durable shape (mixed would be the bug).
      assertNoMixedReadableState(committed.rows!, "new");
      // Caller pre-image snapshot remains OLD (commit wrote a separate array).
      assertNoMixedReadableState(
        fixtures.map((f) => f.row),
        "old",
      );
    });
  });
});


import { createHash, randomBytes } from "node:crypto";
import { Buffer } from "node:buffer";
import { describe, expect, it, vi } from "vitest";

import {
  rotateVaultMasterKey,
  type NodeSigningInterlock,
  type RotationAbortReason,
  type RotationCrypto,
  type RotationSecretHandle,
  type RotationVaultRow,
  type RotationWallet,
} from "../src/core/recovery/index.js";

const WALLET_A = "00000000-0000-4000-8000-00000000000a";
const WALLET_B = "00000000-0000-4000-8000-00000000000b";
const WALLET_C = "00000000-0000-4000-8000-00000000000c";

function b64url(bytes: Uint8Array): string {
  const unpadded = Buffer.from(bytes).toString("base64url");
  return unpadded + "=".repeat((4 - (unpadded.length % 4)) % 4);
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function publicKeyFor(walletId: string): string {
  return b64url(createHash("sha256").update(walletId).digest());
}

function makeRow(walletId: string, keyVersion = 1): RotationVaultRow {
  const ciphertext = new Uint8Array(
    createHash("sha256").update(`${walletId}:${keyVersion}`).digest(),
  );
  return {
    walletId,
    keyVersion,
    ciphertext: b64url(ciphertext),
    nonce: b64url(new Uint8Array(randomBytes(12))),
    authTag: b64url(new Uint8Array(randomBytes(16))),
    ciphertextSha256: sha256Hex(ciphertext),
  };
}

function makeWallet(walletId: string): RotationWallet {
  return {
    walletId,
    publicKey: publicKeyFor(walletId),
    keyOrigin: "node_generated",
    row: makeRow(walletId),
  };
}

interface CryptoOverrides {
  /** This wallet's row cannot be opened under the old key (unreadable row). */
  readonly unreadable?: string;
  /** The re-sealed row for this wallet cannot be opened back (broken round trip). */
  readonly roundTripBroken?: string;
  /** The re-sealed row derives a different public key. */
  readonly publicKeySwapped?: string;
  /** The re-sealed row's declared digest does not describe its ciphertext. */
  readonly digestMismatch?: string;
  readonly resealThrows?: string;
  /** Force these wallets' re-sealed rows onto one shared nonce. */
  readonly forceNonce?: { readonly walletIds: readonly string[]; readonly nonce: string };
}

function makeCrypto(overrides: CryptoOverrides = {}) {
  const wiped: string[] = [];
  const resealed = new Set<string>();

  const crypto: RotationCrypto = {
    open: vi.fn(async (row: RotationVaultRow, epoch: "old" | "new") => {
      if (epoch === "old" && row.walletId === overrides.unreadable) return null;
      if (epoch === "new" && row.walletId === overrides.roundTripBroken) return null;
      return { walletId: row.walletId } satisfies RotationSecretHandle;
    }),
    derivePublicKey: vi.fn(async (handle: RotationSecretHandle) =>
      resealed.has(handle.walletId) && handle.walletId === overrides.publicKeySwapped
        ? publicKeyFor("someone-else")
        : publicKeyFor(handle.walletId),
    ),
    reseal: vi.fn(async (handle: RotationSecretHandle, nextKeyVersion: number) => {
      if (handle.walletId === overrides.resealThrows) throw new Error("seal failed");
      let row = makeRow(handle.walletId, nextKeyVersion);
      if (overrides.forceNonce?.walletIds.includes(handle.walletId) === true) {
        row = { ...row, nonce: overrides.forceNonce.nonce };
      }
      if (handle.walletId === overrides.digestMismatch) {
        row = { ...row, ciphertextSha256: sha256Hex(new Uint8Array([0])) };
      }
      resealed.add(handle.walletId);
      return row;
    }),
    wipe: vi.fn(async (handle: RotationSecretHandle) => {
      wiped.push(handle.walletId);
    }),
  };

  return { crypto, wiped };
}

function makeInterlock(): NodeSigningInterlock & { held: () => boolean } {
  let holding = false;
  return {
    acquire: vi.fn(async () => {
      holding = true;
    }),
    release: vi.fn(async () => {
      holding = false;
    }),
    held: () => holding,
  };
}

describe("vault master-key rotation ceremony", () => {
  it("rewraps every row, verifies each round trip, and commits once", async () => {
    const wallets = [makeWallet(WALLET_C), makeWallet(WALLET_A), makeWallet(WALLET_B)];
    const { crypto, wiped } = makeCrypto();
    const interlock = makeInterlock();
    let committed: readonly RotationVaultRow[] = [];
    const commit = vi.fn(async (rows: readonly RotationVaultRow[]) => {
      committed = rows;
    });

    const result = await rotateVaultMasterKey({ wallets, crypto, interlock, commit });

    expect(result.state).toBe("ROTATION_COMPLETE");
    expect(result.rowsRewrapped).toBe(3);
    expect(result.abort).toBeNull();
    expect(commit).toHaveBeenCalledTimes(1);
    // Canonical wallet-id sequence, and every row advanced exactly one key version.
    expect(committed.map((row) => row.walletId)).toEqual([WALLET_A, WALLET_B, WALLET_C]);
    expect(committed.every((row) => row.keyVersion === 2)).toBe(true);
    // Every opened handle is zeroized: the old envelope and the new one, per wallet.
    expect(wiped).toHaveLength(6);
    expect(interlock.acquire).toHaveBeenCalledTimes(1);
    expect(interlock.release).toHaveBeenCalledTimes(1);
    expect(interlock.held()).toBe(false);
  });

  it("aborts the whole rotation on one unreadable row, leaving nothing committed", async () => {
    const wallets = [makeWallet(WALLET_A), makeWallet(WALLET_B), makeWallet(WALLET_C)];
    const before = wallets.map((wallet) => ({ ...wallet.row }));
    const { crypto } = makeCrypto({ unreadable: WALLET_B });
    const interlock = makeInterlock();
    const commit = vi.fn(async () => {});

    const result = await rotateVaultMasterKey({ wallets, crypto, interlock, commit });

    expect(result.state).toBe("ABORTED");
    expect(result.abort).toEqual({ reason: "row_unreadable", walletId: WALLET_B });
    expect(result.rowsRewrapped).toBe(0);
    // Nothing committed means zero rows left in a mixed old/new key-version state, and the
    // pre-rotation state is fully intact.
    expect(commit).not.toHaveBeenCalled();
    expect(wallets.map((wallet) => wallet.row)).toEqual(before);
    expect(wallets.every((wallet) => wallet.row.keyVersion === 1)).toBe(true);
    // The interlock is released even on the abort path.
    expect(interlock.release).toHaveBeenCalledTimes(1);
    expect(interlock.held()).toBe(false);
  });

  it("never touches recovery_verified_at or the immutable wallet columns", async () => {
    // Rotation preserves the underlying key, so the stamp is monotonic across it. The
    // ceremony's only write is `commit`, which carries `vault` rows and nothing else.
    const stamps = new Map([
      [WALLET_A, "2026-05-01T00:00:00.000Z"],
      [WALLET_B, "2026-05-02T00:00:00.000Z"],
    ]);
    const before = new Map(stamps);
    const wallets = [makeWallet(WALLET_A), makeWallet(WALLET_B)];
    const { crypto } = makeCrypto();
    let committed: readonly RotationVaultRow[] = [];
    const commit = vi.fn(async (rows: readonly RotationVaultRow[]) => {
      committed = rows;
    });

    const result = await rotateVaultMasterKey({
      wallets,
      crypto,
      interlock: makeInterlock(),
      commit,
    });

    expect(result.state).toBe("ROTATION_COMPLETE");
    expect(stamps).toEqual(before);
    for (const row of committed) {
      for (const forbidden of ["recoveryVerifiedAt", "recoveryVerificationId", "publicKey", "keyOrigin"]) {
        expect(Object.hasOwn(row, forbidden)).toBe(false);
      }
    }
    expect(wallets.map((wallet) => wallet.publicKey)).toEqual([
      publicKeyFor(WALLET_A),
      publicKeyFor(WALLET_B),
    ]);
    expect(wallets.every((wallet) => wallet.keyOrigin === "node_generated")).toBe(true);
  });

  const abortCases: Array<[string, CryptoOverrides, RotationAbortReason]> = [
    ["a broken round trip", { roundTripBroken: WALLET_A }, "round_trip_unreadable"],
    [
      "a public key that changed under the new key",
      { publicKeySwapped: WALLET_A },
      "public_key_mismatch_after",
    ],
    [
      "a ciphertext digest that does not describe the row",
      { digestMismatch: WALLET_A },
      "ciphertext_digest_mismatch",
    ],
    ["a re-seal that throws", { resealThrows: WALLET_A }, "reseal_failed"],
  ];

  it.each(abortCases)("aborts on %s", async (_label, overrides, reason) => {
    const wallets = [makeWallet(WALLET_A), makeWallet(WALLET_B)];
    const { crypto } = makeCrypto(overrides);
    const commit = vi.fn(async () => {});

    const result = await rotateVaultMasterKey({
      wallets,
      crypto,
      interlock: makeInterlock(),
      commit,
    });

    expect(result.state).toBe("ABORTED");
    expect(result.abort).toEqual({ reason, walletId: WALLET_A });
    expect(commit).not.toHaveBeenCalled();
  });

  it("aborts when two re-sealed rows claim the same (key_version, nonce)", async () => {
    // The `vault` UNIQUE (key_version, nonce) guard has to hold across the whole rotation.
    const nonce = b64url(new Uint8Array(randomBytes(12)));
    const { crypto } = makeCrypto({ forceNonce: { walletIds: [WALLET_A, WALLET_B], nonce } });
    const commit = vi.fn(async () => {});

    const result = await rotateVaultMasterKey({
      wallets: [makeWallet(WALLET_A), makeWallet(WALLET_B)],
      crypto,
      interlock: makeInterlock(),
      commit,
    });

    expect(result.state).toBe("ABORTED");
    expect(result.abort).toEqual({ reason: "nonce_reuse", walletId: WALLET_B });
    expect(commit).not.toHaveBeenCalled();
  });

  it("aborts when a re-sealed row reuses a nonce a pre-rotation row already holds", async () => {
    const walletA = makeWallet(WALLET_A);
    // A pre-rotation row already sitting at key version 2 with the nonce the re-seal will pick.
    const nonce = b64url(new Uint8Array(randomBytes(12)));
    const walletB: RotationWallet = {
      ...makeWallet(WALLET_B),
      row: { ...makeRow(WALLET_B, 2), nonce },
    };
    const { crypto } = makeCrypto({ forceNonce: { walletIds: [WALLET_A], nonce } });
    const commit = vi.fn(async () => {});

    const result = await rotateVaultMasterKey({
      wallets: [walletA, walletB],
      crypto,
      interlock: makeInterlock(),
      commit,
    });

    expect(result.state).toBe("ABORTED");
    expect(result.abort).toEqual({ reason: "nonce_reuse", walletId: WALLET_A });
    expect(commit).not.toHaveBeenCalled();
  });

  it("aborts when the commit itself fails", async () => {
    const { crypto } = makeCrypto();
    const commit = vi.fn(async () => {
      throw new Error("transaction rolled back");
    });

    const result = await rotateVaultMasterKey({
      wallets: [makeWallet(WALLET_A)],
      crypto,
      interlock: makeInterlock(),
      commit,
    });

    expect(result.state).toBe("ABORTED");
    expect(result.abort).toEqual({ reason: "commit_failed", walletId: null });
  });
});

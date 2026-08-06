// Unit tests for wallet-vault rewrap primitive.
//
// Acceptance:
//   - count parity: rowsBefore == rowsAfter == rewrapped on the sealed subset
//   - N>1 wallets all rewrapped (not a singleton)
//   - wrong old key / wrong new key / tamper fail closed (no partial success return)
//   - AAD-forming columns (walletId, keyVersion, and identity fields) never change
//
// Governing: signing custody.

import { createPrivateKey, createPublicKey } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  deriveRootKey,
  openWalletSecret,
  rewrapWalletVaultStore,
  sealWalletSecret,
  toBase64UrlPadded,
  VaultOpenError,
  type WalletIdentity,
  type WalletVaultRewrapRow,
} from "../src/vault/index.js";
import { SEALED_STORES } from "../src/schema/sealed-store-registry.contract.js";

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const MASTER_OLD = Buffer.from("old-master-key-for-rewrap-tests!!");
const MASTER_NEW = Buffer.from("new-master-key-for-rewrap-tests!!");
const SALT = Buffer.from("rewrap-test-salt!");

const OLD_ROOT = deriveRootKey(MASTER_OLD, SALT);
const NEW_ROOT = deriveRootKey(MASTER_NEW, SALT);

function makeSecret(seedByte: number): { secretKey: Buffer; publicKey: string } {
  const seed = Buffer.alloc(32, seedByte);
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const rawPub = Buffer.from(spki).subarray(-32);
  return {
    publicKey: toBase64UrlPadded(rawPub),
    secretKey: Buffer.concat([seed, rawPub]),
  };
}

function makeRow(seedByte: number, walletOrdinal: number): {
  row: WalletVaultRewrapRow;
  secretKey: Buffer;
} {
  const { secretKey, publicKey } = makeSecret(seedByte);
  const identity: WalletIdentity = {
    nodeId: "11111111-1111-4111-8111-111111111111",
    walletId: `aaaaaaaa-0000-4000-8000-00000000000${walletOrdinal}`,
    keyVersion: 1,
    publicKey,
    keyOrigin: "node_generated",
  };
  const envelope = sealWalletSecret(OLD_ROOT, identity, secretKey);
  return { row: { identity, envelope }, secretKey };
}

describe("rewrapWalletVaultStore", () => {
  it("rewraps N>1 wallets with count parity and round-trip under the new root", () => {
    const fixtures = [1, 2, 3].map((n) => makeRow(0xa0 + n, n));
    const { result, rewrappedRows } = rewrapWalletVaultStore({
      oldRootKey: OLD_ROOT,
      newRootKey: NEW_ROOT,
      rows: fixtures.map((f) => f.row),
    });

    expect(result.rowsBefore).toBe(3);
    expect(result.rowsAfter).toBe(3);
    expect(result.rewrapped).toBe(3);
    expect(result.rowsBefore).toBe(result.rowsAfter);
    expect(result.rewrapped).toBe(result.rowsBefore);

    for (let i = 0; i < fixtures.length; i++) {
      const before = fixtures[i]!;
      const after = rewrappedRows[i]!;
      // AAD source columns immutable.
      expect(after.identity).toEqual(before.row.identity);
      expect(after.envelope.walletId).toBe(before.row.identity.walletId);
      expect(after.envelope.keyVersion).toBe(before.row.identity.keyVersion);
      // Fresh nonce + different ciphertext.
      expect(Buffer.from(after.envelope.nonce).equals(Buffer.from(before.row.envelope.nonce))).toBe(
        false,
      );
      // Opens under NEW, not OLD.
      const opened = openWalletSecret(NEW_ROOT, after.envelope, after.identity);
      try {
        expect(Buffer.from(opened.bytes)).toEqual(before.secretKey);
      } finally {
        opened.wipe();
      }
      expect(() =>
        openWalletSecret(OLD_ROOT, after.envelope, after.identity),
      ).toThrow(VaultOpenError);
    }
  });

  it("fail-closed on wrong old key — no partial rewrapped set returned", () => {
    const fixtures = [1, 2].map((n) => makeRow(0xb0 + n, n));
    const wrongOld = deriveRootKey(Buffer.from("totally-wrong-old-master-key!!"), SALT);
    expect(() =>
      rewrapWalletVaultStore({
        oldRootKey: wrongOld,
        newRootKey: NEW_ROOT,
        rows: fixtures.map((f) => f.row),
      }),
    ).toThrow(VaultOpenError);
  });

  it("fail-closed when a row's envelope is tampered (auth tag)", () => {
    const { row } = makeRow(0xc1, 1);
    const tampered = {
      ...row,
      envelope: {
        ...row.envelope,
        authTag: Buffer.alloc(row.envelope.authTag.length, 0x7f),
      },
    };
    expect(() =>
      rewrapWalletVaultStore({
        oldRootKey: OLD_ROOT,
        newRootKey: NEW_ROOT,
        rows: [tampered],
      }),
    ).toThrow(VaultOpenError);
  });

  it("fail-closed on empty root keys", () => {
    const { row } = makeRow(0xd1, 1);
    expect(() =>
      rewrapWalletVaultStore({
        oldRootKey: new Uint8Array(0),
        newRootKey: NEW_ROOT,
        rows: [row],
      }),
    ).toThrow(/non-empty/);
  });

  it("empty row set is a successful zero-count rewrap (vacuous parity)", () => {
    const { result, rewrappedRows } = rewrapWalletVaultStore({
      oldRootKey: OLD_ROOT,
      newRootKey: NEW_ROOT,
      rows: [],
    });
    expect(result).toEqual({ rowsBefore: 0, rowsAfter: 0, rewrapped: 0 });
    expect(rewrappedRows).toEqual([]);
  });

  it("registry marks wallet, signing, and push rewrap IMPLEMENTED", () => {
    const byId = Object.fromEntries(SEALED_STORES.map((s) => [s.id, s.rewrapStatus]));
    expect(byId).toEqual({
      WALLET_VAULT: "IMPLEMENTED",
      NODE_SIGNING_KEYS: "IMPLEMENTED",
      PUSH_RECEIVER_SECRETS: "IMPLEMENTED",
      TOTP_SECRET: "DEFERRED_NO_SEAL_RUNTIME",
      SESSION_SECRETS: "DEFERRED_NO_SEAL_RUNTIME",
    });
  });
});

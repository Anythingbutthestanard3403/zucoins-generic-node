// TOTP_SECRET seal site + rewrap + plaintext migration (ZTR-1134).

import { describe, expect, it } from "vitest";

import { encodeBase32 } from "../src/totp/secret.js";
import {
  TOTP_SECRET_ENVELOPE_PREFIX,
  TOTP_SECRET_HKDF_LABEL,
  TotpOpenError,
  openTotpSecret,
  sealTotpSecret,
} from "../src/totp/seal.js";
import { rewrapTotpSecretStore } from "../src/totp/rewrap.js";
import { migrateTotpSecretsAtRest } from "../src/totp/migrate-plaintext.js";
import { buildKeyRing } from "../src/vault/key-ring.js";
import {
  InMemoryMasterKeyRotationJournal,
  InMemoryRotationUnitOfWork,
  ProcessLocalMasterKeyRotationInterlock,
  rotateMasterKey,
} from "../src/vault/index.js";
import { SEALED_STORES } from "../src/schema/sealed-store-registry.contract.js";

const OLD_ROOT = Buffer.alloc(32, 0x41);
const NEW_ROOT = Buffer.alloc(32, 0x42);
const FROM_EPOCH = 3;
const TO_EPOCH = 4;
const ADMIN_A = "admin-operator-aaaaaaaa";
const ADMIN_B = "admin-operator-bbbbbbbb";

function secretBytes(fill: number): Buffer {
  return Buffer.alloc(20, fill);
}

describe("TOTP_SECRET seal/open", () => {
  it("round-trips under admin-row-id AAD and exports frozen HKDF label", () => {
    expect(TOTP_SECRET_HKDF_LABEL).toBe("zupayments/totp-secret/v1");
    const secret = secretBytes(7);
    const sealed = sealTotpSecret(OLD_ROOT, ADMIN_A, secret);
    expect(sealed.startsWith(`${TOTP_SECRET_ENVELOPE_PREFIX}.`)).toBe(true);
    const opened = openTotpSecret(OLD_ROOT, ADMIN_A, sealed);
    try {
      expect(Buffer.from(opened).equals(secret)).toBe(true);
    } finally {
      opened.fill(0);
    }
  });

  it("fails closed when opened with the wrong admin-row id", () => {
    const sealed = sealTotpSecret(OLD_ROOT, ADMIN_A, secretBytes(9));
    expect(() => openTotpSecret(OLD_ROOT, ADMIN_B, sealed)).toThrow(TotpOpenError);
  });

  it("fails closed under the wrong root key", () => {
    const sealed = sealTotpSecret(OLD_ROOT, ADMIN_A, secretBytes(3));
    expect(() => openTotpSecret(NEW_ROOT, ADMIN_A, sealed)).toThrow(TotpOpenError);
  });
});

describe("rewrapTotpSecretStore", () => {
  it("reseals under the new root so the secret verifies after rotation", () => {
    const secret = secretBytes(0x55);
    const envelope = sealTotpSecret(OLD_ROOT, ADMIN_A, secret);
    const keyRing = buildKeyRing({
      writerEpoch: TO_EPOCH,
      writerRoot: NEW_ROOT,
      retained: [{ epoch: FROM_EPOCH, root: OLD_ROOT }],
    });
    const { result, rewrappedRows } = rewrapTotpSecretStore({
      keyRing,
      newRootKey: NEW_ROOT,
      fromEpoch: FROM_EPOCH,
      toEpoch: TO_EPOCH,
      rows: [{ identity: { adminOperatorId: ADMIN_A }, envelope }],
    });
    expect(result).toEqual({ rowsBefore: 1, rowsAfter: 1, rewrapped: 1 });
    expect(rewrappedRows).toHaveLength(1);
    const opened = openTotpSecret(NEW_ROOT, ADMIN_A, rewrappedRows[0]!.envelope);
    try {
      expect(Buffer.from(opened).equals(secret)).toBe(true);
    } finally {
      opened.fill(0);
    }
    expect(() => openTotpSecret(OLD_ROOT, ADMIN_A, rewrappedRows[0]!.envelope)).toThrow(
      TotpOpenError,
    );
  });
});

describe("rotateMasterKey covers TOTP_SECRET", () => {
  it("rewraps TOTP secrets and commits under the new root", async () => {
    const secret = secretBytes(0x66);
    const envelope = sealTotpSecret(OLD_ROOT, ADMIN_A, secret);
    let committed: Array<{ identity: { adminOperatorId: string }; envelope: string }> = [];
    const result = await rotateMasterKey({
      sealedStores: SEALED_STORES,
      walletVault: { rows: [] },
      countWalletVaultRows: async () => 0,
      nodeSigningKeys: { rows: [] },
      countNodeSigningKeyRows: async () => 0,
      pushReceiverSecrets: { rows: [] },
      countPushSecretRows: async () => 0,
      totpSecrets: { rows: [{ identity: { adminOperatorId: ADMIN_A }, envelope }] },
      countTotpSecretRows: async () => 1,
      rewrapTotpSecretStore,
      commitTotpSecrets: async (rows) => {
        committed = [...rows];
      },
      keyRing: buildKeyRing({
        writerEpoch: TO_EPOCH,
        writerRoot: NEW_ROOT,
        retained: [{ epoch: FROM_EPOCH, root: OLD_ROOT }],
      }),
      fromEpoch: FROM_EPOCH,
      toEpoch: TO_EPOCH,
      oldRootKey: OLD_ROOT,
      newRootKey: NEW_ROOT,
      journal: new InMemoryMasterKeyRotationJournal(FROM_EPOCH),
      interlock: new ProcessLocalMasterKeyRotationInterlock(),
      commitWalletVault: async () => {},
      unitOfWork: new InMemoryRotationUnitOfWork(),
    });
    expect(result.committed).toBe(true);
    const report = result.stores.find((s) => s.storeId === "TOTP_SECRET");
    expect(report?.status).toBe("REWRAPPED");
    expect(report?.result).toEqual({ rowsBefore: 1, rowsAfter: 1, rewrapped: 1 });
    expect(committed).toHaveLength(1);
    const opened = openTotpSecret(NEW_ROOT, ADMIN_A, committed[0]!.envelope);
    try {
      expect(Buffer.from(opened).equals(secret)).toBe(true);
    } finally {
      opened.fill(0);
    }
  });
});

describe("migrateTotpSecretsAtRest", () => {
  it("seals plaintext rows, clears base32, and drops the plaintext column", async () => {
    const secret = secretBytes(0x77);
    const plain = encodeBase32(secret);
    type Row = {
      id: string;
      totp_secret_base32: string | null;
      totp_secret_sealed: string | null;
    };
    const operators = new Map<string, Row>([
      [ADMIN_A, { id: ADMIN_A, totp_secret_base32: plain, totp_secret_sealed: null }],
    ]);
    let hasBase32Col = true;
    const db = {
      async query<T extends Record<string, unknown>>(sql: string, params: readonly unknown[] = []) {
        const s = sql.replace(/\s+/g, " ").trim().toLowerCase();
        if (s.includes("information_schema.columns") && s.includes("in ('totp_secret_base32'")) {
          const cols: Array<{ column_name: string }> = [{ column_name: "totp_secret_sealed" }];
          if (hasBase32Col) cols.push({ column_name: "totp_secret_base32" });
          return { rows: cols as T[] };
        }
        if (s.includes("information_schema.columns") && s.includes("= 'totp_secret_base32'")) {
          return { rows: (hasBase32Col ? [{ column_name: "totp_secret_base32" }] : []) as T[] };
        }
        if (s.startsWith("select id, totp_secret_base32")) {
          const rows = [...operators.values()].filter(
            (r) => r.totp_secret_base32 !== null && r.totp_secret_base32.trim().length > 0,
          );
          return { rows: rows as unknown as T[] };
        }
        if (s.startsWith("update admin_operators set totp_secret_sealed")) {
          const id = String(params[0]);
          const sealed = String(params[1]);
          const row = operators.get(id)!;
          operators.set(id, { ...row, totp_secret_sealed: sealed });
          return { rows: [] as T[] };
        }
        if (s.startsWith("update admin_operators set totp_secret_base32 = null")) {
          const id = String(params[0]);
          const row = operators.get(id)!;
          operators.set(id, { ...row, totp_secret_base32: null });
          return { rows: [] as T[] };
        }
        if (s.includes("count(*)") && s.includes("totp_secret_base32")) {
          const n = [...operators.values()].filter(
            (r) => r.totp_secret_base32 !== null && r.totp_secret_base32.trim().length > 0,
          ).length;
          return { rows: [{ n: String(n) }] as unknown as T[] };
        }
        if (s.startsWith("alter table admin_operators drop column")) {
          hasBase32Col = false;
          return { rows: [] as T[] };
        }
        throw new Error(`unexpected sql: ${sql}`);
      },
    };

    const result = await migrateTotpSecretsAtRest({ db, rootKey: OLD_ROOT });
    expect(result.migrated).toBe(1);
    expect(result.plaintextColumnDropped).toBe(true);
    expect(hasBase32Col).toBe(false);
    const sealed = operators.get(ADMIN_A)!.totp_secret_sealed;
    expect(sealed).toBeTruthy();
    const opened = openTotpSecret(OLD_ROOT, ADMIN_A, sealed!);
    try {
      expect(Buffer.from(opened).equals(secret)).toBe(true);
    } finally {
      opened.fill(0);
    }
  });
});

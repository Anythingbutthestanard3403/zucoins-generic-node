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
        if (s.startsWith("select id, totp_secret_sealed")) {
          const rows = [...operators.values()]
            .filter((r) => r.totp_secret_sealed !== null && r.totp_secret_sealed.trim().length > 0)
            .map((r) => ({ id: r.id, totp_secret_sealed: r.totp_secret_sealed }));
          return { rows: rows as unknown as T[] };
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


// --- ZTR-1134 rework: arm gate, sealed census, money-path open mapping ---

describe("SqlAdminUserStore seal arm gate (ZTR-1134 B1)", () => {
  const ROOT = Buffer.alloc(32, 0x51);

  function memDb() {
    const operators = new Map<string, Record<string, unknown>>();
    operators.set(ADMIN_A, {
      id: ADMIN_A,
      username: "admin",
      password_hash: "x",
      role: "admin",
      must_change_password: false,
      must_enrol_totp: true,
      disabled_at: null,
      created_at: new Date(1),
      totp_status: "none",
      totp_secret_sealed: null,
    });
    return {
      operators,
      async query<T extends Record<string, unknown>>(sql: string, params: readonly unknown[] = []) {
        const s = sql.replace(/\s+/g, " ").trim().toLowerCase();
        if (s.startsWith("select totp_status from admin_operators")) {
          const id = String(params[0]);
          const row = operators.get(id);
          return { rows: (row ? [{ totp_status: row["totp_status"] }] : []) as T[] };
        }
        if (s.startsWith("select totp_status, totp_secret_sealed")) {
          const id = String(params[0]);
          const row = operators.get(id);
          return {
            rows: (row
              ? [{ totp_status: row["totp_status"], totp_secret_sealed: row["totp_secret_sealed"] }]
              : []) as T[],
          };
        }
        if (s.includes("set totp_status = 'pending'")) {
          const id = String(params[0]);
          const sealed = String(params[1]);
          const row = operators.get(id);
          if (row && String(row["totp_status"]) !== "active") {
            operators.set(id, { ...row, totp_status: "pending", totp_secret_sealed: sealed });
          }
          return { rows: [] as T[] };
        }
        if (s.includes("set totp_status = 'active'") && s.includes("totp_secret_sealed")) {
          const id = String(params[0]);
          const sealed = String(params[1]);
          const row = operators.get(id);
          if (row) {
            operators.set(id, {
              ...row,
              totp_status: "active",
              totp_secret_sealed: sealed,
              must_enrol_totp: false,
            });
            return { rows: [{ id }] as T[] };
          }
          return { rows: [] as T[] };
        }
        if (s.startsWith("select * from admin_operators where id")) {
          const id = String(params[0]);
          const row = operators.get(id);
          return { rows: (row ? [row] : []) as T[] };
        }
        throw new Error(`unexpected sql: ${sql}`);
      },
    };
  }

  it("refuses setPending/setActive while unarmed and writes no sealed row", async () => {
    const db = memDb();
    const { SqlAdminUserStore, VaultSealingNotArmedError } = await import(
      "../src/http/admin-user-sql-store.js"
    );
    const store = new SqlAdminUserStore(db, ROOT);
    await expect(store.setPendingTotpSecret(ADMIN_A, encodeBase32(secretBytes(1)))).rejects.toBeInstanceOf(
      VaultSealingNotArmedError,
    );
    await expect(store.setActiveTotpSecret(ADMIN_A, encodeBase32(secretBytes(2)))).rejects.toBeInstanceOf(
      VaultSealingNotArmedError,
    );
    expect(db.operators.get(ADMIN_A)!["totp_secret_sealed"]).toBeNull();
  });

  it("after arm, seals under final root and open succeeds", async () => {
    const db = memDb();
    const { SqlAdminUserStore } = await import("../src/http/admin-user-sql-store.js");
    const store = new SqlAdminUserStore(db, ROOT);
    store.armVaultRoot();
    const plain = encodeBase32(secretBytes(0x33));
    expect(await store.setPendingTotpSecret(ADMIN_A, plain)).toBe("ok");
    const sealed = db.operators.get(ADMIN_A)!["totp_secret_sealed"];
    expect(typeof sealed).toBe("string");
    const opened = openTotpSecret(ROOT, ADMIN_A, String(sealed));
    try {
      expect(Buffer.from(opened).equals(secretBytes(0x33))).toBe(true);
    } finally {
      opened.fill(0);
    }
    const factor = await store.getTotpFactor(ADMIN_A);
    expect(factor.status).toBe("pending");
  });

  it("provisional≠final: refuse pre-arm; seal under final after arm", async () => {
    const provisional = Buffer.alloc(32, 0x11);
    const finalRoot = Buffer.alloc(32, 0x22);
    const shared = Buffer.from(provisional);
    const db = memDb();
    const { SqlAdminUserStore, VaultSealingNotArmedError } = await import(
      "../src/http/admin-user-sql-store.js"
    );
    const store = new SqlAdminUserStore(db, shared);
    await expect(store.setPendingTotpSecret(ADMIN_A, encodeBase32(secretBytes(4)))).rejects.toBeInstanceOf(
      VaultSealingNotArmedError,
    );
    shared.set(finalRoot);
    store.armVaultRoot();
    const plain = encodeBase32(secretBytes(5));
    expect(await store.setActiveTotpSecret(ADMIN_A, plain)).toBe("ok");
    const sealed = String(db.operators.get(ADMIN_A)!["totp_secret_sealed"]);
    expect(() => openTotpSecret(provisional, ADMIN_A, sealed)).toThrow(TotpOpenError);
    const opened = openTotpSecret(finalRoot, ADMIN_A, sealed);
    opened.fill(0);
  });
});

describe("migrateTotpSecretsAtRest sealed census fail-closed (ZTR-1134 B1b/c)", () => {
  it("throws when a sealed row is unreadable under final root", async () => {
    const wrongRoot = Buffer.alloc(32, 0x99);
    const orphan = sealTotpSecret(wrongRoot, ADMIN_A, secretBytes(0x44));
    type Row = { id: string; totp_secret_base32: string | null; totp_secret_sealed: string | null };
    const operators = new Map<string, Row>([
      [ADMIN_A, { id: ADMIN_A, totp_secret_base32: null, totp_secret_sealed: orphan }],
    ]);
    const db = {
      async query<T extends Record<string, unknown>>(sql: string, _params: readonly unknown[] = []) {
        const s = sql.replace(/\s+/g, " ").trim().toLowerCase();
        if (s.includes("information_schema.columns") && s.includes("in ('totp_secret_base32'")) {
          return { rows: [{ column_name: "totp_secret_sealed" }] as T[] };
        }
        if (s.includes("information_schema.columns") && s.includes("= 'totp_secret_base32'")) {
          return { rows: [] as T[] };
        }
        if (s.startsWith("select id, totp_secret_sealed")) {
          const rows = [...operators.values()]
            .filter((r) => r.totp_secret_sealed)
            .map((r) => ({ id: r.id, totp_secret_sealed: r.totp_secret_sealed }));
          return { rows: rows as unknown as T[] };
        }
        throw new Error(`unexpected sql: ${sql}`);
      },
    };
    await expect(migrateTotpSecretsAtRest({ db, rootKey: OLD_ROOT })).rejects.toThrow(
      /sealed TOTP envelope unreadable/,
    );
  });
});

describe("money-path TotpOpenError mapping (ZTR-1134 B2)", () => {
  const user = {
    id: ADMIN_A,
    username: "admin",
    passwordHash: "x",
    role: "admin" as const,
    mustChangePassword: false,
    mustEnrolTotp: false,
    disabledAt: null,
    createdAt: 1,
  };

  it("requireActiveTotpFactor returns totp_required on TotpOpenError", async () => {
    const { requireActiveTotpFactor } = await import("../src/http/admin-session.js");
    const store = {
      async getTotpFactor() {
        throw new TotpOpenError("envelope authentication failed");
      },
    } as never;
    const gate = await requireActiveTotpFactor(store, user);
    expect(gate.ok).toBe(false);
    if (!gate.ok) {
      expect(gate.status).toBe(401);
      expect(gate.code).toBe("totp_required");
    }
  });

  it("resolveOperatorTotpConfig returns null on open error without lab", async () => {
    const { resolveOperatorTotpConfig } = await import("../src/http/admin-auth-handlers.js");
    const store = {
      async getTotpFactor() {
        throw new TotpOpenError("envelope authentication failed");
      },
    } as never;
    const cfg = await resolveOperatorTotpConfig(store, ADMIN_A, null);
    expect(cfg).toBeNull();
  });

  it("resolveOperatorTotpConfig falls through to lab when armed", async () => {
    const { resolveOperatorTotpConfig } = await import("../src/http/admin-auth-handlers.js");
    const store = {
      async getTotpFactor() {
        throw new TotpOpenError("envelope authentication failed");
      },
    } as never;
    const lab = { secret: Buffer.alloc(20, 0x7e), windowSteps: 1 as const };
    const cfg = await resolveOperatorTotpConfig(store, ADMIN_A, lab);
    expect(cfg).not.toBeNull();
    expect(cfg!.secret).toBe(lab.secret);
  });
});

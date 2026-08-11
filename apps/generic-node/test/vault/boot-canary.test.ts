// Boot-time vault unlock canary (ZTR-1177).
//
// The canary is the virgin-node half of the vault-unlock proof: seal a fixed
// non-secret under the derived root on first boot, open it on every later boot.
// A wrong VAULT_MASTER_KEY must fail closed here with a named error that carries
// no key material — before readiness opens the vault gate.

import { randomBytes } from "node:crypto";

import { describe, expect, it } from "vitest";

import { deriveRootKey } from "@zucoins/node-core";

import {
  VAULT_BOOT_CANARY_ENVELOPE_PREFIX,
  VAULT_BOOT_CANARY_HKDF_LABEL,
  VAULT_BOOT_CANARY_PLAINTEXT,
  VAULT_BOOT_CANARY_SETTING_KEY,
  VaultBootCanaryError,
  buildVaultBootCanaryAad,
  buildVaultBootCanaryDekInfo,
  openVaultBootCanary,
  proveVaultRootWithBootCanary,
  sealVaultBootCanary,
  rewrapVaultBootCanary,
  commitVaultBootCanary,
  countVaultBootCanaryRows,
  loadVaultBootCanary,
  type VaultBootCanarySqlExecutor,
} from "../../src/vault/boot-canary.js";
import { HISTORICAL_ROOT_KDF_SALT } from "../../src/vault/root-kdf-salt.js";

const NODE_ID = "22222222-2222-4222-8222-222222222222";
const OTHER_NODE_ID = "33333333-3333-4333-8333-333333333333";
const MASTER_KEY = "boot-canary-fixture-master-key-32b!!!!";

function rootUnderHistorical(): Buffer {
  return deriveRootKey(MASTER_KEY, HISTORICAL_ROOT_KDF_SALT);
}

function wrongRoot(): Buffer {
  return deriveRootKey(MASTER_KEY, randomBytes(32));
}

/** In-memory node_settings stand-in keyed only on the canary setting. */
function makeSql(initial: string | null = null): {
  sql: VaultBootCanarySqlExecutor;
  store: Map<string, string>;
} {
  const store = new Map<string, string>();
  if (initial !== null) store.set(VAULT_BOOT_CANARY_SETTING_KEY, initial);
  const sql: VaultBootCanarySqlExecutor = {
    async query<T extends Record<string, unknown>>(text: string, params?: readonly unknown[]) {
      if (text.includes("SELECT setting_value")) {
        const key = String(params?.[0] ?? "");
        const value = store.get(key);
        return {
          rows: (value === undefined ? [] : [{ setting_value: value }]) as T[],
        };
      }
      if (text.includes("INSERT INTO node_settings")) {
        const key = String(params?.[0] ?? "");
        const value = String(params?.[1] ?? "");
        // ON CONFLICT DO NOTHING
        if (!store.has(key)) store.set(key, value);
        return { rows: [] as T[] };
      }
      throw new Error(`unexpected sql in boot-canary fixture: ${text.slice(0, 80)}`);
    },
  };
  return { sql, store };
}

describe("vault boot canary — seal/open primitives", () => {
  it("round-trips the fixed plaintext under the derived root", () => {
    const root = rootUnderHistorical();
    const sealed = sealVaultBootCanary(root, NODE_ID);
    expect(sealed.startsWith(`${VAULT_BOOT_CANARY_ENVELOPE_PREFIX}.`)).toBe(true);
    const opened = openVaultBootCanary(root, NODE_ID, sealed);
    try {
      expect(opened.toString("utf8")).toBe(VAULT_BOOT_CANARY_PLAINTEXT);
    } finally {
      opened.fill(0);
    }
  });

  it("refuses a wrong root key with a named no-material error", () => {
    const sealed = sealVaultBootCanary(rootUnderHistorical(), NODE_ID);
    const err = (() => {
      try {
        openVaultBootCanary(wrongRoot(), NODE_ID, sealed);
        return null;
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(VaultBootCanaryError);
    expect((err as VaultBootCanaryError).code).toBe("VAULT_BOOT_CANARY_DOES_NOT_OPEN");
    const msg = (err as Error).message;
    expect(msg).toContain("vault-unlock");
    // Never leak material or config.
    expect(msg).not.toContain(MASTER_KEY);
    expect(msg).not.toContain(sealed);
    expect(msg).not.toContain(VAULT_BOOT_CANARY_PLAINTEXT);
    expect(msg).not.toMatch(/[A-Za-z0-9+/]{40,}={0,2}/); // no long base64 blobs
  });

  it("refuses a canary sealed for a different nodeId (AAD bind)", () => {
    const root = rootUnderHistorical();
    const sealed = sealVaultBootCanary(root, NODE_ID);
    expect(() => openVaultBootCanary(root, OTHER_NODE_ID, sealed)).toThrow(VaultBootCanaryError);
  });

  it("refuses a truncated or wrong-prefix envelope without opening", () => {
    const root = rootUnderHistorical();
    expect(() => openVaultBootCanary(root, NODE_ID, "not-an-envelope")).toThrow(
      /VAULT_BOOT_CANARY_MALFORMED/,
    );
    expect(() =>
      openVaultBootCanary(root, NODE_ID, `${VAULT_BOOT_CANARY_ENVELOPE_PREFIX}.AA==`),
    ).toThrow(/VAULT_BOOT_CANARY_MALFORMED/);
  });

  it("pins the HKDF label and AAD shape (byte contracts)", () => {
    expect(buildVaultBootCanaryDekInfo()).toBe(VAULT_BOOT_CANARY_HKDF_LABEL);
    expect(buildVaultBootCanaryAad(NODE_ID)).toBe(NODE_ID);
    expect(VAULT_BOOT_CANARY_HKDF_LABEL).toBe("zupayments/vault-boot-canary/v1");
    expect(VAULT_BOOT_CANARY_SETTING_KEY).toBe("vault.boot_canary_v1");
  });
});

describe("proveVaultRootWithBootCanary — durable round-trip", () => {
  it("seals on a virgin node and opens on the next call under the same root", async () => {
    const { sql, store } = makeSql(null);
    const root = rootUnderHistorical();

    const first = await proveVaultRootWithBootCanary({ sql, nodeId: NODE_ID, rootKey: root });
    expect(first).toEqual({ verified: false, action: "sealed" });
    expect(store.has(VAULT_BOOT_CANARY_SETTING_KEY)).toBe(true);

    const second = await proveVaultRootWithBootCanary({ sql, nodeId: NODE_ID, rootKey: root });
    expect(second).toEqual({ verified: true, action: "opened" });
  });

  it("fails closed when a returning node presents the wrong root", async () => {
    const root = rootUnderHistorical();
    const sealed = sealVaultBootCanary(root, NODE_ID);
    const { sql } = makeSql(sealed);

    const err = await proveVaultRootWithBootCanary({
      sql,
      nodeId: NODE_ID,
      rootKey: wrongRoot(),
    }).catch((e) => e);

    expect(err).toBeInstanceOf(VaultBootCanaryError);
    expect((err as VaultBootCanaryError).code).toBe("VAULT_BOOT_CANARY_DOES_NOT_OPEN");
    expect((err as Error).message).toContain("vault-unlock");
    expect((err as Error).message).not.toContain(MASTER_KEY);
    expect((err as Error).message).not.toContain(sealed);
  });

  it("does not overwrite an existing canary on a concurrent insert (DO NOTHING)", async () => {
    const root = rootUnderHistorical();
    const existing = sealVaultBootCanary(root, NODE_ID);
    const { sql, store } = makeSql(existing);

    // Even if prove tries to seal again, the row stays the original envelope.
    const result = await proveVaultRootWithBootCanary({
      sql,
      nodeId: NODE_ID,
      rootKey: root,
    });
    expect(result.action).toBe("opened");
    expect(store.get(VAULT_BOOT_CANARY_SETTING_KEY)).toBe(existing);
  });

  it("works on a node with zero wallets (empty sql surface other than node_settings)", async () => {
    // The whole point of option 1: no wallet/signing-key rows required.
    const { sql } = makeSql(null);
    const root = rootUnderHistorical();
    await expect(
      proveVaultRootWithBootCanary({ sql, nodeId: NODE_ID, rootKey: root }),
    ).resolves.toMatchObject({ action: "sealed" });
    await expect(
      proveVaultRootWithBootCanary({ sql, nodeId: NODE_ID, rootKey: root }),
    ).resolves.toMatchObject({ action: "opened" });
  });
});

describe("rewrapVaultBootCanary (ZTR-1177 r2 rotation)", () => {
  const nodeId = "11111111-1111-4111-8111-111111111111";
  const rootA = Buffer.alloc(32, 0xa1);
  const rootB = Buffer.alloc(32, 0xb2);

  it("reseals under the new root so prove/open succeed after rotation", () => {
    const sealedA = sealVaultBootCanary(rootA, nodeId);
    const { result, rewrappedEnvelope } = rewrapVaultBootCanary({
      oldRootKey: rootA,
      newRootKey: rootB,
      nodeId,
      envelope: sealedA,
    });
    expect(result).toEqual({ rowsBefore: 1, rowsAfter: 1, rewrapped: 1 });
    expect(rewrappedEnvelope).not.toBe(sealedA);
    expect(rewrappedEnvelope.startsWith(`${VAULT_BOOT_CANARY_ENVELOPE_PREFIX}.`)).toBe(true);

    // Old root no longer opens the rewrapped envelope.
    expect(() => openVaultBootCanary(rootA, nodeId, rewrappedEnvelope)).toThrow(
      /VAULT_BOOT_CANARY_DOES_NOT_OPEN/,
    );

    const opened = openVaultBootCanary(rootB, nodeId, rewrappedEnvelope);
    try {
      expect(Buffer.from(opened).toString("utf8")).toBe(VAULT_BOOT_CANARY_PLAINTEXT);
    } finally {
      opened.fill(0);
    }
  });

  it("refuses rewrap when neither new nor old root opens the durable canary", () => {
    const sealedA = sealVaultBootCanary(rootA, nodeId);
    const rootC = Buffer.alloc(32, 0xc3);
    expect(() =>
      rewrapVaultBootCanary({
        oldRootKey: rootB, // wrong "old"
        newRootKey: rootC, // wrong "new"
        nodeId,
        envelope: sealedA,
      }),
    ).toThrow(/VAULT_BOOT_CANARY_DOES_NOT_OPEN/);
  });

  it("skips reseal when the durable canary is already under the new root (crash-resume)", () => {
    const sealedB = sealVaultBootCanary(rootB, nodeId);
    const { result, rewrappedEnvelope } = rewrapVaultBootCanary({
      oldRootKey: rootA,
      newRootKey: rootB,
      nodeId,
      envelope: sealedB,
    });
    expect(result).toEqual({ rowsBefore: 1, rowsAfter: 1, rewrapped: 1 });
    // Carry-through — no fresh seal (identical envelope).
    expect(rewrappedEnvelope).toBe(sealedB);
    const opened = openVaultBootCanary(rootB, nodeId, rewrappedEnvelope);
    try {
      expect(Buffer.from(opened).toString("utf8")).toBe(VAULT_BOOT_CANARY_PLAINTEXT);
    } finally {
      opened.fill(0);
    }
  });

  it("opens under new first when both roots could theoretically apply (writer-first)", () => {
    // Envelope under new; old is wrong for this envelope — still succeeds via new-first.
    const sealedB = sealVaultBootCanary(rootB, nodeId);
    const report = rewrapVaultBootCanary({
      oldRootKey: rootA,
      newRootKey: rootB,
      nodeId,
      envelope: sealedB,
    });
    expect(report.rewrappedEnvelope).toBe(sealedB);
  });

  it("commit updates the durable row; wrong-key prove still fails closed without overwrite", async () => {
    const sealedA = sealVaultBootCanary(rootA, nodeId);
    const store = new Map<string, string>([[VAULT_BOOT_CANARY_SETTING_KEY, sealedA]]);
    const sql = {
      async query<T extends Record<string, unknown>>(sqlText: string, params?: readonly unknown[]) {
        if (sqlText.includes("COUNT(*)")) {
          const n = store.has(VAULT_BOOT_CANARY_SETTING_KEY) ? 1 : 0;
          return { rows: [{ n }] as unknown as T[] };
        }
        if (sqlText.startsWith("SELECT setting_value")) {
          const v = store.get(String(params?.[0]));
          return { rows: (v === undefined ? [] : [{ setting_value: v }]) as unknown as T[] };
        }
        if (sqlText.includes("UPDATE node_settings")) {
          const key = String(params?.[0]);
          const val = String(params?.[1]);
          if (!store.has(key)) return { rows: [] as T[] };
          store.set(key, val);
          return { rows: [{ setting_key: key }] as unknown as T[] };
        }
        if (sqlText.includes("INSERT INTO node_settings")) {
          const key = String(params?.[0]);
          const val = String(params?.[1]);
          if (!store.has(key)) store.set(key, val);
          return { rows: [] as T[] };
        }
        throw new Error(`unexpected sql: ${sqlText}`);
      },
    };

    expect(await countVaultBootCanaryRows(sql)).toBe(1);
    const report = rewrapVaultBootCanary({
      oldRootKey: rootA,
      newRootKey: rootB,
      nodeId,
      envelope: sealedA,
    });
    await commitVaultBootCanary(sql, report.rewrappedEnvelope);
    expect(await loadVaultBootCanary(sql)).toBe(report.rewrappedEnvelope);

    // Post-rotation prove under new root succeeds.
    const ok = await proveVaultRootWithBootCanary({ sql, nodeId, rootKey: rootB });
    expect(ok.action).toBe("opened");

    // Wrong root without rotation proof still fails closed and does NOT overwrite.
    const before = await loadVaultBootCanary(sql);
    await expect(
      proveVaultRootWithBootCanary({ sql, nodeId, rootKey: rootA }),
    ).rejects.toThrow(/VAULT_BOOT_CANARY_DOES_NOT_OPEN/);
    expect(await loadVaultBootCanary(sql)).toBe(before);
  });
});


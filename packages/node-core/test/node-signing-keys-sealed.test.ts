// NODE_SIGNING_KEYS seal/open + rewrap + ensure unit tests.
// Never logs seed/private material. Synthetic keys only.

import { createHash, randomUUID } from "node:crypto";

import { describe, expect, it } from "vitest";

import { ED25519_SEED_BYTES, VaultOpenError, deriveRootKey } from "../src/vault/index.js";
import {
  NODE_SIGNING_DEK_HKDF_LABEL,
  NODE_SIGNING_SECRET_AAD_DOMAIN,
  buildNodeSigningDekInfo,
  buildNodeSigningSecretAad,
  ensureActiveNodeSigningKey,
  generateEd25519Seed,
  openNodeSigningSeed,
  publicKeyFromEd25519Seed,
  rewrapNodeSigningKeyStore,
  sealNodeSigningSeed,
  type NodeSigningKeyIdentity,
  type SqlExecutor,
} from "../src/signing-keys/index.js";

const MASTER = Buffer.from("node-signing-keys-master-key-v1!!");
const SALT = Buffer.from("node-signing-test-salt-v1");
const ROOT = deriveRootKey(MASTER, SALT);
const NEW_ROOT = deriveRootKey(Buffer.from("node-signing-keys-master-key-v2!!"), SALT);
const NODE_ID = "11111111-1111-4111-8111-111111111111";

function makeIdentity(seed: Uint8Array, purpose: "NODE_IDENTITY" | "EVENT_SIGNING" = "NODE_IDENTITY"): {
  identity: NodeSigningKeyIdentity;
  seed: Buffer;
} {
  const seedBuf = Buffer.from(seed.subarray(0, 32));
  return {
    seed: seedBuf,
    identity: {
      nodeId: NODE_ID,
      purpose,
      publicKey: publicKeyFromEd25519Seed(seedBuf),
      keyVersion: 1,
    },
  };
}

describe("NODE_SIGNING_KEYS seal/open", () => {
  it("round-trips a sealed seed and wipes open buffer", () => {
    const seed = generateEd25519Seed();
    const { identity } = makeIdentity(seed);
    const ref = randomUUID();
    const envelope = sealNodeSigningSeed(ROOT, identity, seed, ref);
    expect(envelope.ciphertext.length).toBe(ED25519_SEED_BYTES);
    expect(envelope.vaultSecretRef).toBe(ref);

    const opened = openNodeSigningSeed(ROOT, envelope, identity);
    try {
      expect(Buffer.from(opened.bytes)).toEqual(seed);
    } finally {
      opened.wipe();
    }
    // wiped bytes are zeros
    expect(Buffer.from(opened.bytes).every((b) => b === 0)).toBe(true);
  });

  it("fail-closed on wrong root / tampered tag / purpose mismatch", () => {
    const seed = generateEd25519Seed();
    const { identity } = makeIdentity(seed);
    const envelope = sealNodeSigningSeed(ROOT, identity, seed, randomUUID());

    expect(() => openNodeSigningSeed(NEW_ROOT, envelope, identity)).toThrow(VaultOpenError);

    expect(() =>
      openNodeSigningSeed(
        ROOT,
        { ...envelope, authTag: Buffer.alloc(16, 0xab) },
        identity,
      ),
    ).toThrow(VaultOpenError);

    expect(() =>
      openNodeSigningSeed(ROOT, envelope, { ...identity, purpose: "EVENT_SIGNING" }),
    ).toThrow(VaultOpenError);
  });

  it("AAD and HKDF info use real LF joiners and frozen domain labels", () => {
    const seed = Buffer.alloc(32, 0x42);
    const { identity } = makeIdentity(seed);
    const aad = buildNodeSigningSecretAad(identity);
    const info = buildNodeSigningDekInfo(identity);
    expect(aad.split("\n")[0]).toBe(NODE_SIGNING_SECRET_AAD_DOMAIN);
    expect(info.split("\n")[0]).toBe(NODE_SIGNING_DEK_HKDF_LABEL);
    expect(aad).not.toContain("\\n");
    expect(info).not.toContain("\\n");
    expect(aad).toContain(identity.publicKey);
    expect(info).toContain(identity.purpose);
  });

  it("seed override is deterministic for public key", () => {
    const seed = Buffer.alloc(32, 0x11);
    expect(publicKeyFromEd25519Seed(seed)).toBe(publicKeyFromEd25519Seed(Buffer.from(seed)));
  });
});

describe("rewrapNodeSigningKeyStore", () => {
  it("rewraps N>1 keys with count parity under new root", () => {
    const fixtures = [0xa1, 0xa2, 0xa3].map((b) => {
      const seed = Buffer.alloc(32, b);
      const { identity } = makeIdentity(seed, b % 2 === 0 ? "NODE_IDENTITY" : "EVENT_SIGNING");
      const envelope = sealNodeSigningSeed(ROOT, identity, seed, randomUUID());
      return { seed, identity, envelope };
    });

    const { result, rewrappedRows } = rewrapNodeSigningKeyStore({
      oldRootKey: ROOT,
      newRootKey: NEW_ROOT,
      rows: fixtures.map((f) => ({ identity: f.identity, envelope: f.envelope })),
    });

    expect(result).toEqual({ rowsBefore: 3, rowsAfter: 3, rewrapped: 3 });
    for (let i = 0; i < fixtures.length; i++) {
      const before = fixtures[i]!;
      const after = rewrappedRows[i]!;
      expect(after.identity).toEqual(before.identity);
      const opened = openNodeSigningSeed(NEW_ROOT, after.envelope, after.identity);
      try {
        expect(Buffer.from(opened.bytes)).toEqual(before.seed);
      } finally {
        opened.wipe();
      }
      expect(() => openNodeSigningSeed(ROOT, after.envelope, after.identity)).toThrow(
        VaultOpenError,
      );
    }
  });
});

/** Minimal in-memory SqlExecutor for ensureActiveNodeSigningKey. */
function makeMemorySql(): {
  sql: SqlExecutor;
  sealed: Map<string, Record<string, unknown>>;
  keys: Map<string, Record<string, unknown>>;
  nodes: Map<string, string>;
} {
  const sealed = new Map<string, Record<string, unknown>>();
  const keys = new Map<string, Record<string, unknown>>();
  const nodes = new Map<string, string>([[NODE_ID, "ephemeral-pub"]]);

  const sql: SqlExecutor = {
    async query<R>(text: string, params: readonly unknown[]): Promise<{ rows: R[] }> {
      const t = text.replace(/\s+/g, " ").trim();

      if (t.startsWith("SELECT pg_advisory_xact_lock")) {
        return { rows: [] };
      }

      if (t.startsWith("SELECT k.id, k.public_key, k.vault_secret_ref, s.key_version")) {
        const nodeId = params[0];
        const purpose = params[1];
        for (const k of keys.values()) {
          if (
            k.node_id === nodeId &&
            k.purpose === purpose &&
            k.retired_at == null &&
            sealed.has(String(k.vault_secret_ref))
          ) {
            const s = sealed.get(String(k.vault_secret_ref))!;
            return {
              rows: [
                {
                  id: k.id,
                  public_key: k.public_key,
                  vault_secret_ref: k.vault_secret_ref,
                  key_version: s.key_version,
                  ciphertext: s.ciphertext,
                  nonce: s.nonce,
                  auth_tag: s.auth_tag,
                  ciphertext_sha256: s.ciphertext_sha256,
                },
              ] as R[],
            };
          }
        }
        return { rows: [] };
      }

      if (t.startsWith("SELECT k.id, k.public_key, k.vault_secret_ref FROM node_signing_keys")) {
        const nodeId = params[0];
        const purpose = params[1];
        const out: Activeish[] = [];
        for (const k of keys.values()) {
          if (
            k.node_id === nodeId &&
            k.purpose === purpose &&
            k.retired_at == null &&
            !sealed.has(String(k.vault_secret_ref))
          ) {
            out.push({
              id: String(k.id),
              public_key: String(k.public_key),
              vault_secret_ref: String(k.vault_secret_ref),
            });
          }
        }
        return { rows: out as R[] };
      }

      if (t.startsWith("UPDATE node_signing_keys SET retired_at")) {
        const nodeId = params[0];
        const purpose = params[1];
        const exceptId = params.length >= 3 ? String(params[2]) : undefined;
        for (const k of keys.values()) {
          if (
            k.node_id === nodeId &&
            k.purpose === purpose &&
            k.retired_at == null &&
            (exceptId === undefined || String(k.id) !== exceptId)
          ) {
            k.retired_at = "now";
          }
        }
        return { rows: [] };
      }

      if (t.startsWith("INSERT INTO node_signing_key_sealed_store")) {
        const [ref, kv, ct, nonce, tag, sha] = params;
        sealed.set(String(ref), {
          vault_secret_ref: ref,
          key_version: kv,
          ciphertext: ct,
          nonce,
          auth_tag: tag,
          ciphertext_sha256: sha,
        });
        return { rows: [] };
      }

      if (t.startsWith("INSERT INTO node_signing_keys")) {
        const [id, nodeId, purpose, pub, ref] = params;
        // Simulate partial unique one-active-(node,purpose).
        for (const k of keys.values()) {
          if (k.node_id === nodeId && k.purpose === purpose && k.retired_at == null) {
            throw Object.assign(new Error("duplicate key value violates unique constraint"), {
              code: "23505",
            });
          }
        }
        keys.set(String(id), {
          id,
          node_id: nodeId,
          purpose,
          public_key: pub,
          vault_secret_ref: ref,
          retired_at: null,
        });
        return { rows: [] };
      }

      if (t.startsWith("UPDATE nodes SET identity_public_key")) {
        const [nodeId, pub] = params;
        nodes.set(String(nodeId), String(pub));
        return { rows: [] };
      }

      throw new Error(`unexpected SQL in memory ensure harness: ${t.slice(0, 80)}`);
    },
  };

  return { sql, sealed, keys, nodes };
}

interface Activeish {
  id: string;
  public_key: string;
  vault_secret_ref: string;
}

describe("ensureActiveNodeSigningKey", () => {
  it("mints once then reopens the same public key", async () => {
    const { sql, keys, nodes } = makeMemorySql();
    const first = await ensureActiveNodeSigningKey({
      sql,
      rootKey: ROOT,
      nodeId: NODE_ID,
      purpose: "NODE_IDENTITY",
    });
    expect(keys.size).toBe(1);
    expect(nodes.get(NODE_ID)).toBe(first.publicKey);

    const second = await ensureActiveNodeSigningKey({
      sql,
      rootKey: ROOT,
      nodeId: NODE_ID,
      purpose: "NODE_IDENTITY",
    });
    expect(second.publicKey).toBe(first.publicKey);
    expect(second.signingKeyId).toBe(first.signingKeyId);
    expect(keys.size).toBe(1);

    const sig = first.sign(Buffer.from("zp-expected-preimage"));
    expect(sig.length).toBe(64);
    const sig2 = second.sign(Buffer.from("zp-expected-preimage"));
    expect(Buffer.from(sig2)).toEqual(Buffer.from(sig));
  });

  it("refuses to reopen an active sealed identity under the wrong root", async () => {
    const { sql } = makeMemorySql();
    await ensureActiveNodeSigningKey({
      sql,
      rootKey: ROOT,
      nodeId: NODE_ID,
      purpose: "NODE_IDENTITY",
      seedOverride: Buffer.alloc(32, 0x42),
    });

    await expect(
      ensureActiveNodeSigningKey({
        sql,
        rootKey: NEW_ROOT,
        nodeId: NODE_ID,
        purpose: "NODE_IDENTITY",
      }),
    ).rejects.toThrow(VaultOpenError);
  });

  it("seed override produces a deterministic public key on first mint", async () => {
    const { sql } = makeMemorySql();
    const seed = Buffer.alloc(32, 0x55);
    const expectedPub = publicKeyFromEd25519Seed(seed);
    const first = await ensureActiveNodeSigningKey({
      sql,
      rootKey: ROOT,
      nodeId: NODE_ID,
      purpose: "NODE_IDENTITY",
      seedOverride: seed,
    });
    expect(first.publicKey).toBe(expectedPub);

    // Second call with a *different* override still prefers sealed active row.
    const other = Buffer.alloc(32, 0x66);
    const second = await ensureActiveNodeSigningKey({
      sql,
      rootKey: ROOT,
      nodeId: NODE_ID,
      purpose: "NODE_IDENTITY",
      seedOverride: other,
    });
    expect(second.publicKey).toBe(expectedPub);
  });

  it("refuses short seedOverride instead of silent CSPRNG mint", async () => {
    const { sql, keys } = makeMemorySql();
    await expect(
      ensureActiveNodeSigningKey({
        sql,
        rootKey: ROOT,
        nodeId: NODE_ID,
        purpose: "NODE_IDENTITY",
        seedOverride: Buffer.alloc(16, 0x01),
      }),
    ).rejects.toThrow(/exactly 32 bytes/);
    expect(keys.size).toBe(0);
  });

  it("seal-fills pre-923 public-only row when seed matches", async () => {
    const { sql, keys, sealed, nodes } = makeMemorySql();
    const seed = Buffer.alloc(32, 0xab);
    const publicKey = publicKeyFromEd25519Seed(seed);
    const keyId = randomUUID();
    const vaultRef = randomUUID();
    keys.set(keyId, {
      id: keyId,
      node_id: NODE_ID,
      purpose: "NODE_IDENTITY",
      public_key: publicKey,
      vault_secret_ref: vaultRef,
      retired_at: null,
    });
    expect(sealed.size).toBe(0);

    const signer = await ensureActiveNodeSigningKey({
      sql,
      rootKey: ROOT,
      nodeId: NODE_ID,
      purpose: "NODE_IDENTITY",
      seedOverride: seed,
    });
    expect(signer.signingKeyId).toBe(keyId);
    expect(signer.publicKey).toBe(publicKey);
    expect(sealed.has(vaultRef)).toBe(true);
    expect(keys.size).toBe(1);
    expect(nodes.get(NODE_ID)).toBe(publicKey);
    const sig = signer.sign(Buffer.from("pre-923-upgrade"));
    expect(sig.length).toBe(64);
  });

  it("retires unmatched public-only orphan and mints sealed (no dual-active)", async () => {
    const { sql, keys, sealed } = makeMemorySql();
    const orphanSeed = Buffer.alloc(32, 0xcd);
    const orphanPub = publicKeyFromEd25519Seed(orphanSeed);
    const orphanId = randomUUID();
    keys.set(orphanId, {
      id: orphanId,
      node_id: NODE_ID,
      purpose: "NODE_IDENTITY",
      public_key: orphanPub,
      vault_secret_ref: randomUUID(),
      retired_at: null,
    });

    const newSeed = Buffer.alloc(32, 0xef);
    const signer = await ensureActiveNodeSigningKey({
      sql,
      rootKey: ROOT,
      nodeId: NODE_ID,
      purpose: "NODE_IDENTITY",
      seedOverride: newSeed,
    });
    expect(signer.publicKey).toBe(publicKeyFromEd25519Seed(newSeed));
    expect(signer.signingKeyId).not.toBe(orphanId);
    expect(keys.get(orphanId)?.retired_at).not.toBeNull();
    const active = [...keys.values()].filter((k) => k.retired_at == null);
    expect(active).toHaveLength(1);
    expect(sealed.size).toBe(1);
  });

  it("retires public-only orphan and CSPRNG-mints when seedOverride absent", async () => {
    const { sql, keys, sealed, nodes } = makeMemorySql();
    const orphanId = randomUUID();
    keys.set(orphanId, {
      id: orphanId,
      node_id: NODE_ID,
      purpose: "NODE_IDENTITY",
      public_key: publicKeyFromEd25519Seed(Buffer.alloc(32, 0x11)),
      vault_secret_ref: randomUUID(),
      retired_at: null,
    });

    const signer = await ensureActiveNodeSigningKey({
      sql,
      rootKey: ROOT,
      nodeId: NODE_ID,
      purpose: "NODE_IDENTITY",
    });
    expect(signer.signingKeyId).not.toBe(orphanId);
    expect(keys.get(orphanId)?.retired_at).not.toBeNull();
    expect(sealed.size).toBe(1);
    expect(nodes.get(NODE_ID)).toBe(signer.publicKey);
  });

  it("does not embed seed bytes in error messages", async () => {
    const seed = Buffer.alloc(32, 0x77);
    const seedHex = Buffer.from(seed).toString("hex");
    try {
      await ensureActiveNodeSigningKey({
        sql: {
          async query() {
            throw new Error("db down");
          },
        },
        rootKey: ROOT,
        nodeId: NODE_ID,
        purpose: "NODE_IDENTITY",
        seedOverride: seed,
      });
      expect.unreachable("should throw");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      expect(msg).not.toContain(seedHex);
      expect(msg).not.toMatch(/[A-Za-z0-9+/]{40,}={0,2}/); // no large base64 blob
    }
  });

  it("refuses unknown purpose before any durable write", async () => {
    const { sql, keys } = makeMemorySql();
    await expect(
      ensureActiveNodeSigningKey({
        sql,
        rootKey: ROOT,
        nodeId: NODE_ID,
        purpose: "WALLET",
      }),
    ).rejects.toThrow(/unknown signing-key purpose/);
    expect(keys.size).toBe(0);
  });
});

describe("hygiene: checkpoints do not hash secrets into fixtures", () => {
  it("public key digest is independent of root material", () => {
    const seed = Buffer.alloc(32, 0x01);
    const pub = publicKeyFromEd25519Seed(seed);
    const digest = createHash("sha256").update(pub).digest("hex");
    expect(digest).toHaveLength(64);
    expect(digest).not.toContain(Buffer.from(ROOT).toString("hex").slice(0, 16));
  });
});

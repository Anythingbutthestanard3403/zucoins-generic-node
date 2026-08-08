// The vault root-KDF salt resolver (ZTR-1159).
//
// The single most important assertion in this file is the first one: an envelope sealed under
// the pre-ZTR-1159 hardcoded literal still opens after the change, with VAULT_ROOT_SALT_B64
// unset. Every deployment in existence sealed under that literal; if this test goes red the
// change is a total custody loss, not a regression.
//
// The second is that a salt mismatch fails loudly and early — a specific named error at the
// resolver, not a generic decrypt failure surfacing three steps into a recovery ceremony.
//
// Nothing here writes key material to disk or logs it. The "master keys" below are fixtures.

import { randomBytes, randomUUID } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  DEK_LENGTH_BYTES,
  ROOT_KDF_HASH,
  ROOT_KDF_ITERATIONS,
  SUPPORTED_ENVELOPE_VERSION,
  deriveEd25519PublicKeyBase64Url,
  deriveRootKey,
  sealWalletSecret,
  openWalletSecret,
  type WalletIdentity,
} from "@zucoins/node-core";

import {
  GENESIS_ROOT_KDF_SALT_BYTES,
  HISTORICAL_ROOT_KDF_SALT,
  MIN_ROOT_KDF_SALT_BYTES,
  VaultRootSaltError,
  assertRootKeyOpensSealedEnvelope,
  decodeRootKdfSaltB64,
  loadPersistedRootKdfSalt,
  reconcileRootKdfSalt,
  resolveCeremonyRootKdfSalt,
  resolveConfiguredRootKdfSalt,
  type RootKdfSaltSource,
  type RootKdfSaltSqlExecutor,
} from "../../src/vault/root-kdf-salt.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const MASTER_KEY = "root-kdf-salt-fixture-master-key-32b!!!!";

/**
 * A real Ed25519 keypair in the 64-byte libsodium layout the vault seals (seed || pubkey).
 * `deriveEd25519PublicKeyBase64Url` reads only the seed half, so the public half of the secret
 * is reconstructed from the derived key rather than guessed — the open path re-derives it and
 * rejects a mismatch.
 */
function mintWallet(): { identity: WalletIdentity; secretKey: Buffer; walletId: string } {
  const walletId = randomUUID();
  const seed = randomBytes(32);
  const publicKey = deriveEd25519PublicKeyBase64Url(Buffer.concat([seed, Buffer.alloc(32)]));
  if (publicKey === null) throw new Error("fixture keypair did not derive a public key");
  const secretKey = Buffer.concat([seed, Buffer.from(publicKey, "base64url")]);
  return {
    walletId,
    secretKey,
    identity: {
      nodeId: NODE_ID,
      walletId,
      keyVersion: 1,
      publicKey,
      keyOrigin: "node_generated",
    },
  };
}

/**
 * A SQL fake that answers exactly the three statements this module issues, keyed on a
 * distinguishing fragment rather than the full text (which carries formatting).
 */
function makeSql(options: {
  salt?: { salt: Buffer; source: RootKdfSaltSource };
  sealedWallets?: readonly {
    identity: WalletIdentity;
    envelope: ReturnType<typeof sealWalletSecret>;
  }[];
}): RootKdfSaltSqlExecutor & { inserts: unknown[][] } {
  let row = options.salt;
  const sealed = options.sealedWallets ?? [];
  const inserts: unknown[][] = [];
  return {
    inserts,
    async query<T>(text: string, params: readonly unknown[] = []): Promise<{ rows: T[] }> {
      if (text.includes("SELECT salt, source FROM vault_root_kdf_salt")) {
        return { rows: (row === undefined ? [] : [{ salt: row.salt, source: row.source }]) as T[] };
      }
      if (text.includes("INSERT INTO vault_root_kdf_salt")) {
        inserts.push([...params]);
        // ON CONFLICT DO NOTHING semantics: an existing row wins.
        row ??= { salt: params[1] as Buffer, source: params[2] as RootKdfSaltSource };
        return { rows: [] as T[] };
      }
      if (text.includes("AS present")) {
        return { rows: [{ present: sealed.length > 0 }] as T[] };
      }
      if (text.includes("INNER JOIN vault v ON v.wallet_id = w.id")) {
        return {
          rows: sealed.map((w) => ({
            id: w.identity.walletId,
            node_id: w.identity.nodeId,
            public_key: w.identity.publicKey,
            key_origin: w.identity.keyOrigin,
            key_version: w.identity.keyVersion,
            ciphertext: Buffer.from(w.envelope.ciphertext),
            nonce: Buffer.from(w.envelope.nonce),
            auth_tag: Buffer.from(w.envelope.authTag),
            ciphertext_sha256: w.envelope.ciphertextSha256,
          })) as T[],
        };
      }
      throw new Error(`unexpected SQL: ${text.slice(0, 80)}`);
    },
  };
}

describe("backward compatibility — the historical salt still opens historical envelopes", () => {
  it("opens an envelope sealed under the hardcoded literal with VAULT_ROOT_SALT_B64 unset", () => {
    // Seal exactly as every node shipped to date did: the literal, byte for byte.
    const legacySalt = Buffer.from("zupayments-vault-root-kdf-salt-v1", "utf8");
    const legacyRoot = deriveRootKey(MASTER_KEY, legacySalt);
    const wallet = mintWallet();
    const envelope = sealWalletSecret(legacyRoot, wallet.identity, wallet.secretKey);

    // Open through the resolver, with nothing configured.
    const resolved = resolveConfiguredRootKdfSalt({});
    expect(resolved.source).toBe("historical_default");
    const rootKey = deriveRootKey(MASTER_KEY, resolved.salt);

    const opened = openWalletSecret(rootKey, envelope, wallet.identity);
    try {
      expect(Buffer.from(opened.bytes).equals(wallet.secretKey)).toBe(true);
    } finally {
      opened.wipe();
    }
  });

  it("the exported historical salt is the literal itself, unchanged", () => {
    expect(HISTORICAL_ROOT_KDF_SALT.toString("utf8")).toBe("zupayments-vault-root-kdf-salt-v1");
  });

  it("never hands out the shared historical buffer — a wiping caller cannot zero it", () => {
    // The master-key rotation CLI zeroes its salt in a `finally`. Returning the module-level
    // constant there would leave every later derivation in the process on 33 zero bytes.
    const resolved = resolveConfiguredRootKdfSalt({});
    expect(resolved.salt).not.toBe(HISTORICAL_ROOT_KDF_SALT);
    resolved.salt.fill(0);
    expect(HISTORICAL_ROOT_KDF_SALT.toString("utf8")).toBe("zupayments-vault-root-kdf-salt-v1");
  });

  it("a node with sealed material and no persisted row is bound to the historical salt", async () => {
    const wallet = mintWallet();
    const legacyRoot = deriveRootKey(MASTER_KEY, HISTORICAL_ROOT_KDF_SALT);
    const sql = makeSql({
      sealedWallets: [
        { identity: wallet.identity, envelope: sealWalletSecret(legacyRoot, wallet.identity, wallet.secretKey) },
      ],
    });

    const result = await reconcileRootKdfSalt({
      sql,
      nodeId: NODE_ID,
      configured: resolveConfiguredRootKdfSalt({}),
    });

    expect(result.source).toBe("historical_default");
    expect(result.rederive).toBe(false);
    expect(result.persisted).toBe(true);
    expect(Buffer.from(result.salt).equals(HISTORICAL_ROOT_KDF_SALT)).toBe(true);
    // The upgrade wrote the row so the provenance survives, and the derived key still opens.
    expect(sql.inserts).toHaveLength(1);
    await expect(
      assertRootKeyOpensSealedEnvelope({
        sql,
        nodeId: NODE_ID,
        rootKey: deriveRootKey(MASTER_KEY, result.salt),
        saltSource: result.source,
      }),
    ).resolves.toMatchObject({ checked: true, walletId: wallet.walletId });
  });
});

describe("a salt mismatch fails loudly, early, and by name", () => {
  it("refuses a configured salt that disagrees with the persisted one", async () => {
    const sql = makeSql({ salt: { salt: HISTORICAL_ROOT_KDF_SALT, source: "historical_default" } });
    const configured = resolveConfiguredRootKdfSalt({
      VAULT_ROOT_SALT_B64: randomBytes(32).toString("base64"),
    });

    const err = await reconcileRootKdfSalt({ sql, nodeId: NODE_ID, configured }).catch((e) => e);

    expect(err).toBeInstanceOf(VaultRootSaltError);
    expect((err as VaultRootSaltError).code).toBe("VAULT_ROOT_SALT_MISMATCH");
    // Refused before anything opened an envelope, and without echoing salt bytes.
    expect((err as Error).message).toContain("VAULT_ROOT_SALT_B64");
    expect((err as Error).message).not.toContain(configured.salt.toString("base64"));
  });

  it("a recovery ceremony refuses the same disagreement, and never writes a row", async () => {
    const sql = makeSql({ salt: { salt: HISTORICAL_ROOT_KDF_SALT, source: "historical_default" } });

    const err = await resolveCeremonyRootKdfSalt({
      sql,
      nodeId: NODE_ID,
      env: { VAULT_ROOT_SALT_B64: randomBytes(32).toString("base64") },
    }).catch((e) => e);

    expect(err).toBeInstanceOf(VaultRootSaltError);
    expect((err as VaultRootSaltError).code).toBe("VAULT_ROOT_SALT_MISMATCH");
    expect(sql.inserts).toHaveLength(0);
  });

  it("the derivation self-check names the failure instead of surfacing a generic decrypt error", async () => {
    const wallet = mintWallet();
    const sealed = sealWalletSecret(
      deriveRootKey(MASTER_KEY, HISTORICAL_ROOT_KDF_SALT),
      wallet.identity,
      wallet.secretKey,
    );
    const sql = makeSql({ sealedWallets: [{ identity: wallet.identity, envelope: sealed }] });

    // The exact shape of the trap the ticket describes: a rotation ran under some other salt.
    const wrongRoot = deriveRootKey(MASTER_KEY, randomBytes(GENESIS_ROOT_KDF_SALT_BYTES));

    const err = await assertRootKeyOpensSealedEnvelope({
      sql,
      nodeId: NODE_ID,
      rootKey: wrongRoot,
      saltSource: "environment",
    }).catch((e) => e);

    expect(err).toBeInstanceOf(VaultRootSaltError);
    expect((err as VaultRootSaltError).code).toBe("VAULT_ROOT_KEY_DOES_NOT_OPEN");
    expect((err as Error).message).toContain(wallet.walletId);
  });

  it("a node that has sealed nothing passes the self-check rather than blocking first boot", async () => {
    await expect(
      assertRootKeyOpensSealedEnvelope({
        sql: makeSql({}),
        nodeId: NODE_ID,
        rootKey: deriveRootKey(MASTER_KEY, HISTORICAL_ROOT_KDF_SALT),
        saltSource: "genesis_random",
      }),
    ).resolves.toMatchObject({ checked: false });
  });
});

describe("configuration resolution", () => {
  it("prefers VAULT_ROOT_SALT_B64 over the historical default", () => {
    const salt = randomBytes(32);
    const resolved = resolveConfiguredRootKdfSalt({ VAULT_ROOT_SALT_B64: salt.toString("base64") });
    expect(resolved.source).toBe("environment");
    expect(Buffer.from(resolved.salt).equals(salt)).toBe(true);
  });

  it("accepts URL-safe base64, so an operator keeps whichever encoding they recorded", () => {
    const salt = Buffer.from("ff".repeat(32), "hex");
    const std = decodeRootKdfSaltB64(salt.toString("base64"));
    const url = decodeRootKdfSaltB64(salt.toString("base64url"));
    expect(std.equals(salt)).toBe(true);
    expect(url.equals(salt)).toBe(true);
  });

  it("treats a blank value as unset rather than as a zero-length salt", () => {
    expect(resolveConfiguredRootKdfSalt({ VAULT_ROOT_SALT_B64: "   " }).source).toBe(
      "historical_default",
    );
  });

  it(`refuses a salt shorter than ${MIN_ROOT_KDF_SALT_BYTES} bytes without echoing it`, () => {
    const err = (() => {
      try {
        decodeRootKdfSaltB64(Buffer.from("short").toString("base64"));
      } catch (e) {
        return e;
      }
      return null;
    })();
    expect(err).toBeInstanceOf(VaultRootSaltError);
    expect((err as VaultRootSaltError).code).toBe("VAULT_ROOT_SALT_MALFORMED");
    expect((err as Error).message).not.toContain("short");
  });
});

describe("genesis mints a per-deployment salt", () => {
  it("mints and persists a random salt on a node that has sealed nothing", async () => {
    const sql = makeSql({});
    const result = await reconcileRootKdfSalt({
      sql,
      nodeId: NODE_ID,
      configured: resolveConfiguredRootKdfSalt({}),
    });

    expect(result.source).toBe("genesis_random");
    expect(result.persisted).toBe(true);
    expect(result.salt.length).toBe(GENESIS_ROOT_KDF_SALT_BYTES);
    // Not the historical literal — that is the whole point of minting one.
    expect(Buffer.from(result.salt).equals(HISTORICAL_ROOT_KDF_SALT)).toBe(false);
    // The caller must re-derive: the configured resolution was the historical default.
    expect(result.rederive).toBe(true);
    expect(sql.inserts[0]?.[2]).toBe("genesis_random");
  });

  it("two nodes do not share a salt", async () => {
    const a = await reconcileRootKdfSalt({
      sql: makeSql({}),
      nodeId: NODE_ID,
      configured: resolveConfiguredRootKdfSalt({}),
    });
    const b = await reconcileRootKdfSalt({
      sql: makeSql({}),
      nodeId: randomUUID(),
      configured: resolveConfiguredRootKdfSalt({}),
    });
    expect(Buffer.from(a.salt).equals(Buffer.from(b.salt))).toBe(false);
  });

  it("the second boot reads the minted salt back and asks for no further re-derivation", async () => {
    const minted = randomBytes(GENESIS_ROOT_KDF_SALT_BYTES);
    const sql = makeSql({ salt: { salt: minted, source: "genesis_random" } });

    const first = await reconcileRootKdfSalt({
      sql,
      nodeId: NODE_ID,
      configured: resolveConfiguredRootKdfSalt({}),
    });
    expect(first.rederive).toBe(true); // configuration still resolves to the historical default
    expect(Buffer.from(first.salt).equals(minted)).toBe(true);
    expect(sql.inserts).toHaveLength(0); // never rewrites an existing row

    // Deriving under the salt the row names is what actually opens this node's envelopes.
    const wallet = mintWallet();
    const envelope = sealWalletSecret(deriveRootKey(MASTER_KEY, minted), wallet.identity, wallet.secretKey);
    const withWallet = makeSql({
      salt: { salt: minted, source: "genesis_random" },
      sealedWallets: [{ identity: wallet.identity, envelope }],
    });
    await expect(
      assertRootKeyOpensSealedEnvelope({
        sql: withWallet,
        nodeId: NODE_ID,
        rootKey: deriveRootKey(MASTER_KEY, first.salt),
        saltSource: first.source,
      }),
    ).resolves.toMatchObject({ checked: true });
  });

  it("an operator-supplied salt on a virgin node is persisted verbatim, not replaced", async () => {
    const supplied = randomBytes(24);
    const sql = makeSql({});
    const result = await reconcileRootKdfSalt({
      sql,
      nodeId: NODE_ID,
      configured: resolveConfiguredRootKdfSalt({ VAULT_ROOT_SALT_B64: supplied.toString("base64") }),
    });
    expect(result.source).toBe("environment");
    expect(Buffer.from(result.salt).equals(supplied)).toBe(true);
    expect(result.rederive).toBe(false);
  });

  it("a lost first-boot race refuses rather than proceeding under the salt that did not stick", async () => {
    const winner = randomBytes(GENESIS_ROOT_KDF_SALT_BYTES);
    // No row on the first read, but the INSERT hits ON CONFLICT DO NOTHING against a row
    // another replica has already committed.
    let reads = 0;
    const sql: RootKdfSaltSqlExecutor = {
      async query<T>(text: string): Promise<{ rows: T[] }> {
        if (text.includes("SELECT salt, source FROM vault_root_kdf_salt")) {
          reads += 1;
          return {
            rows: (reads === 1 ? [] : [{ salt: winner, source: "genesis_random" }]) as T[],
          };
        }
        if (text.includes("INSERT INTO vault_root_kdf_salt")) return { rows: [] as T[] };
        throw new Error(`unexpected SQL: ${text.slice(0, 60)}`);
      },
    };

    const err = await reconcileRootKdfSalt({
      sql,
      nodeId: NODE_ID,
      configured: resolveConfiguredRootKdfSalt({
        VAULT_ROOT_SALT_B64: randomBytes(32).toString("base64"),
      }),
    }).catch((e) => e);

    expect(err).toBeInstanceOf(VaultRootSaltError);
    expect((err as VaultRootSaltError).code).toBe("VAULT_ROOT_SALT_MISMATCH");
  });
});

describe("persisted-row hygiene", () => {
  it("refuses a persisted salt below the minimum length instead of deriving under it", async () => {
    const sql = makeSql({ salt: { salt: Buffer.alloc(4), source: "genesis_random" } });
    const err = await loadPersistedRootKdfSalt(sql, NODE_ID).catch((e) => e);
    expect(err).toBeInstanceOf(VaultRootSaltError);
    expect((err as VaultRootSaltError).code).toBe("VAULT_ROOT_SALT_MALFORMED");
  });

  it("decodes a bytea returned as a hex-escaped string", async () => {
    const salt = randomBytes(32);
    const sql: RootKdfSaltSqlExecutor = {
      async query<T>(): Promise<{ rows: T[] }> {
        return { rows: [{ salt: `\\x${salt.toString("hex")}`, source: "genesis_random" }] as T[] };
      },
    };
    const loaded = await loadPersistedRootKdfSalt(sql, NODE_ID);
    expect(Buffer.from(loaded!.salt).equals(salt)).toBe(true);
  });
});

describe("the KDF itself is untouched", () => {
  // ZTR-1159 changes which salt is chosen and nothing else. These pins exist so a future
  // edit to the derivation cannot ride along in a commit whose migration story is only
  // about the salt — the ticket calls that out explicitly.
  it("pins PBKDF2 at 600_000 iterations of SHA-256 producing a 32-byte root", () => {
    expect(ROOT_KDF_ITERATIONS).toBe(600_000);
    expect(ROOT_KDF_HASH).toBe("sha256");
    expect(DEK_LENGTH_BYTES).toBe(32);
    expect(deriveRootKey(MASTER_KEY, HISTORICAL_ROOT_KDF_SALT)).toHaveLength(32);
  });

  it("pins the derivation to a known-answer vector", () => {
    // Regenerating this constant means the KDF changed — which this ticket forbids.
    expect(deriveRootKey("known-answer-master-key-fixture!!", Buffer.from("kat-salt", "utf8"))
      .toString("hex")).toBe(
      "f02eaa8c8a65f27b3efe03ccbc4f608a4f03714081d50ed570be9cff72919db2",
    );
  });

  it("pins the AEAD envelope shape (AES-256-GCM: 12-byte nonce, 16-byte tag, v1 AAD domain)", () => {
    const wallet = mintWallet();
    const envelope = sealWalletSecret(
      deriveRootKey(MASTER_KEY, HISTORICAL_ROOT_KDF_SALT),
      wallet.identity,
      wallet.secretKey,
    );
    expect(envelope.nonce).toHaveLength(12);
    expect(envelope.authTag).toHaveLength(16);
    expect(envelope.ciphertext).toHaveLength(64);
    expect(SUPPORTED_ENVELOPE_VERSION).toBe(1);
  });

  it("the HKDF step still binds the DEK to node, wallet and key version", () => {
    // Proven behaviourally: the same root key opens an envelope only under the identity it
    // was sealed for. If HKDF stopped consuming key_version this would decrypt.
    const wallet = mintWallet();
    const root = deriveRootKey(MASTER_KEY, HISTORICAL_ROOT_KDF_SALT);
    const envelope = sealWalletSecret(root, wallet.identity, wallet.secretKey);
    expect(() =>
      openWalletSecret(root, { ...envelope, keyVersion: 2 }, { ...wallet.identity, keyVersion: 2 }),
    ).toThrow();
  });
});

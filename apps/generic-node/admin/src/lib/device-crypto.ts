/**
 * Browser WebCrypto Ed25519 device key + suite preimage helpers.
 *
 * Private keys stay non-extractable in IndexedDB (never localStorage, never
 * platform, never logged). Signing uses SubtleCrypto over exact UTF-8 preimage
 * bytes — the server rebuilds the same bytes via suite builders.
 *
 * Ceremony signatures are valid for at most 300s from issued_at; TOTP is the floor.
 */

const DB_NAME = "zu-node-device-keys";
const DB_VERSION = 1;
const STORE = "keys";
const CEREMONY_WINDOW_MS = 300_000;

export const DEVICE_CEREMONY_WINDOW_MS = CEREMONY_WINDOW_MS;

export interface StoredDeviceRecord {
  readonly id: string;
  readonly label: string;
  readonly publicKey: string;
  readonly createdAt: string;
  readonly nodeId: string;
  /** Non-extractable CryptoKey — never serialised to JSON. */
  readonly privateKey: CryptoKey;
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { keyPath: "id" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("indexedDB open failed"));
  });
}

function idbReq<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("indexedDB request failed"));
  });
}

/** Padded base64url (RFC 4648 section 5 with `=` pad) — matches node-core suite encoders. */
export function bytesToPaddedBase64Url(bytes: ArrayBuffer | Uint8Array): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]!);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_");
}

export function paddedBase64UrlToBytes(text: string): Uint8Array {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function randomUuid(): string {
  return crypto.randomUUID();
}

/**
 * Generate a non-extractable Ed25519 device keypair.
 * Public key is exported as padded base64url (32 raw bytes).
 */
export async function generateDeviceKeyPair(): Promise<{
  readonly privateKey: CryptoKey;
  readonly publicKey: string;
  readonly publicKeyRaw: Uint8Array;
}> {
  const pair = (await crypto.subtle.generateKey("Ed25519", false, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const spki = await crypto.subtle.exportKey("spki", pair.publicKey);
  // SPKI for Ed25519 is 12-byte DER prefix + 32 raw bytes.
  const raw = new Uint8Array(spki).slice(-32);
  return {
    privateKey: pair.privateKey,
    publicKey: bytesToPaddedBase64Url(raw),
    publicKeyRaw: raw,
  };
}

/** Sign exact UTF-8 preimage bytes; return padded base64url signature. */
export async function signPreimage(
  privateKey: CryptoKey,
  preimageText: string,
): Promise<string> {
  const bytes = new TextEncoder().encode(preimageText);
  const sig = await crypto.subtle.sign("Ed25519", privateKey, bytes);
  return bytesToPaddedBase64Url(sig);
}

export async function sha256Hex(preimageText: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(preimageText),
  );
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function putDeviceRecord(record: StoredDeviceRecord): Promise<void> {
  const db = await openDb();
  try {
    const tx = db.transaction(STORE, "readwrite");
    await idbReq(tx.objectStore(STORE).put(record));
  } finally {
    db.close();
  }
}

export async function getDeviceRecord(id: string): Promise<StoredDeviceRecord | null> {
  const db = await openDb();
  try {
    const tx = db.transaction(STORE, "readonly");
    const row = await idbReq(tx.objectStore(STORE).get(id));
    return (row as StoredDeviceRecord | undefined) ?? null;
  } finally {
    db.close();
  }
}

export async function listLocalDeviceRecords(): Promise<
  readonly Omit<StoredDeviceRecord, "privateKey">[]
> {
  const db = await openDb();
  try {
    const tx = db.transaction(STORE, "readonly");
    const rows = (await idbReq(tx.objectStore(STORE).getAll())) as StoredDeviceRecord[];
    return rows.map(({ id, label, publicKey, createdAt, nodeId }) => ({
      id,
      label,
      publicKey,
      createdAt,
      nodeId,
    }));
  } finally {
    db.close();
  }
}

export async function deleteLocalDeviceRecord(id: string): Promise<void> {
  const db = await openDb();
  try {
    const tx = db.transaction(STORE, "readwrite");
    await idbReq(tx.objectStore(STORE).delete(id));
  } finally {
    db.close();
  }
}

/**
 * Build zp-destination-bless-v1 preimage with field insertion order matching
 * the suite registry (purpose, canonical_version, node_id, destination_id,
 * wallet_id, wallet_pubkey, nonce, issued_at, expires_at).
 * Callers MUST use server-issued timestamps within 300s.
 */
export function buildDestinationBlessPreimage(fields: {
  readonly node_id: string;
  readonly destination_id: string;
  readonly wallet_id: string;
  readonly wallet_pubkey: string;
  readonly nonce: string;
  readonly issued_at: string;
  readonly expires_at: string;
}): string {
  const payload = {
    purpose: "zp-destination-bless-v1",
    canonical_version: 1,
    node_id: fields.node_id,
    destination_id: fields.destination_id,
    wallet_id: fields.wallet_id,
    wallet_pubkey: fields.wallet_pubkey,
    nonce: fields.nonce,
    issued_at: fields.issued_at,
    expires_at: fields.expires_at,
  };
  return `zp-destination-bless-v1\n${JSON.stringify(payload)}`;
}

/**
 * Build zp-device-enrol-v1 preimage. Server rebuilds from the same challenge
 * fields — keep insertion order identical to suite registry.
 */
export function buildDeviceEnrolPreimage(fields: {
  readonly node_id: string;
  readonly new_device_key_id: string;
  readonly new_device_public_key: string;
  readonly label: string;
  readonly nonce: string;
  readonly issued_at: string;
  readonly expires_at: string;
}): string {
  const payload = {
    purpose: "zp-device-enrol-v1",
    canonical_version: 1,
    node_id: fields.node_id,
    new_device_key_id: fields.new_device_key_id,
    new_device_public_key: fields.new_device_public_key,
    label: fields.label,
    nonce: fields.nonce,
    issued_at: fields.issued_at,
    expires_at: fields.expires_at,
  };
  return `zp-device-enrol-v1\n${JSON.stringify(payload)}`;
}

/** Ceremony window helpers — max 300s from issued_at. */
export function ceremonyWindowFromNow(nowMs: number = Date.now()): {
  readonly issued_at: string;
  readonly expires_at: string;
} {
  const issued = new Date(nowMs);
  const expires = new Date(nowMs + CEREMONY_WINDOW_MS);
  return {
    issued_at: issued.toISOString(),
    expires_at: expires.toISOString(),
  };
}

export function isCeremonyLive(issuedAt: string, expiresAt: string, nowMs: number = Date.now()): boolean {
  const issued = Date.parse(issuedAt);
  const expires = Date.parse(expiresAt);
  if (!Number.isFinite(issued) || !Number.isFinite(expires)) return false;
  if (expires <= issued) return false;
  if (expires - issued > CEREMONY_WINDOW_MS) return false;
  return nowMs >= issued && nowMs <= expires;
}

/**
 * Sign a revoke identity proof. Shape is node-local (not a money tuple);
 * server validates padded base64url Ed25519 length + enrolled authorizer.
 */
export async function signRevokeProof(
  privateKey: CryptoKey,
  fields: {
    readonly node_id: string;
    readonly target_device_key_id: string;
    readonly authorizing_device_key_id: string;
  },
): Promise<string> {
  const preimage = `zp-device-revoke-v1\n${JSON.stringify({
    purpose: "zp-device-revoke-v1",
    node_id: fields.node_id,
    target_device_key_id: fields.target_device_key_id,
    authorizing_device_key_id: fields.authorizing_device_key_id,
  })}`;
  return signPreimage(privateKey, preimage);
}

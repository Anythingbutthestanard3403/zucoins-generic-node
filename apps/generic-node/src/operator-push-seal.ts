// At-rest seal for operator Web Push auth secrets.
// Separate from wallet push_subscriptions and vault-rooted push/seal.ts.
//
// Key source (first match):
//   1. OPERATOR_PUSH_SEAL_KEY — 32 raw bytes as 64 hex chars, or base64/base64url of 32 bytes
//   2. Process-local random key (dev/test) — subscriptions sealed under this key work
//      until restart; documented residual when env unset.
//
// Envelope: zp-op-push-auth-v1.<base64(nonce||tag||ciphertext)>  AES-256-gcm, empty AAD.
// Never log plaintext auth. Open is used only by an injected OperatorPushSender.
//
// Delivery: no undeclared npm dependency (boundary census). Mount wires sealAuth always;
// optional sender is injected when the operator provides one (tests / future VAPID adapter).
// When VAPID_* env is set but no sender is injected, subscribe still stores real sealed
// auth and notifyOperatorsPendingAttention is fail-soft no-op delivery (inbox authoritative).

import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

const PREFIX = "zp-op-push-auth-v1";
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;

export class OperatorPushSealError extends Error {
  readonly code = "OPERATOR_PUSH_SEAL_FAILED";
  constructor(message: string) {
    super(message);
    this.name = "OperatorPushSealError";
  }
}

function parseKeyMaterial(raw: string): Buffer | null {
  const t = raw.trim();
  if (t.length === 0) return null;
  if (/^[0-9a-fA-F]{64}$/u.test(t)) {
    return Buffer.from(t, "hex");
  }
  try {
    const b64 = t.replace(/-/g, "+").replace(/_/g, "/");
    const buf = Buffer.from(b64, "base64");
    if (buf.length === KEY_BYTES) return buf;
  } catch {
    /* fall through */
  }
  return createHash("sha256").update(`zp-op-push-seal-key-v1\n${t}`, "utf8").digest();
}

/** Resolve seal key from env; when unset, return null so caller can use process-local. */
export function resolveOperatorPushSealKeyFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): Buffer | null {
  const raw = env.OPERATOR_PUSH_SEAL_KEY;
  if (raw === undefined || raw.trim().length === 0) return null;
  return parseKeyMaterial(raw);
}

/** Process-local key factory — stable for the lifetime of the Node process. */
export function createProcessLocalOperatorPushSealKey(): Buffer {
  return randomBytes(KEY_BYTES);
}

export function sealOperatorPushAuth(plaintext: string, key: Buffer): string {
  if (key.length !== KEY_BYTES) {
    throw new OperatorPushSealError(`operator push seal key must be ${KEY_BYTES} bytes`);
  }
  if (plaintext.length === 0) {
    throw new OperatorPushSealError("auth plaintext required");
  }
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  const tag = cipher.getAuthTag();
  const blob = Buffer.concat([nonce, tag, ciphertext]).toString("base64");
  return `${PREFIX}.${blob}`;
}

export function openOperatorPushAuth(sealed: string, key: Buffer): string {
  if (key.length !== KEY_BYTES) {
    throw new OperatorPushSealError(`operator push seal key must be ${KEY_BYTES} bytes`);
  }
  const dot = sealed.indexOf(".");
  if (dot < 0 || sealed.slice(0, dot) !== PREFIX) {
    throw new OperatorPushSealError("unrecognised operator push auth envelope");
  }
  const blob = Buffer.from(sealed.slice(dot + 1), "base64");
  if (blob.length < NONCE_BYTES + TAG_BYTES + 1) {
    throw new OperatorPushSealError("operator push auth envelope truncated");
  }
  const nonce = blob.subarray(0, NONCE_BYTES);
  const tag = blob.subarray(NONCE_BYTES, NONCE_BYTES + TAG_BYTES);
  const ciphertext = blob.subarray(NONCE_BYTES + TAG_BYTES);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plain.toString("utf8");
}

export interface OperatorPushAuthSealer {
  seal(authPlaintext: string): string;
  open(authSealed: string): string;
}

export function createOperatorPushAuthSealer(key: Buffer): OperatorPushAuthSealer {
  return {
    seal: (p) => sealOperatorPushAuth(p, key),
    open: (s) => openOperatorPushAuth(s, key),
  };
}

/**
 * True when VAPID public+private env is present. Does not load any external package.
 * A future adapter can open sealed auth via OperatorPushAuthSealer and POST to endpoints.
 */
export function isOperatorPushVapidConfigured(env: NodeJS.ProcessEnv = process.env): boolean {
  const pub = env.VAPID_PUBLIC_KEY?.trim();
  const priv = env.VAPID_PRIVATE_KEY?.trim();
  return Boolean(pub && priv);
}

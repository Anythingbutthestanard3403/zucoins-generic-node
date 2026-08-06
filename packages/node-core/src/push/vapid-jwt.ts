import { webcrypto } from "node:crypto";

const DEFAULT_MAX_EXPIRY_SKEW_SECONDS = 24 * 60 * 60;

export interface VerifyVapidAuthorizationParams {
  readonly authorizationHeader: string | null | undefined;
  /** Cached SplitChain app-server public key; never trust the header's k parameter. */
  readonly appServerPublicKeyRaw: string;
  readonly nodeOrigin: string;
  readonly now?: Date;
  readonly maxExpirySkewSeconds?: number;
}

export function decodeTolerantBase64(value: string): Buffer {
  const normalized = value.trim().replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(normalized + "=".repeat((4 - (normalized.length % 4)) % 4), "base64");
}

export function parseVapidAuthorizationHeader(
  header: string | null | undefined,
): { jwt: string; k?: string } | null {
  if (!header) return null;
  const match = /^vapid\s+(.+)$/i.exec(header.trim());
  if (!match) return null;
  const params: Record<string, string> = {};
  for (const part of match[1].split(",")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    const key = part.slice(0, separator).trim();
    let value = part.slice(separator + 1).trim();
    if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    params[key] = value;
  }
  return params.t ? { jwt: params.t, k: params.k } : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Verify RFC 8292 ES256 material against the cached app-server trust root. */
export async function verifyVapidAuthorization(
  params: VerifyVapidAuthorizationParams,
): Promise<boolean> {
  const parsed = parseVapidAuthorizationHeader(params.authorizationHeader);
  if (!parsed) return false;
  const segments = parsed.jwt.split(".");
  if (segments.length !== 3) return false;
  const [protectedHeader, payloadSegment, signatureSegment] = segments;

  let header: unknown;
  let payload: unknown;
  try {
    header = JSON.parse(Buffer.from(protectedHeader, "base64url").toString("utf8"));
    payload = JSON.parse(Buffer.from(payloadSegment, "base64url").toString("utf8"));
  } catch {
    return false;
  }
  if (!isRecord(header) || header.alg !== "ES256" || !isRecord(payload)) return false;
  if (payload.aud !== params.nodeOrigin || typeof payload.exp !== "number" || !Number.isFinite(payload.exp)) {
    return false;
  }
  const nowSeconds = Math.floor((params.now ?? new Date()).getTime() / 1000);
  const maxSkew = params.maxExpirySkewSeconds ?? DEFAULT_MAX_EXPIRY_SKEW_SECONDS;
  if (payload.exp <= nowSeconds || payload.exp > nowSeconds + maxSkew) return false;

  try {
    const key = await webcrypto.subtle.importKey(
      "raw",
      decodeTolerantBase64(params.appServerPublicKeyRaw),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return await webcrypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      Buffer.from(signatureSegment, "base64url"),
      Buffer.from(`${protectedHeader}.${payloadSegment}`, "utf8"),
    );
  } catch {
    return false;
  }
}

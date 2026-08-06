// Device signature verification — verifies that a request is signed by an enrolled,
// non-revoked device key. Fail-closed: unknown or revoked devices are rejected.

import { verifyDetachedEd25519 } from "../reporting/ed25519.js";
import type { DeviceKeyStore } from "./store.js";
import type { DeviceSignatureVerificationResult } from "./types.js";

const PADDED_BASE64URL_RE = /^[A-Za-z0-9_-]{43}=$/;

export interface DeviceSignatureInput {
  readonly nodeId: string;
  readonly publicKey: string;
  readonly preimageText: string;
  readonly signatureBytes: Uint8Array;
}

export function verifyDeviceSignature(
  store: DeviceKeyStore,
  input: DeviceSignatureInput,
): DeviceSignatureVerificationResult {
  if (!PADDED_BASE64URL_RE.test(input.publicKey)) {
    return { ok: false, code: "INVALID_PUBLIC_KEY", detail: "public key is not valid padded base64url" };
  }

  const deviceKey = store.findByNodeAndPublicKey(input.nodeId, input.publicKey);
  if (deviceKey === null) {
    return { ok: false, code: "UNKNOWN_DEVICE", detail: "no enrolled device with this public key for this node" };
  }

  if (deviceKey.revokedAt !== null) {
    return { ok: false, code: "DEVICE_REVOKED", detail: "device key has been revoked" };
  }

  // Active-path gate (same as enrollment authorizer resolution).
  const active = store.findActiveByNodeAndPublicKey(input.nodeId, input.publicKey);
  if (active === null) {
    return { ok: false, code: "DEVICE_REVOKED", detail: "device key has been revoked" };
  }

  const rawKeyBytes = decodePaddedBase64Url(input.publicKey);
  if (rawKeyBytes === null || rawKeyBytes.length !== 32) {
    return { ok: false, code: "INVALID_PUBLIC_KEY", detail: "public key does not decode to 32 bytes" };
  }

  const valid = verifyDetachedEd25519({
    publicKeyBytes: rawKeyBytes,
    preimageText: input.preimageText,
    signatureBytes: input.signatureBytes,
  });
  if (!valid) {
    return { ok: false, code: "SIGNATURE_INVALID", detail: "signature verification failed" };
  }

  return { ok: true, deviceKey: active };
}

function decodePaddedBase64Url(value: string): Uint8Array | null {
  try {
    const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
}

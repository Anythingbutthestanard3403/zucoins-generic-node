/**
 * Shared one-tap device signature for external-send approve (ZTR-1256).
 * Matches TransferDetailPage: list enrolled keys, pick a local private key,
 * sign the server-issued preimage_text byte-exact. TOTP remains the floor.
 */

import { listDeviceKeys } from "./money.js";
import {
  getDeviceRecord,
  listLocalDeviceRecords,
} from "./device-crypto.js";
import { signPreimage } from "./device-crypto.js";

export interface ApproveDeviceFields {
  readonly device_key_id: string | null;
  readonly device_signature: string | null;
}

export interface LocalApproveDeviceAvailability {
  /** Server-listed enrolled keys for this node. */
  readonly enrolledCount: number;
  /** Local IndexedDB private keys that match an enrolled id. */
  readonly localMatchCount: number;
  /** True when at least one enrolled key has a local private half. */
  readonly canSign: boolean;
}

/**
 * Whether this browser can produce a device signature for approve.
 * Used to disable the Approve button before TOTP when no key is present.
 */
export async function getLocalApproveDeviceAvailability(): Promise<LocalApproveDeviceAvailability> {
  try {
    const keys = await listDeviceKeys();
    const locals = await listLocalDeviceRecords();
    const localIds = new Set(locals.map((l) => l.id));
    const localMatchCount = keys.filter((k) => localIds.has(k.id)).length;
    return {
      enrolledCount: keys.length,
      localMatchCount,
      // Only a local private key that matches an enrolled id can sign.
      canSign: localMatchCount > 0,
    };
  } catch {
    return { enrolledCount: 0, localMatchCount: 0, canSign: false };
  }
}

/**
 * Sign the challenge preimage with a local device key when available.
 * Returns null fields when no usable local key — caller still POSTs (server
 * may accept TOTP-only when policy is optional; default nodes require device).
 */
export async function signApproveChallengePreimage(
  preimageText: string,
): Promise<ApproveDeviceFields> {
  let device_key_id: string | null = null;
  let device_signature: string | null = null;
  try {
    const keys = await listDeviceKeys();
    const locals = await listLocalDeviceRecords();
    const localIds = new Set(locals.map((l) => l.id));
    const match = keys.find((k) => localIds.has(k.id)) ?? keys[0];
    if (match !== undefined) {
      const local = await getDeviceRecord(match.id);
      if (local !== null) {
        device_key_id = match.id;
        device_signature = await signPreimage(local.privateKey, preimageText);
      }
    }
  } catch {
    // Fall through: TOTP-only path if device unavailable (server may still require device).
  }
  return { device_key_id, device_signature };
}

/**
 * Operator-facing copy for approve failures that the wire distinguishes.
 * Factor failures stay opaque as `approval_rejected` (ZTR-1194); policy denial
 * and non-401 codes are safe to surface.
 */
export function formatApproveFailure(err: unknown, fallback = "Approve failed"): string {
  if (err && typeof err === "object" && "code" in err) {
    const code = String((err as { code: unknown }).code);
    const message =
      "message" in err && typeof (err as { message: unknown }).message === "string"
        ? (err as { message: string }).message
        : "";
    if (code === "same_operator_both_sides") {
      return (
        message ||
        "Two-human dual control requires a different operator to approve than the one who opened the challenge."
      );
    }
    if (code === "device_required" || (code === "approval_rejected" && /device/i.test(message))) {
      return "Device signature required — enrol a device key on this browser, then approve again.";
    }
    if (code === "totp_invalid" || code === "invalid_credentials") {
      return message || "Authenticator code invalid — try again.";
    }
    if (code === "row_version_mismatch" || /row.?version|stale/i.test(message)) {
      return "This send changed while you were reviewing it — refresh the challenge and try again.";
    }
    if (code === "challenge_expired") {
      return "Approval challenge expired — open Review & decide again for a fresh challenge.";
    }
    if (message) {
      const rid =
        "requestId" in err && typeof (err as { requestId: unknown }).requestId === "string"
          ? ` (${(err as { requestId: string }).requestId})`
          : "";
      return `${message}${rid}`;
    }
  }
  if (err instanceof Error && err.message) return err.message;
  return fallback;
}

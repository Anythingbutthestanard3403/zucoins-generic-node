// Resolving the transfer code out of a DELIVERED Web Push envelope ((2026-07-16): canonical DELIVERED Web Push payload shape).
//
// wallet.zucoins.com does NOT hand our endpoint the sender's `action_data` verbatim: it
// reshapes into a standard push envelope before encrypting, so the decrypted cleartext
// sits at the same nesting a service worker's `event.data.json` would see. The
// precedence below mirrors the wallet's own service worker:
//
// type_data = envelope.aps?.data?.type_data (Apple APNs shape)
// ?? envelope.data?.type_data (standard FCM / Mozilla shape)
//
// and the code is `type_data.transfer_code_encoded`. The pre-reshape, send-side
// `notification_type_data` is a TRAILING FALLBACK ONLY — reading it first was the
// original silent-204 defect (the code resolved `undefined`, so nothing was ever
// enqueued and the delivery looked successful).
//
// Nothing here parses or re-encodes the code itself: it is already-signed bytes and is
// passed through verbatim to candidate intake (the byte-exact signing rule).

export interface ResolvedPushDelivery {
  /** The opaque, already-encoded transfer code, byte-identical to what was delivered. */
  readonly transferCodeEncoded: string;
  /** Which shape matched — recorded for diagnostics, never used for control flow. */
  readonly shape: "aps" | "data" | "send_side_fallback";
}

function readTypeData(source: unknown): Record<string, unknown> | null {
  if (typeof source !== "object" || source === null) return null;
  const td = (source as Record<string, unknown>).type_data;
  if (typeof td !== "object" || td === null || Array.isArray(td)) return null;
  return td as Record<string, unknown>;
}

function readCode(typeData: Record<string, unknown> | null): string | null {
  if (typeData === null) return null;
  const code = typeData.transfer_code_encoded;
  return typeof code === "string" && code.length > 0 ? code : null;
}

/**
 * Resolve the transfer code from decrypted push cleartext. Returns null when the payload
 * carries no code — a notification we do not act on, which is discarded rather than
 * treated as an error (discard semantics).
 */
export function resolveTransferCodeFromEnvelope(envelope: unknown): ResolvedPushDelivery | null {
  if (typeof envelope !== "object" || envelope === null) return null;
  const obj = envelope as Record<string, unknown>;

  // 1. Apple APNs shape.
  const aps = obj.aps;
  if (typeof aps === "object" && aps !== null) {
    const code = readCode(readTypeData((aps as Record<string, unknown>).data));
    if (code !== null) return { transferCodeEncoded: code, shape: "aps" };
  }

  // 2. Standard FCM / Mozilla shape.
  const code = readCode(readTypeData(obj.data));
  if (code !== null) return { transferCodeEncoded: code, shape: "data" };

  // 3. Trailing fallback: an un-reshaped send-side envelope.
  const sendSide = obj.notification_type_data;
  if (typeof sendSide === "object" && sendSide !== null && !Array.isArray(sendSide)) {
    const fallback = (sendSide as Record<string, unknown>).transfer_code_encoded;
    if (typeof fallback === "string" && fallback.length > 0) {
      return { transferCodeEncoded: fallback, shape: "send_side_fallback" };
    }
  }

  return null;
}

/** Parse decrypted cleartext into an envelope object, folding malformed JSON to null. */
export function parsePushCleartext(cleartext: Uint8Array): unknown {
  let text: string;
  try {
    text = Buffer.from(cleartext).toString("utf8");
  } catch {
    return null;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

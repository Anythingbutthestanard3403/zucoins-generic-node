// Inbound Web Push receive handler (channel 1; (2026-07-16): canonical DELIVERED Web Push payload shape; all gates before co-sign).
//
// The push service POSTs an RFC 8291 `aes128gcm` body to the node's own per-wallet URL
// (`/v1/receivers/push/:endpoint_id`). This resolves the endpoint id to its subscription,
// verifies the RFC 8292 VAPID Authorization header against the stored app-server trust
// root (defence-in-depth second factor), opens the sealed ECDH private half + auth secret,
// decrypts, pulls the transfer code out of the DELIVERED envelope shape (precedence), and
// hands the code to the SAME candidate-intake sink the origin relay uses — one intake path,
// two producers. Landing and settlement logic is not duplicated here.
//
// Discard semantics (all gates before co-sign): every rejection is a 204 with an audit
// record. A forged or corrupt push must not be distinguishable from an accepted one by an
// outside observer, and it cannot reach the money path anyway — the code still has to pass
// candidate intake, which verifies the payer's step-1 signature over the exact captured
// inner text.
//
// VAPID rollout (ZTR-1161): `vapidMode` is `observe` (default) or `enforce`.
//   - verified  — signature ok against the stored key
//   - rejected  — header present/malformed/wrong key/wrong aud/exp
//   - absent    — no Authorization header
//   - no_key    — row has no stored app_server_public_key (pre-wiring / FAILED rows)
// Observe counts + audits every outcome but never blocks decrypt. Enforce fails closed on
// rejected/absent/no_key (still 204 at the HTTP edge). Flip to enforce only after the
// observe counter shows live deliveries carry verifiable VAPID and every ACTIVE row has a key.

import { isValidEndpointId } from "./endpoint.js";
import { parsePushCleartext, resolveTransferCodeFromEnvelope } from "./payload.js";
import type {
  PushAuditSink,
  PushSecretSealer,
  PushSubscriptionStore,
  WebPushPayloadDecryptor,
} from "./store.js";
import { verifyVapidAuthorization } from "./vapid-jwt.js";

/**
 * Receives an already-decoded transfer code. Implemented by the app over the intake inbox.
 * Returns the inbox's verdict: `false` means the deposit was refused (lane at cap) and is
 * gone. The verdict is threaded back so the audit record names what actually happened —
 * a refusal audited as `enqueued` is a lost credit notification with a record claiming
 * the opposite (ZTR-1188).
 */
export type PushTransferCodeSink = (transferCodeEncoded: string) => boolean;

/** Observe-only vs fail-closed VAPID gate (ZTR-1161 staged rollout). */
export type PushVapidMode = "observe" | "enforce";

/** Closed counter vocabulary for gn_push_vapid_total / audit detail. */
export type PushVapidOutcome = "verified" | "rejected" | "absent" | "no_key";

export interface PushReceiverDeps {
  readonly store: PushSubscriptionStore;
  readonly sealer: Pick<PushSecretSealer, "open">;
  readonly decryptor: WebPushPayloadDecryptor;
  readonly sink: PushTransferCodeSink;
  readonly audit?: PushAuditSink;
  /**
   * Node origin (`https://host[:port]`) bound into the VAPID JWT `aud` claim.
   * Required for verification; when omitted, VAPID is treated as `no_key` and
   * never blocks in observe mode.
   */
  readonly nodeOrigin?: string;
  /** Default `observe` — count and audit without blocking. */
  readonly vapidMode?: PushVapidMode;
  /** Optional counter seam (app wires MetricsHooks). */
  readonly onVapidOutcome?: (outcome: PushVapidOutcome) => void;
}

export type PushReceiveOutcome =
  | "enqueued"
  | "refused"
  | "unknown_endpoint"
  | "malformed_endpoint"
  | "decrypt_failed"
  | "no_transfer_code"
  | "vapid_rejected";

export interface PushReceiver {
  /** Always resolves; the caller answers 204 regardless of outcome. */
  receive(
    endpointId: string,
    body: Buffer,
    authorizationHeader?: string | null,
  ): Promise<PushReceiveOutcome>;
}

function classifyVapidHeader(authorizationHeader: string | null | undefined): "absent" | "present" {
  if (authorizationHeader === undefined || authorizationHeader === null) return "absent";
  if (authorizationHeader.trim().length === 0) return "absent";
  return "present";
}

export function createPushReceiver(deps: PushReceiverDeps): PushReceiver {
  const mode: PushVapidMode = deps.vapidMode ?? "observe";
  const audit = async (
    type: string,
    walletId: string,
    detail: Record<string, unknown>,
  ): Promise<void> => {
    try {
      await deps.audit?.record({ type, walletId, detail });
    } catch {
      // never converts a discard into a throw
    }
  };

  const noteVapid = (outcome: PushVapidOutcome): void => {
    try {
      deps.onVapidOutcome?.(outcome);
    } catch {
      // counter must never convert a discard into a throw
    }
  };

  return {
    async receive(endpointId, body, authorizationHeader) {
      if (!isValidEndpointId(endpointId)) {
        await audit("push.receive_malformed_endpoint", "", { endpointId: "<redacted>" });
        return "malformed_endpoint";
      }

      const row = await deps.store.findByEndpointId(endpointId);
      if (row === null) {
        // Unknown token: either a stale endpoint from a retired wallet or a probe.
        await audit("push.receive_unknown_endpoint", "", { endpointId: "<redacted>" });
        return "unknown_endpoint";
      }

      // VAPID second factor — before any sealed material is opened.
      const headerClass = classifyVapidHeader(authorizationHeader);
      const storedKey = row.appServerPublicKey;
      const origin = deps.nodeOrigin?.trim() ?? "";
      let vapidOutcome: PushVapidOutcome;
      if (storedKey === null || storedKey.length === 0 || origin.length === 0) {
        vapidOutcome = "no_key";
      } else if (headerClass === "absent") {
        vapidOutcome = "absent";
      } else {
        const ok = await verifyVapidAuthorization({
          authorizationHeader,
          appServerPublicKeyRaw: storedKey,
          nodeOrigin: origin,
        });
        vapidOutcome = ok ? "verified" : "rejected";
      }
      noteVapid(vapidOutcome);
      await audit("push.receive_vapid", row.walletId, {
        outcome: vapidOutcome,
        mode,
        hasAuthorization: headerClass === "present",
      });

      if (mode === "enforce" && vapidOutcome !== "verified") {
        await audit("push.receive_vapid_rejected", row.walletId, {
          outcome: vapidOutcome,
        });
        return "vapid_rejected";
      }

      let ecdhPrivate: Buffer | null = null;
      let authSecret: Buffer | null = null;
      try {
        // Open sealed material in its own try: only unopenable envelopes flag the row
        // FAILED for reconcile self-heal. Decrypt/parse/sink failures stay pure discard
        // (all gates before co-sign) — a forged body must never become a money-path kill switch.
        try {
          [ecdhPrivate, authSecret] = await Promise.all([
            deps.sealer.open(row.receiverEcdhPrivateSealed, "ECDH_PRIVATE"),
            deps.sealer.open(row.receiverAuthSecretSealed, "AUTH_SECRET"),
          ]);
        } catch (err) {
          try {
            await deps.store.markStatus(row.walletId, "FAILED", null);
          } catch {
            // A markStatus failure must not convert a discard into a throw.
          }
          await audit("push.receive_decrypt_failed", row.walletId, {
            error: err instanceof Error ? err.message : String(err),
          });
          return "decrypt_failed";
        }

        try {
          const cleartext = await deps.decryptor.decrypt({
            body,
            ecdhPrivateKeyBytes: ecdhPrivate,
            authSecret,
          });

          const resolved = resolveTransferCodeFromEnvelope(parsePushCleartext(cleartext));
          if (resolved === null) {
            await audit("push.receive_no_code", row.walletId, {});
            return "no_transfer_code";
          }

          // Verbatim hand-off — the code is already-signed bytes (the byte-exact signing rule).
          if (!deps.sink(resolved.transferCodeEncoded)) {
            // The inbox shed it. The route still answers 204 either way (non-oracular), but
            // the audit trail is internal and must not claim an enqueue that never happened —
            // this is the only wallet-scoped record of the loss.
            await audit("push.receive_refused", row.walletId, { shape: resolved.shape });
            return "refused";
          }
          await audit("push.receive_enqueued", row.walletId, { shape: resolved.shape });
          return "enqueued";
        } catch (err) {
          // Body/AEAD/sink failure: discard only. Sealed material opened fine — do not
          // flip the row (attacker-controlled body and stale-key race both land here).
          await audit("push.receive_decrypt_failed", row.walletId, {
            error: err instanceof Error ? err.message : String(err),
          });
          return "decrypt_failed";
        }
      } finally {
        ecdhPrivate?.fill(0);
        authSecret?.fill(0);
      }
    },
  };
}

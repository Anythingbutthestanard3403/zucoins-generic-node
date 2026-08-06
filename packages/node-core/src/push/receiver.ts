// Inbound Web Push receive handler (channel 1; (2026-07-16): canonical DELIVERED Web Push payload shape; all gates before co-sign).
//
// The push service POSTs an RFC 8291 `aes128gcm` body to the node's own per-wallet URL
// (`/v1/receivers/push/:endpoint_id`). This resolves the endpoint id to its subscription,
// opens the sealed ECDH private half + auth secret, decrypts, pulls the transfer code out
// of the DELIVERED envelope shape (precedence), and hands the code to the SAME
// candidate-intake sink the origin relay uses — one intake path, two producers. Landing
// and settlement logic is not duplicated here.
//
// Discard semantics (all gates before co-sign): every rejection is a 204 with an audit record. A forged or
// corrupt push must not be distinguishable from an accepted one by an outside observer,
// and it cannot reach the money path anyway — the code still has to pass candidate intake,
// which verifies the payer's step-1 signature over the exact captured inner text.

import { isValidEndpointId } from "./endpoint.js";
import { parsePushCleartext, resolveTransferCodeFromEnvelope } from "./payload.js";
import type {
  PushAuditSink,
  PushSecretSealer,
  PushSubscriptionStore,
  WebPushPayloadDecryptor,
} from "./store.js";

/** Receives an already-decoded transfer code. Implemented by the app over the intake inbox. */
export type PushTransferCodeSink = (transferCodeEncoded: string) => void;

export interface PushReceiverDeps {
  readonly store: PushSubscriptionStore;
  readonly sealer: Pick<PushSecretSealer, "open">;
  readonly decryptor: WebPushPayloadDecryptor;
  readonly sink: PushTransferCodeSink;
  readonly audit?: PushAuditSink;
}

export type PushReceiveOutcome =
  | "enqueued"
  | "unknown_endpoint"
  | "malformed_endpoint"
  | "decrypt_failed"
  | "no_transfer_code";

export interface PushReceiver {
  /** Always resolves; the caller answers 204 regardless of outcome. */
  receive(endpointId: string, body: Buffer): Promise<PushReceiveOutcome>;
}

export function createPushReceiver(deps: PushReceiverDeps): PushReceiver {
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

  return {
    async receive(endpointId, body) {
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
          deps.sink(resolved.transferCodeEncoded);
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

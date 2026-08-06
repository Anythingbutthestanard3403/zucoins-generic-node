// Push subscription lifecycle (channel 1; push API base; destination binding).
//
// 's rule, 2026-07-31: an EXTERNAL receive or send requires push — if push is down,
// external receives stop, and that is intended. INTERNAL transfers (both wallets ours:
// sub-wallet to treasury, treasury to treasury) never need push, because the operator // contract-allow:treasury:frozen structural vocabulary
// holds both sides and can move the code directly. So this module keeps every wallet
// subscribed by construction, and `requireActiveSubscription` is the hard gate the
// EXTERNAL paths call — the internal paths must not call it.
//
// Provisioning itself never throws into a caller: a push-API outage is audited and
// leaves the row FAILED, which the gate then refuses on. That is the difference between
// "the money path is blocked" (correct, visible) and "the node crashed" (never).

import { generateAuthSecret, generateEcdhKeypair } from "./crypto.js";
import { buildPushEndpointUrl, generateEndpointId } from "./endpoint.js";
import { buildIdProofQuery, type PushIdProofSigner } from "./id-proof.js";
import type {
  PushAuditSink,
  PushGatewayActions,
  PushSecretSealer,
  PushSubscriptionRow,
  PushSubscriptionStore,
  PushWalletRef,
} from "./store.js";

export interface PushSubscriptionServiceDeps {
  readonly store: PushSubscriptionStore;
  readonly sealer: PushSecretSealer;
  readonly gateway: PushGatewayActions;
  readonly sign: PushIdProofSigner;
  readonly nodePublicUrl: string;
  readonly audit?: PushAuditSink;
  readonly nowMs?: () => number;
}

export type ProvisionOutcome = "subscribed" | "failed";

export interface ProvisionResult {
  readonly outcome: ProvisionOutcome;
  readonly endpointId: string | null;
}

/** Raised by {@link requireActiveSubscription}. External money paths must fail closed on it. */
export class PushSubscriptionRequiredError extends Error {
  readonly code = "push_subscription_required";
  constructor(readonly walletId: string) {
    super(
      `wallet ${walletId} has no ACTIVE push subscription; an external operation cannot ` +
        `use it (internal transfers are exempt)`,
    );
    this.name = "PushSubscriptionRequiredError";
  }
}

export interface PushSubscriptionService {
  /** Create-or-reuse the row and subscribe it. Never throws. */
  provision(wallet: PushWalletRef): Promise<ProvisionResult>;
  /**
   * Re-check every subscribable wallet against the push service and re-subscribe any the
   * service reports absent. Returns per-outcome counts. Never throws.
   */
  reconcileAll(): Promise<ReconcileSummary>;
  /**
   * Hard gate for EXTERNAL receives/sends. Throws {@link PushSubscriptionRequiredError}
   * unless the wallet holds a locally-ACTIVE subscription. Internal transfers must not
   * call this.
   */
  requireActiveSubscription(walletId: string): Promise<void>;
}

export interface ReconcileSummary {
  readonly checked: number;
  readonly alreadySubscribed: number;
  readonly resubscribed: number;
  readonly failed: number;
}

export function createPushSubscriptionService(
  deps: PushSubscriptionServiceDeps,
): PushSubscriptionService {
  const audit = async (
    type: string,
    walletId: string,
    detail: Record<string, unknown>,
  ): Promise<void> => {
    try {
      await deps.audit?.record({ type, walletId, detail });
    } catch {
      // An audit sink failure must never convert a best-effort push path into a throw.
    }
  };

  interface EnsuredRow {
    readonly row: PushSubscriptionRow;
    readonly ecdhPrivate: Buffer;
    readonly authSecret: Buffer;
    /** True when sealed material was unopenable and was re-minted under the same endpoint. */
    readonly reminted: boolean;
  }

  /** Fresh ECDH keypair + auth secret, sealed, under the caller's chosen endpoint id. */
  const mintMaterial = async (
    wallet: PushWalletRef,
    endpointId: string,
    reminted = false,
  ): Promise<EnsuredRow> => {
    const keypair = generateEcdhKeypair();
    const authSecret = generateAuthSecret();
    const [privateSealed, authSealed] = await Promise.all([
      deps.sealer.seal(keypair.privateKeyBytes, "ECDH_PRIVATE"),
      deps.sealer.seal(authSecret, "AUTH_SECRET"),
    ]);
    return {
      row: {
        walletId: wallet.walletId,
        walletPublicKey: wallet.publicKey,
        endpointId,
        receiverEcdhPublic: keypair.publicKeyB64url,
        receiverEcdhPrivateSealed: privateSealed,
        receiverAuthSecretSealed: authSealed,
        // Pessimistic until the gateway acknowledges — see the module header.
        status: "FAILED",
      },
      ecdhPrivate: keypair.privateKeyBytes,
      authSecret,
      reminted,
    };
  };

  /**
   * Reuse an existing row's ECDH keypair and endpoint id when one exists — the endpoint
   * must stay stable across re-subscribes, otherwise every sweep would orphan the // contract-allow:sweep:frozen structural vocabulary
   * previously registered URL. A wallet with no row at all gets fresh material.
   *
   * A row whose sealed material no longer OPENS is the third case, and it must not fail
   * open. That happens when the envelopes were sealed under a scheme or a root this node
   * can no longer reproduce (a master-key rotation that never rewrapped this store, a
   * truncated column). The keys behind an ACTIVE row would then be unusable while the gate
   * still admitted external money, so the row is forced back to FAILED first, then re-minted
   * in place under the SAME endpoint id and re-registered by the caller.
   */
  const ensureRow = async (wallet: PushWalletRef): Promise<EnsuredRow> => {
    const existing = await deps.store.findByWalletId(wallet.walletId);
    if (existing === null) {
      const minted = await mintMaterial(wallet, generateEndpointId());
      await deps.store.insert(minted.row);
      return minted;
    }

    let ecdhPrivate: Buffer | undefined;
    let authSecret: Buffer | undefined;
    try {
      // Sequential, not Promise.all: if the second open throws, the first's plaintext must
      // still be reachable to wipe rather than stranded in a settled promise.
      ecdhPrivate = await deps.sealer.open(existing.receiverEcdhPrivateSealed, "ECDH_PRIVATE");
      authSecret = await deps.sealer.open(existing.receiverAuthSecretSealed, "AUTH_SECRET");
      return { row: existing, ecdhPrivate, authSecret, reminted: false };
    } catch (err) {
      ecdhPrivate?.fill(0);
      authSecret?.fill(0);
      // Fail closed before anything else can throw: FAILED is what requireActiveSubscription
      // refuses on, so even if the re-mint or its write dies below, external money is stopped.
      await deps.store.markStatus(wallet.walletId, "FAILED", null);
      await audit("push.sealed_material_unopenable", wallet.walletId, {
        endpointId: existing.endpointId,
        error: err instanceof Error ? err.message : String(err),
      });
      const minted = await mintMaterial(wallet, existing.endpointId, true);
      await deps.store.replaceSealedMaterial({
        walletId: minted.row.walletId,
        receiverEcdhPublic: minted.row.receiverEcdhPublic,
        receiverEcdhPrivateSealed: minted.row.receiverEcdhPrivateSealed,
        receiverAuthSecretSealed: minted.row.receiverAuthSecretSealed,
      });
      return minted;
    }
  };

  const subscribeRow = async (
    wallet: PushWalletRef,
    row: PushSubscriptionRow,
    authSecret: Buffer,
  ): Promise<ProvisionOutcome> => {
    try {
      const appServerPublicKey = await deps.gateway.getAppServerPublicKey();
      const idProofQuery = await buildIdProofQuery({
        walletId: wallet.walletId,
        walletPublicKeyB64url: wallet.publicKey,
        sign: deps.sign,
        nowSecs: Math.floor((deps.nowMs?.() ?? Date.now()) / 1000),
      });
      await deps.gateway.subscribe({
        idProofQuery,
        endpoint: buildPushEndpointUrl(deps.nodePublicUrl, row.endpointId),
        keyP256dh: row.receiverEcdhPublic,
        keyAuth: authSecret.toString("base64url"),
      });
      await deps.store.markStatus(wallet.walletId, "ACTIVE", appServerPublicKey);
      return "subscribed";
    } catch (err) {
      await deps.store.markStatus(wallet.walletId, "FAILED", null);
      await audit("push.subscribe_failed", wallet.walletId, {
        endpointId: row.endpointId,
        error: err instanceof Error ? err.message : String(err),
      });
      return "failed";
    }
  };

  return {
    async provision(wallet) {
      let ensured;
      try {
        ensured = await ensureRow(wallet);
      } catch (err) {
        // Row creation failed (seal or SQL) — nothing to subscribe. Audited, not thrown:
        // the gate below is what stops external money, not an exception here.
        await audit("push.provision_failed", wallet.walletId, {
          error: err instanceof Error ? err.message : String(err),
        });
        return { outcome: "failed", endpointId: null };
      }
      try {
        const outcome = await subscribeRow(wallet, ensured.row, ensured.authSecret);
        return { outcome, endpointId: ensured.row.endpointId };
      } finally {
        ensured.ecdhPrivate.fill(0);
        ensured.authSecret.fill(0);
      }
    },

    async reconcileAll() {
      let checked = 0;
      let alreadySubscribed = 0;
      let resubscribed = 0;
      let failed = 0;

      let wallets: readonly PushWalletRef[];
      try {
        wallets = await deps.store.listSubscribableWallets();
      } catch {
        return { checked: 0, alreadySubscribed: 0, resubscribed: 0, failed: 0 };
      }

      for (const wallet of wallets) {
        checked += 1;
        try {
          const remoteHas = await deps.gateway.hasSubscriptionForPublicKey(wallet.publicKey);
          const local = await deps.store.findByWalletId(wallet.walletId);
          if (remoteHas && local !== null && local.status === "ACTIVE") {
            // Verify the sealed material is still openable before skipping. An ACTIVE row
            // with unopenable material (corrupt envelope, master-key rotation without
            // rewrap) would otherwise stay stuck forever — the gate refuses it but
            // reconcile never re-provisions. ensureRow marks FAILED on open failure,
            // re-mints, and returns reminted=true so we re-subscribe without a racy
            // status re-read. Wipe secrets in finally so a store throw cannot leak them.
            let ensured;
            try {
              ensured = await ensureRow(wallet);
            } catch {
              // ensureRow itself failed (seal or SQL); fall through to provision.
              const result = await this.provision(wallet);
              if (result.outcome === "subscribed") resubscribed += 1;
              else failed += 1;
              continue;
            }
            try {
              if (ensured.reminted) {
                const result = await this.provision(wallet);
                if (result.outcome === "subscribed") resubscribed += 1;
                else failed += 1;
              } else {
                alreadySubscribed += 1;
              }
            } finally {
              ensured.ecdhPrivate.fill(0);
              ensured.authSecret.fill(0);
            }
            continue;
          }
          const result = await this.provision(wallet);
          if (result.outcome === "subscribed") resubscribed += 1;
          else failed += 1;
        } catch (err) {
          // One wallet's failure never aborts the pass ( best-effort sweep). // contract-allow:sweep:frozen structural vocabulary
          failed += 1;
          await audit("push.reconcile_failed", wallet.walletId, {
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
      return { checked, alreadySubscribed, resubscribed, failed };
    },

    async requireActiveSubscription(walletId) {
      const row = await deps.store.findByWalletId(walletId);
      if (row === null || row.status !== "ACTIVE") {
        throw new PushSubscriptionRequiredError(walletId);
      }
    },
  };
}

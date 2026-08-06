// Composition of the push inbound leg.
//
// Operator rule (2026-07-31): EXTERNAL receives/sends require push; INTERNAL transfers do
// not. Everything here serves the external leg — keeping every wallet subscribed so the
// payer's wallet can deliver a partial transaction without the operator relaying it by
// hand.
//
// Three call sites keep the invariant true:
//   1. subscribe-on-mint  — money-workers pool scale-up, post-commit
//   2. boot reconcile     — one immediate pass at startup
//  3. periodic sweep — jittered loop, first run deferred one interval so it // contract-allow:sweep:frozen structural vocabulary
//                           does not duplicate the boot pass
//
// A push-API outage never throws into the money path or crashes a loop; it leaves rows
// FAILED, which is exactly what `requireActiveSubscription` refuses on.

import type { Pool } from "pg";

import {
  createPushReceiver,
  createPushSecretSealer,
  createPushSubscriptionService,
  type PushSubscriptionService,
  type PushWalletRef,
} from "@zucoins/node-core";

import { createEceDecryptor } from "./ece-decryptor.js";
import { createPushGatewayActions } from "./gateway-actions.js";
import { createSqlPushSubscriptionStore } from "./sql-store.js";

export interface PushCompositionLogger {
  info(message: string): void;
  error(message: string, err?: unknown): void;
}

export interface ComposePushDeps {
  readonly pool: Pool;
  readonly nodeId: string;
  /** Derived vault root — the same one the wallet secrets are sealed under. */
  readonly rootKey: Uint8Array;
  /** Push API base. */
  readonly pushApiBase: string;
  /** Public base URL; the per-wallet endpoint is built from it. */
  readonly nodePublicUrl: string;
  /** Signs the id-proof with the wallet's own Ed25519 key (vault seam). */
  readonly sign: (walletId: string, preimage: Uint8Array) => Promise<string>;
  /** Hands a decoded transfer code to the shared candidate-intake inbox. */
  readonly sink: (transferCodeEncoded: string) => void;
  readonly logger: PushCompositionLogger;
}

export interface PushComposition {
  readonly service: PushSubscriptionService;
  /** Bind to runtime-listener `onPushDelivery`. */
  readonly onPushDelivery: (endpointId: string, body: Buffer) => Promise<void>;
  /** Bind to money-workers `onWalletsMinted`. */
  readonly onWalletsMinted: (walletIds: readonly string[]) => void;
  /** One immediate pass; call during boot after the vault is available. */
  readonly reconcileNow: () => Promise<void>;
  /** Start the jittered sweep. Returns a stop handle for graceful shutdown. */ // contract-allow:sweep:frozen structural vocabulary
  readonly startSweep: (intervalMs?: number) => { stop: () => void };
}

/** ~6h between sweeps; ±25% jitter so replicas do not synchronise. */ // contract-allow:sweep:frozen structural vocabulary
export const DEFAULT_PUSH_SWEEP_INTERVAL_MS = 6 * 60 * 60 * 1000;

export function composePush(deps: ComposePushDeps): PushComposition {
  const store = createSqlPushSubscriptionStore(deps.pool, deps.nodeId);
  const gateway = createPushGatewayActions({ pushApiBase: deps.pushApiBase });
  const decryptor = createEceDecryptor();

  // One sealer per wallet: the AAD binds node+wallet+purpose, so the wallet is fixed at
  // construction and the purpose is passed per call.
  const sealerFor = (walletId: string) =>
    createPushSecretSealer({ rootKey: deps.rootKey, nodeId: deps.nodeId, walletId });

  const audit = {
    async record(event: {
      readonly type: string;
      readonly walletId: string;
      readonly detail: Record<string, unknown>;
    }): Promise<void> {
      deps.logger.info(`push: ${event.type} wallet=${event.walletId}`);
    },
  };

  const serviceFor = (walletId: string): PushSubscriptionService =>
    createPushSubscriptionService({
      store,
      sealer: sealerFor(walletId),
      gateway,
      sign: deps.sign,
      nodePublicUrl: deps.nodePublicUrl,
      audit,
    });

  // Wallet-agnostic surface. Each operation resolves the per-wallet sealer internally,
  // so no caller has to know that sealing is wallet-scoped.
  const service: PushSubscriptionService = {
    async provision(wallet: PushWalletRef) {
      return await serviceFor(wallet.walletId).provision(wallet);
    },
    async reconcileAll() {
      let checked = 0;
      let alreadySubscribed = 0;
      let resubscribed = 0;
      let failed = 0;
      const wallets = await store.listSubscribableWallets();
      for (const wallet of wallets) {
        checked += 1;
        try {
          const remoteHas = await gateway.hasSubscriptionForPublicKey(wallet.publicKey);
          const local = await store.findByWalletId(wallet.walletId);
          if (remoteHas && local !== null && local.status === "ACTIVE") {
            alreadySubscribed += 1;
            continue;
          }
          const result = await serviceFor(wallet.walletId).provision(wallet);
          if (result.outcome === "subscribed") resubscribed += 1;
          else failed += 1;
        } catch (err) {
          // One wallet never aborts the pass.
          failed += 1;
          deps.logger.error(`push: reconcile failed for wallet ${wallet.walletId}`, err);
        }
      }
      return { checked, alreadySubscribed, resubscribed, failed };
    },
    async requireActiveSubscription(walletId: string) {
      await serviceFor(walletId).requireActiveSubscription(walletId);
    },
  };

  return {
    service,

    async onPushDelivery(endpointId, body) {
      // Resolve the row here so the sealer can be bound to the right wallet before decrypt.
      const row = await store.findByEndpointId(endpointId);
      if (row === null) {
        deps.logger.info("push: delivery for unknown endpoint discarded");
        return;
      }
      const perRow = createPushReceiver({
        store,
        sealer: sealerFor(row.walletId),
        decryptor,
        sink: deps.sink,
        audit,
      });
      const outcome = await perRow.receive(endpointId, body);
      deps.logger.info(`push: delivery outcome=${outcome}`);
    },

    onWalletsMinted(walletIds) {
      // Fire-and-forget: the money tick must not await a third-party network call.
      void (async () => {
        for (const walletId of walletIds) {
          try {
            const { rows } = await deps.pool.query<{ public_key: string }>(
              `SELECT public_key FROM wallets WHERE id = $1::uuid AND node_id = $2::uuid`,
              [walletId, deps.nodeId],
            );
            const publicKey = rows[0]?.public_key;
            if (publicKey === undefined) continue;
            const result = await service.provision({ walletId, publicKey });
            deps.logger.info(
              `push: mint-time provision wallet=${walletId} outcome=${result.outcome}`,
            );
          } catch (err) {
            deps.logger.error(`push: mint-time provision failed wallet=${walletId}`, err);
          }
        }
      })();
    },

    async reconcileNow() {
      try {
        const summary = await service.reconcileAll();
        deps.logger.info(
          `push: boot reconcile checked=${summary.checked} active=${summary.alreadySubscribed} ` +
            `resubscribed=${summary.resubscribed} failed=${summary.failed}`,
        );
      } catch (err) {
        deps.logger.error("push: boot reconcile failed", err);
      }
    },

    startSweep(intervalMs = DEFAULT_PUSH_SWEEP_INTERVAL_MS) {
      let stopped = false;
      let timer: NodeJS.Timeout | null = null;
      const schedule = (): void => {
        if (stopped) return;
        const jittered = Math.floor(intervalMs * (0.75 + Math.random() * 0.5));
        timer = setTimeout(() => {
          void (async () => {
            try {
              const summary = await service.reconcileAll();
              deps.logger.info(
                `push: sweep checked=${summary.checked} active=${summary.alreadySubscribed} ` + // contract-allow:sweep:frozen structural vocabulary
                  `resubscribed=${summary.resubscribed} failed=${summary.failed}`,
              );
            } catch (err) {
              // A sweep failure must never kill the loop. // contract-allow:sweep:frozen structural vocabulary
              deps.logger.error("push: sweep pass failed", err); // contract-allow:sweep:frozen structural vocabulary
            }
            schedule();
          })();
        }, jittered);
        timer.unref?.();
      };
      // First run deferred one interval — boot already ran an immediate reconcile.
      schedule();
      return {
        stop() {
          stopped = true;
          if (timer !== null) clearTimeout(timer);
        },
      };
    },
  };
}

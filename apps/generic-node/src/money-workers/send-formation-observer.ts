// SEND formation observer from receive T0 observer (no submit).

import {
  RECEIVE_T0_OBSERVATION_ROLE,
  type ReceiveT0Observer,
  type SendFormationObserver,
} from "@zucoins/node-core";

export type { SendFormationObserver };

/**
 * Compose SendFormationObserver from the money-path T0 observer.
 *
 * Source and destination both OBSERVE through the same durable stream (gateway
 * get_transaction__v1, or the allowGenesisT0Stub-gated genesis stub). Destination
 * never invents a VERIFIED projection on the production money path — Wave-4 live
 * dest land widens submission, not dest T0 honesty.
 *
 * Projection role is preserved as observed. In particular genesis is
 * `{ role: "genesis", S: "", … }`; remapping empty-S to `role: "receiver"` makes
 * constructSendInner reject with invalid_genesis_link and blocks AWAITING_REDEMPTION.
 */
export function createSendFormationObserverFromReceiveT0(
  t0Observer: ReceiveT0Observer,
  opts?: {
    readonly observeDestination?: SendFormationObserver["observeDestination"];
  },
): SendFormationObserver {
  return {
    async observeSource(sourcePublicKey: string) {
      const outcome = await t0Observer.observe(
        sourcePublicKey,
        RECEIVE_T0_OBSERVATION_ROLE,
      );
      if (outcome.kind === "INDETERMINATE") {
        return { kind: "INDETERMINATE", detail: outcome.detail };
      }
      if (outcome.kind === "UNVERIFIED") {
        return { kind: "UNVERIFIED", detail: outcome.detail };
      }
      // Source formation needs a sender baseline; genesis source keeps role genesis so
      // empty-S links construct as GENESIS (HEAD + empty S is invalid_genesis_link).
      if (outcome.projection.role === "genesis") {
        return {
          kind: "VERIFIED" as const,
          observationId: outcome.observationId,
          projection: outcome.projection,
        };
      }
      return {
        kind: "VERIFIED" as const,
        observationId: outcome.observationId,
        projection: {
          role: "sender" as const,
          S: outcome.projection.S,
          P: outcome.projection.P,
          B: outcome.projection.B,
          I: outcome.projection.I,
        },
      };
    },
    observeDestination:
      opts?.observeDestination ??
      (async (destinationAddress: string) => {
        const outcome = await t0Observer.observe(
          destinationAddress,
          RECEIVE_T0_OBSERVATION_ROLE,
        );
        if (outcome.kind === "INDETERMINATE") {
          return { kind: "INDETERMINATE", detail: outcome.detail };
        }
        if (outcome.kind === "UNVERIFIED") {
          return { kind: "UNVERIFIED", detail: outcome.detail };
        }
        // Preserve observed role (genesis | sender | receiver). Never invent receiver+empty S.
        return {
          kind: "VERIFIED" as const,
          observationId: outcome.observationId,
          projection: outcome.projection,
        };
      }),
  };
}

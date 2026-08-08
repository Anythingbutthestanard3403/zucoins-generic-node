// EVENT_SIGNING is a custody authority, not a preferred sibling.
//
// Byte-exact is absolute: no committed transition without its signed event. The way to
// keep that true is to gate the AUTHORITY, never the transition — the shell must
// refuse to run an event-producing money worker while the event signer is absent,
// rather than let a transition commit and log the missing event as a residual.
//
// Two halves, both fail-closed:
//   boot    — `ensureActiveNodeSigningKey({purpose:"EVENT_SIGNING"})` failure
//             propagates out of boot recovery exactly like NODE_IDENTITY does, so
//             readiness never opens and `startMoneyWorkers` is never reached.
//             `arm` is the only thing that opens the readiness conjunct, and it is
//             called only on a signer that has already proven it can sign.
//   runtime — the first `sign` failure closes the readiness conjunct,
//             withdraws signer authority and quiesces the money surface, in the same
//             sequence graceful stop uses for its synchronous steps 1–2, and the failure
//             is rethrown so the in-flight READY transaction rolls back instead of
//             committing eventless.
//
// Scope of "readiness" here: node-core's ReadinessStateInputs.eventSignerAvailable,
// stamped through the boot/readiness.ts forwarder. One conjunct, three consumers: it
// stops `startMoneyWorkers` at boot, forces /health/ready to 503 (evaluateReadinessFromProbes
// gates on it like `stopping`), and makes money admission refuse with
// `event_signer_unavailable` — so a withdrawn node stops reporting healthy and stops
// admitting new money work (ZTR-1179).
//
// Once authority is withdrawn the armed signer keeps THROWING rather than reverting to
// null. A null signer is the appender's "skip the event, keep the money" branch
// (receive-ready-event-appender.ts) — reachable only before arm, never after a
// loss. Reverting to null on loss would hand a concurrently in-flight tick the
// eventless commit this arming contract exists to prevent.

import type { NodeEventSigner } from "@zucoins/node-core";

import type { NodeReadiness } from "./readiness.js";

export interface EventSignerAuthorityLogger {
  info(message: string): void;
  error(message: string, err?: unknown): void;
}

export interface EventSignerAuthorityDeps {
  readonly readiness: Pick<NodeReadiness, "setEventSignerAvailable">;
  /** Shutdown step SIGNER_AUTHORITY_WITHDRAW — `shutdownRegistry.hooks.withdrawSignerAuthority`. */
  readonly withdrawSignerAuthority: () => void;
  /** Shutdown step ENGINE_QUIESCE — `shutdownRegistry.hooks.stopWorkers`. */
  readonly stopWorkers: () => void;
  readonly logger: EventSignerAuthorityLogger;
}

export interface EventSignerAuthority {
  /**
   * Install a proven signer and open the `eventSigner` readiness conjunct.
   * Returns the signer to hold: a wrapper that reports the first signing failure
   * to {@link EventSignerAuthority.withdraw} and rethrows.
   */
  arm(signer: NodeEventSigner): NodeEventSigner;
  /**
   * Runtime authority loss. Idempotent — a quiesced money surface must not be
   * re-quiesced on every subsequent tick, and ENGINE_QUIESCE never reopens.
   */
  withdraw(reason: unknown): void;
  /** Test/inspection: authority has been withdrawn for the rest of the process. */
  readonly withdrawn: boolean;
}

export function createEventSignerAuthority(
  deps: EventSignerAuthorityDeps,
): EventSignerAuthority {
  let withdrawn = false;

  function withdraw(reason: unknown): void {
    if (withdrawn) return;
    withdrawn = true;
    deps.logger.error(
      "EVENT_SIGNING authority lost at runtime — readiness closed, signer authority withdrawn, " +
        "money surface quiesced (no custody transition may outrun its signed event)",
      reason,
    );
    // Same sequence as graceful-stop's synchronous steps: close the
    // readiness conjunct, drop the signing latch, then quiesce the engines. Each is
    // independently fail-closed, so a throw from one must not skip the rest.
    try {
      deps.readiness.setEventSignerAvailable(false);
    } finally {
      try {
        deps.withdrawSignerAuthority();
      } finally {
        deps.stopWorkers();
      }
    }
  }

  return {
    arm(signer: NodeEventSigner): NodeEventSigner {
      if (withdrawn) {
        // No reopen once withdrawn, matching ENGINE_QUIESCE's own monotonicity.
        throw new Error("EVENT_SIGNING authority already withdrawn — restart required");
      }
      deps.readiness.setEventSignerAvailable(true);
      const wrapped: NodeEventSigner = {
        signingKeyId: signer.signingKeyId,
        sign(preimageBytes: Uint8Array): string {
          if (withdrawn) {
            throw new Error("EVENT_SIGNING authority withdrawn — refusing to sign");
          }
          try {
            return signer.sign(preimageBytes);
          } catch (err) {
            withdraw(err);
            throw err;
          }
        },
      };
      return wrapped;
    },
    withdraw,
    get withdrawn(): boolean {
      return withdrawn;
    },
  };
}

/**
 * The boot half of signer-authority arming, extracted from `main` so it is executable in a test:
 * open → correspondence probe → arm, in that sequence, with no catch anywhere.
 *
 * Either failure — the sealed-store ensure inside `openSigner`, or the reopen-and-sign
 * probe — propagates to the caller (boot recovery), which is what keeps readiness closed
 * and money workers unarmed. The authority is armed only by a signer that has already
 * proven it can sign, and the probe runs the exact signer the appender will use, so a
 * key that opens but produces an unusable wire form is caught here. The probe signature
 * is discarded and never logged.
 */
export async function installEventSigner(deps: {
  readonly openSigner: () => Promise<NodeEventSigner>;
  readonly authority: Pick<EventSignerAuthority, "arm">;
  readonly logger: Pick<EventSignerAuthorityLogger, "info">;
}): Promise<NodeEventSigner> {
  const signer = await deps.openSigner();
  signer.sign(new Uint8Array());
  const armed = deps.authority.arm(signer);
  deps.logger.info(
    `boot: EVENT_SIGNING active signingKeyId=${signer.signingKeyId} (sealed-store; public only logged)`,
  );
  return armed;
}

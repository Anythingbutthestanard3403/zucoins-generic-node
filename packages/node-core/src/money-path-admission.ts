// production composition for money-path admission ports.
//
// Root-level (not core/operator/receive) so it may close over readiness +
// storage-backpressure + quarantine without breaking module boundaries
// (core ↛ operator/observation; receive ↛ core).
//
// Every money signUnderLease / captureReceiveT0 path MUST obtain gates from
// here (or an equivalent composition that always supplies the three ports).
// The signer boundary enforces this structurally.

import { assertNewMoneyWorkAdmitted } from "./core/money-admission.js";
import type { MoveSignerBoundaryDeps } from "./core/move-form-and-sign.js";
import type { ReadinessStateInputs } from "./core/readiness-state.js";
import {
  WalletSigningHaltedError,
  type MoneyPathSignerGates,
  type SignerBoundaryDeps,
} from "./core/signer-boundary.js";
import { isSigningHalted, type QuarantineWalletSnapshot } from "./observation/quarantine.js";
import {
  assertHaltAdmitsKind as assertOperatorHaltAdmitsKind,
  type HaltGate,
} from "./operator/halt.js";
import type { StorageBackpressure } from "./operator/storage-backpressure.js";
import type { CaptureReceiveT0Params } from "./receive/t0-capture.js";

export type { MoneyPathSignerGates };

export type MoneyPathWalletLookup = (
  walletId: string,
) => Promise<QuarantineWalletSnapshot | null | undefined>;

/**
 * Production admission ports: the three signer-boundary gates plus kind-scoped operator halt /
 * kind-scoped operator halt. Halt is deliberately NOT folded into
 * assertMoneyAdmitted — that shared chokepoint is also consulted by receive T0
 * capture and the money-worker tick, and a blanket halt would freeze
 * RECEIVE_EXTERNAL (revenue) which the decision exempts.
 */
export type MoneyPathAdmissionPorts = MoneyPathSignerGates & {
  /**
   * Refuse first formation of MOVE_INTERNAL / SEND_EXTERNAL while halt engaged.
   * RECEIVE_EXTERNAL always admits. No-op when haltGate was omitted (harness).
   */
  readonly assertHaltAdmitsKind: (kind: string) => void;
};

export interface MoneyPathAdmissionPortInput {
  /** Live readiness stamp (schema/vault/observation/stopping). */
  readonly snapshotReadiness: () => ReadinessStateInputs;
  /**
   * Live DB reachability. Composition keeps this fresh (health CachedDbProbe
   * cache, or fail-closed ` => false` until a database adapter exists).
   */
  readonly isDatabaseReachable: () => boolean;
  /** Storage CRITICAL / HALTED operate gate. */
  readonly assertCanOperate: () => void;
  /**
   * Optional quarantine / signing-halt lookup. When omitted, wallet gate admits
   * (no quarantine store yet). When present, isSigningHalted wallets refuse.
   */
  readonly getWallet?: MoneyPathWalletLookup;
  /**
   * Operator emergency halt (kind-scoped operator halt). When set, assertHaltAdmitsKind
   * gates MOVE/SEND first formation only. assertMoneyAdmitted stays halt-free
   * so RECEIVE_EXTERNAL (T0 + worker tick) continues. Fail-open when omitted
   * so unit harnesses without a halt stack stay unchanged.
   */
  readonly haltGate?: HaltGate;
}

/**
 * Always-populated money gates for production money paths.
 * Value sites assign these onto SignerBoundaryDeps / CaptureReceiveT0Params.
 */
export function createMoneyPathAdmissionPorts(
  input: MoneyPathAdmissionPortInput,
): MoneyPathAdmissionPorts {
  const getWallet = input.getWallet;
  const haltGate = input.haltGate;
  return Object.freeze({
    assertMoneyAdmitted: (): void => {
      // Readiness / DB only. Operator halt is kind-scoped — see assertHaltAdmitsKind.
      assertNewMoneyWorkAdmitted(input.snapshotReadiness(), input.isDatabaseReachable());
    },
    assertCanOperate: (): void => {
      input.assertCanOperate();
    },
    assertWalletMaySign: async (walletId: string): Promise<void> => {
      if (getWallet === undefined) return;
      const wallet = await getWallet(walletId);
      if (wallet !== null && wallet !== undefined && isSigningHalted(wallet)) {
        throw new WalletSigningHaltedError(walletId);
      }
    },
    assertHaltAdmitsKind: (kind: string): void => {
      if (haltGate === undefined) return;
      assertOperatorHaltAdmitsKind(haltGate, kind);
    },
  });
}

/**
 * Build money-path SignerBoundaryDeps with required gates always installed.
 */
export function createMoneySignerBoundaryDeps(
  base: Omit<SignerBoundaryDeps, keyof MoneyPathSignerGates>,
  ports: MoneyPathSignerGates,
): SignerBoundaryDeps {
  return {
    leadership: base.leadership,
    leaseReader: base.leaseReader,
    vaultSigner: base.vaultSigner,
    auditLog: base.auditLog,
    now: base.now,
    // ZTR-1160: pin lease FOR UPDATE across vault sign + SIGNED audit when the composition
    // root supplies a transaction scope (production SEND/MOVE/RECEIVE).
    ...(base.withSignTransaction !== undefined
      ? { withSignTransaction: base.withSignTransaction }
      : {}),
    assertMoneyAdmitted: ports.assertMoneyAdmitted,
    assertCanOperate: ports.assertCanOperate,
    assertWalletMaySign: ports.assertWalletMaySign,
  };
}

/**
 * MOVE_INTERNAL first-formation deps: three recovery gates plus required kind-scoped operator halt
 * kind-scope halt port consumed by {@link signMoveStepsUnderLeases}.
 */
export function createMoneyMoveSignerBoundaryDeps(
  base: Omit<SignerBoundaryDeps, keyof MoneyPathSignerGates>,
  ports: MoneyPathAdmissionPorts,
): MoveSignerBoundaryDeps {
  return {
...createMoneySignerBoundaryDeps(base, ports),
    assertHaltAdmitsKind: ports.assertHaltAdmitsKind,
  };
}

/**
 * Build CaptureReceiveT0Params with required assertMoneyAdmitted installed.
 */
export function createMoneyCaptureReceiveT0Params(
  base: Omit<CaptureReceiveT0Params, "assertMoneyAdmitted">,
  ports: Pick<MoneyPathSignerGates, "assertMoneyAdmitted">,
): CaptureReceiveT0Params {
  return {
    operationId: base.operationId,
    walletId: base.walletId,
    observer: base.observer,
    assertMoneyAdmitted: ports.assertMoneyAdmitted,
  };
}

/** Convenience: ports from readiness + backpressure + optional quarantine/halt. */
export function createMoneyPathAdmissionPortsFromRuntime(input: {
  readonly snapshotReadiness: () => ReadinessStateInputs;
  readonly isDatabaseReachable: () => boolean;
  readonly backpressure: StorageBackpressure;
  readonly getWallet?: MoneyPathWalletLookup;
  readonly haltGate?: HaltGate;
}): MoneyPathAdmissionPorts {
  return createMoneyPathAdmissionPorts({
    snapshotReadiness: input.snapshotReadiness,
    isDatabaseReachable: input.isDatabaseReachable,
    assertCanOperate: () => {
      input.backpressure.assertCanOperate();
    },
    getWallet: input.getWallet,
    haltGate: input.haltGate,
  });
}

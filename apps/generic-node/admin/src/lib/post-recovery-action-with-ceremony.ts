/**
 * POST recovery-actions with max ceremony for operator-risk release (ZTR-1280).
 * Other actions keep the existing TOTP + nonce path.
 */

import { getRecovery, postRecoveryAction, recoveryActionLabel } from "./money.js";
import { signOperatorRiskRecovery } from "./recovery-operator-risk-sign.js";

export async function postRecoveryActionWithCeremony(
  operationId: string,
  action: string,
  totp: string,
): Promise<Awaited<ReturnType<typeof postRecoveryAction>>> {
  const fresh = await getRecovery(operationId);

  if (action === "RELEASE_EXPIRED_RECEIVE_OPERATOR_RISK") {
    const overrideRationale =
      typeof globalThis.prompt === "function"
        ? globalThis.prompt(
            "Operator-accepted risk release — T0-unchanged is NOT proven.\n" +
              "Record why you override the failing release predicates (min 8 chars):",
            "Gateway permanently unreadable; custody capacity recovery after durable attention park.",
          )
        : null;
    if (overrideRationale === null || overrideRationale.trim().length < 8) {
      throw new Error("Override rationale is required for operator-risk release (min 8 characters).");
    }
    const walletChoice =
      typeof globalThis.confirm === "function"
        ? globalThis.confirm(
            "Return wallet to AVAILABLE pool?\n\n" +
              "OK = AVAILABLE (explicit operator choice)\n" +
              "Cancel = leave QUARANTINED after release",
          )
        : true;
    const device = await signOperatorRiskRecovery({
      operationId,
      recoveryNonce: fresh.recovery_nonce,
      overrideRationale: overrideRationale.trim(),
      walletToAvailable: walletChoice,
    });
    return postRecoveryAction(
      operationId,
      {
        action,
        expected_row_version: fresh.row_version,
        recovery_nonce: fresh.recovery_nonce,
        override_rationale: overrideRationale.trim(),
        wallet_to_available: walletChoice,
        device_key_id: device.device_key_id,
        device_signature: device.device_signature,
        operator_note: overrideRationale.trim(),
      },
      totp,
    );
  }

  return postRecoveryAction(
    operationId,
    {
      action,
      expected_row_version: fresh.row_version,
      recovery_nonce: fresh.recovery_nonce,
    },
    totp,
  );
}

export function recoveryActionConfirmDetail(action: string): string {
  if (action === "RELEASE_EXPIRED_RECEIVE_OPERATOR_RISK") {
    return (
      `${recoveryActionLabel(action)} — released on operator-accepted risk; ` +
      `T0-unchanged NOT proven. Requires device signature + override rationale.`
    );
  }
  return recoveryActionLabel(action);
}

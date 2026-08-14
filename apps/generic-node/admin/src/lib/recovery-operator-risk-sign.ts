/**
 * Device signature helper for RELEASE_EXPIRED_RECEIVE_OPERATOR_RISK (ZTR-1280).
 * Signs the deterministic recovery preimage with a local enrolled device key.
 */

import { buildOperatorRiskRecoveryPreimage, listDeviceKeys } from "./money.js";
import {
  getDeviceRecord,
  listLocalDeviceRecords,
  signPreimage,
} from "./device-crypto.js";

export interface OperatorRiskDeviceFields {
  readonly device_key_id: string;
  readonly device_signature: string;
}

export async function signOperatorRiskRecovery(input: {
  readonly operationId: string;
  readonly recoveryNonce: string;
  readonly overrideRationale: string;
  readonly walletToAvailable: boolean;
}): Promise<OperatorRiskDeviceFields> {
  const preimage = buildOperatorRiskRecoveryPreimage(input);
  const keys = await listDeviceKeys();
  const locals = await listLocalDeviceRecords();
  const localIds = new Set(locals.map((l) => l.id));
  const match = keys.find((k) => localIds.has(k.id));
  if (match === undefined) {
    throw new Error(
      "Device signature required for operator-risk release — enrol a device key on this browser.",
    );
  }
  const local = await getDeviceRecord(match.id);
  if (local === null) {
    throw new Error(
      "Local device private key missing — re-enrol this device before operator-risk release.",
    );
  }
  const device_signature = await signPreimage(local.privateKey, preimage);
  return { device_key_id: match.id, device_signature };
}

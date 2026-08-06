/**
 * Shared genesis Device #1 enrol.
 *
 * Same path as DevicesPage: challenge → WebCrypto keypair → PoP → enrol + TOTP
 * → IndexedDB non-extractable private key. Destinations are not involved.
 */

import {
  buildDeviceEnrolPreimage,
  generateDeviceKeyPair,
  putDeviceRecord,
  randomUuid,
  signPreimage,
} from "./device-crypto.js";
import {
  postEnrollmentChallenge,
  postGenesisEnrol,
  type GenesisEnrolResult,
} from "./money.js";

export async function runGenesisDeviceEnrol(opts: {
  readonly label: string;
  readonly totp: string;
}): Promise<GenesisEnrolResult> {
  const label = opts.label.trim();
  if (label.length === 0) {
    throw new Error("Label is required.");
  }
  const challenge = await postEnrollmentChallenge();
  const pair = await generateDeviceKeyPair();
  const deviceId = randomUuid();
  const preimage = buildDeviceEnrolPreimage({
    node_id: challenge.node_id,
    new_device_key_id: deviceId,
    new_device_public_key: pair.publicKey,
    label,
    nonce: challenge.nonce,
    issued_at: challenge.issued_at,
    expires_at: challenge.expires_at,
  });
  const pop = await signPreimage(pair.privateKey, preimage);
  const result = await postGenesisEnrol(
    {
      label,
      new_device_key_id: deviceId,
      new_device_public_key: pair.publicKey,
      new_device_pop_signature: pop,
      challenge_nonce: challenge.nonce,
    },
    opts.totp,
  );
  await putDeviceRecord({
    id: result.id,
    label: result.label,
    publicKey: pair.publicKey,
    createdAt: result.enrolled_at,
    nodeId: challenge.node_id,
    privateKey: pair.privateKey,
  });
  return result;
}

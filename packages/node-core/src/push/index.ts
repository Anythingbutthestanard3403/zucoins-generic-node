// channel 1 — SplitChain Web Push, the primary detection channel for EXTERNAL
// receives. Policy + the single RFC 8291 aes128gcm decrypt live here. SQL and the
// push-API transport remain app-supplied ports; the decryptor port's production binding
// is `decryptWebPushPayload` in this package.
//
// Inbound factors (ZTR-1161):
//   1. ECE auth secret + endpoint id (AEAD) — always required to decrypt.
//   2. RFC 8292 VAPID Authorization — verified against the stored app-server public
//      key before decrypt. Default mode is observe (count+audit); enforce fails closed
//      while the HTTP edge stays uniform 204. See receiver.ts + PUSH_VAPID_MODE.

export { decodeTolerantBase64 } from "./base64-tolerant.js";

export {
  generateAuthSecret,
  generateEcdhKeypair,
  ecdhFromPrivateKeyBytes,
  type EcdhKeypair,
} from "./crypto.js";

export {
  decryptWebPushPayload,
  WebPushDecryptError,
  type DecryptWebPushPayloadParams,
} from "./aes128gcm.js";
export {
  assertHttpEceKeyLoggingDisabled,
  HTTP_ECE_KEYLOG_REFUSAL,
} from "./http-ece-keylog.js";

export {
  buildPushEndpointUrl,
  generateEndpointId,
  isValidEndpointId,
  ENDPOINT_ID_PATTERN,
  PUSH_RECEIVER_PATH_PREFIX,
} from "./endpoint.js";

export {
  buildIdProofQuery,
  type BuildIdProofQueryParams,
  type PushIdProofSigner,
} from "./id-proof.js";

export {
  parsePushCleartext,
  resolveTransferCodeFromEnvelope,
  type ResolvedPushDelivery,
} from "./payload.js";

export {
  buildPushReceiverDekInfo,
  buildPushSecretAad,
  createPushSecretSealer,
  PUSH_RECEIVER_DEK_HKDF_LABEL,
  PushSealError,
} from "./seal.js";

export {
  createPushReceiver,
  type PushReceiver,
  type PushReceiverDeps,
  type PushReceiveOutcome,
  type PushTransferCodeSink,
  type PushVapidMode,
  type PushVapidOutcome,
} from "./receiver.js";

export type {
  PushAuditSink,
  PushGatewayActions,
  PushSecretPurpose,
  PushSecretSealer,
  PushSubscriptionRow,
  PushSubscriptionStatus,
  PushSubscriptionStore,
  PushWalletRef,
  WebPushPayloadDecryptor,
} from "./store.js";

export {
  createPushSubscriptionService,
  PushSubscriptionRequiredError,
  type ProvisionResult,
  type PushSubscriptionService,
  type PushSubscriptionServiceDeps,
  type ReconcileSummary,
} from "./subscription-service.js";

export {
  rewrapPushSecretStore,
  type PushSecretRewrapInput,
  type PushSecretRewrapRow,
} from "./rewrap.js";

export {
  parseVapidAuthorizationHeader,
  verifyVapidAuthorization,
  type VerifyVapidAuthorizationParams,
} from "./vapid-jwt.js";

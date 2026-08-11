// Ports for the push subscription lifecycle. node-core owns the policy and the single
// RFC 8291 aes128gcm decrypt implementation; the app supplies SQL, a decryptor binding
// (thin adapter over `decryptWebPushPayload`), and the gateway transport. DB drivers stay
// out of this package — `http_ece` is the one sanctioned non-DB dependency here.

/** Lifecycle state of one wallet's subscription. */
export type PushSubscriptionStatus = "ACTIVE" | "FAILED";

export interface PushSubscriptionRow {
  readonly walletId: string;
  readonly walletPublicKey: string;
  readonly endpointId: string;
  /** Node's P-256 ECDH public key (the subscription `p256dh`). Non-secret. */
  readonly receiverEcdhPublic: string;
  /** Sealed private half — opaque envelope text, opened only through the vault seam. */
  readonly receiverEcdhPrivateSealed: string;
  /** Sealed 16-byte `auth` secret. */
  readonly receiverAuthSecretSealed: string;
  readonly status: PushSubscriptionStatus;
  /**
   * SplitChain app-server VAPID public key captured at last successful subscribe
   * (RFC 8292 trust root). Null on rows provisioned before the key was selected,
   * or while still FAILED before the first ACTIVE mark.
   */
  readonly appServerPublicKey: string | null;
}

export interface PushSubscriptionStore {
  /** Existing row for a wallet, or null. */
  findByWalletId(walletId: string): Promise<PushSubscriptionRow | null>;
  /** Row addressed by the opaque endpoint id — the inbound receiver lookup. */
  findByEndpointId(endpointId: string): Promise<PushSubscriptionRow | null>;
  /**
   * Insert a new subscription. Status starts FAILED: pessimistic until the gateway
   * subscribe actually acknowledges, so a crash between insert and ack can never leave a
   * row claiming an active remote subscription that does not exist.
   */
  insert(row: PushSubscriptionRow): Promise<void>;
  /**
   * Replace an existing row's sealed receive material in place, keeping its endpoint id.
   * The recovery path for a row whose envelopes no longer open: `insert` cannot heal it
   * (it is ON CONFLICT DO NOTHING by design, so a re-mint would silently no-op and the
   * wallet would keep unusable keys). Returns the row to FAILED — the gateway still holds
   * the superseded public half until a subscribe acknowledges the new one.
   */
  replaceSealedMaterial(input: {
    readonly walletId: string;
    readonly receiverEcdhPublic: string;
    readonly receiverEcdhPrivateSealed: string;
    readonly receiverAuthSecretSealed: string;
  }): Promise<void>;
  /** Record the outcome of a subscribe attempt. */
  markStatus(
    walletId: string,
    status: PushSubscriptionStatus,
    appServerPublicKey: string | null,
  ): Promise<void>;
  /** Every wallet that should hold a subscription, for the boot reconcile and sweep. */ // contract-allow:sweep:frozen structural vocabulary
  listSubscribableWallets(): Promise<readonly PushWalletRef[]>;
}

export interface PushWalletRef {
  readonly walletId: string;
  readonly publicKey: string;
}

/** Which secret an envelope holds. Part of the AAD, so it cannot be confused on open. */
export type PushSecretPurpose = "ECDH_PRIVATE" | "AUTH_SECRET";

/**
 * Seals/opens one wallet's push secrets. Supplied by the app so node-core never holds a
 * root key. `purpose` is explicit on both sides rather than inferred from call order — // contract-allow:order:frozen structural vocabulary
 * the two secrets have different lengths and different AADs, and guessing between them
 * would be a silent cross-purpose decrypt waiting to happen.
 */
export interface PushSecretSealer {
  seal(plaintext: Uint8Array, purpose: PushSecretPurpose): Promise<string>;
  open(sealed: string, purpose: PushSecretPurpose): Promise<Buffer>;
}

/** RFC 8291 / RFC 8188 `aes128gcm` decrypt. Production binding is node-core's `decryptWebPushPayload`. */
export interface WebPushPayloadDecryptor {
  decrypt(input: {
    readonly body: Buffer;
    readonly ecdhPrivateKeyBytes: Buffer;
    readonly authSecret: Buffer;
  }): Promise<Uint8Array>;
}

/** The three push-API calls the inbound leg needs. */
export interface PushGatewayActions {
  subscribe(input: {
    readonly idProofQuery: string;
    readonly endpoint: string;
    readonly keyP256dh: string;
    readonly keyAuth: string;
  }): Promise<void>;
  hasSubscriptionForPublicKey(walletPublicKey: string): Promise<boolean>;
  getAppServerPublicKey(): Promise<string>;
}

export interface PushAuditSink {
  record(event: {
    readonly type: string;
    readonly walletId: string;
    readonly detail: Record<string, unknown>;
  }): Promise<void>;
}

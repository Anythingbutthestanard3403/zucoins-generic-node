// The id-proof query accompanying `push_notification__subscribe__v1__tos2d5b5md`.
//
// It proves the node controls the wallet's private key by signing a fresh timestamp with
// it, so the push service will bind our endpoint to that pubkey. Field names and their
// ORDER are transcribed from the wallet's own subscribe path and must not be reordered // contract-allow:order:frozen structural vocabulary
// or renamed: the receiving service reads them positionally out of the query string.
//
// The signature is produced by the caller's VaultSigner (the wallet secret never leaves
// the vault seam), and is the padded 88-char base64url form every other Ed25519
// signature on this node uses.

/** Signs UTF-8 preimage bytes with the wallet's Ed25519 key, returning padded base64url. */
export type PushIdProofSigner = (
  walletId: string,
  preimageBytes: Uint8Array,
) => Promise<string>;

export interface BuildIdProofQueryParams {
  readonly walletId: string;
  readonly walletPublicKeyB64url: string;
  readonly sign: PushIdProofSigner;
  /** Pure tracking string, not signed or verified. */
  readonly nodeVersion?: string;
  /** Injectable for deterministic tests. */
  readonly nowSecs?: number;
}

const DEFAULT_NODE_VERSION = "1";

/**
 * Build `id_proof__url_query`. The signed preimage is the timestamp as a UTF-8 decimal
 * string — the same bytes the wallet signs — and the five parameters are appended in the
 * exact documented order. // contract-allow:order:frozen structural vocabulary
 */
export async function buildIdProofQuery(params: BuildIdProofQueryParams): Promise<string> {
  const nowSecs = params.nowSecs ?? Math.floor(Date.now() / 1000);
  const timestampStr = String(nowSecs);
  const signature = await params.sign(params.walletId, Buffer.from(timestampStr, "utf8"));

  const query = new URLSearchParams();
  query.append("utm_source", `zupayments_node_v${params.nodeVersion ?? DEFAULT_NODE_VERSION}`);
  query.append("zucoin__data_pass_through__version", "1");
  query.append(
    "zucoin__data_pass_through__key_public__base64urlsafe",
    params.walletPublicKeyB64url,
  );
  query.append("zucoin__data_pass_through__data_timestamp_secs", timestampStr);
  query.append(
    "zucoin__data_pass_through__data_timestamp_secs_signature__base64urlsafe",
    signature,
  );
  return query.toString();
}

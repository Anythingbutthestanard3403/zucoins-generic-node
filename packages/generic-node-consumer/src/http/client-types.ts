/**
 * Shared transport plumbing for every wrapped route. `fetchImpl` is always injectable so
 * callers can point the SDK at any Fetch-compatible implementation and so tests never open a
 * real socket (this package's own tests inject a stub — see test/setup-network-guard.ts, which
 * denies the platform network primitives the same way @zucoins/consumer-example's
 * network-contained test guard does).
 */

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface NodeClientConfig {
  /** Node's exact base origin, no trailing slash (e.g. "https://node.example.com"). */
  readonly baseUrl: string;
  readonly fetchImpl?: FetchLike;
}

/**
 * Join a base origin with the exact raw request target (opaque, used byte-for-byte).
 * The target string is never re-encoded or re-parsed here — it is the same string used, byte
 * for byte, as the signed reporting `path` field when the route requires one.
 */
export function resolveUrl(config: NodeClientConfig, rawTarget: string): string {
  return `${config.baseUrl}${rawTarget}`;
}

export function resolveFetch(config: NodeClientConfig): FetchLike {
  return config.fetchImpl ?? ((input, init) => fetch(input, init));
}

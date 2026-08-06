// net surface barrel.
export {
  DEFAULT_TRUST_PROXY_HOPS,
  clientIpFromXff,
  parseTrustProxyDirectExposure,
  parseTrustProxyHops,
  resolveClientIp,
  trustProxyOptionsFromEnv,
  type ResolveClientIpOptions,
} from "./client-ip.js";

export {
  validateHostAndOrigin,
  type HostValidationOutcome,
  type NodeIdentityConfig,
} from "./host-validate.js";

export {
  DNS_RESOLUTION_TIMEOUT_MS,
  SsrfError,
  assertUrlSafe,
  resolveAndPin,
  validateUrl,
  type DnsResolver,
  type ResolvedAddress,
  type SsrfOptions,
  type SsrfReason,
} from "./ssrf-guard.js";

export {
  MAX_RESPONSE_DRAIN_BYTES,
  OutboundHttpCensus,
  drainBounded,
  pinnedTargetFromUrl,
  type PinnedTarget,
} from "./pinned-send.js";

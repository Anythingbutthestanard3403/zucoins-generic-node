// SSRF guard for the nodes remaining outbound HTTP class // contract-allow:outbound:frozen structural vocabulary
// (boot-configured SplitChain gateway endpoint; single canonical SSRF guard validate-at-registration +
// pin-at-connect; reporting-key enrolment ceremony egress absence for every other target). Pure classifier
// over a URL string + injectable DNS resolver. No product/implementer coupling.
//
// TWO PHASES — both required:
// 1. validateUrl — syntactic + literal-IP checks (usable at boot/register).
// 2. resolveAndPin — DNS at CONNECT time; fails closed on any blocked A/AAAA.
// `assertUrlSafe` runs both. Redirects must be disabled or revalidated.
//
// CONNECT-TIME PINNING: connect to a returned pinned IP with the original
// hostname as TLS SNI / Host — never re-resolve (DNS-rebind defence).

import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

export type SsrfReason =
  | "invalid_url"
  | "scheme_not_allowed"
  | "not_https"
  | "blocked_host"
  | "blocked_ip"
  | "dns_resolution_failed"
  | "dns_resolution_timeout"
  | "no_addresses";

export class SsrfError extends Error {
  readonly reason: SsrfReason;
  constructor(reason: SsrfReason, message: string) {
    super(message);
    this.name = "SsrfError";
    this.reason = reason;
  }
}

/** One resolved address, mirroring the shape of `dns.lookup(host,{all:true})`. */
export interface ResolvedAddress {
  address: string;
  family: number;
}

/** Injectable resolver — the default hits real DNS; tests pass a mock. */
export type DnsResolver = (host: string) => Promise<ResolvedAddress[]>;

const defaultResolver: DnsResolver = (host) =>
  // `verbatim: true` keeps the OS result sequence; we check ALL results regardless.
  lookup(host, { all: true, verbatim: true });

/**
 * Wall-clock bound on the connect-time DNS resolve. Matches the 10s
 * ceiling every other outbound leg already uses — `delivery-queue.ts` // contract-allow:outbound:frozen structural vocabulary
 * `DELIVERY_TIMEOUT_MS` (the sibling outbound HTTP POST), `reporting/pusher.ts` // contract-allow:outbound:frozen structural vocabulary
 * `DEFAULT_TRANSPORT_TIMEOUT_MS`; `rate/rate-fetch.ts` mirrors the same value at
 * 5s. Without it, a hostile/black-hole DNS server for one caller's host makes
 * `resolveAndPin` hang forever, which (via the outbound worker's // contract-allow:outbound:frozen structural vocabulary
 * `Promise.allSettled` batch + non-overlapping tick guard) deadlocks EVERY
 * caller's outbound delivery on the node until restart. // contract-allow:outbound:frozen structural vocabulary
 */
export const DNS_RESOLUTION_TIMEOUT_MS = 10_000;

export interface SsrfOptions {
  /** Reject non-HTTPS URLs. Default true (HTTPS-only outbound in prod). */ // contract-allow:outbound:frozen structural vocabulary
  requireHttps?: boolean;
  /** DNS resolver override (tests inject rebinding scenarios). */
  resolver?: DnsResolver;
  /**
   * Wall-clock bound (ms) on the resolve step in `resolveAndPin`. Defaults to
   * DNS_RESOLUTION_TIMEOUT_MS. Overridable so tests can force a fast timeout
   * without a 10s wait.
   */
  dnsTimeoutMs?: number;
}

/**
 * Resolve `host` but reject with an SsrfError("dns_resolution_timeout") if the
 * resolver has not settled within `timeoutMs`. This bounds the *promise* the
 * caller awaits; note that `dns.lookup` (getaddrinfo, run on the libuv thread
 * pool) is NOT cancellable, so the underlying lookup keeps running until the OS
 * resolver's own timeout releases it — but the caller (and therefore the
 * outbound delivery worker) is unblocked immediately, which is what unwedges the // contract-allow:outbound:frozen structural vocabulary
 * batch. The timer is unref'd so it never keeps the event loop alive on its own.
 */
async function resolveWithTimeout(
  resolver: DnsResolver,
  host: string,
  timeoutMs: number,
): Promise<ResolvedAddress[]> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      reject(
        new SsrfError(
          "dns_resolution_timeout",
          `DNS resolution for ${host} exceeded ${timeoutMs}ms`,
        ),
      );
    }, timeoutMs);
    if (typeof timer === "object" && timer && "unref" in timer) {
      (timer as { unref: () => void }).unref();
    }
  });
  try {
    return await Promise.race([resolver(host), timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

// Hostnames that must never be fetched even before/independent of resolution.
const BLOCKED_HOST_LITERALS = new Set<string>([
  "localhost",
  "metadata.google.internal", // GCP metadata (single canonical SSRF guard)
  "metadata", // common short alias
]);

// Hostname SUFFIXES that must never be fetched (interior-DNS / mDNS zones). Ported from
// the retired lib/url-safety.ts when the two SSRF guards were deconflicted into
// this single canonical validator — this guard is now a strict superset of
// both. `.localhost` = RFC 6761 subnames of localhost; `.internal` / `.local` = common
// private-DNS / mDNS zones. No valid public host ends in these, so no false positives.
const BLOCKED_HOST_SUFFIXES: readonly string[] = [".internal", ".local", ".localhost"];

// ---------------------------------------------------------------------------
// IP literal parsing — attacker-supplied hosts can encode an IP in many forms
// that `new URL` does NOT canonicalise. We normalise to bytes ourselves so a
// numeric/obfuscated literal is classified against the blocklist BEFORE any DNS
// step (getaddrinfo would also decode e.g. `2130706433`, but we must not depend
// on platform resolver behaviour — and a mock resolver in tests would not).
// ---------------------------------------------------------------------------

/** Parse a single IPv4 octet/word written in decimal, octal (0…) or hex (0x…). */
function parseNumericPart(part: string): number | null {
  if (part.length === 0) return null;
  let value: number;
  if (/^0[xX][0-9a-fA-F]+$/.test(part)) {
    value = parseInt(part.slice(2), 16);
  } else if (/^0[0-7]+$/.test(part)) {
    value = parseInt(part, 8);
  } else if (part === "0") {
    value = 0;
  } else if (/^[1-9][0-9]*$/.test(part)) {
    value = parseInt(part, 10);
  } else {
    return null; // not a valid numeric token (e.g. "08", "0xG", "1a")
  }
  return Number.isFinite(value) ? value : null;
}

/**
 * Decode an IPv4 literal in any inet_aton-style form into 4 bytes, or null if
 * `host` is not a numeric IPv4 literal. Handles: a.b.c.d, a.b.c (c=16-bit),
 * a.b (b=24-bit), a (a=32-bit), each part decimal/octal/hex. This mirrors what
 * `getaddrinfo`/`inet_aton` accept, which is the actual attack surface.
 */
function parseIpv4Literal(host: string): number[] | null {
  const parts = host.split(".");
  if (parts.length === 0 || parts.length > 4) return null;

  const nums: number[] = [];
  for (const p of parts) {
    const n = parseNumericPart(p);
    if (n === null) return null;
    nums.push(n);
  }

  // inet_aton packing rules: the final part absorbs the remaining bytes.
  const bytes = [0, 0, 0, 0];
  const last = nums[nums.length - 1];
  const leading = nums.slice(0, -1);
  const maxLast = 2 ** (8 * (4 - leading.length));
  if (last < 0 || last >= maxLast) return null;
  for (let i = 0; i < leading.length; i++) {
    if (leading[i] < 0 || leading[i] > 255) return null;
    bytes[i] = leading[i];
  }
  // Spread `last` across the trailing byte positions, big-endian.
  for (let i = 0; i < 4 - leading.length; i++) {
    bytes[3 - i] = Math.floor(last / 2 ** (8 * i)) & 0xff;
  }
  return bytes;
}

/** Parse a standard-notation IPv6 string (incl. `::` and embedded IPv4) to 16 bytes. */
function parseIpv6Literal(host: string): number[] | null {
  let str = host;
  // Strip a zone id (fe80::1%eth0) — irrelevant to range classification.
  const pct = str.indexOf("%");
  if (pct !== -1) str = str.slice(0, pct);

  if (isIP(str) !== 6) return null;

  // Embedded IPv4 tail (::ffff:127.0.0.1 or ::1.2.3.4) → fold into two hextets.
  if (str.includes(".")) {
    const lastColon = str.lastIndexOf(":");
    const v4 = str.slice(lastColon + 1);
    const v4Parts = v4.split(".").map((p) => parseInt(p, 10));
    if (v4Parts.length !== 4 || v4Parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
      return null;
    }
    str = `${str.slice(0, lastColon + 1)}${((v4Parts[0] << 8) | v4Parts[1]).toString(16)}:${(
      (v4Parts[2] << 8) |
      v4Parts[3]
    ).toString(16)}`;
  }

  const halves = str.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 ? (halves[1] ? halves[1].split(":") : []) : null;

  const groups: number[] = [];
  const pushGroup = (g: string): boolean => {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return false;
    groups.push(parseInt(g, 16));
    return true;
  };

  if (tail === null) {
    if (head.length !== 8) return null;
    for (const g of head) if (!pushGroup(g)) return null;
  } else {
    for (const g of head) if (!pushGroup(g)) return null;
    const zeros = 8 - head.length - tail.length;
    if (zeros < 1) return null; // `::` must stand for >=1 zero group
    for (let i = 0; i < zeros; i++) groups.push(0);
    for (const g of tail) if (!pushGroup(g)) return null;
  }
  if (groups.length !== 8) return null;

  const bytes: number[] = [];
  for (const g of groups) {
    bytes.push((g >> 8) & 0xff, g & 0xff);
  }
  return bytes;
}

function inRange4(bytes: number[], prefix: number[], bits: number): boolean {
  let remaining = bits;
  for (let i = 0; i < 4 && remaining > 0; i++) {
    const take = Math.min(8, remaining);
    const mask = (0xff << (8 - take)) & 0xff;
    if ((bytes[i] & mask) !== (prefix[i] & mask)) return false;
    remaining -= take;
  }
  return true;
}

// IPv4 ranges that must never be fetched. Spec-required (single canonical SSRF guard):
// 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16. The rest are defence in
// depth (unspecified, CGNAT, benchmarking, doc/test nets, multicast, reserved,
// broadcast) — all non-routable-to-the-internet or internal.
const V4_BLOCKS: Array<{ prefix: number[]; bits: number; label: string }> = [
  { prefix: [0, 0, 0, 0], bits: 8, label: "unspecified/this-network 0.0.0.0/8" },
  { prefix: [10, 0, 0, 0], bits: 8, label: "private 10.0.0.0/8" },
  { prefix: [100, 64, 0, 0], bits: 10, label: "CGNAT 100.64.0.0/10" },
  { prefix: [127, 0, 0, 0], bits: 8, label: "loopback 127.0.0.0/8" },
  { prefix: [169, 254, 0, 0], bits: 16, label: "link-local/metadata 169.254.0.0/16" },
  { prefix: [172, 16, 0, 0], bits: 12, label: "private 172.16.0.0/12" },
  { prefix: [192, 0, 0, 0], bits: 24, label: "IETF protocol 192.0.0.0/24" },
  { prefix: [192, 0, 2, 0], bits: 24, label: "TEST-NET-1 192.0.2.0/24" },
  { prefix: [192, 168, 0, 0], bits: 16, label: "private 192.168.0.0/16" },
  { prefix: [198, 18, 0, 0], bits: 15, label: "benchmark 198.18.0.0/15" },
  { prefix: [198, 51, 100, 0], bits: 24, label: "TEST-NET-2 198.51.100.0/24" },
  { prefix: [203, 0, 113, 0], bits: 24, label: "TEST-NET-3 203.0.113.0/24" },
  { prefix: [224, 0, 0, 0], bits: 4, label: "multicast 224.0.0.0/4" },
  { prefix: [240, 0, 0, 0], bits: 4, label: "reserved 240.0.0.0/4" },
];

function classifyV4(bytes: number[]): string | null {
  for (const b of V4_BLOCKS) {
    if (inRange4(bytes, b.prefix, b.bits)) return b.label;
  }
  return null;
}

function classifyV6(bytes: number[]): string | null {
  // IPv4-mapped (::ffff:0:0/96) — reclassify the embedded IPv4 so
  // `::ffff:127.0.0.1` is caught by the v4 blocklist.
  const first10Zero = bytes.slice(0, 10).every((x) => x === 0);
  if (first10Zero && bytes[10] === 0xff && bytes[11] === 0xff) {
    return classifyV4(bytes.slice(12, 16));
  }
  // IPv4-compatible ::a.b.c.d (deprecated) — first 12 bytes zero, non-trivial tail
  // (the `!(…<=1)` guard excludes :: and ::1, handled below). Reclassify the embedded
  // IPv4 so e.g. `::127.0.0.1` / `::169.254.169.254` are caught. Ported from the retired
  // lib/url-safety.ts so this guard is a strict superset of both.
  const first12Zero = first10Zero && bytes[10] === 0 && bytes[11] === 0;
  if (first12Zero && !(bytes[12] === 0 && bytes[13] === 0 && bytes[14] === 0 && bytes[15] <= 1)) {
    const v4Label = classifyV4(bytes.slice(12, 16));
    if (v4Label) return `ipv4-compatible ${v4Label}`;
  }
  if (bytes.every((x) => x === 0)) return "unspecified ::/128";
  if (bytes.slice(0, 15).every((x) => x === 0) && bytes[15] === 1) return "loopback ::1";
  if ((bytes[0] & 0xfe) === 0xfc) return "unique-local fc00::/7";
  if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80) return "link-local fe80::/10";
  if (bytes[0] === 0xff) return "multicast ff00::/8";
  return null;
}

/**
 * If `host` is an IP literal in any recognised encoding, return whether it is
 * blocked. Returns `null` when `host` is not an IP literal (→ treat as a DNS
 * name and defer to resolveAndPin).
 */
function classifyHostLiteral(host: string): { blocked: boolean; label?: string } | null {
  const v6 = parseIpv6Literal(host);
  if (v6) {
    const label = classifyV6(v6);
    return label ? { blocked: true, label } : { blocked: false };
  }
  const v4 = parseIpv4Literal(host);
  if (v4) {
    const label = classifyV4(v4);
    return label ? { blocked: true, label } : { blocked: false };
  }
  return null;
}

/** Classify an already-canonical resolved IP string (from DNS). */
export function isBlockedIp(ip: string): string | null {
  const fam = isIP(ip);
  if (fam === 4) {
    const bytes = ip.split(".").map((p) => parseInt(p, 10));
    return classifyV4(bytes);
  }
  if (fam === 6) {
    const bytes = parseIpv6Literal(ip);
    return bytes ? classifyV6(bytes) : "unparseable-ipv6";
  }
  return "not-an-ip";
}

/**
 * Phase 1 — syntactic + literal-IP validation. Safe to run at save time. Throws
 * SsrfError on any violation; returns the parsed URL and its lower-cased host.
 */
export function validateUrl(
  rawUrl: string,
  options: SsrfOptions = {},
): { url: URL; host: string } {
  const requireHttps = options.requireHttps ?? true;

  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new SsrfError("invalid_url", "url is not a valid absolute URL");
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new SsrfError("scheme_not_allowed", `scheme ${url.protocol} is not allowed`);
  }
  if (requireHttps && url.protocol !== "https:") {
    throw new SsrfError("not_https", "only https urls are allowed");
  }

  let host = url.hostname.toLowerCase();
  // Node keeps brackets on IPv6 hostnames; strip them for classification.
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  if (host.length === 0) {
    throw new SsrfError("invalid_url", "url has no host");
  }

  if (BLOCKED_HOST_LITERALS.has(host)) {
    throw new SsrfError("blocked_host", `host ${host} is blocked`);
  }
  for (const suffix of BLOCKED_HOST_SUFFIXES) {
    if (host.endsWith(suffix)) {
      throw new SsrfError("blocked_host", `host ${host} has a blocked suffix ${suffix}`);
    }
  }

  const literal = classifyHostLiteral(host);
  if (literal?.blocked) {
    throw new SsrfError("blocked_ip", `host is a blocked ip literal: ${literal.label}`);
  }

  return { url, host };
}

/**
 * Phase 2 — resolve the host and check EVERY resolved address against the
 * blocklist (multi-A-record rebinding defence), returning the pinned IPs the
 * caller must connect to. MUST be called at connect time.
 */
export async function resolveAndPin(
  host: string,
  options: SsrfOptions = {},
): Promise<string[]> {
  // A bare IP literal needs no DNS; classify + pin it directly.
  const literal = classifyHostLiteral(host);
  if (literal) {
    if (literal.blocked) {
      throw new SsrfError("blocked_ip", `host is a blocked ip literal: ${literal.label}`);
    }
    return [host];
  }

  const resolver = options.resolver ?? defaultResolver;
  const timeoutMs = options.dnsTimeoutMs ?? DNS_RESOLUTION_TIMEOUT_MS;
  let addrs: ResolvedAddress[];
  try {
    // Bounds the resolve — applied to WHATEVER resolver is in play
    // (default or injected) so no caller path can hang the connect-time step.
    addrs = await resolveWithTimeout(resolver, host, timeoutMs);
  } catch (err) {
    // Preserve a timeout (or any structured SsrfError) verbatim; only a bare
    // resolver rejection (NXDOMAIN/SERVFAIL/etc.) collapses to the generic
    // dns_resolution_failed reason.
    if (err instanceof SsrfError) throw err;
    throw new SsrfError("dns_resolution_failed", `could not resolve ${host}`);
  }
  if (!addrs || addrs.length === 0) {
    throw new SsrfError("no_addresses", `no addresses for ${host}`);
  }

  const pinned: string[] = [];
  for (const a of addrs) {
    const label = isBlockedIp(a.address);
    if (label) {
      // ANY blocked address rejects the whole host — a rebinding attacker only
      // needs one blocked record among several to win, so we fail closed.
      throw new SsrfError(
        "blocked_ip",
        `resolved address ${a.address} is in a blocked range: ${label}`,
      );
    }
    pinned.push(a.address);
  }
  return pinned;
}

/**
 * Full guard: phase 1 (syntactic/literal) + phase 2 (resolve + pin). Call this
 * at connect time. Returns the validated URL and the pinned IPs to connect to.
 */
export async function assertUrlSafe(
  rawUrl: string,
  options: SsrfOptions = {},
): Promise<{ url: URL; host: string; pinnedIps: string[] }> {
  const { url, host } = validateUrl(rawUrl, options);
  const pinnedIps = await resolveAndPin(host, options);
  return { url, host, pinnedIps };
}

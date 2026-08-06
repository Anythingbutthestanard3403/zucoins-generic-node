// client-ip, host-validate, SSRF pin-at-connect, egress census.
import { describe, expect, it } from "vitest";

import {
  DEFAULT_TRUST_PROXY_HOPS,
  MAX_RESPONSE_DRAIN_BYTES,
  OutboundHttpCensus,
  SsrfError,
  assertUrlSafe,
  clientIpFromXff,
  drainBounded,
  parseTrustProxyDirectExposure,
  parseTrustProxyHops,
  pinnedTargetFromUrl,
  resolveAndPin,
  resolveClientIp,
  trustProxyOptionsFromEnv,
  validateHostAndOrigin,
  validateUrl,
} from "../src/net/index.js";

describe("clientIpFromXff trusted proxy hops", () => {
  it("uses rightmost trusted hop; forged prefix ignored", () => {
    const forged = "6.6.6.6, 203.0.113.7";
    expect(clientIpFromXff(forged, 1)).toBe("203.0.113.7");
    expect(clientIpFromXff(forged, 1)).not.toBe("6.6.6.6");
  });

  it("invalid/missing TRUST_PROXY_HOPS degrades to 1", () => {
    expect(parseTrustProxyHops(undefined)).toBe(DEFAULT_TRUST_PROXY_HOPS);
    expect(parseTrustProxyHops("")).toBe(1);
    expect(parseTrustProxyHops("nope")).toBe(1);
    expect(parseTrustProxyHops("0")).toBe(1);
    expect(parseTrustProxyHops("-3")).toBe(1);
    expect(parseTrustProxyHops("2")).toBe(2);
  });

  it("directExposure gates socket peer fallback", () => {
    expect(resolveClientIp(undefined, { directExposure: false, socketPeer: "10.0.0.1" })).toBeNull();
    expect(resolveClientIp(undefined, { directExposure: true, socketPeer: "10.0.0.1" })).toBe(
      "10.0.0.1",
    );
    const env = trustProxyOptionsFromEnv({
      TRUST_PROXY_HOPS: "bad",
      TRUST_PROXY_DIRECT_EXPOSURE: "true",
    });
    expect(env.trustedHops).toBe(1);
    expect(env.directExposure).toBe(true);
    expect(parseTrustProxyDirectExposure("yes")).toBe(true);
    expect(parseTrustProxyDirectExposure(undefined)).toBe(false);
  });
});

describe("Host/Origin identity validation", () => {
  const identity = {
    allowedHosts: ["node.example"],
    allowedOrigins: ["https://node.example"],
  };

  it("rejects Host that is not the node identity", () => {
    expect(
      validateHostAndOrigin(identity, { host: "evil.example", origin: "https://node.example" }),
    ).toEqual({ ok: false, reason: "host_not_allowed" });
  });

  it("rejects Origin not on allowlist (admin/SSE)", () => {
    expect(
      validateHostAndOrigin(identity, { host: "node.example", origin: "https://evil.example" }),
    ).toEqual({ ok: false, reason: "origin_not_allowed" });
  });

  it("allows matching Host + Origin and Host without Origin", () => {
    expect(
      validateHostAndOrigin(identity, { host: "node.example", origin: "https://node.example" }),
    ).toEqual({ ok: true });
    expect(validateHostAndOrigin(identity, { host: "node.example" })).toEqual({ ok: true });
  });
});

describe("SSRF validate-at-registration + pin-at-connect", () => {
  it("validateUrl rejects blocked literals and non-https by default", () => {
    expect(() => validateUrl("http://example.com/x")).toThrow(SsrfError);
    expect(() => validateUrl("https://127.0.0.1/x")).toThrow(SsrfError);
    expect(() => validateUrl("https://169.254.169.254/latest")).toThrow(SsrfError);
    const ok = validateUrl("https://gateway.example/v1");
    expect(ok.host).toBe("gateway.example");
  });

  it("DNS-rebinding: permitted at validate, blocked at connect → fail closed", async () => {
    const raw = "https://rebind.example/path";
    validateUrl(raw); // registration-time OK (hostname not a blocked literal)
    await expect(
      resolveAndPin("rebind.example", {
        resolver: async () => [{ address: "127.0.0.1", family: 4 }],
      }),
    ).rejects.toBeInstanceOf(SsrfError);

    await expect(
      assertUrlSafe(raw, {
        resolver: async () => [{ address: "127.0.0.1", family: 4 }],
      }),
    ).rejects.toBeInstanceOf(SsrfError);
  });

  it("assertUrlSafe returns pinned public IP when resolver is clean", async () => {
    const result = await assertUrlSafe("https://gateway.example/v1", {
      resolver: async () => [{ address: "8.8.8.8", family: 4 }],
    });
    expect(result.pinnedIps).toContain("8.8.8.8");
    expect(result.host).toBe("gateway.example");
  });
});

describe("pinned connector + drain bound", () => {
  it("builds pinned target with hostname SNI surface", () => {
    const u = new URL("https://gateway.example:8443/v1/tx");
    const t = pinnedTargetFromUrl(u, "8.8.8.8");
    expect(t.hostname).toBe("gateway.example");
    expect(t.pinnedIp).toBe("8.8.8.8");
    expect(t.port).toBe(8443);
    expect(t.tls).toBe(true);
  });

  it("drainBounded caps at 64 KiB", async () => {
    const big = new Uint8Array(MAX_RESPONSE_DRAIN_BYTES + 100).fill(1);
    async function* gen() {
      yield big;
    }
    const r = await drainBounded(gen());
    expect(r.bytes.byteLength).toBe(MAX_RESPONSE_DRAIN_BYTES);
    expect(r.truncated).toBe(true);
  });
});

describe("egress-absence census", () => {
  it("flags any non-gateway outbound HTTP", () => {
    const census = new OutboundHttpCensus();
    census.record("https://gateway.example/step1");
    census.record("https://evil.example/callback");
    const leaks = census.nonGatewayCalls(["gateway.example"]);
    expect(leaks).toEqual(["https://evil.example/callback"]);
  });

  it("RECEIVE_EXTERNAL / MOVE_INTERNAL / SEND_EXTERNAL with only gateway calls is clean", () => {
    const census = new OutboundHttpCensus();
    // Simulated operation cycle: only the boot-configured gateway is contacted.
    for (const kind of ["RECEIVE_EXTERNAL", "MOVE_INTERNAL", "SEND_EXTERNAL"] as const) {
      void kind;
      census.record("https://splitchain-gateway.example/v1/submit");
    }
    expect(census.nonGatewayCalls(["splitchain-gateway.example"])).toEqual([]);
  });
});

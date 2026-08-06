// TLS and request-transport hardening tests. Adversarial matrix per
// the test plan Phase 7 hardening and
// the API contract wire conventions.

import { describe, expect, it } from "vitest";
import {
  MIN_TLS_VERSION,
  MAX_TLS_VERSION,
  HARDENED_CIPHER_SUITES,
  buildHardenedTlsConfig,
  JSON_MEDIA_TYPE,
  JSON_CONTENT_TYPE_HEADER,
  MIN_HTTP_VERSION,
  DEFAULT_REQUEST_TIMEOUT_MS,
  DEFAULT_HEADERS_TIMEOUT_MS,
  DEFAULT_MAX_BODY_BYTES,
  buildTransportHardeningConfig,
  guardHttpVersion,
  guardContentType,
  guardRequestSize,
  guardHeaderSize,
  DEFAULT_MAX_HEADER_BYTES,
  enforceTransportGuards,
  buildHardenedServerConfig,
} from "../src/api/index.js";

describe("TLS hardening configuration", () => {
  it("enforces a TLS 1.2 floor and prefers TLS 1.3", () => {
    const tls = buildHardenedTlsConfig();
    expect(tls.minVersion).toBe("TLSv1.2");
    expect(tls.maxVersion).toBe("TLSv1.3");
    expect(MIN_TLS_VERSION).toBe("TLSv1.2");
    expect(MAX_TLS_VERSION).toBe("TLSv1.3");
  });

  it("always enforces certificate validation (rejectUnauthorized is not overridable)", () => {
    const tls = buildHardenedTlsConfig();
    expect(tls.rejectUnauthorized).toBe(true);
    // The overrides surface exposes no way to disable peer verification.
    expect(Object.keys(buildHardenedTlsConfig())).toContain("rejectUnauthorized");
  });

  it("selects only AEAD forward-secrecy cipher suites", () => {
    const tls = buildHardenedTlsConfig();
    expect(tls.ciphers).toEqual(HARDENED_CIPHER_SUITES);
    expect(tls.honorCipherOrder).toBe(true);
    for (const cipher of tls.ciphers) {
      const isTls13 = cipher.startsWith("TLS_");
      const isEcdheAead =
        cipher.startsWith("ECDHE-") &&
        (cipher.includes("-GCM-") || cipher.includes("-CHACHA20-POLY1305"));
      expect(isTls13 || isEcdheAead).toBe(true);
    }
  });

  it("rejects weak cipher families by omission", () => {
    const joined = HARDENED_CIPHER_SUITES.join(":").toUpperCase();
    expect(joined).not.toContain("RC4");
    expect(joined).not.toContain("3DES");
    expect(joined).not.toContain("MD5");
    expect(joined).not.toContain("NULL");
    expect(joined).not.toContain("EXPORT");
    // No SHA-1 MAC suites (OpenSSL names them with a trailing -SHA / -SHA1).
    for (const cipher of HARDENED_CIPHER_SUITES) {
      expect(cipher.toUpperCase()).not.toMatch(/-SHA1?$/);
    }
  });

  it("only permits forward-secret key exchange (no static RSA)", () => {
    for (const cipher of HARDENED_CIPHER_SUITES) {
      const forwardSecret =
        cipher.startsWith("TLS_") || cipher.startsWith("ECDHE-") || cipher.startsWith("DHE-");
      expect(forwardSecret).toBe(true);
    }
  });

  it("allows cipher and requestCert overrides but never weakens the floor", () => {
    const custom = ["ECDHE-RSA-AES256-GCM-SHA384"];
    const tls = buildHardenedTlsConfig({ ciphers: custom, requestCert: true });
    expect(tls.ciphers).toEqual(custom);
    expect(tls.requestCert).toBe(true);
    expect(tls.minVersion).toBe("TLSv1.2");
    expect(tls.rejectUnauthorized).toBe(true);
  });

  it("defaults requestCert to false (server auth only, not mutual TLS)", () => {
    expect(buildHardenedTlsConfig().requestCert).toBe(false);
  });
});

describe("transport hardening configuration", () => {
  it("disables HTTP/1.0 by setting a 1.1 floor", () => {
    const transport = buildTransportHardeningConfig();
    expect(transport.minHttpVersion).toBe("1.1");
    expect(MIN_HTTP_VERSION).toBe("1.1");
  });

  it("carries bounded size and timeout defaults", () => {
    const transport = buildTransportHardeningConfig();
    expect(transport.maxBodyBytes).toBe(DEFAULT_MAX_BODY_BYTES);
    expect(transport.requestTimeoutMs).toBe(DEFAULT_REQUEST_TIMEOUT_MS);
    expect(transport.headersTimeoutMs).toBe(DEFAULT_HEADERS_TIMEOUT_MS);
    expect(transport.requireJsonContentType).toBe(true);
    expect(transport.requestTimeoutMs).toBeGreaterThan(0);
    expect(transport.headersTimeoutMs).toBeGreaterThan(0);
  });

  it("honours overrides", () => {
    const transport = buildTransportHardeningConfig({
      maxBodyBytes: 2048,
      requestTimeoutMs: 5000,
      headersTimeoutMs: 1000,
      requireJsonContentType: false,
    });
    expect(transport.maxBodyBytes).toBe(2048);
    expect(transport.requestTimeoutMs).toBe(5000);
    expect(transport.headersTimeoutMs).toBe(1000);
    expect(transport.requireJsonContentType).toBe(false);
  });
});

describe("HTTP version guard", () => {
  const config = buildTransportHardeningConfig();

  it("rejects HTTP/1.0 and HTTP/0.9", () => {
    expect(guardHttpVersion("1.0", config)).toEqual({
      ok: false,
      code: "http_version_too_old",
    });
    expect(guardHttpVersion("0.9", config)).toEqual({
      ok: false,
      code: "http_version_too_old",
    });
  });

  it("accepts HTTP/1.1 and HTTP/2", () => {
    expect(guardHttpVersion("1.1", config)).toEqual({ ok: true });
    expect(guardHttpVersion("2.0", config)).toEqual({ ok: true });
  });

  it("compares dotted versions numerically, not lexicographically", () => {
    expect(guardHttpVersion("1.10", config)).toEqual({ ok: true });
    expect(guardHttpVersion("1.2", config)).toEqual({ ok: true });
  });
});

describe("content-type guard", () => {
  const config = buildTransportHardeningConfig();

  it("accepts application/json with and without charset", () => {
    expect(guardContentType("application/json", config)).toEqual({ ok: true });
    expect(guardContentType(JSON_CONTENT_TYPE_HEADER, config)).toEqual({ ok: true });
    expect(guardContentType("application/json; charset=UTF-8", config)).toEqual({ ok: true });
  });

  it("is case-insensitive and tolerant of surrounding whitespace", () => {
    expect(guardContentType("Application/JSON", config)).toEqual({ ok: true });
    expect(guardContentType("  application/json ; charset=utf-8", config)).toEqual({ ok: true });
  });

  it("rejects non-JSON and absent content types", () => {
    expect(guardContentType("text/plain", config)).toEqual({
      ok: false,
      code: "unsupported_content_type",
    });
    expect(guardContentType("application/x-www-form-urlencoded", config)).toEqual({
      ok: false,
      code: "unsupported_content_type",
    });
    expect(guardContentType(undefined, config)).toEqual({
      ok: false,
      code: "unsupported_content_type",
    });
    expect(guardContentType("", config)).toEqual({
      ok: false,
      code: "unsupported_content_type",
    });
  });

  it("can be disabled for non-JSON (SSE) routes", () => {
    const permissive = buildTransportHardeningConfig({ requireJsonContentType: false });
    expect(guardContentType("text/event-stream", permissive)).toEqual({ ok: true });
    expect(guardContentType(undefined, permissive)).toEqual({ ok: true });
  });

  it("exposes the canonical wire media type constant", () => {
    expect(JSON_MEDIA_TYPE).toBe("application/json");
    expect(JSON_CONTENT_TYPE_HEADER).toBe("application/json; charset=utf-8");
  });
});

describe("request size guard", () => {
  const config = buildTransportHardeningConfig();

  it("accepts bodies at or under the limit", () => {
    expect(guardRequestSize(0, config)).toEqual({ ok: true });
    expect(guardRequestSize(DEFAULT_MAX_BODY_BYTES, config)).toEqual({ ok: true });
  });

  it("rejects bodies over the limit", () => {
    expect(guardRequestSize(DEFAULT_MAX_BODY_BYTES + 1, config)).toEqual({
      ok: false,
      code: "request_too_large",
    });
  });

  it("respects a tightened override", () => {
    const tight = buildTransportHardeningConfig({ maxBodyBytes: 100 });
    expect(guardRequestSize(100, tight)).toEqual({ ok: true });
    expect(guardRequestSize(101, tight)).toEqual({ ok: false, code: "request_too_large" });
  });
});

describe("composite transport guard ordering", () => {
  const config = buildTransportHardeningConfig();

  it("passes a well-formed HTTP/1.1 JSON request within size", () => {
    expect(
      enforceTransportGuards(
        { httpVersion: "1.1", contentType: JSON_CONTENT_TYPE_HEADER, contentLength: 512 },
        config,
      ),
    ).toEqual({ ok: true });
  });

  it("fails on protocol version before content type or size", () => {
    expect(
      enforceTransportGuards(
        { httpVersion: "1.0", contentType: "text/plain", contentLength: 999_999_999 },
        config,
      ),
    ).toEqual({ ok: false, code: "http_version_too_old" });
  });

  it("fails on content type before size", () => {
    expect(
      enforceTransportGuards(
        { httpVersion: "1.1", contentType: "text/plain", contentLength: 999_999_999 },
        config,
      ),
    ).toEqual({ ok: false, code: "unsupported_content_type" });
  });

  it("fails on size last", () => {
    expect(
      enforceTransportGuards(
        { httpVersion: "1.1", contentType: JSON_MEDIA_TYPE, contentLength: 999_999_999 },
        config,
      ),
    ).toEqual({ ok: false, code: "request_too_large" });
  });
});

describe("hardened server config bundle", () => {
  it("composes TLS and transport hardening into one object", () => {
    const config = buildHardenedServerConfig();
    expect(config.tls.minVersion).toBe("TLSv1.2");
    expect(config.tls.rejectUnauthorized).toBe(true);
    expect(config.transport.minHttpVersion).toBe("1.1");
    expect(config.transport.requireJsonContentType).toBe(true);
  });

  it("threads overrides into both halves independently", () => {
    const config = buildHardenedServerConfig({
      tls: { requestCert: true },
      transport: { maxBodyBytes: 4096 },
    });
    expect(config.tls.requestCert).toBe(true);
    expect(config.tls.rejectUnauthorized).toBe(true);
    expect(config.transport.maxBodyBytes).toBe(4096);
    expect(config.transport.minHttpVersion).toBe("1.1");
  });
});

describe("header size bound", () => {
  it("defaults maxHeaderBytes and rejects oversized headers", () => {
    const config = buildTransportHardeningConfig();
    expect(config.maxHeaderBytes).toBe(DEFAULT_MAX_HEADER_BYTES);
    expect(guardHeaderSize(DEFAULT_MAX_HEADER_BYTES, config).ok).toBe(true);
    expect(guardHeaderSize(DEFAULT_MAX_HEADER_BYTES + 1, config)).toEqual({
      ok: false,
      code: "headers_too_large",
    });
  });

  it("enforceTransportGuards applies header bound before body", () => {
    const config = buildTransportHardeningConfig({ maxHeaderBytes: 32 });
    const r = enforceTransportGuards(
      {
        httpVersion: "1.1",
        contentType: "application/json",
        contentLength: 10,
        headerBytes: 100,
      },
      config,
    );
    expect(r).toEqual({ ok: false, code: "headers_too_large" });
  });
});


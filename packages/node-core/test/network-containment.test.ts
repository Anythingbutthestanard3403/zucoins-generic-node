import dgram from "node:dgram";
import http from "node:http";
import http2 from "node:http2";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { describe, expect, it } from "vitest";

const DENY_MESSAGE = "generic-node core tests are network-contained";

describe("network containment", () => {
  it("rejects fetch before an HTTP call can begin", async () => {
    await expect(fetch("https://gateway.invalid/rpc")).rejects.toThrow(DENY_MESSAGE);
  });

  it("rejects native HTTP and HTTPS calls", () => {
    expect(() => http.request("http://gateway.invalid")).toThrow(DENY_MESSAGE);
    expect(() => http.get("http://gateway.invalid")).toThrow(DENY_MESSAGE);
    expect(() => https.request("https://gateway.invalid")).toThrow(DENY_MESSAGE);
    expect(() => https.get("https://gateway.invalid")).toThrow(DENY_MESSAGE);
  });

  it("rejects native HTTP/2 calls", () => {
    expect(() => http2.connect("https://gateway.invalid")).toThrow(DENY_MESSAGE);
  });

  it("rejects direct TCP and TLS calls", () => {
    expect(() => net.connect(443, "gateway.invalid")).toThrow(DENY_MESSAGE);
    expect(() => net.createConnection(443, "gateway.invalid")).toThrow(DENY_MESSAGE);
    expect(() => tls.connect(443, "gateway.invalid")).toThrow(DENY_MESSAGE);
  });

  it("rejects direct UDP sockets", () => {
    expect(() => dgram.createSocket("udp4")).toThrow(DENY_MESSAGE);
  });

  it("rejects dynamically imported named built-ins", async () => {
    const dynamicHttps = await import("node:https");
    const dynamicHttp2 = await import("node:http2");
    const dynamicNet = await import("node:net");
    const dynamicDgram = await import("node:dgram");
    expect(() => dynamicHttps.request("https://gateway.invalid")).toThrow(DENY_MESSAGE);
    expect(() => dynamicHttp2.connect("https://gateway.invalid")).toThrow(DENY_MESSAGE);
    expect(() => dynamicNet.connect(443, "gateway.invalid")).toThrow(DENY_MESSAGE);
    expect(() => dynamicDgram.createSocket("udp4")).toThrow(DENY_MESSAGE);
  });

  it.each(["WebSocket", "EventSource"])("rejects the global %s transport when present", (name) => {
    const constructor = Reflect.get(globalThis, name);
    if (typeof constructor !== "function") {
      return;
    }
    expect(() => Reflect.construct(constructor, ["https://gateway.invalid"])).toThrow(DENY_MESSAGE);
  });
});

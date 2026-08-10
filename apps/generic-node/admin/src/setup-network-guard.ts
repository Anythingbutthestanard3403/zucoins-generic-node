import dgram from "node:dgram";
import http from "node:http";
import http2 from "node:http2";
import https from "node:https";
import { syncBuiltinESMExports } from "node:module";
import net from "node:net";
import tls from "node:tls";

// Network containment for the operator SPA suite, mirroring apps/generic-node/test/setup-network-guard.ts.
// This project runs under jsdom, where a component reaches the network through fetch, XHR,
// WebSocket, EventSource or sendBeacon rather than through node:net — so the browser surfaces are
// denied here alongside the node ones. Every SPA test already stubs the calls it needs; this guard
// exists so one that forgets fails loudly instead of quietly opening a socket.
// packages/node-core/test/vitest-network-guard.census.test.ts fails if this project stops loading it.
const DENY_MESSAGE = "generic-node-ui tests are network-contained (stub fetch instead)";

function denySync(): never {
  throw new Error(DENY_MESSAGE);
}

async function denyAsync(): Promise<never> {
  throw new Error(DENY_MESSAGE);
}

globalThis.fetch = denyAsync as typeof globalThis.fetch;
http.request = denySync as typeof http.request;
http.get = denySync as typeof http.get;
http2.connect = denySync as typeof http2.connect;
https.request = denySync as typeof https.request;
https.get = denySync as typeof https.get;
net.connect = denySync as typeof net.connect;
net.createConnection = denySync as typeof net.createConnection;
tls.connect = denySync as typeof tls.connect;
dgram.createSocket = denySync as typeof dgram.createSocket;
syncBuiltinESMExports();

for (const constructorName of ["WebSocket", "EventSource", "XMLHttpRequest"]) {
  if (Reflect.get(globalThis, constructorName) !== undefined) {
    Object.defineProperty(globalThis, constructorName, {
      configurable: true,
      value: denySync,
      writable: true,
    });
  }
}

if (typeof navigator !== "undefined" && "sendBeacon" in navigator) {
  Object.defineProperty(navigator, "sendBeacon", {
    configurable: true,
    value: denySync,
    writable: true,
  });
}

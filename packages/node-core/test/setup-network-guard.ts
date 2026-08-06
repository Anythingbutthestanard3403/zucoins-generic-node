import dgram from "node:dgram";
import http from "node:http";
import http2 from "node:http2";
import https from "node:https";
import { syncBuiltinESMExports } from "node:module";
import net from "node:net";
import tls from "node:tls";

const DENY_MESSAGE = "generic-node core tests are network-contained";

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

for (const constructorName of ["WebSocket", "EventSource"]) {
  if (Reflect.get(globalThis, constructorName) !== undefined) {
    Object.defineProperty(globalThis, constructorName, {
      configurable: true,
      value: denySync,
      writable: true,
    });
  }
}

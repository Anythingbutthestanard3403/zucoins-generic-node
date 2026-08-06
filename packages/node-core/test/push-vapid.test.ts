import { webcrypto } from "node:crypto";

import { describe, expect, test } from "vitest";

import {
  decodeTolerantBase64,
  parseVapidAuthorizationHeader,
  verifyVapidAuthorization,
} from "../src/push/index.js";

const NODE_ORIGIN = "https://node.merchant.example";
const NOW = new Date("2026-07-14T00:00:00Z");

function b64url(value: ArrayBuffer | Buffer): string {
  return (Buffer.isBuffer(value) ? value : Buffer.from(value)).toString("base64url");
}

async function keypair() {
  const pair = await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  return {
    privateKey: pair.privateKey,
    publicKey: b64url(await webcrypto.subtle.exportKey("raw", pair.publicKey)),
  };
}

async function jwt(privateKey: webcrypto.CryptoKey, aud = NODE_ORIGIN, expDelta = 3600, alg = "ES256") {
  const header = b64url(Buffer.from(JSON.stringify({ typ: "JWT", alg })));
  const payload = b64url(
    Buffer.from(JSON.stringify({ aud, exp: Math.floor(NOW.getTime() / 1000) + expDelta })),
  );
  const signature = await webcrypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    Buffer.from(`${header}.${payload}`),
  );
  return `${header}.${payload}.${b64url(signature)}`;
}

describe("VAPID verification material", () => {
  test("parses the vapid authorization scheme and tolerant key encodings", () => {
    expect(parseVapidAuthorizationHeader("VAPID t=a.b.c, k=key")).toEqual({ jwt: "a.b.c", k: "key" });
    expect(parseVapidAuthorizationHeader("Bearer token")).toBeNull();
    const bytes = Buffer.from("app-server-public-key");
    expect(decodeTolerantBase64(bytes.toString("base64")).equals(bytes)).toBe(true);
    expect(decodeTolerantBase64(bytes.toString("base64url")).equals(bytes)).toBe(true);
  });

  test("accepts a correctly signed, in-window token for the exact origin", async () => {
    const appServer = await keypair();
    const token = await jwt(appServer.privateKey);
    await expect(
      verifyVapidAuthorization({
        authorizationHeader: `vapid t=${token}, k=${appServer.publicKey}`,
        appServerPublicKeyRaw: appServer.publicKey,
        nodeOrigin: NODE_ORIGIN,
        now: NOW,
      }),
    ).resolves.toBe(true);
  });

  test.each([
    ["missing", undefined],
    ["malformed", "vapid t=not-a-jwt"],
  ])("rejects %s authorization without throwing", async (_name, authorizationHeader) => {
    await expect(
      verifyVapidAuthorization({ authorizationHeader, appServerPublicKeyRaw: "garbage", nodeOrigin: NODE_ORIGIN, now: NOW }),
    ).resolves.toBe(false);
  });

  test("rejects wrong audience, expiry, excessive lifetime, algorithm, and signing key", async () => {
    const trusted = await keypair();
    const attacker = await keypair();
    const candidates = [
      await jwt(trusted.privateKey, "https://attacker.example"),
      await jwt(trusted.privateKey, NODE_ORIGIN, -1),
      await jwt(trusted.privateKey, NODE_ORIGIN, 100_000),
      await jwt(trusted.privateKey, NODE_ORIGIN, 3600, "none"),
      await jwt(attacker.privateKey),
    ];
    for (const token of candidates) {
      await expect(
        verifyVapidAuthorization({
          authorizationHeader: `vapid t=${token}, k=${trusted.publicKey}`,
          appServerPublicKeyRaw: trusted.publicKey,
          nodeOrigin: NODE_ORIGIN,
          now: NOW,
        }),
      ).resolves.toBe(false);
    }
  });
});

// ZTR-1161 — VAPID gate on createPushReceiver: verified / rejected / absent / no_key,
// observe vs enforce, uniform discard (caller still answers 204).

import { webcrypto } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  createPushReceiver,
  type PushAuditSink,
  type PushReceiveOutcome,
  type PushSecretSealer,
  type PushSubscriptionRow,
  type PushSubscriptionStore,
  type PushVapidOutcome,
  type WebPushPayloadDecryptor,
} from "../src/push/index.js";

const NODE_ORIGIN = "https://node.merchant.example";
const ENDPOINT = "wp_" + "A".repeat(32);
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

function makeStore(row: PushSubscriptionRow | null): PushSubscriptionStore {
  return {
    async findByWalletId() {
      return row;
    },
    async findByEndpointId(endpointId) {
      return row !== null && row.endpointId === endpointId ? row : null;
    },
    async insert() {},
    async replaceSealedMaterial() {},
    async markStatus() {},
    async listSubscribableWallets() {
      return [];
    },
  };
}

function makeSealer(): PushSecretSealer {
  return {
    async seal(bytes) {
      return `sealed:${Buffer.from(bytes).toString("base64")}`;
    },
    async open(sealed) {
      if (typeof sealed === "string" && sealed.startsWith("sealed:")) {
        return Buffer.from(sealed.slice(7), "base64");
      }
      throw new Error("unopenable");
    },
  };
}

function makeDecryptor(cleartext: string): WebPushPayloadDecryptor {
  return {
    async decrypt() {
      return new TextEncoder().encode(cleartext);
    },
  };
}

function makeAudit(): PushAuditSink & { records: Array<{ type: string; detail: Record<string, unknown> }> } {
  const records: Array<{ type: string; detail: Record<string, unknown> }> = [];
  return {
    records,
    async record(event) {
      records.push({ type: event.type, detail: event.detail });
    },
  };
}

function activeRow(appServerPublicKey: string | null): PushSubscriptionRow {
  return {
    walletId: "wallet-vapid-1",
    walletPublicKey: "pk",
    endpointId: ENDPOINT,
    receiverEcdhPublic: "p256",
    receiverEcdhPrivateSealed: "sealed:AA==",
    receiverAuthSecretSealed: "sealed:AA==",
    status: "ACTIVE",
    appServerPublicKey,
  };
}

// Minimal DELIVERED shape the payload resolver accepts.
const CLEARTEXT_WITH_CODE = JSON.stringify({
  data: { type_data: { transfer_code_encoded: "tc_test_code_bytes" } },
});

describe("createPushReceiver VAPID gate (ZTR-1161)", () => {
  it("observe + verified header: decrypts and enqueues; counts verified", async () => {
    const app = await keypair();
    const outcomes: PushVapidOutcome[] = [];
    const audit = makeAudit();
    const sunk: string[] = [];
    const receiver = createPushReceiver({
      store: makeStore(activeRow(app.publicKey)),
      sealer: makeSealer(),
      decryptor: makeDecryptor(CLEARTEXT_WITH_CODE),
      sink: (code) => {
        sunk.push(code);
        return true;
      },
      audit,
      nodeOrigin: NODE_ORIGIN,
      vapidMode: "observe",
      onVapidOutcome: (o) => outcomes.push(o),
    });

    // Freeze verify clock via real Date is fine — jwt uses NOW+3600 and verify defaults to now.
    // Re-sign with a far-future exp relative to wall clock so the unit is not flaky.
    const liveToken = await (async () => {
      const header = b64url(Buffer.from(JSON.stringify({ typ: "JWT", alg: "ES256" })));
      const payload = b64url(
        Buffer.from(
          JSON.stringify({
            aud: NODE_ORIGIN,
            exp: Math.floor(Date.now() / 1000) + 3600,
          }),
        ),
      );
      const signature = await webcrypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        app.privateKey,
        Buffer.from(`${header}.${payload}`),
      );
      return `${header}.${payload}.${b64url(signature)}`;
    })();

    const outcome = await receiver.receive(
      ENDPOINT,
      Buffer.from("cipher"),
      `vapid t=${liveToken}, k=${app.publicKey}`,
    );
    expect(outcome).toBe("enqueued");
    expect(sunk).toEqual(["tc_test_code_bytes"]);
    expect(outcomes).toEqual(["verified"]);
    expect(audit.records.some((r) => r.type === "push.receive_vapid" && r.detail.outcome === "verified")).toBe(
      true,
    );
  });

  it("enforce + rejected signature: vapid_rejected, no decrypt/sink", async () => {
    const trusted = await keypair();
    const attacker = await keypair();
    const header = b64url(Buffer.from(JSON.stringify({ typ: "JWT", alg: "ES256" })));
    const payload = b64url(
      Buffer.from(
        JSON.stringify({ aud: NODE_ORIGIN, exp: Math.floor(Date.now() / 1000) + 3600 }),
      ),
    );
    const signature = await webcrypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      attacker.privateKey,
      Buffer.from(`${header}.${payload}`),
    );
    const badToken = `${header}.${payload}.${b64url(signature)}`;

    const outcomes: PushVapidOutcome[] = [];
    let decryptCalls = 0;
    const receiver = createPushReceiver({
      store: makeStore(activeRow(trusted.publicKey)),
      sealer: makeSealer(),
      decryptor: {
        async decrypt() {
          decryptCalls += 1;
          return new Uint8Array();
        },
      },
      sink: () => {
        throw new Error("sink must not run");
      },
      nodeOrigin: NODE_ORIGIN,
      vapidMode: "enforce",
      onVapidOutcome: (o) => outcomes.push(o),
    });

    const outcome = await receiver.receive(
      ENDPOINT,
      Buffer.from("cipher"),
      `vapid t=${badToken}, k=${trusted.publicKey}`,
    );
    expect(outcome).toBe("vapid_rejected");
    expect(decryptCalls).toBe(0);
    expect(outcomes).toEqual(["rejected"]);
  });

  it("enforce + absent header: vapid_rejected", async () => {
    const app = await keypair();
    const outcomes: PushVapidOutcome[] = [];
    const receiver = createPushReceiver({
      store: makeStore(activeRow(app.publicKey)),
      sealer: makeSealer(),
      decryptor: makeDecryptor(CLEARTEXT_WITH_CODE),
      sink: () => true,
      nodeOrigin: NODE_ORIGIN,
      vapidMode: "enforce",
      onVapidOutcome: (o) => outcomes.push(o),
    });
    const outcome = await receiver.receive(ENDPOINT, Buffer.from("cipher"), null);
    expect(outcome).toBe("vapid_rejected");
    expect(outcomes).toEqual(["absent"]);
  });

  it("enforce + NULL stored key: vapid_rejected (no_key)", async () => {
    const outcomes: PushVapidOutcome[] = [];
    const receiver = createPushReceiver({
      store: makeStore(activeRow(null)),
      sealer: makeSealer(),
      decryptor: makeDecryptor(CLEARTEXT_WITH_CODE),
      sink: () => true,
      nodeOrigin: NODE_ORIGIN,
      vapidMode: "enforce",
      onVapidOutcome: (o) => outcomes.push(o),
    });
    const outcome = await receiver.receive(ENDPOINT, Buffer.from("cipher"), "vapid t=a.b.c, k=x");
    expect(outcome).toBe("vapid_rejected");
    expect(outcomes).toEqual(["no_key"]);
  });

  it("observe + absent header: still decrypts (does not block); counts absent", async () => {
    const app = await keypair();
    const outcomes: PushVapidOutcome[] = [];
    const sunk: string[] = [];
    const receiver = createPushReceiver({
      store: makeStore(activeRow(app.publicKey)),
      sealer: makeSealer(),
      decryptor: makeDecryptor(CLEARTEXT_WITH_CODE),
      sink: (c) => {
        sunk.push(c);
        return true;
      },
      nodeOrigin: NODE_ORIGIN,
      vapidMode: "observe",
      onVapidOutcome: (o) => outcomes.push(o),
    });
    const outcome: PushReceiveOutcome = await receiver.receive(
      ENDPOINT,
      Buffer.from("cipher"),
      undefined,
    );
    expect(outcome).toBe("enqueued");
    expect(sunk).toHaveLength(1);
    expect(outcomes).toEqual(["absent"]);
  });

  it("observe + NULL stored key: still decrypts; counts no_key", async () => {
    const outcomes: PushVapidOutcome[] = [];
    const receiver = createPushReceiver({
      store: makeStore(activeRow(null)),
      sealer: makeSealer(),
      decryptor: makeDecryptor(CLEARTEXT_WITH_CODE),
      sink: () => true,
      nodeOrigin: NODE_ORIGIN,
      vapidMode: "observe",
      onVapidOutcome: (o) => outcomes.push(o),
    });
    const outcome = await receiver.receive(ENDPOINT, Buffer.from("cipher"), "vapid t=x.y.z");
    expect(outcome).toBe("enqueued");
    expect(outcomes).toEqual(["no_key"]);
  });
});

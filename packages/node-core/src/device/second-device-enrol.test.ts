// Second-device QR enrolment: happy path, expired, replay, QR safety.

import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";

import { InMemoryEnrollmentAuditLog } from "./audit.js";
import { InMemoryEnrollmentChallengeStore } from "./challenge.js";
import { InMemoryDeviceKeyStore } from "./in-memory-store.js";
import {
  assertSafeSecondDeviceQr,
  authorizeSecondDeviceEnrol,
  bindSecondDevicePublicKey,
  completeSecondDeviceEnrol,
  InMemorySecondDeviceCeremonyStore,
  issueSecondDeviceCeremony,
  peekSecondDeviceCeremony,
  SECOND_DEVICE_QR_FORBIDDEN_KEYS,
} from "./second-device-enrol.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111";
const ORIGIN = "https://node.example";
const AUTHORIZER_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

const ED25519_SPKI_DER_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function generateTestKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spkiDer = publicKey.export({ format: "der", type: "spki" });
  const rawPub = new Uint8Array(spkiDer.slice(ED25519_SPKI_DER_PREFIX.length));
  const paddedBase64Url = Buffer.from(rawPub)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  return { publicKey, privateKey, rawPub, paddedBase64Url };
}

function signPreimageB64(
  privateKey: ReturnType<typeof generateTestKeyPair>["privateKey"],
  preimageText: string,
): string {
  const sig = sign(null, Buffer.from(preimageText, "utf8"), privateKey);
  return Buffer.from(sig).toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}

describe("second-device QR payload safety", () => {
  it("accepts only challenge_id + node_origin", () => {
    const qr = assertSafeSecondDeviceQr({
      challenge_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      node_origin: "https://node.example/",
    });
    expect(qr.node_origin).toBe("https://node.example");
  });

  it("rejects forbidden secret keys", () => {
    for (const key of SECOND_DEVICE_QR_FORBIDDEN_KEYS) {
      expect(() =>
        assertSafeSecondDeviceQr({
          challenge_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          node_origin: "https://node.example",
          [key]: "x",
        }),
      ).toThrow(/forbid/i);
    }
  });
});

describe("second-device enrolment ceremony", () => {
  it("happy path: two devices enrolled; replay fails closed; audit rows present", () => {
    const challengeStore = new InMemoryEnrollmentChallengeStore();
    const ceremonyStore = new InMemorySecondDeviceCeremonyStore();
    const deviceStore = new InMemoryDeviceKeyStore();
    const auditLog = new InMemoryEnrollmentAuditLog();
    const authorizing = generateTestKeyPair();
    const newDevice = generateTestKeyPair();
    const nowMs = Date.parse("2026-08-03T12:00:00.000Z");

    deviceStore.insert({
      id: AUTHORIZER_ID,
      nodeId: NODE_ID,
      publicKey: authorizing.paddedBase64Url,
      label: "phone-a",
      enrolledAt: "2026-01-01T00:00:00.000Z",
      revokedAt: null,
    });

    const issued = issueSecondDeviceCeremony({
      challengeStore,
      ceremonyStore,
      nodeId: NODE_ID,
      nodeOrigin: ORIGIN,
      nowMs,
      issuedByOperatorId: "op-a",
    });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    assertSafeSecondDeviceQr(issued.qr);
    expect(Object.keys(issued.qr).sort()).toEqual(["challenge_id", "node_origin"]);
    expect(JSON.stringify(issued.qr)).not.toMatch(/private|secret|totp|master/i);

    const bound = bindSecondDevicePublicKey(ceremonyStore, {
      challengeId: issued.ceremony.challengeId,
      newDevicePublicKey: newDevice.paddedBase64Url,
      label: "phone-b",
      nowMs: nowMs + 1_000,
    });
    expect(bound.ok).toBe(true);
    if (!bound.ok) return;

    // First authorize builds preimage; second stores the real signature.
    const draft = authorizeSecondDeviceEnrol(ceremonyStore, {
      challengeId: issued.ceremony.challengeId,
      authorizingKeyId: AUTHORIZER_ID,
      authorizingPublicKey: authorizing.paddedBase64Url,
      authorizingSignature: signPreimageB64(authorizing.privateKey, "draft"),
      nowMs: nowMs + 2_000,
    });
    expect(draft.ok).toBe(true);
    if (!draft.ok) return;

    const realSig = signPreimageB64(authorizing.privateKey, draft.preimage_text);
    const authz = authorizeSecondDeviceEnrol(ceremonyStore, {
      challengeId: issued.ceremony.challengeId,
      authorizingKeyId: AUTHORIZER_ID,
      authorizingPublicKey: authorizing.paddedBase64Url,
      authorizingSignature: realSig,
      nowMs: nowMs + 2_500,
    });
    expect(authz.ok).toBe(true);
    if (!authz.ok) return;

    const popSig = signPreimageB64(newDevice.privateKey, authz.preimage_text);
    const completed = completeSecondDeviceEnrol(
      { deviceStore, challengeStore, auditLog, ceremonyStore },
      {
        challengeId: issued.ceremony.challengeId,
        newDevicePopSignature: popSig,
        nowMs: nowMs + 3_000,
      },
    );
    expect(completed.ok).toBe(true);
    if (!completed.ok) return;
    expect(completed.deviceKey.label).toBe("phone-b");
    expect(deviceStore.listActiveByNode(NODE_ID)).toHaveLength(2);

    // Audit has ENROLLED for new device (and authorizer key id recorded).
    expect(auditLog.entries.some((e) => e.outcome === "ENROLLED")).toBe(true);
    expect(auditLog.entries.some((e) => e.authorizingKeyId === AUTHORIZER_ID)).toBe(true);
    expect(auditLog.entries.some((e) => e.newDeviceKeyId === completed.deviceKey.id)).toBe(true);

    // Replay fails closed.
    const replay = completeSecondDeviceEnrol(
      { deviceStore, challengeStore, auditLog, ceremonyStore },
      {
        challengeId: issued.ceremony.challengeId,
        newDevicePopSignature: popSig,
        nowMs: nowMs + 4_000,
      },
    );
    expect(replay.ok).toBe(false);
  });

  it("expired QR/challenge fails closed on bind", () => {
    const challengeStore = new InMemoryEnrollmentChallengeStore();
    const ceremonyStore = new InMemorySecondDeviceCeremonyStore();
    const nowMs = Date.parse("2026-08-03T12:00:00.000Z");
    const issued = issueSecondDeviceCeremony({
      challengeStore,
      ceremonyStore,
      nodeId: NODE_ID,
      nodeOrigin: ORIGIN,
      nowMs,
    });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;
    const bound = bindSecondDevicePublicKey(ceremonyStore, {
      challengeId: issued.ceremony.challengeId,
      newDevicePublicKey: "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=",
      label: "late",
      nowMs: nowMs + 301_000,
    });
    expect(bound.ok).toBe(false);
    if (!bound.ok) expect(bound.code).toBe("CHALLENGE_EXPIRED");
  });

  it("peek never exposes authorizing signature or private material", () => {
    const challengeStore = new InMemoryEnrollmentChallengeStore();
    const ceremonyStore = new InMemorySecondDeviceCeremonyStore();
    const nowMs = Date.parse("2026-08-03T12:00:00.000Z");
    const issued = issueSecondDeviceCeremony({
      challengeStore,
      ceremonyStore,
      nodeId: NODE_ID,
      nodeOrigin: ORIGIN,
      nowMs,
    });
    if (!issued.ok) return;
    const peek = peekSecondDeviceCeremony(ceremonyStore, issued.ceremony.challengeId, nowMs);
    expect(peek).not.toBeNull();
    const blob = JSON.stringify(peek);
    expect(blob).not.toMatch(/private_key|authorizing_signature|totp|master/i);
    expect(createHash("sha256").update(blob).digest("hex").length).toBe(64);
  });
});

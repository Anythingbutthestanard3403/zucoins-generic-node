// device dual-control destination bless authorizer.

import { Buffer } from "node:buffer";
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { describe, expect, it } from "vitest";

import type { Uuid, WalletPublicKey } from "../protocol/scalars.js";
import { buildDestinationBless } from "../protocol/suite/builders.js";
import {
  createDeviceBlessingAuthorizer,
  type DestinationBlessAuditEntry,
  type DestinationBlessingArtifactRow,
} from "./blessing-authorizer.js";
import type { EnrolledDeviceKey } from "./types.js";

const NODE_ID = "11111111-1111-4111-8111-111111111111" as Uuid;
const DEST_ID = "66666666-6666-4666-8666-666666666666" as Uuid;
const WALLET_ID = "44444444-4444-4444-8444-444444444444" as Uuid;
const WALLET_PUB = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=" as WalletPublicKey;
const DEVICE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" as Uuid;
const NONCE = "99999999-9999-4999-8999-999999999999" as Uuid;

function privFromSeed(byte: number) {
  const seed = Buffer.alloc(32, byte);
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}

function pubB64(byte: number): string {
  const pub = createPublicKey(privFromSeed(byte));
  const spki = pub.export({ format: "der", type: "spki" }) as Buffer;
  return Buffer.from(spki.subarray(-32))
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function signB64(preimage: string, seedByte: number): string {
  const sig = sign(null, Buffer.from(preimage, "utf8"), privFromSeed(seedByte));
  return Buffer.from(sig).toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}

const DEVICE_PUB = pubB64(0x01);

function enrolled(patch: Partial<EnrolledDeviceKey> = {}): EnrolledDeviceKey {
  return {
    id: DEVICE_ID,
    nodeId: NODE_ID,
    publicKey: DEVICE_PUB,
    label: "test-device",
    enrolledAt: "2026-01-01T00:00:00.000Z",
    revokedAt: null,
    ...patch,
  };
}

describe("createDeviceBlessingAuthorizer", () => {
  const baseNow = Date.parse("2026-07-18T00:02:00.000Z");

  function harness(opts: {
    device?: EnrolledDeviceKey | null;
    persist?: "inserted" | "nonce_conflict" | "failed";
  } = {}) {
    const artifacts: DestinationBlessingArtifactRow[] = [];
    const audits: DestinationBlessAuditEntry[] = [];
    const device = opts.device === undefined ? enrolled() : opts.device;
    const authorizer = createDeviceBlessingAuthorizer({
      nowMs: () => baseNow,
      newArtifactId: () => "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" as Uuid,
      lookupDevice: async (nodeId, id) => {
        if (device === null) return null;
        if (device.id !== id || device.nodeId !== nodeId) return null;
        if (device.revokedAt !== null) return null;
        return device;
      },
      persistArtifact: async (row) => {
        const outcome = opts.persist ?? "inserted";
        if (outcome !== "inserted") return outcome;
        artifacts.push(row);
        return "inserted";
      },
      appendAudit: async (e) => {
        audits.push(e);
      },
    });
    return { authorizer, artifacts, audits };
  }

  function ceremony(issuedAt: string, expiresAt: string, seedByte = 0x01) {
    const preimage = buildDestinationBless({
      node_id: NODE_ID,
      destination_id: DEST_ID,
      wallet_id: WALLET_ID,
      wallet_pubkey: WALLET_PUB,
      nonce: NONCE,
      issued_at: issuedAt,
      expires_at: expiresAt,
    });
    return {
      nodeId: NODE_ID,
      destinationId: DEST_ID,
      walletId: WALLET_ID,
      walletPublicKey: WALLET_PUB,
      nonce: NONCE,
      issuedAt,
      expiresAt,
      deviceSignature: signB64(preimage.preimageText, seedByte),
      deviceKeyId: DEVICE_ID,
      preimage,
    };
  }

  it("accepts valid enrolled device signature and persists artifact + audit", async () => {
    const { authorizer, artifacts, audits } = harness();
    const c = ceremony("2026-07-18T00:00:00.000Z", "2026-07-18T00:05:00.000Z");
    const ok = await authorizer.authorize(c);
    expect(ok).toEqual({
      deviceKeyId: DEVICE_ID,
      artifactId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    });
    expect(artifacts).toHaveLength(1);
    expect(artifacts[0]!.preimageSha256).toBe(c.preimage.sha256);
    expect(audits.some((a) => a.action === "destination.bless" && a.code === "OK")).toBe(true);
    const blob = JSON.stringify({ audits, artifacts: artifacts.map((a) => ({
      id: a.id,
      sha: a.preimageSha256,
      // public key is allowed; assert private seed material absent
    })) });
    expect(blob).not.toMatch(/BEGIN (EC )?PRIVATE KEY/i);
    expect(blob).not.toContain(Buffer.alloc(32, 0x01).toString("hex"));
  });

  it("rejects unknown device", async () => {
    const { authorizer, artifacts } = harness({ device: null });
    const c = ceremony("2026-07-18T00:00:00.000Z", "2026-07-18T00:05:00.000Z");
    expect(await authorizer.authorize(c)).toBeNull();
    expect(artifacts).toHaveLength(0);
  });

  it("rejects revoked device", async () => {
    const { authorizer } = harness({
      device: enrolled({ revokedAt: "2026-07-01T00:00:00.000Z" }),
    });
    const c = ceremony("2026-07-18T00:00:00.000Z", "2026-07-18T00:05:00.000Z");
    expect(await authorizer.authorize(c)).toBeNull();
  });

  it("rejects wrong-key signature", async () => {
    const { authorizer, artifacts } = harness();
    const c = ceremony("2026-07-18T00:00:00.000Z", "2026-07-18T00:05:00.000Z", 0x02);
    expect(await authorizer.authorize(c)).toBeNull();
    expect(artifacts).toHaveLength(0);
  });

  it("rejects expired window against wall clock", async () => {
    const { authorizer } = harness();
    const c = ceremony("2026-07-18T00:00:00.000Z", "2026-07-18T00:01:00.000Z");
    expect(await authorizer.authorize(c)).toBeNull();
  });

  it("rejects nonce reuse at artifact persist", async () => {
    const { authorizer } = harness({ persist: "nonce_conflict" });
    const c = ceremony("2026-07-18T00:00:00.000Z", "2026-07-18T00:05:00.000Z");
    expect(await authorizer.authorize(c)).toBeNull();
  });
});

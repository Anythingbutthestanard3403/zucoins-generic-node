// Destination blessing authorizer — A.4.2 zp-destination-bless-v1 + enrolled device key.
// Device-signature blessing authorizer. TOTP alone never reaches this path.
//
// Boundary: lives in device/ (protocol + reporting only). Structural return type matches
// api BlessingAuthorizer without importing api/ (node-core boundary graph).

import { randomUUID } from "node:crypto";

import type { Uuid, WalletPublicKey } from "../protocol/scalars.js";
import { buildDestinationBless } from "../protocol/suite/builders.js";
import {
  SuiteVerifyError,
  verifyDestinationBless,
  type ResolvedSuiteVerificationKey,
} from "../protocol/suite/verify.js";
import { SuiteSerializeError } from "../protocol/suite/serialize.js";
import type { EnrolledDeviceKey } from "./types.js";

const PADDED_SIG_RE = /^[A-Za-z0-9_-]{86}==$/;
const PADDED_PUB_RE = /^[A-Za-z0-9_-]{43}=$/;

export interface BlessingAuthorizeInput {
  readonly nodeId: Uuid;
  readonly destinationId: Uuid;
  readonly walletId: Uuid;
  readonly walletPublicKey: WalletPublicKey;
  readonly nonce: Uuid;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly deviceSignature: string;
  /** Enrolled operator_device_keys.id that signed the preimage. */
  readonly deviceKeyId: Uuid;
}

export interface BlessingAuthorizeOk {
  readonly deviceKeyId: Uuid;
  readonly artifactId: Uuid;
}

/** Port: load one enrolled, non-revoked device row. Public key only — never private material. */
export type LookUpActiveDevice = (
  nodeId: string,
  deviceKeyId: string,
) => Promise<EnrolledDeviceKey | null>;

export interface DestinationBlessingArtifactRow {
  readonly id: Uuid;
  readonly nodeId: Uuid;
  readonly destinationId: Uuid;
  readonly walletId: Uuid;
  readonly walletPubkey: string;
  readonly nonce: Uuid;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly deviceSignature: string;
  readonly preimageText: string;
  readonly preimageSha256: string;
  readonly createdAt: string;
}

/**
 * Insert-only destination_blessing_artifacts row (signer-support).
 * Return null on unique-nonce conflict (single-use gate) so callers fail closed.
 */
export type PersistBlessingArtifact = (
  row: DestinationBlessingArtifactRow,
) => Promise<"inserted" | "nonce_conflict" | "failed">;

export interface DestinationBlessAuditEntry {
  readonly action: "destination.bless" | "destination.bless_rejected";
  readonly nodeId: string;
  readonly destinationId: string;
  readonly walletId: string | null;
  readonly deviceKeyId: string | null;
  readonly artifactId: string | null;
  readonly code: string;
  readonly detail: string;
  readonly at: string;
}

export type AppendBlessingAudit = (entry: DestinationBlessAuditEntry) => Promise<void>;

export interface DeviceBlessingAuthorizerDeps {
  readonly lookupDevice: LookUpActiveDevice;
  readonly persistArtifact: PersistBlessingArtifact;
  readonly appendAudit?: AppendBlessingAudit;
  readonly nowMs?: () => number;
  readonly newArtifactId?: () => Uuid;
}

export interface DeviceBlessingAuthorizer {
  authorize(input: BlessingAuthorizeInput): Promise<BlessingAuthorizeOk | null>;
}

function isPaddedSignature(value: string): boolean {
  return PADDED_SIG_RE.test(value);
}

function noopAudit(): AppendBlessingAudit {
  return async () => {};
}

/**
 * Verify A.4.2 preimage + enrolled device signature, persist the blessing artifact,
 * return device + artifact ids. Never logs or accepts private key material (Key-custody).
 */
export function createDeviceBlessingAuthorizer(
  deps: DeviceBlessingAuthorizerDeps,
): DeviceBlessingAuthorizer {
  const nowMs = deps.nowMs ?? (() => Date.now());
  const newArtifactId = deps.newArtifactId ?? (() => randomUUID() as Uuid);
  const appendAudit = deps.appendAudit ?? noopAudit();

  return {
    async authorize(input) {
      const at = new Date(nowMs()).toISOString();
      const reject = async (code: string, detail: string): Promise<null> => {
        await appendAudit({
          action: "destination.bless_rejected",
          nodeId: input.nodeId,
          destinationId: input.destinationId,
          walletId: input.walletId,
          deviceKeyId: input.deviceKeyId,
          artifactId: null,
          code,
          detail,
          at,
        });
        return null;
      };

      if (typeof input.deviceKeyId !== "string" || input.deviceKeyId.length === 0) {
        return reject("device_key_required", "device_key_id required for blessing");
      }
      if (!isPaddedSignature(input.deviceSignature)) {
        return reject("signature_format", "device_signature is not padded base64url");
      }

      const issuedMs = Date.parse(input.issuedAt);
      const expiresMs = Date.parse(input.expiresAt);
      if (!Number.isFinite(issuedMs) || !Number.isFinite(expiresMs)) {
        return reject("window_invalid", "issued_at/expires_at not parseable");
      }
      const now = nowMs();
      if (now < issuedMs) {
        return reject("window_not_started", "ceremony issued_at is in the future");
      }
      if (now >= expiresMs) {
        return reject("window_expired", "ceremony expires_at has passed");
      }

      const device = await deps.lookupDevice(input.nodeId, input.deviceKeyId);
      if (device === null) {
        return reject("device_unknown", "no active enrolled device for device_key_id");
      }
      if (device.revokedAt !== null) {
        return reject("device_revoked", "device key has been revoked");
      }
      if (device.nodeId !== input.nodeId) {
        return reject("device_node_mismatch", "device key belongs to another node");
      }
      if (!PADDED_PUB_RE.test(device.publicKey)) {
        return reject("device_public_key_invalid", "enrolled public key shape invalid");
      }

      let preimage;
      try {
        preimage = buildDestinationBless({
          node_id: input.nodeId,
          destination_id: input.destinationId,
          wallet_id: input.walletId,
          wallet_pubkey: input.walletPublicKey,
          nonce: input.nonce,
          issued_at: input.issuedAt,
          expires_at: input.expiresAt,
        });
      } catch (err) {
        const reason =
          err instanceof SuiteSerializeError ? err.reason : "preimage_build_failed";
        return reject(String(reason), "destination bless preimage rejected");
      }

      const key: ResolvedSuiteVerificationKey<"device"> = {
        keyId: device.id as Uuid,
        keyClass: "device",
        publicKey: device.publicKey as WalletPublicKey,
      };

      try {
        verifyDestinationBless(
          {
            key_id: device.id as Uuid,
            preimage_text: preimage.preimageText,
            preimage_sha256: preimage.sha256,
            signature: input.deviceSignature as never,
          },
          key,
        );
      } catch (err) {
        const reason = err instanceof SuiteVerifyError ? err.reason : "signature_invalid";
        return reject(String(reason), "device signature verification failed");
      }

      const artifactId = newArtifactId();
      const persist = await deps.persistArtifact({
        id: artifactId,
        nodeId: input.nodeId,
        destinationId: input.destinationId,
        walletId: input.walletId,
        walletPubkey: input.walletPublicKey,
        nonce: input.nonce,
        issuedAt: input.issuedAt,
        expiresAt: input.expiresAt,
        deviceSignature: input.deviceSignature,
        preimageText: preimage.preimageText,
        preimageSha256: preimage.sha256,
        createdAt: at,
      });
      if (persist === "nonce_conflict") {
        return reject("nonce_reused", "blessing nonce already consumed");
      }
      if (persist !== "inserted") {
        return reject("artifact_persist_failed", "destination_blessing_artifacts insert failed");
      }

      await appendAudit({
        action: "destination.bless",
        nodeId: input.nodeId,
        destinationId: input.destinationId,
        walletId: input.walletId,
        deviceKeyId: device.id,
        artifactId,
        code: "OK",
        detail: "destination blessed",
        at,
      });

      return { deviceKeyId: device.id as Uuid, artifactId };
    },
  };
}

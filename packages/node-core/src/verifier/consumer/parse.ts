// consumer verifier kit — proof-bundle parsing and validation.
//
// Supplied bodies are untrusted evidence. Accepts an
// untrusted wire bundle (e.g. decoded JSON) and produces a typed ProofBundle, or a typed
// rejection. Never throws; never verifies signatures or economic predicates (verify.ts).
import { Buffer } from "node:buffer";

import type { WalletStateProjection } from "../../protocol/wallet-role.js";
import {
  OPERATION_PROOF_KINDS,
  type ArtifactEnvelope,
  type ProofBundle,
  type ProofBundleParseResult,
  type WireProofBundle,
} from "./types.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

// Accepts both padded and unpadded base64url (RFC 4648 section 5); Node's decoder handles both.
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+=*$/;

function decodeBase64Url(value: unknown): Uint8Array | null {
  if (!isNonEmptyString(value)) return null;
  if (!BASE64URL_PATTERN.test(value)) return null;
  return new Uint8Array(Buffer.from(value, "base64url"));
}

function isArtifactEnvelope(value: unknown): value is ArtifactEnvelope {
  if (!isRecord(value)) return false;
  return (
    isNonEmptyString(value.key_id) &&
    isNonEmptyString(value.preimage_text) &&
    isNonEmptyString(value.preimage_sha256) &&
    isNonEmptyString(value.signature)
  );
}

function isProjection(value: unknown): value is WalletStateProjection {
  if (!isRecord(value)) return false;
  return (
    (value.role === "sender" || value.role === "receiver" || value.role === "genesis") &&
    typeof value.S === "string" &&
    typeof value.P === "string" &&
    typeof value.B === "string" &&
    (typeof value.I === "string" || value.I === null)
  );
}

function isSpawnLink(value: unknown): value is { readonly receiveTransactionStepTwoSignature: string } {
  return isRecord(value) && isNonEmptyString(value.receiveTransactionStepTwoSignature);
}

function malformed(reason: "MALFORMED_BUNDLE" | "INVALID_RESPONSE_ENCODING", detail: string): ProofBundleParseResult {
  return { ok: false, reason, detail };
}

// Parses and structurally validates an untrusted wire bundle. Response bytes are decoded from
// canonical padded base64url; signature and predicate verification are deferred to verify.ts.
export function parseProofBundle(input: unknown): ProofBundleParseResult {
  if (!isRecord(input)) return malformed("MALFORMED_BUNDLE", "bundle must be a JSON object");

  const wire = input as Partial<WireProofBundle>;
  const kind = wire.kind;
  if (typeof kind !== "string" || !(OPERATION_PROOF_KINDS as readonly string[]).includes(kind)) {
    return malformed("MALFORMED_BUNDLE", `bundle.kind must be one of ${OPERATION_PROOF_KINDS.join(", ")}`);
  }
  if (!isArtifactEnvelope(wire.artifact)) {
    return malformed("MALFORMED_BUNDLE", "bundle.artifact must carry key_id, preimage_text, preimage_sha256, signature");
  }
  const artifact = wire.artifact;

  if (wire.baseline !== undefined && !isProjection(wire.baseline)) {
    return malformed("MALFORMED_BUNDLE", "bundle.baseline is not a wallet-state projection");
  }

  if (kind === "move") {
    const sourceBytes = decodeBase64Url(wire.sourceResponse?.base64url);
    if (sourceBytes === null) {
      return malformed("INVALID_RESPONSE_ENCODING", "bundle.sourceResponse.base64url is not canonical padded base64url");
    }
    const destinationBytes = decodeBase64Url(wire.destinationResponse?.base64url);
    if (destinationBytes === null) {
      return malformed("INVALID_RESPONSE_ENCODING", "bundle.destinationResponse.base64url is not canonical padded base64url");
    }
    if (wire.sourceBaseline !== undefined && !isProjection(wire.sourceBaseline)) {
      return malformed("MALFORMED_BUNDLE", "bundle.sourceBaseline is not a wallet-state projection");
    }
    if (wire.destinationBaseline !== undefined && !isProjection(wire.destinationBaseline)) {
      return malformed("MALFORMED_BUNDLE", "bundle.destinationBaseline is not a wallet-state projection");
    }
    const bundle: ProofBundle = {
      kind: "move",
      artifact,
      sourceResponse: sourceBytes,
      destinationResponse: destinationBytes,
      sourceBaseline: wire.sourceBaseline,
      destinationBaseline: wire.destinationBaseline,
      spawnedFromReceive: isSpawnLink(wire.spawnedFromReceive) ? wire.spawnedFromReceive : undefined,
    };
    return { ok: true, bundle };
  }

  const responseBytes = decodeBase64Url(wire.response?.base64url);
  if (responseBytes === null) {
    return malformed("INVALID_RESPONSE_ENCODING", "bundle.response.base64url is not canonical padded base64url");
  }

  if (kind === "receive") {
    const bundle: ProofBundle = {
      kind: "receive",
      artifact,
      receiverResponse: responseBytes,
      receiverBaseline: wire.baseline,
    };
    return { ok: true, bundle };
  }

  const bundle: ProofBundle = {
    kind: "send",
    artifact,
    sourceResponse: responseBytes,
    sourceBaseline: wire.baseline,
  };
  return { ok: true, bundle };
}

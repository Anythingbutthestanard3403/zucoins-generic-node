// SplitChain-compatible receiver-channel producer (the endpoint-id-credential and relay rules).
// Internal adapter: not a fourth public money-operation endpoint
// (CANDIDATE_INTAKE_IS_PUBLIC_OPERATION_ENDPOINT=false). Enqueues the payer step-1
// partial into MoneyWorkersHandle.candidateIntake for the leadership drain. // contract-allow:drain:frozen structural vocabulary
//
// The byte-exact signing rule: inner_preimage_text is sliced from the decoded envelope / bare
// partial JSON WITHOUT parse→stringify. Signature verify runs over those exact bytes.
//
// Action literals match packages/generic-node-contracts candidate-intake.contract
// . Inlined — contracts package is not a production dependency of this app.

import type { MetricCandidateIntakeRefusal } from "@zucoins/node-core";

import type {
  CandidateIntakeInbox,
  CandidateIntakeSource,
} from "./receive-candidate-intake-step.js";

/** Wallet-compatible action name. */
export const RECEIVER_CHANNEL_ACTION_NAME =
  "zucoin_wallet_sender_partial_transfer_code__v1" as const;

/** Action_data field carrying the encoded sender partial. */
export const RECEIVER_CHANNEL_ACTION_DATA_FIELD = "sender_transfer_code_encoded" as const;

/** Path is mount-side; not in ROUTE_POLICIES (internal adapter). */
export const RECEIVER_CHANNEL_PATH = "/v1/receivers/origin-relay" as const;

export interface ReceiverChannelEnqueueResult {
  readonly enqueued: boolean;
  /** Discard reasons stay coarse — never echo signed material. */
  readonly reason?: MetricCandidateIntakeRefusal;
}

/**
 * Extract `{inner_preimage_text, step_1_signature}` from a wallet-encoded transfer
 * code or bare partial. Returns null when the shape is not a signed step-1 partial.
 */
export function extractSenderPartialCapture(encodedTransferCode: string): {
  readonly inner_preimage_text: string;
  readonly step_1_signature: string;
} | null {
  let envelopeJson: string;
  try {
    envelopeJson = decodeTransferCodeToJsonText(encodedTransferCode);
  } catch {
    return null;
  }
  return extractCaptureFromPartialJson(envelopeJson);
}

/**
 * Decode a POST body (receiver-channel action) into an inbox enqueue.
 * Fire-and-forget: always safe to 204 after this returns (discard semantics).
 *
 * `source` names the producer lane and is required rather than defaulted — a new
 * producer must choose its trust level explicitly, not inherit one.
 */
export function enqueueReceiverChannelDeposit(
  inbox: CandidateIntakeInbox,
  rawBody: unknown,
  source: CandidateIntakeSource,
): ReceiverChannelEnqueueResult {
  if (typeof rawBody !== "object" || rawBody === null) {
    return { enqueued: false, reason: "malformed_body" };
  }
  const body = rawBody as Record<string, unknown>;
  if (body.action_name !== RECEIVER_CHANNEL_ACTION_NAME) {
    return { enqueued: false, reason: "wrong_action" };
  }
  const actionData = body.action_data;
  if (typeof actionData !== "object" || actionData === null) {
    return { enqueued: false, reason: "malformed_body" };
  }
  const encoded = (actionData as Record<string, unknown>)[RECEIVER_CHANNEL_ACTION_DATA_FIELD];
  if (typeof encoded !== "string" || encoded.length === 0) {
    return { enqueued: false, reason: "malformed_body" };
  }

  const capture = extractSenderPartialCapture(encoded);
  if (capture === null) {
    return { enqueued: false, reason: "decode_failed" };
  }

  let locate: { receiverPubkey: string; discriminator: string; expiry: string };
  try {
    locate = locateKeysFromInnerText(capture.inner_preimage_text);
  } catch {
    return { enqueued: false, reason: "decode_failed" };
  }

  // Cap enforcement lives in the inbox, so every producer is bounded by construction.
  return inbox.enqueue(
    {
      locate,
      inner_preimage_text: capture.inner_preimage_text,
      step_1_signature: capture.step_1_signature,
    },
    source,
  );
}

function decodeTransferCodeToJsonText(encoded: string): string {
  const pad = encoded.length % 4 === 0 ? "" : "=".repeat(4 - (encoded.length % 4));
  const uriEncoded = Buffer.from(encoded + pad, "base64url").toString("utf8");
  return decodeURIComponent(uriEncoded);
}

function extractCaptureFromPartialJson(source: string): {
  readonly inner_preimage_text: string;
  readonly step_1_signature: string;
} | null {
  const partialMarker = '"partial_transaction":';
  const ptIdx = source.indexOf(partialMarker);
  let partialRegion = source;
  if (ptIdx >= 0) {
    const brace = source.indexOf("{", ptIdx + partialMarker.length);
    if (brace < 0) return null;
    const extracted = extractJsonObjectAt(source, brace);
    if (extracted === null) return null;
    partialRegion = extracted;
  }

  const innerKey = '"inner":';
  const innerKeyIdx = partialRegion.indexOf(innerKey);
  if (innerKeyIdx < 0) return null;
  const innerBrace = partialRegion.indexOf("{", innerKeyIdx + innerKey.length);
  if (innerBrace < 0) return null;
  const innerText = extractJsonObjectAt(partialRegion, innerBrace);
  if (innerText === null) return null;

  const sigKey = '"step_1_signature":';
  const sigKeyIdx = partialRegion.indexOf(sigKey);
  if (sigKeyIdx < 0) return null;
  const sigQuote = partialRegion.indexOf('"', sigKeyIdx + sigKey.length);
  if (sigQuote < 0) return null;
  const sigEnd = findClosingStringQuote(partialRegion, sigQuote);
  if (sigEnd < 0) return null;
  let step1: string;
  try {
    step1 = JSON.parse(partialRegion.slice(sigQuote, sigEnd + 1)) as string;
  } catch {
    return null;
  }
  if (typeof step1 !== "string" || step1.length === 0) return null;

  return { inner_preimage_text: innerText, step_1_signature: step1 };
}

function extractJsonObjectAt(source: string, openBraceIndex: number): string | null {
  if (source[openBraceIndex] !== "{") return null;
  let depth = 0;
  let inString = false;
  let escape = false;
  for (let i = openBraceIndex; i < source.length; i++) {
    const c = source[i]!;
    if (inString) {
      if (escape) {
        escape = false;
        continue;
      }
      if (c === "\\") {
        escape = true;
        continue;
      }
      if (c === '"') inString = false;
      continue;
    }
    if (c === '"') {
      inString = true;
      continue;
    }
    if (c === "{") depth += 1;
    else if (c === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(openBraceIndex, i + 1);
    }
  }
  return null;
}

function findClosingStringQuote(source: string, openQuoteIndex: number): number {
  if (source[openQuoteIndex] !== '"') return -1;
  let escape = false;
  for (let i = openQuoteIndex + 1; i < source.length; i++) {
    const c = source[i]!;
    if (escape) {
      escape = false;
      continue;
    }
    if (c === "\\") {
      escape = true;
      continue;
    }
    if (c === '"') return i;
  }
  return -1;
}

function locateKeysFromInnerText(innerText: string): {
  receiverPubkey: string;
  discriminator: string;
  expiry: string;
} {
  const inner = JSON.parse(innerText) as Record<string, unknown>;
  const receiverPubkey = inner.step_2_key_public__base64urlsafe;
  const expiry = inner.expiry__unix_time_secs;
  const message = inner.message;
  if (typeof receiverPubkey !== "string" || receiverPubkey.length === 0) {
    throw new Error("missing receiver");
  }
  if (typeof expiry !== "string" || expiry.length === 0) {
    throw new Error("missing expiry");
  }
  if (typeof message !== "string" || !message.startsWith("zp1:")) {
    throw new Error("bad message");
  }
  // zp1:<uuid-discriminator>:<anchor> — UUID is fixed-width; split once after prefix.
  const rest = message.slice("zp1:".length);
  const colon = rest.indexOf(":");
  if (colon <= 0) throw new Error("bad message");
  const discriminator = rest.slice(0, colon);
  if (discriminator.length === 0) throw new Error("bad message");
  return { receiverPubkey, discriminator, expiry };
}

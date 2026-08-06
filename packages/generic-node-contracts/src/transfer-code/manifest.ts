import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  TRANSFER_CODE_WIRE_VERSION,
  TRANSFER_CODE_TOP_LEVEL_FIELDS,
  TRANSFER_CODE_TYPES,
  SENDER_CREATE_REQUIRED_FIELDS,
  SENDER_CREATE_OPTIONAL_FIELDS,
  RECEIVER_CONFIRM_INCOMING_DATA_FIELDS,
  TRANSFER_CODE_ENCODE_PIPELINE,
  TRANSFER_CODE_DECODE_PIPELINE,
  EXPIRY_FIELD,
  EXPIRY_UNIT,
  EXPIRY_MAX_SECONDS_AHEAD_OF_BLOCK,
  RECEIVE_MESSAGE_PREFIX,
} from "./transfer-code.contract.ts";
import {
  CANDIDATE_RAW_CAPTURE_FIELDS,
  CANDIDATE_LOCATE_KEYS,
  RECEIVER_CHANNEL_ACTION_NAME,
  GATEWAY_FORM_BODY_TEMPLATE,
  GATEWAY_ACTION_FIELDS,
  GATEWAY_RESPONSE_FIELDS,
  SUBMIT_ACTION_NAME,
  SUBMIT_ACK_STATUS_TRUE_MEANS_SETTLED,
  SUBMIT_OUTCOME_CATEGORIES,
} from "./candidate-intake.contract.ts";

/**
 * The transfer-code concern's self-registered ConcernManifest (../../CONTRACT.md "ConcernManifest schema
 * (the concern-manifest registry leave-behind)"). Registration import only — the concern-manifest registry assembles `src/registry.ts`; no
 * other module touches it. The two encoded goldens are the byte authority (verified
 * wallet-identical against libsodium); their per-file provenance lives in
 * goldens/transfer-code/*.meta.json.
 */
export const TRANSFER_CODE_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "transfer-code",
  decisionRefs: ["form-transport", "transfer-code-encoding", "code-matching-window", "wire-version-freeze", "inner-retention", "expiry-seconds-encoding", "submit-ack-receipt-only", "receiver-channel-literals", "candidate-intake"],
  frozenValues: {
    TRANSFER_CODE_WIRE_VERSION,
    TRANSFER_CODE_TOP_LEVEL_FIELDS,
    TRANSFER_CODE_TYPES,
    SENDER_CREATE_REQUIRED_FIELDS,
    SENDER_CREATE_OPTIONAL_FIELDS,
    RECEIVER_CONFIRM_INCOMING_DATA_FIELDS,
    TRANSFER_CODE_ENCODE_PIPELINE,
    TRANSFER_CODE_DECODE_PIPELINE,
    EXPIRY_FIELD,
    EXPIRY_UNIT,
    EXPIRY_MAX_SECONDS_AHEAD_OF_BLOCK,
    RECEIVE_MESSAGE_PREFIX,
    CANDIDATE_RAW_CAPTURE_FIELDS,
    CANDIDATE_LOCATE_KEYS,
    RECEIVER_CHANNEL_ACTION_NAME,
    GATEWAY_FORM_BODY_TEMPLATE,
    GATEWAY_ACTION_FIELDS,
    GATEWAY_RESPONSE_FIELDS,
    SUBMIT_ACTION_NAME,
    SUBMIT_ACK_STATUS_TRUE_MEANS_SETTLED,
    SUBMIT_OUTCOME_CATEGORIES,
  },
  goldenRefs: [
    {
      path: "goldens/transfer-code/receive-code.v1.b64url.txt",
      sha256: "104eb00c3bda958b82b7ce5a24e582dd9efa3e63d2192838fe26b5b23dcb2bab",
    },
    {
      path: "goldens/transfer-code/receive-code.v1.json.txt",
      sha256: "6884acef681a435f7ef04b82c0d6d5df28c8f12275c2c69063d721ae6dcd0869",
    },
    {
      path: "goldens/transfer-code/send-code.v1.b64url.txt",
      sha256: "d454846fddc861c059476553ec4fe03fdbf3cb494a0b5be6357ceb8049d6d0e4",
    },
    {
      path: "goldens/transfer-code/send-code.v1.json.txt",
      sha256: "fc0af28b7232f2b83df93a39dac0bd1ddedcd477e658af23b49de49e3ed09640",
    },
  ],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "protocol transport and submit semantics",
    "operation flows",
    "transfer-code bytes A.2, A.8",
    "form-transport",
    "transfer-code-encoding",
    "code-matching-window",
    "wire-version-freeze",
    "inner-retention",
    "expiry-seconds-encoding",
    "submit-ack-receipt-only",
    "receiver-channel-literals",
    "candidate-intake",
    "wallet splitchain.js:1647-1868,4067-4200",
  ],
});

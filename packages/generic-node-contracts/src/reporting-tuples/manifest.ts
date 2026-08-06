// the reporting node-event purpose — Concern manifest: the serialized surface the freeze gate snapshots.
// buildReportingTuplesManifest() aggregates the frozen request/event tuple facts and their goldens
// into one JSON-serializable object; manifest.freeze.test.ts diffs it against gen/reporting-tuples.json.

import { defineConcernManifest } from "../testkit/concernManifest.ts";
import {
  REPORTING_REQUEST_HEADERS,
  REPORT_REQUEST_CANONICAL_VERSION,
  REPORT_REQUEST_FIELD_ORDER,
  REPORT_REQUEST_GOLDEN_PREIMAGE,
  REPORT_REQUEST_QUERY_GOLDEN_PREIMAGE,
  REPORT_REQUEST_MAX_WINDOW_SECONDS,
  REPORT_REQUEST_PURPOSE,
} from "./request-tuple.js";
import {
  NEUTRAL_EVENT_TYPES,
  NODE_EVENT_CANONICAL_VERSION,
  NODE_EVENT_FIELD_ORDER,
  NODE_EVENT_GOLDEN_A_PREIMAGE,
  NODE_EVENT_GOLDEN_B_PREIMAGE,
  NODE_EVENT_PURPOSE,
  SEQUENCE_MODEL,
} from "./event-tuple.js";
import {
  NODE_EVENT_A_EVENT_HASH,
  NODE_EVENT_A_SHA256,
  NODE_EVENT_A_SIGNATURE,
  NODE_EVENT_B_EVENT_HASH,
  NODE_EVENT_B_SHA256,
  NODE_EVENT_B_SIGNATURE,
  NODE_EVENT_KEY_PUBKEY,
  REPORTING_KEY_PUBKEY,
  REPORT_REQUEST_GOLDEN_SHA256,
  REPORT_REQUEST_GOLDEN_SIGNATURE,
  REPORT_REQUEST_QUERY_GOLDEN_SHA256,
  REPORT_REQUEST_QUERY_GOLDEN_SIGNATURE,
} from "./digests.js";
import { REPORT_REQUEST_CLOCK_SKEW_MS } from "./request-target.js";

export const reportingTuplesConcernManifest = {
  concern: "reporting-tuples",
  frozen: ["REPORT_REQUEST_TUPLE", "NODE_EVENT_TUPLE", "SEQUENCE_MODEL", "EVENT_HASH_RULE"],
} as const;

export const EVENT_HASH_RULE = "SHA256(preimage_bytes || signature_bytes)" as const;

export function buildReportingTuplesManifest() {
  return {
    concern: reportingTuplesConcernManifest.concern,
    governing: {
      spec: "canonical serializer; report-request and node-event tuple tables and goldens; closed event set; api-contract auth",
      decisions: [
        "reporting-ingest-auth",
        "signed-event-log",
        "sealed-store",
        "reporting-channel",
      ],
      dependsOn: "the reporting-auth register tuple",
    },
    requestTuple: {
      purpose: REPORT_REQUEST_PURPOSE,
      canonicalVersion: REPORT_REQUEST_CANONICAL_VERSION,
      fieldOrder: [...REPORT_REQUEST_FIELD_ORDER],
      maxWindowSeconds: REPORT_REQUEST_MAX_WINDOW_SECONDS,
      clockSkewMs: REPORT_REQUEST_CLOCK_SKEW_MS,
      rawTargetPolicy: {
        source: "OUTER_TRUSTED_HTTP_ADAPTER_EXACT_ORIGIN_FORM",
        reconstruction: "FORBIDDEN",
        proxyOriginalUrlHeader: "UNTRUSTED",
        encoding: "VISIBLE_ASCII_ONLY",
        percentEncoding: "REJECTED",
        queryOrder: "UNIQUE_KEYS_STRICTLY_ASCENDING_RAW_ASCII",
      },
      headers: REPORTING_REQUEST_HEADERS.map((h) => ({ header: h.header, mapsTo: h.mapsTo, signed: h.signed })),
      golden: {
        preimage: REPORT_REQUEST_GOLDEN_PREIMAGE,
        sha256: REPORT_REQUEST_GOLDEN_SHA256,
        signature: REPORT_REQUEST_GOLDEN_SIGNATURE,
        reportingKeyPubkey: REPORTING_KEY_PUBKEY,
      },
      queryGolden: {
        preimage: REPORT_REQUEST_QUERY_GOLDEN_PREIMAGE,
        sha256: REPORT_REQUEST_QUERY_GOLDEN_SHA256,
        signature: REPORT_REQUEST_QUERY_GOLDEN_SIGNATURE,
        reportingKeyPubkey: REPORTING_KEY_PUBKEY,
      },
    },
    eventTuple: {
      purpose: NODE_EVENT_PURPOSE,
      canonicalVersion: NODE_EVENT_CANONICAL_VERSION,
      fieldOrder: [...NODE_EVENT_FIELD_ORDER],
      eventTypes: [...NEUTRAL_EVENT_TYPES],
      sequenceModel: { ...SEQUENCE_MODEL },
      eventHashRule: EVENT_HASH_RULE,
      nodeEventKeyPubkey: NODE_EVENT_KEY_PUBKEY,
      goldenA: {
        preimage: NODE_EVENT_GOLDEN_A_PREIMAGE,
        sha256: NODE_EVENT_A_SHA256,
        signature: NODE_EVENT_A_SIGNATURE,
        eventHash: NODE_EVENT_A_EVENT_HASH,
      },
      goldenB: {
        preimage: NODE_EVENT_GOLDEN_B_PREIMAGE,
        sha256: NODE_EVENT_B_SHA256,
        signature: NODE_EVENT_B_SIGNATURE,
        eventHash: NODE_EVENT_B_EVENT_HASH,
      },
    },
  } as const;
}

export type ReportingTuplesManifest = ReturnType<typeof buildReportingTuplesManifest>;

/**
 * the reporting node-event purpose's self-registered ConcernManifest. Wraps the exact `buildReportingTuplesManifest()` output — the same call the
 * freeze gate diffs against `gen/reporting-tuples.json` — byte-identically under the
 * canonical shape; `reportingTuplesConcernManifest` above is the provisional form
 * supersedes. Registration export only — the concern-manifest registry assembles `src/registry.ts`.
 */
export const REPORTING_TUPLES_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "reporting",
  decisionRefs: [
    "reporting-ingest-auth",
    "signed-event-log",
    "sealed-store",
    "reporting-channel",
  ],
  frozenValues: { reportingTuples: buildReportingTuplesManifest() },
  goldenRefs: [
    {
      path: "src/reporting-tuples/gen/reporting-tuples.json",
      sha256: "5ff91a1e7771148902a84558dcc8f5a62387102ccb0452d6aef052b4f3661410",
    },
    {
      path: "src/reporting-tuples/gen/zp-node-event-v1.golden-a.preimage.txt",
      sha256: "9644a48d9f0a988c62321a371ad66f993ae4f428ae3a3ee48d0dc290e0560226",
    },
    {
      path: "src/reporting-tuples/gen/zp-node-event-v1.golden-b.preimage.txt",
      sha256: "42c27944165f242f2c4fc276ff369da58ed6055ffd71c2788f1f6fe73aec2e2c",
    },
    {
      path: "src/reporting-tuples/gen/zp-report-request-v1.preimage.txt",
      sha256: "31a0edb52dea2b193bd56add32363b7afba1021c5f9820b8c2ee3ea263cfc463",
    },
    {
      path: "src/reporting-tuples/gen/zp-report-request-v1.query.preimage.txt",
      sha256: "e752d80f744472031ac7a85bfe605b938005fb10a2a10d0bffdc83338aca9d81",
    },
  ],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "canonical-fields reference: serializer, report-request and node-event tuple tables, goldens, negative vectors",
    "state-event reference: closed durable event set",
    "api contract: reporting auth",
    "reporting-ingest-auth",
    "signed-event-log",
    "sealed-store",
    "reporting-channel",
  ],
});

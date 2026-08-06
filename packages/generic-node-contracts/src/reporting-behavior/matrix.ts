// the reporting bootstrap enrolment — The replay / key-rotation behavioural matrix. Each cell runs the reporting bootstrap enrolment decision
// function over a fixed scenario and records the frozen outcome. Chain scenarios consume the
// the reporting node-event purpose event-hash goldens; rotation scenarios exercise the reporting-auth register tuple lifecycle states.
//
// Governing contract: register tuple / event signing; signed reporting; the pull-cursor authority decision.

import { NODE_EVENT_A_EVENT_HASH, NODE_EVENT_GOLDEN_B } from "../reporting-tuples/index.js";
import {
  cutoverNeverGoesDark,
  evaluateChainAppend,
  evaluateKeyUse,
  evaluateReportRequest,
  evaluateRestoreIngest,
  evaluateTenantSeq,
  type KeyRegistry,
  type KeySlot,
  type RequestContext,
} from "./decisions.js";

const NODE = "11111111-1111-4111-8111-111111111111";
const IMPL = "22222222-2222-4222-8222-222222222222";
const OTHER_IMPL = "deadbeef-dead-4ead-8ead-deaddeaddead";
const BODY = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
const METHOD = "GET";
const TARGET = "/v1/events?after_implementer_seq=1043&limit=100&wait_seconds=30";
const ZERO_HASH = "0".repeat(64);
const CUR = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const PRI = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const NEW = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";

function req(over: Partial<RequestContext>): RequestContext {
  return {
    boundNodeId: NODE,
    boundImplementerId: IMPL,
    tupleNodeId: NODE,
    tupleImplementerId: IMPL,
    issuedAtMs: 0,
    expiresAtMs: 60_000,
    receiptTimeMs: 30_000,
    nonceSeen: false,
    signedMethod: METHOD,
    actualMethod: METHOD,
    signedTarget: TARGET,
    actualTarget: TARGET,
    signedBodySha256: BODY,
    actualBodySha256: BODY,
    ...over,
  };
}

const reg = (current: KeySlot | null, prior: KeySlot | null): KeyRegistry => ({ current, prior });
const slot = (key_id: string, state: "ACTIVE" | "RETIRED" | "REVOKED"): KeySlot => ({ key_id, state });

export interface MatrixCell {
  readonly dimension: string;
  readonly scenario: string;
  readonly outcome: string;
}

export function buildReplayMatrix(): MatrixCell[] {
  const cell = (dimension: string, scenario: string, outcome: string): MatrixCell => ({ dimension, scenario, outcome });
  return [
    cell("request", "fresh", evaluateReportRequest(req({}))),
    cell("request", "duplicate_nonce", evaluateReportRequest(req({ nonceSeen: true }))),
    cell("request", "expired", evaluateReportRequest(req({ receiptTimeMs: 60_001 }))),
    cell("request", "not_yet_valid", evaluateReportRequest(req({ receiptTimeMs: -1 }))),
    cell("request", "at_issued_boundary", evaluateReportRequest(req({ receiptTimeMs: 0 }))),
    cell("request", "at_expires_boundary", evaluateReportRequest(req({ receiptTimeMs: 60_000 }))),
    cell("request", "zero_length_window", evaluateReportRequest(req({ expiresAtMs: 0, receiptTimeMs: 0 }))),
    cell("request", "negative_window", evaluateReportRequest(req({ expiresAtMs: -1, receiptTimeMs: 0 }))),
    cell("request", "window_over_60s", evaluateReportRequest(req({ expiresAtMs: 60_001 }))),
    cell("request", "method_mutated", evaluateReportRequest(req({ actualMethod: "POST" }))),
    cell("request", "target_mutated", evaluateReportRequest(req({ actualTarget: "/v1/events?limit=100&after_implementer_seq=1043&wait_seconds=30" }))),
    cell("request", "target_mutated_nonce_seen", evaluateReportRequest(req({ actualTarget: "/v1/events?limit=100&after_implementer_seq=1043&wait_seconds=30", nonceSeen: true }))),
    cell("request", "body_mutated", evaluateReportRequest(req({ actualBodySha256: ZERO_HASH }))),
    cell("request", "wrong_tenant", evaluateReportRequest(req({ tupleImplementerId: OTHER_IMPL }))),

    cell("rotation", "current_active", evaluateKeyUse(reg(slot(CUR, "ACTIVE"), slot(PRI, "ACTIVE")), CUR)),
    cell("rotation", "prior_overlap", evaluateKeyUse(reg(slot(CUR, "ACTIVE"), slot(PRI, "ACTIVE")), PRI)),
    cell("rotation", "prior_retired_post_cutover", evaluateKeyUse(reg(slot(CUR, "ACTIVE"), slot(PRI, "RETIRED")), PRI)),
    cell("rotation", "revoked_current", evaluateKeyUse(reg(slot(CUR, "REVOKED"), slot(PRI, "ACTIVE")), CUR)),
    cell("rotation", "unknown_key", evaluateKeyUse(reg(slot(CUR, "ACTIVE"), null), "unknown-key-id")),
    cell("rotation", "revoke_to_zero", evaluateKeyUse(reg(slot(CUR, "REVOKED"), slot(PRI, "RETIRED")), CUR)),

    cell("event_stream", "tenant_seq_sparse_jump", evaluateTenantSeq(5n, 9n)),
    cell("event_stream", "tenant_seq_reorder", evaluateTenantSeq(9n, 5n)),
    cell("event_stream", "chain_intact", evaluateChainAppend(NODE_EVENT_A_EVENT_HASH, NODE_EVENT_GOLDEN_B.previous_event_hash)),
    cell("event_stream", "chain_break", evaluateChainAppend(NODE_EVENT_A_EVENT_HASH, ZERO_HASH)),

    cell("restore", "same_epoch_chain_intact", evaluateRestoreIngest({ epoch: 1, lastEventHash: NODE_EVENT_A_EVENT_HASH }, { epoch: 1, previousEventHash: NODE_EVENT_A_EVENT_HASH })),
    cell("restore", "same_epoch_chain_break", evaluateRestoreIngest({ epoch: 1, lastEventHash: NODE_EVENT_A_EVENT_HASH }, { epoch: 1, previousEventHash: ZERO_HASH })),
    cell("restore", "epoch_regression", evaluateRestoreIngest({ epoch: 2, lastEventHash: null }, { epoch: 1, previousEventHash: null })),
    cell("restore", "post_restore_new_epoch", evaluateRestoreIngest({ epoch: 1, lastEventHash: NODE_EVENT_A_EVENT_HASH }, { epoch: 2, previousEventHash: null })),

    cell("cutover", "activate_before_retire", cutoverNeverGoesDark([
      reg(slot(CUR, "ACTIVE"), null),
      reg(slot(NEW, "ACTIVE"), slot(CUR, "ACTIVE")),
      reg(slot(NEW, "ACTIVE"), slot(CUR, "RETIRED")),
    ]) ? "VALID" : "INVALID"),
    cell("cutover", "retire_before_activate", cutoverNeverGoesDark([
      reg(slot(CUR, "ACTIVE"), null),
      reg(null, slot(CUR, "RETIRED")),
      reg(slot(NEW, "ACTIVE"), slot(CUR, "RETIRED")),
    ]) ? "VALID" : "INVALID"),
  ];
}

import { describe, expect, it } from "vitest";

import { assertFieldOrder } from "../testkit/freeze.ts";
import {
  RAW_OBSERVATION_CAPTURE_FIELDS,
  GATEWAY_OBSERVATION_RECORD_FIELDS,
  WALLET_OBSERVATION_CURSOR_FIELDS,
  OBSERVATION_ANOMALY_RECORD_FIELDS,
  type FieldSpec,
} from "./record-fields.contract.ts";

const names = (fields: readonly FieldSpec[]): readonly string[] => fields.map((f) => f.name);
const nullable = (fields: readonly FieldSpec[], name: string): boolean =>
  fields.find((f) => f.name === name)?.nullable ?? false;

describe("raw observation record field contracts are frozen (the observation dedup freeze)", () => {
  it("capture fields — names and sequence", () => {
    assertFieldOrder(names(RAW_OBSERVATION_CAPTURE_FIELDS), [
      "observer_id",
      "endpoint_fingerprint",
      "wallet_public_key",
      "observed_at",
      "http_status",
      "raw_response_bytes",
      "raw_response_octets",
      "raw_response_sha256",
    ]);
  });

  it("gateway_observations fields — names and sequence match the DDL column sequence", () => {
    assertFieldOrder(names(GATEWAY_OBSERVATION_RECORD_FIELDS), [
      "id",
      "observer_id",
      "endpoint_fingerprint",
      "wallet_id",
      "wallet_public_key",
      "wallet_seq",
      "observed_at",
      "http_status",
      "raw_response_bytes",
      "raw_response_sha256",
      "parse_result",
      "relationship",
      "semantic_fingerprint",
      "state_changed",
      "wallet_role",
      "s_signature",
      "p_signature",
      "b_amount",
      "inner_preimage_text",
      "step_1_signature",
      "step_2_signature",
      "completed_transaction_text",
      "completed_transaction_sha256",
      "previous_recorded_observation_id",
      "created_at",
    ]);
  });

  it("wallet_observation_cursors fields — names and sequence", () => {
    assertFieldOrder(names(WALLET_OBSERVATION_CURSOR_FIELDS), [
      "observer_id",
      "wallet_id",
      "wallet_public_key",
      "last_recorded_observation_id",
      "last_raw_response_sha256",
      "last_semantic_fingerprint",
      "last_seen_at",
      "consecutive_repeat_count",
      "next_wallet_seq",
    ]);
  });

  it("observation_anomalies fields — names and sequence", () => {
    assertFieldOrder(names(OBSERVATION_ANOMALY_RECORD_FIELDS), [
      "id",
      "observation_id",
      "observer_id",
      "wallet_id",
      "wallet_public_key",
      "kind",
      "prior_observation_id",
      "details",
      "detected_at",
    ]);
  });

  it("nullability of the load-bearing fields is frozen", () => {
    expect(nullable(GATEWAY_OBSERVATION_RECORD_FIELDS, "raw_response_bytes")).toBe(false);
    expect(nullable(GATEWAY_OBSERVATION_RECORD_FIELDS, "raw_response_sha256")).toBe(false);
    expect(nullable(GATEWAY_OBSERVATION_RECORD_FIELDS, "parse_result")).toBe(false);
    expect(nullable(GATEWAY_OBSERVATION_RECORD_FIELDS, "relationship")).toBe(false);
    expect(nullable(GATEWAY_OBSERVATION_RECORD_FIELDS, "wallet_id")).toBe(true);
    expect(nullable(GATEWAY_OBSERVATION_RECORD_FIELDS, "semantic_fingerprint")).toBe(true);
    expect(nullable(GATEWAY_OBSERVATION_RECORD_FIELDS, "completed_transaction_text")).toBe(true);
    expect(nullable(GATEWAY_OBSERVATION_RECORD_FIELDS, "previous_recorded_observation_id")).toBe(
      true,
    );
  });

  it("the b_amount field uses the amounts-grammar freeze balance domain, not the strictly-positive domain", () => {
    const bAmount = GATEWAY_OBSERVATION_RECORD_FIELDS.find((f) => f.name === "b_amount");
    expect(bAmount?.type).toBe("zkz_balance_text");
  });
});

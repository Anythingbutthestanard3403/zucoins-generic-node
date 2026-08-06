// The consumer cursor / checkpoint contract and the node-side restart/recovery
// sequencing invariants, plus the tenant-sparsity and hash-chain-as-gap-detector facts (which defer
// to the reporting concerns' frozen surfaces). CONTRACT_FREEZE.

// The /v1/events cursor contract. `after_seq` is exclusive; the consumer applies events strictly
// after the watermark; the cursor tracks the dedicated gapless sequence, never
// audit_log.id. A checkpoint is the consumer's own durable cursor position.
export const CURSOR_CONTRACT = {
  requestCursorField: "after_seq",
  requestCursorExclusive: true,
  responseWatermarkField: "watermark_seq",
  responseNextCursorField: "next_after_seq",
  applyRule: "strictly_after_watermark",
  tracks: "dedicated_gapless_sequence",
  monotonic: true,
  checkpoint: "consumer_durable_cursor_position",
} as const;

// Node-side restart / recovery invariants. On restart the counter resumes from the durable
// high-water mark — it never resets and never reuses a seq. An allocated-but-uncommitted seq is
// rolled back with its transaction, so the counter does not advance past an uncommitted value: there
// is no phantom gap. (This is the writer-side counter recovery; the consumer-side restore epoch +
// hash-chain hard-stop is the reporting bootstrap enrolment's restore guard.)
export const RESTART_INVARIANTS = {
  resumesFrom: "durable_high_water_mark",
  resetsToZero: false,
  reusesSeq: false,
  uncommittedSeqRolledBack: true,
  phantomGapPossible: false,
} as const;

// Tenant-view sparsity + the authoritative gap/tamper detector. The counter is node-global, so a
// tenant-filtered consumer sees a legitimately sparse subset: a skipped seq is another tenant's
// event, NOT a gap. Seq contiguity is therefore NOT the tenant-visible gap detector — the
// node-global previous_event_hash chain is the sole authoritative gap/tamper detector. These facts
// are owned by reporting-tuples (SEQUENCE_MODEL / event_hash rule); this module records them to
// bind the cursor contract to them and defers to reporting-tuples on any conflict.
export const GAP_DETECTION = {
  counterScope: "node_global",
  tenantViewSparse: true,
  skippedSeqMeaning: "another_tenants_event_not_a_gap",
  authoritativeGapDetector: "previous_event_hash_chain",
  seqContiguityIsGapDetector: false,
} as const;

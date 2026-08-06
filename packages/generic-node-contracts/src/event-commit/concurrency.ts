// the events concern.2 — Concurrent-writer contract for the atomic commit. Concurrent full commits serialize on
// the counter increment (the gap-detection fact's `lock_and_increment_counter`, step 1 of ALLOCATION_STEP_ORDER):
// exactly one writer wins each seq, no two committed events share a seq, and the loser proceeds on the
// NEXT seq — the sequence stays contiguous and gapless under contention. The data model requires the data
// digest, exact preimage, signature, previous-link, and event_hash to be recomputed in the SAME
// serialized transaction, so a concurrent reader never observes a half-built event or an uncommitted
// seq (durable-before-visible, the gap-detection fact).
//
// Governing contract: node_events data model ("same serialized transaction"); event signing. Consumes the gap-detection fact's
// ALLOCATION_STEP_ORDER (the counter lock is step 1). CONTRACT_FREEZE — no runtime transaction code.

export const CONCURRENCY = {
  serializedOn: "lock_and_increment_counter",
  oneWinnerPerSeq: true,
  distinctSeqPerCommittedEvent: true,
  loserProceedsOnNextSeq: true,
  contiguousUnderContention: true,
  concurrentReaderObservesHalfBuiltEvent: false,
} as const;

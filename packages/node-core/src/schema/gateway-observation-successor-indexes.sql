-- Buried SEND completion landing: the gateway_observations indexes the any-depth
-- complete-path landing oracle and the retained-body forward walk need.
--
-- Frozen schema contract. This file is contract text: it is executed only by the schema-apply phase against a live database; nothing in this package runs it. Every invariant
-- below is inventoried in gateway-observation-successor-indexes.contract.ts.
--
-- Scope: three indexes on the already-created gateway_observations table (observation-
-- ledger.sql, applied first; this file is an extension and does not re-declare it) that
-- the production RetainedPathBodySource adapter (packages/node-core/src/verifier/
-- ancestry-walker.ts's resolveSuccessorByBacklink / countDistinctBodiesWithDigest) and
-- retained-path-body-source-sql.ts's fetchRetainedBodyByStepOneSignature (buried SEND
-- completion landing) need to walk a retained body chain without a full-table scan.
--
-- Pack position: appended after node-signing-key-sealed-store so earlier money-pack
-- version numbers (and sql_sha256 journal entries) stay stable for already-applied
-- greenfield DBs (mirrors the node-signing-key-sealed-store.sql precedent).

-- Successor-by-backlink index (ancestry-walker.ts resolveSuccessorByBacklink).
-- The walk resolves the immediate successor of a state by its backlink: given a wallet's
-- retained stream and a candidate S signature, find the row(s) whose p_signature equals
-- that S. Deliberately observer-agnostic (no observer_id column) - the walk needs the
-- wallet's true next hop regardless of which observer captured it, matching the shape of
-- gateway_observations_exact_body_idx. Partial on rows that carry a p_signature: every
-- VERIFIED_GENESIS/VERIFIED_HEAD row does (p_signature is '' for a first-hop-from-genesis
-- row, never NULL); only non-verified anomaly rows have p_signature NULL.

CREATE INDEX gateway_observations_successor_by_backlink_idx
  ON gateway_observations(wallet_public_key, p_signature)
  WHERE p_signature IS NOT NULL;

-- Completed-transaction digest index (ancestry-walker.ts
-- countDistinctBodiesWithDigest). The walk's duplicate/cycle-free proof counts how many
-- DISTINCT completed_transaction_text values share a given completed_transaction_sha256,
-- globally (not wallet-scoped, matching InMemoryRetainedPathBodySource semantics) - this
-- index supports that count without a full-table scan. Partial on head rows, which are
-- the only rows that carry this digest.

CREATE INDEX gateway_observations_completed_tx_digest_idx
  ON gateway_observations(completed_transaction_sha256)
  WHERE completed_transaction_sha256 IS NOT NULL;

-- Own-body-by-step-1-signature index (retained-path-body-source-sql.ts
-- fetchRetainedBodyByStepOneSignature). A buried SEND completion's expected body
-- (AncestryWalkInput.expectedBody, path_index 0) is found by the one thing that
-- identifies OUR OWN send independent of chain position: the wallet's public key plus
-- the step-1 signature the node signed in advance (the node never learns step-2 from its
-- own records - only from independent observation). Partial on step_1_signature IS NOT
-- NULL, which the observation-ledger.sql CHECK makes exactly the VERIFIED_HEAD rows -
-- the same partial-index shape as gateway_observations_exact_body_idx.

CREATE INDEX gateway_observations_step_one_signature_idx
  ON gateway_observations(wallet_public_key, step_1_signature)
  WHERE step_1_signature IS NOT NULL;

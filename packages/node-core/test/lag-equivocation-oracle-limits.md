# Residual oracle limits of the lag / equivocation / disagreement suite

Companion to `packages/node-core/test/lag-equivocation.pg.test.ts`. That suite drives the
real `createEndpointFailoverService` (`src/gateway/failover.ts`) against scripted gateway endpoints and
a **real PostgreSQL observation ledger** built by applying the frozen DDL verbatim
(`src/schema/observation-ledger.sql` + `src/schema/observation-anomaly-indexes.sql`).

This document records what the suite **deliberately cannot close**. It is asserted by the suite itself
(the verbatim quotes below are read out of this file by the suite), so it cannot silently
drift away from either the observation model or the tests.

## What the suite does prove

- A backup that serves the **same** semantic head after the active endpoint goes transport-ambiguous is
  ordinary continuation evidence: accepted, no anomaly, and recorded as
  `EQUIVALENT_STATE_DIFFERENT_ENVELOPE` in the real ledger.
- A backup that serves a **different** semantic head is never silently adopted: the read is
  `INDETERMINATE`, an `EndpointDisagreementAnomaly` is emitted, the service halts stickily, and the
  active endpoint does not move.
- The halt is exited only through `resolveHalt()`; no subsequent agreeing read self-clears it, the
  stream position does not advance while halted, and the anomaly evidence survives resolution.
- An endpoint identity outside the configured allowlist is refused before any exchange, so it can never
  contribute a row to the observation ledger at all.
- The pairing between an anomaly-classified observation and its `observation_anomalies` row is enforced
  by the real deferred constraint trigger, so an incident cannot be laundered out of the ledger.

Everything below is outside that boundary.

## 1. A consistently lying gateway is out of model

Verbatim, from the observation model:

> The model defeats a lying node. It does not defeat a fully Byzantine SplitChain gateway that presents a
> consistent cryptographic fiction to every verifier; that requires an additional independent oracle.

Verbatim, from the observation model:

> - **Gateway equivocation:** independent node/platform observations expose some disagreement, but a gateway
>   that lies consistently to both remains out of model.

The suite's Byzantine-fiction scenario therefore asserts that the service **accepts** a fiction on which
both configured endpoints agree — no halt, no anomaly, a promoted head in the ledger. That is the
specified behaviour, not a defect, and the test states it as a limitation rather than reporting a false
green. Closing it requires an independent oracle that this slice does not have and must not pretend to
have: cross-endpoint comparison detects *disagreement*, never *agreed-upon falsehood*.

## 2. Gateway lag parked `INDETERMINATE` is correct, and diverges from the acceptance wording

Verbatim, from the observation model:

> - **Gateway lag:** a genuine landing may be safely parked `INDETERMINATE`. Availability yields to avoiding
>   phantom settlement or duplicate payment.

The acceptance criterion says a lagging replica's failover to a fresher endpoint "must not be
misread as a disagreement/anomaly". Two cases have to be separated:

- **Backup carries the same semantic head.** The AC holds exactly, and the suite proves it: no
  disagreement, no anomaly, no false alarm. This is the failover-is-not-a-disagreement guarantee.
- **Backup is genuinely ahead of the endpoint it replaced.** `failover.ts` compares the backup's semantic
  state against the immediate prior accepted state and has no material that could distinguish
  "honest fresher replica" from "forked or compromised endpoint". It fails closed. Per the quote
  above, that is the accepted trade: a genuine landing may be parked `INDETERMINATE`, and availability yields.

The observation model governs over the acceptance wording. The suite tests the advanced-head case as a correct
availability sacrifice. Making that case accept silently would require the complete-path landing
oracle to prove the fresher head is a successor of the stale one — out of scope here, and the reason the
conservative behaviour is not a bug.

## 3. Head material in the ledger is synthetic

Rows are written with DDL-valid but synthetic head material (role, S/P signatures, step 1/2 signatures,
inner preimage, completed body). The *endpoint fingerprints*, *raw response bytes*, *response digests*
and *semantic fingerprints* are real values derived from the scripted exchanges; the signature columns
are not real Ed25519 material and nothing here verifies a signature.

This suite proves **disagreement, lag, failover and recovery mechanics**. Envelope decode and the
signature-verification pipeline are the envelope-verification suite's remit. A green run here is not evidence that a forged
envelope would be rejected.

## 4. No second observer domain

The suite runs a single `NODE` observer reading two endpoints. The observation independence argument also rests
on the platform observing independently (`observer_domain` = `PLATFORM`). Node/platform cross-domain
corroboration is not exercised here, so the suite cannot speak to disagreement that is only visible
across trust domains.

## 5. `observation_anomalies` has no home for an endpoint disagreement

The observation model requires "two independent gateway endpoints disagree → halt affected wallet/operation |
`INDETERMINATE`; oracle incident". The frozen `observation_anomalies.kind` CHECK admits exactly nine
members:

```
TRANSPORT_ERROR, MALFORMED_ENVELOPE, MALFORMED_TRANSACTION, UNVERIFIED_SIGNATURE,
WALLET_ROLE_INVALID, REGRESSION, UNEXPLAINED_JUMP, GENESIS_AFTER_HISTORY, SIGNATURE_COLLISION
```

None of them is an endpoint disagreement, and the table has no column for the second (serving) endpoint
fingerprint — it is keyed one-to-one to a single `observation_id`. So the
`EndpointDisagreementAnomaly` currently has **no DDL home**, exactly as `src/gateway/anomaly.ts` states
("the concrete, DDL-backed recorder … is DEFERRED").

The suite proves this at the real database — it executes an insert with `kind='ENDPOINT_DISAGREEMENT'`
and asserts SQLSTATE 23514 — rather than inventing a kind or minting a stand-in table, which
`anomaly.ts` explicitly forbids. Consequently the injected `AnomalyRecorder` in the disagreement
scenarios captures in memory: that is the port's actual production reality today, not a substitute for a
store that exists. The *observation ledger itself* is real Postgres throughout.

Until a schema lane adds the member and the second-endpoint provenance, an oracle incident is durable
only as the halt plus the two conflicting observation rows.

## 6. `wallet_observation_cursors` is not transcribed

Boot recovery is defined in terms of `wallet_observation_cursors.last_recorded_observation_id`.
That table is deliberately absent from the frozen schema files (see the header of
`src/schema/observation-ledger.sql`; it belongs to the observation-cursor slice). The suite therefore proves "the cursor does
not advance during a halt" against the frozen stream position — `MAX(wallet_seq)` under
`UNIQUE (observer_id, wallet_public_key, wallet_seq)` — plus retrievability of the prior row's exact raw
bytes, which is the material boot recovery needs. When the cursor table lands, these assertions should be re-pointed
at it; the substitution is a scope statement, not a proof that the cursor logic is correct.

## 7. A transport-ambiguous marker is indistinguishable from an empty response

`GatewayObservationRecord.rawResponseBytes` is `null` for a transport-ambiguous attempt, but
`gateway_observations.raw_response_bytes` is `bytea NOT NULL`. A real recorder must map the ambiguous
case onto empty bytes plus the digest of the empty string, which is what this suite does. In the ledger
"no response was captured" and "an empty response was captured" then look identical. Distinguishing them
needs a schema change (a nullable body, or an explicit ambiguity flag); it is recorded here rather than
worked around silently.

## 8. TLS is not exercised on the wire

node-core tests are network-contained (`fetch`, `http`, `https`, `net`, `tls`, `dgram` are all
denied). Endpoint-identity mismatch is therefore proved at the two layers that are in process — the
allowlist refusing an unconfigured identity before any exchange, and configuration refusing non-loopback
`http` and credentials-in-URL — plus a scripted handshake failure surfacing as
`GatewayTransportAmbiguityError`. Certificate chain validation, pinning, hostname verification and
downgrade behaviour are the platform TLS stack's, and are not covered by any assertion here.

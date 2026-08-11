# Mandatory database tests — discharge matrix (ZTR-1173)

Source: `04-data-model.md` §16 (36 items). Each row cites a repository artifact that
opens PostgreSQL. The contracts package is deliberately excluded — it cannot import `pg`.

### 3.18 Mandatory database tests (`04-data-model.md` §16)

| Element | Source | Requirement | Ticket | PR | Contract anchor | Test / golden | Verification |
|---|---|---|---|---|---|---|---|
| `DB-TEST-01` | D §16 | imported wallet cannot become a destination | GN-035 / ZTR-35 | #1340 | — | `packages/node-core/test/custody-claim-boundary.pg.test.ts` | `term-matched` |
| `DB-TEST-02` | D §16 | blessed but recovery-unverified destination is excluded from every automatic-sink query | GN-035 / ZTR-35 | #1422 | — | `packages/node-core/test/custody-transition-gates.pg.test.ts` | `term-matched` |
| `DB-TEST-03` | D §16 | a second active lease for any wallet fails, including cross-operation-kind races | GN-035 / ZTR-35 | #1428 | — | `packages/node-core/test/receive/pool-race.stress.pg.test.ts` | `term-matched` |
| `DB-TEST-04` | D §16 | two-wallet acquisition is all-or-nothing and sorted | GN-035 / ZTR-35 | #1331 | — | `packages/node-core/test/lease-foundation.pg.test.ts` | `term-matched` |
| `DB-TEST-05` | D §16 | every operation-kind/status/nullable-field invalid combination fails its CHECK | GN-035 / ZTR-35 | #1304 | — | `packages/node-core/test/operations.pg.test.ts` | `named` |
| `DB-TEST-06` | D §16 | one idempotency key with a different request hash is a conflict, never a replay success | GN-035 / ZTR-35 | #797 | — | `packages/node-core/test/move-internal-create.pg.test.ts` | `term-matched` |
| `DB-TEST-07` | D §16 | exact artifact, approval, preimage, transaction, partial, observation, and event bytes survive round-trip | GN-035 / ZTR-35 | #1427 | — | `packages/node-core/test/transaction-material-store.pg.test.ts` | `term-matched` |
| `DB-TEST-08` | D §16 | JSONB is absent from all authoritative-byte columns | GN-035 / ZTR-35 | #1127 | — | `packages/node-core/test/transaction-material-store.pg.test.ts` | `term-matched` |
| `DB-TEST-09` | D §16 | a persisted external partial cannot be replaced, even after expiry or crash | GN-035 / ZTR-35 | #1088 | — | `packages/node-core/test/transaction-material-store.pg.test.ts` | `term-matched` |
| `DB-TEST-10` | D §16 | a second transaction attempt, submit decision, or submit call for one operation fails; no positive | GN-007 / ZTR-7 | #798 | — | `packages/node-core/test/submit-decision-claim-store.pg.test.ts` | `term-matched` |
| `DB-TEST-11` | D §16 | node code cannot create any submit attempt for `SEND_EXTERNAL` | GN-035 / ZTR-35 | #1382 | — | `packages/node-core/test/external-send-partial-uniqueness.pg.test.ts` | `term-matched` |
| `DB-TEST-12` | D §16 | consecutive byte-identical `A,A` stores one observation; same semantic head with a changed wrapper | GN-035 / ZTR-35 | #1142 | — | `packages/node-core/test/observation-migration-integrity.test.ts` | `term-matched` |
| `DB-TEST-13` | D §16 | malformed and unverifiable responses always append with raw bytes | GN-005 / ZTR-5 | #743 | — | `packages/node-core/test/observation-migration-integrity.test.ts` | `term-matched` |
| `DB-TEST-14` | D §16 | the node and platform use different observer rows and cannot import one another's cursor as authority | GN-035 / ZTR-35 | #1310 | — | `packages/node-core/test/two-independent-observations.pg.test.ts` | `term-matched` |
| `DB-TEST-15` | D §16 | observation/event/audit append-only triggers reject update and delete | GN-035 / ZTR-35 | #1330 | — | `packages/node-core/test/evidence-append-only.pg.test.ts` | `term-matched` |
| `DB-TEST-16` | D §16 | `verification-complete` conflicting replay fails and cannot release the wallet; and | GN-035 / ZTR-35 | #797 | — | `packages/node-core/test/proof-access-verdict-history.pg.test.ts` | `term-matched` |
| `DB-TEST-17` | D §16 | zero-depth and arbitrary-depth path bodies/manifests round-trip exactly; path indexes support ordered | GN-035 / ZTR-35 | #1150 | — | `packages/node-core/test/proof-access-verdict-history.pg.test.ts` | `term-matched` |
| `DB-TEST-18` | D §16 | a gap, cycle, duplicate body/signature, conflicting body at one index, missing completed SEND body, | GN-035 / ZTR-35 | #1372 | — | `packages/node-core/test/proof-access-verdict-history.pg.test.ts` | `term-matched` |
| `DB-TEST-19` | D §16 | an `UNEXPLAINED_JUMP` observation remains immutable and gains effective | GN-035 / ZTR-35 | #1399 | — | `packages/node-core/test/proof-access-verdict-history.pg.test.ts` | `term-matched` |
| `DB-TEST-20` | D §16 | retention jobs revoke proof access without deleting any permanent row | GN-035 / ZTR-35 | #1275 | — | `packages/node-core/test/ledger-export-retention-safety.pg.test.ts` | `term-matched` |
| `DB-TEST-21` | D §16 | one nonce claimed by `zp-reporting-register-v1` cannot be claimed by `zp-report-request-v1`, another | GN-035 / ZTR-35 | #797 | — | `packages/node-core/test/mandatory-db-discharge-21-36.pg.test.ts` | `term-matched` |
| `DB-TEST-22` | D §16 | invalid/expired/revoked/bad-signature requests insert no burn, while authenticated 404/409/500, | GN-035 / ZTR-35 | #797 | — | `packages/node-core/test/mandatory-db-discharge-21-36.pg.test.ts` | `term-matched` |
| `DB-TEST-23` | D §16 | competing rotations and request-admission-versus-revocation races lock one | GN-035 / ZTR-35 | #1232 | — | `packages/node-core/test/mandatory-db-discharge-21-36.pg.test.ts` | `term-matched` |
| `DB-TEST-24` | D §16 | mutation idempotency rejects non-visible-ASCII or out-of-range keys, resolves completed replay/conflict | GN-035 / ZTR-35 | #797 | — | `packages/node-core/test/mandatory-db-discharge-21-36.pg.test.ts` | `term-matched` |
| `DB-TEST-25` | D §16 | changing only the unsigned `Idempotency-Key` cannot re-execute arm or verification-complete because the | GN-035 / ZTR-35 | #797 | — | `packages/node-core/test/mandatory-db-discharge-21-36.pg.test.ts` | `term-matched` |
| `DB-TEST-26` | D §16 | composite foreign keys reject cross-node or cross-implementer attachment of operation, nonce, | GN-035 / ZTR-35 | #797 | — | `packages/node-core/test/mandatory-db-discharge-21-36.pg.test.ts` | `term-matched` |
| `DB-TEST-27` | D §16 | missing trusted restore source/markers, lifecycle-epoch or nonce-high-water regression, partial backup, | GN-035 / ZTR-35 | #797 | — | `apps/generic-node/test/dr/auth-hold-force.pg.test.ts` | `term-matched` |
| `DB-TEST-28` | D §16 | exact raw target, request preimage/digest/signature, exact-body digest, lifecycle public evidence, and | GN-035 / ZTR-35 | #797 | — | `apps/generic-node/test/reporting-credential-service.pg.test.ts` | `term-matched` |
| `DB-TEST-29` | D §16 | reporting key identities accept only `id`, `node_id`, `implementer_id`, `public_key`, and `registered_at` | GN-035 / ZTR-35 | #797 | — | `packages/node-core/test/signing-key-registry.pg.test.ts` | `term-matched` |
| `DB-TEST-30` | D §16 | the actual deferred lifecycle triggers reject unknown event types, illegal/latest-state edges, missing or | GN-035 / ZTR-35 | #797 | — | `packages/node-core/test/mandatory-db-discharge-21-36.pg.test.ts` | `term-matched` |
| `DB-TEST-31` | D §16 | a register nonce naming another new key, any enrolment mismatch in exact preimage text/digest/signature, | GN-035 / ZTR-35 | #991 | — | `packages/node-core/test/mandatory-db-discharge-21-36.pg.test.ts` | `term-matched` |
| `DB-TEST-32` | D §16 | request evidence beyond 60 seconds, register evidence beyond 300 seconds, or a rotation overlap not | GN-035 / ZTR-35 | #991 | — | `packages/node-core/test/mandatory-db-discharge-21-36.pg.test.ts` | `term-matched` |
| `DB-TEST-33` | D §16 | the actual deferred route triggers reject a pending parent, arm/ack without its completed parent, parent | GN-035 / ZTR-35 | #1395 | — | `apps/generic-node/test/mutation-correlation.pg.test.ts` | `term-matched` |
| `DB-TEST-34` | D §16 | nonce/idempotency/arm/ack disagreement in method, opaque exact raw target, or body digest fails, as does a | GN-035 / ZTR-35 | #797 | — | `apps/generic-node/test/mutation-correlation.pg.test.ts` | `term-matched` |
| `DB-TEST-35` | D §16 | missing or unequal local/trusted lifecycle epoch, nonce-burn high-water, or event hash retains | GN-035 / ZTR-35 | #797 | — | `apps/generic-node/test/dr/auth-hold-force.pg.test.ts` | `term-matched` |
| `DB-TEST-36` | D §16 | a sign-intent insert stores `redemption_expiry_at` exactly equal to the whole-second projection | GN-035 / ZTR-35 | #1445 | — | `packages/node-core/test/mandatory-db-discharge-21-36.pg.test.ts` | `term-matched` |


# ZTR-1216 — implementer handoff

**PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/89
**Head SHA:** `43ce258388d6c357f575c9e30d856959f3782254`
**Branch:** `ztr-1216-candidate-intake-residuals`

## Locked defaults (sweeper 2026-08-11)
- (a) Rate-limit anonymous relay (non-oracular); no new auth scheme
- (b) `gn_candidate_intake_backlog{source}` gauge required
- (c) Accept reconcile as sufficient for restart durability; document; no durable queue

## What landed
1. **Rate-limit** — `packages/node-core/src/http/origin-relay-rate-limit.ts`
   - Fixed window 60s / 120 req per socket peer (`InMemoryReportingRateLimiter`)
   - Wired in `runtime-listener.ts` **before** body read
   - Shed → still 204 + `onCandidateIntakeRefused("relay","rate_limited")`
2. **Backlog gauge** — `gn_candidate_intake_backlog{source}`
   - Set on deposit (`main.ts`) and after take (`runReceiveCandidateIntakeStep`)
   - `CandidateIntakeInbox.sizeBySource(source)`
3. **Ops note** — `docs/operations/README.md` § Candidate-intake backlog
   - Restart drops in-memory inbox; reconcile re-detects

## AC
| # | Status |
| --- | --- |
| 1 relay rate-limited + test + non-oracular | ✅ |
| 2 backlog gauge scraped + test | ✅ |
| 3 ops note restart/reconcile | ✅ |
| 4 no frozen-ops change; 1188 caps | ✅ |

## Evidence at head
- `tsc -b` clean
- node-core: origin-relay-rate-limit + metrics → 22 passed
- generic-node: candidate-intake-inbox + runtime-listener → 40 passed
- lint both packages: 0 errors

## Not done (intentional)
- Durable candidate queue
- Relay authentication / new credentials

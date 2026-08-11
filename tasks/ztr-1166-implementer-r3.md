# ZTR-1166 implementer r3 — CI freeze resync

## Head
- Branch: `ztr-1166-dead-code`
- PR: #91
- HEAD_SHA: `de6d76885842ab0562d4dc35cf4deaca177812cc`

## Problem
Dual A+B had PASSed at `d0098202`, but Contracts CI failed on freeze drift
introduced by dead-code removal:
- `FROZEN_EXEMPTION_COUNT` / live markers: 206≠207 (pre-rebase) → after
  rebase onto main (admin in SCAN_SCOPE): live 238 vs frozen 239
- `FROZEN_SUPPRESSED_VIOLATION_COUNT`: live 219 vs frozen 220
- `coupling-exceptions.manifest.json` still listed 4 security-headers
  markers; live file has 3 after deleting `isCheckoutFrameAllowed`

## Fix
1. Rebased `ztr-1166-dead-code` onto latest `origin/main` (`76170994`).
   Resolve modify/delete on `admin/src/lib/demo-data.ts` by keeping deletion
   (no remaining imports; main had no consumers either after ZTR-1167).
2. Regenerated freeze surface from live SCAN_SCOPE
   (`contracts` + `node-core` + `generic-node` + `admin`):
   - `FROZEN_EXEMPTION_COUNT = 238`
   - `FROZEN_SUPPRESSED_VIOLATION_COUNT = 219`
   - `coupling-exceptions.manifest.json` inline entries + frozenCount = 238
   - Only material delta vs main freeze: one fewer
     `packages/node-core/src/http/security-headers.ts` entry
     (`checkout:frozen structural vocabulary` for deleted helper).
3. Did **not** weaken scan-gate. Unmarked hits match main's preexisting
   scan-gate red (order/drain stems in money-schema-pack, safety-alerts,
   origin-relay-rate-limit, main.ts, receive-candidate-intake-step,
   shutdown-registry).

## Verification (local)
```
pnpm --filter @zucoins/generic-node-contracts exec vitest run \
  --config vitest.config.ts \
  src/scan/forbidden-terms.test.ts \
  src/scan/coupling-exceptions.manifest.test.ts
# → 30/30 pass
```

## Release
- Dual A+B VOID after this push (new head).
- Ticket → QA-Review for fresh dual.

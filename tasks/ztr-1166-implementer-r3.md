# ZTR-1166 implementer r3 — CI freeze resync

## Head
- Branch: `ztr-1166-dead-code`
- PR: https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/91
- Freeze-fix commit: `0a0e5fe2442b12590e51e1ccdbe84e2249bd9681` 
- PR head SHA: `07f480cde161c1bdbb5b13fb18285fa92a311bf6`

## Problem
Dual A+B PASSed at `d0098202`, but Contracts CI failed on freeze drift from dead-code removal:
- Live markers ≠ `FROZEN_EXEMPTION_COUNT`
- Live suppressed hits ≠ `FROZEN_SUPPRESSED_VIOLATION_COUNT`
- `coupling-exceptions.manifest.json` still listed 4× `security-headers.ts` markers; live file has 3 after deleting `isCheckoutFrameAllowed`

After rebase onto main (`76170994`), SCAN_SCOPE includes `apps/generic-node/admin/src` (ZTR-1167), so main freeze baseline is 239/220 — not the pre-rebase 207/205.

## Fix
1. Rebased `ztr-1166-dead-code` onto `origin/main` @ `76170994`.
   - modify/delete on `admin/src/lib/demo-data.ts`: kept deletion (no remaining imports).
2. Resynced freeze to live SCAN_SCOPE (contracts + node-core + generic-node + admin):
   - `FROZEN_EXEMPTION_COUNT = 238` (was 239)
   - `FROZEN_SUPPRESSED_VIOLATION_COUNT = 219` (was 220)
   - `coupling-exceptions.manifest.json` entries + `frozenCount` = 238
   - Material delta: one fewer `packages/node-core/src/http/security-headers.ts` entry
     (`checkout:frozen structural vocabulary` for deleted helper).
3. Did **not** weaken scan-gate. Unmarked hits match main's preexisting scan-gate red
   (order/drain stems in money-schema-pack, safety-alerts, origin-relay-rate-limit,
   main.ts, receive-candidate-intake-step, shutdown-registry).

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
- Ticket released → QA-Review for fresh dual.
- Claim run: `7be9a03f-0b91-473a-9701-dc8a6d855c38`

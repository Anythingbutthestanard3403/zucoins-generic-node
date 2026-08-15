# ZTR-1316 implementer r2 — CI product fail

- **PR:** https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/175
- **Branch:** `ztr-1316-landed-unacked`
- **Prior reviewed head:** `033e4937812c6a47feec58da3559c9318768f1ce`
- **Claim run:** `37052d7e-cdde-4844-bb56-d82ad5f5dc3a`
- **Lane:** `/Volumes/Ai Building/.zup-scratch/impl-ztr-1316-r2-033e4937`

## Defect
`generic-node-ui` `ApproveInboxPage.test.tsx` asserted `LIVE_RECOVERY_ACTIONS` length 9.
ZTR-1316 added live `CLOSE_LANDED_UNACKNOWLEDGED`, so the derived catalog is 10
(11 catalog − 1 reserved). CI: expected length 9 but got 10.

## Fix
Test now asserts the new kind is live and `toHaveLength(10)`. Recovery-card fixture
includes the new kind as an enabled button. Action itself unchanged.

## Verification
`pnpm --filter @zucoins/generic-node-ui test` — 56 files / 379 tests, including
`ApproveInboxPage.test.tsx` (11).

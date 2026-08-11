# ZTR-1165 implementer

- PR: https://github.com/Anythingbutthestanard3403/zucoins-generic-node/pull/60
- Head: `3c590d5158b9ae9bf41698f9de0d23b809bb3d28`
- Deleted `IMPLEMENTED_RECOVERY_ACTIONS`; inbox uses `partitionRecoveryActions` / `isLiveRecoveryAction`.
- LIVE derived from `OPERATOR_RECOVERY_ACTIONS − RESERVED`; store kinds from contract.
- New `@zucoins/generic-node-contracts/operator-halt` subpath + vitest aliases.
- SPA tests: 40/318 green; UI build ok; tsc -b clean; boundaries shell allowlist 71 green.
- Pre-existing main reds: forbidden-terms scan-gate, transaction-isolation census (not this diff).
- Detail: `tasks/ztr-1165-implementation.md`

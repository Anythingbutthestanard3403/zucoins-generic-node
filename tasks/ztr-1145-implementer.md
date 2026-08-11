# ZTR-1145 implementer

**Head SHA:** `927cb027c239d7b3f9f7865ca5f4d3d98cbf8967`
**Branch:** `ztr-1145-implementer-event-verifier`
**Governing:** doc 10 §7 (event may wake, never establish success); D9.16 (signed pull sole channel); A.6 dual continuity; `implementer-events/CONTRACT.md` byte-freeze; suite verify discipline (purpose before signature, key class).

## Acceptance

1. **Consumer-side verifier for `zp-implementer-event-v1` exported from `generic-node-consumer`** — SATISFIED
   - `authenticateImplementerEvent` in `@zucoins/node-core/verifier/consumer`
   - Re-exported from `@zucoins/generic-node-consumer`
   - Lower-level `verifyImplementerEvent` / checkpoint / keyrotation in `node-core/protocol/implementer-events`
2. **Byte-exact preimage, purpose before signature, key class** — SATISFIED
   - Rebuilds via `buildImplementerEventPreimage` (contracts); refuses non-canonical bytes
   - Purpose prefix checked before Ed25519
   - Key class fixed to `node_event`
3. **Rejects wrong purpose / key class / field order / whitespace / signature** — SATISFIED
   - `verify.test.ts` 12 tests
4. **`pipeline.test.ts` exercises purpose actually served** — SATISFIED
   - `makeEventWake` builds `zp-implementer-event-v1`
   - `ingestEventWake` calls `authenticateImplementerEvent`
5. **Gate: every route-served purpose has a consumer verifier** — SATISFIED
   - `route-purpose-verifiers.ts` + `route-purpose-verifier.gate.test.ts`
6. **`suite-tuples.contract.ts` deferred-c4 updated; census green** — SATISFIED
   - Disposition `frozen`; purposes + suite-tuples + negative-vectors + gen sync green (226)
7. **checkpoint + keyrotation assessed** — SATISFIED
   - Both verifiers ship (`verifyImplementerCheckpoint`, `verifyImplementerKeyRotation`)
   - Checkpoint is on GET /v1/events `checkpoints[]` and covered by the route gate
   - Keyrotation: byte-frozen + verifier; **no tenant route serves it yet** — deliberately omitted from `ROUTE_SERVED_PURPOSES` (not ticketed separately; gate documents the gap)

## Files

| Path | Why |
|---|---|
| `packages/node-core/src/protocol/implementer-events/*` | Byte-exact verifiers for event/checkpoint/keyrotation |
| `packages/node-core/src/verifier/consumer/verify.ts` | `authenticateImplementerEvent` |
| `packages/generic-node-consumer/src/pipeline.ts` | Wake path uses implementer verifier |
| `packages/generic-node-consumer/src/pipeline.test.ts` | Fixture purpose = served purpose |
| `packages/generic-node-consumer/src/route-purpose-verifiers.ts` | Served-purpose → verifier map |
| `packages/generic-node-consumer/src/route-purpose-verifier.gate.test.ts` | Gate against fiction |
| `packages/generic-node-contracts/.../purposes.contract.ts` | C4 discharged → frozen |
| `packages/generic-node-contracts/.../suite-tuples.contract.ts` | Disposition frozen |
| `gen/purposes.json` / `suite-tuples.json` / `negative-vectors.json` | Emit sync |

## Verification

```
pnpm install
tsc -b                                          # exit 0
pnpm --filter @zucoins/generic-node-contracts exec vitest run \
  src/machine-manifests src/implementer-events gen/json-sync.test.ts
  # → 14 files, 226 passed
pnpm --filter @zucoins/node-core exec vitest run \
  src/protocol/implementer-events/verify.test.ts \
  src/verifier/consumer/consumer.test.ts \
  test/protocol-suite-census.test.ts
  # → 12 + 36 + 8 passed
pnpm --filter @zucoins/generic-node-consumer test
  # → 11 files, 73 passed
pnpm --filter @zucoins/generic-node-contracts lint  # 0
pnpm --filter @zucoins/generic-node-consumer lint   # 0
pnpm --filter @zucoins/node-core lint
  # our paths clean; 1 pre-existing error in workers/leadership.ts (no-useless-catch)
```

## Deferred

- `zp-implementer-keyrotation-v1` has no tenant route yet; verifier ships, route gate excludes it until a route is added.
- Overlap with ZTR-1146 (events stream delivery) intentionally not in scope.

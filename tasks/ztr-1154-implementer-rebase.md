# ZTR-1154 implementer rebase (PR #58)

- **lane:** implementer
- **run:** `8f71ce16-4b7d-499e-a700-c79cd30d042c`
- **prior dual-PASS head:** `e8ab9d1688af9f9acdfd99bc2c8ca70502a091ca`
- **product HEAD (verify tip):** `fa5718bf39d39dcbb9058874d6059897d5f35118`
- **base:** `origin/main` @ `f154bebb523e8d9226dbb3e6fb5f4668d2874f0d`
- **PR:** #58 (`ztr-1154-push-envelope-golden`)
- **worktree:** `/Volumes/Ai Building/.zup-scratch/ztr-1154-rebase-w9`

## Why

Merge to main was CONFLICTING after parallel merges (#60/#59/#61 etc.). Rebased three
product commits onto latest `origin/main` (no merge commit). Dual must re-run — rebase voids prior dual.

## Commits after rebase

```
fa5718b docs(tasks): ZTR-1154 r2 implementer note (Review B rework)
24f3afc fix(push): honest golden supersession + pageable no_transfer_code alert (ZTR-1154 r2)
a169e67 fix(push): pin delivered envelope golden and alert on no_transfer_code run (ZTR-1154)
```

Plus this docs-only note commit on the branch tip.

## Conflicts (commit 1/3 only: cbd9453 → a169e67)

All three files: keep **both** main VAPID (ZTR-1161) and PR push-receive (ZTR-1154).

| File | Resolution |
|------|------------|
| `packages/node-core/src/core/metrics.ts` | Both metric families: `METRIC_PUSH_VAPID_*` + `METRIC_PUSH_RECEIVE_*` / shapes; `pushVapid` + `pushReceiveTotal` + `pushNoTransferCodeStreak` on registry/create/reset/render; hooks `onPushVapid` + `onPushReceive` + `setPushNoTransferCodeStreak`. |
| `packages/node-core/src/push/receiver.ts` | Deps keep VAPID fields (`nodeOrigin`, `vapidMode`, `onVapidOutcome`) **and** `metrics?: PushReceiveMetrics`. Body already had both paths post-merge. |
| `apps/generic-node/src/push/compose.ts` | `createPushReceiver` gets VAPID wiring + `metrics: pushReceiveMetrics`. |

Commits 2–3 (r2 + docs note) applied cleanly.

## Product work preserved

- goldens/push `delivered-envelope.data.v1` + meta + provenance records/digest pins
- `SAFETY_ALERT_SIGNALS` / rules / thresholds `push_no_transfer_code_streak`
- Prom rules + ops docs + compose → `safetyAlertEvaluator`
- `createPushReceiveMetricsPort` **observe-then-set** order (streak before sink)
- main.ts: `metricsHooks` + `safetyAlertEvaluator: custodyAlertEvaluator` + VAPID `onPushVapid`

## Local verify (PASS)

```
safety-alerts.test.ts                         44 PASS
metrics.test.ts                               17 PASS
push-payload-and-seal.test.ts                 39 PASS
fixture-provenance registry+verify            12+17 PASS
push-no-transfer-code-streak.alert.test.ts     2 PASS
operator-docs.census.test.ts                  35 PASS
tsc -b node-core + contracts + generic-node    exit 0
```

**Total focused:** 166/166 PASS @ `fa5718bf39d39dcbb9058874d6059897d5f35118`

## Push

`git push --force-with-lease origin ztr-1154-push-envelope-golden` (rebased e8ab9d1 → fa5718b + note)

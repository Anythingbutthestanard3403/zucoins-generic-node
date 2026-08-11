# Push action-name suffix rotation

Policy ticket: **ZTR-1207**. Detection and classification: **ZTR-1152**.

## Policy (decide once)

| Choice | Status |
| --- | --- |
| **Runbook-only recovery** — re-transcribe the four suffixed literals from the current wallet bundle after a host rotation | **Adopted** |
| Client-side suffix-derivation helper | **Banned** (ZTR-1152 — suffixes are opaque; there is no derivation rule) |
| Host vocabulary discovery / handshake endpoint ("Option A") | **Deferred** — adopt only if/when the wallet host offers one; do not invent a client |

Recovery is a manual code change in a reviewed PR. That is intentional and consistent with
the no-derivation rule.

## What the suffixes are

The push host (`wallet.zucoins.com` push API) dispatches on **exact** action-name strings.
Each name ends in a ten-character opaque token (e.g. `__jxqlqcj5zv`). The token is part of
the name, not a version qualifier. Live probe 2026-08-08 (ZTR-1152):

- bare `__v1` form → HTTP 200 + `status:false` + unsupported-action envelope
- correct suffixed form → routed domain answer

The four literals currently pinned (wallet **200.6**):

| Role | Literal | Wallet source (200.6) |
| --- | --- | --- |
| subscribe | `push_notification__subscribe__v1__tos2d5b5md` | `app.js:4841` |
| has_subscription | `push_notification__has_subscription_for_public_key_base64urlsafe__v1__jxqlqcj5zv` | `main.js:8866` |
| send_to_public_key (unused vocabulary) | `push_notification__send_to_public_key_base64urlsafe__v1__jc34lsh7ps` | `main.js:8925` |
| get_app_server_public_key | `push_notification__get_app_server_public_key__v1__nozleh4wul` | `app.js:4222` |

`send_to_public_key` has zero production callers; it stays in the read-safe union so the
union remains the complete gateway vocabulary minus submit.

## Probe-failure signature

Boot runs one smoke call after gateway-read readiness (`probePushActionVocabulary` →
`hasSubscriptionForPublicKey` with a fixed zero-key probe). Wiring:

- `apps/generic-node/src/main.ts` — gateway-read region calls `push.probeActionVocabulary()`
- `apps/generic-node/src/push/compose.ts` — binds the probe onto the push surface
- `apps/generic-node/src/push/gateway-actions.ts` — `probePushActionVocabulary`,
  `PushActionVocabularyRejectedError`, `isActionVocabularyRejection`

### Vocabulary drift (action required)

| Field | Value |
| --- | --- |
| Error class | `PushActionVocabularyRejectedError` |
| `error.code` | `push_action_vocabulary_rejected` |
| Typical log / message | `push action <name> is not in the push host's dispatch vocabulary (code=…) — wallet-release action-name drift, not an outage; re-transcribe the suffixed literals from the current wallet bundle` |
| Host HTTP | **200** (not a transport failure) |
| Host envelope | `status: false`, message containing `Unsupported "action_name"`, observed `code` often `oysinkh3cy` |
| Retry | None — rejection is deterministic; the call path does not burn attempts |
| Boot effect | Probe **throws** → boot fails closed on vocabulary drift |

Do **not** treat this as network outage, TLS, or push-host downtime.

### Plain unavailability (not this runbook)

If the probe cannot reach the host, it **logs and returns** — availability has never gated
boot. Expect log text like:

`push: action-vocabulary probe could not reach the push host — proceeding (availability, not vocabulary)`

Boot reconcile and the periodic push pass repair outages later. That path is
`PushGatewayUnavailableError` / transport errors, not vocabulary rejection.

### Classification note (host envelope `code`)

Host error-envelope `code` values (`oysinkh3cy`, and related tokens such as `ehmqh23o7m`)
look like opaque tokens themselves and may rotate. Classification in
`isActionVocabularyRejection` is **message-primary**
(`message` includes `Unsupported "action_name"`) with the observed code as a **secondary**
signal. If the host ever publishes stable codes, flip classification to code-primary in the
same reviewed change that updates the fixtures — do not invent stability.

## Literal locations (update all of these)

Primary pins (must match byte-for-byte):

1. **`packages/node-core/src/gateway/actions.ts`** — `READ_SAFE_ACTION_NAMES` (type-level
   vocabulary + `assertReadSafeActionName` backstop). Comments cite wallet line numbers.
2. **`apps/generic-node/src/push/gateway-actions.ts`** — three live `call("…")` sites:
   subscribe, has_subscription, get_app_server_public_key. (send_to is not called.)

Tests and comments that pin the same strings (update in the same PR so CI stays green):

3. `packages/node-core/src/gateway/separation.test.ts` — asserts the four literals in the union
4. `apps/generic-node/src/push/gateway-actions.test.ts` — wire-shape and vocabulary-rejection tests
5. Ancillary citations (comments / schema docs only — not dispatch):  
   `packages/node-core/src/push/base64-tolerant.ts`,  
   `packages/node-core/src/push/id-proof.ts`,  
   `packages/node-core/src/schema/push-subscriptions.sql`

Grep after editing:

```bash
rg -n 'push_notification__' packages/node-core apps/generic-node --glob '!node_modules'
```

Every hit must show the **new** suffixes (or a deliberate historical citation in this
runbook / a ticket note).

## Recovery steps (manual transcription)

1. **Confirm vocabulary drift**, not outage.  
   Boot or a push call throws `PushActionVocabularyRejectedError` /
   `code=push_action_vocabulary_rejected`. Host returned HTTP 200 with
   `Unsupported "action_name"` (see signature above).

2. **Obtain the current wallet bundle** the host is serving (same release operators and
   end-users hit). Prefer the deployed static assets for that release, not an older checkout.

3. **Locate the four action-name string literals** in the bundle (search the bare stems
   `push_notification__subscribe`,  
   `push_notification__has_subscription_for_public_key_base64urlsafe`,  
   `push_notification__send_to_public_key_base64urlsafe`,  
   `push_notification__get_app_server_public_key`).  
   Copy each **full** string including the `__v1__…` suffix **verbatim**. Do not trim,
   lowercase, or re-encode. Do not invent a suffix from a hash or timestamp.

4. **Patch the primary pins** (items 1–2 above) and refresh wallet line citations in
   comments if the bundle paths/lines moved.

5. **Update tests** (items 3–4) so they expect the new literals and still assert
   vocabulary-rejection behaviour on a deliberately wrong name.

6. **Open a normal reviewed PR.** No money-path behaviour change beyond the action-name
   strings. Land, deploy, confirm boot log:
   `push: action-vocabulary probe accepted by the push host`.

7. **Do not** add a derivation helper, scrape algorithm, or guessed suffix. If transcription
   is unclear, stop and escalate — wrong names fail closed at the next probe, but a clever
   wrong guess is still a failed deploy cycle.

## Future: host discovery endpoint (out of scope)

If the wallet host later exposes a vocabulary discovery or handshake endpoint, evaluate
adopting it under a new ticket. Requirements for that path (not built here):

- Host-documented, stable contract — not reverse-engineered from errors
- Still no client-side derivation of suffixes from other material
- Boot probe remains fail-closed until the discovered names are persisted/reviewed per
  whatever change-control that ticket defines

Until that exists, **this runbook is the only recovery path**.

## Related

- ZTR-1152 — suffix transcription, vocabulary rejection class, boot probe (Option B)
- ZTR-1153 — related push follow-ups
- ZTR-1154 / ops README "Push delivered-envelope shape" — inbound Web Push payload shape
  (different failure mode: 204 discard + streak alert, not action-name dispatch)
- `docs/operations/README.md` — index link under push ops

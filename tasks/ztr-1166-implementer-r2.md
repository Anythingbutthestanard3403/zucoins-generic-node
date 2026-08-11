# ZTR-1166 — implementer rework r2

**PR:** #91  
**Branch:** `ztr-1166-dead-code`  
**Claim run:** `7be9a03f-0b91-473a-9701-dc8a6d855c38`  
**Clears:** Review B FAIL at `2d52335f` (D1 dual Cache-Control keys; D2 admin-spa CSP case)

## Root cause

`computeSecurityHeaders("admin")` emits Title-Case `Cache-Control: no-store`.  
`tryServeAdminSpa` spread that bag then set lowercase `"cache-control"` for SPA policy.  
JS object keys are case-sensitive → both keys coexist → Node serializes two wire lines → clients join to `no-store, no-cache` / `no-store, public, …`.

## Fix

- `lowerHeaderBag()` collapses security headers to lowercase keys before SPA overrides.
- Single `cache-control` key: assets `public, max-age=31536000, immutable`; HTML/SW/manifest `no-cache` (no `no-store` prefix).
- Exported constants `ADMIN_SPA_ASSET_CACHE_CONTROL` / `ADMIN_SPA_SHELL_CACHE_CONTROL`.
- Tests: case-aware header getters; exact one-key assertions; Node `ServerResponse` wire-block sink that reproduces dual-line D1 and asserts production emits exactly one Cache-Control line.

## Verify

```
vitest run --config apps/generic-node/vitest.config.ts apps/generic-node/src/admin-spa.test.ts
→ 7 passed
```

## Head

See git tip after push (this file committed with the fix).

**Head SHA:** `60cd36e9a688212880dc01dd951fa650c063aa66`

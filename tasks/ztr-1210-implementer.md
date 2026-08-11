# ZTR-1210 implementer handoff

**PR:** (filled after create)
**HEAD:** 0009e5754a278a4604fc38aa7da450d5038adfe4
**run:** 464608e3-b1e9-4609-847b-24f001a5c572

## What landed

Shared `resolveAdminLockoutIp` in `apps/generic-node/src/admin-router.ts`:

- Default (no/blank `TRUST_PROXY_HOPS`): socket peer via `ipForDb(remoteAddress)` — never XFF.
- Proxied (non-empty `TRUST_PROXY_HOPS`): `trustProxyOptionsFromEnv` + `resolveClientIp` with `directExposure: true` so missing XFF falls back to socket peer.

Wired on both:

- `POST /admin/v1/login`
- `POST /admin/v1/confirm-totp`

## Tests

`apps/generic-node/test/admin-lockout-ip-unification.test.ts` (7):

1. helper ignores XFF when proxy trust off
2. helper null without socket when proxy trust off
3. helper peels trusted XFF hop when TRUST_PROXY_HOPS set
4. helper socket fallback when XFF missing under proxy trust
5. both routes share (socket, username) pair; confirm sees login lock; login sees confirm lock; spoofed XFF not a key
6. XFF spoof does not reset login lockout (ZTR-1192 preserved)
7. TRUST_PROXY_HOPS keys both routes on trusted hop

## Verify at HEAD

- `tsc -b` clean
- generic-node lint clean
- new test file 7/7 pass
- node-core lockout-related 61/61 pass (admin-auth-abuse, admin-totp-enrol, login-rate-limit, transport-proxy-ssrf)

## Not done

- Schema/`.env.example` registration of TRUST_PROXY_* (ZTR-1166 remainder)
- Durable multi-replica lockout (pre-existing in-memory ceiling)

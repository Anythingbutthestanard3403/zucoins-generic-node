# credential-matrix — CONTRACT

Freeze slice: **the credential-error matrix** (depends on the auth-errors and route-policy
concerns). Gate: `CONTRACT_FREEZE`.

## Scope boundary (read first)

The matrix exercises every credential state against every scope and tenant, compares response
bytes and timing class, and proves no protected mutation or enumeration. There is **no runtime
server** in this CONTRACT_FREEZE group, so the matrix is **contract-level**: every cell's response
is reconstructed from the auth-errors frozen bodies and the route-policy route policy, not observed
on a live wire. The "timing class" is modelled structurally as the pipeline stage at which each
state short-circuits — a guarantee that is both deterministic and stronger than a flaky wall-clock
measurement. Exercising the matrix against a running server is a later (post-freeze) acceptance
run; this slice freezes the matrix and the contract-level proofs.

Governing spec: the API contract — wire conventions and authentication classes; canonical
`non-oracular-auth-errors`.

## What is frozen / proven

`matrix.ts` builds the full matrix = **3 frozen auth classes × representative routes × 8 failure
states** (40 cells), each reconstructed from the frozen contracts. `gen/credential-matrix.json` is
the committed snapshot of the full credential/error response matrix.
`manifest.freeze.test.ts` consumes the auth-errors `indistinguishable`/`isNonOracular` and the
route-policy `firstOracularRoute`/`isRoutePolicyNonOracular` to prove, across the matrix:

- **Credential + scope collapse.** Missing, malformed, unknown, expired, revoked, and out-of-scope
  all produce one byte-identical `401` body (equal to the auth-errors frozen
  `CANONICAL_AUTH_FAILURE_BODY` modulo request_id) — no key-existence or scope oracle.
- **Tenant collapse.** Absent and cross-tenant objects produce one byte-identical `404` body
  (`CANONICAL_NOT_FOUND_BODY`) — no cross-tenant existence oracle.
- **No 403 anywhere** in the matrix; every cell uses an auth-errors canonical code.
- **No protected mutation or enumeration.** Every failure cell resolves before the `handler` stage
  (`reachesHandler === false`), so no failing request mutates state or enumerates an object — proven
  on a real mutation route (`POST /v1/receives`, `POST /v1/operations/:id/armed`).
- **Timing class.** Every credential/scope cell resolves at a pipeline stage strictly before object
  resolution, so its timing is independent of object existence.
- **Centralization.** A class+state response is identical across that class's representative routes.

## Mandatory negatives (one per matrix dimension)

- **credential** — a `401` body whose message leaks "unknown" is caught by `isNonOracular`.
- **scope** — an out-of-scope `403` is caught by `indistinguishable`.
- **tenant** — a cross-tenant `403 wrong_tenant` is caught by `indistinguishable`.
- **mutation/enumeration** — a failure cell that reaches the handler is caught by the no-handler
  predicate.

The first three are demonstrated to fire: breaking the auth-errors verifier turns those three red,
while the self-contained mutation negative stays green.

## Deferred

A live-server acceptance run of the same matrix (real bytes and real wall-clock timing class) is a
post-freeze implementation/acceptance slice; the wider error surface and the package
index/registry are outside this concern.

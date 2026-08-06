# Vault concern — CONTRACT_FREEZE — CUSTODY-SENSITIVE

The wallet-vault **architecture decision record**. Governing rule: `vault-storage-model` (the
operative guard set plus the dual-run addendum, canonical). Governing spec: the data model: vault
table; signing-custody: vault; the `single-blob-vault-precursor`, `vault-column-names`,
`secure-buffer`, and `sealed-store` rules. Gate: contract/ADR freeze only — **no runtime vault, no
key material, no DB code, no crypto operations, no ZKZ.** The key-custody rule (platform zero key
custody) is never conceded.

## What vault.1 freezes (architecture only)

Per the custody dual-run synthesis, this layer freezes the **architecture-level ADR** and
explicitly disowns byte/schema/runtime subcontracts (see `DEFERRED_SUBCONTRACTS`). It invents
no cryptographic byte layout.

- **`storage.contract.ts`** — the resolved grain (`PER_WALLET_ENVELOPE_ROW` supersedes the
  `single-blob-vault-precursor` single blob for v2; that precursor stays canonical for v1; no
  hybrid, no shim), the `vault-column-names` frozen names (table `vault`, PK `wallet_id`, column
  `key_version`), the envelope logical structure (AES-256-GCM, 96-bit nonce, 128-bit tag,
  `UNIQUE(key_version, nonce)`, **no stored AAD column**), the required-model target, and the
  rejected draft descriptor.
- **`crypto.contract.ts`** — the key-hierarchy algorithm + parameter contract (PBKDF2-SHA256
  600k once at boot → root; HKDF-SHA256 root → per-wallet DEK binding node_id/wallet_id/
  key_version; AES-256-GCM seal of the 64-byte Ed25519 secret) as identifiers/params only, and
  the per-wallet key-isolation property. **No real key values, no salt/root bytes, no info-string
  encoding.**
- **`aad.contract.ts`** — the AAD binding: the **6-field input set** (domain `zp-wallet-secret-v1`,
  node_id, wallet_id, **key_version**, public_key, **key_origin**), reconstructed at open, never
  a stored column; the primary substitution control (decrypt → derive-pubkey → assert
  `== wallets.public_key`); and the superseded 4-field/stored-column draft. **Exact serialization
  is frozen in vault.2 below.**
- **`lifecycle.contract.ts`** — the crash-safe resumable rotation state machine, the signing
  concurrency invariants (no vault row lock across signing; C-02 lease is the sole wallet-sequencing
  authority; rotation quiesces signing and locks a canonical wallet-id sequence), and the recovery
  contract (`recovery_verified_at` per-wallet, monotonic, never cleared by rotation; key
  replacement never in-place — mint → move via blessed sink → retire).
- **`compatibility.contract.ts`** — the carried-forward `single-blob-vault-precursor` invariants,
  the **`key_version` semantics landmine** (v1 `key_version` is an append counter that must not bump
  on master rotation; v2 `key_version` is a per-row epoch that does bump per row — inverse
  semantics), the sealed-store census (wallet keys, node signing/event keys, TOTP, webhook secret —
  none on a shared-key/reused-nonce shortcut), the concrete zeroization discipline (libsodium secure
  `Uint8Array`, never a JS string; `sodium_memzero` post-sign; core dumps disabled; keys never
  logged), and the `DEFERRED_SUBCONTRACTS` boundary.
- **`vault-verifier.ts`** — pure conformance verifiers: `verifyVaultModelDescriptor` (rejects a
  model that is not per-wallet HKDF / fresh-nonce / reconstructed-AAD / crash-safe-rotation — it
  returns the full violation set for the rejected draft) and `verifySealedStore` (rejects a
  shared-key or reused-nonce shortcut).

## What vault.2 freezes (schema + interfaces + byte goldens)

Built on the vault.1 architecture; consumes its frozen facts, re-freezes none.

- **`vault-schema.contract.ts`** — the concrete `vault` columns (wallet_id PK, key_version,
  ciphertext, nonce, auth_tag, ciphertext_sha256, created_at, rotated_at), the CHECK/UNIQUE
  constraints (`key_version > 0`, `octet_length(nonce)=12`, `octet_length(auth_tag)=16`,
  `UNIQUE(key_version, nonce)`), and the explicit no-`aad_text`-column record.
- **`aad-serialization.ts`** — the **byte-exact** 6-field AAD encoding
  (`zp-wallet-secret-v1\n<node_id>\n<wallet_id>\n<key_version>\n<public_key>\n<key_origin>`),
  its `buildWalletSecretAad` constructor, and a synthetic obviously-fake golden with a pinned
  sha256. **STATUS: FROZEN** — the AAD/HKDF encoding decision (2026-07-19) confirmed this encoding
  exactly as frozen.
- **`hkdf-info.ts`** — the **byte-exact** HKDF info encoding, its `buildWalletDekInfo` constructor,
  and a pinned golden. The originally drafted form (`<node_id>\n<wallet_id>\n<key_version>`, no
  domain prefix — faithful to the `vault-storage-model` literal info fields) was AMENDED to carry
  its own domain label; see the encoding freeze section below. Same FROZEN status.
- **`interfaces.contract.ts`** — the sealing/signer API signature contracts (WalletSigningCapability,
  seal/open surface), the leadership rules (single-writer mutations, rotation sole all-envelope
  writer, no hybrid fallback), and the zeroization interface (secure `Uint8Array`, mandatory wipe).
- **`failure-behavior.ts`** — the frozen open-failure vocabulary and the pure fail-closed
  `classifyOpenOutcome` (any failing check yields a failure code, never OPEN_OK, never a fallback).

`compatibility.contract.ts` `DEFERRED_SUBCONTRACTS` records the **vault.1 ADR** boundary as it
stood; its `vault.2` items are now DELIVERED in the schema / serialization / interfaces / failure
blocks above (the `vault.3` items remain deferred).

## What vault.3 proves (threat model + verification matrix)

- **`threat-model.contract.ts`** — the frozen `THREAT_MATRIX`: 13 threat classes (envelope
  substitution cross-wallet/version/origin, key-smuggle via origin flip, AAD strip/reorder,
  stored-AAD downgrade, nonce reuse, truncated ciphertext, rotation crash window, restore-with-
  stale-vault, signing-during-rotation, key-disclosure via logs/dumps, stale-process-holds-key),
  each mapped to its mitigating control, the vault.1/.2 contract that supplies it, the
  `vault-storage-model` guard it belongs to, and its detection outcome.
- **`threat-verifier.ts`** — `assessThreat(threatId, controlEnabled)` reads the ACTUAL frozen
  vault.1/.2 contract values when the control is enabled, so weakening any control (e.g.
  flipping `stored_aad_column` true, dropping the `UNIQUE(key_version, nonce)` guard) makes its
  threat no longer caught and fails the tests; disabling a control lets the threat through
  (`NOT_CAUGHT`).
- Tests: the census freezes the matrix and asserts the **five-guard completeness** (every
  `vault-storage-model` guard mitigates at least one threat), and the verifier suite proves
  control-enabled → the frozen caught outcome and control-disabled → `NOT_CAUGHT` for every threat
  (the mandatory per-class negative).

Still runtime-side (no key material / no DB in this package): exact PBKDF2 salt/root byte
derivation, active `key_version` selection, the concrete rotation journal/cutover format, and
real-PostgreSQL rotation/restore execution tests.

## AAD / HKDF encoding freeze status — RESOLVED

The AAD/HKDF encoding decision (2026-07-19) has been absorbed:

- **AAD — CONFIRMED.** `aad-serialization.ts` `AAD_SERIALIZATION.status` = `FROZEN`, the
  6-field encoding unchanged.
- **HKDF info — AMENDED.** It now carries its own domain label:
  `zp-wallet-dek-v1\n<node_id>\n<wallet_id>\n<key_version>` (4 fields). Golden + pinned sha256
  regenerated, `buildWalletDekInfo` updated, status `FROZEN`. Rationale: under a shared
  root the distinct label is the only thing stopping two sealed stores deriving the same AES key
  (a vault-scoped `UNIQUE(key_version, nonce)` cannot catch a cross-store nonce collision).

Binding conditions from the rule, now frozen: `canonicalization.contract.ts` (per-field pins —
lowercase hyphenated UUIDs, minimal base-10 `key_version`, padded base64url `public_key` with no
`+/`, lowercase `key_origin`; AAD-source injectivity — every source field NOT NULL and LF-free so
the joined encoding is injective; the label<->field-set coupling — a field-set change requires a
new `-vN` label, never appended under an existing label); `hkdf-info.ts` `HKDF_PARAMS` (L=32, salt
never per-row, IKM = the PBKDF2 root) and `CROSS_STORE_LABEL_SEPARATION` (globally-unique label per
store; sibling stores' labels are their own sub-freezes and are not frozen here). The threat model
gains `CROSS_STORE_KEY_DERIVATION_COLLISION` (control: the distinct HKDF label; a shared-label
scenario is `NOT_CAUGHT`).

## Freeze status

The vault contract freeze is complete across vault.1 (architecture ADR), vault.2 (schema /
interfaces / byte goldens), and vault.3 (threat model / verification matrix). This document covers
all three.

## Flagged conflicts (draft vs canonical)

- An earlier data-model draft names the table `wallet_secrets` with `vault_key_version` and a
  stored `aad_text` column; an earlier signing-custody draft makes the AAD a 4-field newline
  string. `vault-storage-model` supersedes all three: table `vault`, column `key_version`, **no
  stored AAD column**, and a 6-field reconstructed AAD adding `key_version` and `key_origin`.
  This ADR freezes the canonical shape.

## Encoding tiers

1. `.contract.ts` `as const` sources — authority.
2. `gen/vault.json` (package `gen/`) — review-diff snapshot of `VAULT_CONTRACT`, never byte
   authority; `gen-sync.test.ts` asserts it equals a fresh emit; its sha256 is pinned in
   `VAULT_CONCERN_MANIFEST.goldenRefs` and cross-checked by `manifest.census.test.ts`.
3. No tier-3 raw digest-pinned byte artifact at the architecture layer: it freezes architecture, not
   a signed preimage — the genuine byte layouts (AAD serialization, HKDF info) live in the vault.2 /
   vault.3 blocks above.

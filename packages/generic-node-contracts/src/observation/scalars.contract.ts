/**
 * SOURCE: the data-model reference scalar domains and the amounts-grammar freeze
 * (canonical ZKZ balance domain).
 *
 * These are the scalar formats the raw observation record's fields carry. Only the regex
 * SOURCE string and any fixed length are frozen here; the data model is explicit that "database
 * insertion is not proof of valid Ed25519 material" — canonical decode/re-encode is the
 * verifier's job (record-verifier.ts checks format only, as the DB CHECK does).
 *
 * The `sha256_hex` / `padded_base64url_*` domains are shared scalar primitives; a later canonical
 * lane may freeze the same strings, deduped at the concern-manifest registry rollup. `zkz_balance_text` is OWNED by
 * the amounts concern / the amounts-grammar freeze and only REFERENCED here as the `b_amount` field domain.
 */

/** `sha256_hex` — lowercase hex digest. */
export const SHA256_HEX_PATTERN = "^[0-9a-f]{64}$" as const;

/** `padded_base64url_pubkey` — 43 base64url chars + one `=`. */
export const PADDED_BASE64URL_PUBKEY_PATTERN = "^[A-Za-z0-9_-]{43}=$" as const;
export const PADDED_BASE64URL_PUBKEY_LENGTH = 44 as const;

/** `padded_base64url_signature` — 86 base64url chars + `==`. */
export const PADDED_BASE64URL_SIGNATURE_PATTERN = "^[A-Za-z0-9_-]{86}==$" as const;
export const PADDED_BASE64URL_SIGNATURE_LENGTH = 88 as const;

/**
 * CANONICAL OVERRIDE (the amounts-grammar freeze): the observation record's `b_amount` is a role-relative absolute
 * BALANCE / post-state value, so it uses the balance domain — `0 <= amount < 1e8`, "0"
 * legal (a swept payer, genesis, and a landed payer partial are legitimately "0"). The v2
 * draft names this column `zkz_amount_text` with the UNBOUNDED regex
 * `^(0|[1-9][0-9]*)(\.[0-9]{1,32})?$`; the amounts-grammar freeze supersedes that with the bound-carrying
 * `zkz_balance_text` regex below (`[1-9][0-9]{0,7}` = at most 8 integer digits). Never the
 * strictly-positive `zkz_amount_positive_text` domain — that would reject the legal "0".
 */
export const ZKZ_BALANCE_TEXT_PATTERN = "^(0|[1-9][0-9]{0,7})(\\.[0-9]{1,32})?$" as const;

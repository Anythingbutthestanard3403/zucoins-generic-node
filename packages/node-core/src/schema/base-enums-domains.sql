-- Database-wide conventions: the reference scalar checks and the closed enumerations.
-- Frozen schema contract. This file is contract text: it is executed only
-- by the schema-apply phase against a live database; nothing in this package runs it.
-- Every invariant below is inventoried in base-enums-domains.contract.ts.
--
-- Scope: the database-wide foundation every table-bearing schema contract depends on  -
-- required extensions, the five reference scalar domains, and the full closed enumeration
-- set. Table definitions live in their own scoped contracts.

-- Required extensions:

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Reference scalar checks (verbatim, except the ZKZ amount pair below):

-- CANONICAL OVERRIDE. The draft carried a single unbounded `zkz_amount_text`
-- domain: it permits any number of integer digits and permits zero everywhere. The
-- canonical ZKZ amount contract is `< 100000000` (10^8, EXCLUSIVE) with at most 32
-- fractional digits, and enforcement is split by layer. v1 stored amounts as NUMERIC(40,32),
-- where the precision WAS the bound; v2 stores canonical decimal `text`, which carries
-- no bound of its own, so the bound has to live in the CHECK. Both predicates below are frozen
-- in packages/generic-node-contracts (`ZKZ_AMOUNT_CHECK_DOMAINS`) and are executed against a
-- live database by test/base-enums-domains.pg.test.ts. The superseded single domain is retired
-- and MUST NOT be attached to any column; pick by column role per
-- CONVENTIONS.md "ZKZ amount CHECK domains" / `ZKZ_CHECK_DOMAIN_BY_ROLE`.

-- Balance layer: 0 <= amount < 1e8. "0" is LEGAL - a swept payer, a genesis row, and a landed
-- payer partial are all legitimately "0" byte authority (the byte-exact signing rule).
CREATE DOMAIN zkz_balance_text AS text
  CHECK (VALUE ~ '^(0|[1-9][0-9]{0,7})(\.[0-9]{1,32})?$');

-- Operation layer: 0 < amount < 1e8, strictly positive. `VALUE::numeric > 0` is NUMERIC
-- positivity, deliberately not the string test `VALUE <> '0'`: '0.0', '0.00' and '0.' followed by
-- 32 zeros all satisfy the shared regex and are `<> '0'` AS STRINGS while being mathematically
-- zero. Only the numeric cast rejects them. A silently-zero per-operation amount is a money-path
-- defect, so this is a byte-exact-signing-adjacent guardrail, not a stylistic choice.
CREATE DOMAIN zkz_amount_positive_text AS text
  CHECK (VALUE ~ '^(0|[1-9][0-9]{0,7})(\.[0-9]{1,32})?$' AND VALUE::numeric > 0);

CREATE DOMAIN sha256_hex AS text
  CHECK (VALUE ~ '^[0-9a-f]{64}$');

CREATE DOMAIN padded_base64url_pubkey AS text
  CHECK (length(VALUE) = 44 AND VALUE ~ '^[A-Za-z0-9_-]{43}=$');

CREATE DOMAIN padded_base64url_signature AS text
  CHECK (length(VALUE) = 88 AND VALUE ~ '^[A-Za-z0-9_-]{86}==$');

-- Enumerations (verbatim, closed set):

CREATE TYPE operation_kind AS ENUM (
  'RECEIVE_EXTERNAL',
  'MOVE_INTERNAL',
  'SEND_EXTERNAL'
);

CREATE TYPE operation_status AS ENUM (
  'CREATED',
  'READY',
  'RECEIVE_LANDED',
  'INTERNAL_MOVE_LANDED',
  'APPROVED',
  'AWAITING_REDEMPTION',
  'EXTERNAL_SEND_LANDED',
  'EXPIRED',
  'REJECTED',
  'NEEDS_ATTENTION'
);

CREATE TYPE wallet_key_origin AS ENUM ('node_generated', 'imported');
CREATE TYPE wallet_state AS ENUM ('AVAILABLE', 'PINNED', 'QUARANTINED', 'RETIRED');
CREATE TYPE destination_state AS ENUM ('PENDING', 'BLESSED', 'RETIRED');
CREATE TYPE wallet_lease_role AS ENUM (
  'RECEIVE_WINDOW',
  'MOVE_SOURCE',
  'MOVE_DESTINATION',
  'SEND_SOURCE',
  'RECONCILIATION'
);
CREATE TYPE approval_method AS ENUM ('TOTP_ONLY', 'TOTP_AND_DEVICE', 'AUTO_POLICY');
CREATE TYPE approval_challenge_status AS ENUM ('ISSUED', 'CONSUMED', 'SUPERSEDED', 'EXPIRED');
CREATE TYPE external_formation_state AS ENUM (
  'NOT_REQUIRED',
  'APPROVAL_PENDING',
  'APPROVED_UNSIGNED',
  'SIGNING_CLAIMED',
  'PARTIAL_PERSISTED',
  'PARTIAL_DELIVERED'
);
CREATE TYPE observer_domain AS ENUM ('NODE', 'PLATFORM');
CREATE TYPE observation_parse_result AS ENUM (
  'VERIFIED_GENESIS',
  'VERIFIED_HEAD',
  'TRANSPORT_ERROR',
  'MALFORMED_ENVELOPE',
  'MALFORMED_TRANSACTION',
  'UNVERIFIED_SIGNATURE',
  'WALLET_ROLE_INVALID'
);
CREATE TYPE observation_relationship AS ENUM (
  'FIRST',
  'SUCCESSOR',
  'COMPLETE_PATH_SUCCESSOR',
  'DUPLICATE',
  'EQUIVALENT_STATE_DIFFERENT_ENVELOPE',
  'REGRESSION',
  'UNEXPLAINED_JUMP',
  'GENESIS_AFTER_HISTORY',
  'SIGNATURE_COLLISION',
  'NOT_APPLICABLE'
);
CREATE TYPE verification_verdict AS ENUM (
  'PENDING',
  'VERIFIED',
  'REJECTED',
  'INDETERMINATE'
);

CREATE TYPE lineage_proof_verdict AS ENUM (
  'LANDED_EXACT',
  'LANDED_COMPLETE_PATH',
  'INDETERMINATE',
  'INVARIANT_BREACH'
);
CREATE TYPE reporting_key_state AS ENUM (
  'PENDING',
  'ACTIVE',
  'RETIRED',
  'REVOKED'
);
CREATE TYPE reporting_key_lifecycle_event_type AS ENUM (
  'FIRST_KEY_ACTIVATED',
  'KEY_ROTATED',
  'PRIOR_KEY_RETIRED',
  'KEY_REVOKED',
  'AUTH_HOLD_SET',
  'AUTH_HOLD_RELEASED'
);
CREATE TYPE reporting_request_class AS ENUM ('READ', 'MUTATION');

CREATE FUNCTION reporting_logical_fingerprint(
  p_method text,
  p_raw_target text,
  p_body_sha256 sha256_hex
) RETURNS sha256_hex
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
  SELECT encode(
    digest(
      convert_to(
        'm' || octet_length(p_method)::text || ':' || p_method ||
        't' || octet_length(p_raw_target)::text || ':' || p_raw_target ||
        'b64:' || p_body_sha256::text,
        'UTF8'
      ),
      'sha256'
    ),
    'hex'
  )::sha256_hex
$$;

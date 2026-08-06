-- The implementer_reporting_keys and node_signing_keys signing-key registries, plus the
-- padded_base64url_pubkey reference domain (re-declared for self-containment). The gate-default
-- anti-pattern, applied by exclusion -- registered_at / activated_at are event timestamps, not
-- recovery gates, and they get NO default; none is added).
-- Frozen schema contract, stacked on the root-registry slice which declares the
-- nodes + implementers root registries these tables reference. This file is contract text: it is
-- executed only by the schema-apply phase against a live database; nothing in this package runs it.
-- Every invariant below is inventoried in signing-key-registry.contract.ts.
--
-- Scope: implementer_reporting_keys and node_signing_keys ONLY. The nodes and
-- implementers root registries live in node-implementer-registry.sql and are NOT
-- re-created here; the reference targets nodes(id) / implementers(id) come from that base.
--
-- PREREQUISITE-BOUND: applied alone into an empty schema this slice fails on the missing nodes
-- relation (the first reference target), exactly like event-ledger.sql. migration-integrity.test.ts
-- classifies it {applies:false, missingRelation:"nodes"}; the real-Postgres behavioural proof in
-- signing-key-registry.pg.test.ts layers it on the root-registry base first.
--
-- vault_secret_ref: a bare uuid reference resolved only inside the node vault (
-- "vault_secret_ref resolves only inside the node vault for node-owned signing keys; no platform
-- table has an equivalent private-key reference"). It carries NO foreign key and stores NO key
-- material; only public keys and this opaque reference appear in these relational tables.

-- Reference scalar domain (verbatim; the one domain both tables use), re-declared so this
-- slice materialises its own type when applied standalone -- mirrors the node-implementer-registry
-- / proof-body-store / custody-eligibility self-containment pattern:

CREATE DOMAIN padded_base64url_pubkey AS text
  CHECK (length(VALUE) = 44 AND VALUE ~ '^[A-Za-z0-9_-]{43}=$');

-- Implementer reporting-key identity registry (verbatim):

CREATE TABLE implementer_reporting_keys (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  implementer_id uuid NOT NULL REFERENCES implementers(id),
  public_key padded_base64url_pubkey NOT NULL,
  registered_at timestamptz NOT NULL,
  UNIQUE (node_id, implementer_id, public_key),
  UNIQUE (id, node_id, implementer_id),
  UNIQUE (id, node_id, implementer_id, registered_at)
);

-- Node signing-key registry (verbatim):

CREATE TABLE node_signing_keys (
  id uuid PRIMARY KEY,
  node_id uuid NOT NULL REFERENCES nodes(id),
  purpose text NOT NULL CHECK (purpose IN ('NODE_IDENTITY', 'EVENT_SIGNING')),
  public_key padded_base64url_pubkey NOT NULL,
  vault_secret_ref uuid NOT NULL UNIQUE,
  activated_at timestamptz NOT NULL,
  retired_at timestamptz,
  UNIQUE (node_id, purpose, public_key),
  CHECK (retired_at IS NULL OR retired_at >= activated_at)
);

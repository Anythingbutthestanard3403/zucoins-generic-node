-- The nodes and implementers root registries, plus the padded_base64url_pubkey reference
-- domain (re-declared for self-containment).
-- Frozen schema contract. This file is contract text: it is executed only
-- by the schema-apply phase against a live database; nothing in this package runs it. Every
-- invariant below is inventoried in node-implementer-registry.contract.ts.
--
-- Scope: the nodes and implementers root registries ONLY. The signing-key tables
-- (implementer_reporting_keys, node_signing_keys) live in signing-key-registry.sql.
--
-- PRIMARY KEY: transcribed VERBATIM -- bare `id uuid PRIMARY KEY`, the uniform id convention
-- used across the registries, custody and operations. Downstream operations(node_id REFERENCES nodes(id),
-- implementer_id REFERENCES implementers(id)) and receive_arms/verification tables FK
-- this `id` directly. No node_id/implementer_id surrogate PK is invented.
--
-- created_at DEFAULT now(): transcribed verbatim. A DEFAULT now() is forbidden
-- ONLY on a GATE column (the v1 grandfather pattern that silently nulled the recovery gate).
-- created_at here is a plain creation timestamp, not a gate, so the doc default stands. This
-- is deliberately unlike custody-eligibility.sql, which drops a gate timestamp's default.

-- Reference scalar domain (verbatim; the one domain nodes uses), re-declared so this
-- slice applies greenfield standalone -- mirrors the proof-body-store.sql / custody-eligibility.sql
-- self-containment pattern (each slice re-declares the domains and enums its tables reference):

CREATE DOMAIN padded_base64url_pubkey AS text
  CHECK (length(VALUE) = 44 AND VALUE ~ '^[A-Za-z0-9_-]{43}=$');

-- Nodes registry (verbatim):

CREATE TABLE nodes (
  id uuid PRIMARY KEY,
  display_name text NOT NULL,
  identity_public_key padded_base64url_pubkey NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  UNIQUE (identity_public_key),
  CHECK (retired_at IS NULL OR retired_at >= created_at)
);

-- Implementers registry (verbatim):

CREATE TABLE implementers (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz
);

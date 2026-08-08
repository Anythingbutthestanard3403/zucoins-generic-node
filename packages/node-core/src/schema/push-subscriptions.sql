-- Push subscriptions. SplitChain push is the primary detection channel and every wallet
-- pubkey subscribed via push_notification__subscribe__v1__tos2d5b5md to a node-controlled Web Push
-- pubkey is subscribed. Web Push/VAPID is keyed per wallet pubkey: there is NO node-wide
-- VAPID keypair, only a fresh P-256 ECDH keypair plus a 16-byte auth secret per wallet,
-- encrypted at rest under the vault master key. The URL carries an opaque >=128-bit
-- endpoint token, never the pubkey. The app-server public key is cached.
--
-- Frozen schema contract. This file is contract text: it is executed only by the schema
-- phase against a live database; nothing in this package runs it.
--
-- Operating rule: an EXTERNAL receive or send requires an ACTIVE subscription;
-- INTERNAL transfers (both wallets node-controlled) do not. The gate is enforced in
-- application code (push/subscription-service.ts requireActiveSubscription) rather than
-- by a constraint here, because the same wallet row serves both classes of operation.

-- Reference scalar checks (re-declared for self-contained contract text; the pack
-- de-duplicates against base-enums-domains.sql on combined application):

CREATE DOMAIN padded_base64url_pubkey AS text
  CHECK (length(VALUE) = 44 AND VALUE ~ '^[A-Za-z0-9_-]{43}=$');

-- One Web Push subscription per wallet. The private ECDH half and the auth secret are
-- sealed envelopes (vault root, same seal the wallet secrets use); no plaintext key
-- material is ever stored in this table and no read path returns the sealed text outside
-- the vault seam.
--
-- `status` starts FAILED on insert and only becomes ACTIVE once the push service has
-- acknowledged the subscribe. That ordering is deliberate: a crash between INSERT and the
-- gateway ack must never leave a row asserting a remote subscription that does not exist,
-- because the external-operation gate trusts this column.
CREATE TABLE push_subscriptions (
  wallet_id uuid PRIMARY KEY REFERENCES wallets(id),
  node_id uuid NOT NULL,
  wallet_public_key padded_base64url_pubkey NOT NULL,

  -- Opaque unguessable token; this, not the pubkey, is what appears in the URL
  -- handed to the third-party push service.
  endpoint_id text NOT NULL CHECK (endpoint_id ~ '^wp_[A-Za-z0-9_-]{20,64}$'),

  -- Non-secret: the subscription's `p256dh` value, published to the push service.
  receiver_ecdh_public text NOT NULL,

  -- AES-GCM sealed under the vault root. Opaque envelope text.
  receiver_ecdh_private_sealed text NOT NULL,
  receiver_auth_secret_sealed text NOT NULL,

  status text NOT NULL CHECK (status IN ('ACTIVE','FAILED')),

  -- Cached `key_public__base64urlsafenopad` from the push app server. Base64 but
  -- NOT strictly urlsafe despite the field name — decode tolerantly, so no domain here.
  app_server_public_key text,

  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  -- Set only on a successful subscribe; NULL means "never yet acknowledged".
  subscribed_at timestamptz,

  CHECK ((status = 'ACTIVE') = (subscribed_at IS NOT NULL)),
  UNIQUE (wallet_id, node_id)
);

-- The inbound receiver resolves an endpoint token to its subscription on every delivery,
-- so this lookup is on the hot path. Unique because two wallets sharing a token would
-- make the inbound decrypt ambiguous.
CREATE UNIQUE INDEX push_subscriptions_by_endpoint
  ON push_subscriptions (endpoint_id);

-- The boot reconcile and the periodic sweep scan for wallets whose subscription is not
-- ACTIVE; this keeps that pass from degrading into a full table scan as the pool grows.
CREATE INDEX push_subscriptions_by_status
  ON push_subscriptions (node_id, status);

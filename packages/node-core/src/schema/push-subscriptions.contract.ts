// Push subscriptions: push is the primary detection channel; the push API base (
// Web Push per wallet pubkey), destination binding (per-wallet P-256 keypair + auth secret, encrypted at
// rest; no node-wide VAPID keypair), inbound push receivers (opaque >=128-bit endpoint token in the URL),
// (cached app-server public key).
//
// Frozen inventory of the structural invariants carried by push-subscriptions.sql. The
// census test binds every entry here to the literal SQL text, so the inventory and the
// schema contract cannot drift apart.

export const PUSH_SUBSCRIPTIONS_SCHEMA_FILE = "push-subscriptions.sql" as const;

export interface PushSubscriptionsInvariant {
  readonly id: string;
  readonly sqlAnchor: string;
  readonly rule: string;
}

export const PUSH_SUBSCRIPTIONS_INVARIANTS: readonly PushSubscriptionsInvariant[] = [
  {
    id: "PUSH_ONE_PER_WALLET",
    sqlAnchor: "wallet_id uuid PRIMARY KEY REFERENCES wallets(id),",
    rule: "exactly one subscription per wallet, and the wallet must exist (every wallet pubkey is subscribed).",
  },
  {
    id: "PUSH_NODE_SCOPED",
    sqlAnchor: "node_id uuid NOT NULL,",
    rule: "every row is node-scoped; a node never reads or mutates another node's subscriptions even when they share a database.",
  },
  {
    id: "PUSH_ENDPOINT_TOKEN_SHAPE",
    sqlAnchor: "endpoint_id text NOT NULL CHECK (endpoint_id ~ '^wp_[A-Za-z0-9_-]{20,64}$'),",
    rule: "The URL carries an opaque unguessable token, never the wallet pubkey. The shape check rejects a short or traversal-shaped token before it can address a row.",
  },
  {
    id: "PUSH_ENDPOINT_UNIQUE",
    sqlAnchor: "CREATE UNIQUE INDEX push_subscriptions_by_endpoint\n  ON push_subscriptions (endpoint_id);",
    rule: "an endpoint token resolves to at most one subscription: two wallets sharing a token would make the inbound decrypt ambiguous.",
  },
  {
    id: "PUSH_SECRETS_SEALED_ONLY",
    sqlAnchor: "receiver_ecdh_private_sealed text NOT NULL,",
    rule: "The ECDH private half is stored only as a sealed envelope under the vault root. No plaintext key material column exists on this table.",
  },
  {
    id: "PUSH_AUTH_SECRET_SEALED_ONLY",
    sqlAnchor: "receiver_auth_secret_sealed text NOT NULL,",
    rule: "the RFC 8291 auth secret is likewise sealed-only; its sole at-rest copy is this column.",
  },
  {
    id: "PUSH_STATUS_CLOSED_SET",
    sqlAnchor: "status text NOT NULL CHECK (status IN ('ACTIVE','FAILED')),",
    rule: "two states only. ACTIVE is what the external-operation gate trusts, so a third ambiguous state must not be representable.",
  },
  {
    id: "PUSH_ACTIVE_IMPLIES_ACKNOWLEDGED",
    sqlAnchor: "CHECK ((status = 'ACTIVE') = (subscribed_at IS NOT NULL)),",
    rule: "ACTIVE and a recorded subscribe time are the same fact. A row cannot claim an active remote subscription without the timestamp proving the push service acknowledged it — the invariant that makes a crash between INSERT and ack fail closed.",
  },
];

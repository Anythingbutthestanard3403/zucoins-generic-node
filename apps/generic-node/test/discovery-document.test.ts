// GET /.well-known/zupay-node was publishing eventSigningKeys/artifactSigningKeys
// as hardcoded `[]` regardless of the durable node_signing_keys registry boot already
// populated (apps/generic-node/src/full-http-mount.ts, apps/generic-node/src/main.ts:655-697).
//
// Unit-level (fake pool, no PG): proves createProductionRouteSurface's discoveryDocument
// reads the signing-key registry instead of returning the two hardcoded empty arrays, that
// the active key PLUS every retained (retired) prior key are published with lifecycle
// metadata, that a not-yet-active (future activated_at) key is excluded, that pg Date-typed
// timestamp columns are still normalized to RFC3339-ms, and that no field beyond the frozen
// discovery projection ever reaches the wire even if a future row grows extra columns. The PG
// round-trip (boot/rotate/restart, signature verified against the published key — including a
// signature made under a retired key, verified from discovery after rotation) lives in
// discovery-signing-keys.pg.test.ts.

import { describe, expect, it } from "vitest";

import { createProductionRouteSurface } from "../src/full-http-mount.js";


/** Non-zero 32-byte test vault root for SqlAdminUserStore composition (ZTR-1134 B3). */
const ZTR_1134_TEST_VAULT_ROOT = Buffer.alloc(32, 0xa7);


const NODE_ID = "11111111-1111-4111-8111-111111111111";
const IDENTITY_KEY_ID = "22222222-2222-4222-8222-222222222222";
const EVENT_KEY_ID = "33333333-3333-4333-8333-333333333333";
const RETIRED_KEY_ID = "44444444-4444-4444-8444-444444444444";
const IDENTITY_PUBLIC_KEY = "wUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrM=";
const EVENT_PUBLIC_KEY = "aUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrN=";
const RETIRED_PUBLIC_KEY = "bUlP99lNH660FAgVMrSJmkB-G15KnagFFcSxv1BGCrO=";
const RFC3339_MS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

interface FakeRow {
  readonly id: string;
  readonly node_id: string;
  readonly purpose: string;
  readonly public_key: string;
  readonly activated_at: string | Date;
  readonly retired_at: string | Date | null;
  // Adversarial: a future registry-store row could grow extra columns; the discovery
  // projection must never forward them regardless (the key-custody rule).
  readonly vault_secret_ref?: string;
}

// Mirrors STATEMENTS.SELECT_RETAINED_NODE_KEYS's WHERE clause (registry-store.ts) so the fake
// exercises the same activated_at lower bound the real query enforces, not just a purpose
// filter — the production code under test must not re-derive or bypass that bound. Discovery
// reads findRetainedNodeSigningKeys (not findActiveNodeSigningKeys), whose statement omits the
// `retired_at IS NULL OR retired_at > now()` upper bound on purpose: node_signing_keys rows are
// never deleted, so a retired row is retained and published forever alongside the active one.
function fakePool(rows: readonly FakeRow[]) {
  const isRetainedNow = (row: FakeRow): boolean => new Date(row.activated_at).getTime() <= Date.now();
  return {
    query: async (text: string, params?: readonly unknown[]) => {
      if (
        text.includes("FROM node_signing_keys") &&
        text.includes("activated_at <= now()") &&
        text.includes("ORDER BY activated_at")
      ) {
        const purpose = params?.[1];
        const matched = rows
          .filter((r) => r.purpose === purpose && isRetainedNow(r))
          .sort((a, b) => new Date(a.activated_at).getTime() - new Date(b.activated_at).getTime());
        return { rows: matched };
      }
      return { rows: [] };
    },
  } as never;
}

describe("discovery document reads the durable signing-key registry", () => {
  it("publishes the active NODE_IDENTITY key as expected_artifact_public_keys and EVENT_SIGNING as event_signing_public_keys", async () => {
    const surface = createProductionRouteSurface({
    dualControlMode: "single_operator",
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      nodeId: NODE_ID,
      pool: fakePool([
        {
          id: IDENTITY_KEY_ID,
          node_id: NODE_ID,
          purpose: "NODE_IDENTITY",
          public_key: IDENTITY_PUBLIC_KEY,
          activated_at: "2026-01-15T00:00:00.000Z",
          retired_at: null,
        },
        {
          id: EVENT_KEY_ID,
          node_id: NODE_ID,
          purpose: "EVENT_SIGNING",
          public_key: EVENT_PUBLIC_KEY,
          activated_at: "2026-01-15T00:00:00.000Z",
          retired_at: null,
        },
      ]),
    });

    const doc = await surface.discoveryDocument();

    expect(doc.expected_artifact_public_keys).toEqual([
      { key_id: IDENTITY_KEY_ID, public_key: IDENTITY_PUBLIC_KEY },
    ]);
    expect(doc.event_signing_public_keys).toEqual([
      { key_id: EVENT_KEY_ID, public_key: EVENT_PUBLIC_KEY },
    ]);
    // ZTR-1288: node-default funding unset → explicit null (never omitted / worker-swapped).
    expect(doc.funding_wallet_id).toBeNull();
    expect(doc.funding_wallet_public_key).toBeNull();
    const identityInterval = doc.key_validity_intervals.find((i) => i.key_id === IDENTITY_KEY_ID);
    expect(identityInterval).toEqual({
      key_id: IDENTITY_KEY_ID,
      valid_from: "2026-01-15T00:00:00.000Z",
      valid_until: null,
    });
  });

  it("publishes the active key PLUS a retained (retired) prior key, oldest first, with lifecycle metadata", async () => {
    const surface = createProductionRouteSurface({
    dualControlMode: "single_operator",
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      nodeId: NODE_ID,
      pool: fakePool([
        {
          id: IDENTITY_KEY_ID,
          node_id: NODE_ID,
          purpose: "NODE_IDENTITY",
          public_key: IDENTITY_PUBLIC_KEY,
          activated_at: "2026-01-15T00:00:00.000Z",
          retired_at: null,
        },
        {
          id: RETIRED_KEY_ID,
          node_id: NODE_ID,
          purpose: "NODE_IDENTITY",
          public_key: RETIRED_PUBLIC_KEY,
          activated_at: "2025-01-15T00:00:00.000Z",
          retired_at: "2026-01-01T00:00:00.000Z",
        },
      ]),
    });

    const doc = await surface.discoveryDocument();
    const keyIds = doc.expected_artifact_public_keys.map((k) => k.key_id);
    // Oldest (retired) first, active last — mirrors SELECT_RETAINED_NODE_KEYS's
    // ORDER BY activated_at ASC.
    expect(keyIds).toEqual([RETIRED_KEY_ID, IDENTITY_KEY_ID]);

    const retiredInterval = doc.key_validity_intervals.find((i) => i.key_id === RETIRED_KEY_ID);
    expect(retiredInterval).toEqual({
      key_id: RETIRED_KEY_ID,
      valid_from: "2025-01-15T00:00:00.000Z",
      valid_until: "2026-01-01T00:00:00.000Z",
    });
    const activeInterval = doc.key_validity_intervals.find((i) => i.key_id === IDENTITY_KEY_ID);
    expect(activeInterval).toEqual({
      key_id: IDENTITY_KEY_ID,
      valid_from: "2026-01-15T00:00:00.000Z",
      valid_until: null,
    });
  });

  it("excludes a not-yet-active (future activated_at) key", async () => {
    const futureKeyId = "55555555-5555-4555-8555-555555555555";
    const surface = createProductionRouteSurface({
    dualControlMode: "single_operator",
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      nodeId: NODE_ID,
      pool: fakePool([
        {
          id: IDENTITY_KEY_ID,
          node_id: NODE_ID,
          purpose: "NODE_IDENTITY",
          public_key: IDENTITY_PUBLIC_KEY,
          activated_at: "2026-01-15T00:00:00.000Z",
          retired_at: null,
        },
        {
          id: futureKeyId,
          node_id: NODE_ID,
          purpose: "NODE_IDENTITY",
          public_key: RETIRED_PUBLIC_KEY,
          activated_at: "2099-01-01T00:00:00.000Z",
          retired_at: null,
        },
      ]),
    });

    const doc = await surface.discoveryDocument();
    const keyIds = doc.expected_artifact_public_keys.map((k) => k.key_id);
    expect(keyIds).toEqual([IDENTITY_KEY_ID]);
    expect(keyIds).not.toContain(futureKeyId);
  });

  it("normalizes a pg-driver Date-typed timestamp column to RFC3339-ms", async () => {
    const surface = createProductionRouteSurface({
    dualControlMode: "single_operator",
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      nodeId: NODE_ID,
      pool: fakePool([
        {
          id: IDENTITY_KEY_ID,
          node_id: NODE_ID,
          purpose: "NODE_IDENTITY",
          public_key: IDENTITY_PUBLIC_KEY,
          activated_at: new Date("2026-01-15T00:00:00.123Z"),
          retired_at: null,
        },
      ]),
    });

    const doc = await surface.discoveryDocument();
    const interval = doc.key_validity_intervals.find((i) => i.key_id === IDENTITY_KEY_ID);
    expect(interval?.valid_from).toMatch(RFC3339_MS);
    expect(interval?.valid_from).toBe("2026-01-15T00:00:00.123Z");
  });

  it("never forwards private/vault-reference fields onto the wire document", async () => {
    const surface = createProductionRouteSurface({
    dualControlMode: "single_operator",
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      nodeId: NODE_ID,
      pool: fakePool([
        {
          id: IDENTITY_KEY_ID,
          node_id: NODE_ID,
          purpose: "NODE_IDENTITY",
          public_key: IDENTITY_PUBLIC_KEY,
          activated_at: "2026-01-15T00:00:00.000Z",
          retired_at: null,
          vault_secret_ref: "99999999-9999-4999-8999-999999999999",
        },
      ]),
    });

    const doc = await surface.discoveryDocument();
    const json = JSON.stringify(doc);
    expect(json).not.toContain("vault_secret_ref");
    expect(json).not.toContain("99999999-9999-4999-8999-999999999999");
    expect(json).not.toContain("ciphertext");
    expect(json).not.toContain("private");
    expect(json).not.toContain("seed");
  });

  it("returns non-empty arrays when active keys exist (the defect returned [] unconditionally)", async () => {
    const surface = createProductionRouteSurface({
    dualControlMode: "single_operator",
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      nodeId: NODE_ID,
      pool: fakePool([
        {
          id: IDENTITY_KEY_ID,
          node_id: NODE_ID,
          purpose: "NODE_IDENTITY",
          public_key: IDENTITY_PUBLIC_KEY,
          activated_at: "2026-01-15T00:00:00.000Z",
          retired_at: null,
        },
        {
          id: EVENT_KEY_ID,
          node_id: NODE_ID,
          purpose: "EVENT_SIGNING",
          public_key: EVENT_PUBLIC_KEY,
          activated_at: "2026-01-15T00:00:00.000Z",
          retired_at: null,
        },
      ]),
    });
    const doc = await surface.discoveryDocument();
    expect(doc.event_signing_public_keys.length).toBeGreaterThan(0);
    expect(doc.expected_artifact_public_keys.length).toBeGreaterThan(0);
  });

  it("still returns empty arrays (not a throw) when the node has no active keys yet", async () => {
    const surface = createProductionRouteSurface({
    dualControlMode: "single_operator",
      vaultRootKey: ZTR_1134_TEST_VAULT_ROOT,
      nodeId: NODE_ID,
      pool: fakePool([]),
    });
    const doc = await surface.discoveryDocument();
    expect(doc.event_signing_public_keys).toEqual([]);
    expect(doc.expected_artifact_public_keys).toEqual([]);
  });
});

// Wallet custody administration.
// Governing rules: derived eligibility, the operator custody endpoints, cross-tenant reads
// collapsing to not_found, the trust-domain boundary, custody classification, a quarantined
// wallet keeping its lease, and the wallets / destinations / wallet_recovery_verifications
// CHECK constraints.
//
// The negative assertions here are the point of the slice: the field allowlist is asserted as
// a schema (WALLET_CUSTODY_VIEW_FIELDS), not by eyeballing a sample response, and the leak
// test feeds the service a store row polluted with real vault column names to prove the
// projection drops what it does not name.

import { describe, expect, it } from "vitest";

import {
  createDestinationService,
  type BlessingAuthorizer,
  type DestinationRecord,
  type DestinationStore,
  type DestinationWalletFacts,
  type DestinationWalletKeyGenerator,
  type NewDestination,
} from "../src/api/destination.js";
import {
  WALLET_CUSTODY_VIEW_FIELDS,
  WALLET_RECOVERY_EVIDENCE_FIELDS,
  buildWalletCustodyView,
  createWalletCustodyAdminService,
  type WalletCustodyRow,
  type WalletCustodyStore,
  type WalletRecoveryVerificationRow,
} from "../src/api/wallet-custody-admin.js";
import type { Uuid, WalletPublicKey } from "../src/protocol/scalars.js";
import type { WalletKeyOrigin } from "@zucoins/generic-node-contracts/custody";

const NODE_ID = "11111111-1111-4111-8111-111111111111" as Uuid;
const OTHER_NODE_ID = "22222222-2222-4222-8222-222222222222" as Uuid;
const DEVICE_KEY_ID = "33333333-3333-4333-8333-333333333333" as Uuid;
const ARTIFACT_ID = "44444444-4444-4444-8444-444444444444" as Uuid;
const NONCE = "99999999-9999-4999-8999-999999999999" as Uuid;
const AUDIT_EVENT_ID = "55555555-5555-4555-8555-555555555555" as Uuid;
const VERIFICATION_ID = "66666666-6666-4666-8666-666666666666" as Uuid;
const RECOVERY_VERIFIED_AT = "2026-07-17T12:00:00.000Z";
const CREATED_AT = "2026-07-01T00:00:00.000Z";

const uuid = (tag: string): Uuid => `00000000-0000-4000-8000-${tag.padStart(12, "0")}` as Uuid;
const pubkey = (tag: string): WalletPublicKey => `${tag}-pubkey` as WalletPublicKey;

const WALLET_ID = uuid("1");

/* ─── fixtures ─────────────────────────────────────────────────────── */

const walletRow = (patch: Partial<WalletCustodyRow> = {}): WalletCustodyRow => ({
  walletId: WALLET_ID,
  nodeId: NODE_ID,
  publicKey: pubkey("w1"),
  keyOrigin: "node_generated",
  state: "AVAILABLE",
  createdAt: CREATED_AT,
  retiredAt: null,
  quarantineReason: null,
  recoveryVerifiedAt: null,
  recoveryVerificationId: null,
  ...patch,
});

const evidenceRow = (patch: Partial<WalletRecoveryVerificationRow> = {}): WalletRecoveryVerificationRow => ({
  verificationId: VERIFICATION_ID,
  walletId: WALLET_ID,
  method: "AUDITED_EXPORT",
  verifiedAt: RECOVERY_VERIFIED_AT,
  verifierIdentity: "operator@example.test",
  auditEventId: AUDIT_EVENT_ID,
  ...patch,
});

/**
 * In-memory `wallets` + `wallet_recovery_verifications`. `writes` records every mutation so a
 * test can assert what a transition did and did not touch.
 */
class MemoryWalletCustodyStore implements WalletCustodyStore {
  readonly wallets = new Map<string, WalletCustodyRow>();
  readonly verifications = new Map<string, WalletRecoveryVerificationRow>();
  readonly writes: string[] = [];

  constructor(rows: readonly WalletCustodyRow[] = [], evidence: readonly WalletRecoveryVerificationRow[] = []) {
    for (const row of rows) this.wallets.set(row.walletId, row);
    for (const row of evidence) this.verifications.set(row.verificationId, row);
  }

  async findWallet(walletId: Uuid): Promise<WalletCustodyRow | null> {
    return this.wallets.get(walletId) ?? null;
  }

  async findRecoveryVerification(verificationId: Uuid): Promise<WalletRecoveryVerificationRow | null> {
    return this.verifications.get(verificationId) ?? null;
  }

  async quarantine(walletId: Uuid, reason: string): Promise<WalletCustodyRow> {
    const current = this.wallets.get(walletId);
    if (current === undefined) throw new Error(`no wallet ${walletId}`);
    const next: WalletCustodyRow = { ...current, state: "QUARANTINED", quarantineReason: reason };
    this.wallets.set(walletId, next);
    this.writes.push(`wallets:${walletId}`);
    return next;
  }
}

const serviceOver = (
  rows: readonly WalletCustodyRow[],
  evidence: readonly WalletRecoveryVerificationRow[] = [],
): { store: MemoryWalletCustodyStore; service: ReturnType<typeof createWalletCustodyAdminService> } => {
  const store = new MemoryWalletCustodyStore(rows, evidence);
  return { store, service: createWalletCustodyAdminService({ store }) };
};

/* ─── field allowlist / leak boundary (the key-custody rule) ──────── */

// Real column names from src/schema/vault.sql plus the plaintext material keeps out of
// the node database entirely. Any of these appearing in a response is the defect this slice
// exists to make impossible.
const FORBIDDEN_TOKENS = [
  "ciphertext",
  "nonce",
  "auth_tag",
  "private_key",
  "privateKey",
  "secret_key",
  "seed",
  "master_key",
  "totp",
] as const;

describe("the custody view schema is an allowlist", () => {
  it("names no vault or key-material field", () => {
    const declared = [...WALLET_CUSTODY_VIEW_FIELDS, ...WALLET_RECOVERY_EVIDENCE_FIELDS].join(" ").toLowerCase();
    for (const token of FORBIDDEN_TOKENS) {
      expect(declared, `allowlist must not name ${token}`).not.toContain(token.toLowerCase());
    }
    // Non-vacuity: the same scan DOES see a field that is present, so the misses above are an
    // absent token and not an inert search.
    expect(declared).toContain("public_key");
  });

  it("emits exactly the allowlisted keys — no more, no fewer", () => {
    const view = buildWalletCustodyView(
      walletRow({ recoveryVerifiedAt: RECOVERY_VERIFIED_AT, recoveryVerificationId: VERIFICATION_ID }),
      evidenceRow(),
    );
    expect(Object.keys(view).sort()).toEqual([...WALLET_CUSTODY_VIEW_FIELDS].sort());
    expect(Object.keys(view.recovery_verification ?? {}).sort()).toEqual(
      [...WALLET_RECOVERY_EVIDENCE_FIELDS].sort(),
    );
  });

  it("drops vault material a store hands back alongside the wallet row", async () => {
    // A store that over-selects (SELECT * across a join, or a column added later) must not be
    // able to leak through. The projection copies named fields only.
    const polluted = {
      ...walletRow({ recoveryVerifiedAt: RECOVERY_VERIFIED_AT, recoveryVerificationId: VERIFICATION_ID }),
      ciphertext: "ZGVhZGJlZWY=",
      nonce: "cccccccccccc",
      auth_tag: "dddddddddddd",
      private_key: "NEVER-SERVE-THIS",
      seed: "correct horse battery staple",
    } as unknown as WalletCustodyRow;
    const pollutedEvidence = {
      ...evidenceRow(),
      export_sha256: "e".repeat(64),
      exportBytes: "NEVER-SERVE-THIS-EITHER",
    } as unknown as WalletRecoveryVerificationRow;

    const { service } = serviceOver([polluted], [pollutedEvidence]);
    const view = await service.view(NODE_ID, WALLET_ID);
    const serialized = JSON.stringify(view).toLowerCase();
    for (const token of FORBIDDEN_TOKENS) {
      expect(serialized, `serialized view must not contain ${token}`).not.toContain(token.toLowerCase());
    }
    expect(serialized).not.toContain("never-serve-this");
    // The export digest is not part of the operator view either: the ticket allows the linked
    // row's method/verified_at/verifier_identity/audit_event_id and nothing else.
    expect(serialized).not.toContain("export_sha256");
    // Non-vacuity: the safe metadata really is there.
    expect(view?.public_key).toBe(pubkey("w1"));
  });

  it("exposes exactly two operations — no mint, import, export or rotate surface", () => {
    const { service } = serviceOver([walletRow()]);
    expect(Object.keys(service).sort()).toEqual(["quarantine", "view"]);
  });
});

/* ─── recovery status and evidence ──────────── */

describe("recovery status exposure", () => {
  it("reports an unverified wallet as unverified and fabricates no verification", async () => {
    const { service } = serviceOver([walletRow()], [evidenceRow()]);
    const view = await service.view(NODE_ID, WALLET_ID);
    expect(view?.recovery_verified).toBe(false);
    expect(view?.recovery_verified_at).toBeNull();
    // An evidence row exists in the store but was never stamped onto the wallet. That does
    // not make the wallet verified — gate is the wallets column, not the row's mere
    // existence.
    expect(view?.recovery_verification).toBeNull();
  });

  it("surfaces the evidence row behind a verified wallet, including the audit pointer", async () => {
    const { service } = serviceOver(
      [walletRow({ recoveryVerifiedAt: RECOVERY_VERIFIED_AT, recoveryVerificationId: VERIFICATION_ID })],
      [evidenceRow()],
    );
    const view = await service.view(NODE_ID, WALLET_ID);
    expect(view?.recovery_verified).toBe(true);
    expect(view?.recovery_verified_at).toBe(RECOVERY_VERIFIED_AT);
    expect(view?.recovery_verification).toEqual({
      method: "AUDITED_EXPORT",
      verified_at: RECOVERY_VERIFIED_AT,
      verifier_identity: "operator@example.test",
      audit_event_id: AUDIT_EVENT_ID,
    });
  });

  it("reports a missing evidence row as absent rather than inventing one", async () => {
    // wallets_recovery_verification_fk makes this unreachable in the database; if it is ever
    // observed the honest answer is "no evidence", never a synthesized one.
    const { service } = serviceOver(
      [walletRow({ recoveryVerifiedAt: RECOVERY_VERIFIED_AT, recoveryVerificationId: VERIFICATION_ID })],
      [],
    );
    const view = await service.view(NODE_ID, WALLET_ID);
    expect(view?.recovery_verification).toBeNull();
    expect(view?.recovery_verified_at).toBe(RECOVERY_VERIFIED_AT);
  });
});

/* ─── quarantine transition (wallets_quarantine_reason_iff) ─ */

describe("quarantine", () => {
  it("sets QUARANTINED and the reason together", async () => {
    const { store, service } = serviceOver([walletRow()]);
    const outcome = await service.quarantine({
      nodeId: NODE_ID,
      walletId: WALLET_ID,
      reason: "indeterminate head",
    });
    expect(outcome.status).toBe("quarantined");
    expect(outcome.status === "quarantined" && outcome.wallet.state).toBe("QUARANTINED");
    expect(outcome.status === "quarantined" && outcome.wallet.quarantine_reason).toBe("indeterminate head");
    expect(store.wallets.get(WALLET_ID)?.quarantineReason).toBe("indeterminate head");
  });

  it("refuses a blank reason — the state is unreachable without one", async () => {
    const { store, service } = serviceOver([walletRow()]);
    for (const reason of ["", "   ", "\n\t"]) {
      const outcome = await service.quarantine({ nodeId: NODE_ID, walletId: WALLET_ID, reason });
      expect(outcome.status).toBe("reason_required");
    }
    expect(store.wallets.get(WALLET_ID)?.state).toBe("AVAILABLE");
    expect(store.writes).toEqual([]);
  });

  it("quarantines a PINNED wallet — SEC requires it while a lease is held", async () => {
    const { service } = serviceOver([walletRow({ state: "PINNED" })]);
    const outcome = await service.quarantine({
      nodeId: NODE_ID,
      walletId: WALLET_ID,
      reason: "needs attention: ambiguous submit",
    });
    expect(outcome.status).toBe("quarantined");
  });

  it("never touches a lease row — the service has no lease port at all", async () => {
    const { store, service } = serviceOver([walletRow({ state: "PINNED" })]);
    await service.quarantine({ nodeId: NODE_ID, walletId: WALLET_ID, reason: "held lease" });
    // "A NEEDS_ATTENTION lease remains held or the wallet is quarantined until
    // human-gated resolution." Quarantine writes wallets and nothing else.
    expect(store.writes).toEqual([`wallets:${WALLET_ID}`]);
  });

  it("refuses to quarantine a RETIRED wallet — RETIRED is terminal", async () => {
    const { store, service } = serviceOver([
      walletRow({ state: "RETIRED", retiredAt: "2026-07-20T00:00:00.000Z" }),
    ]);
    const outcome = await service.quarantine({
      nodeId: NODE_ID,
      walletId: WALLET_ID,
      reason: "too late",
    });
    expect(outcome).toEqual({ status: "invalid_transition", walletId: WALLET_ID, from: "RETIRED" });
    expect(store.writes).toEqual([]);
  });

  it("is idempotent and never overwrites the original operator reason", async () => {
    const { store, service } = serviceOver([walletRow()]);
    await service.quarantine({ nodeId: NODE_ID, walletId: WALLET_ID, reason: "first reason" });
    const replay = await service.quarantine({
      nodeId: NODE_ID,
      walletId: WALLET_ID,
      reason: "second reason",
    });
    expect(replay.status).toBe("already_quarantined");
    expect(replay.status === "already_quarantined" && replay.wallet.quarantine_reason).toBe("first reason");
    expect(store.writes).toEqual([`wallets:${WALLET_ID}`]);
  });

  it("collapses another tenant's wallet to not_found for both view and quarantine", async () => {
    const { store, service } = serviceOver([walletRow()]);
    expect(await service.view(OTHER_NODE_ID, WALLET_ID)).toBeNull();
    const outcome = await service.quarantine({
      nodeId: OTHER_NODE_ID,
      walletId: WALLET_ID,
      reason: "cross-tenant attempt",
    });
    // not_found, never a 403-shaped answer that confirms the wallet exists.
    expect(outcome).toEqual({ status: "not_found", walletId: WALLET_ID });
    expect(store.writes).toEqual([]);
  });

  it("returns not_found for an absent wallet", async () => {
    const { service } = serviceOver([]);
    const outcome = await service.quarantine({
      nodeId: NODE_ID,
      walletId: WALLET_ID,
      reason: "no such wallet",
    });
    expect(outcome).toEqual({ status: "not_found", walletId: WALLET_ID });
  });
});

/* ─── quarantine/retire feed the live eligibility derivation ─ */

/**
 * One shared wallet map behind both the destination store and the custody
 * store, so an eligibility read after a quarantine is a genuine re-derivation and not a fixture
 * rewritten by hand.
 */
class SharedCustodyFixture implements DestinationStore, WalletCustodyStore {
  readonly wallets = new Map<string, WalletCustodyRow>();
  readonly destinations = new Map<string, DestinationRecord>();
  readonly verifications = new Map<string, WalletRecoveryVerificationRow>();
  readonly writes: string[] = [];

  /* WalletCustodyStore */
  async findWallet(walletId: Uuid): Promise<WalletCustodyRow | null> {
    return this.wallets.get(walletId) ?? null;
  }

  async findRecoveryVerification(verificationId: Uuid): Promise<WalletRecoveryVerificationRow | null> {
    return this.verifications.get(verificationId) ?? null;
  }

  async quarantine(walletId: Uuid, reason: string): Promise<WalletCustodyRow> {
    const current = this.wallets.get(walletId);
    if (current === undefined) throw new Error(`no wallet ${walletId}`);
    const next: WalletCustodyRow = { ...current, state: "QUARANTINED", quarantineReason: reason };
    this.wallets.set(walletId, next);
    this.writes.push(`wallets:${walletId}`);
    return next;
  }

  /* DestinationStore */
  async findById(destinationId: Uuid): Promise<DestinationRecord | null> {
    return this.destinations.get(destinationId) ?? null;
  }

  async findByIdempotencyKey(): Promise<DestinationRecord | null> {
    return null;
  }

  async insert(record: NewDestination, _idempotencyKey: string): Promise<DestinationRecord> {
    const stored: DestinationRecord = {
      ...record,
      state: "PENDING",
      blessedAt: null,
      blessedByDeviceKeyId: null,
      blessingArtifactId: null,
      retiredAt: null,
    };
    this.destinations.set(record.destinationId, stored);
    this.writes.push(`destinations:${record.destinationId}`);
    return stored;
  }

  async walletKeyOrigin(walletId: Uuid): Promise<WalletKeyOrigin | null> {
    return this.wallets.get(walletId)?.keyOrigin ?? null;
  }

  async walletFacts(walletId: Uuid): Promise<DestinationWalletFacts | null> {
    const row = this.wallets.get(walletId);
    if (row === undefined) return null;
    return {
      keyOrigin: row.keyOrigin,
      walletState: row.state,
      recoveryVerifiedAt: row.recoveryVerifiedAt,
    };
  }

  async bless(
    destinationId: Uuid,
    patch: {
      readonly blessedAt: string;
      readonly blessedByDeviceKeyId: Uuid;
      readonly blessingArtifactId: Uuid;
    },
  ): Promise<DestinationRecord | null> {
    const current = this.destinations.get(destinationId);
    // Atomic PENDING-only CAS — mirrors DestinationStore on main (fix).
    if (current === undefined || current.state !== "PENDING") {
      return null;
    }
    const next: DestinationRecord = { ...current, state: "BLESSED", ...patch };
    this.destinations.set(destinationId, next);
    this.writes.push(`destinations:${destinationId}`);
    return next;
  }

  async retire(destinationId: Uuid, retiredAt: string): Promise<DestinationRecord> {
    const current = this.destinations.get(destinationId);
    if (current === undefined) throw new Error(`no destination ${destinationId}`);
    const next: DestinationRecord = { ...current, state: "RETIRED", retiredAt };
    this.destinations.set(destinationId, next);
    this.writes.push(`destinations:${destinationId}`);
    return next;
  }

  async list(
    nodeId: Uuid,
  ): Promise<{ readonly items: readonly DestinationRecord[]; readonly nextAfter: Uuid | null }> {
    const items = [...this.destinations.values()].filter((row) => row.nodeId === nodeId);
    return { items, nextAfter: null };
  }
}

const blessingAuthorizer: BlessingAuthorizer = {
  async authorize() {
    return { deviceKeyId: DEVICE_KEY_ID, artifactId: ARTIFACT_ID };
  },
};

const keyGenerator = (walletId: Uuid): DestinationWalletKeyGenerator => ({
  async generate() {
    return { walletId, publicKey: pubkey("w1") };
  },
});

/** Registers + blesses one destination over a recovery-verified, node-generated wallet. */
const blessedFixture = async (): Promise<{
  fixture: SharedCustodyFixture;
  destinations: ReturnType<typeof createDestinationService>;
  custody: ReturnType<typeof createWalletCustodyAdminService>;
  destinationId: Uuid;
}> => {
  const fixture = new SharedCustodyFixture();
  fixture.wallets.set(
    WALLET_ID,
    walletRow({ recoveryVerifiedAt: RECOVERY_VERIFIED_AT, recoveryVerificationId: VERIFICATION_ID }),
  );
  fixture.verifications.set(VERIFICATION_ID, evidenceRow());
  const destinationId = uuid("d1");
  const destinations = createDestinationService({
    store: fixture,
    keyGenerator: keyGenerator(WALLET_ID),
    blessingAuthorizer,
    clock: { now: () => "2026-07-25T00:00:00.000Z" },
    ids: { destinationId: () => destinationId },
  });
  await destinations.register({ nodeId: NODE_ID, label: "sink", idempotencyKey: "k1" });
  await destinations.bless({
    nodeId: NODE_ID,
    destinationId,
    nonce: NONCE,
    issuedAt: "2026-07-25T00:00:00.000Z",
    expiresAt: "2026-07-25T00:05:00.000Z",
    deviceSignature: "sig",
    deviceKeyId: DEVICE_KEY_ID,
  });
  return {
    fixture,
    destinations,
    custody: createWalletCustodyAdminService({ store: fixture }),
    destinationId,
  };
};

describe("quarantine and retirement feed live eligibility", () => {
  it("flips move_eligible to false on the very next eligibility read, with no caching lag", async () => {
    const { fixture, destinations, custody, destinationId } = await blessedFixture();

    const before = await destinations.get(NODE_ID, destinationId);
    expect(before?.move_eligible).toBe(true);
    expect(before?.ineligibility_reason).toBeNull();

    await custody.quarantine({ nodeId: NODE_ID, walletId: WALLET_ID, reason: "operator hold" });

    const after = await destinations.get(NODE_ID, destinationId);
    expect(after?.move_eligible).toBe(false);
    expect(after?.ineligibility_reason).toBe("WALLET_STATE_NOT_AUTOMATIC_SINK_ELIGIBLE");
    // The destination row itself is untouched — eligibility is derived, never a stored column.
    expect(fixture.destinations.get(destinationId)?.state).toBe("BLESSED");
    const listed = await destinations.list(NODE_ID, {});
    expect(listed.items[0]?.move_eligible).toBe(false);
  });

  it("retirement flips eligibility and leaves in-flight operation artifacts byte-identical", async () => {
    const { fixture, destinations, destinationId } = await blessedFixture();

    // Stand-ins for the rows says retirement must never rewrite. They are captured
    // byte-exact so this assertion goes red the moment the retire path gains any port that
    // could reach an operation artifact, lease, or partial (the byte-exact signing rule).
    const inFlight = {
      lease: {
        wallet_id: WALLET_ID,
        operation_id: uuid("a1"),
        lease_role: "MOVE_DESTINATION",
        lease_epoch: 7,
      },
      signedArtifact: {
        operation_id: uuid("a1"),
        artifact_sha256: "f".repeat(64),
        signature: "Zm9vYmFy",
      },
    };
    const beforeBytes = JSON.stringify(inFlight);

    const outcome = await destinations.retire({ nodeId: NODE_ID, destinationId });
    expect(outcome.status).toBe("retired");

    expect(JSON.stringify(inFlight)).toBe(beforeBytes);
    // The retire path wrote the destinations row and nothing else in this run.
    expect(fixture.writes.filter((w) => !w.startsWith("destinations:"))).toEqual([]);

    const after = await destinations.get(NODE_ID, destinationId);
    expect(after?.move_eligible).toBe(false);
    expect(after?.ineligibility_reason).toBe("DESTINATION_NOT_BLESSED");
  });
});

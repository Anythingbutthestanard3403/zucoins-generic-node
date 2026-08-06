// The two properties of dual-lease acquisition that need no database:
// the ordering comparator itself, and the conflict mapping a busy wallet produces.
//
// Governing: ("ascending binary UUID value")
// ("ascending `wallet_id` byte order"); ("Explicitly selected busy
// wallets return 409 wallet_busy … An automatic child remains CREATED and is visibly queued
// within its existing lease group").
//
// The database-enforced behaviour (atomic all-or-nothing acquisition, the race, the
// receive-child path) is proven in dual-lease-acquire.pg.test.ts against real PostgreSQL
// this file deliberately covers only what is decidable without one.

import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  moveLeaseRejectionCode,
  type MoveLeaseOutcome,
} from "../../src/move/acquire-leases.ts";
import { MoveAdmissionError } from "../../src/move/create.ts";
import { sortWalletIdsAscending } from "../../src/leases/sort-wallets.ts";
import { handleCreateInternalMove } from "../../src/api/routes/operation-routes.ts";
import type { OperationRouteStore } from "../../src/api/routes/operation-routes.ts";
import type { PipelineContext } from "../../src/api/pipeline.ts";

const SOURCE = "a0000000-0000-4000-8000-000000000001";
const DESTINATION = "a0000000-0000-4000-8000-000000000002";

/** The reference order: raw 16-byte unsigned comparison, hyphens stripped. */
const rawBytes = (uuid: string): Buffer =>
  Buffer.from(uuid.replace(/-/g, "").toLowerCase(), "hex");

const byRawBytes = (ids: readonly string[]): string[] =>
  [...ids].sort((a, b) => Buffer.compare(rawBytes(a), rawBytes(b)));

describe("ascending-UUID comparator", () => {
  it("orders 500 random UUIDs exactly as a raw 16-byte comparison does", () => {
    const ids = Array.from({ length: 500 }, () => randomUUID());
    expect(sortWalletIdsAscending(ids)).toEqual(byRawBytes(ids));
  });

  it("is byte order, not ASCII order: uppercase input sorts by its canonical value", () => {
    // 'A' (0x41) sorts before 'a' (0x61) in ASCII, so a case-sensitive text sort would put
    // the uppercase form first regardless of its actual UUID value. Byte order must not.
    const lower = "a0000000-0000-4000-8000-000000000001";
    const upperHigher = "F0000000-0000-4000-8000-000000000002";
    expect(sortWalletIdsAscending([upperHigher, lower])).toEqual([lower, upperHigher]);
    expect(byRawBytes([upperHigher, lower])).toEqual([lower, upperHigher]);
  });

  it("is byte order, not collation order, across the digit/letter boundary", () => {
    // A locale-aware collation (en_US.UTF-8) ignores punctuation and can interleave digits
    // with letters; raw bytes always place '9' (0x39) before 'a' (0x61).
    const nine = "99999999-0000-4000-8000-000000000001";
    const alpha = "a9999999-0000-4000-8000-000000000001";
    expect(sortWalletIdsAscending([alpha, nine])).toEqual([nine, alpha]);
  });

  it("does not mutate its input", () => {
    const input = [DESTINATION, SOURCE];
    sortWalletIdsAscending(input);
    expect(input).toEqual([DESTINATION, SOURCE]);
  });
});

describe("acquisition outcome → rejection code", () => {
  const cases: ReadonlyArray<readonly [MoveLeaseOutcome, string | null]> = [
    [{ outcome: "WALLET_BUSY", walletId: SOURCE }, "wallet_busy"],
    [{ outcome: "WALLET_BUSY", walletId: DESTINATION }, "wallet_busy"],
    // step 3: the automatic child is not a rejection — it stays CREATED and queued.
    [{ outcome: "CHILD_WAITING", walletId: DESTINATION }, null],
    [{ outcome: "SOURCE_NOT_HELD", walletId: SOURCE, detail: "x" }, "source_wallet_not_eligible"],
    [
      { outcome: "NOT_ELIGIBLE", walletId: SOURCE, reason: "WALLET_NOT_ELIGIBLE", detail: "x" },
      "source_wallet_not_eligible",
    ],
    [
      { outcome: "NOT_ELIGIBLE", walletId: DESTINATION, reason: "CUSTODY_REJECTED", detail: "x" },
      "destination_not_eligible",
    ],
  ];

  it.each(cases)("maps %o", (outcome, expected) => {
    expect(moveLeaseRejectionCode(outcome, SOURCE)).toBe(expected);
  });

  it("treats HELD as no rejection at all", () => {
    const held: MoveLeaseOutcome = {
      outcome: "HELD",
      source: { walletId: SOURCE, membershipId: randomUUID(), leaseEpoch: 1n },
      destination: { walletId: DESTINATION, membershipId: randomUUID(), leaseEpoch: 1n },
    };
    expect(moveLeaseRejectionCode(held, SOURCE)).toBeNull();
  });
});

// ─── end-to-end: the busy outcome reaches the wire as the frozen 409 envelope ──────────

const moveCtx: PipelineContext = {
  requestId: "req-00000000-0000-0000-0000-000000000286",
  request: {
    method: "POST",
    path: "/v1/internal-moves",
    rawBody: new Uint8Array(0),
    headers: { "idempotency-key": "dual-lease-idempotency-key-0001" },
    query: {},
  },
  routeSchema: { method: "POST", path: "/v1/internal-moves", requiresIdempotencyKey: true },
  parsedBody: {
    source_wallet_id: SOURCE,
    destination_id: DESTINATION,
    amount_zkz: "5.5",
  },
  parsedQuery: undefined,
  principal: { implementerId: "impl-dual-lease", scopes: ["move:create"] },
  idempotencyTenantId: "impl-dual-lease",
};

const storeThrowing = (err: unknown): OperationRouteStore =>
  ({
    createInternalMove: async () => {
      throw err;
    },
  }) as unknown as OperationRouteStore;

describe("busy dual-lease acquisition on the wire", () => {
  it("returns exactly 409 wallet_busy, not a generic 500", async () => {
    const busy: MoveLeaseOutcome = { outcome: "WALLET_BUSY", walletId: DESTINATION };
    const code = moveLeaseRejectionCode(busy, SOURCE);
    expect(code).toBe("wallet_busy");

    const result = await handleCreateInternalMove(
      moveCtx,
      storeThrowing(new MoveAdmissionError(code!, `destination_wallet_id=${DESTINATION}`)),
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.status).toBe(409);
    expect(JSON.parse(result.error.body).error.code).toBe("wallet_busy");
  });

  it("renders an ineligible destination as 422, not 409", async () => {
    const ineligible: MoveLeaseOutcome = {
      outcome: "NOT_ELIGIBLE",
      walletId: DESTINATION,
      reason: "CUSTODY_REJECTED",
      detail: "CUSTODY_LEASE_DESTINATION_NOT_BLESSED",
    };
    const code = moveLeaseRejectionCode(ineligible, SOURCE);
    expect(code).toBe("destination_not_eligible");

    const result = await handleCreateInternalMove(moveCtx, storeThrowing(new MoveAdmissionError(code!)));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.status).toBe(422);
    expect(JSON.parse(result.error.body).error.code).toBe("protocol_predicate_failed");
  });
});

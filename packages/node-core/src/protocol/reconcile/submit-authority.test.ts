// compile-time unrepresentability proof (via `@ts-expect-error`, enforced
// by `tsc -b`: TypeScript errors on any `@ts-expect-error` directive whose following line does
// NOT actually error) plus runtime guard tests proving a duck-typed impostor is rejected too.

import { describe, expect, it } from "vitest";

import {
  mintLandingPathProofFromOracle,
} from "./landing-oracle-mint.fixture.js";
import {
  captureSubmitAcknowledgement,
  isSettlementAuthority,
  isSubmitAcknowledgement,
  mintSettlementAuthority,
  mintSubmitClaim,
  type SettlementAuthority,
  type SubmitAcknowledgement,
} from "./submit-authority.js";

const proof = mintLandingPathProofFromOracle({
      walletPubkeyBase64Urlsafe: "wallet-pub",
      expectedBodySha256: "body-sha",
      freshHeadBodySha256: "body-sha",
      freshHeadObservationId: "obs-1",
      depth: 0,
    });
const ack = captureSubmitAcknowledgement("attempt-1", true, "ok", "2026-07-20T00:00:00.000Z");
const authority = mintSettlementAuthority("attempt-1", proof);

describe("submit authority unrepresentability", () => {
  it("a SubmitAcknowledgement cannot be assigned where a SettlementAuthority is required", () => {
    // @ts-expect-error — ack lacks the private settlementAuthorityBrand key; not assignable.
    const bad: SettlementAuthority = ack;
    expect(bad).toBeDefined(); // reached only if the type check above is (wrongly) bypassed
  });

  it("a SettlementAuthority cannot be assigned where a SubmitAcknowledgement is required", () => {
    // @ts-expect-error — authority lacks the private submitAcknowledgementBrand key.
    const bad: SubmitAcknowledgement = authority;
    expect(bad).toBeDefined();
  });

  it("mintSettlementAuthority rejects a SubmitAcknowledgement passed as the proof parameter", () => {
    // @ts-expect-error — the second parameter requires LandingPathProof, not
    // SubmitAcknowledgement; passing the wrong evidence class is a compile error, not a runtime
    // discipline. also refuses at runtime if the type check is bypassed.
    expect(() => mintSettlementAuthority("attempt-1", ack)).toThrow(
      /issued landing path proof/,
    );
  });

  it("a hand-written object literal cannot satisfy SettlementAuthority (brand symbol is not exported)", () => {
    // @ts-expect-error — no external literal can name the module-private brand symbol, so this
    // structurally can never match, regardless of how many fields are copied.
    const bad: SettlementAuthority = { attemptId: "attempt-1", path: proof };
    expect(bad).toBeDefined();
  });

  it("a hand-written object literal cannot satisfy SubmitAcknowledgement either", () => {
    // @ts-expect-error — same reasoning, the other direction.
    const bad: SubmitAcknowledgement = {
      attemptId: "attempt-1",
      gatewayStatus: true,
      gatewayCode: "ok",
      capturedAt: "2026-07-20T00:00:00.000Z",
    };
    expect(bad).toBeDefined();
  });

  it("runtime guard: isSettlementAuthority accepts only a real mintSettlementAuthority output", () => {
    expect(isSettlementAuthority(authority)).toBe(true);
    expect(isSettlementAuthority(ack)).toBe(false);
    // A duck-typed impostor with every same-named field but no brand — proves the guard checks
    // real symbol identity, not shape.
    const impostor = { attemptId: "attempt-1", path: proof };
    expect(isSettlementAuthority(impostor)).toBe(false);
    expect(isSettlementAuthority(null)).toBe(false);
    expect(isSettlementAuthority(undefined)).toBe(false);
  });

  it("runtime guard: isSubmitAcknowledgement accepts only a real captureSubmitAcknowledgement output", () => {
    expect(isSubmitAcknowledgement(ack)).toBe(true);
    expect(isSubmitAcknowledgement(authority)).toBe(false);
    const impostor = {
      attemptId: "attempt-1",
      gatewayStatus: true,
      gatewayCode: "ok",
      capturedAt: "2026-07-20T00:00:00.000Z",
    };
    expect(isSubmitAcknowledgement(impostor)).toBe(false);
  });

  it("mintSubmitClaim is a plain durable-fact value, never itself settlement authority", () => {
    const claim = mintSubmitClaim("attempt-1", "2026-07-20T00:00:00.000Z");
    expect(isSettlementAuthority(claim)).toBe(false);
    expect(isSubmitAcknowledgement(claim)).toBe(false);
  });
});

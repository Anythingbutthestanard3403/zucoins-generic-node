// the reporting node-event purpose freeze + census gate for the reporting request and event tuples.
//
// Governing: the canonical-fields tuple tables and goldens, the closed event set, the api contract, and the pull-cursor authority rule.
// Proves: (a) the manifest matches the golden; (b) both tuple preimages are byte-exact and match
// the A.8 pinned digests; (c) cross-implementation node-signs → verifies reproduces the A.8
// signatures, and the event hashes chain (B.previous == A.event_hash) incl. the null-field case;
// (d) census — closed event set, headers, sequence source, and alignment with the reporting-auth register tuple frozen
// key purposes (the reporting-auth register tuple wins); and (e) a negative per fact class.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import golden from "./gen/reporting-tuples.json" with { type: "json" };
import {
  NODE_EVENT_KEY_ALLOWED_PURPOSES,
  REPORTING_KEY_ALLOWED_PURPOSES,
  V2_REPORTING_PURPOSES,
} from "../reporting-auth/index.js";
import {
  REPORT_REQUEST_GOLDEN_PAYLOAD,
  REPORT_REQUEST_GOLDEN_PREIMAGE,
  REPORT_REQUEST_QUERY_GOLDEN_PAYLOAD,
  REPORT_REQUEST_QUERY_GOLDEN_PREIMAGE,
  REPORT_REQUEST_PURPOSE,
  REPORTING_REQUEST_HEADERS,
  buildReportRequestPreimage,
} from "./request-tuple.js";
import {
  NEUTRAL_EVENT_TYPES,
  NODE_EVENT_GOLDEN_A,
  NODE_EVENT_GOLDEN_A_PREIMAGE,
  NODE_EVENT_GOLDEN_B,
  NODE_EVENT_GOLDEN_B_PREIMAGE,
  NODE_EVENT_PURPOSE,
  buildNodeEventPreimage,
} from "./event-tuple.js";
import {
  NODE_EVENT_A_EVENT_HASH,
  NODE_EVENT_A_SHA256,
  NODE_EVENT_A_SIGNATURE,
  NODE_EVENT_B_EVENT_HASH,
  NODE_EVENT_B_SIGNATURE,
  NODE_EVENT_KEY_PUBKEY,
  REPORTING_KEY_PUBKEY,
  REPORT_REQUEST_GOLDEN_SHA256,
  REPORT_REQUEST_GOLDEN_SIGNATURE,
  REPORT_REQUEST_QUERY_GOLDEN_SHA256,
  REPORT_REQUEST_QUERY_GOLDEN_SIGNATURE,
} from "./digests.js";
import {
  eventChainLinks,
  verifyNodeEventPreimage,
  verifyReportRequestPreimage,
} from "./verifier.js";
import {
  REPORT_REQUEST_CLOCK_SKEW_MS,
  parseCanonicalRfc3339Ms,
  validateReportingRequestTarget,
} from "./request-target.js";
import { buildReportingTuplesManifest } from "./manifest.js";

const sha256 = (b: Buffer | string): string =>
  createHash("sha256").update(typeof b === "string" ? Buffer.from(b, "utf8") : b).digest("hex");
const b64url = (buf: Buffer): string => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
const readArtifact = (name: string): string =>
  readFileSync(fileURLToPath(new URL(`./gen/${name}`, import.meta.url)), "utf8");
function keyFromSeed(byte: number) {
  const seed = Buffer.alloc(32, byte);
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}
function pubOf(priv: ReturnType<typeof keyFromSeed>): string {
  return b64url(createPublicKey(priv).export({ type: "spki", format: "der" }).subarray(-32));
}

describe("the reporting node-event purpose reporting-tuples manifest freeze", () => {
  it("serialized manifest matches the committed golden snapshot", () => {
    expect(buildReportingTuplesManifest()).toEqual(golden);
  });
});

describe("the reporting node-event purpose byte-exact goldens (A.8)", () => {
  it("request preimage equals its raw artifact and the A.8 pinned digest", () => {
    expect(REPORT_REQUEST_GOLDEN_PREIMAGE).toBe(readArtifact("zp-report-request-v1.preimage.txt"));
    expect(Buffer.byteLength(REPORT_REQUEST_GOLDEN_PREIMAGE, "utf8")).toBe(488);
    expect(sha256(REPORT_REQUEST_GOLDEN_PREIMAGE)).toBe(REPORT_REQUEST_GOLDEN_SHA256);
    expect(verifyReportRequestPreimage(REPORT_REQUEST_GOLDEN_PREIMAGE)).toEqual({ ok: true, reason: null });
  });

  it("additive query-bearing request golden preserves exact raw target bytes", () => {
    expect(REPORT_REQUEST_QUERY_GOLDEN_PREIMAGE).toBe(
      readArtifact("zp-report-request-v1.query.preimage.txt"),
    );
    expect(Buffer.byteLength(REPORT_REQUEST_QUERY_GOLDEN_PREIMAGE, "utf8")).toBe(477);
    expect(sha256(REPORT_REQUEST_QUERY_GOLDEN_PREIMAGE)).toBe(REPORT_REQUEST_QUERY_GOLDEN_SHA256);
    expect(REPORT_REQUEST_QUERY_GOLDEN_PAYLOAD.path).toBe(
      "/v1/events?after_implementer_seq=1043&limit=100&wait_seconds=30",
    );
    expect(verifyReportRequestPreimage(REPORT_REQUEST_QUERY_GOLDEN_PREIMAGE)).toEqual({ ok: true, reason: null });
  });

  it("event preimages equal their raw artifacts and the A.8 pinned digest", () => {
    expect(NODE_EVENT_GOLDEN_A_PREIMAGE).toBe(readArtifact("zp-node-event-v1.golden-a.preimage.txt"));
    expect(NODE_EVENT_GOLDEN_B_PREIMAGE).toBe(readArtifact("zp-node-event-v1.golden-b.preimage.txt"));
    expect(sha256(NODE_EVENT_GOLDEN_A_PREIMAGE)).toBe(NODE_EVENT_A_SHA256);
    expect(verifyNodeEventPreimage(NODE_EVENT_GOLDEN_A_PREIMAGE)).toEqual({ ok: true, reason: null });
    expect(verifyNodeEventPreimage(NODE_EVENT_GOLDEN_B_PREIMAGE)).toEqual({ ok: true, reason: null });
    // Nullable field is serialized as JSON null, present not omitted (the tuple field rules).
    expect(NODE_EVENT_GOLDEN_B_PREIMAGE.includes('"wallet_id":null')).toBe(true);
  });
});

describe("the reporting node-event purpose cross-implementation sign → verify (A.8) + hash chain", () => {
  it("the reporting key reproduces the A.8 request signature and verifies", () => {
    const priv = keyFromSeed(0x04);
    expect(pubOf(priv)).toBe(REPORTING_KEY_PUBKEY);
    const bytes = Buffer.from(REPORT_REQUEST_GOLDEN_PREIMAGE, "utf8");
    const sig = sign(null, bytes, priv);
    expect(b64url(sig)).toBe(REPORT_REQUEST_GOLDEN_SIGNATURE);
    expect(verify(null, bytes, createPublicKey(priv), sig)).toBe(true);
  });

  it("the reporting key reproduces the additive query-bearing signature", () => {
    const priv = keyFromSeed(0x04);
    const bytes = Buffer.from(REPORT_REQUEST_QUERY_GOLDEN_PREIMAGE, "utf8");
    const sig = sign(null, bytes, priv);
    expect(b64url(sig)).toBe(REPORT_REQUEST_QUERY_GOLDEN_SIGNATURE);
    expect(verify(null, bytes, createPublicKey(priv), sig)).toBe(true);
  });

  it("the node event key reproduces the A.8 event signature, event_hash, and the chain", () => {
    const priv = keyFromSeed(0x00);
    expect(pubOf(priv)).toBe(NODE_EVENT_KEY_PUBKEY);

    const aBytes = Buffer.from(NODE_EVENT_GOLDEN_A_PREIMAGE, "utf8");
    const aSig = sign(null, aBytes, priv);
    expect(b64url(aSig)).toBe(NODE_EVENT_A_SIGNATURE);
    const aHash = sha256(Buffer.concat([aBytes, aSig]));
    expect(aHash).toBe(NODE_EVENT_A_EVENT_HASH);

    const bBytes = Buffer.from(NODE_EVENT_GOLDEN_B_PREIMAGE, "utf8");
    const bSig = sign(null, bBytes, priv);
    expect(b64url(bSig)).toBe(NODE_EVENT_B_SIGNATURE);
    expect(sha256(Buffer.concat([bBytes, bSig]))).toBe(NODE_EVENT_B_EVENT_HASH);

    // Gapless chain linkage: B.previous_event_hash == A.event_hash; A is the first event (null).
    expect(eventChainLinks(null, NODE_EVENT_GOLDEN_A)).toBe(true);
    expect(eventChainLinks(aHash, NODE_EVENT_GOLDEN_B)).toBe(true);
    expect(NODE_EVENT_GOLDEN_B.previous_event_hash).toBe(NODE_EVENT_A_EVENT_HASH);
  });
});

describe("the reporting node-event purpose census + alignment with the reporting-auth register tuple", () => {
  it("the event set is the nine closed neutral literals", () => {
    expect([...NEUTRAL_EVENT_TYPES]).toEqual([
      "receive.ready",
      "receive.landed",
      "internal_move.created",
      "internal_move.landed",
      "external_send.created",
      "external_send.awaiting_redemption",
      "external_send.landed",
      "operation.needs_attention",
      "operation.expired",
    ]);
  });

  it("the five reporting headers are mandatory and key-id is not signed", () => {
    expect(REPORTING_REQUEST_HEADERS.map((h) => h.header)).toEqual([
      "X-ZP-Reporting-Key-Id",
      "X-ZP-Reporting-Timestamp",
      "X-ZP-Reporting-Expires-At",
      "X-ZP-Reporting-Nonce",
      "X-ZP-Reporting-Signature",
    ]);
    expect(REPORTING_REQUEST_HEADERS.find((h) => h.header === "X-ZP-Reporting-Key-Id")?.signed).toBe(false);
  });

  it("both purposes are the reporting-auth register tuple-frozen key purposes (the reporting-auth register tuple wins)", () => {
    expect(REPORTING_KEY_ALLOWED_PURPOSES).toContain(REPORT_REQUEST_PURPOSE);
    expect(NODE_EVENT_KEY_ALLOWED_PURPOSES).toContain(NODE_EVENT_PURPOSE);
    expect(V2_REPORTING_PURPOSES).toContain(REPORT_REQUEST_PURPOSE);
    expect(V2_REPORTING_PURPOSES).toContain(NODE_EVENT_PURPOSE);
  });
});

describe("the reporting node-event purpose negative path (one per fact class)", () => {
  const jsonOf = (p: string): string => p.slice(p.indexOf("\n") + 1);

  it("request — a field reorder is rejected", () => {
    const { purpose, canonical_version, ...rest } = REPORT_REQUEST_GOLDEN_PAYLOAD;
    const reordered = `${REPORT_REQUEST_PURPOSE}\n` + JSON.stringify({ canonical_version, purpose, ...rest });
    expect(verifyReportRequestPreimage(reordered).ok).toBe(false);
  });

  it("request — a window longer than 60 seconds is rejected", () => {
    // the builder now rejects >60s windows at mint time.
    expect(() =>
      buildReportRequestPreimage({ ...REPORT_REQUEST_GOLDEN_PAYLOAD, expires_at: "2026-07-18T00:02:00.000Z" }),
    ).toThrow("window exceeds 60 seconds");
  });

  it("request — a lowercase method is rejected", () => {
    const lower = buildReportRequestPreimage({ ...REPORT_REQUEST_GOLDEN_PAYLOAD, method: "post" });
    expect(verifyReportRequestPreimage(lower).ok).toBe(false);
  });

  it("request — raw origin-form mutations and aliases are rejected without normalization", () => {
    const invalidTargets = [
      "https://node.example/v1/events",
      "//node.example/v1/events",
      "*",
      "/v1/events#fragment",
      "/v1\\events",
      "/v1/events ",
      "/v1/events\u007f",
      "/v1/événements",
      "/v1//events",
      "/v1/events/",
      "/v1/./events",
      "/v1/../events",
      "/v1/events?after_implementer_seq=%31",
      "/v1/events?after_implementer_seq=1+2",
      "/v1/events?",
      "/v1/events?after_implementer_seq=1&&limit=1",
      "/v1/events?after_implementer_seq=1?limit=2",
      "/v1/events?=1",
      "/v1/events?after_implementer_seq=",
      "/v1/events?after_implementer_seq",
      "/v1/events?after_implementer_seq=1=2",
      "/v1/events?after_implementer_seq=1&after_implementer_seq=2",
      "/v1/events?limit=1&after_implementer_seq=1",
      "/v1/events?unknown=1",
      "/v1/events?after_seq=1",
      "/v1/events?after_implementer_seq=01",
      "/v1/events?limit=501",
      "/v1/events?wait_seconds=31",
      "/v1/events/stream?after_implementer_seq=1&limit=1",
      "/v1/events/stream?after_seq=1",
      "/v1/destinations?after=33333333-3333-4333-8333-33333333333X",
      "/v1/destinations?limit=0",
      "/v1/destinations?limit=101",
      "/v1/destinations?state=ACTIVE",
      "/v1/state/snapshot?limit=1",
      "/v1/operations/AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA/verification-material",
      "/v1/operations/33333333-3333-4333-8333-333333333333/verification-material?limit=1",
      "/v1/operations/33333333-3333-4333-8333-333333333333/armed",
      "/v1/not-a-reporting-route",
    ];
    for (const target of invalidTargets) {
      expect(validateReportingRequestTarget("GET", target).ok, target).toBe(false);
    }
    expect(validateReportingRequestTarget("get", "/v1/events").ok).toBe(false);
    expect(validateReportingRequestTarget("PUT", "/v1/events").ok).toBe(false);
    expect(
      validateReportingRequestTarget(
        "POST",
        "/v1/operations/33333333-3333-4333-8333-333333333333/verification-material",
      ).ok,
    ).toBe(false);
  });

  it("request — route-specific canonical queries and UUID paths accept", () => {
    expect(validateReportingRequestTarget("GET", "/v1/events").ok).toBe(true);
    expect(validateReportingRequestTarget("GET", "/v1/events?after_implementer_seq=0").ok).toBe(true);
    expect(validateReportingRequestTarget("GET", "/v1/events/stream?after_implementer_seq=0").ok).toBe(true);
    expect(validateReportingRequestTarget("GET", "/v1/events/stream?after_implementer_seq=1").ok).toBe(true);
    expect(
      validateReportingRequestTarget(
        "GET",
        "/v1/destinations?after=33333333-3333-4333-8333-333333333333&limit=100&state=BLESSED",
      ).ok,
    ).toBe(true);
    expect(
      validateReportingRequestTarget(
        "POST",
        "/v1/operations/33333333-3333-4333-8333-333333333333/armed",
      ).ok,
    ).toBe(true);
    expect(
      validateReportingRequestTarget(
        "GET",
        "/v1/operations/33333333-3333-4333-8333-333333333333/verification-material",
      ).ok,
    ).toBe(true);
  });

  it("request — timestamps are exact calendar-valid RFC3339 milliseconds", () => {
    expect(REPORT_REQUEST_CLOCK_SKEW_MS).toBe(0);
    expect(parseCanonicalRfc3339Ms("2024-02-29T23:59:59.999Z")).not.toBeNull();
    for (const invalid of [
      "2023-02-29T00:00:00.000Z",
      "2026-02-30T00:00:00.000Z",
      "2026-00-01T00:00:00.000Z",
      "2026-07-18T24:00:00.000Z",
      "2026-07-18T00:00:60.000Z",
      "2026-07-18T00:00:00.00Z",
      "2026-07-18T00:00:00.000z",
      "2026-07-18T00:00:00.000+00:00",
    ]) {
      expect(parseCanonicalRfc3339Ms(invalid), invalid).toBeNull();
      // the builder now rejects non-canonical timestamps at mint time.
      expect(() => buildReportRequestPreimage({ ...REPORT_REQUEST_GOLDEN_PAYLOAD, issued_at: invalid }), invalid).toThrow();
    }
  });

  it("request — zero and negative lifetimes are rejected", () => {
    // the builder now rejects zero/negative windows at mint time.
    expect(() =>
      buildReportRequestPreimage({
        ...REPORT_REQUEST_GOLDEN_PAYLOAD,
        expires_at: REPORT_REQUEST_GOLDEN_PAYLOAD.issued_at,
      }),
    ).toThrow("expires_at must be later than issued_at");
    expect(() =>
      buildReportRequestPreimage({
        ...REPORT_REQUEST_GOLDEN_PAYLOAD,
        expires_at: "2026-07-17T23:59:59.999Z",
      }),
    ).toThrow("expires_at must be later than issued_at");
  });

  it("request — canonical_version as string \"1\" is rejected", () => {
    expect(
      verifyReportRequestPreimage(REPORT_REQUEST_GOLDEN_PREIMAGE.replace('"canonical_version":1', '"canonical_version":"1"')).ok,
    ).toBe(false);
  });

  it("event — an unknown event_type is rejected", () => {
    // Any event_type outside Appendix B's closed neutral set is rejected; "widget.settled" is an
    // arbitrary non-neutral example (the verifier checks membership, not vocabulary).
    const bad = buildNodeEventPreimage({ ...NODE_EVENT_GOLDEN_A, event_type: "widget.settled" });
    expect(verifyNodeEventPreimage(bad).ok).toBe(false);
  });

  it("event — a non-decimal seq is rejected", () => {
    const bad = buildNodeEventPreimage({ ...NODE_EVENT_GOLDEN_A, seq: "01" });
    expect(verifyNodeEventPreimage(bad).ok).toBe(false);
  });

  it("event — an omitted nullable field (not JSON null) is rejected", () => {
    const withoutWallet = `${NODE_EVENT_PURPOSE}\n${jsonOf(NODE_EVENT_GOLDEN_A_PREIMAGE).replace(',"wallet_id":"55555555-5555-4555-8555-555555555555"', "")}`;
    expect(verifyNodeEventPreimage(withoutWallet).ok).toBe(false);
  });

  it("event — a broken hash-chain link is rejected", () => {
    expect(eventChainLinks("0".repeat(64), NODE_EVENT_GOLDEN_B)).toBe(false);
  });
});

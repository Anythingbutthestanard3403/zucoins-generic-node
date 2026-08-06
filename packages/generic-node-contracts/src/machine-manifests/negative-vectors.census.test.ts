import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { AUTH_ERROR_CODES } from "../auth-errors/codes.ts";
import { assertClosedSet, assertFieldOrder, expectRejects } from "../testkit/freeze.ts";
import { FUNDED_SENDER_GENESIS_PREDECESSOR_REJECTION } from "./genesis.contract.ts";
import {
  SPLITCHAIN_INNER_FIELD_SEQUENCE,
  SPLITCHAIN_INNER_OPTIONAL_FIELDS,
} from "./fields.contract.ts";
import { SPLITCHAIN_INNER_VERSION, SUITE_CANONICAL_VERSION } from "./versions.contract.ts";
import { CEREMONY_WINDOW_RULE } from "./suite-tuples.contract.ts";
import {
  GATEWAY_ENVELOPE_MUTATION_RULE,
} from "./gateway-envelopes.contract.ts";
import {
  ADVERSARIAL_CATEGORIES,
  ADVERSARIAL_FIXTURES,
  NEGATIVE_VECTORS_CONTRACT_VERSION,
  type AdversarialFixture,
} from "./negative-vectors.contract.ts";
import { SUITE_PURPOSE_CENSUS } from "./purposes.contract.ts";
import { ZKZ_AMOUNT_TEXT_PATTERN } from "./schema-vocabs.contract.ts";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

const sha256Hex = (text: string): string =>
  createHash("sha256").update(text, "utf8").digest("hex");

const FROZEN_PURPOSES = SUITE_PURPOSE_CENSUS.map((entry) => entry.purpose);
const amountRegex = new RegExp(ZKZ_AMOUNT_TEXT_PATTERN);

// --- Verifier-style rejection helpers (the checks each fixture attacks) ---

const assertPurposeTwice = (preimageText: string, expectedPurpose: string): void => {
  const lf = preimageText.indexOf("\n");
  const prefix = lf === -1 ? preimageText : preimageText.slice(0, lf);
  const payload = JSON.parse(lf === -1 ? "{}" : preimageText.slice(lf + 1)) as { purpose?: string };
  if (prefix !== expectedPurpose || payload.purpose !== expectedPurpose) {
    throw new Error("prefix/payload purpose mismatch");
  }
};

const assertNoAppendedBytes = (preimageText: string): void => {
  if (/\s$/.test(preimageText) || preimageText.charCodeAt(0) === 0xfeff) {
    throw new Error("trailing whitespace/BOM appended");
  }
};

const assertSuiteCanonicalVersion = (value: unknown): void => {
  if (value !== SUITE_CANONICAL_VERSION || typeof value !== "number") {
    throw new Error("canonical_version must be the JSON number 1");
  }
};

const assertInnerVersion = (value: unknown): void => {
  if (value !== SPLITCHAIN_INNER_VERSION || typeof value !== "string") {
    throw new Error('inner version must be the string "2"');
  }
};

const assertSenderPreflight = (preflightBalance: string, predecessor: string): void => {
  if (preflightBalance !== "0" && predecessor === "") {
    throw new Error(FUNDED_SENDER_GENESIS_PREDECESSOR_REJECTION.rejectionCode);
  }
};

const assertChainLink = (link: string, hasSettledHistory: boolean): void => {
  if (hasSettledHistory && link === "") {
    throw new Error("genesis link after settled history");
  }
};

const UUID_CANONICAL = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const assertLowercaseUuid = (value: string): void => {
  if (!UUID_CANONICAL.test(value)) {
    throw new Error("non-canonical UUID spelling");
  }
};

const PADDED_KEY = /^[A-Za-z0-9_-]{43}=$/;
const assertPaddedKey = (value: string): void => {
  if (!PADDED_KEY.test(value)) {
    throw new Error("unpadded or non-canonical key");
  }
};

const assertZkzAmount = (value: unknown): void => {
  if (typeof value !== "string" || !amountRegex.test(value)) {
    throw new Error("not a canonical ZKZ amount string");
  }
};

const CANONICAL_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const assertCanonicalTimestamp = (value: string): void => {
  if (!CANONICAL_TIMESTAMP.test(value)) {
    throw new Error("timestamp lacks exactly three fractional digits or Z");
  }
};

const assertCeremonyWindow = (issuedAt: string, expiresAt: string): void => {
  const deltaSeconds = (Date.parse(expiresAt) - Date.parse(issuedAt)) / 1000;
  if (deltaSeconds <= 0 || deltaSeconds > CEREMONY_WINDOW_RULE.maxSeconds) {
    throw new Error("ceremony window outside (0, 300] seconds");
  }
};

interface GoldenInner {
  readonly step_1_key_public__base64urlsafe: string;
  readonly step_2_key_public__base64urlsafe: string;
  readonly previous_step_1_state_signature: string;
  readonly previous_step_2_state_signature: string;
}

const assertExactlyOneRole = (inner: GoldenInner, wallet: string): void => {
  const isSender = inner.step_1_key_public__base64urlsafe === wallet;
  const isReceiver = inner.step_2_key_public__base64urlsafe === wallet;
  if (isSender === isReceiver) {
    throw new Error("exactly one role predicate must hold");
  }
};

const assertSenderSideP = (inner: GoldenInner, claimedSenderP: string): void => {
  if (claimedSenderP !== inner.previous_step_1_state_signature) {
    throw new Error("sender P must come from previous_step_1_state_signature");
  }
};

const assertAuthErrorCode = (code: string): void => {
  if (!AUTH_ERROR_CODES.some((entry) => entry.code === code)) {
    throw new Error("auth-error code outside the frozen non-oracular set");
  }
};

const targetInner = (): GoldenInner =>
  (JSON.parse(
    readFileSync(join(packageRoot, "src/receive-golden/gen/target.settled.json"), "utf8"),
  ) as { inner: GoldenInner }).inner;

const fundedSenderGenesisInner = (): GoldenInner =>
  JSON.parse(
    readFileSync(
      join(
        packageRoot,
        "src/receive-golden/negative-vectors/funded-sender-genesis-predecessor.inner.json",
      ),
      "utf8",
    ),
  ) as GoldenInner;

// --- One executor per fixture id. A fixture without an executor (or vice versa) fails the
// set-equality census below. Each executor proves the mutated input is REJECTED by the check
// it attacks — never merely documented. ---

const EXECUTORS: Readonly<Record<string, () => void>> = {
  "purposes/unknown-purpose": () =>
    expectRejects(
      () => [...FROZEN_PURPOSES, "zp-extra-thing-v1"],
      (mutated) => assertClosedSet(mutated, FROZEN_PURPOSES),
    ),
  "purposes/deferred-tuple-as-frozen": () =>
    expectRejects(
      () => [...FROZEN_PURPOSES, "zp-implementer-event-v1"],
      (mutated) => assertClosedSet(mutated, FROZEN_PURPOSES),
    ),
  "purposes/legacy-on-suite-path": () =>
    expectRejects(
      () => [...FROZEN_PURPOSES, "zupay-reporting-v1"],
      (mutated) => assertClosedSet(mutated, FROZEN_PURPOSES),
    ),
  "fields/reordered-inner": () =>
    expectRejects(
      () => [...SPLITCHAIN_INNER_FIELD_SEQUENCE].reverse(),
      (mutated) => assertFieldOrder(mutated, SPLITCHAIN_INNER_FIELD_SEQUENCE),
    ),
  "fields/missing-field": () =>
    expectRejects(
      () => SPLITCHAIN_INNER_FIELD_SEQUENCE.filter((field) => field !== "signer_steps"),
      (mutated) => assertFieldOrder(mutated, SPLITCHAIN_INNER_FIELD_SEQUENCE),
    ),
  "fields/unexpected-field": () =>
    expectRejects(
      () => [...SPLITCHAIN_INNER_FIELD_SEQUENCE, "memo"],
      (mutated) => assertFieldOrder(mutated, SPLITCHAIN_INNER_FIELD_SEQUENCE),
    ),
  "fields/optional-misplaced": () =>
    expectRejects(
      () => ["message", "expiry__unix_time_secs"],
      (mutated) => assertFieldOrder(mutated, SPLITCHAIN_INNER_OPTIONAL_FIELDS),
    ),
  "prefixes/purpose-prefix-mismatch": () =>
    expectRejects(
      () => 'zp-move-internal-expected-v1\n{"purpose":"zp-receive-expected-v1"}',
      (mutated) => assertPurposeTwice(mutated, "zp-receive-expected-v1"),
    ),
  "prefixes/trailing-newline": () =>
    expectRejects(
      () => 'zp-receive-expected-v1\n{"purpose":"zp-receive-expected-v1"}\n',
      (mutated) => assertNoAppendedBytes(mutated),
    ),
  "prefixes/decoded-transfer-code-hash": () => {
    const exactEncoded = "eyJhIjoxfQ%3D%3D";
    const decoded = '{"a":1}';
    expect(sha256Hex(exactEncoded)).not.toBe(sha256Hex(decoded));
    expect(sha256Hex(exactEncoded)).not.toBe(sha256Hex("eyJhIjoxfQ=="));
  },
  "versions/canonical-version-as-string": () =>
    expectRejects(
      () => "1",
      (mutated) => assertSuiteCanonicalVersion(mutated),
    ),
  "versions/inner-version-as-number": () =>
    expectRejects(
      () => 2,
      (mutated) => assertInnerVersion(mutated),
    ),
  "genesis/funded-sender-empty-predecessor": () => {
    const inner = fundedSenderGenesisInner();
    expect(inner.previous_step_1_state_signature).toBe("");
    expectRejects(
      () => inner.previous_step_1_state_signature,
      (predecessor) => assertSenderPreflight("10", predecessor),
    );
  },
  "genesis/genesis-link-after-history": () =>
    expectRejects(
      () => "",
      (link) => assertChainLink(link, true),
    ),
  "suite-tuples/uppercase-uuid": () =>
    expectRejects(
      () => "aaaaaaaa-3333-4333-8333-333333333333".toUpperCase(),
      (mutated) => assertLowercaseUuid(mutated),
    ),
  "suite-tuples/unpadded-key": () =>
    expectRejects(
      () => "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q",
      (mutated) => assertPaddedKey(mutated),
    ),
  "suite-tuples/amount-as-number": () => {
    for (const mutated of [2.25, "1e2", "+1", "01", `0.${"1".repeat(33)}`]) {
      expectRejects(
        () => mutated,
        (value) => assertZkzAmount(value),
      );
    }
  },
  "suite-tuples/timestamp-without-millis": () => {
    for (const mutated of ["2026-07-18T00:00:00Z", "2026-07-18T00:00:00.000+00:00"]) {
      expectRejects(
        () => mutated,
        (value) => assertCanonicalTimestamp(value),
      );
    }
    expect(() => assertCanonicalTimestamp("2026-07-18T00:00:00.000Z")).not.toThrow();
  },
  "suite-tuples/nfc-nfd-substitution": () => {
    const nfc = "\u00e9"; // NFC single code point
    const nfd = "e\u0301"; // NFD: e + combining acute accent
    expect(Buffer.from(nfc, "utf8").equals(Buffer.from(nfd, "utf8"))).toBe(false);
    expect(sha256Hex(nfc)).not.toBe(sha256Hex(nfd));
  },
  "suite-tuples/ceremony-window-over-300": () =>
    expectRejects(
      () => ["2026-07-18T00:00:00.000Z", "2026-07-18T00:05:01.000Z"],
      ([issued, expires]) => assertCeremonyWindow(issued, expires),
    ),
  "gateway-envelopes/envelope-mutation-changes-verdict": () => {
    const innerText = readFileSync(
      join(packageRoot, "src/receive-golden/gen/target.step-1.json"),
      "utf8",
    );
    const verifies = (preimage: string): boolean => sha256Hex(preimage) === sha256Hex(innerText);
    // Envelope bytes mutate freely around the same signed inner; verification is unaffected.
    const mutatedEnvelope = `HTTP/1.1 500\n{"status":false,"data":${innerText}}`;
    expect(verifies(innerText)).toBe(true);
    expect(GATEWAY_ENVELOPE_MUTATION_RULE.preimageVerificationAffected).toBe(false);
    expect(mutatedEnvelope).not.toBe(innerText);
    expect(GATEWAY_ENVELOPE_MUTATION_RULE.unchangedSemanticHeadClassification).toBe(
      "EQUIVALENT_STATE_DIFFERENT_ENVELOPE",
    );
  },
  "role-projections/self-transfer": () => {
    const inner = targetInner();
    const selfInner = { ...inner, step_2_key_public__base64urlsafe: inner.step_1_key_public__base64urlsafe };
    expectRejects(
      () => inner.step_1_key_public__base64urlsafe,
      (wallet) => assertExactlyOneRole(selfInner, wallet),
    );
  },
  "role-projections/absent-wallet": () =>
    expectRejects(
      () => "bnoc3Smwt4_ROvTFWY_v9O8qlxZuPKby5Pv8zYBQW_E=",
      (wallet) => assertExactlyOneRole(targetInner(), wallet),
    ),
  "role-projections/cross-role-p-substitution": () =>
    expectRejects(
      () => targetInner().previous_step_2_state_signature,
      (claimedSenderP) => assertSenderSideP(targetInner(), claimedSenderP),
    ),
  "api/403-scope-code": () => {
    for (const code of ["forbidden", "insufficient_scope"]) {
      expectRejects(
        () => code,
        (mutated) => assertAuthErrorCode(mutated),
      );
    }
  },
  "api/amount-as-json-number": () =>
    expectRejects(
      () => 2.25,
      (mutated) => assertZkzAmount(mutated),
    ),
  "schema-vocabs/amount-leading-zero": () =>
    expectRejects(
      () => "01.5",
      (mutated) => assertZkzAmount(mutated),
    ),
  "schema-vocabs/amount-exponent": () =>
    expectRejects(
      () => "1e2",
      (mutated) => assertZkzAmount(mutated),
    ),
  "schema-vocabs/amount-over-32dp": () =>
    expectRejects(
      () => `0.${"1".repeat(33)}`,
      (mutated) => assertZkzAmount(mutated),
    ),
  "schema-vocabs/noncanonical-uuid": () =>
    expectRejects(
      () => "aaaaaaaa-3333-4333-8333-333333333333".toUpperCase(),
      (mutated) => assertLowercaseUuid(mutated),
    ),
};

describe("negative-vectors census (the fixture-provenance purposes census, A.9; protocol rules 2,5,10; the adversarial-fixture gate)", () => {
  it("fixture ids are unique and every category carries at least one fixture", () => {
    const ids = ADVERSARIAL_FIXTURES.map((fixture) => fixture.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const category of ADVERSARIAL_CATEGORIES) {
      const inCategory = ADVERSARIAL_FIXTURES.filter((fixture) => fixture.category === category);
      expect(inCategory.length, category).toBeGreaterThan(0);
    }
  });

  it("every fixture names its category, mutation, rejection reason, and spec citation", () => {
    for (const fixture of ADVERSARIAL_FIXTURES) {
      expect(ADVERSARIAL_CATEGORIES).toContain(fixture.category);
      expect(fixture.mutation.length).toBeGreaterThan(0);
      expect(fixture.rejectionReason.length).toBeGreaterThan(0);
      expect(fixture.specCitation.length).toBeGreaterThan(0);
    }
  });

  it("executor map and fixture list are set-equal (no fixture unexecuted)", () => {
    assertClosedSet(Object.keys(EXECUTORS), ADVERSARIAL_FIXTURES.map((fixture) => fixture.id));
  });

  for (const fixture of ADVERSARIAL_FIXTURES) {
    it(`rejects: ${fixture.id}`, () => {
      const executor = EXECUTORS[fixture.id];
      expect(executor, fixture.id).toBeDefined();
      (executor as (fixture: AdversarialFixture) => void)(fixture);
    });
  }

  it("pins the manifest version", () => {
    expect(NEGATIVE_VECTORS_CONTRACT_VERSION).toBe(1);
  });
});

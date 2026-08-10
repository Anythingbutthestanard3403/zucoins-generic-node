import { describe, expect, it } from "vitest";

import {
  CONCERN_MODULES,
  concernDirsOnDisk,
  isConcernManifest,
  listProvisionalConcerns,
  listRegisteredConcerns,
  PENDING_CONCERN_DIRS,
  sha256OfPackageFile,
  staleConcernEntries,
  unregisteredConcernDirs,
} from "./registry.ts";

/**
 * the concern-manifest registry drift-audit check 1 — registry walk.
 *
 * Enumerates every concern manifest, audits the ones that self-register the canonical
 * `ConcernManifest`, and enumerates (never fails) the provisional ones still to migrate. Coverage
 * gaps this check cannot verify are listed in "enumerates coverage gaps" below.
 */
// Both ids are free-form non-empty identifiers: a concern id names its concern, a decision
// ref names the frozen rule that governs it. Emptiness is the drift signal, not the format.
const CONCERN_ID = /^\S.*$/;
const DECISION_REF = /^\S.*$/;

describe("drift-audit check 1: registry walk", () => {
  it("on-disk concern census has no unregistered concern (wired, or a known-pending queued landing)", () => {
    // Hard-fail direction preserved: a genuinely unknown dir (neither wired nor pre-enumerated as
    // a known-pending queued landing) is real drift.
    expect(unregisteredConcernDirs()).toEqual([]);
    // A statically-wired entry with no on-disk manifest is a stale/removed registry entry.
    expect(staleConcernEntries()).toEqual([]);
    expect(concernDirsOnDisk().length).toBeGreaterThan(0);
  });

  it("enumerates known-pending queued concern directories (PENDING, not failed) not yet landed", () => {
    // Frozen expectation of today's queued-but-unlanded set; a dir leaving this set because it
    // landed and self-registered is expected. This list exists so the first queued landing
    // does not turn the registry-walk red for every subsequent change.
    //  discharged every landed pending dir into CONCERN_MODULES; list stays empty until
    // a future queued landing re-adds a name.
    expect(PENDING_CONCERN_DIRS).toEqual([]);
    // Pending dirs are name-only placeholders — none may already be wired (that would mean the
    // dir has landed and self-registered; it belongs off this list at that point).
    const wired = new Set(Object.keys(CONCERN_MODULES));
    for (const dir of PENDING_CONCERN_DIRS) {
      expect(wired.has(dir), dir).toBe(false);
    }
  });

  // the zz-* fixture exclusion and positive-detection tests are now in
  // census-filter.test.ts, driving the real concernDirsOnDisk()/unregisteredConcernDirs()
  // against an isolated os.tmpdir() fixture tree (via the srcDir scan option) — not this
  // package's own src/, and not a mock or a reimplemented replica of the filter logic.

  it("every concern that has migrated to the canonical shape self-registers a ConcernManifest (: canonical ConcernManifest set including admin-auth-errors (ZTR-1196))", () => {
    const dirs = listRegisteredConcerns().map((concern) => concern.dir);
    // `no-callback` appears twice: it self-registers two independent ConcernManifests across two
    // files (the no-callback channel freeze in manifest.ts, the no-callback doc/attack census in attack-manifest.ts), merged under one directory
    // key in CONCERN_MODULES — a legitimate multi-manifest directory, not a duplicate-registration
    // defect.
    expect(dirs).toEqual([
      "admin-auth-errors",
      "amounts",
      "api-schema",
      "approval",
      "artifacts",
      "auth-errors",
      "compat-literals",
      "credential-matrix",
      "crypto-goldens",
      "custody",
      "engine-startup",
      "event-commit",
      "event-sequencing",
      "handoff-proof",
      "implementer-events",
      "instruction-origin",
      "landing-proof",
      "launch-deferral",
      "machine-manifests",
      "no-callback",
      "no-callback",
      "observation",
      "operations",
      "operator-halt",
      "pool-policy",
      "readiness",
      "reporting-auth",
      "reporting-behavior",
      "reporting-tuples",
      "route-policy",
      "transfer-code",
      "vault",
      "wallet-state",
    ]);
  });

  it("every registered manifest has a well-formed concernId and non-empty decisionRefs", () => {
    for (const { dir, manifest } of listRegisteredConcerns()) {
      expect(manifest.concernId, dir).toMatch(CONCERN_ID);
      expect(manifest.decisionRefs.length, dir).toBeGreaterThan(0);
      for (const ref of manifest.decisionRefs) {
        expect(ref, `${dir} decisionRef`).toMatch(DECISION_REF);
      }
    }
  });

  it("every registered manifest has non-empty frozenValues with no undefined value", () => {
    for (const { dir, manifest } of listRegisteredConcerns()) {
      const entries = Object.entries(manifest.frozenValues);
      expect(entries.length, dir).toBeGreaterThan(0);
      for (const [key, value] of entries) {
        expect(key.length, `${dir} frozenValue key`).toBeGreaterThan(0);
        // An undefined value is the drift signal: a renamed/removed contract export whose
        // manifest entry silently resolved to undefined.
        expect(value, `${dir}.${key}`).toBeDefined();
      }
    }
  });

  it("every registered manifest has non-empty sourceDocCitations", () => {
    for (const { dir, manifest } of listRegisteredConcerns()) {
      expect(manifest.sourceDocCitations.length, dir).toBeGreaterThan(0);
      for (const citation of manifest.sourceDocCitations) {
        expect(typeof citation, dir).toBe("string");
        expect(citation.length, dir).toBeGreaterThan(0);
      }
    }
  });

  it("every declared goldenRef sha256-verifies against its committed file", () => {
    for (const { dir, manifest } of listRegisteredConcerns()) {
      for (const golden of manifest.goldenRefs) {
        expect(sha256OfPackageFile(golden.path), `${dir} -> ${golden.path}`).toBe(golden.sha256);
      }
    }
  });

  it("enumerates provisional concerns (PENDING, not failed) awaiting canonical migration", () => {
    const provisional = listProvisionalConcerns();
    const dirs = provisional.map((concern) => concern.dir);
    // Frozen expectation of today's not-yet-migrated set; shrinks as concerns adopt the
    // canonical ConcernManifest. A concern LEAVING this set (migrating) is expected; a NEW
    // provisional concern appearing is surfaced here for triage, never silently absorbed.
    //  wired three provisional-shaped concerns (no canonical ConcernManifest yet).
    // They are enumerated here, never structurally audited — promotion is a separate ticket.
    expect(dirs).toEqual([
      "receive-expiry",
      "reporting-persistence",
      "sequence-recovery",
    ]);
  });

  it("every concern is either registered or provisional — none unaccounted for", () => {
    const registered = listRegisteredConcerns().map((concern) => concern.dir);
    const provisional = listProvisionalConcerns().map((concern) => concern.dir);
    // Deduped: a directory may contribute more than one registered concern (`no-callback` has
    // two — see the ConcernManifest test above), so this checks dir COVERAGE, not a 1:1 count.
    const union = [...new Set([...registered, ...provisional])].sort();
    expect(union).toEqual(Object.keys(CONCERN_MODULES).sort());
  });

  it("fail-first: isConcernManifest rejects a provisional-shaped object (missing concernId)", () => {
    const provisionalShape = { concern: "amounts", frozenBy: "zkz-amount-grammar", contract: {} };
    expect(isConcernManifest(provisionalShape)).toBe(false);
  });

  it("fail-first: an undefined frozenValue fails the no-undefined assertion", () => {
    const driftedFrozenValues: Record<string, unknown> = { RENAMED_EXPORT: undefined };
    expect(() => {
      for (const value of Object.values(driftedFrozenValues)) {
        expect(value).toBeDefined();
      }
    }).toThrow();
  });

  it("fail-first: a wrong golden sha256 is caught", () => {
    const realSha = sha256OfPackageFile("gen/custody.json");
    const claimedSha = "0".repeat(64);
    expect(() => expect(realSha).toBe(claimedSha)).toThrow();
  });

  it("enumerates coverage gaps this check does not verify", () => {
    const gaps = [
      "frozenValues values are checked for definedness only, not deep-equated to each concern's contract exports",
      "provisional manifests' frozen facts are enumerated, not structurally audited",
      "scanRules strings are not executed here (the scan gates own that)",
      "known-pending queued concern directories are enumerated by name only; no structural audit until each self-registers a manifest",
    ];
    expect(gaps.length).toBeGreaterThan(0);
  });
});

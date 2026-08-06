// bind durable-table assembly to the verification-material
// HTTP source port.
//
// The load+map half lives in observation/verification/source.ts (boundary:
// observation → protocol only). This module is the api-edge adapter that:
// 1. turns AssembleFromTablesResult into VerificationMaterialRow
// 2. optionally composes the access-window RECORD gate
//
// api may import observation via the package root / observation subpath is not
// in ALLOWED_INTERNAL_IMPORTS for api (api: protocol|core|reporting). So this
// adapter takes the table port + pure assembler functions as injected deps, OR
// imports through a relative path that the boundary checker classifies.
//
// Relative path from api/ → observation/ is classified as api → observation,
// which is NOT allowed. Therefore the composition root (apps/generic-node) or
// a thin factory that lives outside both modules must wire them. For in-package
// tests and the convenient factory used by generic-node, we place the factory
// here but accept the table-port + assemble function as parameters so the
// production import graph stays legal when composition is external.
//
// Convenience factories that DO import observation are gated behind a dedicated
// composition helper file that the boundary allow-list may need to carve — see
// createTableBackedVerificationMaterialSource below: it uses dynamic structural
// typing only (no observation import). Callers pass assembleVerificationMaterialFromTables.

import type { OperationKind } from "@zucoins/generic-node-contracts/operations";

import {
  authorizeVerificationAccessWindow,
  type AccessWindowDecision,
  type VerificationAccessWindowStore,
} from "./verification-access.js";
import type {
  VerificationMaterialRow,
  VerificationMaterialSource,
} from "./verification-material.js";

/** Minimal shape of the observation assemble result (no observation import). */
export type AssembleFromTablesFn = (
  port: unknown,
  operationId: string,
  implementerId: string,
) => Promise<
  | {
      readonly ok: true;
      readonly row: {
        readonly kind: OperationKind;
        readonly status: string;
        readonly verificationMaterialAvailableUntilMs: number | null;
        readonly material: Readonly<Record<string, unknown>>;
      };
    }
  | { readonly ok: false; readonly reason: "not_found" | "missing_artifact" }
>;

export type LoadOperationFn = (
  operationId: string,
  implementerId: string,
) => Promise<{
  readonly kind: OperationKind;
  readonly status: string;
  readonly verification_material_available_until_ms: number | null;
} | null>;

/**
 * `VerificationMaterialSource` backed by a durable table port + assembler.
 * Missing artifact is surfaced as a landed-but-not-ready row (null window) so
 * the HTTP gate returns 409 rather than forging an empty artifact.
 */
export function createTableBackedVerificationMaterialSource(deps: {
  readonly assemble: AssembleFromTablesFn;
  readonly port: unknown;
  readonly loadOperation: LoadOperationFn;
}): VerificationMaterialSource {
  return {
    async load(operationId, tenantId) {
      const result = await deps.assemble(deps.port, operationId, tenantId);
      if (!result.ok) {
        if (result.reason === "not_found") return null;
        const header = await deps.loadOperation(operationId, tenantId);
        if (header === null) return null;
        return {
          kind: header.kind,
          status: header.status,
          verificationMaterialAvailableUntilMs: null,
          material: {},
        } satisfies VerificationMaterialRow;
      }
      return {
        kind: result.row.kind,
        status: result.row.status,
        verificationMaterialAvailableUntilMs: result.row.verificationMaterialAvailableUntilMs,
        material: result.row.material,
      } satisfies VerificationMaterialRow;
    },
  };
}

/**
 * Compose the durable source with the access-window RECORD gate.
 *
 * When a window store is supplied, every load first authorizes the window. A 410
 * decision collapses the row's window to an already-expired timestamp so the HTTP
 * binder emits `verification_material_expired` without deleting evidence. A 409
 * decision nulls the window column (not_ready). Cross-tenant / absent stays null.
 *
 * The operations.verification_material_available_until column remains authoritative
 * when no window store is wired (backward compatible with transport tests).
 */
export function createGatedTableVerificationMaterialSource(deps: {
  readonly inner: VerificationMaterialSource;
  readonly accessWindowStore?: VerificationAccessWindowStore;
  readonly nowMs: () => number;
  /** Optional hook so callers can audit every access decision. */
  readonly onAccessDecision?: (
    decision: AccessWindowDecision,
    operationId: string,
  ) => void | Promise<void>;
}): VerificationMaterialSource {
  return {
    async load(operationId, tenantId) {
      const row = await deps.inner.load(operationId, tenantId);
      if (row === null) return null;

      if (deps.accessWindowStore === undefined) {
        return row;
      }

      const decision = await authorizeVerificationAccessWindow(deps.accessWindowStore, {
        operationId,
        implementerId: tenantId,
        kind: row.kind,
        status: row.status,
        nowMs: deps.nowMs(),
        verificationMaterialAvailableUntilMs: row.verificationMaterialAvailableUntilMs,
      });

      if (deps.onAccessDecision !== undefined) {
        await deps.onAccessDecision(decision, operationId);
      }

      if (decision.verdict === "EXPIRED") {
        // Force 410: set window to a past instant. Evidence bytes stay durable —
        // the HTTP binder never serializes material on 410.
        const past = deps.nowMs() - 1;
        return {
          kind: row.kind,
          status: row.status,
          verificationMaterialAvailableUntilMs: past,
          material: row.material,
        };
      }

      if (decision.verdict === "NOT_READY") {
        return {
          kind: row.kind,
          status: row.status,
          verificationMaterialAvailableUntilMs: null,
          material: row.material,
        };
      }

      // ACCESSIBLE — prefer the window record's expires_at when present so the
      // wire available_until matches the access-window record.
      if (decision.record !== null) {
        return {
          kind: row.kind,
          status: row.status,
          verificationMaterialAvailableUntilMs: decision.record.expiresAtMs,
          material: row.material,
        };
      }

      return row;
    },
  };
}

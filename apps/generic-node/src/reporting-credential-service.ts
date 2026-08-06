// admin-SPA reporting credential surface.
//
// Operations:
//   * list()  — public identity allowlist + lifecycle status (never the private seed).
//   * issue() — first ACTIVE reporting credential; raw seed once. 409 if already ACTIVE.
//   * recoverLost() — operator declares the current seed unrecoverable (TOTP-gated in router).
//     Retires that implementer, seeds a fresh implementer + reporting key, returns both
//     secrets once. Same trust root as REPORTING_KEY_RECOVER boot — no Railway env required.
//
// Normal rotation (still have the seed) stays the implementer-signed lifecycle ceremony and
// is not this path. Key-custody: reporting seed is a verification key, not a wallet signing key.

import { randomUUID } from "node:crypto";
import type { Pool } from "pg";

import {
  CredentialService,
  IMPLEMENTER_SCOPES,
  type CredentialStore,
} from "@zucoins/node-core";

import { retireImplementerWithLostReportingKey } from "./bootstrap/genesis.js";
import { issueReportingCredential } from "./bootstrap/reporting-key-enrol.js";

/** The immutable reporting-key identity allowlist + derived lifecycle status. */
export interface ReportingKeyListing {
  readonly id: string;
  readonly node_id: string;
  readonly implementer_id: string;
  readonly public_key: string;
  readonly registered_at: string;
  readonly status: string;
}

/**
 * Issue response. The raw private seed is returned exactly once, never persisted, never
 * logged. `id` and `key_id` are the same reporting-key UUID (kept distinct so the client
 * type reads the same as the ik_ shape it clones).
 */
export interface ReportingCredentialIssueResult {
  readonly id: string;
  readonly key_id: string;
  readonly public_key: string;
  readonly raw_private_key: string;
  readonly registered_at: string;
}

/** Lost-seed recovery: new reporting seed + new implementer bearer (both once). */
export interface ReportingCredentialRecoverResult extends ReportingCredentialIssueResult {
  readonly object: "reporting_key_recovered";
  readonly superseded_key_id: string;
  readonly implementer_id: string;
  /** Fresh ik_… for the new implementer — old ik_ died with the retired implementer. */
  readonly implementer_raw_key: string;
  readonly implementer_key_prefix: string;
}

export interface ReportingCredentialService {
  list(): Promise<readonly ReportingKeyListing[]>;
  issue(operatorSessionId: string): Promise<ReportingCredentialIssueResult>;
  /**
   * Declare `lostKeyId` (must be the current lifecycle head) unrecoverable and mint a
   * replacement. Operator session id is audit-only.
   */
  recoverLost(
    operatorSessionId: string,
    lostKeyId: string,
  ): Promise<ReportingCredentialRecoverResult>;
}

/** No non-retired implementer is registered for this node — cannot issue. */
export class NoNodeImplementerError extends Error {
  readonly code = "no_implementer" as const;
  constructor() {
    super("no non-retired implementer registered for this node");
    this.name = "NoNodeImplementerError";
  }
}

/** Body key id is not the live lifecycle head (wrong id, or already recovered). */
export class ReportingKeyNotCurrentHeadError extends Error {
  readonly code = "reporting_key_not_current" as const;
  constructor(readonly keyId: string) {
    super("reporting key is not the current lifecycle head — nothing to recover");
    this.name = "ReportingKeyNotCurrentHeadError";
  }
}

const toIso = (value: unknown): string =>
  value instanceof Date ? value.toISOString() : String(value);

export function createSqlReportingCredentialService(
  pool: Pool,
  nodeId: string,
  opts?: {
    readonly credentialStore?: CredentialStore;
  },
): ReportingCredentialService {
  // Unlike the api-key resolver this cannot key off implementer_reporting_keys — that table
  // is empty until the first reporting credential is issued, which is exactly this flow. The
  // implementer is the single non-retired row genesis seeded (mirrors bootstrapImplementerIfEmpty).
  const resolveImplementerId = async (): Promise<string> => {
    const { rows } = await pool.query<{ id: string }>(
      `SELECT id::text AS id FROM implementers WHERE retired_at IS NULL`,
    );
    if (rows.length === 0) throw new NoNodeImplementerError();
    if (rows.length > 1) {
      throw new Error(
        `reporting credential issue: ${rows.length} non-retired implementers — refusing to pick one`,
      );
    }
    return rows[0]!.id;
  };

  return {
    async list(): Promise<readonly ReportingKeyListing[]> {
      const { rows } = await pool.query<{
        id: string;
        node_id: string;
        implementer_id: string;
        public_key: string;
        registered_at: unknown;
        status: string | null;
      }>(
        `SELECT k.id::text            AS id,
                k.node_id::text        AS node_id,
                k.implementer_id::text AS implementer_id,
                k.public_key,
                k.registered_at,
                s.state                AS status
           FROM implementer_reporting_keys k
           LEFT JOIN LATERAL (
             SELECT state
               FROM reporting_key_lifecycle_states s
              WHERE s.reporting_key_id = k.id
              ORDER BY s.lifecycle_epoch DESC -- contract-allow:order:frozen-sql-text
              LIMIT 1
           ) s ON true
          WHERE k.node_id = $1::uuid
          ORDER BY k.registered_at DESC`, // contract-allow:order:frozen-sql-text
        [nodeId],
      );
      return rows.map((r) => ({
        id: r.id,
        node_id: r.node_id,
        implementer_id: r.implementer_id,
        public_key: r.public_key,
        registered_at: toIso(r.registered_at),
        status: r.status ?? "UNKNOWN",
      }));
    },

    async issue(operatorSessionId: string): Promise<ReportingCredentialIssueResult> {
      const implementerId = await resolveImplementerId();
      const issued = await issueReportingCredential(pool, {
        nodeId,
        implementerId,
        onboardingActorId: operatorSessionId,
      });
      return {
        id: issued.id,
        key_id: issued.id,
        public_key: issued.public_key,
        raw_private_key: issued.raw_private_key,
        registered_at: issued.registered_at,
      };
    },

    async recoverLost(
      operatorSessionId: string,
      lostKeyId: string,
    ): Promise<ReportingCredentialRecoverResult> {
      if (opts?.credentialStore === undefined) {
        throw new Error("reporting recoverLost requires credentialStore");
      }

      const retired = await retireImplementerWithLostReportingKey(pool, nodeId, lostKeyId);
      if (retired === null) {
        throw new ReportingKeyNotCurrentHeadError(lostKeyId);
      }

      // Fresh implementer — same shape as genesis bootstrapImplementerIfEmpty.
      const implementerId = randomUUID();
      await pool.query(`INSERT INTO implementers (id, name) VALUES ($1::uuid, $2)`, [
        implementerId,
        "operator-recovered",
      ]);

      const credentialService = new CredentialService(opts.credentialStore);
      const created = await credentialService.create(
        implementerId,
        [...IMPLEMENTER_SCOPES],
        null,
        operatorSessionId,
      );

      const issued = await issueReportingCredential(pool, {
        nodeId,
        implementerId,
        onboardingActorId: `reporting-key-recovery:superseded=${lostKeyId};operator=${operatorSessionId}`,
      });

      return {
        object: "reporting_key_recovered",
        id: issued.id,
        key_id: issued.id,
        public_key: issued.public_key,
        raw_private_key: issued.raw_private_key,
        registered_at: issued.registered_at,
        superseded_key_id: lostKeyId,
        implementer_id: implementerId,
        implementer_raw_key: created.raw_key,
        implementer_key_prefix: created.public_prefix,
      };
    },
  };
}

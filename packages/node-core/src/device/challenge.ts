// Node-origin enrollment challenge issuance/consume.
// Shape mirrors approval_challenges: status enum, unique nonce,
// issued_at/expires_at with expires > issued, single-consume, supersede.

import { randomUUID } from "node:crypto";

import type { EnrollmentChallenge, EnrollmentChallengeStatus } from "./types.js";

export const DEVICE_ENROL_PURPOSE = "zp-device-enrol-v1" as const;
export const ENROLLMENT_CHALLENGE_WINDOW_MS = 300_000;

export interface EnrollmentChallengeStore {
  findByNonce(nonce: string): EnrollmentChallenge | null;
  findIssuedByNode(nodeId: string): EnrollmentChallenge | null;
  /** All ISSUED challenges for a node (revocation invalidation). */
  listIssuedByNode(nodeId: string): readonly EnrollmentChallenge[];
  insert(challenge: EnrollmentChallenge): void;
  update(challenge: EnrollmentChallenge): void;
}

export class InMemoryEnrollmentChallengeStore implements EnrollmentChallengeStore {
  private readonly byNonce = new Map<string, EnrollmentChallenge>();
  private readonly byId = new Map<string, EnrollmentChallenge>();

  findByNonce(nonce: string): EnrollmentChallenge | null {
    return this.byNonce.get(nonce) ?? null;
  }

  findIssuedByNode(nodeId: string): EnrollmentChallenge | null {
    for (const c of this.byId.values()) {
      if (c.nodeId === nodeId && c.status === "ISSUED") return c;
    }
    return null;
  }

  listIssuedByNode(nodeId: string): readonly EnrollmentChallenge[] {
    const out: EnrollmentChallenge[] = [];
    for (const c of this.byId.values()) {
      if (c.nodeId === nodeId && c.status === "ISSUED") out.push(c);
    }
    return out;
  }

  insert(challenge: EnrollmentChallenge): void {
    if (this.byNonce.has(challenge.nonce)) {
      throw new Error(`duplicate enrollment challenge nonce: ${challenge.nonce}`);
    }
    if (this.byId.has(challenge.id)) {
      throw new Error(`duplicate enrollment challenge id: ${challenge.id}`);
    }
    this.byNonce.set(challenge.nonce, challenge);
    this.byId.set(challenge.id, challenge);
  }

  update(challenge: EnrollmentChallenge): void {
    if (!this.byId.has(challenge.id)) {
      throw new Error(`unknown enrollment challenge: ${challenge.id}`);
    }
    this.byId.set(challenge.id, challenge);
    this.byNonce.set(challenge.nonce, challenge);
  }
}

/**
 * Mark every ISSUED enrollment challenge for a node as EXPIRED so a revoked
 * device cannot complete an in-flight ceremony. Returns how many were flipped.
 * Does not delete rows (append-only challenge history).
 */
export function invalidateIssuedEnrollmentChallenges(
  store: EnrollmentChallengeStore,
  nodeId: string,
): number {
  const issued = store.listIssuedByNode(nodeId);
  for (const challenge of issued) {
    store.update({ ...challenge, status: "EXPIRED" });
  }
  return issued.length;
}

export interface IssueEnrollmentChallengeInput {
  readonly nodeId: string;
  readonly nowMs: number;
  /** Override window end; default now + 300s. Must be > now and ≤ now + 300s. */
  readonly expiresAtMs?: number;
  readonly id?: string;
  readonly nonce?: string;
}

export type IssueEnrollmentChallengeResult =
  | { readonly ok: true; readonly challenge: EnrollmentChallenge }
  | { readonly ok: false; readonly code: "WINDOW_TOO_LONG" | "WINDOW_NON_POSITIVE"; readonly detail: string };

/**
 * Issue a node-origin enrollment challenge. Supersedes any prior ISSUED challenge
 * for the same node (refresh). Callers build the A.4.3 tuple using the returned
 * nonce / issued_at / expires_at — those fields must match on consume.
 */
export function issueEnrollmentChallenge(
  store: EnrollmentChallengeStore,
  input: IssueEnrollmentChallengeInput,
): IssueEnrollmentChallengeResult {
  const issuedAtMs = input.nowMs;
  const expiresAtMs = input.expiresAtMs ?? issuedAtMs + ENROLLMENT_CHALLENGE_WINDOW_MS;
  const windowMs = expiresAtMs - issuedAtMs;
  if (!(windowMs > 0)) {
    return { ok: false, code: "WINDOW_NON_POSITIVE", detail: "expires_at must be after issued_at" };
  }
  if (windowMs > ENROLLMENT_CHALLENGE_WINDOW_MS) {
    return {
      ok: false,
      code: "WINDOW_TOO_LONG",
      detail: `window ${windowMs}ms exceeds 300s ceiling`,
    };
  }

  const previous = store.findIssuedByNode(input.nodeId);
  const challenge: EnrollmentChallenge = {
    id: input.id ?? randomUUID(),
    nodeId: input.nodeId,
    status: "ISSUED",
    purpose: DEVICE_ENROL_PURPOSE,
    canonicalVersion: 1,
    nonce: input.nonce ?? randomUUID(),
    issuedAt: new Date(issuedAtMs).toISOString(),
    expiresAt: new Date(expiresAtMs).toISOString(),
    supersededBy: null,
  };

  store.insert(challenge);

  if (previous !== null) {
    const superseded: EnrollmentChallenge = {
      ...previous,
      status: "SUPERSEDED",
      supersededBy: challenge.id,
    };
    store.update(superseded);
  }

  return { ok: true, challenge };
}

export type ConsumeChallengeResult =
  | { readonly ok: true; readonly challenge: EnrollmentChallenge }
  | {
      readonly ok: false;
      readonly code: "CHALLENGE_UNKNOWN" | "CHALLENGE_NOT_ISSUED" | "CHALLENGE_EXPIRED" | "CHALLENGE_MISMATCH";
      readonly detail: string;
    };

/**
 * Bind and single-consume a challenge against tuple-carried ceremony fields.
 * Does not mutate on failure; on success flips status to CONSUMED.
 */
export function consumeEnrollmentChallenge(
  store: EnrollmentChallengeStore,
  binding: {
    readonly nonce: string;
    readonly nodeId: string;
    readonly issuedAt: string;
    readonly expiresAt: string;
    readonly nowMs: number;
  },
): ConsumeChallengeResult {
  const challenge = store.findByNonce(binding.nonce);
  if (challenge === null) {
    return { ok: false, code: "CHALLENGE_UNKNOWN", detail: "no enrollment challenge for nonce" };
  }
  if (challenge.status !== "ISSUED") {
    return {
      ok: false,
      code: "CHALLENGE_NOT_ISSUED",
      detail: `challenge status is ${challenge.status as EnrollmentChallengeStatus}, expected ISSUED`,
    };
  }
  if (
    challenge.nodeId !== binding.nodeId ||
    challenge.issuedAt !== binding.issuedAt ||
    challenge.expiresAt !== binding.expiresAt
  ) {
    return {
      ok: false,
      code: "CHALLENGE_MISMATCH",
      detail: "tuple ceremony fields do not match issued challenge",
    };
  }
  const expiresMs = Date.parse(challenge.expiresAt);
  if (binding.nowMs > expiresMs) {
    store.update({ ...challenge, status: "EXPIRED" });
    return { ok: false, code: "CHALLENGE_EXPIRED", detail: "enrollment challenge has expired" };
  }

  const consumed: EnrollmentChallenge = { ...challenge, status: "CONSUMED" };
  store.update(consumed);
  return { ok: true, challenge: consumed };
}

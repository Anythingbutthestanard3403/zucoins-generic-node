// Side store: which admin_operator issued the current ISSUED approval challenge.
// Kept out of the frozen approval_challenges DDL so two-human dual
// control can bind challenge vs approve without a money-schema pack change.

export interface ApprovalChallengeIssuerStore {
  /** Record (or replace) the issuer for the current ISSUED challenge on an operation. */
  recordIssuer(operationId: string, challengeId: string, operatorId: string): void | Promise<void>;
  /** Look up issuer for the live ISSUED challenge on an operation. */
  findIssuer(operationId: string): string | null | Promise<string | null>;
  /** Drop issuer row when challenge is consumed/superseded (best-effort). */
  clear(operationId: string): void | Promise<void>;
}

export class InMemoryApprovalChallengeIssuerStore implements ApprovalChallengeIssuerStore {
  private readonly byOp = new Map<string, { challengeId: string; operatorId: string }>();

  recordIssuer(operationId: string, challengeId: string, operatorId: string): void {
    this.byOp.set(operationId, { challengeId, operatorId });
  }

  findIssuer(operationId: string): string | null {
    return this.byOp.get(operationId)?.operatorId ?? null;
  }

  clear(operationId: string): void {
    this.byOp.delete(operationId);
  }
}

// Enrollment audit seam — every attempt (success + each rejection) is recorded.
// Never log private key material (the key-custody rule).

import type { EnrollmentAuditEntry } from "./types.js";

export interface EnrollmentAuditLog {
  append(entry: EnrollmentAuditEntry): void;
}

export class InMemoryEnrollmentAuditLog implements EnrollmentAuditLog {
  readonly entries: EnrollmentAuditEntry[] = [];

  append(entry: EnrollmentAuditEntry): void {
    this.entries.push(entry);
  }
}

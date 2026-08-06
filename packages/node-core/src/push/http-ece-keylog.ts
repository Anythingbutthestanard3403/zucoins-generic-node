export const HTTP_ECE_KEYLOG_REFUSAL =
  "Web Push decrypt refused: dependency key logging is enabled";

export interface HttpEceKeylogBoundary {
  readonly verifyKeylogDisabled?: (challenge: object) => unknown;
}

/** Refuse if install drift ever replaces the repository-patched dependency. */
export function assertHttpEceKeyLoggingDisabled(ece: HttpEceKeylogBoundary): void {
  const challenge = Object.freeze(Object.create(null)) as object;
  try {
    if (
      typeof ece.verifyKeylogDisabled !== "function" ||
      ece.verifyKeylogDisabled(challenge) !== challenge
    ) {
      throw new Error(HTTP_ECE_KEYLOG_REFUSAL);
    }
  } catch {
    throw new Error(HTTP_ECE_KEYLOG_REFUSAL);
  }
}
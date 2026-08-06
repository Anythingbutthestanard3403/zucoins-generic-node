// One-time, in-memory handoff from API-key issuance to the Integration route.
// The plaintext key must never enter URLs, router history, Web Storage, or logs.

let pendingIssuedKey: string | null = null;

export function stageIssuedIntegrationKey(rawKey: string): void {
  if (!/^ik_[A-Za-z0-9_-]+$/.test(rawKey)) {
    throw new Error("The one-time implementer key is not valid.");
  }
  pendingIssuedKey = rawKey;
}

export function consumeIssuedIntegrationKey(): string | null {
  const issuedKey = pendingIssuedKey;
  pendingIssuedKey = null;
  return issuedKey;
}

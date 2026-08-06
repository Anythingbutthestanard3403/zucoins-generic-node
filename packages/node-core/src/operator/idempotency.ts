export interface IdempotencyKey {
  readonly implementerId: string;
  readonly method: string;
  readonly route: string;
  readonly idempotencyKey: string;
}

export interface IdempotencyRecord {
  readonly key: IdempotencyKey;
  readonly statusCode: number;
  readonly responseBytes: Uint8Array;
  readonly childRecordId: string | null;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export type IdempotencyOutcome =
  | { readonly type: "executed"; readonly record: IdempotencyRecord }
  | { readonly type: "replayed"; readonly record: IdempotencyRecord };

// Persistence port for idempotency records. Records are keyed by the composite
// (implementerId, method, route, idempotencyKey) and carry a TTL. A completed
// record stores the exact committed status and response bytes — replays return
// those bytes verbatim without re-executing the handler.
export interface IdempotencyStore {
  lookup(key: IdempotencyKey): Promise<IdempotencyRecord | null>;
  store(record: IdempotencyRecord): Promise<void>;
  purgeExpired(now: number): Promise<number>;
}

export interface IdempotencyConfig {
  readonly ttlMs: number;
}

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;

export interface IdempotencyService {
  execute(
    key: IdempotencyKey,
    handler: () => Promise<{
      statusCode: number;
      responseBytes: Uint8Array;
      childRecordId?: string | null;
    }>,
  ): Promise<IdempotencyOutcome>;
  purgeExpired(): Promise<number>;
}

export function createIdempotencyService(
  store: IdempotencyStore,
  config: Partial<IdempotencyConfig> = {},
  clock: () => number = Date.now,
): IdempotencyService {
  const ttlMs = config.ttlMs ?? DEFAULT_TTL_MS;

  return {
    async execute(key, handler) {
      const now = clock();
      const existing = await store.lookup(key);

      if (existing !== null && existing.expiresAt > now) {
        return { type: "replayed", record: existing };
      }

      const result = await handler();
      const record: IdempotencyRecord = {
        key,
        statusCode: result.statusCode,
        responseBytes: result.responseBytes,
        childRecordId: result.childRecordId ?? null,
        createdAt: now,
        expiresAt: now + ttlMs,
      };
      await store.store(record);
      return { type: "executed", record };
    },

    async purgeExpired() {
      return store.purgeExpired(clock());
    },
  };
}

export function createInMemoryIdempotencyStore(): IdempotencyStore & {
  readonly records: Map<string, IdempotencyRecord>;
} {
  const records = new Map<string, IdempotencyRecord>();

  function compositeKey(key: IdempotencyKey): string {
    return `${key.implementerId}\x00${key.method}\x00${key.route}\x00${key.idempotencyKey}`;
  }

  return {
    records,

    async lookup(key: IdempotencyKey): Promise<IdempotencyRecord | null> {
      return records.get(compositeKey(key)) ?? null;
    },

    async store(record: IdempotencyRecord): Promise<void> {
      records.set(compositeKey(record.key), record);
    },

    async purgeExpired(now: number): Promise<number> {
      let purged = 0;
      for (const [k, record] of records) {
        if (record.expiresAt <= now) {
          records.delete(k);
          purged += 1;
        }
      }
      return purged;
    },
  };
}

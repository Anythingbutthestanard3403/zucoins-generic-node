/**
 * A module namespace object's own key sequence is NOT guaranteed identical across JS
 * runtimes: plain Node's native ESM loader returns sorted string keys, while esbuild/Vite's
 * transform (used by vitest) preserves declaration sequence. Re-sorting explicitly — rather
 * than trusting `Object.entries(contractModule)`'s native sequence — keeps a JSON
 * serialization of a `.contract.ts` module byte-identical regardless of which runtime
 * produced it. Used by both `scripts/emit-json.ts` (plain Node) and `gen/json-sync.test.ts`
 * (vitest/esbuild) so they agree on one canonical rendering.
 */
export const toSortedPlainObject = (contractModule: object): Record<string, unknown> =>
  Object.fromEntries(Object.entries(contractModule).sort(([a], [b]) => a.localeCompare(b)));

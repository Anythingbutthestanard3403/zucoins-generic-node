declare module "js-yaml" {
  export function load(input: string, options?: unknown): unknown;
  export function dump(obj: unknown, options?: unknown): string;
  const yaml: { load: typeof load; dump: typeof dump };
  export default yaml;
}

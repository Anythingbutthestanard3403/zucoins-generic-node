/**
 * dependency-boundary gate for the migration-classifier IPC contract.
 *
 * The contract module is the sole shared type source between the parent and the
 * isolated child. It must remain inert (no runtime imports, no side effects)
 * and secret-free (no env/vault/DB/boot graph) so either side can import it
 * without widening the child's attack surface.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const IPC_PATH = fileURLToPath(
  new URL("../../src/db/migration-classifier.ipc.ts", import.meta.url),
);

const FORBIDDEN_IMPORT_SPECIFIERS = [
  "node:child_process",
  "child_process",
  "node:worker_threads",
  "worker_threads",
  "node:net",
  "node:http",
  "node:https",
  "node:tls",
  "node:fs",
  "node:crypto",
  "pg",
  "postgres",
  "drizzle-orm",
  "@libpg-query/parser",
  "@zucoins/node-core",
  "@zucoins/generic-node-contracts",
] as const;

const FORBIDDEN_SECRET_TOKENS = [
  "process.env",
  "FUNDED_NODE_SIGNING_KEY",
  "DATABASE_URL",
  "PGPASSWORD",
  "VAULT_MASTER_KEY",
  "vault",
  "signingKey",
  "privateKey",
] as const;

const REQUIRED_EXPORTS = [
  "LockClass",
  "StatementClassification",
  "ClassificationResult",
  "WorkerRequest",
  "WorkerResponse",
] as const;

const importLine = /^\s*import\b/;

describe("migration-classifier.ipc dependency boundary", () => {
  const src = readFileSync(IPC_PATH, "utf8");

  it("has no import statements (side-effect-free, no boot graph)", () => {
    const imports = src.split("\n").filter((line) => importLine.test(line));
    expect(imports).toEqual([]);
  });

  it("does not import forbidden runtime / DB / keystore modules", () => {
    for (const specifier of FORBIDDEN_IMPORT_SPECIFIERS) {
      const re = new RegExp(
        String.raw`\b(?:import|require|from)\b[^;\n]*["'\`]${specifier.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["'\`]`,
      );
      expect(src, `must not import ${specifier}`).not.toMatch(re);
      // bare require/dynamicForm outside an import statement
      expect(src.includes(`"${specifier}"`) || src.includes(`'${specifier}'`) || src.includes(`\`${specifier}\``)).toBe(
        false,
      );
    }
  });

  it("is secret-free (no env access tokens or key material names)", () => {
    // Strip block comments so didactic header prose cannot trip the gate.
    const code = src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    for (const token of FORBIDDEN_SECRET_TOKENS) {
      expect(code, `must not contain ${token}`).not.toContain(token);
    }
  });

  it("exports the full IPC contract once", () => {
    for (const name of REQUIRED_EXPORTS) {
      expect(src, `must export ${name}`).toMatch(new RegExp(`\\bexport\\b[^;]*\\b${name}\\b`));
    }
  });

  it("parent and worker both import the shared contract (no local redefinitions)", () => {
    const parent = readFileSync(
      fileURLToPath(new URL("../../src/db/migration-classifier.ts", import.meta.url)),
      "utf8",
    );
    const worker = readFileSync(
      fileURLToPath(new URL("../../src/db/migration-classifier.worker.ts", import.meta.url)),
      "utf8",
    );
    expect(parent).toContain("./migration-classifier.ipc.js");
    expect(worker).toContain("./migration-classifier.ipc.js");
    // The types must not be redeclared as local unions/interfaces in either side.
    expect(parent).not.toMatch(/export type LockClass\s*=/);
    expect(worker).not.toMatch(/export type LockClass\s*=/);
    expect(parent).not.toMatch(/export interface StatementClassification\b/);
    expect(worker).not.toMatch(/export interface StatementClassification\b/);
    expect(parent).not.toMatch(/export interface ClassificationResult\b/);
    expect(worker).not.toMatch(/export interface ClassificationResult\b/);
    expect(parent).not.toMatch(/\binterface WorkerRequest\b/);
    expect(worker).not.toMatch(/\binterface WorkerRequest\b/);
    expect(parent).not.toMatch(/\btype WorkerResponse\b/);
    expect(worker).not.toMatch(/\btype WorkerResponse\b/);
  });
});

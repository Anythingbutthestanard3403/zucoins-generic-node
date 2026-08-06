import { defineConfig } from "drizzle-kit";

// The generic-node reporting store is migrated from hand-written frozen SQL
// (drizzle/0000_reporting_persistence.sql), not drizzle-kit-generated schema diffs — the DDL is
// the verbatim frozen contract from 04-data-model.md. drizzle-kit is kept only so `generate`
// remains available for future schema work; `out` points at the same drizzle/ folder the
// migration runner (src/db/migrate.ts) reads.
export default defineConfig({
  dialect: "postgresql",
  out: "./drizzle",
  dbCredentials: {
    url: process.env.DATABASE_URL ?? "postgres://localhost:5432/generic_node",
  },
});

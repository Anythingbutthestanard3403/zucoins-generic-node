/**
 * Last-applied ZTR-1300 slice for disposable-PG drill packs that CREATE
 * operations / send_operations / receive_operations without the money-pack
 * tail. Production INSERT/SELECT lists verification_mode; omitting this
 * helper yields 42703 on those statements.
 *
 * Stubs only the slice's prerequisite relations when the pack never created
 * them. Does not invent a numbered migration.
 */
import { readFileSync } from "node:fs";

const SLICE_SQL = readFileSync(
  new URL("../src/schema/verification-mode.sql", import.meta.url),
  "utf-8",
);

/** Missing-relation stubs + receive_release_status so the slice CHECK rewrite is valid. */
export const VERIFICATION_MODE_FIXTURE_PREREQ_SQL = `
CREATE TABLE IF NOT EXISTS operations (id uuid PRIMARY KEY);
CREATE TABLE IF NOT EXISTS receive_operations (operation_id uuid PRIMARY KEY);
CREATE TABLE IF NOT EXISTS send_operations (operation_id uuid PRIMARY KEY);
CREATE TABLE IF NOT EXISTS node_settings (
  setting_key text PRIMARY KEY,
  setting_value text NOT NULL,
  row_version bigint NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS audit_log (
  id uuid PRIMARY KEY,
  action text NOT NULL
);
DO $vm_fixture_release$
BEGIN
  IF to_regclass('operations') IS NOT NULL THEN
    ALTER TABLE operations ADD COLUMN IF NOT EXISTS receive_release_status text;
  END IF;
END
$vm_fixture_release$;
`;

/** Prerequisite stubs + frozen verification-mode.sql. Apply after the pack's table DDLs. */
export function verificationModeFixtureSql(): string {
  return `${VERIFICATION_MODE_FIXTURE_PREREQ_SQL}\n${SLICE_SQL}\n`;
}

/**
 * Out-of-process migration lock-class classifier worker.
 *
 * ISOLATION BOUNDARY (the key-custody rule): this module runs as a SEPARATE OS PROCESS,
 * forked by `migration-classifier.ts` via `child_process.fork` with a SCRUBBED
 * environment (only PATH). It imports ONLY the PostgreSQL parser.
 *
 * The isolation is enforced by the PROCESS BOUNDARY plus the scrubbed `env`, not
 * merely by which modules this file imports: the child's `process.env` contains
 * no FUNDED_NODE_SIGNING_KEY, no DATABASE_URL, and no vault/config credential,
 * because `fork`'s `env` replaced the environment instead of inheriting it. So
 * even a compromised parser dependency running here cannot read key material or
 * reach the parent process's memory / key files.
 *
 * Communication protocol (child_process IPC channel — process.on/process.send):
 *   Main → Worker: { id: number; sqlText: string }
 *   Worker → Main: { id: number; result: ClassificationResult } | { id: number; error: string }
 */
import { parse } from "@libpg-query/parser";
import type {
  ClassificationResult,
  LockClass,
  StatementClassification,
  WorkerRequest,
  WorkerResponse,
} from "./migration-classifier.ipc.js";

export type {
  ClassificationResult,
  LockClass,
  StatementClassification,
  WorkerRequest,
  WorkerResponse,
} from "./migration-classifier.ipc.js";

type StmtNode = Record<string, unknown>;

function classifyStmtNode(node: StmtNode, rawSql: string): StatementClassification {
  const stmtType = Object.keys(node)[0];
  const stmt = node[stmtType] as Record<string, unknown>;

  switch (stmtType) {
    case "IndexStmt": {
      const concurrent = stmt["concurrent"] === true;
      if (concurrent) {
        return { sql: rawSql, lockClass: "blocking", reason: "CREATE INDEX CONCURRENTLY takes ACCESS EXCLUSIVE on the index's table" };
      }
      return { sql: rawSql, lockClass: "blocking", reason: "CREATE INDEX (non-CONCURRENTLY) takes SHARE lock blocking writes" };
    }

    case "ReindexStmt": {
      const params = stmt["params"] as Array<{ DefElem?: { defname?: string } }> | undefined;
      const isConcurrent = params?.some((p) => p.DefElem?.defname === "concurrently");
      if (isConcurrent) {
        return { sql: rawSql, lockClass: "blocking", reason: "REINDEX CONCURRENTLY takes ACCESS EXCLUSIVE on the table" };
      }
      return { sql: rawSql, lockClass: "blocking", reason: "REINDEX takes ACCESS EXCLUSIVE lock" };
    }

    case "AlterTableStmt": {
      const cmds = stmt["cmds"] as Array<{ AlterTableCmd?: { subtype?: string; def?: { Constraint?: { contype?: string } } } }> | undefined;
      if (!cmds || cmds.length === 0) {
        return { sql: rawSql, lockClass: "blocking", reason: "ALTER TABLE (unknown subcommand) takes ACCESS EXCLUSIVE" };
      }
      for (const cmd of cmds) {
        const sub = cmd.AlterTableCmd?.subtype;
        if (sub === "AT_AddConstraint") {
          const contype = cmd.AlterTableCmd?.def?.Constraint?.contype;
          if (contype === "CONSTR_FOREIGN") {
            return { sql: rawSql, lockClass: "blocking", reason: "ADD CONSTRAINT FOREIGN KEY takes ACCESS EXCLUSIVE" };
          }
        }
        if (sub === "AT_AlterColumnType") {
          return { sql: rawSql, lockClass: "blocking", reason: "ALTER COLUMN TYPE rewrites the table (ACCESS EXCLUSIVE)" };
        }
      }
      return { sql: rawSql, lockClass: "blocking", reason: "ALTER TABLE takes ACCESS EXCLUSIVE lock" };
    }

    case "DropStmt":
      return { sql: rawSql, lockClass: "blocking", reason: "DROP takes ACCESS EXCLUSIVE lock" };

    case "TruncateStmt":
      return { sql: rawSql, lockClass: "blocking", reason: "TRUNCATE takes ACCESS EXCLUSIVE lock" };

    case "CreateStmt":
      return { sql: rawSql, lockClass: "online", reason: "CREATE TABLE locks only the new table (no existing-table lock)" };

    case "InsertStmt":
    case "UpdateStmt":
    case "DeleteStmt":
    case "MergeStmt":
      return { sql: rawSql, lockClass: "online", reason: "DML takes ROW EXCLUSIVE (compatible with concurrent reads)" };

    case "SelectStmt":
      return { sql: rawSql, lockClass: "online", reason: "SELECT takes ACCESS SHARE (read-only)" };

    case "TransactionStmt":
    case "VariableSetStmt":
    case "VariableShowStmt":
      return { sql: rawSql, lockClass: "online", reason: "Transaction/session control — no table lock" };

    case "CreateFunctionStmt":
    case "CreateEnumStmt":
    case "CreateDomainStmt":
    case "CompositeTypeStmt":
      // These store a definition (a function body, a type). The body is NOT
      // executed at migration time, so no existing table is locked.
      return { sql: rawSql, lockClass: "online", reason: "CREATE type/function stores a definition — no existing-table lock" };

    case "DoStmt":
      // A DO block EXECUTES an anonymous body of dynamic SQL immediately, and the
      // parser returns it as a single opaque DoStmt node — it never descends into
      // the body. So `DO $$ BEGIN DROP TABLE wallets; END $$` is indistinguishable
      // from a harmless block at parse time. Per the fail-closed default
      // (opaque/unparseable ⇒ blocking), every DO block is blocking.
      return { sql: rawSql, lockClass: "blocking", reason: "DO block body is opaque dynamic SQL (parser cannot see into it) — fail-closed (blocking)" };

    case "CommentStmt":
    case "GrantStmt":
      return { sql: rawSql, lockClass: "online", reason: "COMMENT/GRANT — metadata only, no blocking lock" };

    default:
      return { sql: rawSql, lockClass: "blocking", reason: `Unrecognized statement type "${stmtType}" — fail-closed` };
  }
}

async function classifySql(sql: string): Promise<ClassificationResult> {
  const trimmed = sql.trim();
  if (trimmed.length === 0) {
    return { lockClass: "online", statements: [] };
  }

  let parseResult: { stmts: Array<{ stmt: StmtNode }> };
  try {
    parseResult = await parse(trimmed) as { stmts: Array<{ stmt: StmtNode }> };
  } catch {
    return {
      lockClass: "blocking",
      statements: [{ sql: trimmed, lockClass: "blocking", reason: "Parse failure — fail-closed (unparseable SQL)" }],
    };
  }

  const statements: StatementClassification[] = [];
  for (const entry of parseResult.stmts) {
    statements.push(classifyStmtNode(entry.stmt, trimmed));
  }

  const overall: LockClass = statements.some((s) => s.lockClass === "blocking")
    ? "blocking"
    : "online";

  return { lockClass: overall, statements };
}

if (typeof process.send !== "function") {
  throw new Error("migration-classifier.worker must be run as a forked child process (no IPC channel)");
}

process.on("message", (msg: WorkerRequest) => {
  classifySql(msg.sqlText)
    .then((result) => {
      const ok: WorkerResponse = { id: msg.id, result };
      process.send!(ok);
    })
    .catch((err: unknown) => {
      const fail: WorkerResponse = { id: msg.id, error: err instanceof Error ? err.message : String(err) };
      process.send!(fail);
    });
});

/**
 * Out-of-process migration lock-class classifier.
 *
 * Spawns a dedicated CHILD PROCESS (`child_process.fork`) that runs
 * `migration-classifier.worker.ts`, which imports ONLY the PostgreSQL parser.
 *
 * The key-custody rule (the node's private keys are never exposed):
 *   - The classifier runs in a SEPARATE OS PROCESS — not a `worker_thread`. A
 *     worker_thread is a thread inside THIS process: it shares the fd table,
 *     uid, cwd, network namespace, and the same `process.env`. A forked child
 *     is a distinct OS process with its own address space.
 *   - The child is spawned with a SCRUBBED `env` (see `resolveWorkerEnv`). Node
 *     copies the parent's ENTIRE `process.env` into a child ONLY when no `env`
 *     option is given; passing an explicit `env` REPLACES it. We pass the
 *     minimal set the WASM parser needs (PATH), so an injected
 *     FUNDED_NODE_SIGNING_KEY, the DATABASE_URL password, and every other secret
 *     in the parent's environment are simply absent from the child.
 *   - Isolation therefore does NOT rest on module-graph curation alone. Even if
 *     `@libpg-query/parser` (or any transitive dep imported by the worker) were
 *     compromised, it cannot read the signing key or DB credentials from
 *     `process.env` — they were never handed to the child, and it cannot reach
 *     the parent's memory or key files across the process boundary.
 *
 * Fail-closed semantics: if the worker crashes, times out, or the SQL fails to
 * parse (or is opaque — e.g. a `DO` block, whose body the parser cannot see
 * into), the result is `blocking`. We never fall back to the old
 * hand-rolled regex scanner (it fails open — the thing we're replacing).
 */
import { fork, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type {
  ClassificationResult,
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

const WORKER_TIMEOUT_MS = 10_000;

let workerInstance: ChildProcess | null = null;
let nextId = 0;
const pending = new Map<number, {
  resolve: (r: ClassificationResult) => void;
  reject: (e: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}>();

/**
 * Resolve the worker entry point. Prefer the compiled `.js` (production); fall
 * back to the `.ts` source under `--experimental-strip-types` (dev/test).
 * Exported for the key-custody isolation test.
 */
export function resolveWorkerEntry(): { path: string; execArgv: string[] } {
  const jsPath = fileURLToPath(new URL("./migration-classifier.worker.js", import.meta.url));
  if (existsSync(jsPath)) {
    return { path: jsPath, execArgv: [] };
  }
  const tsPath = fileURLToPath(new URL("./migration-classifier.worker.ts", import.meta.url));
  return { path: tsPath, execArgv: ["--experimental-strip-types"] };
}

/**
 * The MINIMAL environment handed to the classifier child process (the key-custody rule).
 * `fork`'s `env` option REPLACES the child's environment rather than inheriting
 * the parent's, so anything omitted here is unreachable from the child's
 * `process.env`. The WASM-based parser needs nothing beyond PATH; every secret
 * (FUNDED_NODE_SIGNING_KEY, DATABASE_URL, vault/config credentials, ...) is
 * deliberately excluded. Exported for the isolation test.
 */
export function resolveWorkerEnv(): NodeJS.ProcessEnv {
  return { PATH: process.env.PATH ?? "" };
}

/**
 * Fork the classifier worker as a real, separate OS process with a scrubbed
 * environment. Exported so the isolation test can assert the production spawn
 * path (child_process.fork + scrubbed env), not a reconstruction of it.
 */
export function spawnWorker(): ChildProcess {
  const { path, execArgv } = resolveWorkerEntry();
  const child = fork(path, [], { execArgv, env: resolveWorkerEnv() });

  child.on("message", (msg: WorkerResponse) => {
    const entry = pending.get(msg.id);
    if (!entry) return;
    pending.delete(msg.id);
    clearTimeout(entry.timer);

    if ("error" in msg) {
      entry.reject(new Error(msg.error));
    } else {
      entry.resolve(msg.result);
    }
  });

  child.on("error", (err) => {
    for (const [id, entry] of pending) {
      pending.delete(id);
      clearTimeout(entry.timer);
      entry.reject(err);
    }
    if (workerInstance === child) workerInstance = null;
  });

  child.on("exit", () => {
    for (const [id, entry] of pending) {
      pending.delete(id);
      clearTimeout(entry.timer);
      entry.reject(new Error("Classifier worker exited unexpectedly"));
    }
    if (workerInstance === child) workerInstance = null;
  });

  return child;
}

function ensureWorker(): ChildProcess {
  if (!workerInstance) {
    workerInstance = spawnWorker();
  }
  return workerInstance;
}

const FAIL_CLOSED_BLOCKING: ClassificationResult = {
  lockClass: "blocking",
  statements: [{ sql: "", lockClass: "blocking", reason: "Classifier unavailable — fail-closed" }],
};

export async function classifyMigrationSql(sql: string): Promise<ClassificationResult> {
  const trimmed = sql.trim();
  if (trimmed.length === 0) {
    return { lockClass: "online", statements: [] };
  }

  try {
    const worker = ensureWorker();
    const id = nextId++;
    const request: WorkerRequest = { id, sqlText: trimmed };

    return await new Promise<ClassificationResult>((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`Classifier worker timed out after ${WORKER_TIMEOUT_MS}ms`));
      }, WORKER_TIMEOUT_MS);

      pending.set(id, { resolve, reject, timer });
      worker.send(request);
    });
  } catch {
    return FAIL_CLOSED_BLOCKING;
  }
}

export async function disposeClassifier(): Promise<void> {
  const w = workerInstance;
  if (!w) return;
  workerInstance = null;
  if (w.exitCode !== null || w.signalCode !== null) {
    return; // already exited — nothing to reap
  }
  await new Promise<void>((resolve) => {
    w.once("exit", () => resolve());
    if (!w.kill()) resolve(); // signal not delivered (process already gone)
  });
}

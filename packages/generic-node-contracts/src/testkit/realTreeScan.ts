import { readFileSync } from "node:fs";

/**
 * : the shared read for every gate that walks the real working tree.
 *
 * Several gates in this package glob a live working tree and then read each hit, so a path the
 * glob returned can be gone by the time the read runs. A bare `readFileSync` turns that into an
 * ENOENT crash in a test that has nothing to do with whatever removed the file.
 *
 * That has already shipped twice from inside this package: `src/zz-*` fixture directories planted
 * under the scanned root, and the `__census-fixture-*` positive controls that
 * `../operations/operations.drift-gate.test.ts` wrote directly into `packages/node-core/src` and
 * the `apps` source trees. Both now build their fixtures under `mkdtemp` instead, so no test in
 * this package mutates the scanned tree today. The hazard that remains is the working tree itself: these gates
 * run against whatever is on disk, and an editor save, a branch switch, or a build writing beside
 * a parallel worker can still retire a path mid-walk.
 *
 * Tolerating that removal weakens nothing: a file that no longer exists is not committed
 * tree content and can hold no violation. Only ENOENT is absorbed; every other read failure
 * still throws, and each gate keeps its own "the glob found files" guard so a broken glob
 * can never pass vacuously.
 */
export const readIfPresent = (filePath: string): string | undefined => {
  try {
    return readFileSync(filePath, "utf8");
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
};

/** The walked paths that still exist, paired with their text. Vanished paths drop out. */
export const readPresentFiles = (filePaths: readonly string[]): { file: string; text: string }[] =>
  filePaths.flatMap((file) => {
    const text = readIfPresent(file);
    return text === undefined ? [] : [{ file, text }];
  });

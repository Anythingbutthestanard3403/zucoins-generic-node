// Shared Zod issue formatting for the config module. Array-element paths are
// rendered as FIELD[0] so messages stay field-first and greppable. Messages
// here never include the rejected value — only the field path and the
// constraint message.

export function formatZodIssuePath(path: readonly (string | number)[]): string {
  let rendered = "";
  for (const segment of path) {
    if (typeof segment === "number") {
      rendered = `${rendered}[${segment}]`;
      continue;
    }
    rendered = rendered === "" ? segment : `${rendered}.${segment}`;
  }
  return rendered;
}

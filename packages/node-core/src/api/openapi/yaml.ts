// Deterministic YAML 1.2 emitter for the frozen OpenAPI document.
// No third-party YAML dependency — output must be byte-stable across Node versions.

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v);

const needsQuotes = (s: string): boolean => {
  if (s.length === 0) return true;
  if (/^[\s]|[\s]$/.test(s)) return true;
  if (/[:#{}[\],&*?|>!%@`'"]/.test(s)) return true;
  if (/^(true|false|null|yes|no|on|off)$/i.test(s)) return true;
  if (/^-?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(s)) return true;
  if (s.includes("\n") || s.includes("\r")) return true;
  return false;
};

const quote = (s: string): string => {
  const escaped = s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  return `"${escaped}"`;
};

const renderScalar = (v: unknown): string => {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error(`non-finite number in OpenAPI emit: ${v}`);
    return String(v);
  }
  if (typeof v === "string") return needsQuotes(v) ? quote(v) : v;
  throw new Error(`unsupported scalar type: ${typeof v}`);
};

/**
 * Render a JSON-compatible value as YAML. Objects keep insertion ordering.
 * Arrays of objects / nested maps indent under `-`.
 */
export function renderYaml(value: unknown, indent = 0): string {
  const pad = "  ".repeat(indent);

  if (Array.isArray(value)) {
    if (value.length === 0) return `${pad}[]\n`;
    let out = "";
    for (const item of value) {
      if (isPlainObject(item) || Array.isArray(item)) {
        const nested = renderYaml(item, indent + 1);
        // First line of nested content rides after "- "
        const lines = nested.replace(/\n$/, "").split("\n");
        const first = lines[0] ?? "";
        const firstBody = first.startsWith("  ".repeat(indent + 1))
          ? first.slice("  ".repeat(indent + 1).length)
          : first.trimStart();
        out += `${pad}- ${firstBody}\n`;
        for (let i = 1; i < lines.length; i++) {
          out += `${lines[i]}\n`;
        }
      } else {
        out += `${pad}- ${renderScalar(item)}\n`;
      }
    }
    return out;
  }

  if (isPlainObject(value)) {
    const keys = Object.keys(value);
    if (keys.length === 0) return `${pad}{}\n`;
    let out = "";
    for (const key of keys) {
      const child = value[key];
      const keyText = needsQuotes(key) ? quote(key) : key;
      if (child === undefined) continue;
      if (isPlainObject(child) || Array.isArray(child)) {
        const nested = renderYaml(child, indent + 1);
        if (
          (isPlainObject(child) && Object.keys(child).length === 0) ||
          (Array.isArray(child) && child.length === 0)
        ) {
          out += `${pad}${keyText}: ${nested.trimStart()}`;
        } else {
          out += `${pad}${keyText}:\n${nested}`;
        }
      } else {
        out += `${pad}${keyText}: ${renderScalar(child)}\n`;
      }
    }
    return out;
  }

  return `${pad}${renderScalar(value)}\n`;
}

export function renderOpenApiYaml(doc: unknown): string {
  // Leading document marker keeps parsers unambiguous; trailing newline is required.
  return `---\n${renderYaml(doc).replace(/\n$/, "")}\n`;
}

/** Strip optional markdown fences from model output before JSON.parse. */
export function extractJsonText(text: string): string {
  const trimmed = text.trim();
  if (trimmed.startsWith("```")) {
    const withoutFence = trimmed.replace(/^```[a-zA-Z]*\n?/, "").replace(/\n?```\s*$/, "");
    return withoutFence.trim();
  }
  return trimmed;
}

/**
 * Find the first top-level `{ ... }` slice, respecting strings so nested `{}` in prose is ignored.
 * Returns null if no balanced object found.
 */
export function extractFirstJsonObject(text: string): string | null {
  const start = text.indexOf("{");
  if (start < 0) {
    return null;
  }
  let depth = 0;
  let inString = false;
  let escape = false;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (escape) {
      escape = false;
      continue;
    }
    if (inString) {
      if (c === "\\") {
        escape = true;
      } else if (c === '"') {
        inString = false;
      }
      continue;
    }
    if (c === '"') {
      inString = true;
      continue;
    }
    if (c === "{") {
      depth++;
    } else if (c === "}") {
      depth--;
      if (depth === 0) {
        return text.slice(start, i + 1);
      }
    }
  }
  return null;
}

/**
 * If the model output was cut mid-stream (token limit), the top-level `{...}` never closes.
 * Close an open string and append `]` / `}` to match a tracked bracket stack. Removes a trailing
 * comma before closers when safe (e.g. `...,` end of array contents).
 */
export function repairTruncatedJsonSlice(text: string): string {
  const start = text.indexOf("{");
  if (start < 0) {
    return text;
  }
  const s = text.slice(start);
  const stack: string[] = [];
  let inString = false;
  let escape = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (escape) {
      escape = false;
      continue;
    }
    if (inString) {
      if (c === "\\") {
        escape = true;
      } else if (c === '"') {
        inString = false;
      }
      continue;
    }
    if (c === '"') {
      inString = true;
      continue;
    }
    if (c === "{") {
      stack.push("}");
      continue;
    }
    if (c === "[") {
      stack.push("]");
      continue;
    }
    if (c === "}" || c === "]") {
      if (stack.length > 0 && stack[stack.length - 1] === c) {
        stack.pop();
      }
    }
  }
  let out = s;
  if (inString) {
    out += '"';
  }
  out = out.replace(/,(\s*)$/, "$1");
  for (let j = stack.length - 1; j >= 0; j--) {
    out += stack[j];
  }
  return out;
}

function sanitizeAlmostJson(input: string): string {
  // Normalize curly quotes that break strict JSON.
  const normalized = input.replace(/[“”]/g, '"').replace(/[‘’]/g, "'");
  let out = "";
  let inString = false;
  let escape = false;
  for (let i = 0; i < normalized.length; i++) {
    const c = normalized[i];
    if (escape) {
      out += c;
      escape = false;
      continue;
    }
    if (inString) {
      if (c === "\\") {
        out += c;
        escape = true;
        continue;
      }
      if (c === '"') {
        out += c;
        inString = false;
        continue;
      }
      // Raw control characters in a JSON string are invalid; escape them.
      if (c === "\n") {
        out += "\\n";
        continue;
      }
      if (c === "\r") {
        out += "\\r";
        continue;
      }
      if (c === "\t") {
        out += "\\t";
        continue;
      }
      out += c;
      continue;
    }
    if (c === '"') {
      inString = true;
    }
    out += c;
  }
  // Remove trailing commas before object/array close: { "a": 1, } / [1,2,]
  return out.replace(/,\s*([}\]])/g, "$1");
}

/**
 * Parse a JSON object from model output: try the full (defenced) string, then the first balanced object.
 * Handles local models that prepend "Here is..." or append commentary.
 */
function tryParseObjectWithSanitize(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch {
    return JSON.parse(sanitizeAlmostJson(raw));
  }
}

export function parseJsonObjectFromModelText(text: string): unknown {
  const defenced = extractJsonText(text);
  try {
    return JSON.parse(defenced);
  } catch {
    /* fall through */
  }
  let slice = extractFirstJsonObject(defenced);
  if (slice) {
    try {
      return tryParseObjectWithSanitize(slice);
    } catch {
      /* fall through */
    }
  }
  slice = extractFirstJsonObject(text);
  if (slice) {
    try {
      return tryParseObjectWithSanitize(slice);
    } catch {
      /* fall through */
    }
  }
  const repaired = repairTruncatedJsonSlice(defenced);
  try {
    return tryParseObjectWithSanitize(repaired);
  } catch {
    /* fall through */
  }
  slice = extractFirstJsonObject(repaired);
  if (slice) {
    try {
      return tryParseObjectWithSanitize(slice);
    } catch (e2) {
      throw new Error(`JSON.parse failed after truncation repair: ${e2}`);
    }
  }
  const preview = defenced.slice(0, 240).replace(/\s+/g, " ");
  throw new Error(`no parseable JSON object in model response (preview: ${preview}…)`);
}

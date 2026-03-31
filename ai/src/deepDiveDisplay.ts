/**
 * Deep-dive text sometimes arrives double-escaped (literal \\n, leading quote) from
 * JSON round-trips, or trailing JSON array/object debris when the model leaks structure.
 * Normalize for Markdown/HTML display.
 */
export function decodeDeepDiveDisplayText(raw: string): string {
  let t = raw.trim();
  for (let i = 0; i < 2; i++) {
    if (t.length >= 2 && t.startsWith('"') && t.endsWith('"')) {
      try {
        const next = JSON.parse(t) as unknown;
        if (typeof next === "string") {
          t = next;
          continue;
        }
      } catch {
        t = t.slice(1, -1);
        break;
      }
    }
    break;
  }
  t = t
    .replace(/\\n/g, "\n")
    .replace(/\\r\n/g, "\n")
    .replace(/\\r/g, "\n")
    .replace(/\\t/g, "\t")
    .replace(/\\"/g, '"')
    .replace(/\\\\/g, "\\");

  t = tryExtractMarkdownFromLooseJson(t);
  t = stripTrailingJsonArtifacts(t);
  t = stripTrailingEmbeddedObjectLine(t);
  return t.trimEnd();
}

/** Model sometimes returns a full threat-shaped JSON blob instead of markdown prose. */
function tryExtractMarkdownFromLooseJson(s: string): string {
  const t = s.trim();
  if (!t.startsWith("{")) {
    return s;
  }
  try {
    const o = JSON.parse(t) as Record<string, unknown>;
    if (typeof o.markdown === "string" && o.markdown.trim()) {
      return o.markdown;
    }
    if (typeof o.description === "string" && o.description.trim()) {
      return o.description;
    }
  } catch {
    /* fall through */
  }
  return s;
}

/**
 * Remove trailing leaked array/object closers and broken string tails
 * (e.g. `", ""}]}`, `} ] }`, `", "`).
 */
export function stripTrailingJsonArtifacts(s: string): string {
  let t = s;
  for (let i = 0; i < 16; i++) {
    const before = t;
    t = t.replace(/",\s*""\s*\}\s*\]\s*\}\s*$/g, "");
    t = t.replace(/,\s*""\s*\]\s*\}\s*$/g, "");
    t = t.replace(/,\s*""\s*\}\s*$/g, "");
    t = t.replace(/"\s*,\s*""\s*$/g, "");
    t = t.replace(/\s*[\]}]+\s*$/g, "").trimEnd();
    t = t.replace(/,\s*$/g, "").trimEnd();
    t = t.replace(/"\s*,?\s*$/g, "").trimEnd();
    if (t === before) {
      break;
    }
  }
  return t;
}

/** Drop a final line that is only JSON debris (e.g. `} ] }`). */
function stripTrailingEmbeddedObjectLine(s: string): string {
  const lines = s.split("\n");
  while (lines.length > 0) {
    const last = lines[lines.length - 1].trim();
    if (last === "") {
      lines.pop();
      continue;
    }
    if (/^[\]\}\s",]+$/.test(last)) {
      lines.pop();
      continue;
    }
    if (/^\{.*"id"\s*:\s*"/.test(last)) {
      lines.pop();
      continue;
    }
    break;
  }
  return lines.join("\n");
}

/** Single place for reports to sanitize deep-dive blobs before escaping. */
export function formatDeepDiveForDisplay(raw: string): string {
  return decodeDeepDiveDisplayText(raw);
}

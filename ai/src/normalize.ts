/**
 * LLMs (especially local ones) often omit optional arrays or use null.
 * They also emit full STRIDE names instead of S/T/R/I/D/E.
 * Normalize parsed JSON before Zod so validation matches real-world output.
 */
const fallbackRefUrl = "https://owasp.org/www-project-top-ten/";

type StrideLetter = "S" | "T" | "R" | "I" | "D" | "E";

/** Maps full STRIDE labels (and common variants) to the single-letter code the schema expects. */
export function normalizeStride(v: unknown): StrideLetter {
  if (v === null || v === undefined) {
    return "T";
  }
  const raw = String(v).trim();
  if (raw.length === 1) {
    const c = raw.toUpperCase();
    if (c === "S" || c === "T" || c === "R" || c === "I" || c === "D" || c === "E") {
      return c;
    }
  }
  const lower = raw.toLowerCase().replace(/^stride[\s:-]*/i, "").trim();
  const direct: Record<string, StrideLetter> = {
    spoofing: "S",
    spoof: "S",
    tampering: "T",
    tamper: "T",
    repudiation: "R",
    "information disclosure": "I",
    "information-disclosure": "I",
    disclosure: "I",
    "denial of service": "D",
    "denial-of-service": "D",
    dos: "D",
    ddos: "D",
    "elevation of privilege": "E",
    "elevation-of-privilege": "E",
    "privilege escalation": "E",
    elevation: "E",
  };
  if (direct[lower]) {
    return direct[lower];
  }
  for (const [phrase, letter] of Object.entries(direct)) {
    if (lower.includes(phrase)) {
      return letter;
    }
  }
  return "T";
}

/** If `id` looks like "S", "S-01", "T-2", use that letter (models often mismatch stride vs id). */
export function inferStrideFromId(id: unknown): StrideLetter | null {
  const s = String(id ?? "").trim();
  if (s.length === 1) {
    const c = s.toUpperCase();
    if (c === "S" || c === "T" || c === "R" || c === "I" || c === "D" || c === "E") {
      return c;
    }
    return null;
  }
  const m = /^([STRIDE])[-_\s]/i.exec(s);
  if (m) {
    const c = m[1].toUpperCase();
    if (c === "S" || c === "T" || c === "R" || c === "I" || c === "D" || c === "E") {
      return c;
    }
  }
  // S1, R1, T2 — ID prefix is authoritative for register consistency
  const md = /^([STRIDE])(?:\d+)$/i.exec(s);
  if (md) {
    const c = md[1].toUpperCase();
    if (c === "S" || c === "T" || c === "R" || c === "I" || c === "D" || c === "E") {
      return c;
    }
  }
  return null;
}

/** Title prefixes like "Spoofing: ..." (or "Spoofing ...") — trust over a wrong stride field. */
export function inferStrideFromTitle(title: string): StrideLetter | null {
  const t = title.trim();
  const m = t.match(
    /^(Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege)(?:\s*:|\s+-|\s+|$)/i,
  );
  if (!m) {
    return null;
  }
  return normalizeStride(m[1]);
}

export function normalizeThreatPayload(raw: unknown): unknown {
  if (raw === null || typeof raw !== "object") {
    return raw;
  }
  const o = raw as Record<string, unknown>;
  const threats = o.threats;
  if (!Array.isArray(threats)) {
    return raw;
  }

  o.threats = threats.map((t) => normalizeThreatItem(t));
  if (typeof o.notes !== "string") {
    o.notes = o.notes == null ? "" : String(o.notes);
  }
  o.architecture_flows = normalizeArchitectureFlows(o.architecture_flows);
  o.threat_actor_categories = normalizeThreatActorCategories(o.threat_actor_categories);
  return o;
}

function normalizeArchitectureFlows(v: unknown): unknown[] {
  if (!Array.isArray(v)) {
    return [];
  }
  return (v as unknown[]).map((row) => {
    if (row === null || typeof row !== "object") {
      return { boundary_name: "", from_component: "", to_component: "" };
    }
    const r = row as Record<string, unknown>;
    return {
      boundary_name: r.boundary_name == null ? "" : String(r.boundary_name),
      from_component: r.from_component == null ? "" : String(r.from_component),
      to_component: r.to_component == null ? "" : String(r.to_component),
    };
  });
}

/**
 * Models sometimes emit related_paths as objects, e.g. { "path": "…" } or { "file": "…" }.
 * Coerce every entry to a repo-relative path string for Zod.
 */
export function normalizeRelatedPaths(v: unknown): string[] {
  if (!Array.isArray(v)) {
    return [];
  }
  const out: string[] = [];
  for (const item of v as unknown[]) {
    const s = coerceRelatedPathEntry(item);
    if (s.length > 0) {
      out.push(s);
    }
  }
  return out;
}

function coerceRelatedPathEntry(item: unknown): string {
  if (item === null || item === undefined) {
    return "";
  }
  if (typeof item === "string") {
    return item.trim();
  }
  if (typeof item === "number" || typeof item === "boolean") {
    return String(item).trim();
  }
  if (typeof item !== "object") {
    return String(item).trim();
  }
  const o = item as Record<string, unknown>;
  const pathKeys = [
    "path",
    "file",
    "filepath",
    "repo_path",
    "source_file",
    "source",
    "relative_path",
    "location",
  ] as const;
  for (const k of pathKeys) {
    const val = o[k];
    if (typeof val === "string" && val.trim().length > 0) {
      return val.trim();
    }
  }
  // Rare: one key looks like a file path (e.g. { "internal/x.go": "note" })
  const entries = Object.entries(o).filter(([, val]) => typeof val === "string");
  if (entries.length === 1) {
    const key = entries[0][0].trim();
    if (/[/\\]|\.(go|proto|ts|js|yaml|yml|json|tf|md)\b/i.test(key)) {
      return key;
    }
  }
  return "";
}

function normalizeThreatActorCategories(v: unknown): unknown[] {
  if (!Array.isArray(v)) {
    return [];
  }
  return (v as unknown[]).map((row) => {
    if (row === null || typeof row !== "object") {
      return { category: "", description: "", example: "" };
    }
    const r = row as Record<string, unknown>;
    return {
      category: r.category == null ? "" : String(r.category),
      description: r.description == null ? "" : String(r.description),
      example: r.example == null ? "" : String(r.example),
    };
  });
}

function normalizeThreatItem(t: unknown): unknown {
  if (t === null || typeof t !== "object") {
    return t;
  }
  const th = { ...(t as Record<string, unknown>) };

  th.stride = normalizeStride(th.stride);
  const fromId = inferStrideFromId(th.id);
  if (fromId) {
    th.stride = fromId;
  } else {
    const fromTitle = inferStrideFromTitle(String(th.title ?? ""));
    if (fromTitle) {
      th.stride = fromTitle;
    }
  }

  th.related_paths = normalizeRelatedPaths(th.related_paths);
  th.immediate_actions = normalizeStringArray(th.immediate_actions);
  th.mitigations = normalizeStringArray(th.mitigations);
  if (typeof th.verification !== "string") {
    th.verification = th.verification == null ? "" : String(th.verification);
  }
  if (typeof th.attack_scenario !== "string") {
    th.attack_scenario = th.attack_scenario == null ? "" : String(th.attack_scenario);
  }
  if (typeof th.prerequisites !== "string") {
    th.prerequisites = th.prerequisites == null ? "" : String(th.prerequisites);
  }
  if (!Array.isArray(th.cwe_candidates)) {
    th.cwe_candidates = [];
  } else {
    th.cwe_candidates = (th.cwe_candidates as unknown[]).map((c) => String(c));
  }
  if (typeof th.detection_and_monitoring !== "string") {
    th.detection_and_monitoring =
      th.detection_and_monitoring == null ? "" : String(th.detection_and_monitoring);
  }
  if (typeof th.likelihood_rationale !== "string") {
    th.likelihood_rationale =
      th.likelihood_rationale == null ? "" : String(th.likelihood_rationale);
  }
  if (typeof th.impact_rationale !== "string") {
    th.impact_rationale = th.impact_rationale == null ? "" : String(th.impact_rationale);
  }

  let refs: unknown = th.references;
  if (refs === null || refs === undefined) {
    refs = [];
  }
  if (!Array.isArray(refs)) {
    refs = [];
  }
  th.references = (refs as unknown[]).map((r: unknown) => normalizeReference(r));

  return th;
}

function normalizeStringArray(v: unknown): string[] {
  if (!Array.isArray(v)) {
    return [];
  }
  const out: string[] = [];
  for (const item of v as unknown[]) {
    const s = coerceStringArrayItem(item);
    if (s.length > 0) {
      out.push(s);
    }
  }
  return out;
}

function coerceStringArrayItem(item: unknown): string {
  if (item === null || item === undefined) {
    return "";
  }
  if (typeof item === "string") {
    return item.trim();
  }
  if (typeof item === "number" || typeof item === "boolean") {
    return String(item).trim();
  }
  if (typeof item !== "object") {
    return String(item).trim();
  }
  const o = item as Record<string, unknown>;
  const commonKeys = [
    "text",
    "value",
    "description",
    "title",
    "action",
    "mitigation",
    "step",
    "name",
    "label",
  ] as const;
  for (const k of commonKeys) {
    const val = o[k];
    if (typeof val === "string" && val.trim().length > 0) {
      return val.trim();
    }
  }
  return "";
}

function normalizeReference(r: unknown): { label: string; url: string } {
  if (r === null || typeof r !== "object") {
    return { label: "OWASP", url: fallbackRefUrl };
  }
  const x = r as Record<string, unknown>;
  const label = typeof x.label === "string" && x.label.length > 0 ? x.label : "Reference";
  let url = typeof x.url === "string" ? x.url.trim() : "";
  if (!url) {
    url = fallbackRefUrl;
  }
  return { label, url };
}

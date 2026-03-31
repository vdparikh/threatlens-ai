import type { ThreatOutput } from "./schemas.js";

export type ArchitectureFlowRow = {
  boundary_name: string;
  from_component: string;
  to_component: string;
};

export type ThreatActorRow = {
  category: string;
  description: string;
  example: string;
};

const placeholderTokens = new Set(["actor_user", "proc_http", "data_store", "ext_services"]);

/** Generic SDLC-friendly actor taxonomy when the model omits tailored rows. */
export const DEFAULT_THREAT_ACTOR_CATEGORIES: ThreatActorRow[] = [
  {
    category: "External attackers",
    description:
      "Unauthenticated or opportunistic attackers against internet-facing interfaces.",
    example: "Exploitation of a public API, UI, or authentication endpoint.",
  },
  {
    category: "Authenticated users",
    description: "Legitimate users exceeding authorization or abusing business logic.",
    example: "IDOR, tenant crossover, or privilege escalation via misconfigured roles.",
  },
  {
    category: "Automated threats",
    description: "Bots, scanners, credential stuffing, or denial-of-resource campaigns.",
    example: "High-volume login attempts or scraping of sensitive metadata.",
  },
  {
    category: "Insider / privileged operators",
    description: "Staff, contractors, or break-glass accounts with production access.",
    example: "Abuse of admin keys, CI secrets, or overly broad cloud IAM.",
  },
  {
    category: "Supply chain & dependencies",
    description: "Third-party libraries, images, SaaS, or CI integrations.",
    example: "Vulnerable package, compromised pipeline credential, or rogue MCP/tooling.",
  },
];

export function deriveArchitectureFlowsFromModel(systemModel: Record<string, unknown>): ArchitectureFlowRow[] {
  const g = systemModel.flow_graph as
    | {
        nodes?: { id: string; label?: string }[];
        edges?: { from: string; to: string; label?: string }[];
      }
    | undefined;
  if (!g?.edges?.length) {
    return [];
  }
  const labels = new Map<string, string>();
  for (const n of g.nodes ?? []) {
    if (n.id) {
      labels.set(n.id, (n.label ?? n.id).trim() || n.id);
    }
  }
  const lbl = (id: string): string => labels.get(id) ?? id;
  const max = 50;
  const edges = g.edges.slice(0, max);
  return edges.map((e, i) => ({
    boundary_name:
      (e.label?.trim() && e.label.trim()) ||
      `Flow ${i + 1}: ${lbl(e.from)} → ${lbl(e.to)}`,
    from_component: lbl(e.from),
    to_component: lbl(e.to),
  }));
}

function hasPlaceholder(s: string): boolean {
  const v = s.trim();
  if (!v) {
    return true;
  }
  if (placeholderTokens.has(v)) {
    return true;
  }
  if (v.startsWith("/")) {
    return true;
  }
  return false;
}

function looksImportOrFileLikeComponent(s: string): boolean {
  const v = s.trim();
  if (!v) {
    return false;
  }
  if (v.endsWith(".go")) {
    return true;
  }
  // Import/package-like token: no spaces, slash-separated, lowercase-heavy.
  if (!v.includes(" ") && /[a-z0-9_\-./]+/.test(v) && v.includes("/")) {
    return true;
  }
  return false;
}

/** Low-quality rows look like internal graph ids or absolute paths; prefer derived graph labels. */
export function isLowQualityArchitectureRows(rows: ArchitectureFlowRow[]): boolean {
  if (rows.length === 0) {
    return true;
  }
  let bad = 0;
  for (const r of rows) {
    if (hasPlaceholder(r.from_component) || hasPlaceholder(r.to_component) || hasPlaceholder(r.boundary_name)) {
      bad++;
    }
    if (looksImportOrFileLikeComponent(r.from_component) || looksImportOrFileLikeComponent(r.to_component)) {
      bad++;
    }
    if (!r.from_component.trim() || !r.to_component.trim()) {
      bad++;
    }
  }
  return bad >= rows.length;
}

export function resolveArchitectureRows(
  systemModel: Record<string, unknown>,
  threats: ThreatOutput,
): { rows: ArchitectureFlowRow[]; sourceNote: string } {
  const llm = threats.architecture_flows.filter(
    (r) =>
      r.boundary_name.trim().length > 0 ||
      r.from_component.trim().length > 0 ||
      r.to_component.trim().length > 0,
  );
  if (llm.length > 0 && !isLowQualityArchitectureRows(llm)) {
    return { rows: llm, sourceNote: "Generated from repository context (LLM)." };
  }
  const derived = deriveArchitectureFlowsFromModel(systemModel);
  if (derived.length > 0) {
    return {
      rows: derived,
      sourceNote: "Derived heuristically from indexed flow_graph (confirm in architecture review).",
    };
  }
  return {
    rows: [],
    sourceNote: "No flows indexed — widen analysis root or add an architecture diagram to the model.",
  };
}

export function resolveThreatActorRows(threats: ThreatOutput): {
  rows: ThreatActorRow[];
  isTailored: boolean;
} {
  const llm = threats.threat_actor_categories.filter((r) => r.category.trim().length > 0);
  const looksPlaceholder = llm.every((r) => {
    const s = `${r.category} ${r.description} ${r.example}`.toLowerCase();
    return s.includes("actor_user") || s.includes("proc_http") || s.includes("data_store");
  });
  if (looksPlaceholder) {
    return { rows: DEFAULT_THREAT_ACTOR_CATEGORIES, isTailored: false };
  }
  if (llm.length > 0) {
    return { rows: llm, isTailored: true };
  }
  return { rows: DEFAULT_THREAT_ACTOR_CATEGORIES, isTailored: false };
}

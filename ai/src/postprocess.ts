import { inferStrideFromId, inferStrideFromTitle, normalizeStride } from "./normalize.js";
import {
  deriveArchitectureFlowsFromModel,
  isLowQualityArchitectureRows,
  type ArchitectureFlowRow,
} from "./reportContext.js";
import {
  CHAIN_HARDCODED_CREDS_ID,
  isSyntheticChainThreatId,
  maxSeverityOf,
  parseSecuritySignalsFromModel,
  pathsMatch,
  signalsMatchingThreat,
  synthesizeAllChainThreats,
  type SecuritySignalRow,
} from "./signalGrounding.js";
import type { ThreatOutput } from "./schemas.js";

type ThreatItem = ThreatOutput["threats"][number];

/** Signals that define CHAIN-HARDCODED-CREDS — redundant I-row on same files adds no value. */
const HARDCODED_CREDENTIAL_SIGNAL_IDS = new Set([
  "default-hsm-pin",
  "default-db-dsn-with-password",
]);

function lower(s: string): string {
  return s.toLowerCase();
}

function strideFromText(t: string): ThreatItem["stride"] | null {
  const s = lower(t);
  if (s.includes("spoof")) return "S";
  if (s.includes("tamper")) return "T";
  if (s.includes("repudiation") || s.includes("non-repudiation")) return "R";
  if (s.includes("information disclosure") || s.includes("data leak") || s.includes("disclosure")) return "I";
  if (s.includes("denial of service") || s.includes("dos") || s.includes("resource exhaustion")) return "D";
  if (s.includes("elevation of privilege") || s.includes("privilege escalation")) return "E";
  return null;
}

function pickRelatedPaths(model: Record<string, unknown>, text: string): string[] {
  const files = Array.isArray(model.files) ? (model.files as { path?: string }[]) : [];
  const all = files
    .map((f) => String(f.path ?? "").trim())
    .filter((p) => p.length > 0);
  if (all.length === 0) {
    return [];
  }
  const s = lower(text);
  const scored = all
    .map((p) => {
      const pl = lower(p);
      let score = 0;
      if (s.includes("grpc") && (pl.includes("grpc") || pl.endsWith("_grpc.pb.go"))) score += 6;
      if ((s.includes("policy") || s.includes("auth")) && pl.includes("policy")) score += 5;
      if ((s.includes("database") || s.includes("sql") || s.includes("dsn")) && (pl.includes("store") || pl.includes("db"))) score += 5;
      if ((s.includes("tls") || s.includes("mtls") || s.includes("certificate")) && (pl.includes("server") || pl.includes("main"))) score += 4;
      if ((s.includes("hsm") || s.includes("pkcs11") || s.includes("pin")) && (pl.includes("backend") || pl.includes("main"))) score += 5;
      if (pl.endsWith("main.go")) score += 1;
      if (pl.includes("server.go")) score += 1;
      return { p, score };
    })
    .filter((x) => x.score > 0)
    .sort((a, b) => b.score - a.score);
  if (scored.length > 0) {
    return scored.slice(0, 3).map((x) => x.p);
  }
  // Fallback to a few central Go files when no keyword matches.
  const go = all.filter((p) => p.endsWith(".go"));
  return go.slice(0, 2);
}

function normalizeRelatedPaths(model: Record<string, unknown>, paths: string[]): string[] {
  const files = Array.isArray(model.files) ? (model.files as { path?: string }[]) : [];
  const known = new Set(
    files.map((f) => String(f.path ?? "").trim()).filter((p) => p.length > 0),
  );
  const cleaned = paths
    .map((p) => String(p).trim())
    .filter((p) => p.length > 0)
    .filter((p) => known.has(p));
  return Array.from(new Set(cleaned));
}

function downgradeUnsupportedSeverity(th: ThreatItem): ThreatItem {
  if (th.related_paths.length > 0) {
    return th;
  }
  if (th.severity === "CRITICAL") {
    return { ...th, severity: "HIGH" };
  }
  if (th.severity === "HIGH") {
    return { ...th, severity: "MEDIUM" };
  }
  return th;
}

/**
 * Reduce severity inflation: HIGH/CRITICAL need HIGH+ static signal grounding or synthetic chain rows.
 * Keeps reviewers from ignoring an all-red dashboard.
 */
function calibrateSeverityInflation(
  th: ThreatItem,
  matched: SecuritySignalRow[],
  modelHasSignals: boolean,
): ThreatItem {
  if (isSyntheticChainThreatId(th.id) || !modelHasSignals) {
    return th;
  }
  const sigFloor =
    matched.length > 0 ? maxSeverityOf(matched.map((m) => m.severity)) : ("LOW" as ThreatItem["severity"]);
  let severity = th.severity;
  if (severity === "CRITICAL" && sigFloor !== "CRITICAL") {
    severity = "HIGH";
  }
  if (severity === "HIGH" && sigFloor !== "HIGH" && sigFloor !== "CRITICAL") {
    severity = "MEDIUM";
  }
  return { ...th, severity };
}

function mergeSignalsIntoThreat(
  model: Record<string, unknown>,
  th: ThreatItem,
  signals: SecuritySignalRow[],
): ThreatItem {
  const modelHasSignals = signals.length > 0;
  const matched = modelHasSignals ? signalsMatchingThreat(th, signals) : [];
  if (!modelHasSignals || matched.length === 0) {
    return calibrateSeverityInflation(th, matched, modelHasSignals);
  }
  const desc = th.description.trim();
  const prefix = matched
    .map(
      (s) =>
        `**Static signal \`${s.id}\`** (\`${s.path}\`, ${s.severity}): ${s.summary.trim()}`,
    )
    .join("\n\n");
  const looksMerged = matched.every((s) => {
    const frag = s.summary.trim().slice(0, Math.min(48, s.summary.trim().length));
    return frag.length > 0 && desc.includes(frag);
  });
  const description = looksMerged ? desc : `${prefix}\n\n${desc}`.trim();
  const mergedPaths = [
    ...th.related_paths.map((p) => p.trim()).filter(Boolean),
    ...matched.map((m) => m.path.trim()).filter(Boolean),
  ];
  let related_paths = normalizeRelatedPaths(model, mergedPaths);
  if (related_paths.length === 0) {
    related_paths = pickRelatedPaths(model, `${th.title} ${description}`);
  }
  const severity = maxSeverityOf([th.severity, ...matched.map((m) => m.severity)]);
  let out: ThreatItem = { ...th, description, related_paths, severity };
  out = downgradeUnsupportedSeverity(out);
  out = calibrateSeverityInflation(out, matched, true);
  return out;
}

function fixOneThreat(model: Record<string, unknown>, th: ThreatItem): ThreatItem {
  const text = `${th.title} ${th.description}`;
  /** Title wins when it names STRIDE explicitly — keeps badge consistent with card headline (critique: T1 + "Repudiation…"). */
  const inferred =
    inferStrideFromTitle(th.title) ??
    inferStrideFromId(th.id) ??
    strideFromText(text) ??
    normalizeStride(th.stride);
  let out: ThreatItem = { ...th, stride: inferred };
  out = { ...out, related_paths: normalizeRelatedPaths(model, out.related_paths) };
  if (out.related_paths.length === 0) {
    out = { ...out, related_paths: pickRelatedPaths(model, text) };
  }
  out = downgradeUnsupportedSeverity(out);
  return out;
}

function insertChainedThreats(
  model: Record<string, unknown>,
  threats: ThreatItem[],
  signals: SecuritySignalRow[],
): ThreatItem[] {
  const existing = new Set(threats.map((t) => t.id));
  const prefix: ThreatItem[] = [];
  for (const row of synthesizeAllChainThreats(signals)) {
    if (existing.has(row.id)) {
      continue;
    }
    existing.add(row.id);
    let r: ThreatItem = { ...row };
    r = {
      ...r,
      related_paths: normalizeRelatedPaths(
        model,
        r.related_paths.length > 0 ? r.related_paths : pickRelatedPaths(model, r.description),
      ),
    };
    r = downgradeUnsupportedSeverity(r);
    prefix.push(r);
  }
  return [...prefix, ...threats];
}

function hasSignalCoveredByThreat(
  threats: ThreatItem[],
  signals: SecuritySignalRow[],
  signalId: string,
): boolean {
  for (const t of threats) {
    const matched = signalsMatchingThreat(t, signals);
    if (matched.some((m) => m.id === signalId)) {
      return true;
    }
  }
  return false;
}

function synthesizeReflectionDisclosureThreat(
  model: Record<string, unknown>,
  threats: ThreatItem[],
  signals: SecuritySignalRow[],
): ThreatItem[] {
  const refl = signals.find((s) => s.id === "grpc-reflection-enabled");
  if (!refl) {
    return threats;
  }
  if (hasSignalCoveredByThreat(threats, signals, refl.id)) {
    return threats;
  }
  const row: ThreatItem = {
    id: "SIGNAL-REFLECTION",
    stride: "I",
    title: "Information disclosure via gRPC reflection",
    description:
      `**Static signal \`${refl.id}\`** (\`${refl.path}\`, ${refl.severity}): ${refl.summary}\n\n` +
      "Unauthenticated or broadly reachable reflection endpoints enable method and schema enumeration. " +
      "This does not directly grant data access, but materially improves attacker reconnaissance and targeting.",
    severity: "LOW",
    related_paths: normalizeRelatedPaths(model, [refl.path]),
    immediate_actions: [
      "Disable gRPC server reflection in production profiles.",
      "If reflection is required, restrict access to trusted internal networks/operators only.",
    ],
    mitigations: [
      "Treat reflection as a diagnostic surface; gate with environment flags and network policy.",
    ],
    verification:
      "Confirm production startup does not register reflection handlers, or that access is restricted to trusted origins.",
    references: [],
    attack_scenario:
      "Attacker enumerates service and method names via reflection, then crafts targeted calls against exposed operations.",
    prerequisites: "Network reachability to the gRPC endpoint with reflection enabled.",
    cwe_candidates: ["CWE-200"],
    detection_and_monitoring:
      "Log and alert on reflection service calls in non-debug environments.",
    likelihood_rationale:
      "Common when debug defaults leak into production-like deployments.",
    impact_rationale:
      "Primarily reconnaissance amplification; usually lower impact than direct auth bypasses.",
  };
  return [...threats, row];
}

function sanitizeImmediateActions(
  threats: ThreatItem[],
  signals: SecuritySignalRow[],
): ThreatItem[] {
  return threats.map((t) => {
    const cleaned = t.immediate_actions.map((a) => a.trim()).filter((a) => a.length >= 15);
    if (cleaned.length > 0) {
      return { ...t, immediate_actions: cleaned };
    }
    const matched = signalsMatchingThreat(t, signals);
    const refl = matched.find((m) => m.id === "grpc-reflection-enabled");
    if (refl) {
      return {
        ...t,
        immediate_actions: [
          `Disable grpc-reflection-enabled in ${refl.path} for production builds.`,
        ],
      };
    }
    return { ...t, immediate_actions: [] };
  });
}

function ensureVariedStride(threats: ThreatItem[]): ThreatItem[] {
  const uniq = new Set(threats.map((t) => t.stride));
  if (threats.length < 3 || uniq.size > 1) {
    return threats;
  }
  return threats.map((t) => {
    const inferred = strideFromText(`${t.title} ${t.description}`);
    if (!inferred) {
      return t;
    }
    return { ...t, stride: inferred };
  });
}

function preferredStrideForSignalId(signalId: string): ThreatItem["stride"] | null {
  const id = lower(signalId);
  if (id === "grpc-reflection-enabled") {
    // Reflection primarily exposes API surface and method metadata.
    return "I";
  }
  if (id === "grpc-metadata-identity-fallback") {
    return "R";
  }
  return null;
}

function sanitizeReferences(threats: ThreatItem[]): ThreatItem[] {
  return threats.map((t) => ({
    ...t,
    references: t.references.filter((r) => {
      const u = String(r.url ?? "").trim();
      if (!u) return false;
      if (!/^https?:\/\//i.test(u)) return false;
      if (lower(u).includes("example.com/security-signal")) return false;
      return true;
    }),
  }));
}

function scoreThreatRichness(t: ThreatItem): number {
  let score = t.description.trim().length;
  if (t.attack_scenario.trim()) score += 120;
  if (t.prerequisites.trim()) score += 80;
  if (t.detection_and_monitoring.trim()) score += 80;
  if (t.likelihood_rationale.trim()) score += 80;
  if (t.impact_rationale.trim()) score += 80;
  score += t.cwe_candidates.length * 20;
  score += t.immediate_actions.length * 8;
  score += t.mitigations.length * 8;
  return score;
}

function normalizeStrideFromSingleSignal(threats: ThreatItem[], signals: SecuritySignalRow[]): ThreatItem[] {
  return threats.map((t) => {
    if (isSyntheticChainThreatId(t.id)) {
      return t;
    }
    const matched = signalsMatchingThreat(t, signals);
    if (matched.length !== 1) {
      return t;
    }
    const preferred = preferredStrideForSignalId(matched[0].id);
    if (!preferred) {
      return t;
    }
    return { ...t, stride: preferred };
  });
}

function dedupeSingleSignalThreats(threats: ThreatItem[], signals: SecuritySignalRow[]): ThreatItem[] {
  const bySignal = new Map<string, ThreatItem[]>();
  for (const t of threats) {
    if (isSyntheticChainThreatId(t.id)) {
      continue;
    }
    const matched = signalsMatchingThreat(t, signals);
    if (matched.length !== 1) {
      continue;
    }
    const key = matched[0].id;
    const list = bySignal.get(key) ?? [];
    list.push(t);
    bySignal.set(key, list);
  }

  const drop = new Set<string>();
  for (const [signalId, list] of bySignal.entries()) {
    if (list.length < 2) {
      continue;
    }
    const preferred = preferredStrideForSignalId(signalId);
    const ranked = [...list].sort((a, b) => {
      const aPref = preferred && a.stride === preferred ? 1 : 0;
      const bPref = preferred && b.stride === preferred ? 1 : 0;
      if (aPref !== bPref) {
        return bPref - aPref;
      }
      return scoreThreatRichness(b) - scoreThreatRichness(a);
    });
    for (const t of ranked.slice(1)) {
      drop.add(t.id);
    }
  }
  return threats.filter((t) => !drop.has(t.id));
}

function chainSignalIds(threats: ThreatItem[], signals: SecuritySignalRow[]): Set<string> {
  const out = new Set<string>();
  for (const t of threats) {
    if (!isSyntheticChainThreatId(t.id)) {
      continue;
    }
    const matched = signalsMatchingThreat(t, signals);
    for (const m of matched) {
      out.add(m.id);
    }
  }
  return out;
}

/**
 * If a synthetic CHAIN threat already covers a signal, drop non-chain rows whose primary
 * evidence is that same signal. This prevents duplicate cards that re-state chain findings.
 */
function filterThreatsCoveredByChainSignals(
  threats: ThreatItem[],
  signals: SecuritySignalRow[],
): ThreatItem[] {
  const covered = chainSignalIds(threats, signals);
  if (covered.size === 0) {
    return threats;
  }
  return threats.filter((t) => {
    if (isSyntheticChainThreatId(t.id)) {
      return true;
    }
    const matched = signalsMatchingThreat(t, signals);
    if (matched.length === 0) {
      return true;
    }
    // "primary signal" = first matched static signal after path-grounded matching.
    return !covered.has(matched[0].id);
  });
}

function enrichSparseMetadataFallbackThreats(
  threats: ThreatItem[],
  signals: SecuritySignalRow[],
): ThreatItem[] {
  return threats.map((t) => {
    if (isSyntheticChainThreatId(t.id)) {
      return t;
    }
    const matched = signalsMatchingThreat(t, signals);
    if (matched.length !== 1 || matched[0].id !== "grpc-metadata-identity-fallback") {
      return t;
    }
    const baseline =
      "When gRPC identity is derived from unverified metadata headers, audit logs record a principal chosen by the caller. That breaks attribution, enables repudiation against the real user, and weakens forensic confidence.";
    const description = t.description.includes("audit logs")
      ? t.description
      : `${baseline}\n\n${t.description}`.trim();
    return {
      ...t,
      description,
      attack_scenario:
        t.attack_scenario.trim() ||
        "Attacker submits crafted metadata (`user`/`x-user`) without a transport-bound identity and performs sensitive actions logged under a forged principal.",
      prerequisites:
        t.prerequisites.trim() ||
        "Ability to reach the gRPC endpoint and provide caller-controlled metadata where identity fallback is accepted.",
      cwe_candidates: t.cwe_candidates.length > 0 ? t.cwe_candidates : ["CWE-345", "CWE-778"],
      detection_and_monitoring:
        t.detection_and_monitoring.trim() ||
        "Alert when metadata-derived identity is accepted without peer certificate identity; correlate auth principal with mTLS peer fields.",
      likelihood_rationale:
        t.likelihood_rationale.trim() ||
        "Likely in environments where mTLS is optional or legacy metadata identity paths remain enabled.",
      impact_rationale:
        t.impact_rationale.trim() ||
        "Undermines non-repudiation and incident response because actor attribution in logs can be attacker-controlled.",
    };
  });
}

function reindexThreatIdsByStride(threats: ThreatItem[]): ThreatItem[] {
  const counters: Record<ThreatItem["stride"], number> = {
    S: 0,
    T: 0,
    R: 0,
    I: 0,
    D: 0,
    E: 0,
  };
  return threats.map((t) => {
    if (isSyntheticChainThreatId(t.id)) {
      return t;
    }
    counters[t.stride] += 1;
    return { ...t, id: `${t.stride}${counters[t.stride]}` };
  });
}

function threatPathsSubsetOfChain(chainPaths: string[], threatPaths: string[]): boolean {
  if (threatPaths.length === 0 || chainPaths.length === 0) {
    return false;
  }
  return threatPaths.every((p) => chainPaths.some((c) => pathsMatch(p, c)));
}

/**
 * Drop I-disclosure rows that only repeat hardcoded-credential signals already covered by CHAIN-HARDCODED-CREDS.
 */
function filterRedundantWithHardcodedChainThreats(
  threats: ThreatItem[],
  signals: SecuritySignalRow[],
): ThreatItem[] {
  const chainRow = threats.find((t) => t.id === CHAIN_HARDCODED_CREDS_ID);
  if (!chainRow) {
    return threats;
  }
  const chainPaths = chainRow.related_paths;
  return threats.filter((t) => {
    if (t.id === CHAIN_HARDCODED_CREDS_ID || isSyntheticChainThreatId(t.id)) {
      return true;
    }
    if (t.stride !== "I") {
      return true;
    }
    const matched = signalsMatchingThreat(t, signals);
    if (matched.length === 0) {
      return true;
    }
    const coversHardcodedStory = matched.some((m) => HARDCODED_CREDENTIAL_SIGNAL_IDS.has(m.id));
    if (!coversHardcodedStory) {
      return true;
    }
    const onlyBootstrapCredSignals = matched.every(
      (m) =>
        HARDCODED_CREDENTIAL_SIGNAL_IDS.has(m.id) || m.id === "tls-optional-config",
    );
    if (!onlyBootstrapCredSignals) {
      return true;
    }
    if (!threatPathsSubsetOfChain(chainPaths, t.related_paths)) {
      return true;
    }
    return false;
  });
}

function lowerBlob(t: ThreatItem): string {
  return lower(`${t.title} ${t.description}`);
}

/** Claim of SQL injection with no scanner support for query-layer abuse (DSN alone does not imply SQLi). */
function isUnfoundedSqlInjectionClaim(t: ThreatItem, signals: SecuritySignalRow[]): boolean {
  const blob = lowerBlob(t);
  if (!/\bsql\s+injection\b|\bsqli\b/.test(blob)) {
    return false;
  }
  const scannerSupportsSqliNarrative = signals.some((s) => {
    const id = lower(s.id);
    const sum = lower(s.summary);
    return (
      id.includes("injection") ||
      sum.includes("sql injection") ||
      sum.includes("sqli")
    );
  });
  return !scannerSupportsSqliNarrative;
}

/**
 * Drop findings with no path overlap to static signals when the model has signals (and no LLM paths),
 * and drop obvious SQLi hallucinations even if the LLM invented paths.
 */
function filterUnmooredThreats(
  threats: ThreatItem[],
  signals: SecuritySignalRow[],
  llmPathsById: Map<string, boolean>,
  modelHasSignals: boolean,
): ThreatItem[] {
  return threats.filter((t) => {
    if (isSyntheticChainThreatId(t.id)) {
      return true;
    }
    const matched = signalsMatchingThreat(t, signals);
    const hadLlmPaths = llmPathsById.get(t.id) ?? false;
    if (modelHasSignals && matched.length === 0 && !hadLlmPaths) {
      return false;
    }
    if (modelHasSignals && isUnfoundedSqlInjectionClaim(t, signals)) {
      return false;
    }
    return true;
  });
}

function cleanArchitectureFlows(
  model: Record<string, unknown>,
  flows: ThreatOutput["architecture_flows"],
): ThreatOutput["architecture_flows"] {
  const rows = flows.filter(
    (r) =>
      r.boundary_name.trim().length > 0 ||
      r.from_component.trim().length > 0 ||
      r.to_component.trim().length > 0,
  );
  if (rows.length > 0 && !isLowQualityArchitectureRows(rows as ArchitectureFlowRow[])) {
    return rows;
  }
  return deriveArchitectureFlowsFromModel(model);
}

/** Deterministic repair pass for noisy LLM output. */
export function postprocessThreatOutput(
  modelInput: unknown,
  parsed: ThreatOutput,
): ThreatOutput {
  const model = (modelInput && typeof modelInput === "object"
    ? (modelInput as Record<string, unknown>)
    : {}) as Record<string, unknown>;
  const signals = parseSecuritySignalsFromModel(model);
  const modelHasSignals = signals.length > 0;
  const llmPathsById = new Map(
    parsed.threats.map((t) => [
      t.id,
      normalizeRelatedPaths(model, t.related_paths).length > 0,
    ]),
  );
  let threats = parsed.threats.map((t) => fixOneThreat(model, t));
  threats = threats.map((t) => mergeSignalsIntoThreat(model, t, signals));
  threats = insertChainedThreats(model, threats, signals);
  threats = synthesizeReflectionDisclosureThreat(model, threats, signals);
  threats = sanitizeReferences(threats);
  threats = normalizeStrideFromSingleSignal(threats, signals);
  threats = filterRedundantWithHardcodedChainThreats(threats, signals);
  threats = filterUnmooredThreats(threats, signals, llmPathsById, modelHasSignals);
  threats = filterThreatsCoveredByChainSignals(threats, signals);
  threats = dedupeSingleSignalThreats(threats, signals);
  threats = enrichSparseMetadataFallbackThreats(threats, signals);
  threats = sanitizeImmediateActions(threats, signals);
  threats = reindexThreatIdsByStride(threats);
  return {
    ...parsed,
    architecture_flows: cleanArchitectureFlows(model, parsed.architecture_flows),
    threats,
  };
}


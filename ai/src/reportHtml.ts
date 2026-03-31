import { findingKeyForThreat } from "./baseline.js";
import { formatDeepDiveForDisplay } from "./deepDiveDisplay.js";
import { STRIDE_REFERENCE } from "./referenceStride.js";
import { resolveArchitectureRows, resolveThreatActorRows } from "./reportContext.js";
import {
  parseSecuritySignalsFromModel,
  sortSignalsBySeverity,
  signalsMatchingThreat,
} from "./signalGrounding.js";
import type { ThreatReportMeta, ThreatReportOptions } from "./reportMarkdown.js";
import type { ThreatOutput } from "./schemas.js";

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function sevClass(sev: string): string {
  switch (sev) {
    case "CRITICAL":
      return "sev crit";
    case "HIGH":
      return "sev high";
    case "MEDIUM":
      return "sev med";
    default:
      return "sev low";
  }
}

/** Allow Mermaid source in HTML without breaking out of the page script context. */
function safeMermaidBody(src: string): string {
  return src.replace(/<\/script/gi, "<\\/script");
}

const STRIDE_ORDER = ["S", "T", "R", "I", "D", "E"] as const;

function strideLabel(letter: string): string {
  const m: Record<string, string> = {
    S: "Spoofing",
    T: "Tampering",
    R: "Repudiation",
    I: "Information disclosure",
    D: "Denial of service",
    E: "Elevation of privilege",
  };
  return m[letter] ?? letter;
}

/**
 * Self-contained HTML threat assessment (open in a browser). Styling evokes dashboard cards / severity badges.
 */
export function buildThreatAssessmentHTML(
  systemModel: Record<string, unknown>,
  threats: ThreatOutput,
  meta: ThreatReportMeta,
  opts?: ThreatReportOptions,
): string {
  const deepDiveById = opts?.deepDiveById ?? {};
  const includeRef = opts?.includeReferenceAppendix !== false;
  const delta = opts?.delta;

  const strideCounts: Record<string, number> = { S: 0, T: 0, R: 0, I: 0, D: 0, E: 0 };
  for (const t of threats.threats) {
    strideCounts[t.stride] = (strideCounts[t.stride] ?? 0) + 1;
  }
  const sevCounts: Record<string, number> = {};
  for (const t of threats.threats) {
    sevCounts[t.severity] = (sevCounts[t.severity] ?? 0) + 1;
  }

  const arch = resolveArchitectureRows(systemModel, threats);
  const actors = resolveThreatActorRows(threats);
  const sortedSignals = sortSignalsBySeverity(parseSecuritySignalsFromModel(systemModel));

  const flowRowsText =
    arch.rows.length > 0
      ? arch.rows
          .map(
            (r) =>
              `<tr><td>${escapeHtml(r.boundary_name)}</td><td>${escapeHtml(r.from_component)}</td><td>${escapeHtml(r.to_component)}</td></tr>`,
          )
          .join("")
      : `<tr><td colspan="3"><em>${escapeHtml(arch.sourceNote)}</em></td></tr>`;

  const actorRowsText = actors.rows
    .map(
      (a) =>
        `<tr><td>${escapeHtml(a.category)}</td><td>${escapeHtml(a.description)}</td><td>${escapeHtml(a.example)}</td></tr>`,
    )
    .join("");

  const strideSummary = STRIDE_ORDER.map(
    (k) =>
      `<tr><td>${k} (${escapeHtml(strideLabel(k))})</td><td style="text-align:right">${strideCounts[k] ?? 0}</td></tr>`,
  ).join("");

  const sevSummary = (["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const)
    .filter((k) => sevCounts[k] !== undefined)
    .map((k) => `<tr><td>${k}</td><td style="text-align:right">${sevCounts[k]}</td></tr>`)
    .join("");

  const staticSignalRows =
    sortedSignals.length > 0
      ? sortedSignals
          .map(
            (s) =>
              `<tr><td><code>${escapeHtml(s.id)}</code></td><td><span class="${sevClass(s.severity)}">${escapeHtml(s.severity)}</span></td><td><code>${escapeHtml(s.path)}</code></td><td>${escapeHtml(s.summary)}</td></tr>`,
          )
          .join("")
      : "";

  const staticSignalSection =
    sortedSignals.length > 0
      ? `<h2>Static security signals (code scan)</h2>
<p class="note">Deterministic pattern matches — triage these first; they ground LLM findings in real code paths.</p>
<table class="data signals"><thead><tr><th>Signal</th><th>Severity</th><th>Path</th><th>Summary</th></tr></thead><tbody>${staticSignalRows}</tbody></table>`
      : "";

  const execDeltaNote =
    delta == null
      ? ""
      : !delta.hadBaseline
        ? `<p class="note">No prior baseline — all findings are <span class="delta-badge delta-new">NEW</span>. The next run compares to <code>.threatlensai/baseline.json</code>.</p>`
        : `<p class="note">Delta vs last run: <strong>${Object.values(delta.statusByKey).filter((s) => s === "NEW").length}</strong> new, <strong>${Object.values(delta.statusByKey).filter((s) => s === "UNCHANGED").length}</strong> unchanged, <strong>${delta.resolved.length}</strong> resolved.</p>`;

  const resolvedSection =
    delta != null && delta.hadBaseline && delta.resolved.length > 0
      ? `<h2>Resolved since last run</h2>
<p class="note">Present in the previous baseline, absent from the current register.</p>
<ul>${delta.resolved
          .map(
            (r) =>
              `<li><span class="delta-badge delta-resolved">RESOLVED</span> <code>${escapeHtml(r.id)}</code> — ${escapeHtml(r.title)} (${escapeHtml(r.stride)} / ${escapeHtml(r.severity)})</li>`,
          )
          .join("")}</ul>`
      : "";

  const threatCardsText = threats.threats
    .map((t) => {
      const dKey = findingKeyForThreat(t, sortedSignals);
      const dSt = delta?.statusByKey[dKey] ?? (delta ? "NEW" : undefined);
      const deltaBadge =
        dSt === "NEW"
          ? `<span class="delta-badge delta-new">NEW</span>`
          : dSt === "UNCHANGED"
            ? `<span class="delta-badge delta-unchanged">UNCHANGED</span>`
            : "";
      const mitPills = t.mitigations
        .map((m) => `<span class="pill">${escapeHtml(m)}</span>`)
        .join("");
      const actionPills = t.immediate_actions
        .map((m) => `<span class="pill action">${escapeHtml(m)}</span>`)
        .join("");
      const diveRaw = deepDiveById[t.id]?.trim();
      const diveDecoded = diveRaw ? formatDeepDiveForDisplay(diveRaw) : "";
      const dive = diveDecoded
        ? `<details><summary>Deep-dive (LLM)</summary><div class="deep">${escapeHtml(diveDecoded)}</div></details>`
        : "";
      const linked = signalsMatchingThreat(t, sortedSignals);
      const signalPills =
        linked.length > 0
          ? `<div class="signal-row"><span class="signal-h">Static signals:</span> ${linked
              .map(
                (s) =>
                  `<span class="sig-pill ${sevClass(s.severity)}" title="${escapeHtml(s.summary)}">${escapeHtml(s.id)}</span>`,
              )
              .join(" ")}</div>`
          : "";
      const cweHtml =
        t.cwe_candidates.length > 0
          ? `<div class="tmeta"><p><strong>CWE candidates (triage)</strong></p><ul>${t.cwe_candidates
              .map((c) => `<li>${escapeHtml(c)}</li>`)
              .join("")}</ul></div>`
          : "";
      const refHtml =
        t.references.length > 0
          ? `<div class="tmeta"><p><strong>References</strong></p><ul>${t.references
              .map((r) => `<li><a href="${escapeHtml(r.url)}">${escapeHtml(r.label)}</a></li>`)
              .join("")}</ul></div>`
          : "";
      const detailsExtra = [
        signalPills,
        t.attack_scenario?.trim()
          ? `<p><strong>Attack scenario</strong><br>${escapeHtml(t.attack_scenario)}</p>`
          : "",
        t.prerequisites?.trim()
          ? `<p><strong>Prerequisites</strong><br>${escapeHtml(t.prerequisites)}</p>`
          : "",
        cweHtml,
        t.likelihood_rationale?.trim()
          ? `<p><strong>Likelihood rationale</strong><br>${escapeHtml(t.likelihood_rationale)}</p>`
          : "",
        t.impact_rationale?.trim()
          ? `<p><strong>Impact rationale</strong><br>${escapeHtml(t.impact_rationale)}</p>`
          : "",
        t.detection_and_monitoring?.trim()
          ? `<p><strong>Detection and monitoring</strong><br>${escapeHtml(t.detection_and_monitoring)}</p>`
          : "",
        t.verification?.trim()
          ? `<p><strong>Verification</strong><br>${escapeHtml(t.verification)}</p>`
          : "",
        refHtml,
        dive,
      ].join("");
      return `
      <article class="card">
        <header class="card-h">
          <h3>${deltaBadge}${escapeHtml(t.id)} — ${escapeHtml(t.title)}</h3>
          <span class="${sevClass(t.severity)}">${escapeHtml(t.severity)}</span>
          <span class="stride" title="${escapeHtml(strideLabel(t.stride))}">${escapeHtml(t.stride)}</span>
        </header>
        <p class="desc">${escapeHtml(t.description)}</p>
        ${mitPills || actionPills ? `<div class="pills">${actionPills}${mitPills}</div>` : ""}
        ${detailsExtra}
      </article>`;
    })
    .join("");

  let appendix = "";
  if (includeRef) {
    const blocks = STRIDE_ORDER.map((k) => {
      const ref = STRIDE_REFERENCE[k];
      if (!ref) {
        return "";
      }
      const cweRows = ref.cwes
        .map((c) => `<tr><td>${escapeHtml(c.id)}</td><td>${escapeHtml(c.name)}</td></tr>`)
        .join("");
      const ow = ref.owasp
        .map((o) => `<li><a href="${escapeHtml(o.url)}">${escapeHtml(o.label)}</a></li>`)
        .join("");
      return `<section class="ref-block"><h4>${escapeHtml(k)} — ${escapeHtml(strideLabel(k))}</h4><p>${escapeHtml(ref.summary)}</p><table class="data"><thead><tr><th>CWE</th><th>Name</th></tr></thead><tbody>${cweRows}</tbody></table><ul>${ow}</ul></section>`;
    }).join("");
    appendix = `<section class="appendix"><h2>STRIDE reference</h2>${blocks}</section>`;
  }

  const mermaidRaw = typeof systemModel.mermaid_flow === "string" ? systemModel.mermaid_flow.trim() : "";
  const mermaidSection = mermaidRaw
    ? `<h2>Architecture (Mermaid)</h2>
<p class="note">Rendered inline in the browser from your indexed flow diagram.</p>
<div class="mermaid">${safeMermaidBody(mermaidRaw)}</div>`
    : "";

  const mermaidScripts = mermaidRaw
    ? `<script src="https://cdn.jsdelivr.net/npm/mermaid@11.4.0/dist/mermaid.min.js"></script>
<script>
  mermaid.initialize({ startOnLoad: true, theme: "neutral" });
</script>`
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${escapeHtml(meta.title)}</title>
<style>
  :root { font-family: system-ui, sans-serif; color: #1a1a1a; background: #f6f7fb; }
  body { max-width: 1100px; margin: 0 auto; padding: 24px; }
  h1 { font-size: 1.6rem; }
  h2 { font-size: 1.15rem; margin-top: 2rem; border-bottom: 1px solid #ccd; padding-bottom: 6px; }
  .meta { color: #555; font-size: 0.9rem; margin-bottom: 1.5rem; }
  table.data { width: 100%; border-collapse: collapse; margin: 12px 0; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 2px rgba(0,0,0,.06); }
  table.data th, table.data td { border: 1px solid #e2e5ee; padding: 10px 12px; text-align: left; font-size: 0.9rem; }
  table.data th { background: #eef1f8; font-weight: 600; }
  table.signals td .sev { display: inline-block; font-size: 0.72rem; font-weight: 700; padding: 3px 8px; border-radius: 999px; text-transform: uppercase; }
  table.signals td .sev.crit { background: #3d0a0a; color: #fff; }
  table.signals td .sev.high { background: #c0392b; color: #fff; }
  table.signals td .sev.med { background: #d68910; color: #fff; }
  table.signals td .sev.low { background: #949494; color: #fff; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  @media (max-width: 800px) { .grid2 { grid-template-columns: 1fr; } }
  .card { background: #fff; border-radius: 10px; padding: 16px 18px; margin: 14px 0; box-shadow: 0 1px 3px rgba(0,0,0,.08); border: 1px solid #e8e8ef; }
  .card-h { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; margin-bottom: 8px; }
  .card-h h3 { flex: 1 1 200px; margin: 0; font-size: 1rem; }
  .sev { font-size: 0.72rem; font-weight: 700; padding: 4px 10px; border-radius: 999px; text-transform: uppercase; letter-spacing: .04em; }
  .sev.crit { background: #3d0a0a; color: #fff; }
  .sev.high { background: #c0392b; color: #fff; }
  .sev.med { background: #d68910; color: #fff; }
  .sev.low { background: #949494; color: #fff; }
  .stride { font-size: 0.75rem; background: #e8ecf7; padding: 4px 8px; border-radius: 6px; font-weight: 600; }
  .desc { font-size: 0.92rem; line-height: 1.45; white-space: pre-wrap; }
  .pills { margin-top: 10px; display: flex; flex-wrap: wrap; gap: 6px; }
  .pill { font-size: 0.75rem; background: #e8f4ea; color: #145a32; padding: 5px 10px; border-radius: 999px; border: 1px solid #c8e6c9; }
  .pill.action { background: #e3f2fd; color: #0d47a1; border-color: #90caf9; }
  .signal-row { margin-top: 10px; font-size: 0.82rem; display: flex; flex-wrap: wrap; align-items: center; gap: 6px; }
  .signal-h { font-weight: 600; color: #444; }
  .sig-pill { font-size: 0.7rem; font-weight: 700; padding: 3px 8px; border-radius: 999px; text-transform: uppercase; letter-spacing: .03em; }
  details { margin-top: 10px; font-size: 0.88rem; }
  .tmeta { font-size: 0.88rem; margin-top: 10px; line-height: 1.45; }
  .tmeta ul { margin: 6px 0; padding-left: 1.2rem; }
  .deep { margin-top: 8px; white-space: pre-wrap; }
  .mermaid { background: #fff; padding: 16px; border-radius: 8px; border: 1px solid #ddd; margin: 12px 0; overflow: auto; }
  .note { font-size: 0.85rem; color: #555; font-style: italic; }
  .appendix .ref-block { margin-bottom: 1.5rem; }
  .delta-badge { font-size: 0.72rem; font-weight: 700; padding: 4px 8px; border-radius: 6px; margin-right: 8px; display: inline-block; vertical-align: middle; text-transform: uppercase; letter-spacing: .03em; }
  .delta-new { background: #e1f5fe; color: #01579b; }
  .delta-unchanged { background: #eceff1; color: #37474f; }
  .delta-resolved { background: #e8f5e9; color: #1b5e20; }
</style>
</head>
<body>
  <h1>${escapeHtml(meta.title)}</h1>
  <p class="meta">Generated ${escapeHtml(new Date().toISOString())} · Root <code>${escapeHtml(meta.projectRoot)}</code></p>
  <p>ThreatLensAI — validate against live architecture before production sign-off.</p>

  <h2>Executive summary</h2>
  <div class="grid2">
    <table class="data"><thead><tr><th>STRIDE</th><th>Count</th></tr></thead><tbody>${strideSummary}</tbody></table>
    <table class="data"><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>${sevSummary}</tbody></table>
  </div>
  <p class="note">${threats.threats.length} threats modeled (heuristic index).</p>
  ${execDeltaNote}

  ${staticSignalSection}

  <h2>Data flows and trust boundaries</h2>
  <p class="note">${escapeHtml(arch.sourceNote)}</p>
  <table class="data"><thead><tr><th>Boundary / flow</th><th>From</th><th>To</th></tr></thead><tbody>${flowRowsText}</tbody></table>

  <h2>Threat sources</h2>
  <p class="note">${escapeHtml(actors.isTailored ? "Tailored to this application (LLM)." : "Generic SDLC categories — customize for your org.")}</p>
  <table class="data"><thead><tr><th>Category</th><th>Description</th><th>Example</th></tr></thead><tbody>${actorRowsText}</tbody></table>

  ${mermaidSection}

  ${resolvedSection}

  <h2>Threat catalog</h2>
  ${threatCardsText}

  ${appendix}

  <h2>Disclaimer</h2>
  <p class="note">Automated models are incomplete; use as a starting point for human review.</p>
  ${mermaidScripts}
</body>
</html>`;
}

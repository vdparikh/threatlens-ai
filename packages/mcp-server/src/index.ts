#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import {
  explainThreatMarkdown,
  generateThreats,
  reportDeltaFromModel,
  runDeepDiveEnrichment,
  saveBaseline,
} from "@threatlensai/ai";
import { resolve } from "node:path";
import { threatDragonJSONString } from "@threatlensai/ai/threat-dragon";
import { mcpDebugLog, mcpDebugEnabled } from "./debug.js";
import { runAnalyzeCodebase } from "./engine.js";
import {
  buildThreatAssessmentHTML,
  buildThreatAssessmentMarkdown,
  resolveSafeOutputPath,
  writeThreatReportFile,
} from "./writeReport.js";

/** Same directory as the Markdown file; `.md` → `.html` for sibling dashboard export. */
function siblingHtmlPathFromMdAbs(mdAbs: string): string {
  const lower = mdAbs.toLowerCase();
  if (lower.endsWith(".md")) {
    return mdAbs.slice(0, -3) + ".html";
  }
  return `${mdAbs}.html`;
}

const server = new Server(
  {
    name: "threatlensai",
    version: "0.1.0",
  },
  {
    capabilities: {
      tools: {},
    },
  },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "analyze_codebase",
      description:
        "Parse a project root into a system model: files, languages, Go imports, http_routes (best-effort), flow_graph, mermaid_flow (Mermaid diagram text for architecture/trust flow).",
      inputSchema: {
        type: "object",
        properties: {
          root: {
            type: "string",
            description: "Absolute path to the project root",
          },
        },
        required: ["root"],
      },
    },
    {
      name: "generate_threats",
      description:
        "Generate STRIDE-categorized threats. Uses Claude if ANTHROPIC_API_KEY is set, or local Ollama if OLLAMA_MODEL is set (e.g. llama3.2). Prefer passing root: the server runs analyze_codebase internally. Alternatively pass system_model_json from a prior analyze_codebase call.",
      inputSchema: {
        type: "object",
        properties: {
          root: {
            type: "string",
            description:
              "Absolute path to the project root. If set, the engine analyzes this path first (same as analyze_codebase). Do not pass system_model_json in the same call.",
          },
          system_model_json: {
            type: "string",
            description:
              "JSON string of the system model from analyze_codebase. Use when you already have the model and it is small enough to pass. Omit when using root.",
          },
        },
      },
    },
    {
      name: "architecture_diagram",
      description:
        "Lightweight view: same analysis as analyze_codebase but returns only go_summary, flow_graph, mermaid_flow, and a sample of http_routes (for large repos). Use when you need the diagram without the full file list.",
      inputSchema: {
        type: "object",
        properties: {
          root: {
            type: "string",
            description: "Absolute path to the project root",
          },
        },
        required: ["root"],
      },
    },
    {
      name: "write_threat_report",
      description:
        "**Primary SDLC handoff tool:** analyze + STRIDE threats + write `security/threat-assessment.md` (and optionally a sibling `.html` dashboard for security reviewers). Persists `.threatlensai/baseline.json` and labels findings NEW/UNCHANGED vs the previous run; lists RESOLVED findings that disappeared. You do not need other MCP tools for a standard review — optional: `export_threat_dragon`, `explain_threat`. Requires ANTHROPIC_API_KEY or OLLAMA_MODEL.",
      inputSchema: {
        type: "object",
        properties: {
          root: {
            type: "string",
            description: "Absolute path to the project root (file is written under this tree only)",
          },
          output_path: {
            type: "string",
            description:
              "Relative path under root (default security/threat-assessment.md). Must not contain ..",
          },
          title: {
            type: "string",
            description: "Report title (H1 heading)",
          },
          include_html: {
            type: "boolean",
            description:
              "If true (default), also write a browser-friendly HTML report next to the Markdown (same basename, .html). Set false for Markdown only.",
          },
          include_deep_dive: {
            type: "boolean",
            description:
              "If true (default), run a second LLM call for per-threat Markdown deep-dives (extra tokens/latency). Set false for a faster, shorter report.",
          },
          include_reference_appendix: {
            type: "boolean",
            description:
              "If true (default), append static STRIDE→CWE and OWASP cheat-sheet pointers for triage.",
          },
        },
        required: ["root"],
      },
    },
    {
      name: "export_threat_dragon",
      description:
        "Run analyze + generate_threats, then return OWASP Threat Dragon JSON (open in Threat Dragon desktop/web). Same LLM env as generate_threats. Saves round-tripping threats into a standard DFD editor.",
      inputSchema: {
        type: "object",
        properties: {
          root: {
            type: "string",
            description: "Absolute path to the project root (analyzed then threat-generated)",
          },
          title: {
            type: "string",
            description: "Optional model title shown in Threat Dragon summary",
          },
        },
        required: ["root"],
      },
    },
    {
      name: "explain_threat",
      description:
        "LLM: long-form Markdown explanation for a single threat (attack scenario, verification, residual risk). Pass threat_json (object as JSON string). Optionally pass system_model_json for grounding. Same ANTHROPIC_API_KEY / OLLAMA_MODEL as generate_threats.",
      inputSchema: {
        type: "object",
        properties: {
          threat_json: {
            type: "string",
            description: "JSON string of one threat object (e.g. from generate_threats output).",
          },
          system_model_json: {
            type: "string",
            description:
              "Optional JSON string of the system model from analyze_codebase for context (may be truncated by the server).",
          },
        },
        required: ["threat_json"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const name = request.params.name;
  const args = (request.params.arguments ?? {}) as Record<string, unknown>;

  if (mcpDebugEnabled()) {
    if (name === "generate_threats") {
      const raw = String(args.system_model_json ?? "");
      const rootArg = String(args.root ?? "").trim();
      if (rootArg) {
        mcpDebugLog(`tool_call name=${name} root=${rootArg}`);
      } else {
        mcpDebugLog(
          `tool_call name=${name} system_model_json_bytes=${raw.length}`,
        );
      }
    } else {
      mcpDebugLog(`tool_call name=${name} args=${JSON.stringify(args)}`);
    }
  }

  if (name === "analyze_codebase") {
    const root = String(args.root ?? "");
    if (!root) {
      return { content: [{ type: "text", text: JSON.stringify({ error: "missing root" }) }] };
    }
    try {
      const model = runAnalyzeCodebase(root);
      return { content: [{ type: "text", text: JSON.stringify(model, null, 2) }] };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: msg }) }],
        isError: true,
      };
    }
  }

  if (name === "architecture_diagram") {
    const root = String(args.root ?? "");
    if (!root) {
      return { content: [{ type: "text", text: JSON.stringify({ error: "missing root" }) }] };
    }
    try {
      const model = runAnalyzeCodebase(root) as Record<string, unknown>;
      const routes = model.http_routes;
      let sample: unknown[] = [];
      if (Array.isArray(routes)) {
        sample = routes.slice(0, 50) as unknown[];
      }
      const gs = model.go_summary as { route_count?: number } | undefined;
      const slim = {
        version: model.version,
        root: model.root,
        go_summary: model.go_summary,
        flow_graph: model.flow_graph,
        mermaid_flow: model.mermaid_flow,
        http_routes_sample: sample,
        routes_truncated: model.routes_truncated,
        route_count: gs?.route_count ?? 0,
      };
      return { content: [{ type: "text", text: JSON.stringify(slim, null, 2) }] };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: msg }) }],
        isError: true,
      };
    }
  }

  if (name === "generate_threats") {
    const rootArg = String(args.root ?? "").trim();
    const raw = String(args.system_model_json ?? "");
    if (rootArg && raw) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              error:
                "pass only one of root (analyze then generate) or system_model_json, not both",
            }),
          },
        ],
        isError: true,
      };
    }
    if (!rootArg && !raw) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              error:
                "missing root or system_model_json: use root with an absolute project path, or pass the JSON string from analyze_codebase",
            }),
          },
        ],
        isError: true,
      };
    }
    const ollamaEnabled =
      Boolean(process.env.OLLAMA_MODEL?.trim()) ||
      process.env.THREATLENS_LLM === "ollama";
    if (!ollamaEnabled && !process.env.ANTHROPIC_API_KEY) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              error:
                "Set ANTHROPIC_API_KEY for Claude, or OLLAMA_MODEL (and run Ollama locally) for offline threat generation",
            }),
          },
        ],
        isError: true,
      };
    }

    let parsed: unknown;
    if (rootArg) {
      try {
        parsed = runAnalyzeCodebase(rootArg);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        return {
          content: [{ type: "text", text: JSON.stringify({ error: msg }) }],
          isError: true,
        };
      }
    } else {
      try {
        parsed = JSON.parse(raw);
      } catch (e) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: `invalid JSON: ${e instanceof Error ? e.message : String(e)}`,
              }),
            },
          ],
          isError: true,
        };
      }
    }

    try {
      const out = await generateThreats(parsed);
      return { content: [{ type: "text", text: JSON.stringify(out, null, 2) }] };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: msg }) }],
        isError: true,
      };
    }
  }

  if (name === "export_threat_dragon") {
    const rootArg = String(args.root ?? "").trim();
    const title = String(args.title ?? "Threat model").trim() || "Threat model";
    if (!rootArg) {
      return { content: [{ type: "text", text: JSON.stringify({ error: "missing root" }) }] };
    }
    const ollamaEnabled =
      Boolean(process.env.OLLAMA_MODEL?.trim()) ||
      process.env.THREATLENS_LLM === "ollama";
    if (!ollamaEnabled && !process.env.ANTHROPIC_API_KEY) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              error:
                "Set ANTHROPIC_API_KEY or OLLAMA_MODEL (same as generate_threats)",
            }),
          },
        ],
        isError: true,
      };
    }
    let parsed: unknown;
    try {
      parsed = runAnalyzeCodebase(rootArg);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: msg }) }],
        isError: true,
      };
    }
    try {
      const out = await generateThreats(parsed);
      const json = threatDragonJSONString(out, {
        title,
        description: `Imported from ThreatLensAI — ${rootArg}`,
      });
      return { content: [{ type: "text", text: json }] };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: msg }) }],
        isError: true,
      };
    }
  }

  if (name === "write_threat_report") {
    const rootArg = String(args.root ?? "").trim();
    const outputRel = String(args.output_path ?? "security/threat-assessment.md").trim();
    const title = String(args.title ?? "Threat assessment").trim() || "Threat assessment";
    if (!rootArg) {
      return { content: [{ type: "text", text: JSON.stringify({ error: "missing root" }) }] };
    }
    const ollamaEnabled =
      Boolean(process.env.OLLAMA_MODEL?.trim()) ||
      process.env.THREATLENS_LLM === "ollama";
    if (!ollamaEnabled && !process.env.ANTHROPIC_API_KEY) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              error:
                "Set ANTHROPIC_API_KEY or OLLAMA_MODEL (same as generate_threats)",
            }),
          },
        ],
        isError: true,
      };
    }
    let parsed: Record<string, unknown>;
    try {
      parsed = runAnalyzeCodebase(rootArg) as Record<string, unknown>;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: msg }) }],
        isError: true,
      };
    }
    let absOut: string;
    try {
      absOut = resolveSafeOutputPath(rootArg, outputRel);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: msg }) }],
        isError: true,
      };
    }
    try {
      const threatOut = await generateThreats(parsed);
      const includeDeep = args.include_deep_dive !== false;
      const includeRefAppendix = args.include_reference_appendix !== false;
      let deepDiveById: Record<string, string> | undefined;
      let deepDiveError: string | undefined;
      if (includeDeep) {
        try {
          deepDiveById = await runDeepDiveEnrichment(parsed, threatOut, {});
        } catch (e) {
          deepDiveError = e instanceof Error ? e.message : String(e);
        }
      }
      const projectRoot = resolve(rootArg);
      const { delta, snapshot } = reportDeltaFromModel(projectRoot, parsed, threatOut);
      const reportOpts = {
        deepDiveById,
        includeReferenceAppendix: includeRefAppendix,
        delta,
      };
      const md = buildThreatAssessmentMarkdown(
        parsed,
        threatOut,
        {
          title,
          projectRoot,
        },
        reportOpts,
      );
      writeThreatReportFile(absOut, md);
      const includeHtml = args.include_html !== false;
      let htmlPath: string | undefined;
      if (includeHtml) {
        htmlPath = siblingHtmlPathFromMdAbs(absOut);
        const html = buildThreatAssessmentHTML(
          parsed,
          threatOut,
          { title, projectRoot },
          reportOpts,
        );
        writeThreatReportFile(htmlPath, html);
      }
      let baselinePath: string | undefined;
      let baselineError: string | undefined;
      try {
        saveBaseline(projectRoot, snapshot);
        baselinePath = resolve(projectRoot, ".threatlensai", "baseline.json");
      } catch (e) {
        baselineError = e instanceof Error ? e.message : String(e);
      }
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              ok: true,
              written_path: absOut,
              relative_path: outputRel,
              html_path: htmlPath,
              baseline_path: baselinePath,
              baseline_error: baselineError,
              delta_new: Object.values(delta.statusByKey).filter((s) => s === "NEW").length,
              delta_unchanged: Object.values(delta.statusByKey).filter((s) => s === "UNCHANGED").length,
              delta_resolved: delta.resolved.length,
              include_html: includeHtml,
              include_deep_dive_requested: includeDeep,
              deep_dive_included: Boolean(deepDiveById && Object.keys(deepDiveById).length > 0),
              deep_dive_error: deepDiveError,
              message:
                "Threat assessment written under the repo (Markdown; HTML too if include_html). Commit and attach to your security / production readiness packet.",
            }),
          },
        ],
      };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: msg }) }],
        isError: true,
      };
    }
  }

  if (name === "explain_threat") {
    const rawThreat = String(args.threat_json ?? "").trim();
    const rawModel = String(args.system_model_json ?? "").trim();
    if (!rawThreat) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "missing threat_json" }) }],
        isError: true,
      };
    }
    const ollamaEnabled =
      Boolean(process.env.OLLAMA_MODEL?.trim()) ||
      process.env.THREATLENS_LLM === "ollama";
    if (!ollamaEnabled && !process.env.ANTHROPIC_API_KEY) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              error:
                "Set ANTHROPIC_API_KEY or OLLAMA_MODEL (same as generate_threats)",
            }),
          },
        ],
        isError: true,
      };
    }
    let threat: unknown;
    try {
      threat = JSON.parse(rawThreat);
    } catch (e) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              error: `invalid threat_json: ${e instanceof Error ? e.message : String(e)}`,
            }),
          },
        ],
        isError: true,
      };
    }
    if (threat === null || typeof threat !== "object") {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({ error: "threat_json must be a JSON object" }),
          },
        ],
        isError: true,
      };
    }
    let systemModel: unknown | undefined;
    if (rawModel) {
      try {
        systemModel = JSON.parse(rawModel);
      } catch (e) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: `invalid system_model_json: ${e instanceof Error ? e.message : String(e)}`,
              }),
            },
          ],
          isError: true,
        };
      }
    }
    try {
      const markdown = await explainThreatMarkdown(threat, systemModel, {});
      return {
        content: [{ type: "text", text: JSON.stringify({ markdown }) }],
      };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        content: [{ type: "text", text: JSON.stringify({ error: msg }) }],
        isError: true,
      };
    }
  }

  return {
    content: [{ type: "text", text: JSON.stringify({ error: "unknown tool" }) }],
    isError: true,
  };
});

async function main(): Promise<void> {
  if (mcpDebugEnabled()) {
    mcpDebugLog("server starting (stdio); tool calls will log here when invoked");
  }
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

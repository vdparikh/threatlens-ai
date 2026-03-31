import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

import { anthropicCompleteText } from "./anthropicChat.js";
import { parseJsonObjectFromModelText } from "./jsonUtils.js";
import {
  type GenerateThreatsOptions,
  ollamaJsonOutputFooter,
  useOllama,
} from "./llmOptions.js";
import { callOllamaChat } from "./ollama.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

const ExplainLegacyOutputSchema = z.object({
  markdown: z.string(),
});

const ExplainStructuredOutputSchema = z.object({
  sections: z.object({
    summary: z.string(),
    attack_scenario: z.string(),
    affected_components: z.string(),
    detection: z.string(),
    verification_checklist: z.string(),
    residual_risk: z.string(),
  }),
});

const ExplainOutputSchema = z.union([ExplainLegacyOutputSchema, ExplainStructuredOutputSchema]);

type ExplainOutput = z.infer<typeof ExplainOutputSchema>;

export function renderExplainOutputToMarkdown(out: ExplainOutput): string {
  if ("markdown" in out) {
    return out.markdown.trim();
  }
  const s = out.sections;
  const lines: string[] = [];
  lines.push("## Summary");
  lines.push("");
  lines.push(s.summary.trim() || "—");
  lines.push("");
  lines.push("## Attack Scenario");
  lines.push("");
  lines.push(s.attack_scenario.trim() || "—");
  lines.push("");
  lines.push("## Affected Components");
  lines.push("");
  lines.push(s.affected_components.trim() || "—");
  lines.push("");
  lines.push("## Detection");
  lines.push("");
  const detection = s.detection
    .split("|")
    .map((x) => x.trim())
    .filter(Boolean);
  if (detection.length > 0) {
    for (const item of detection) {
      lines.push(`- ${item}`);
    }
  } else {
    lines.push("- —");
  }
  lines.push("");
  lines.push("## Verification Checklist");
  lines.push("");
  const checks = s.verification_checklist
    .split("|")
    .map((x) => x.trim())
    .filter(Boolean);
  if (checks.length > 0) {
    for (const item of checks) {
      lines.push(`- ${item}`);
    }
  } else {
    lines.push("- —");
  }
  lines.push("");
  lines.push("## Residual Risk");
  lines.push("");
  lines.push(s.residual_risk.trim() || "—");
  lines.push("");
  return lines.join("\n").trim();
}

function loadExplainPrompt(): string {
  const path = join(__dirname, "..", "prompts", "explain-threat.md");
  return readFileSync(path, "utf-8");
}

function truncateForContext(obj: unknown, maxChars: number): unknown {
  const s = JSON.stringify(obj);
  if (s.length <= maxChars) {
    return obj;
  }
  return {
    _truncated: true,
    preview: s.slice(0, maxChars),
    note: "System model truncated for LLM context.",
  };
}

/**
 * Produce a long-form Markdown explanation for a single threat, optionally grounded in a system model.
 */
export async function explainThreatMarkdown(
  threat: unknown,
  systemModel: unknown | undefined,
  options: GenerateThreatsOptions = {},
): Promise<string> {
  let system = loadExplainPrompt();
  if (useOllama(options)) {
    system += ollamaJsonOutputFooter;
  }
  const payload = {
    threat,
    system_model:
      systemModel === undefined ? undefined : truncateForContext(systemModel, 20_000),
  };
  const user = JSON.stringify(payload);
  const maxTokens = options.maxTokens ?? 8192;

  let text: string;
  if (useOllama(options)) {
    const model =
      options.ollamaModel ?? process.env.OLLAMA_MODEL ?? options.model ?? "llama3.2";
    text = await callOllamaChat({
      host: options.ollamaHost,
      model,
      systemPrompt: system,
      userContent: user,
      maxTokens,
    });
  } else {
    const apiKey = options.apiKey ?? process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      throw new Error(
        "No LLM configured for explain_threat: set ANTHROPIC_API_KEY or OLLAMA_MODEL (and run Ollama)",
      );
    }
    text = await anthropicCompleteText(system, user, {
      model: options.model,
      maxTokens,
      apiKey,
    });
  }

  let parsed: unknown;
  try {
    parsed = parseJsonObjectFromModelText(text);
  } catch (e) {
    throw new Error(`failed to parse explain-threat JSON: ${e}`);
  }
  const out = ExplainOutputSchema.parse(parsed);
  return renderExplainOutputToMarkdown(out);
}

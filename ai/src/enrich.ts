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
import type { ThreatOutput } from "./schemas.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

const DeepDiveLegacyRowSchema = z.object({
  id: z.string(),
  markdown: z.string(),
});

const DeepDiveStructuredRowSchema = z.object({
  id: z.string(),
  attack_path: z.string(),
  code_review: z.array(z.string()),
  detection: z.array(z.string()),
});

const DeepDiveOutputSchema = z.object({
  explanations: z.array(z.union([DeepDiveLegacyRowSchema, DeepDiveStructuredRowSchema])),
});

type DeepDiveRow = z.infer<typeof DeepDiveLegacyRowSchema> | z.infer<typeof DeepDiveStructuredRowSchema>;

export function renderDeepDiveRowToMarkdown(row: DeepDiveRow): string {
  if ("markdown" in row) {
    return row.markdown;
  }
  const lines: string[] = [];
  const attackPath = normalizeAttackPath(row.attack_path);
  if (attackPath) {
    lines.push("### Attack path");
    lines.push("");
    lines.push(attackPath);
    lines.push("");
  }
  lines.push("### Code review focus");
  lines.push("");
  if (row.code_review.length > 0) {
    for (const item of row.code_review) {
      lines.push(`- ${item}`);
    }
  } else {
    lines.push("- No code-review checks provided.");
  }
  lines.push("");
  lines.push("### Detection and monitoring");
  lines.push("");
  if (row.detection.length > 0) {
    for (const item of row.detection) {
      lines.push(`- ${item}`);
    }
  } else {
    lines.push("- No detection guidance provided.");
  }
  return lines.join("\n").trim();
}

function normalizeAttackPath(v: string): string {
  const prefix = "System model is limited for this threat —";
  const t = v.trim();
  if (!t.startsWith(prefix)) {
    return t;
  }
  const rest = t.slice(prefix.length).trim();
  const sentenceCount = rest
    .split(/[.!?]+/)
    .map((s) => s.trim())
    .filter(Boolean).length;
  if (sentenceCount > 1) {
    return rest;
  }
  return t;
}

function loadDeepDivePrompt(): string {
  const path = join(__dirname, "..", "prompts", "deep-dive.md");
  return readFileSync(path, "utf-8");
}

function truncateForContext(obj: unknown, maxChars: number): string {
  const s = JSON.stringify(obj);
  if (s.length <= maxChars) {
    return s;
  }
  return `${s.slice(0, maxChars)}\n…[truncated ${s.length - maxChars} chars]`;
}

function buildDeepDiveUserPayload(systemModel: unknown, threats: ThreatOutput): string {
  const slimThreats = threats.threats.map((t) => ({
    id: t.id,
    stride: t.stride,
    title: t.title,
    description: t.description,
  }));
  return JSON.stringify({
    system_model_summary: truncateForContext(systemModel, 14_000),
    threats: slimThreats,
  });
}

function buildDeepDiveUserPayloadSingle(systemModel: unknown, threat: ThreatOutput["threats"][number]): string {
  const slim = {
    id: threat.id,
    stride: threat.stride,
    title: threat.title,
    description: threat.description,
  };
  return JSON.stringify({
    instruction:
      "The input contains exactly ONE threat. Respond with explanations array length 1; the id must match exactly.",
    system_model_summary: truncateForContext(systemModel, 12_000),
    threats: [slim],
  });
}

async function runDeepDiveEnrichmentOneThreat(
  systemModel: unknown,
  threat: ThreatOutput["threats"][number],
  options: GenerateThreatsOptions,
  systemPrompt: string,
  maxTokens: number,
): Promise<string> {
  const user = buildDeepDiveUserPayloadSingle(systemModel, threat);
  let text: string;
  if (useOllama(options)) {
    const model =
      options.ollamaModel ?? process.env.OLLAMA_MODEL ?? options.model ?? "llama3.2";
    text = await callOllamaChat({
      host: options.ollamaHost,
      model,
      systemPrompt,
      userContent: user,
      maxTokens,
    });
  } else {
    const apiKey = options.apiKey ?? process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      throw new Error(
        "No LLM configured for deep-dive: set ANTHROPIC_API_KEY or OLLAMA_MODEL (and run Ollama)",
      );
    }
    text = await anthropicCompleteText(systemPrompt, user, {
      model: options.model,
      maxTokens,
      apiKey,
    });
  }

  const parsed = parseJsonObjectFromModelText(text);
  const out = DeepDiveOutputSchema.parse(parsed);
  if (out.explanations.length !== 1) {
    throw new Error(`expected 1 explanation for single-threat deep-dive, got ${out.explanations.length}`);
  }
  const row = out.explanations[0];
  if (row.id !== threat.id) {
    throw new Error(`deep-dive id mismatch: expected ${threat.id}, got ${row.id}`);
  }
  return renderDeepDiveRowToMarkdown(row);
}

/**
 * Second LLM pass: per-threat Markdown deep-dives (attack path, review focus, detection).
 * Returns map threat id → markdown.
 */
export async function runDeepDiveEnrichment(
  systemModel: unknown,
  threats: ThreatOutput,
  options: GenerateThreatsOptions = {},
): Promise<Record<string, string>> {
  let system = loadDeepDivePrompt();
  if (useOllama(options)) {
    system += ollamaJsonOutputFooter;
  }
  const user = buildDeepDiveUserPayload(systemModel, threats);
  const maxTokens = options.maxTokens ?? 16_384;

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
        "No LLM configured for deep-dive: set ANTHROPIC_API_KEY or OLLAMA_MODEL (and run Ollama)",
      );
    }
    text = await anthropicCompleteText(system, user, {
      model: options.model,
      maxTokens,
      apiKey,
    });
  }

  try {
    const parsed = parseJsonObjectFromModelText(text);
    const out = DeepDiveOutputSchema.parse(parsed);
    if (out.explanations.length !== threats.threats.length) {
      throw new Error(
        `deep-dive count mismatch: expected ${threats.threats.length}, got ${out.explanations.length}`,
      );
    }
    const byId: Record<string, string> = {};
    for (const row of out.explanations) {
      byId[row.id] = renderDeepDiveRowToMarkdown(row);
    }
    const missing = threats.threats.filter((t) => byId[t.id] === undefined);
    if (missing.length > 0) {
      throw new Error(`deep-dive missing ids: ${missing.map((m) => m.id).join(", ")}`);
    }
    return byId;
  } catch (bulkErr) {
    const bulkMsg = bulkErr instanceof Error ? bulkErr.message : String(bulkErr);
    const perThreat: Record<string, string> = {};
    const oneShotTokens = Math.min(maxTokens, 8192);
    const errors: string[] = [];
    for (const t of threats.threats) {
      try {
        perThreat[t.id] = await runDeepDiveEnrichmentOneThreat(
          systemModel,
          t,
          options,
          system,
          oneShotTokens,
        );
      } catch (e) {
        errors.push(`${t.id}: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
    if (Object.keys(perThreat).length > 0) {
      return perThreat;
    }
    throw new Error(
      `failed to parse deep-dive JSON (bulk): ${bulkMsg}; per-threat fallback also failed: ${errors.slice(0, 3).join("; ")}${errors.length > 3 ? "…" : ""}`,
    );
  }
}

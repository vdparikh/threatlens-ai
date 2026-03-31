import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { anthropicCompleteText } from "./anthropicChat.js";
import { parseJsonObjectFromModelText } from "./jsonUtils.js";
import {
  type GenerateThreatsOptions,
  ollamaJsonOutputFooter,
  useOllama,
} from "./llmOptions.js";
import { callOllamaChat, parseThreatJsonFromAssistant } from "./ollama.js";
import { normalizeThreatPayload } from "./normalize.js";
import { postprocessThreatOutput } from "./postprocess.js";
import { ThreatOutputSchema, type ThreatOutput } from "./schemas.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadStrideSystemPrompt(): string {
  const path = join(__dirname, "..", "prompts", "stride.md");
  return readFileSync(path, "utf-8");
}

export type { GenerateThreatsOptions } from "./llmOptions.js";

/** Default output budget for threat JSON; Ollama especially needs headroom. Override with options.maxTokens or THREATLENS_THREAT_MAX_TOKENS. */
function defaultThreatMaxTokens(override?: number): number {
  if (typeof override === "number" && override > 0) {
    return override;
  }
  const env = process.env.THREATLENS_THREAT_MAX_TOKENS;
  const n = env ? parseInt(env, 10) : NaN;
  if (Number.isFinite(n) && n > 0) {
    return n;
  }
  return 16_384;
}

async function generateThreatsAnthropic(
  systemModel: unknown,
  apiKey: string,
  options: GenerateThreatsOptions,
): Promise<ThreatOutput> {
  const maxTokens = defaultThreatMaxTokens(options.maxTokens);
  const system = loadStrideSystemPrompt();
  const user = JSON.stringify(systemModel);

  const text = await anthropicCompleteText(system, user, {
    model: options.model,
    maxTokens,
    apiKey,
  });
  let parsed: unknown;
  try {
    parsed = parseJsonObjectFromModelText(text);
  } catch (e) {
    throw new Error(`failed to parse threat JSON: ${e}`);
  }
  const out = ThreatOutputSchema.parse(normalizeThreatPayload(parsed));
  return postprocessThreatOutput(systemModel, out);
}

async function generateThreatsOllama(
  systemModel: unknown,
  options: GenerateThreatsOptions,
): Promise<ThreatOutput> {
  const model =
    options.ollamaModel ?? process.env.OLLAMA_MODEL ?? options.model ?? "llama3.2";
  const system = loadStrideSystemPrompt() + ollamaJsonOutputFooter;
  const user = JSON.stringify(systemModel);
  const text = await callOllamaChat({
    host: options.ollamaHost,
    model,
    systemPrompt: system,
    userContent: user,
    maxTokens: defaultThreatMaxTokens(options.maxTokens),
  });
  const out = parseThreatJsonFromAssistant(text);
  return postprocessThreatOutput(systemModel, out);
}

function normalizeOptions(
  apiKeyOrOptions?: string | GenerateThreatsOptions,
  legacy?: GenerateThreatsOptions,
): GenerateThreatsOptions {
  if (typeof apiKeyOrOptions === "string") {
    return { apiKey: apiKeyOrOptions, ...legacy };
  }
  return apiKeyOrOptions ?? {};
}

/**
 * Generate STRIDE threat output from a system model.
 * - **Anthropic:** set `ANTHROPIC_API_KEY` or pass `apiKey` in options (unless `THREATLENS_LLM=ollama`).
 * - **Ollama:** set `OLLAMA_MODEL` (e.g. `llama3.2`) and run `ollama serve`, or set `THREATLENS_LLM=ollama`.
 */
export async function generateThreats(
  systemModel: unknown,
  apiKeyOrOptions?: string | GenerateThreatsOptions,
  legacyOptions?: GenerateThreatsOptions,
): Promise<ThreatOutput> {
  const options = normalizeOptions(apiKeyOrOptions, legacyOptions);

  if (useOllama(options)) {
    return generateThreatsOllama(systemModel, options);
  }

  const apiKey = options.apiKey ?? process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error(
      "No LLM configured: set ANTHROPIC_API_KEY for Claude, or OLLAMA_MODEL (and run Ollama) for local generation",
    );
  }
  return generateThreatsAnthropic(systemModel, apiKey, options);
}

export type { ThreatOutput } from "./schemas.js";
export {
  BASELINE_RELATIVE_PATH,
  type BaselineFile,
  type BaselineFindingEntry,
  buildBaselineSnapshot,
  computeReportDelta,
  findingKeyForThreat,
  loadBaseline,
  type ReportDelta,
  reportDeltaFromModel,
  saveBaseline,
} from "./baseline.js";
export { explainThreatMarkdown } from "./explain.js";
export { runDeepDiveEnrichment } from "./enrich.js";
export { STRIDE_REFERENCE } from "./referenceStride.js";
export {
  buildThreatAssessmentMarkdown,
  type ThreatReportMeta,
  type ThreatReportOptions,
} from "./reportMarkdown.js";
export { buildThreatAssessmentHTML } from "./reportHtml.js";
export { chatWithThreatReport, type ReportChatMessage } from "./reportChat.js";

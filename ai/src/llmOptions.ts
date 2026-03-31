/**
 * Shared LLM routing options for threat generation, deep-dive enrichment, and explain.
 */
export type GenerateThreatsOptions = {
  model?: string;
  maxTokens?: number;
  /** Anthropic API key; not required when using Ollama. */
  apiKey?: string;
  /** Override Ollama host (default http://127.0.0.1:11434 or OLLAMA_HOST). */
  ollamaHost?: string;
  /** Override Ollama model (default OLLAMA_MODEL env or llama3.2). */
  ollamaModel?: string;
};

/** Appended for Ollama/local models to cut "Here is the JSON" preambles; parsing also extracts `{...}`. */
export const ollamaJsonOutputFooter =
  '\n\nOutput: a single JSON object only. No preamble (no "Here is" / "Below is") and no markdown code fences. First non-whitespace character must be `{`.';

export function useOllama(options: GenerateThreatsOptions): boolean {
  if (process.env.THREATLENS_LLM === "anthropic") {
    return false;
  }
  if (process.env.THREATLENS_LLM === "ollama") {
    return true;
  }
  if (options.ollamaModel || process.env.OLLAMA_MODEL) {
    return true;
  }
  return false;
}
